use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::config::SegmentConfig;
use crate::error::{ExposureError, Result};

fn sanitize_prefix(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('.');
    if trimmed.is_empty() || trimmed.contains("..") {
        "node".to_string()
    } else {
        trimmed.chars().take(64).collect()
    }
}

/// Production-layer atomic segment file store:
/// - Batches JSONL records in memory
/// - Flushes atomically (`tmp` with `0o600` -> `sync_all` -> `rename`) when full, on timer, or on SIGINT/SIGTERM
/// - Enforces rotation, max disk usage, and retention policies
pub struct SegmentWriter<T> {
    cfg: SegmentConfig,
    prefix: String,
    buffer: Vec<String>,
    pending_bytes: usize,
    seq: u64,
    _marker: PhantomData<T>,
}

impl<T: Serialize> SegmentWriter<T> {
    pub fn new(cfg: SegmentConfig, prefix: impl Into<String>) -> Result<Self> {
        fs::create_dir_all(&cfg.dir)?;
        let safe_prefix = sanitize_prefix(&prefix.into());
        Ok(Self {
            cfg,
            prefix: safe_prefix,
            buffer: Vec::new(),
            pending_bytes: 0,
            seq: 0,
            _marker: PhantomData,
        })
    }

    fn should_flush(&self) -> bool {
        let max_records = self.cfg.max_batch_records.max(1);
        let max_bytes = self.cfg.max_batch_bytes.max(1024);
        let max_seg_bytes = self.cfg.max_segment_bytes.max(4096);
        self.buffer.len() >= max_records
            || self.pending_bytes >= max_bytes
            || (self.pending_bytes as u64) >= max_seg_bytes
    }

    /// Push a record to the batch buffer. Returns `Ok(true)` if batch or segment thresholds
    /// were reached and an immediate atomic flush occurred.
    pub fn push(&mut self, record: T) -> Result<bool> {
        let line = serde_json::to_string(&record)
            .map_err(|e| ExposureError::Storage(format!("serialize segment record: {e}")))?;
        let est_bytes = line.len() + 1;
        self.buffer.push(line);
        self.pending_bytes = self.pending_bytes.saturating_add(est_bytes);
        if self.should_flush() {
            self.flush()?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Push a batch of records in one pass, flushing intermediate segments whenever
    /// batch/segment limits are reached. Returns `Ok(true)` if at least one flush occurred.
    pub fn push_batch<I>(&mut self, records: I) -> Result<bool>
    where
        I: IntoIterator<Item = T>,
    {
        let mut flushed = false;
        for record in records {
            if self.push(record)? {
                flushed = true;
            }
        }
        Ok(flushed)
    }

    pub fn pending_count(&self) -> usize {
        self.buffer.len()
    }

    pub fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    pub fn flush(&mut self) -> Result<Option<PathBuf>> {
        if self.buffer.is_empty() {
            return Ok(None);
        }
        fs::create_dir_all(&self.cfg.dir)?;
        self.seq = self.seq.saturating_add(1);
        let ts = Utc::now().timestamp_millis();
        let filename = format!("{}-{}-{:06}.seg.jsonl", self.prefix, ts, self.seq);
        let final_path = Path::new(&self.cfg.dir).join(&filename);
        // Random suffix + `create_new` prevents symlink-follow/truncation in a shared directory.
        let rand_suffix = crate::crypto::generate_random_secret_hex(8);
        let tmp_path =
            Path::new(&self.cfg.dir).join(format!(".{filename}.{rand_suffix}.tmp"));

        {
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut file = opts.open(&tmp_path)?;
            for line in &self.buffer {
                file.write_all(line.as_bytes())?;
                file.write_all(b"\n")?;
            }
            file.sync_all()?;
        }

        fs::rename(&tmp_path, &final_path)?;
        self.buffer.clear();
        self.pending_bytes = 0;
        self.enforce_limits()?;
        Ok(Some(final_path))
    }

    pub fn enforce_limits(&self) -> Result<()> {
        let dir = Path::new(&self.cfg.dir);
        if !dir.exists() {
            return Ok(());
        }
        let mut files: Vec<(PathBuf, u64, SystemTime)> = Vec::new();
        let retention_secs = self.cfg.retention_hours.saturating_mul(3600);
        let retention_cutoff = SystemTime::now()
            .checked_sub(Duration::from_secs(retention_secs))
            .unwrap_or(SystemTime::UNIX_EPOCH);

        for entry in fs::read_dir(dir)?.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !name.ends_with(".seg.jsonl") {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                if modified < retention_cutoff {
                    let _ = fs::remove_file(&path);
                } else {
                    files.push((path, meta.len(), modified));
                }
            }
        }

        // Sort oldest first and trim until total disk bytes <= max_disk_bytes (preserving newest file).
        files.sort_by_key(|(_, _, m)| *m);
        let mut total: u64 = files.iter().map(|(_, len, _)| *len).fold(0u64, u64::saturating_add);
        let mut remaining = files.len();
        for (path, len, _) in files {
            if total <= self.cfg.max_disk_bytes || remaining <= 1 {
                break;
            }
            if fs::remove_file(&path).is_ok() {
                total = total.saturating_sub(len);
                remaining -= 1;
            }
        }
        Ok(())
    }
}

pub fn read_segment_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Vec<T>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut out = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let rec: T = serde_json::from_str(&line)
            .map_err(|e| ExposureError::Storage(format!("parse segment line: {e}")))?;
        out.push(rec);
    }
    Ok(out)
}

/// Atomically persist a JSON state snapshot (`0o600` tmp -> `sync_all` -> rename).
pub fn write_json_snapshot_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let bytes = serde_json::to_vec(value)
        .map_err(|e| ExposureError::Storage(format!("serialize snapshot: {e}")))?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("state.json");
    // Random suffix + `create_new` prevents symlink-follow/truncation in a shared directory.
    let rand_suffix = crate::crypto::generate_random_secret_hex(8);
    let tmp_path = path.with_file_name(format!(".{file_name}.{rand_suffix}.tmp"));
    {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp_path)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Read an optional JSON state snapshot from disk (returns `Ok(None)` if missing).
pub fn read_json_snapshot<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    let val: T = serde_json::from_slice(&bytes)
        .map_err(|e| ExposureError::Storage(format!("parse snapshot {}: {e}", path.display())))?;
    Ok(Some(val))
}

/// List `.seg.jsonl` files in `dir` matching `prefix` within `retention_hours`, sorted oldest-first.
pub fn list_recent_segment_files(dir: &Path, prefix: &str, retention_hours: u64) -> Vec<PathBuf> {
    if !dir.exists() {
        return Vec::new();
    }
    let safe_prefix = format!("{}-", sanitize_prefix(prefix));
    let cutoff = SystemTime::now()
        .checked_sub(Duration::from_secs(retention_hours.saturating_mul(3600)))
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let mut files: Vec<(PathBuf, SystemTime)> = Vec::new();
    if let Ok(rd) = fs::read_dir(dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !name.starts_with(&safe_prefix) || !name.ends_with(".seg.jsonl") {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                let m = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                if m >= cutoff {
                    files.push((p, m));
                }
            }
        }
    }
    files.sort_by_key(|(_, m)| *m);
    files.into_iter().map(|(p, _)| p).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::SessionSummary;

    #[test]
    fn segment_atomic_flush_and_disk_limit() {
        let dir = std::env::temp_dir().join(format!("exposure-seg-test-{}", uuid::Uuid::new_v4()));
        let cfg = SegmentConfig {
            dir: dir.to_string_lossy().to_string(),
            max_batch_records: 2,
            max_disk_bytes: 500,
            ..Default::default()
        };
        let mut w = SegmentWriter::<SessionSummary>::new(cfg, "../node-a").unwrap();
        let sample = SessionSummary {
            timestamp_ms: 1700000000000,
            node_tag: "node-a".into(),
            role: "ingress".into(),
            service_tag: "web".into(),
            status: 200,
            latency_ms: 12.5,
            bytes_in: 100,
            bytes_out: 200,
            ip_hmac: "abcdef1234567890".into(),
            ..Default::default()
        };
        assert!(!w.push(sample.clone()).unwrap());
        assert!(w.push(sample.clone()).unwrap());

        let files: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".seg.jsonl"))
            .collect();
        assert_eq!(files.len(), 1);
        let rows: Vec<SessionSummary> = read_segment_file(&files[0].path()).unwrap();
        assert_eq!(rows.len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn segment_flushes_early_when_batch_bytes_hit() {
        let dir = std::env::temp_dir().join(format!("exposure-seg-bytes-{}", uuid::Uuid::new_v4()));
        let cfg = SegmentConfig {
            dir: dir.to_string_lossy().to_string(),
            max_batch_records: 500, // high record cap
            max_batch_bytes: 1024,  // 1 KiB cap to trigger early flush well before 500 records
            ..Default::default()
        };
        let mut w = SegmentWriter::<SessionSummary>::new(cfg, "node-b").unwrap();
        let sample = SessionSummary {
            timestamp_ms: 1700000000000,
            node_tag: "node-b".into(),
            role: "ingress".into(),
            service_tag: "api".into(),
            status: 200,
            latency_ms: 3.2,
            bytes_in: 64,
            bytes_out: 128,
            ip_hmac: "0123456789abcdef".into(),
            ..Default::default()
        };
        let mut flushed_at = None;
        for i in 1..=20 {
            if w.push(sample.clone()).unwrap() {
                flushed_at = Some(i);
                break;
            }
        }
        let n = flushed_at.expect("expected byte-triggered early flush within 20 records");
        assert!(n < 20, "expected flush well before record cap 500, got {n}");
        let files = list_recent_segment_files(&dir, "node-b", 24);
        assert_eq!(files.len(), 1);

        // Verify atomic JSON snapshot helper
        let snap_path = dir.join("state.json");
        write_json_snapshot_atomic(&snap_path, &vec!["ok".to_string()]).unwrap();
        let loaded: Option<Vec<String>> = read_json_snapshot(&snap_path).unwrap();
        assert_eq!(loaded, Some(vec!["ok".to_string()]));
        let _ = fs::remove_dir_all(&dir);
    }
}
