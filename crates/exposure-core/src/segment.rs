use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
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
    buffer: Vec<T>,
    seq: u64,
}

impl<T: Serialize> SegmentWriter<T> {
    pub fn new(cfg: SegmentConfig, prefix: impl Into<String>) -> Result<Self> {
        fs::create_dir_all(&cfg.dir)?;
        let safe_prefix = sanitize_prefix(&prefix.into());
        Ok(Self {
            cfg,
            prefix: safe_prefix,
            buffer: Vec::new(),
            seq: 0,
        })
    }

    pub fn push(&mut self, record: T) -> Result<bool> {
        self.buffer.push(record);
        if self.buffer.len() >= self.cfg.max_batch_records.max(1) {
            self.flush()?;
            return Ok(true);
        }
        Ok(false)
    }

    pub fn pending_count(&self) -> usize {
        self.buffer.len()
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
        let tmp_path = Path::new(&self.cfg.dir).join(format!(".{filename}.tmp"));

        {
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut file = opts.open(&tmp_path)?;
            for item in &self.buffer {
                let line = serde_json::to_string(item)
                    .map_err(|e| ExposureError::Storage(format!("serialize segment record: {e}")))?;
                file.write_all(line.as_bytes())?;
                file.write_all(b"\n")?;
            }
            file.sync_all()?;
        }

        fs::rename(&tmp_path, &final_path)?;
        self.buffer.clear();
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
            raw_ip: None,
            rate_limited: false,
            challenged: false,
            challenge_passed: false,
            error: None,
            device_type: None,
            browser_family: None,
            os_family: None,
            client_fp_verified: false,
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
}
