use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};

use chrono::Utc;
use exposure_core::config::LoggerConfig;
use exposure_core::crypto::{generate_random_secret_hex, hmac_ip, is_weak_secret};
use exposure_core::routing::canonical_ip;
use exposure_core::segment::{read_json_snapshot, write_json_snapshot_atomic, SegmentWriter};
use exposure_core::telemetry::{
    AlertRecord, ClientJsFingerprint, FingerprintObservation, MinuteSummary, SessionSummary,
};
use exposure_core::Result;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify, RwLock};
use tracing::{debug, warn};

const MAX_MINUTE_BUCKETS: usize = 4096;
const MINUTE_BUCKET_RETENTION_SECS: i64 = 3600;
const MAX_FP_OBSERVATIONS: usize = 4096;
const FP_RETENTION_SECS: i64 = 3600 * 6;
const MAX_ALERT_MSG_LEN: usize = 512;
const MAX_RECENT_RECORDS: usize = 4096;

/// Extra unforgeable server-side signals attached to a visitor fingerprint observation.
#[derive(Debug, Clone, Default)]
pub struct FpServerExtras<'a> {
    pub tls_ja3: Option<&'a str>,
    pub tls_grease: bool,
    pub abuse_score: Option<u8>,
    pub abuse_country: Option<&'a str>,
    pub abuse_isp: Option<&'a str>,
    pub abuse_is_tor: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct NodeLoggerCheckpoint {
    #[serde(default)]
    summaries: Vec<MinuteSummary>,
    #[serde(default)]
    fingerprints: Vec<FingerprintObservation>,
    #[serde(default)]
    alerts: Vec<AlertRecord>,
}

fn node_checkpoint_path(dir: &str, node_tag: &str) -> PathBuf {
    let safe: String = node_tag
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '_' })
        .take(64)
        .collect();
    let name = if safe.is_empty() || safe.contains("..") {
        "node".to_string()
    } else {
        safe
    };
    PathBuf::from(dir).join(format!("node-state-{name}.json"))
}

fn canonical_ip_str(raw: &str) -> String {
    raw.trim()
        .parse::<IpAddr>()
        .map(|ip| canonical_ip(ip).to_string())
        .unwrap_or_else(|_| raw.trim().to_string())
}

pub fn ip_subnet_label(raw: &str) -> String {
    match raw.trim().parse::<IpAddr>().map(canonical_ip) {
        Ok(IpAddr::V4(v4)) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        Ok(IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
        Err(_) => String::new(),
    }
}

fn sanitize_alert_msg(raw: String) -> String {
    raw.chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .take(MAX_ALERT_MSG_LEN)
        .collect()
}

fn ensure_strong_hmac_key(mut cfg: LoggerConfig) -> LoggerConfig {
    if is_weak_secret(&cfg.hmac_key) {
        cfg.hmac_key = generate_random_secret_hex(32);
    }
    cfg
}

/// Production-layer Node logger (DESIGN.md §4 & §12):
/// - Applies configured `sample_rate`
/// - Stores HMAC IP by default; raw IP only when `store_raw_ip: true`
/// - Writes batches atomically to disk segments via `spawn_blocking` (never blocking Tokio workers)
/// - Maintains bounded per-(node, role, minute, service) summaries and visitor fingerprint observations
pub struct NodeLogger {
    node_tag: String,
    cfg: Arc<RwLock<Arc<LoggerConfig>>>,
    writer: Arc<StdMutex<SegmentWriter<SessionSummary>>>,
    minute_buckets: Arc<Mutex<HashMap<(i64, String, String), MinuteSummary>>>,
    fp_observations: Arc<Mutex<HashMap<String, FingerprintObservation>>>,
    recent_records: Arc<Mutex<Vec<SessionSummary>>>,
    recent_bytes: Arc<Mutex<usize>>,
    alerts: Arc<Mutex<Vec<AlertRecord>>>,
    flush_notify: Arc<Notify>,
}

impl NodeLogger {
    pub fn new(node_tag: impl Into<String>, cfg: LoggerConfig) -> Result<Arc<Self>> {
        let tag = node_tag.into();
        let cfg = ensure_strong_hmac_key(cfg);
        let writer = SegmentWriter::new(cfg.segment.clone(), &tag)?;

        // Restore unsent summaries, fingerprints, and alerts from disk checkpoint on restart
        let mut init_buckets = HashMap::new();
        let mut init_fps = HashMap::new();
        let mut init_alerts = Vec::new();
        let cp_path = node_checkpoint_path(&cfg.segment.dir, &tag);
        let retention_secs = (cfg.segment.retention_hours.max(1) as i64).saturating_mul(3600);
        let cutoff = Utc::now().timestamp().saturating_sub(retention_secs);
        if let Ok(Some(cp)) = read_json_snapshot::<NodeLoggerCheckpoint>(&cp_path) {
            for s in cp.summaries.into_iter().take(MAX_MINUTE_BUCKETS) {
                if s.minute_epoch >= cutoff && s.uv_hll.is_valid() {
                    init_buckets.insert((s.minute_epoch, s.role.clone(), s.service_tag.clone()), s);
                }
            }
            for mut fp in cp.fingerprints.into_iter().take(MAX_FP_OBSERVATIONS) {
                if fp.last_seen_ts >= cutoff {
                    fp.sanitize();
                    if !fp.id.is_empty() {
                        init_fps.insert(fp.id.clone(), fp);
                    }
                }
            }
            init_alerts = cp.alerts.into_iter().take(200).collect();
        }

        Ok(Arc::new(Self {
            node_tag: tag,
            cfg: Arc::new(RwLock::new(Arc::new(cfg))),
            writer: Arc::new(StdMutex::new(writer)),
            minute_buckets: Arc::new(Mutex::new(init_buckets)),
            fp_observations: Arc::new(Mutex::new(init_fps)),
            recent_records: Arc::new(Mutex::new(Vec::new())),
            recent_bytes: Arc::new(Mutex::new(0)),
            alerts: Arc::new(Mutex::new(init_alerts)),
            flush_notify: Arc::new(Notify::new()),
        }))
    }

    /// Awaits an early-flush notification fired whenever pending batch records or bytes reach configured limits.
    pub async fn wait_early_flush(&self) {
        self.flush_notify.notified().await;
    }

    pub async fn update_config(&self, new_cfg: LoggerConfig) -> Result<()> {
        let new_cfg = ensure_strong_hmac_key(new_cfg);
        let writer = Arc::clone(&self.writer);
        let seg_cfg = new_cfg.segment.clone();
        let tag = self.node_tag.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut guard = writer.lock().unwrap_or_else(|e| e.into_inner());
            let _ = guard.flush();
            *guard = SegmentWriter::new(seg_cfg, &tag)?;
            Ok(())
        })
        .await
        .map_err(|e| exposure_core::ExposureError::Storage(format!("logger update join: {e}")))??;

        *self.cfg.write().await = Arc::new(new_cfg);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_session(
        &self,
        role: &str,
        service_tag: &str,
        client_ip: &str,
        status: u16,
        latency_ms: f64,
        bytes_in: u64,
        bytes_out: u64,
        rate_limited: bool,
        challenged: bool,
        challenge_passed: bool,
        error: Option<String>,
    ) {
        self.record_session_with_fp(
            role,
            service_tag,
            client_ip,
            status,
            latency_ms,
            bytes_in,
            bytes_out,
            rate_limited,
            challenged,
            challenge_passed,
            error,
            None,
            None,
            None,
            false,
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_session_with_fp(
        &self,
        role: &str,
        service_tag: &str,
        client_ip: &str,
        status: u16,
        latency_ms: f64,
        bytes_in: u64,
        bytes_out: u64,
        rate_limited: bool,
        challenged: bool,
        challenge_passed: bool,
        error: Option<String>,
        device_type: Option<String>,
        browser_family: Option<String>,
        os_family: Option<String>,
        client_fp_verified: bool,
    ) {
        let cfg = Arc::clone(&*self.cfg.read().await);

        let sampled = if cfg.sample_rate >= 1.0 {
            true
        } else if cfg.sample_rate <= 0.0 {
            false
        } else {
            rand::thread_rng().r#gen::<f64>() < cfg.sample_rate
        };

        let now = Utc::now();
        let canon_ip = canonical_ip_str(client_ip);
        let ip_tag = hmac_ip(&cfg.hmac_key, &canon_ip);
        let rec = SessionSummary {
            timestamp_ms: now.timestamp_millis(),
            node_tag: self.node_tag.clone(),
            role: role.to_string(),
            service_tag: service_tag.to_string(),
            status,
            latency_ms,
            bytes_in,
            bytes_out,
            ip_hmac: ip_tag,
            raw_ip: if cfg.store_raw_ip {
                Some(canon_ip)
            } else {
                None
            },
            rate_limited,
            challenged,
            challenge_passed,
            error: error.map(sanitize_alert_msg),
            device_type,
            browser_family,
            os_family,
            client_fp_verified,
        };

        // Minute summary aggregates accurate counts/HLL/histograms with rolling eviction
        let minute_epoch = (now.timestamp() / 60) * 60;
        {
            let mut buckets = self.minute_buckets.lock().await;
            if buckets.len() >= MAX_MINUTE_BUCKETS {
                let cutoff = now.timestamp().saturating_sub(MINUTE_BUCKET_RETENTION_SECS);
                buckets.retain(|(min, _, _), _| *min >= cutoff);
                if buckets.len() >= MAX_MINUTE_BUCKETS {
                    buckets.clear();
                }
            }
            let entry = buckets
                .entry((minute_epoch, role.to_string(), service_tag.to_string()))
                .or_insert_with(|| {
                    MinuteSummary::new(
                        minute_epoch,
                        &self.node_tag,
                        role,
                        service_tag,
                        cfg.hll_precision,
                        cfg.hll_seed,
                        cfg.histogram_buckets_ms.clone(),
                    )
                });
            entry.record(&rec);
        }

        if sampled {
            let est_bytes = serde_json::to_vec(&rec).map(|v| v.len() + 1).unwrap_or(256);
            let writer = Arc::clone(&self.writer);
            let rec_disk = rec.clone();
            let disk_flushed = tokio::task::spawn_blocking(move || {
                let mut w = writer.lock().unwrap_or_else(|e| e.into_inner());
                match w.push(rec_disk) {
                    Ok(flushed) => flushed,
                    Err(e) => {
                        warn!(error = %e, "failed to push session segment record");
                        false
                    }
                }
            })
            .await
            .unwrap_or(false);

            let (rec_len, byte_len) = {
                let mut recent = self.recent_records.lock().await;
                let mut bytes = self.recent_bytes.lock().await;
                if recent.len() < MAX_RECENT_RECORDS {
                    recent.push(rec);
                    *bytes = bytes.saturating_add(est_bytes);
                }
                (recent.len(), *bytes)
            };

            let max_recs = cfg.segment.max_batch_records.clamp(1, MAX_RECENT_RECORDS);
            let max_bytes = cfg.segment.max_batch_bytes.max(4096);
            if disk_flushed || rec_len >= max_recs || byte_len >= max_bytes {
                self.flush_notify.notify_one();
            }
        }
    }

    pub async fn emit_alert(&self, severity: &str, message: impl Into<String>) {
        let mut alerts = self.alerts.lock().await;
        alerts.push(AlertRecord {
            timestamp: Utc::now().to_rfc3339(),
            source: self.node_tag.clone(),
            severity: severity.to_string(),
            message: sanitize_alert_msg(message.into()),
        });
        if alerts.len() > 200 {
            let drain = alerts.len() - 200;
            alerts.drain(0..drain);
        }
    }

    pub async fn recent_alerts(&self) -> Vec<AlertRecord> {
        self.alerts.lock().await.clone()
    }

    pub async fn flush_segments(&self) -> Result<()> {
        let writer = Arc::clone(&self.writer);
        let dir = self.cfg.read().await.segment.dir.clone();
        let cp_path = node_checkpoint_path(&dir, &self.node_tag);
        let cp = NodeLoggerCheckpoint {
            summaries: self.minute_buckets.lock().await.values().cloned().collect(),
            fingerprints: self.fp_observations.lock().await.values().cloned().collect(),
            alerts: self.alerts.lock().await.clone(),
        };
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut w = writer.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(path) = w.flush()? {
                debug!(path = %path.display(), "flushed node segment file");
            }
            if let Err(e) = write_json_snapshot_atomic(&cp_path, &cp) {
                warn!(path = %cp_path.display(), error = %e, "failed to persist node logger checkpoint");
            }
            Ok(())
        })
        .await
        .map_err(|e| exposure_core::ExposureError::Storage(format!("flush join: {e}")))?
    }

    /// Record or enrich a visitor + browser fingerprint observation (server UA/TLS/AbuseIPDB + optional JS beacon/PoW).
    #[allow(clippy::too_many_arguments)]
    pub async fn record_fingerprint(
        &self,
        service_tag: &str,
        host: &str,
        client_ip: &str,
        fp_hash: &str,
        js_verified: bool,
        fp_source: &str,
        user_agent: &str,
        accept_language: &str,
        device_type: &str,
        browser_family: &str,
        os_family: &str,
        is_bot: bool,
        is_headless: bool,
        suspicion_score: u8,
        tls_cipher_count: u16,
        tls_alpn: bool,
        js_fp: Option<ClientJsFingerprint>,
        request_inc: u64,
        challenge_inc: u64,
        rate_limited_inc: u64,
    ) {
        self.record_fingerprint_with_extras(
            service_tag,
            host,
            client_ip,
            fp_hash,
            js_verified,
            fp_source,
            user_agent,
            accept_language,
            device_type,
            browser_family,
            os_family,
            is_bot,
            is_headless,
            suspicion_score,
            tls_cipher_count,
            tls_alpn,
            FpServerExtras::default(),
            js_fp,
            request_inc,
            challenge_inc,
            rate_limited_inc,
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_fingerprint_with_extras(
        &self,
        service_tag: &str,
        host: &str,
        client_ip: &str,
        fp_hash: &str,
        js_verified: bool,
        fp_source: &str,
        user_agent: &str,
        accept_language: &str,
        device_type: &str,
        browser_family: &str,
        os_family: &str,
        is_bot: bool,
        is_headless: bool,
        suspicion_score: u8,
        tls_cipher_count: u16,
        tls_alpn: bool,
        extras: FpServerExtras<'_>,
        js_fp: Option<ClientJsFingerprint>,
        request_inc: u64,
        challenge_inc: u64,
        rate_limited_inc: u64,
    ) {
        let cfg = Arc::clone(&*self.cfg.read().await);
        let now_ts = Utc::now().timestamp();
        let canon_ip = canonical_ip_str(client_ip);
        let ip_tag = hmac_ip(&cfg.hmac_key, &canon_ip);
        let prefix = ip_subnet_label(&canon_ip);
        let id = format!("{ip_tag}:{fp_hash}");

        let mut obs = FingerprintObservation {
            id: id.clone(),
            ip_hmac: ip_tag,
            client_ip: if cfg.store_raw_ip { Some(canon_ip) } else { None },
            ip_prefix: prefix,
            fp_hash: fp_hash.to_string(),
            js_verified,
            fp_source: fp_source.to_string(),
            node_tag: self.node_tag.clone(),
            service_tag: service_tag.to_string(),
            host: host.to_string(),
            user_agent: user_agent.to_string(),
            accept_language: accept_language.to_string(),
            device_type: device_type.to_string(),
            browser_family: browser_family.to_string(),
            os_family: os_family.to_string(),
            is_bot,
            is_headless,
            suspicion_score,
            tls_cipher_count,
            tls_alpn,
            tls_ja3: extras.tls_ja3.map(str::to_string),
            tls_grease: extras.tls_grease,
            abuse_score: extras.abuse_score,
            abuse_country: extras.abuse_country.map(str::to_string),
            abuse_isp: extras.abuse_isp.map(str::to_string),
            abuse_is_tor: extras.abuse_is_tor,
            js_fp,
            first_seen_ts: now_ts,
            last_seen_ts: now_ts,
            request_count: request_inc,
            challenge_count: challenge_inc,
            rate_limited_count: rate_limited_inc,
        };
        obs.sanitize();

        let mut map = self.fp_observations.lock().await;
        if map.len() >= MAX_FP_OBSERVATIONS && !map.contains_key(&obs.id) {
            let cutoff = now_ts.saturating_sub(FP_RETENTION_SECS);
            map.retain(|_, v| v.last_seen_ts >= cutoff);
            if map.len() >= MAX_FP_OBSERVATIONS {
                // Evict oldest 25% entries
                let mut entries: Vec<(String, i64)> =
                    map.iter().map(|(k, v)| (k.clone(), v.last_seen_ts)).collect();
                entries.sort_by_key(|(_, ts)| *ts);
                for (k, _) in entries.into_iter().take(MAX_FP_OBSERVATIONS / 4) {
                    map.remove(&k);
                }
            }
        }
        map.entry(obs.id.clone())
            .and_modify(|existing| existing.merge_from(&obs))
            .or_insert(obs);
    }

    /// Drain pending minute summaries, sampled records, and fingerprint observations to send to Maintainer.
    pub async fn drain_for_maintainer(
        &self,
    ) -> (
        Vec<SessionSummary>,
        Vec<MinuteSummary>,
        Vec<FingerprintObservation>,
    ) {
        let records = {
            let mut r = self.recent_records.lock().await;
            let mut b = self.recent_bytes.lock().await;
            *b = 0;
            std::mem::take(&mut *r)
        };
        let summaries = {
            let mut b = self.minute_buckets.lock().await;
            b.drain().map(|(_, v)| v).collect()
        };
        let fingerprints = {
            let mut f = self.fp_observations.lock().await;
            f.drain().map(|(_, v)| v).collect()
        };
        (records, summaries, fingerprints)
    }

    /// Requeue drained records, summaries, and fingerprints if pushing a LogBatch to Maintainer fails transiently.
    pub async fn requeue_for_maintainer(
        &self,
        records: Vec<SessionSummary>,
        summaries: Vec<MinuteSummary>,
        fingerprints: Vec<FingerprintObservation>,
    ) {
        if !records.is_empty() {
            let mut r = self.recent_records.lock().await;
            let mut bytes = self.recent_bytes.lock().await;
            for rec in records {
                if r.len() >= MAX_RECENT_RECORDS {
                    break;
                }
                *bytes = bytes.saturating_add(256);
                r.push(rec);
            }
        }
        if !summaries.is_empty() {
            let mut b = self.minute_buckets.lock().await;
            let cutoff = Utc::now()
                .timestamp()
                .saturating_sub(MINUTE_BUCKET_RETENTION_SECS);
            for s in summaries {
                if s.minute_epoch < cutoff {
                    continue;
                }
                let key = (s.minute_epoch, s.role.clone(), s.service_tag.clone());
                if b.len() >= MAX_MINUTE_BUCKETS && !b.contains_key(&key) {
                    break;
                }
                b.entry(key)
                    .and_modify(|existing| existing.merge_from(&s))
                    .or_insert(s);
            }
        }
        if !fingerprints.is_empty() {
            let mut f = self.fp_observations.lock().await;
            let cutoff = Utc::now().timestamp().saturating_sub(FP_RETENTION_SECS);
            for fp in fingerprints {
                if fp.last_seen_ts < cutoff {
                    continue;
                }
                if f.len() >= MAX_FP_OBSERVATIONS && !f.contains_key(&fp.id) {
                    break;
                }
                f.entry(fp.id.clone())
                    .and_modify(|existing| existing.merge_from(&fp))
                    .or_insert(fp);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exposure_core::config::SegmentConfig;

    #[tokio::test]
    async fn node_logger_persists_checkpoint_and_triggers_early_flush() {
        let dir = std::env::temp_dir().join(format!("exposure-nlog-test-{}", uuid::Uuid::new_v4()));
        let cfg = LoggerConfig {
            hmac_key: "test-hmac-key-0123456789abcdef0123456789".into(),
            segment: SegmentConfig {
                dir: dir.to_string_lossy().to_string(),
                max_batch_records: 2,
                max_batch_bytes: 512 * 1024,
                ..Default::default()
            },
            ..Default::default()
        };

        let logger = NodeLogger::new("edge-1", cfg.clone()).unwrap();
        // Record 2 requests -> hits max_batch_records = 2 -> triggers early flush notify
        logger
            .record_session("ingress", "web", "203.0.113.5", 200, 12.0, 100, 500, false, false, false, None)
            .await;
        logger
            .record_session("ingress", "web", "203.0.113.6", 200, 18.0, 120, 600, false, false, false, None)
            .await;
        // wait_early_flush should resolve immediately because notify_one() stored a permit
        tokio::time::timeout(std::time::Duration::from_millis(200), logger.wait_early_flush())
            .await
            .expect("early flush should have been signalled on batch threshold");

        logger.flush_segments().await.unwrap();

        // Simulate restart: brand-new NodeLogger pointing at the same dir must restore summaries!
        let restored = NodeLogger::new("edge-1", cfg).unwrap();
        let (_, sums, _) = restored.drain_for_maintainer().await;
        assert_eq!(sums.len(), 1);
        assert_eq!(sums[0].requests, 2);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
