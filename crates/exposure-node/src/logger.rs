use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex as StdMutex};

use chrono::Utc;
use exposure_core::config::LoggerConfig;
use exposure_core::crypto::{generate_random_secret_hex, hmac_ip, is_weak_secret};
use exposure_core::routing::canonical_ip;
use exposure_core::segment::SegmentWriter;
use exposure_core::telemetry::{
    AlertRecord, ClientJsFingerprint, FingerprintObservation, MinuteSummary, SessionSummary,
};
use exposure_core::Result;
use rand::Rng;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, warn};

const MAX_MINUTE_BUCKETS: usize = 4096;
const MINUTE_BUCKET_RETENTION_SECS: i64 = 3600;
const MAX_FP_OBSERVATIONS: usize = 4096;
const FP_RETENTION_SECS: i64 = 3600 * 6;
const MAX_ALERT_MSG_LEN: usize = 512;

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
    alerts: Arc<Mutex<Vec<AlertRecord>>>,
}

impl NodeLogger {
    pub fn new(node_tag: impl Into<String>, cfg: LoggerConfig) -> Result<Arc<Self>> {
        let tag = node_tag.into();
        let cfg = ensure_strong_hmac_key(cfg);
        let writer = SegmentWriter::new(cfg.segment.clone(), &tag)?;
        Ok(Arc::new(Self {
            node_tag: tag,
            cfg: Arc::new(RwLock::new(Arc::new(cfg))),
            writer: Arc::new(StdMutex::new(writer)),
            minute_buckets: Arc::new(Mutex::new(HashMap::new())),
            fp_observations: Arc::new(Mutex::new(HashMap::new())),
            recent_records: Arc::new(Mutex::new(Vec::new())),
            alerts: Arc::new(Mutex::new(Vec::new())),
        }))
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
            rand::thread_rng().gen::<f64>() < cfg.sample_rate
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
            let writer = Arc::clone(&self.writer);
            let rec_disk = rec.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let mut w = writer.lock().unwrap_or_else(|e| e.into_inner());
                if let Err(e) = w.push(rec_disk) {
                    warn!(error = %e, "failed to push session segment record");
                }
            })
            .await;

            let mut recent = self.recent_records.lock().await;
            if recent.len() < 1024 {
                recent.push(rec);
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
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut w = writer.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(path) = w.flush()? {
                debug!(path = %path.display(), "flushed node segment file");
            }
            Ok(())
        })
        .await
        .map_err(|e| exposure_core::ExposureError::Storage(format!("flush join: {e}")))?
    }

    /// Record or enrich a visitor + browser fingerprint observation (server UA/TLS + optional JS beacon/PoW).
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
            for rec in records {
                if r.len() >= 1024 {
                    break;
                }
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
