use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use exposure_core::config::LoggerConfig;
use exposure_core::crypto::hmac_ip;
use exposure_core::segment::SegmentWriter;
use exposure_core::telemetry::{AlertRecord, MinuteSummary, SessionSummary};
use exposure_core::Result;
use rand::Rng;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, warn};

/// Production-layer Node logger (DESIGN.md §4 & §12):
/// - Applies configured `sample_rate`
/// - Stores HMAC IP by default; raw IP only when `store_raw_ip: true`
/// - Writes batches atomically to disk segments (on batch full, timer, or SIGINT/SIGTERM)
/// - Maintains per-(node, minute, service) summaries for periodic push to Maintainer
pub struct NodeLogger {
    node_tag: String,
    cfg: Arc<RwLock<LoggerConfig>>,
    writer: Arc<Mutex<SegmentWriter<SessionSummary>>>,
    minute_buckets: Arc<Mutex<HashMap<(i64, String), MinuteSummary>>>,
    recent_records: Arc<Mutex<Vec<SessionSummary>>>,
    alerts: Arc<Mutex<Vec<AlertRecord>>>,
}

impl NodeLogger {
    pub fn new(node_tag: impl Into<String>, cfg: LoggerConfig) -> Result<Arc<Self>> {
        let tag = node_tag.into();
        let writer = SegmentWriter::new(cfg.segment.clone(), &tag)?;
        Ok(Arc::new(Self {
            node_tag: tag,
            cfg: Arc::new(RwLock::new(cfg)),
            writer: Arc::new(Mutex::new(writer)),
            minute_buckets: Arc::new(Mutex::new(HashMap::new())),
            recent_records: Arc::new(Mutex::new(Vec::new())),
            alerts: Arc::new(Mutex::new(Vec::new())),
        }))
    }

    pub async fn update_config(&self, new_cfg: LoggerConfig) -> Result<()> {
        let mut guard = self.writer.lock().await;
        let _ = guard.flush();
        *guard = SegmentWriter::new(new_cfg.segment.clone(), &self.node_tag)?;
        drop(guard);
        *self.cfg.write().await = new_cfg;
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
        let cfg = self.cfg.read().await.clone();

        // Sampling rate truly takes effect for detailed session logs
        let sampled = if cfg.sample_rate >= 1.0 {
            true
        } else if cfg.sample_rate <= 0.0 {
            false
        } else {
            rand::thread_rng().gen::<f64>() < cfg.sample_rate
        };

        let now = Utc::now();
        let ip_tag = hmac_ip(&cfg.hmac_key, client_ip);
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
                Some(client_ip.to_string())
            } else {
                None
            },
            rate_limited,
            challenged,
            challenge_passed,
            error,
            device_type,
            browser_family,
            os_family,
            client_fp_verified,
        };

        // Minute summary always aggregates accurate counts/HLL/histograms
        let minute_epoch = (now.timestamp() / 60) * 60;
        {
            let mut buckets = self.minute_buckets.lock().await;
            let entry = buckets
                .entry((minute_epoch, service_tag.to_string()))
                .or_insert_with(|| {
                    MinuteSummary::new(
                        minute_epoch,
                        &self.node_tag,
                        service_tag,
                        cfg.hll_precision,
                        cfg.hll_seed,
                        cfg.histogram_buckets_ms.clone(),
                    )
                });
            entry.record(&rec);
        }

        if sampled {
            {
                let mut w = self.writer.lock().await;
                if let Err(e) = w.push(rec.clone()) {
                    warn!(error = %e, "failed to push session segment record");
                }
            }
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
            message: message.into(),
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
        let mut w = self.writer.lock().await;
        if let Some(path) = w.flush()? {
            debug!(path = %path.display(), "flushed node segment file");
        }
        Ok(())
    }

    /// Drain pending minute summaries & sampled records to send to Maintainer.
    pub async fn drain_for_maintainer(&self) -> (Vec<SessionSummary>, Vec<MinuteSummary>) {
        let records = {
            let mut r = self.recent_records.lock().await;
            std::mem::take(&mut *r)
        };
        let summaries = {
            let mut b = self.minute_buckets.lock().await;
            b.drain().map(|(_, v)| v).collect()
        };
        (records, summaries)
    }
}
