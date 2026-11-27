use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use dashmap::DashMap;
use exposure_core::Result;
use exposure_core::config::{LogProtectionConfig, LoggerConfig};
use exposure_core::crypto::{generate_random_secret_hex, hmac_ip, is_weak_secret};
use exposure_core::routing::canonical_ip;
use exposure_core::segment::{SegmentWriter, read_json_snapshot, write_json_snapshot_atomic};
use exposure_core::telemetry::{
    AlertRecord, BanRecord, ClientJsFingerprint, EvilpotEventInfo, EvilpotSessionInfo,
    FingerprintObservation, LogProtectionStats, MinuteSummary, SessionSummary, is_autoban_action,
    is_cache_served_status, is_evilpot_action, is_security_block_action, normalize_alert_severity,
    sanitize_log_text,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify, RwLock};
use tracing::{debug, info, warn};

const MAX_MINUTE_BUCKETS: usize = 4096;
const MINUTE_BUCKET_RETENTION_SECS: i64 = 3600;
const MAX_FP_OBSERVATIONS: usize = 4096;
const FP_RETENTION_SECS: i64 = 3600 * 6;
const MAX_ALERT_MSG_LEN: usize = 512;
const MAX_ABUSE_BACKFILLS: usize = 1024;
const ABUSE_BACKFILL_TTL: std::time::Duration = std::time::Duration::from_secs(120);
const MAX_RECENT_RECORDS: usize = 4096;
const MAX_PENDING_DISK_RECORDS: usize = 8192;
const MAX_PER_IP_LOG_BUCKETS: usize = 16_384;
const MAX_FOLDED_LOG_KEYS: usize = 4096;
const MAX_WARN_KEYS: usize = 4096;
const MAX_ALERT_DEDUP_KEYS: usize = 1024;
const PER_IP_IDLE_TTL: Duration = Duration::from_secs(300);
const WARN_KEY_COOLDOWN: Duration = Duration::from_secs(5);
const ALERT_DEDUP_COOLDOWN: Duration = Duration::from_secs(30);

fn evict_half<K, V>(map: &DashMap<K, V>)
where
    K: Eq + std::hash::Hash,
{
    let to_remove = map.len() / 2;
    if to_remove == 0 {
        return;
    }
    let mut removed = 0usize;
    map.retain(|_, _| {
        if removed < to_remove {
            removed += 1;
            false
        } else {
            true
        }
    });
}

/// Extra unforgeable server-side signals attached to a visitor fingerprint observation.
#[derive(Debug, Clone, Default)]
pub struct FpServerExtras<'a> {
    pub tls_ja3: Option<&'a str>,
    pub tls_grease: bool,
    pub abuse_score: Option<u8>,
    pub abuse_country: Option<&'a str>,
    pub abuse_isp: Option<&'a str>,
    pub abuse_is_tor: bool,
    pub geo_country: Option<&'a str>,
    pub geo_continent: Option<&'a str>,
}

/// Rich HTTP request/security metadata recorded with each access log entry.
#[derive(Debug, Clone, Default)]
pub struct AccessLogMeta<'a> {
    pub ray_id: Option<&'a str>,
    pub method: Option<&'a str>,
    pub host: Option<&'a str>,
    pub path: Option<&'a str>,
    pub query: Option<&'a str>,
    pub protocol: Option<&'a str>,
    pub scheme: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub referer: Option<&'a str>,
    pub action: Option<&'a str>,
    pub cache_status: Option<&'a str>,
    pub tls_ja3: Option<&'a str>,
    pub waf_rule_id: Option<u32>,
    pub waf_category: Option<&'a str>,
    pub suspicion_score: Option<u8>,
    pub client_country: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogPriority {
    High,
    Normal,
    Low,
}

impl LogPriority {
    fn classify(status: u16, rate_limited: bool, action: Option<&str>) -> Self {
        if status >= 500
            || matches!(
                action,
                Some("evilpot" | "evilpot_canary" | "geo_evilpot" | "upstream_error")
            )
        {
            return Self::High;
        }
        if rate_limited
            || matches!(
                action,
                Some(
                    "autoban"
                        | "unmatched"
                        | "waf_block"
                        | "guard_reject"
                        | "abuseipdb"
                        | "geo_block"
                        | "geo_challenge"
                        | "challenge"
                        | "rate_limit"
                )
            )
        {
            return Self::Low;
        }
        Self::Normal
    }
}

#[derive(Debug, Clone)]
struct BucketState {
    tokens: f64,
    last_refill: Instant,
}

impl BucketState {
    fn new(capacity: f64, now: Instant) -> Self {
        Self {
            tokens: capacity,
            last_refill: now,
        }
    }

    fn try_consume(&mut self, capacity: f64, refill_per_sec: f64, now: Instant) -> bool {
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * refill_per_sec).min(capacity);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

struct FoldedLogEntry {
    template: SessionSummary,
    started_at: Instant,
    last_ts_ms: i64,
    suppressed_count: u32,
}

enum AdmitDecision {
    Emit(Box<SessionSummary>),
    Folded,
    Dropped,
}

/// Multi-layer anti-DoS log protection engine:
/// - Per-IP & global token buckets (with high-priority emergency reserve for 5xx/canary alerts)
/// - Per-minute byte budget preventing disk/mesh exhaustion
/// - Duplicate flood folding (collapses thousands of identical 429/403/404 flood lines into one
///   summary entry with `repeat_count`)
/// - Stdout `tracing::warn!` & `emit_alert` rate limiting
struct LogDoSGuard {
    global_bucket: StdMutex<BucketState>,
    high_reserve_bucket: StdMutex<BucketState>,
    warn_bucket: StdMutex<BucketState>,
    minute_bytes: StdMutex<(Instant, u64)>,
    per_ip_buckets: DashMap<String, BucketState>,
    folded: DashMap<(String, u16, String, String), FoldedLogEntry>,
    displaced_folded: StdMutex<Vec<SessionSummary>>,
    warn_cooldowns: DashMap<String, (Instant, u64)>,
    alert_cooldowns: DashMap<(String, String), Instant>,
    dropped_records: AtomicU64,
    folded_records: AtomicU64,
    warn_suppressed: AtomicU64,
}

impl LogDoSGuard {
    fn new(cfg: &LogProtectionConfig) -> Self {
        let now = Instant::now();
        let g_rate = cfg.max_records_per_sec.max(1) as f64;
        let w_rate = cfg.warn_rate_per_sec.max(1) as f64;
        Self {
            global_bucket: StdMutex::new(BucketState::new(g_rate * 2.0, now)),
            high_reserve_bucket: StdMutex::new(BucketState::new(64.0, now)),
            warn_bucket: StdMutex::new(BucketState::new(w_rate * 2.0, now)),
            minute_bytes: StdMutex::new((now, 0)),
            per_ip_buckets: DashMap::new(),
            folded: DashMap::new(),
            displaced_folded: StdMutex::new(Vec::new()),
            warn_cooldowns: DashMap::new(),
            alert_cooldowns: DashMap::new(),
            dropped_records: AtomicU64::new(0),
            folded_records: AtomicU64::new(0),
            warn_suppressed: AtomicU64::new(0),
        }
    }

    fn fold_key_raw(
        ip_hmac: &str,
        status: u16,
        action: Option<&str>,
        path: Option<&str>,
        overflow_wildcard: bool,
    ) -> (String, u16, String, String) {
        let act = action.map(|s| sanitize_log_text(s, 32)).unwrap_or_default();
        let path_k = if overflow_wildcard {
            "*".to_string()
        } else {
            path.unwrap_or("").chars().take(64).collect()
        };
        (ip_hmac.to_string(), status, act, path_k)
    }

    fn finalize_folded(is_wildcard: bool, mut entry: FoldedLogEntry) -> Option<SessionSummary> {
        if entry.suppressed_count == 0 {
            return None;
        }
        entry.template.timestamp_ms = entry.last_ts_ms;
        entry.template.repeat_count = entry.suppressed_count;
        // A folded row aggregates N *distinct* requests, so it must not keep the first request's
        // Ray ID: sharing it made the analytics layer group the aggregate with that one request,
        // which reported a phantom second proxy hop (`2 hops` on a single-hop request) and hid the
        // repeat count from the request totals.
        entry.template.ray_id = None;
        if is_wildcard {
            entry.template.path = Some("/* (folded flood)".to_string());
            entry.template.query = None;
        }
        entry.template.sanitize();
        Some(entry.template)
    }

    fn push_displaced(&self, summary: SessionSummary) {
        let mut disp = self
            .displaced_folded
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if disp.len() < MAX_FOLDED_LOG_KEYS {
            disp.push(summary);
        } else {
            self.dropped_records.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn try_fold(
        &self,
        now_ms: i64,
        key: &(String, u16, String, String),
        window: Duration,
        now: Instant,
    ) -> bool {
        if let Some(mut existing) = self.folded.get_mut(key) {
            if now.duration_since(existing.started_at) < window {
                existing.suppressed_count = existing.suppressed_count.saturating_add(1);
                existing.last_ts_ms = existing.last_ts_ms.max(now_ms);
                self.folded_records.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        false
    }

    fn arm_fold(
        &self,
        rec: &SessionSummary,
        key: (String, u16, String, String),
        initial_suppressed: u32,
        window: Duration,
        now: Instant,
    ) {
        if self.folded.len() >= MAX_FOLDED_LOG_KEYS && !self.folded.contains_key(&key) {
            // Drain expired entries first (emitting any accumulated suppressed counts instead of losing them).
            let expired_keys: Vec<(String, u16, String, String)> = self
                .folded
                .iter()
                .filter_map(|e| {
                    if now.duration_since(e.value().started_at) >= window {
                        Some(e.key().clone())
                    } else {
                        None
                    }
                })
                .collect();
            for ek in expired_keys {
                if let Some((rk, entry)) = self.folded.remove(&ek) {
                    if let Some(s) = Self::finalize_folded(rk.3 == "*", entry) {
                        self.push_displaced(s);
                    }
                }
            }
            // If still at capacity, evict half while preserving any accumulated suppressed counts.
            if self.folded.len() >= MAX_FOLDED_LOG_KEYS {
                let to_remove = self.folded.len() / 2;
                let victim_keys: Vec<(String, u16, String, String)> = self
                    .folded
                    .iter()
                    .take(to_remove)
                    .map(|e| e.key().clone())
                    .collect();
                for vk in victim_keys {
                    if let Some((rk, entry)) = self.folded.remove(&vk) {
                        if let Some(s) = Self::finalize_folded(rk.3 == "*", entry) {
                            self.push_displaced(s);
                        }
                    }
                }
            }
        }
        if let Some(old) = self.folded.insert(
            key.clone(),
            FoldedLogEntry {
                template: rec.clone(),
                started_at: now,
                last_ts_ms: rec.timestamp_ms,
                suppressed_count: initial_suppressed,
            },
        ) {
            if let Some(s) = Self::finalize_folded(key.3 == "*", old) {
                self.push_displaced(s);
            }
        }
    }

    fn admit<F>(
        &self,
        ip_hmac: &str,
        status: u16,
        action: Option<&str>,
        path: Option<&str>,
        now_ms: i64,
        est_bytes: usize,
        priority: LogPriority,
        cfg: &LogProtectionConfig,
        build_rec: F,
    ) -> AdmitDecision
    where
        F: FnOnce() -> SessionSummary,
    {
        if !cfg.enabled {
            return AdmitDecision::Emit(Box::new(build_rec()));
        }
        let now = Instant::now();
        let dedup_secs = cfg.dedup_window_secs.clamp(1, 300);
        let dedup_window = Duration::from_secs(dedup_secs);

        // 1. Fold duplicate low-priority flood events BEFORE building/serializing SessionSummary
        if priority == LogPriority::Low {
            let exact_key = Self::fold_key_raw(ip_hmac, status, action, path, false);
            if self.try_fold(now_ms, &exact_key, dedup_window, now) {
                return AdmitDecision::Folded;
            }
            let overflow_key = Self::fold_key_raw(ip_hmac, status, action, path, true);
            if self.try_fold(now_ms, &overflow_key, dedup_window, now) {
                return AdmitDecision::Folded;
            }
        }

        // 2. Per-IP token bucket (for Normal & Low priority; High priority bypasses per-IP limit)
        if priority != LogPriority::High && cfg.max_per_ip_per_sec > 0 {
            if self.per_ip_buckets.len() >= MAX_PER_IP_LOG_BUCKETS
                && !self.per_ip_buckets.contains_key(ip_hmac)
            {
                self.per_ip_buckets
                    .retain(|_, b| now.duration_since(b.last_refill) < PER_IP_IDLE_TTL);
                if self.per_ip_buckets.len() >= MAX_PER_IP_LOG_BUCKETS {
                    evict_half(&self.per_ip_buckets);
                }
            }
            let rate = cfg.max_per_ip_per_sec as f64;
            let cap = (rate * 2.0).max(2.0);
            let mut b = self
                .per_ip_buckets
                .entry(ip_hmac.to_string())
                .or_insert_with(|| BucketState::new(cap, now));
            if !b.try_consume(cap, rate, now) {
                drop(b);
                let overflow_key = Self::fold_key_raw(ip_hmac, status, action, path, true);
                if self.try_fold(now_ms, &overflow_key, dedup_window, now) {
                    return AdmitDecision::Folded;
                }
                let rec = build_rec();
                self.arm_fold(&rec, overflow_key, 1, dedup_window, now);
                self.folded_records.fetch_add(1, Ordering::Relaxed);
                return AdmitDecision::Folded;
            }
        }

        // 3. Global token bucket (with emergency reserve for High-priority 5xx / canary events)
        if cfg.max_records_per_sec > 0 {
            let rate = cfg.max_records_per_sec as f64;
            let cap = (rate * 2.0).max(2.0);
            let global_ok = self
                .global_bucket
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .try_consume(cap, rate, now);
            if !global_ok {
                let high_ok = priority == LogPriority::High
                    && self
                        .high_reserve_bucket
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .try_consume(64.0, 32.0, now);
                if !high_ok {
                    self.dropped_records.fetch_add(1, Ordering::Relaxed);
                    return AdmitDecision::Dropped;
                }
            }
        }

        // 4. Per-minute byte budget ceiling
        if cfg.max_bytes_per_min > 0 {
            let mut mb = self.minute_bytes.lock().unwrap_or_else(|e| e.into_inner());
            if now.duration_since(mb.0) >= Duration::from_secs(60) {
                *mb = (now, 0);
            }
            let cap_bytes = if priority == LogPriority::High {
                cfg.max_bytes_per_min
                    .saturating_add(cfg.max_bytes_per_min / 10)
            } else {
                cfg.max_bytes_per_min
            };
            if mb.1.saturating_add(est_bytes as u64) > cap_bytes {
                self.dropped_records.fetch_add(1, Ordering::Relaxed);
                return AdmitDecision::Dropped;
            }
            mb.1 = mb.1.saturating_add(est_bytes as u64);
        }

        let rec = build_rec();
        // Arm duplicate folder for Low-priority events after admitting the initial full URL record
        if priority == LogPriority::Low {
            let exact_key = Self::fold_key_raw(
                &rec.ip_hmac,
                rec.status,
                rec.action.as_deref(),
                rec.path.as_deref(),
                false,
            );
            self.arm_fold(&rec, exact_key, 0, dedup_window, now);
        }

        AdmitDecision::Emit(Box::new(rec))
    }

    fn drain_folded(&self, flush_all: bool, dedup_window: Duration) -> Vec<SessionSummary> {
        let now = Instant::now();
        let mut out = {
            let mut disp = self
                .displaced_folded
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *disp)
        };
        let expired_keys: Vec<(String, u16, String, String)> = self
            .folded
            .iter()
            .filter_map(|e| {
                if flush_all || now.duration_since(e.value().started_at) >= dedup_window {
                    Some(e.key().clone())
                } else {
                    None
                }
            })
            .collect();
        for k in expired_keys {
            if let Some((rk, entry)) = self.folded.remove(&k) {
                if let Some(s) = Self::finalize_folded(rk.3 == "*", entry) {
                    out.push(s);
                }
            }
        }
        out
    }

    fn should_log_warn(&self, key: &str, cfg: &LogProtectionConfig) -> Option<u64> {
        if !cfg.enabled {
            return Some(0);
        }
        let now = Instant::now();
        if cfg.warn_rate_per_sec > 0 {
            let rate = cfg.warn_rate_per_sec as f64;
            let cap = (rate * 2.0).max(2.0);
            let ok = self
                .warn_bucket
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .try_consume(cap, rate, now);
            if !ok {
                self.warn_suppressed.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }
        let k = sanitize_log_text(key, 64);
        if self.warn_cooldowns.len() >= MAX_WARN_KEYS && !self.warn_cooldowns.contains_key(&k) {
            self.warn_cooldowns
                .retain(|_, (ts, _)| now.duration_since(*ts) < WARN_KEY_COOLDOWN);
            if self.warn_cooldowns.len() >= MAX_WARN_KEYS {
                evict_half(&self.warn_cooldowns);
            }
        }
        if let Some(mut entry) = self.warn_cooldowns.get_mut(&k) {
            if now.duration_since(entry.0) < WARN_KEY_COOLDOWN {
                entry.1 = entry.1.saturating_add(1);
                self.warn_suppressed.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            let prev_suppressed = entry.1;
            *entry = (now, 0);
            Some(prev_suppressed)
        } else {
            self.warn_cooldowns.insert(k, (now, 0));
            Some(0)
        }
    }

    fn should_emit_alert(&self, severity: &str, msg: &str, enabled: bool) -> bool {
        if !enabled {
            return true;
        }
        let now = Instant::now();
        let prefix: String = msg.chars().take(64).collect();
        let key = (severity.to_string(), prefix);
        if self.alert_cooldowns.len() >= MAX_ALERT_DEDUP_KEYS
            && !self.alert_cooldowns.contains_key(&key)
        {
            self.alert_cooldowns
                .retain(|_, ts| now.duration_since(*ts) < ALERT_DEDUP_COOLDOWN);
            if self.alert_cooldowns.len() >= MAX_ALERT_DEDUP_KEYS {
                evict_half(&self.alert_cooldowns);
            }
        }
        if let Some(prev) = self.alert_cooldowns.get(&key) {
            if now.duration_since(*prev) < ALERT_DEDUP_COOLDOWN {
                return false;
            }
        }
        self.alert_cooldowns.insert(key, now);
        true
    }

    fn stats(&self) -> LogProtectionStats {
        LogProtectionStats {
            dropped_records: self.dropped_records.load(Ordering::Relaxed),
            folded_records: self.folded_records.load(Ordering::Relaxed),
            warn_suppressed: self.warn_suppressed.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Default)]
pub struct DrainedLogBatch {
    pub records: Vec<SessionSummary>,
    pub summaries: Vec<MinuteSummary>,
    pub fingerprints: Vec<FingerprintObservation>,
    pub evilpot_sessions: Vec<EvilpotSessionInfo>,
    pub evilpot_events: Vec<EvilpotEventInfo>,
    pub ban_records: Vec<BanRecord>,
    pub alerts: Vec<AlertRecord>,
}

impl DrainedLogBatch {
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
            && self.summaries.is_empty()
            && self.fingerprints.is_empty()
            && self.evilpot_sessions.is_empty()
            && self.evilpot_events.is_empty()
            && self.ban_records.is_empty()
            && self.alerts.is_empty()
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct NodeLoggerCheckpoint {
    #[serde(default)]
    summaries: Vec<MinuteSummary>,
    #[serde(default)]
    fingerprints: Vec<FingerprintObservation>,
    #[serde(default)]
    alerts: Vec<AlertRecord>,
    #[serde(default)]
    pending_evilpot_sessions: Vec<EvilpotSessionInfo>,
    #[serde(default)]
    pending_evilpot_events: Vec<EvilpotEventInfo>,
    #[serde(default)]
    pending_ban_records: Vec<BanRecord>,
    #[serde(default)]
    pending_alerts: Vec<AlertRecord>,
}

fn node_checkpoint_path(dir: &str, node_tag: &str) -> PathBuf {
    let safe: String = node_tag
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
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
/// - Always records 100% exact per-(node, role, minute, service) summaries (HLL UV, latency histograms)
/// - Sanitizes & redacts URL paths/queries/headers to prevent injection and secret leakage
/// - Protects disk, CPU, memory, and stdout from DoS log explosion via rate-limits, byte budgets, and flood folding
/// - Flushes batched JSONL segments atomically via `spawn_blocking` (never per-request)
pub struct NodeLogger {
    node_tag: String,
    cfg: Arc<RwLock<Arc<LoggerConfig>>>,
    writer: Arc<StdMutex<SegmentWriter<SessionSummary>>>,
    minute_buckets: Arc<Mutex<HashMap<(i64, String, String), MinuteSummary>>>,
    fp_observations: Arc<Mutex<HashMap<String, FingerprintObservation>>>,
    recent_abuse_backfills:
        Mutex<HashMap<String, (Instant, u8, Option<String>, Option<String>, bool)>>,
    pending_disk_records: Arc<Mutex<Vec<SessionSummary>>>,
    pending_disk_bytes: Arc<Mutex<usize>>,
    recent_records: Arc<Mutex<Vec<SessionSummary>>>,
    recent_bytes: Arc<Mutex<usize>>,
    alerts: Arc<Mutex<Vec<AlertRecord>>>,
    pending_evilpot_sessions: Arc<Mutex<HashMap<String, EvilpotSessionInfo>>>,
    pending_evilpot_events: Arc<Mutex<Vec<EvilpotEventInfo>>>,
    pending_ban_records: Arc<Mutex<Vec<BanRecord>>>,
    pending_alerts: Arc<Mutex<Vec<AlertRecord>>>,
    dos_guard: Arc<LogDoSGuard>,
    flush_notify: Arc<Notify>,
    dirty: AtomicBool,
}

impl NodeLogger {
    pub fn new(node_tag: impl Into<String>, cfg: LoggerConfig) -> Result<Arc<Self>> {
        let tag = node_tag.into();
        let cfg = ensure_strong_hmac_key(cfg);
        let writer = SegmentWriter::new(cfg.segment.clone(), &tag)?;
        let dos_guard = Arc::new(LogDoSGuard::new(&cfg.protection));

        // Restore unsent summaries, fingerprints, alerts, evilpot/ban deltas from disk checkpoint on restart
        let mut init_buckets = HashMap::new();
        let mut init_fps = HashMap::new();
        let mut init_alerts = Vec::new();
        let mut init_ep_sessions = HashMap::new();
        let mut init_ep_events = Vec::new();
        let mut init_ban_records = Vec::new();
        let mut init_pending_alerts = Vec::new();
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
            for s in cp.pending_evilpot_sessions.into_iter().take(512) {
                init_ep_sessions.insert(s.client_ip.clone(), s);
            }
            init_ep_events = cp.pending_evilpot_events.into_iter().take(1024).collect();
            init_ban_records = cp.pending_ban_records.into_iter().take(1024).collect();
            init_pending_alerts = cp.pending_alerts.into_iter().take(512).collect();
        }

        Ok(Arc::new(Self {
            node_tag: tag,
            cfg: Arc::new(RwLock::new(Arc::new(cfg))),
            writer: Arc::new(StdMutex::new(writer)),
            minute_buckets: Arc::new(Mutex::new(init_buckets)),
            fp_observations: Arc::new(Mutex::new(init_fps)),
            recent_abuse_backfills: Mutex::new(HashMap::new()),
            pending_disk_records: Arc::new(Mutex::new(Vec::new())),
            pending_disk_bytes: Arc::new(Mutex::new(0)),
            recent_records: Arc::new(Mutex::new(Vec::new())),
            recent_bytes: Arc::new(Mutex::new(0)),
            alerts: Arc::new(Mutex::new(init_alerts)),
            pending_evilpot_sessions: Arc::new(Mutex::new(init_ep_sessions)),
            pending_evilpot_events: Arc::new(Mutex::new(init_ep_events)),
            pending_ban_records: Arc::new(Mutex::new(init_ban_records)),
            pending_alerts: Arc::new(Mutex::new(init_pending_alerts)),
            dos_guard,
            flush_notify: Arc::new(Notify::new()),
            dirty: AtomicBool::new(false),
        }))
    }

    /// Awaits an early-flush notification fired whenever pending batch records or bytes reach configured limits.
    pub async fn wait_early_flush(&self) {
        self.flush_notify.notified().await;
    }

    pub fn protection_stats(&self) -> LogProtectionStats {
        self.dos_guard.stats()
    }

    pub fn segment_dir(&self) -> PathBuf {
        self.cfg
            .try_read()
            .map(|c| PathBuf::from(&c.segment.dir))
            .unwrap_or_else(|_| PathBuf::from("./data/segments"))
    }

    /// Rate-limited warning check preventing stdout log flooding under DDoS.
    /// Returns `Some(suppressed_since_last)` when logging is permitted, `None` when throttled.
    pub fn should_log_warn(&self, key: &str) -> Option<u64> {
        let prot = self
            .cfg
            .try_read()
            .map(|c| c.protection.clone())
            .unwrap_or_default();
        self.dos_guard.should_log_warn(key, &prot)
    }

    pub async fn update_config(&self, mut new_cfg: LoggerConfig) -> Result<()> {
        if is_weak_secret(&new_cfg.hmac_key) {
            new_cfg.hmac_key = self.cfg.read().await.hmac_key.clone();
        }
        let writer = Arc::clone(&self.writer);
        let seg_cfg = new_cfg.segment.clone();
        let tag = self.node_tag.clone();
        let pending = {
            let mut p = self.pending_disk_records.lock().await;
            let mut pb = self.pending_disk_bytes.lock().await;
            *pb = 0;
            std::mem::take(&mut *p)
        };
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut guard = writer.lock().unwrap_or_else(|e| e.into_inner());
            let _ = guard.push_batch(pending);
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
        self.record_access_log(
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
            AccessLogMeta::default(),
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_access_log(
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
        meta: AccessLogMeta<'_>,
    ) {
        let cfg = Arc::clone(&*self.cfg.read().await);

        let now = Utc::now();
        let now_ms = now.timestamp_millis();
        let canon_ip = canonical_ip_str(client_ip);
        let ip_tag = hmac_ip(&cfg.hmac_key, &canon_ip);
        let priority = LogPriority::classify(status, rate_limited, meta.action);

        let clean_device = device_type
            .map(|s| sanitize_log_text(&s, 32))
            .filter(|s| !s.is_empty());
        let clean_browser = browser_family
            .map(|s| sanitize_log_text(&s, 32))
            .filter(|s| !s.is_empty());
        let clean_os = os_family
            .map(|s| sanitize_log_text(&s, 32))
            .filter(|s| !s.is_empty());

        // 1. Always update exact minute summary metrics BEFORE sampling / DoS log folding
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
            entry.requests = entry.requests.saturating_add(1);
            if status >= 500 {
                entry.errors = entry.errors.saturating_add(1);
            }
            if rate_limited {
                entry.rate_limited = entry.rate_limited.saturating_add(1);
            }
            if challenged {
                entry.challenges_issued = entry.challenges_issued.saturating_add(1);
            } else if !rate_limited && status < 500 && is_security_block_action(meta.action) {
                entry.blocked = entry.blocked.saturating_add(1);
            }
            if is_evilpot_action(meta.action) {
                entry.evilpot_hits = entry.evilpot_hits.saturating_add(1);
            }
            if is_autoban_action(meta.action) {
                entry.autoban_hits = entry.autoban_hits.saturating_add(1);
            }
            if challenge_passed {
                entry.challenges_passed = entry.challenges_passed.saturating_add(1);
            }
            if client_fp_verified {
                entry.client_fp_verified = entry.client_fp_verified.saturating_add(1);
            }
            if let Some(ref d) = clean_device {
                let e = entry.device_counts.entry(d.clone()).or_insert(0);
                *e = e.saturating_add(1);
            }
            if let Some(ref b) = clean_browser {
                let e = entry.browser_counts.entry(b.clone()).or_insert(0);
                *e = e.saturating_add(1);
            }
            if let Some(ref o) = clean_os {
                let e = entry.os_counts.entry(o.clone()).or_insert(0);
                *e = e.saturating_add(1);
            }
            entry.bytes_in = entry.bytes_in.saturating_add(bytes_in);
            entry.bytes_out = entry.bytes_out.saturating_add(bytes_out);
            if is_cache_served_status(meta.cache_status) {
                entry.cached_requests = entry.cached_requests.saturating_add(1);
                entry.cached_bytes_out = entry.cached_bytes_out.saturating_add(bytes_out);
            }
            entry.uv_hll.insert(&ip_tag);
            entry.latency_hist.observe(latency_ms);
        }
        self.dirty.store(true, Ordering::Relaxed);

        let never_sample = priority == LogPriority::High
            || is_security_block_action(meta.action)
            || meta.action == Some("waf_monitor");
        let sampled = if cfg.sample_rate >= 1.0 || never_sample {
            true
        } else if cfg.sample_rate <= 0.0 {
            false
        } else {
            rand::thread_rng().r#gen::<f64>() < cfg.sample_rate
        };
        if !sampled {
            return;
        }

        let est_bytes = 200usize
            .saturating_add(meta.path.map(|s| s.len().min(512)).unwrap_or(0))
            .saturating_add(if cfg.protection.log_query_string {
                meta.query.map(|s| s.len().min(512)).unwrap_or(0)
            } else {
                0
            })
            .saturating_add(meta.user_agent.map(|s| s.len().min(192)).unwrap_or(0))
            .saturating_add(meta.referer.map(|s| s.len().min(512)).unwrap_or(0))
            .saturating_add(error.as_ref().map(|s| s.len().min(256)).unwrap_or(0));

        // 2. Evaluate anti-DoS log protection BEFORE allocating/sanitizing SessionSummary fields
        let rec = match self.dos_guard.admit(
            &ip_tag,
            status,
            meta.action,
            meta.path,
            now_ms,
            est_bytes,
            priority,
            &cfg.protection,
            || {
                let mut rec = SessionSummary {
                    timestamp_ms: now_ms,
                    node_tag: self.node_tag.clone(),
                    role: role.to_string(),
                    service_tag: service_tag.to_string(),
                    status,
                    latency_ms,
                    bytes_in,
                    bytes_out,
                    ip_hmac: ip_tag.clone(),
                    raw_ip: if cfg.store_raw_ip {
                        Some(canon_ip)
                    } else {
                        None
                    },
                    client_country: meta.client_country.map(str::to_string),
                    rate_limited,
                    challenged,
                    challenge_passed,
                    error,
                    device_type: clean_device,
                    browser_family: clean_browser,
                    os_family: clean_os,
                    client_fp_verified,
                    ray_id: meta.ray_id.map(str::to_string),
                    method: meta.method.map(str::to_string),
                    host: meta.host.map(str::to_string),
                    path: meta.path.map(str::to_string),
                    query: if cfg.protection.log_query_string {
                        meta.query.map(str::to_string)
                    } else {
                        None
                    },
                    protocol: meta.protocol.map(str::to_string),
                    scheme: meta.scheme.map(str::to_string),
                    user_agent: meta.user_agent.map(str::to_string),
                    referer: meta.referer.map(str::to_string),
                    action: meta.action.map(str::to_string),
                    cache_status: meta.cache_status.map(str::to_string),
                    tls_ja3: meta.tls_ja3.map(str::to_string),
                    waf_rule_id: meta.waf_rule_id,
                    waf_category: meta.waf_category.map(str::to_string),
                    suspicion_score: meta.suspicion_score,
                    repeat_count: 1,
                };
                rec.sanitize();
                rec
            },
        ) {
            AdmitDecision::Emit(rec) => *rec,
            AdmitDecision::Folded | AdmitDecision::Dropped => return,
        };

        if cfg.protection.access_log_stdout {
            info!(
                target: "exposure::access",
                node = %rec.node_tag,
                role = %rec.role,
                service = %rec.service_tag,
                ray_id = rec.ray_id.as_deref().unwrap_or("-"),
                method = rec.method.as_deref().unwrap_or("-"),
                host = rec.host.as_deref().unwrap_or("-"),
                path = rec.path.as_deref().unwrap_or("-"),
                status = rec.status,
                action = rec.action.as_deref().unwrap_or("-"),
                latency_ms = rec.latency_ms,
                ip_hmac = %rec.ip_hmac,
                "access"
            );
        }

        // 3. Buffer in bounded memory for batched disk flush & Maintainer push (zero per-request fsync!)
        let (disk_len, disk_bytes) = {
            let mut pending = self.pending_disk_records.lock().await;
            let mut pbytes = self.pending_disk_bytes.lock().await;
            if pending.len() < MAX_PENDING_DISK_RECORDS {
                pending.push(rec.clone());
                *pbytes = pbytes.saturating_add(est_bytes);
            } else {
                self.dos_guard
                    .dropped_records
                    .fetch_add(1, Ordering::Relaxed);
            }
            (pending.len(), *pbytes)
        };

        let (rec_len, byte_len) = {
            let mut recent = self.recent_records.lock().await;
            let mut bytes = self.recent_bytes.lock().await;
            if recent.len() < MAX_RECENT_RECORDS {
                recent.push(rec);
                *bytes = bytes.saturating_add(est_bytes);
            } else if priority == LogPriority::High {
                // Preserve high-priority errors/exploits by displacing the oldest low/normal record
                if let Some(pos) = recent.iter().position(|r| {
                    LogPriority::classify(r.status, r.rate_limited, r.action.as_deref())
                        != LogPriority::High
                }) {
                    recent.remove(pos);
                    recent.push(rec);
                }
            }
            (recent.len(), *bytes)
        };

        let max_recs = cfg.segment.max_batch_records.clamp(1, MAX_RECENT_RECORDS);
        let max_bytes = cfg.segment.max_batch_bytes.max(4096);
        if disk_len >= max_recs
            || disk_bytes >= max_bytes
            || rec_len >= max_recs
            || byte_len >= max_bytes
        {
            self.flush_notify.notify_one();
        }
    }

    async fn promote_expired_folded(&self, flush_all: bool) {
        let dedup_secs = self
            .cfg
            .read()
            .await
            .protection
            .dedup_window_secs
            .clamp(1, 300);
        let folded = self
            .dos_guard
            .drain_folded(flush_all, Duration::from_secs(dedup_secs));
        if folded.is_empty() {
            return;
        }
        {
            let mut pending = self.pending_disk_records.lock().await;
            let mut pbytes = self.pending_disk_bytes.lock().await;
            for rec in &folded {
                if pending.len() >= MAX_PENDING_DISK_RECORDS {
                    break;
                }
                pending.push(rec.clone());
                *pbytes = pbytes.saturating_add(256);
            }
        }
        {
            let mut recent = self.recent_records.lock().await;
            let mut bytes = self.recent_bytes.lock().await;
            for rec in folded {
                if recent.len() >= MAX_RECENT_RECORDS {
                    break;
                }
                recent.push(rec);
                *bytes = bytes.saturating_add(256);
            }
        }
    }

    pub async fn emit_alert(&self, severity: &str, message: impl Into<String>) {
        let raw_msg = message.into();
        let clean_msg = sanitize_alert_msg(raw_msg);
        let norm_sev = normalize_alert_severity(severity);
        let prot_enabled = self
            .cfg
            .try_read()
            .map(|c| c.protection.enabled)
            .unwrap_or(true);
        if !self
            .dos_guard
            .should_emit_alert(norm_sev, &clean_msg, prot_enabled)
        {
            return;
        }
        let now = Utc::now();
        let rec = AlertRecord {
            timestamp_ms: now.timestamp_millis(),
            timestamp: now.to_rfc3339(),
            source: self.node_tag.clone(),
            severity: norm_sev.to_string(),
            message: clean_msg,
        };
        {
            let mut alerts = self.alerts.lock().await;
            alerts.push(rec.clone());
            if alerts.len() > 200 {
                let drain = alerts.len() - 200;
                alerts.drain(0..drain);
            }
        }
        {
            let mut pending = self.pending_alerts.lock().await;
            if pending.len() < 512 {
                pending.push(rec);
            }
        }
        self.dirty.store(true, Ordering::Relaxed);
    }

    pub async fn record_evilpot_interaction(
        &self,
        mut session: EvilpotSessionInfo,
        mut event: EvilpotEventInfo,
    ) {
        if session.node_tag.is_empty() {
            session.node_tag = self.node_tag.clone();
        }
        if event.node_tag.is_empty() {
            event.node_tag = self.node_tag.clone();
        }
        {
            let mut sess = self.pending_evilpot_sessions.lock().await;
            if sess.len() < 1024 || sess.contains_key(&session.client_ip) {
                sess.insert(session.client_ip.clone(), session);
            }
        }
        {
            let mut evs = self.pending_evilpot_events.lock().await;
            if evs.len() < 2048 {
                evs.push(event);
            }
        }
        self.dirty.store(true, Ordering::Relaxed);
        self.flush_notify.notify_one();
    }

    pub async fn record_ban_records(&self, bans: Vec<BanRecord>) {
        if bans.is_empty() {
            return;
        }
        {
            let mut pending = self.pending_ban_records.lock().await;
            for mut b in bans {
                if pending.len() >= 2048 {
                    break;
                }
                if b.node_tag.is_empty() {
                    b.node_tag = self.node_tag.clone();
                }
                pending.push(b);
            }
        }
        self.dirty.store(true, Ordering::Relaxed);
        self.flush_notify.notify_one();
    }

    pub async fn recent_alerts(&self) -> Vec<AlertRecord> {
        self.alerts.lock().await.clone()
    }

    pub async fn flush_segments(&self) -> Result<()> {
        self.flush_segments_inner(false).await
    }

    /// Flush all buffered records AND all active folded flood summaries (e.g. on shutdown/tests).
    pub async fn flush_all(&self) -> Result<()> {
        self.flush_segments_inner(true).await
    }

    async fn flush_segments_inner(&self, flush_folded: bool) -> Result<()> {
        self.promote_expired_folded(flush_folded).await;
        let writer = Arc::clone(&self.writer);
        let dir = self.cfg.read().await.segment.dir.clone();
        let cp_path = node_checkpoint_path(&dir, &self.node_tag);
        let pending_disk = {
            let mut p = self.pending_disk_records.lock().await;
            let mut pb = self.pending_disk_bytes.lock().await;
            *pb = 0;
            std::mem::take(&mut *p)
        };
        let cp = if self.dirty.swap(false, Ordering::AcqRel) {
            Some(NodeLoggerCheckpoint {
                summaries: self.minute_buckets.lock().await.values().cloned().collect(),
                fingerprints: self
                    .fp_observations
                    .lock()
                    .await
                    .values()
                    .cloned()
                    .collect(),
                alerts: self.alerts.lock().await.clone(),
                pending_evilpot_sessions: self
                    .pending_evilpot_sessions
                    .lock()
                    .await
                    .values()
                    .cloned()
                    .collect(),
                pending_evilpot_events: self.pending_evilpot_events.lock().await.clone(),
                pending_ban_records: self.pending_ban_records.lock().await.clone(),
                pending_alerts: self.pending_alerts.lock().await.clone(),
            })
        } else {
            None
        };
        let cp_err = tokio::task::spawn_blocking(move || -> Result<bool> {
            let mut w = writer.lock().unwrap_or_else(|e| e.into_inner());
            if !pending_disk.is_empty() {
                w.push_batch(pending_disk)?;
            }
            if let Some(path) = w.flush()? {
                debug!(path = %path.display(), "flushed node segment file");
            }
            if let Some(cp) = cp {
                if let Err(e) = write_json_snapshot_atomic(&cp_path, &cp) {
                    warn!(path = %cp_path.display(), error = %e, "failed to persist node logger checkpoint");
                    return Ok(true);
                }
            }
            Ok(false)
        })
        .await
        .map_err(|e| exposure_core::ExposureError::Storage(format!("flush join: {e}")))??;
        if cp_err {
            self.dirty.store(true, Ordering::Relaxed);
        }
        Ok(())
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
            client_ip: if cfg.store_raw_ip {
                Some(canon_ip)
            } else {
                None
            },
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
            geo_country: extras.geo_country.map(str::to_string),
            geo_continent: extras.geo_continent.map(str::to_string),
            js_fp,
            first_seen_ts: now_ts,
            last_seen_ts: now_ts,
            request_count: request_inc,
            challenge_count: challenge_inc,
            rate_limited_count: rate_limited_inc,
        };
        if obs.abuse_score.is_none() {
            let mut bf = self.recent_abuse_backfills.lock().await;
            let now_inst = Instant::now();
            if let Some((ts, score, cc, isp, is_tor)) = bf.get(&obs.ip_hmac).cloned() {
                if now_inst.saturating_duration_since(ts) < ABUSE_BACKFILL_TTL {
                    obs.abuse_score = Some(score);
                    if obs.abuse_country.is_none() {
                        obs.abuse_country = cc;
                    }
                    if obs.abuse_isp.is_none() {
                        obs.abuse_isp = isp;
                    }
                    obs.abuse_is_tor |= is_tor;
                } else {
                    bf.remove(&obs.ip_hmac);
                }
            }
        }
        obs.sanitize();
        if !cfg.store_raw_ip {
            if let Some(ref mut js) = obs.js_fp {
                js.mask_raw_ips();
            }
        }

        let mut map = self.fp_observations.lock().await;
        if map.len() >= MAX_FP_OBSERVATIONS && !map.contains_key(&obs.id) {
            let cutoff = now_ts.saturating_sub(FP_RETENTION_SECS);
            map.retain(|_, v| v.last_seen_ts >= cutoff);
            if map.len() >= MAX_FP_OBSERVATIONS {
                // Evict oldest 25% entries
                let mut entries: Vec<(String, i64)> = map
                    .iter()
                    .map(|(k, v)| (k.clone(), v.last_seen_ts))
                    .collect();
                entries.sort_by_key(|(_, ts)| *ts);
                for (k, _) in entries.into_iter().take(MAX_FP_OBSERVATIONS / 4) {
                    map.remove(&k);
                }
            }
        }
        map.entry(obs.id.clone())
            .and_modify(|existing| existing.merge_from(&obs))
            .or_insert(obs);
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// Asynchronously backfills AbuseIPDB reputation into matching `FingerprintObservation` entries
    /// (by `ip_hmac`) when an initially slow lookup finishes in the background after `REQUEST_WAIT_BUDGET`.
    pub async fn backfill_abuse_report(
        &self,
        client_ip: &str,
        abuse_score: u8,
        abuse_country: Option<&str>,
        abuse_isp: Option<&str>,
        abuse_is_tor: bool,
    ) {
        let hmac_key = {
            let cfg = Arc::clone(&*self.cfg.read().await);
            cfg.hmac_key.clone()
        };
        let canon_ip = canonical_ip_str(client_ip);
        let ip_tag = hmac_ip(&hmac_key, &canon_ip);
        let cc_owned = abuse_country.map(str::to_string);
        let isp_owned = abuse_isp.map(str::to_string);

        {
            let now_inst = Instant::now();
            let mut bf = self.recent_abuse_backfills.lock().await;
            if bf.len() >= MAX_ABUSE_BACKFILLS && !bf.contains_key(&ip_tag) {
                bf.retain(|_, (ts, _, _, _, _)| {
                    now_inst.saturating_duration_since(*ts) < ABUSE_BACKFILL_TTL
                });
                if bf.len() >= MAX_ABUSE_BACKFILLS {
                    if let Some(oldest_k) = bf
                        .iter()
                        .min_by_key(|(_, (ts, _, _, _, _))| *ts)
                        .map(|(k, _)| k.clone())
                    {
                        bf.remove(&oldest_k);
                    }
                }
            }
            bf.insert(
                ip_tag.clone(),
                (
                    now_inst,
                    abuse_score,
                    cc_owned.clone(),
                    isp_owned.clone(),
                    abuse_is_tor,
                ),
            );
        }

        let mut map = self.fp_observations.lock().await;
        let mut changed = false;
        for obs in map.values_mut() {
            if obs.ip_hmac == ip_tag {
                obs.abuse_score = Some(
                    obs.abuse_score
                        .map_or(abuse_score, |old| old.max(abuse_score)),
                );
                if obs.abuse_country.is_none() {
                    obs.abuse_country = cc_owned.clone();
                }
                if obs.abuse_isp.is_none() {
                    obs.abuse_isp = isp_owned.clone();
                }
                obs.abuse_is_tor |= abuse_is_tor;
                obs.sanitize();
                changed = true;
            }
        }
        if changed {
            self.dirty.store(true, Ordering::Relaxed);
        }
    }

    /// Drain all pending telemetry, access logs, fingerprints, Evilpot interactions, Bans & Alerts to send to Maintainer.
    pub async fn drain_batch_for_maintainer(&self) -> DrainedLogBatch {
        self.promote_expired_folded(false).await;
        let records = {
            let mut r = self.recent_records.lock().await;
            let mut b = self.recent_bytes.lock().await;
            *b = 0;
            std::mem::take(&mut *r)
        };
        let summaries = {
            let mut b = self.minute_buckets.lock().await;
            b.drain().map(|(_, v)| v).collect::<Vec<_>>()
        };
        let fingerprints = {
            let mut f = self.fp_observations.lock().await;
            f.drain().map(|(_, v)| v).collect::<Vec<_>>()
        };
        let evilpot_sessions = {
            let mut s = self.pending_evilpot_sessions.lock().await;
            s.drain().map(|(_, v)| v).collect::<Vec<_>>()
        };
        let evilpot_events = {
            let mut e = self.pending_evilpot_events.lock().await;
            std::mem::take(&mut *e)
        };
        let ban_records = {
            let mut b = self.pending_ban_records.lock().await;
            std::mem::take(&mut *b)
        };
        let alerts = {
            let mut a = self.pending_alerts.lock().await;
            std::mem::take(&mut *a)
        };
        if !summaries.is_empty()
            || !fingerprints.is_empty()
            || !evilpot_sessions.is_empty()
            || !evilpot_events.is_empty()
            || !ban_records.is_empty()
            || !alerts.is_empty()
        {
            self.dirty.store(true, Ordering::Relaxed);
        }
        DrainedLogBatch {
            records,
            summaries,
            fingerprints,
            evilpot_sessions,
            evilpot_events,
            ban_records,
            alerts,
        }
    }

    /// Drain pending minute summaries, sampled records, and fingerprint observations to send to Maintainer.
    pub async fn drain_for_maintainer(
        &self,
    ) -> (
        Vec<SessionSummary>,
        Vec<MinuteSummary>,
        Vec<FingerprintObservation>,
    ) {
        let batch = self.drain_batch_for_maintainer().await;
        if !batch.evilpot_sessions.is_empty()
            || !batch.evilpot_events.is_empty()
            || !batch.ban_records.is_empty()
            || !batch.alerts.is_empty()
        {
            self.requeue_batch_for_maintainer(DrainedLogBatch {
                records: Vec::new(),
                summaries: Vec::new(),
                fingerprints: Vec::new(),
                evilpot_sessions: batch.evilpot_sessions,
                evilpot_events: batch.evilpot_events,
                ban_records: batch.ban_records,
                alerts: batch.alerts,
            })
            .await;
        }
        (batch.records, batch.summaries, batch.fingerprints)
    }

    /// Requeue drained batch items if pushing a LogBatch to Maintainer fails transiently.
    pub async fn requeue_batch_for_maintainer(&self, batch: DrainedLogBatch) {
        self.requeue_for_maintainer(batch.records, batch.summaries, batch.fingerprints)
            .await;
        if !batch.evilpot_sessions.is_empty() {
            let mut s = self.pending_evilpot_sessions.lock().await;
            for sess in batch.evilpot_sessions {
                if s.len() >= 1024 && !s.contains_key(&sess.client_ip) {
                    break;
                }
                s.entry(sess.client_ip.clone()).or_insert(sess);
            }
            self.dirty.store(true, Ordering::Relaxed);
        }
        if !batch.evilpot_events.is_empty() {
            let mut e = self.pending_evilpot_events.lock().await;
            for ev in batch.evilpot_events {
                if e.len() >= 2048 {
                    break;
                }
                e.push(ev);
            }
            self.dirty.store(true, Ordering::Relaxed);
        }
        if !batch.ban_records.is_empty() {
            let mut b = self.pending_ban_records.lock().await;
            for br in batch.ban_records {
                if b.len() >= 2048 {
                    break;
                }
                b.push(br);
            }
            self.dirty.store(true, Ordering::Relaxed);
        }
        if !batch.alerts.is_empty() {
            let mut a = self.pending_alerts.lock().await;
            for al in batch.alerts {
                if a.len() >= 512 {
                    break;
                }
                a.push(al);
            }
            self.dirty.store(true, Ordering::Relaxed);
        }
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
            self.dirty.store(true, Ordering::Relaxed);
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
            self.dirty.store(true, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exposure_core::config::SegmentConfig;
    use exposure_core::segment::{list_recent_segment_files, read_segment_file};

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
            .record_access_log(
                "ingress",
                "web",
                "203.0.113.5",
                200,
                12.0,
                100,
                500,
                false,
                false,
                false,
                None,
                None,
                None,
                None,
                false,
                AccessLogMeta {
                    ray_id: Some("ray-1"),
                    method: Some("GET"),
                    host: Some("app.example.com"),
                    path: Some("/dashboard"),
                    query: Some("tab=overview&token=secret123"),
                    protocol: Some("HTTP/2"),
                    scheme: Some("https"),
                    action: Some("allow"),
                    ..Default::default()
                },
            )
            .await;
        logger
            .record_session(
                "ingress",
                "web",
                "203.0.113.6",
                200,
                18.0,
                120,
                600,
                false,
                false,
                false,
                None,
            )
            .await;
        // wait_early_flush should resolve immediately because notify_one() stored a permit
        tokio::time::timeout(
            std::time::Duration::from_millis(200),
            logger.wait_early_flush(),
        )
        .await
        .expect("early flush should have been signalled on batch threshold");

        logger.flush_segments().await.unwrap();

        let segs = list_recent_segment_files(&dir, "edge-1", 24);
        assert_eq!(segs.len(), 1);
        let rows: Vec<SessionSummary> = read_segment_file(&segs[0]).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].path.as_deref(), Some("/dashboard"));
        assert_eq!(
            rows[0].query.as_deref(),
            Some("tab=overview&token=[REDACTED]")
        );
        assert_eq!(rows[0].method.as_deref(), Some("GET"));
        assert_eq!(rows[0].ray_id.as_deref(), Some("ray-1"));

        // Simulate restart: brand-new NodeLogger pointing at the same dir must restore summaries!
        let restored = NodeLogger::new("edge-1", cfg).unwrap();
        let (_, sums, _) = restored.drain_for_maintainer().await;
        assert_eq!(sums.len(), 1);
        assert_eq!(sums[0].requests, 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn dos_log_protection_folds_floods_keeps_exact_metrics_and_preserves_high_priority_logs()
    {
        let dir = std::env::temp_dir().join(format!("exposure-nlog-dos-{}", uuid::Uuid::new_v4()));
        let cfg = LoggerConfig {
            hmac_key: "test-hmac-key-0123456789abcdef0123456789".into(),
            segment: SegmentConfig {
                dir: dir.to_string_lossy().to_string(),
                max_batch_records: 1000,
                max_batch_bytes: 2 * 1024 * 1024,
                ..Default::default()
            },
            protection: LogProtectionConfig {
                enabled: true,
                max_records_per_sec: 100,
                max_per_ip_per_sec: 5,
                max_bytes_per_min: 1024 * 1024,
                dedup_window_secs: 30,
                log_query_string: true,
                access_log_stdout: false,
                warn_rate_per_sec: 2,
            },
            ..Default::default()
        };

        let logger = NodeLogger::new("edge-dos", cfg).unwrap();

        // 1. Simulate 500 rapid 429 flood hits from one attacker IP + 50 random-path 404 probes
        for _ in 0..500 {
            logger
                .record_access_log(
                    "ingress",
                    "web",
                    "198.51.100.77",
                    429,
                    0.5,
                    0,
                    32,
                    true,
                    false,
                    false,
                    None,
                    None,
                    None,
                    None,
                    false,
                    AccessLogMeta {
                        method: Some("GET"),
                        host: Some("victim.test"),
                        path: Some("/login"),
                        action: Some("rate_limit"),
                        ..Default::default()
                    },
                )
                .await;
        }
        for i in 0..50 {
            logger
                .record_access_log(
                    "ingress",
                    "_unmatched",
                    "198.51.100.77",
                    404,
                    0.4,
                    0,
                    16,
                    false,
                    false,
                    false,
                    None,
                    None,
                    None,
                    None,
                    false,
                    AccessLogMeta {
                        method: Some("GET"),
                        host: Some("victim.test"),
                        path: Some(&format!("/scan-{i}")),
                        action: Some("unmatched"),
                        ..Default::default()
                    },
                )
                .await;
        }

        // 2. Legitimate visitor 200 + critical 500 error MUST NOT be drowned out!
        logger
            .record_access_log(
                "ingress",
                "web",
                "203.0.113.10",
                200,
                14.0,
                128,
                1024,
                false,
                false,
                false,
                None,
                None,
                None,
                None,
                false,
                AccessLogMeta {
                    method: Some("GET"),
                    host: Some("victim.test"),
                    path: Some("/api/profile"),
                    action: Some("allow"),
                    ..Default::default()
                },
            )
            .await;
        logger
            .record_access_log(
                "ingress",
                "web",
                "203.0.113.11",
                502,
                55.0,
                256,
                0,
                false,
                false,
                false,
                Some("backend down".into()),
                None,
                None,
                None,
                false,
                AccessLogMeta {
                    method: Some("POST"),
                    host: Some("victim.test"),
                    path: Some("/api/checkout"),
                    action: Some("upstream_error"),
                    ..Default::default()
                },
            )
            .await;

        // 3. Flush all active folded summaries + buffered records
        logger.flush_all().await.unwrap();
        let (recs, sums, _) = logger.drain_for_maintainer().await;

        // MinuteSummary MUST have 100% exact total request counts (550 + 2 = 552)
        let total_reqs: u64 = sums.iter().map(|s| s.requests).sum();
        assert_eq!(total_reqs, 552);

        // Emitted log rows must be drastically folded (<< 552 rows) while accounting for all events
        assert!(
            recs.len() < 30,
            "expected DoS folding to reduce 552 events to <30 rows, got {}",
            recs.len()
        );
        let folded_total: u32 = recs.iter().map(|r| r.repeat_count).sum();
        assert_eq!(folded_total, 552);
        assert!(
            recs.iter()
                .any(|r| r.path.as_deref() == Some("/api/profile") && r.status == 200)
        );
        assert!(
            recs.iter()
                .any(|r| r.path.as_deref() == Some("/api/checkout") && r.status == 502)
        );
        assert!(
            recs.iter()
                .any(|r| r.status == 429 && r.repeat_count >= 499)
        );

        let stats = logger.protection_stats();
        assert!(stats.folded_records >= 530);

        // 4. Warn rate limiting suppresses rapid repeated warnings
        let mut warn_emitted = 0u32;
        for _ in 0..20 {
            if logger.should_log_warn("waf:block:attacker").is_some() {
                warn_emitted += 1;
            }
        }
        assert_eq!(warn_emitted, 1);
        assert!(logger.protection_stats().warn_suppressed >= 19);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn folded_repeat_aggregate_does_not_inherit_a_request_ray_id() {
        let dir = std::env::temp_dir().join(format!("exposure-nlog-ray-{}", uuid::Uuid::new_v4()));
        let cfg = LoggerConfig {
            hmac_key: "test-hmac-key-0123456789abcdef0123456789".into(),
            segment: SegmentConfig {
                dir: dir.to_string_lossy().to_string(),
                ..Default::default()
            },
            protection: LogProtectionConfig {
                enabled: true,
                max_records_per_sec: 100_000,
                max_per_ip_per_sec: 100_000,
                max_bytes_per_min: 16 * 1024 * 1024,
                dedup_window_secs: 30,
                log_query_string: true,
                access_log_stdout: false,
                warn_rate_per_sec: 20,
            },
            ..Default::default()
        };
        let logger = NodeLogger::new("edge-rayfold", cfg).unwrap();
        // Identical blocked payload replayed 5x: the folder keeps the first row and aggregates the rest.
        for i in 0..5 {
            let ray = format!("ray-{i}");
            logger
                .record_access_log(
                    "ingress",
                    "web",
                    "198.51.100.9",
                    403,
                    0.7,
                    0,
                    0,
                    false,
                    false,
                    false,
                    None,
                    None,
                    None,
                    None,
                    false,
                    AccessLogMeta {
                        ray_id: Some(ray.as_str()),
                        method: Some("GET"),
                        host: Some("victim.test"),
                        path: Some("/"),
                        action: Some("waf_block"),
                        waf_category: Some("sql-injection"),
                        ..Default::default()
                    },
                )
                .await;
        }

        logger.flush_all().await.unwrap();
        let (recs, _sums, _) = logger.drain_for_maintainer().await;

        let folded = recs
            .iter()
            .find(|r| r.repeat_count > 1)
            .expect("expected a folded aggregate row");
        assert!(
            folded.ray_id.is_none(),
            "folded aggregate spans several requests and must not reuse the first request's Ray ID"
        );
        let first = recs
            .iter()
            .find(|r| r.repeat_count == 1)
            .expect("expected the first request to be emitted as-is");
        assert_eq!(first.ray_id.as_deref(), Some("ray-0"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn dos_log_protection_enforces_per_minute_byte_budget() {
        let dir =
            std::env::temp_dir().join(format!("exposure-nlog-bytes-{}", uuid::Uuid::new_v4()));
        let cfg = LoggerConfig {
            hmac_key: "test-hmac-key-0123456789abcdef0123456789".into(),
            segment: SegmentConfig {
                dir: dir.to_string_lossy().to_string(),
                ..Default::default()
            },
            protection: LogProtectionConfig {
                enabled: true,
                max_records_per_sec: 10_000,
                max_per_ip_per_sec: 100,
                max_bytes_per_min: 1500, // Tight 1.5 KiB/min cap
                dedup_window_secs: 10,
                log_query_string: true,
                access_log_stdout: false,
                warn_rate_per_sec: 20,
            },
            ..Default::default()
        };

        let logger = NodeLogger::new("edge-bytecap", cfg).unwrap();
        for i in 0..30 {
            logger
                .record_access_log(
                    "ingress",
                    "web",
                    &format!("203.0.113.{}", i + 1),
                    200,
                    5.0,
                    100,
                    200,
                    false,
                    false,
                    false,
                    None,
                    None,
                    None,
                    None,
                    false,
                    AccessLogMeta {
                        method: Some("GET"),
                        host: Some("app.example.com"),
                        path: Some(&format!("/items/page/{i}")),
                        action: Some("allow"),
                        ..Default::default()
                    },
                )
                .await;
        }
        let (recs, sums, _) = logger.drain_for_maintainer().await;
        assert_eq!(sums[0].requests, 30);
        assert!(
            recs.len() < 15,
            "byte budget should cap emitted rows, got {}",
            recs.len()
        );
        assert!(logger.protection_stats().dropped_records > 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn slow_abuseipdb_lookup_backfills_fingerprint_observations_without_stalling() {
        use crate::abuseipdb::AbuseIpDbClient;
        use exposure_core::config::AbuseIpDbConfig;
        use std::net::IpAddr;
        use std::time::{Duration, Instant};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let dir = std::env::temp_dir().join(format!("exposure-nlog-abbf-{}", uuid::Uuid::new_v4()));
        let logger = NodeLogger::new(
            "edge-abbf",
            LoggerConfig {
                hmac_key: "test-hmac-key-0123456789abcdef0123456789".into(),
                segment: SegmentConfig {
                    dir: dir.to_string_lossy().to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = sock.read(&mut buf).await;
                    // Exceeds REQUEST_WAIT_BUDGET (250ms) so initial lookup returns None non-blockingly
                    tokio::time::sleep(Duration::from_millis(320)).await;
                    let body = r#"{"data":{"ipAddress":"9.9.9.9","abuseConfidenceScore":91,"countryCode":"DE","isp":"TestHost GmbH","usageType":"Data Center","isTor":true,"totalReports":17}}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });

        let ab_client = AbuseIpDbClient::with_endpoint(
            AbuseIpDbConfig {
                enabled: true,
                api_key: "test-key".into(),
                max_daily_lookups: 50,
                cache_ttl_secs: 3600,
                ..Default::default()
            },
            format!("http://{addr}/api/v2/check"),
        );

        let peer_ip: IpAddr = "9.9.9.9".parse().unwrap();
        let logger_bf = Arc::clone(&logger);
        let t0 = Instant::now();
        let immediate = ab_client
            .lookup_with_backfill(peer_ip, move |rep| async move {
                logger_bf
                    .backfill_abuse_report(
                        "9.9.9.9",
                        rep.abuse_confidence_score,
                        rep.country_code.as_deref(),
                        rep.isp.as_deref(),
                        rep.is_tor,
                    )
                    .await;
            })
            .await;
        assert!(immediate.is_none());
        assert!(t0.elapsed() < Duration::from_millis(310));

        // Ordering 1: record fingerprint BEFORE background lookup completes
        logger
            .record_fingerprint(
                "svc-web",
                "app.example.com",
                "9.9.9.9",
                "fp-before-complete",
                false,
                "none",
                "curl/8.5",
                "en-US",
                "API/CLI",
                "CLI/Script",
                "Other",
                true,
                false,
                60,
                0,
                false,
                None,
                1,
                0,
                0,
            )
            .await;

        tokio::time::sleep(Duration::from_millis(180)).await;

        // Ordering 2: record fingerprint AFTER backfill (with None extras -> filled from recent_abuse_backfills)
        logger
            .record_fingerprint(
                "svc-web",
                "app.example.com",
                "9.9.9.9",
                "fp-after-complete",
                true,
                "pow",
                "Mozilla/5.0",
                "en-US",
                "Desktop",
                "Chrome",
                "Linux",
                false,
                false,
                0,
                10,
                true,
                None,
                1,
                0,
                0,
            )
            .await;

        let (_, _, fps) = logger.drain_for_maintainer().await;
        let obs1 = fps
            .iter()
            .find(|f| f.fp_hash == "fp-before-complete")
            .expect("missing before-complete observation");
        assert_eq!(obs1.abuse_score, Some(91));
        assert_eq!(obs1.abuse_country.as_deref(), Some("DE"));
        assert_eq!(obs1.abuse_isp.as_deref(), Some("TestHost GmbH"));
        assert!(obs1.abuse_is_tor);

        let obs2 = fps
            .iter()
            .find(|f| f.fp_hash == "fp-after-complete")
            .expect("missing after-complete observation");
        assert_eq!(obs2.abuse_score, Some(91));
        assert_eq!(obs2.abuse_country.as_deref(), Some("DE"));
        assert!(obs2.abuse_is_tor);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
