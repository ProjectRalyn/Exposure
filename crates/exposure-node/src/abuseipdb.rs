use std::collections::HashMap;
use std::net::IpAddr;
#[cfg(test)]
use std::sync::atomic::AtomicU32;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use dashmap::DashMap;
use exposure_core::config::AbuseIpDbConfig;
pub use exposure_core::routing::{canonical_ip, is_public_routable_ip};
use exposure_core::segment::{read_json_snapshot, write_json_snapshot_atomic};
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, info, warn};

use crate::ban::evict_half;

const MAX_CACHE_ENTRIES: usize = 32_768;
const MAX_CONCURRENT_BG_LOOKUPS: usize = 16;
const MAX_ABUSEIPDB_RESP_BYTES: usize = 64 * 1024;
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(300);
const RATE_LIMIT_BACKOFF_SECS: u64 = 600;
const REQUEST_WAIT_BUDGET: Duration = Duration::from_millis(250);
const HTTP_TIMEOUT: Duration = Duration::from_secs(4);
const DEFAULT_API_BASE: &str = "https://api.abuseipdb.com/api/v2/check";
const DEFAULT_REPORT_API: &str = "https://api.abuseipdb.com/api/v2/report";

/// AbuseIPDB rejects repeat reports for the same IP within 15 minutes; we additionally dedupe
/// per 24h, which is what their FAQ recommends for continuous abuse (and keeps quota healthy).
const REPORT_DEDUPE_SECS: u64 = 86_400;
/// Quota/rate-limit backoff so a single 429 does not burn the remaining daily allowance.
const REPORT_BACKOFF_SECS: u64 = 600;
const REPORT_ERROR_BACKOFF_SECS: u64 = 300;
const MAX_REPORT_COMMENT_BYTES: usize = 1024;
const MAX_REPORT_STATE_ENTRIES: usize = 8_192;

/// AbuseIPDB category IDs (https://www.abuseipdb.com/categories).
const CAT_WEB_APP_ATTACK: u16 = 21;
const CAT_HACKING: u16 = 15;
const CAT_SQL_INJECTION: u16 = 16;
const CAT_BRUTE_FORCE: u16 = 18;

#[derive(Debug, Clone)]
pub struct AbuseIpReport {
    pub abuse_confidence_score: u8,
    pub country_code: Option<String>,
    pub isp: Option<String>,
    pub usage_type: Option<String>,
    pub is_tor: bool,
    pub total_reports: u32,
}

/// Facts about a honeypot-confirmed offense that are safely publishable to AbuseIPDB.
///
/// Only server-side verdict data is included: the offender's IP, the internal rule token
/// (e.g. `evilpot:verified_exploit:canary`) and ban metadata. Never request headers, URLs,
/// query strings or anything else that could carry visitor PII.
#[derive(Debug, Clone)]
pub struct AbuseReportFacts {
    pub ip: IpAddr,
    pub reason: String,
    pub offense_level: u8,
    pub ban_ttl_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportOutcome {
    /// Reporting is switched off, or no API key is configured.
    Disabled,
    /// Target is private / loopback / CGNAT — never reportable.
    NotPublicIp,
    /// Offense escalation level is below `report_min_offense_level`.
    BelowOffenseLevel,
    /// Same IP already reported within the dedupe window.
    Duplicate,
    /// Per-node daily report budget exhausted.
    QuotaExhausted,
    /// Cooling down after a 429 / transport failure.
    Backoff,
    /// AbuseIPDB accepted the report.
    Sent,
    /// AbuseIPDB returned 429 (daily cap or the per-IP 15-minute rule).
    RateLimited,
    /// AbuseIPDB rejected the payload (4xx); retrying the same facts will not help.
    Rejected(u16),
    /// Transport error or 5xx; the dedupe entry was rolled back so a later attempt can retry.
    Failed,
}

#[derive(Default)]
struct ReportState {
    day: u64,
    submitted_today: u32,
    last_by_ip: HashMap<IpAddr, u64>,
}

impl ReportState {
    fn roll_day(&mut self, today: u64) {
        if self.day != today {
            self.day = today;
            self.submitted_today = 0;
        }
    }

    fn prune(&mut self, now_unix: u64) {
        if self.last_by_ip.len() <= MAX_REPORT_STATE_ENTRIES {
            return;
        }
        self.last_by_ip
            .retain(|_, at| now_unix.saturating_sub(*at) < REPORT_DEDUPE_SECS);
        if self.last_by_ip.len() > MAX_REPORT_STATE_ENTRIES {
            let mut entries: Vec<(IpAddr, u64)> = self.last_by_ip.drain().collect();
            entries.sort_unstable_by_key(|e| std::cmp::Reverse(e.1));
            entries.truncate(MAX_REPORT_STATE_ENTRIES);
            self.last_by_ip = entries.into_iter().collect();
        }
    }

    fn to_persisted(&self) -> PersistedReportState {
        PersistedReportState {
            day: self.day,
            submitted_today: self.submitted_today,
            entries: self
                .last_by_ip
                .iter()
                .map(|(ip, at)| PersistedReportEntry {
                    ip: ip.to_string(),
                    at_unix: *at,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedReportState {
    #[serde(default)]
    day: u64,
    #[serde(default)]
    submitted_today: u32,
    #[serde(default)]
    entries: Vec<PersistedReportEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedReportEntry {
    ip: String,
    at_unix: u64,
}

#[derive(Debug, Clone)]
struct CachedAbuseEntry {
    report: Option<AbuseIpReport>,
    expires_at: Instant,
}

#[derive(Debug, Deserialize)]
struct AbuseApiResp {
    data: AbuseApiData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AbuseApiData {
    #[serde(default)]
    abuse_confidence_score: u8,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    isp: Option<String>,
    #[serde(default)]
    usage_type: Option<String>,
    #[serde(default)]
    is_tor: bool,
    #[serde(default)]
    total_reports: u32,
}

struct InFlightGuard {
    map: Arc<DashMap<IpAddr, ()>>,
    ip: IpAddr,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.map.remove(&self.ip);
    }
}

/// Thread-safe, quota-guarded AbuseIPDB v2 lookup client with bounded LRU/TTL cache
/// and single-flight per-IP deduplication.
pub struct AbuseIpDbClient {
    enabled: AtomicBool,
    report_active: AtomicBool,
    cfg: RwLock<Arc<AbuseIpDbConfig>>,
    api_base: String,
    report_url: String,
    http: reqwest::Client,
    cache: DashMap<IpAddr, CachedAbuseEntry>,
    in_flight: Arc<DashMap<IpAddr, ()>>,
    bg_sem: Arc<Semaphore>,
    daily_quota: StdMutex<(u64, u32)>,
    backoff_until_unix: AtomicU64,
    report_state: StdMutex<ReportState>,
    report_state_path: StdMutex<Option<std::path::PathBuf>>,
    report_backoff_until_unix: AtomicU64,
}

impl AbuseIpDbClient {
    pub fn new(cfg: AbuseIpDbConfig) -> Arc<Self> {
        Self::with_endpoint(cfg, DEFAULT_API_BASE)
    }

    pub fn with_endpoint(cfg: AbuseIpDbConfig, endpoint: impl Into<String>) -> Arc<Self> {
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        let enabled = AtomicBool::new(cfg.enabled && !cfg.api_key.trim().is_empty());
        let report_active = AtomicBool::new(cfg.report_enabled && !cfg.api_key.trim().is_empty());
        let api_base: String = endpoint.into();
        // Derive the sibling `report` endpoint so tests can point both at one mock server.
        let report_url = match api_base.strip_suffix("/check") {
            Some(base) => format!("{base}/report"),
            None => DEFAULT_REPORT_API.to_string(),
        };
        Arc::new(Self {
            enabled,
            report_active,
            cfg: RwLock::new(Arc::new(cfg)),
            api_base,
            report_url,
            http,
            cache: DashMap::new(),
            in_flight: Arc::new(DashMap::new()),
            bg_sem: Arc::new(Semaphore::new(MAX_CONCURRENT_BG_LOOKUPS)),
            daily_quota: StdMutex::new((current_utc_day(), 0)),
            backoff_until_unix: AtomicU64::new(0),
            report_state: StdMutex::new(ReportState::default()),
            report_state_path: StdMutex::new(None),
            report_backoff_until_unix: AtomicU64::new(0),
        })
    }

    /// Attach the on-disk dedupe ledger for outbound reports and restore it from `path`.
    ///
    /// The ledger must survive restarts: without it, a node reboot would re-report every
    /// attacker currently in the ban table and immediately trip AbuseIPDB's per-IP rate limit.
    pub fn attach_report_state_file(self: &Arc<Self>, path: std::path::PathBuf) {
        match read_json_snapshot::<PersistedReportState>(&path) {
            Ok(Some(state)) => {
                let mut st = self.report_state.lock().unwrap_or_else(|e| e.into_inner());
                st.day = state.day;
                st.submitted_today = state.submitted_today;
                for e in state.entries {
                    if let Ok(ip) = e.ip.parse::<IpAddr>() {
                        st.last_by_ip.insert(canonical_ip(ip), e.at_unix);
                    }
                }
                info!(
                    path = %path.display(),
                    ledgers = st.last_by_ip.len(),
                    "restored AbuseIPDB report ledger from disk"
                );
            }
            Ok(None) => {}
            Err(e) => {
                warn!(path = %path.display(), error = %e, "failed to restore AbuseIPDB report ledger")
            }
        }
        *self
            .report_state_path
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(path);
    }

    /// Number of reports accepted in the current UTC day (used for quota-aware logging).
    pub fn reports_submitted_today(&self) -> u32 {
        self.report_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .submitted_today
    }

    pub async fn reconfigure(&self, cfg: AbuseIpDbConfig) {
        let mut g = self.cfg.write().await;
        let key_changed = g.api_key.trim() != cfg.api_key.trim();
        let active = cfg.enabled && !cfg.api_key.trim().is_empty();
        let report_active = cfg.report_enabled && !cfg.api_key.trim().is_empty();
        *g = Arc::new(cfg);
        self.enabled.store(active, Ordering::Relaxed);
        self.report_active.store(report_active, Ordering::Relaxed);
        if !active {
            self.cache.clear();
        }
        if key_changed {
            self.backoff_until_unix.store(0, Ordering::Relaxed);
            self.report_backoff_until_unix.store(0, Ordering::Relaxed);
        }
    }

    /// Fast, lock-free check used to avoid spawning a reporting task when the feature is off.
    #[inline]
    pub fn is_report_active(&self) -> bool {
        self.report_active.load(Ordering::Relaxed)
    }

    /// Look up IP reputation. Returns immediately on cache hit; on cache miss, awaits up to
    /// `REQUEST_WAIT_BUDGET` (250ms) while letting the lookup complete in background if slow.
    pub async fn lookup(self: &Arc<Self>, raw_ip: IpAddr) -> Option<AbuseIpReport> {
        self.lookup_with_backfill(raw_ip, |_| async {}).await
    }

    /// Look up IP reputation with an asynchronous backfill hook invoked when the spawned
    /// background fetch completes (even if `REQUEST_WAIT_BUDGET` timed out on the caller).
    pub async fn lookup_with_backfill<F, Fut>(
        self: &Arc<Self>,
        raw_ip: IpAddr,
        on_complete: F,
    ) -> Option<AbuseIpReport>
    where
        F: FnOnce(AbuseIpReport) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        if !self.enabled.load(Ordering::Relaxed) {
            return None;
        }
        let ip = canonical_ip(raw_ip);
        if !is_public_routable_ip(ip) {
            return None;
        }

        let now = Instant::now();
        if let Some(entry) = self.cache.get(&ip) {
            if now < entry.expires_at {
                return entry.report.clone();
            }
        }

        let cfg = Arc::clone(&*self.cfg.read().await);
        if !cfg.enabled || cfg.api_key.trim().is_empty() {
            return None;
        }

        let now_unix = Utc::now().timestamp().max(0) as u64;
        if now_unix < self.backoff_until_unix.load(Ordering::Relaxed) {
            return None;
        }

        // Single-flight deduplication per IP + concurrency cap for background lookups
        if self.in_flight.insert(ip, ()).is_some() {
            return None;
        }
        let guard = InFlightGuard {
            map: Arc::clone(&self.in_flight),
            ip,
        };
        let Ok(bg_permit) = Arc::clone(&self.bg_sem).try_acquire_owned() else {
            return None;
        };

        // Daily lookup quota enforcement (preserves free-tier 1000/day API keys)
        if !self.consume_daily_quota(cfg.max_daily_lookups.max(1)) {
            return None;
        }

        let this = Arc::clone(self);
        let handle = tokio::spawn(async move {
            let _guard = guard;
            let _bg_permit = bg_permit;
            let res = this.fetch_and_cache(ip, &cfg).await;
            if let Some(ref rep) = res {
                on_complete(rep.clone()).await;
            }
            res
        });

        // Wait briefly so first request from an abusive IP gets immediate scoring,
        // without stalling benign traffic if AbuseIPDB has high latency.
        let mut handle = handle;
        match tokio::time::timeout(REQUEST_WAIT_BUDGET, &mut handle).await {
            Ok(Ok(report)) => report,
            Ok(Err(_)) => None,
            Err(_) => {
                // Keep task running in background to populate cache and run backfill hook
                None
            }
        }
    }

    /// Submit an abuse report for a honeypot-confirmed attacker.
    ///
    /// This performs network I/O and must never be awaited from a request hot path — callers
    /// spawn a background task. Quota and dedupe bookkeeping is reserved *before* the request so
    /// concurrent callers can never overshoot the daily budget.
    pub async fn report(self: &Arc<Self>, facts: AbuseReportFacts) -> ReportOutcome {
        let cfg = Arc::clone(&*self.cfg.read().await);
        if !cfg.report_enabled || cfg.api_key.trim().is_empty() {
            return ReportOutcome::Disabled;
        }
        let ip = canonical_ip(facts.ip);
        if !is_public_routable_ip(ip) {
            return ReportOutcome::NotPublicIp;
        }
        if facts.offense_level < cfg.report_min_offense_level.max(1) {
            return ReportOutcome::BelowOffenseLevel;
        }

        let now_unix = Utc::now().timestamp().max(0) as u64;
        if now_unix < self.report_backoff_until_unix.load(Ordering::Relaxed) {
            return ReportOutcome::Backoff;
        }

        let quota = cfg.report_daily_quota.max(1);
        let (snapshot, sent_today) = {
            let mut st = self.report_state.lock().unwrap_or_else(|e| e.into_inner());
            st.roll_day(now_unix / 86_400);
            if let Some(last) = st.last_by_ip.get(&ip) {
                if now_unix.saturating_sub(*last) < REPORT_DEDUPE_SECS {
                    return ReportOutcome::Duplicate;
                }
            }
            if st.submitted_today >= quota {
                return ReportOutcome::QuotaExhausted;
            }
            st.submitted_today = st.submitted_today.saturating_add(1);
            st.last_by_ip.insert(ip, now_unix);
            st.prune(now_unix);
            (st.to_persisted(), st.submitted_today)
        };
        self.persist_report_state(snapshot);

        let categories = resolve_report_categories(&cfg.report_categories, &facts.reason);
        let categories_csv = categories
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let comment = build_report_comment(&facts);
        let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let form: Vec<(&str, String)> = vec![
            ("ip", ip.to_string()),
            ("categories", categories_csv.clone()),
            ("comment", comment),
            ("timestamp", timestamp),
        ];

        let mut resp = match self
            .http
            .post(&self.report_url)
            .header("Key", cfg.api_key.trim())
            .header("Accept", "application/json")
            .form(&form)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                // Request never reached the API: refund the daily budget and clear the ledger
                // entry so a later offense can retry.
                self.rollback_report_entry(ip, true);
                self.report_backoff_until_unix.store(
                    now_unix.saturating_add(REPORT_ERROR_BACKOFF_SECS),
                    Ordering::Relaxed,
                );
                debug!(ip = %ip, error = %e, "abuseipdb report request failed");
                return ReportOutcome::Failed;
            }
        };

        let status = resp.status().as_u16();
        let mut body = Vec::new();
        while let Ok(Some(chunk)) = resp.chunk().await {
            if body.len().saturating_add(chunk.len()) > MAX_ABUSEIPDB_RESP_BYTES {
                break;
            }
            body.extend_from_slice(&chunk);
        }

        match status {
            200..=299 => {
                info!(
                    ip = %ip,
                    categories = %categories_csv,
                    reports_today = sent_today,
                    "reported honeypot-confirmed attacker to AbuseIPDB"
                );
                ReportOutcome::Sent
            }
            429 => {
                self.report_backoff_until_unix.store(
                    now_unix.saturating_add(REPORT_BACKOFF_SECS),
                    Ordering::Relaxed,
                );
                // The request was counted by AbuseIPDB but produced no report: allow a retry
                // once the backoff expires, keeping the daily counter as consumed.
                self.rollback_report_entry(ip, false);
                warn!(
                    ip = %ip,
                    "abuseipdb report returned 429 (daily cap or per-IP 15-min rule); backing off for {REPORT_BACKOFF_SECS}s"
                );
                ReportOutcome::RateLimited
            }
            500..=u16::MAX => {
                self.rollback_report_entry(ip, false);
                self.report_backoff_until_unix.store(
                    now_unix.saturating_add(REPORT_ERROR_BACKOFF_SECS),
                    Ordering::Relaxed,
                );
                debug!(ip = %ip, status, "abuseipdb report upstream error");
                ReportOutcome::Failed
            }
            other => {
                // 401/403/422: retrying identical facts cannot help, so keep the ledger entry
                // to suppress a retry storm. Surface a truncated reason for operator debugging.
                let detail: String = String::from_utf8_lossy(&body)
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(160)
                    .collect();
                warn!(ip = %ip, status = other, detail = %detail, "abuseipdb rejected report");
                ReportOutcome::Rejected(other)
            }
        }
    }

    fn rollback_report_entry(&self, ip: IpAddr, refund_quota: bool) {
        let mut st = self.report_state.lock().unwrap_or_else(|e| e.into_inner());
        if refund_quota {
            st.submitted_today = st.submitted_today.saturating_sub(1);
        }
        st.last_by_ip.remove(&ip);
    }

    fn persist_report_state(&self, state: PersistedReportState) {
        let path = self
            .report_state_path
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let Some(path) = path else {
            return;
        };
        // Written synchronously on purpose: `report()` always runs inside a spawned task (never
        // the request hot path), and a completed write guarantees a restart cannot re-report.
        if let Err(e) = write_json_snapshot_atomic(&path, &state) {
            debug!(error = %e, path = %path.display(), "failed to persist AbuseIPDB report ledger");
        }
    }

    fn consume_daily_quota(&self, limit: u32) -> bool {
        let today = current_utc_day();
        let mut q = self.daily_quota.lock().unwrap_or_else(|e| e.into_inner());
        if q.0 != today {
            *q = (today, 0);
        }
        if q.1 >= limit {
            return false;
        }
        q.1 = q.1.saturating_add(1);
        true
    }

    async fn fetch_and_cache(&self, ip: IpAddr, cfg: &AbuseIpDbConfig) -> Option<AbuseIpReport> {
        let max_age = cfg.max_age_days.clamp(1, 365).to_string();
        let ip_str = ip.to_string();
        let mut resp = match self
            .http
            .get(&self.api_base)
            .query(&[
                ("ipAddress", ip_str.as_str()),
                ("maxAgeInDays", max_age.as_str()),
            ])
            .header("Key", cfg.api_key.trim())
            .header("Accept", "application/json")
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                debug!(ip = %ip, error = %e, "abuseipdb request failed");
                self.insert_cache(ip, None, NEGATIVE_CACHE_TTL);
                return None;
            }
        };

        if resp.status().as_u16() == 429 {
            let until =
                (Utc::now().timestamp().max(0) as u64).saturating_add(RATE_LIMIT_BACKOFF_SECS);
            self.backoff_until_unix.store(until, Ordering::Relaxed);
            warn!(
                "abuseipdb returned 429 Too Many Requests; backing off for {RATE_LIMIT_BACKOFF_SECS}s"
            );
            self.insert_cache(ip, None, NEGATIVE_CACHE_TTL);
            return None;
        }

        if !resp.status().is_success() {
            debug!(ip = %ip, status = %resp.status(), "abuseipdb non-2xx status");
            self.insert_cache(ip, None, NEGATIVE_CACHE_TTL);
            return None;
        }

        let mut body = Vec::new();
        while let Ok(Some(chunk)) = resp.chunk().await {
            if body.len().saturating_add(chunk.len()) > MAX_ABUSEIPDB_RESP_BYTES {
                debug!(ip = %ip, "abuseipdb response exceeded byte cap");
                self.insert_cache(ip, None, NEGATIVE_CACHE_TTL);
                return None;
            }
            body.extend_from_slice(&chunk);
        }
        let parsed = match serde_json::from_slice::<AbuseApiResp>(&body) {
            Ok(p) => p,
            Err(e) => {
                debug!(ip = %ip, error = %e, "abuseipdb parse failed");
                self.insert_cache(ip, None, NEGATIVE_CACHE_TTL);
                return None;
            }
        };

        let report = AbuseIpReport {
            abuse_confidence_score: parsed.data.abuse_confidence_score.min(100),
            country_code: parsed.data.country_code.filter(|s| !s.trim().is_empty()),
            isp: parsed.data.isp.filter(|s| !s.trim().is_empty()),
            usage_type: parsed.data.usage_type.filter(|s| !s.trim().is_empty()),
            is_tor: parsed.data.is_tor,
            total_reports: parsed.data.total_reports,
        };
        let ttl = Duration::from_secs(cfg.cache_ttl_secs.clamp(300, 86_400));
        self.insert_cache(ip, Some(report.clone()), ttl);
        Some(report)
    }

    fn insert_cache(&self, ip: IpAddr, report: Option<AbuseIpReport>, ttl: Duration) {
        let now = Instant::now();
        if self.cache.len() >= MAX_CACHE_ENTRIES && !self.cache.contains_key(&ip) {
            self.cache.retain(|_, v| now < v.expires_at);
            if self.cache.len() >= MAX_CACHE_ENTRIES {
                evict_half(&self.cache);
            }
        }
        self.cache.insert(
            ip,
            CachedAbuseEntry {
                report,
                expires_at: now + ttl,
            },
        );
    }
}

/// Map an internal offense reason to AbuseIPDB category IDs.
///
/// Explicit operator overrides win. Otherwise we always tag "Web App Attack" (the honeypot only
/// diverts HTTP traffic) and refine by attack class. IDs are kept in sync with
/// <https://www.abuseipdb.com/categories>.
fn resolve_report_categories(overrides: &[u16], reason: &str) -> Vec<u16> {
    if !overrides.is_empty() {
        let mut explicit: Vec<u16> = overrides
            .iter()
            .copied()
            .filter(|c| (1..=23).contains(c))
            .collect();
        explicit.sort_unstable();
        explicit.dedup();
        if !explicit.is_empty() {
            return explicit;
        }
    }

    let r = reason.to_ascii_lowercase();
    let mut cats = vec![CAT_WEB_APP_ATTACK];
    if r.contains("sql") {
        cats.push(CAT_SQL_INJECTION);
    }
    if r.contains("canary")
        || r.contains("rce")
        || r.contains("cmd")
        || r.contains("shell")
        || r.contains("exec")
        || r.contains("ssti")
        || r.contains("lfi")
        || r.contains("rfi")
        || r.contains("traversal")
        || r.contains("upload")
    {
        cats.push(CAT_HACKING);
    }
    if r.contains("brute") || r.contains("login") || r.contains("auth") || r.contains("passwd") {
        cats.push(CAT_BRUTE_FORCE);
    }
    cats.sort_unstable();
    cats.dedup();
    cats
}

/// Build a PII-free comment: internal rule token + ban metadata only. Request paths, query
/// strings, headers and user agents are deliberately excluded — they routinely contain tokens,
/// emails or session IDs, and AbuseIPDB reports are public and effectively permanent.
fn build_report_comment(facts: &AbuseReportFacts) -> String {
    let reason: String = facts
        .reason
        .chars()
        .filter(|c| !c.is_control())
        .take(160)
        .collect();
    let raw = format!(
        "Honeypot-confirmed web exploit attempt detected and blocked by Exposure (evilpot). rule={}; ban_ttl={}s; escalation_level={}",
        reason.trim(),
        facts.ban_ttl_secs,
        facts.offense_level
    );
    truncate_utf8(raw, MAX_REPORT_COMMENT_BYTES)
}

fn truncate_utf8(mut s: String, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    s
}

fn current_utc_day() -> u64 {
    (Utc::now().timestamp().max(0) as u64) / 86_400
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn skips_private_and_loopback_ips() {
        assert!(!is_public_routable_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_public_routable_ip("10.0.0.5".parse().unwrap()));
        assert!(!is_public_routable_ip("192.168.1.1".parse().unwrap()));
        assert!(!is_public_routable_ip("100.64.0.1".parse().unwrap()));
        assert!(!is_public_routable_ip("::1".parse().unwrap()));
        assert!(is_public_routable_ip("8.8.8.8".parse().unwrap()));
        assert!(is_public_routable_ip("118.25.6.39".parse().unwrap()));
    }

    #[tokio::test]
    async fn fetches_caches_and_respects_daily_quota() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicU32::new(0));
        let hits_srv = Arc::clone(&hits);

        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                hits_srv.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let body = r#"{"data":{"ipAddress":"8.8.8.8","abuseConfidenceScore":88,"countryCode":"US","isp":"EvilBotNet","usageType":"Data Center","isTor":true,"totalReports":42}}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });

        let cfg = AbuseIpDbConfig {
            enabled: true,
            api_key: "test-key".into(),
            max_daily_lookups: 1,
            cache_ttl_secs: 3600,
            ..Default::default()
        };
        let client = AbuseIpDbClient::with_endpoint(cfg, format!("http://{addr}/api/v2/check"));

        let ip1: IpAddr = "8.8.8.8".parse().unwrap();
        let r1 = client.lookup(ip1).await.expect("first lookup succeeds");
        assert_eq!(r1.abuse_confidence_score, 88);
        assert_eq!(r1.country_code.as_deref(), Some("US"));
        assert!(r1.is_tor);
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        // Second lookup for same IP served from cache (hits stays 1)
        let r2 = client.lookup(ip1).await.expect("cached hit");
        assert_eq!(r2.abuse_confidence_score, 88);
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        // Different IP denied because daily quota = 1 exhausted
        let ip2: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(client.lookup(ip2).await.is_none());
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    fn facts(ip: IpAddr, level: u8) -> AbuseReportFacts {
        AbuseReportFacts {
            ip,
            reason: "evilpot:verified_exploit:canary".to_string(),
            offense_level: level,
            ban_ttl_secs: 1800,
        }
    }

    async fn mock_report_server() -> (std::net::SocketAddr, Arc<AtomicU32>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let posts = Arc::new(AtomicU32::new(0));
        let posts_srv = Arc::clone(&posts);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = [0u8; 8192];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                if head.starts_with("POST /api/v2/report") {
                    posts_srv.fetch_add(1, Ordering::SeqCst);
                }
                let body = r#"{"data":{"ipAddress":"8.8.8.8","abuseConfidenceScore":52}}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });
        (addr, posts)
    }

    #[tokio::test]
    async fn reports_confirmed_attacker_once_per_ip_and_day() {
        let (addr, posts) = mock_report_server().await;
        let cfg = AbuseIpDbConfig {
            enabled: true,
            api_key: "test-key".into(),
            report_enabled: true,
            report_daily_quota: 5,
            ..Default::default()
        };
        let client = AbuseIpDbClient::with_endpoint(cfg, format!("http://{addr}/api/v2/check"));
        let ip: IpAddr = "8.8.8.8".parse().unwrap();

        assert_eq!(
            client.report(facts(ip, 1)).await,
            ReportOutcome::Sent,
            "first honeypot-confirmed ban must be reported"
        );
        assert_eq!(
            client.report(facts(ip, 1)).await,
            ReportOutcome::Duplicate,
            "same IP must not be re-reported inside the dedupe window"
        );
        assert_eq!(posts.load(Ordering::SeqCst), 1);
        assert_eq!(client.reports_submitted_today(), 1);
    }

    #[tokio::test]
    async fn report_ledger_survives_restart() {
        let (addr, posts) = mock_report_server().await;
        let dir = std::env::temp_dir().join(format!("exp-abuse-report-{}", uuid::Uuid::new_v4()));
        let ledger = dir.join("abuseipdb-reports-edge1.json");
        let cfg = AbuseIpDbConfig {
            enabled: true,
            api_key: "test-key".into(),
            report_enabled: true,
            ..Default::default()
        };
        let ip: IpAddr = "8.8.8.8".parse().unwrap();

        let c1 = AbuseIpDbClient::with_endpoint(cfg.clone(), format!("http://{addr}/api/v2/check"));
        c1.attach_report_state_file(ledger.clone());
        assert_eq!(c1.report(facts(ip, 1)).await, ReportOutcome::Sent);
        assert_eq!(posts.load(Ordering::SeqCst), 1);

        // Simulate a node restart: a fresh client must reload the ledger and stay silent,
        // otherwise every reboot would re-report the whole ban table.
        let c2 = AbuseIpDbClient::with_endpoint(cfg, format!("http://{addr}/api/v2/check"));
        c2.attach_report_state_file(ledger.clone());
        assert_eq!(c2.report(facts(ip, 1)).await, ReportOutcome::Duplicate);
        assert_eq!(posts.load(Ordering::SeqCst), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn report_respects_switch_offense_level_and_quota() {
        let (addr, _posts) = mock_report_server().await;

        let disabled = AbuseIpDbClient::with_endpoint(
            AbuseIpDbConfig {
                enabled: true,
                api_key: "test-key".into(),
                report_enabled: false,
                ..Default::default()
            },
            format!("http://{addr}/api/v2/check"),
        );
        assert_eq!(
            disabled.report(facts("8.8.8.8".parse().unwrap(), 3)).await,
            ReportOutcome::Disabled
        );

        let gated = AbuseIpDbClient::with_endpoint(
            AbuseIpDbConfig {
                enabled: true,
                api_key: "test-key".into(),
                report_enabled: true,
                report_min_offense_level: 3,
                ..Default::default()
            },
            format!("http://{addr}/api/v2/check"),
        );
        assert_eq!(
            gated.report(facts("8.8.4.4".parse().unwrap(), 1)).await,
            ReportOutcome::BelowOffenseLevel
        );
        assert_eq!(
            gated.report(facts("10.0.0.7".parse().unwrap(), 3)).await,
            ReportOutcome::NotPublicIp
        );

        let capped = AbuseIpDbClient::with_endpoint(
            AbuseIpDbConfig {
                enabled: true,
                api_key: "test-key".into(),
                report_enabled: true,
                report_daily_quota: 1,
                ..Default::default()
            },
            format!("http://{addr}/api/v2/check"),
        );
        assert_eq!(
            capped.report(facts("9.9.9.9".parse().unwrap(), 1)).await,
            ReportOutcome::Sent
        );
        assert_eq!(
            capped.report(facts("9.9.9.10".parse().unwrap(), 1)).await,
            ReportOutcome::QuotaExhausted
        );
    }

    #[test]
    fn maps_reasons_to_abuse_categories() {
        assert_eq!(
            resolve_report_categories(&[], "evilpot:verified_exploit:sqli"),
            vec![CAT_SQL_INJECTION, CAT_WEB_APP_ATTACK]
        );
        assert_eq!(
            resolve_report_categories(&[], "evilpot:verified_exploit:canary"),
            vec![CAT_HACKING, CAT_WEB_APP_ATTACK]
        );
        assert_eq!(
            resolve_report_categories(&[], "evilpot:probe:scanner"),
            vec![CAT_WEB_APP_ATTACK]
        );
        // Explicit override wins, invalid IDs are dropped, duplicates collapsed.
        assert_eq!(
            resolve_report_categories(&[21, 21, 99], "whatever"),
            vec![21]
        );
    }

    #[test]
    fn report_comment_is_pii_free_and_bounded() {
        let long_reason = "evilpot:verified_exploit:".to_string() + &"x".repeat(4000);
        let c = build_report_comment(&AbuseReportFacts {
            ip: "8.8.8.8".parse().unwrap(),
            reason: long_reason,
            offense_level: 2,
            ban_ttl_secs: 1800,
        });
        assert!(c.len() <= MAX_REPORT_COMMENT_BYTES);
        assert!(c.starts_with("Honeypot-confirmed web exploit attempt"));
        assert!(!c.contains('\n'));
    }
}
