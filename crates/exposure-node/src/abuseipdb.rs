use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use dashmap::DashMap;
use exposure_core::config::AbuseIpDbConfig;
use exposure_core::routing::canonical_ip;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, warn};

const MAX_CACHE_ENTRIES: usize = 32_768;
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(300);
const RATE_LIMIT_BACKOFF_SECS: u64 = 600;
const REQUEST_WAIT_BUDGET: Duration = Duration::from_millis(750);
const HTTP_TIMEOUT: Duration = Duration::from_secs(4);
const DEFAULT_API_BASE: &str = "https://api.abuseipdb.com/api/v2/check";

#[derive(Debug, Clone)]
pub struct AbuseIpReport {
    pub abuse_confidence_score: u8,
    pub country_code: Option<String>,
    pub isp: Option<String>,
    pub usage_type: Option<String>,
    pub is_tor: bool,
    pub total_reports: u32,
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

pub fn is_public_routable_ip(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000) == 64))
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// Thread-safe, quota-guarded AbuseIPDB v2 lookup client with bounded LRU/TTL cache
/// and single-flight per-IP deduplication.
pub struct AbuseIpDbClient {
    cfg: RwLock<AbuseIpDbConfig>,
    api_base: String,
    http: reqwest::Client,
    cache: DashMap<IpAddr, CachedAbuseEntry>,
    in_flight: DashMap<IpAddr, ()>,
    daily_day: AtomicU64,
    daily_count: AtomicU32,
    backoff_until_unix: AtomicU64,
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
        Arc::new(Self {
            cfg: RwLock::new(cfg),
            api_base: endpoint.into(),
            http,
            cache: DashMap::new(),
            in_flight: DashMap::new(),
            daily_day: AtomicU64::new(current_utc_day()),
            daily_count: AtomicU32::new(0),
            backoff_until_unix: AtomicU64::new(0),
        })
    }

    pub async fn reconfigure(&self, cfg: AbuseIpDbConfig) {
        let mut g = self.cfg.write().await;
        let disabled = !cfg.enabled || cfg.api_key.trim().is_empty();
        *g = cfg;
        if disabled {
            self.cache.clear();
        }
    }

    /// Look up IP reputation. Returns immediately on cache hit; on cache miss, awaits up to
    /// `REQUEST_WAIT_BUDGET` (750ms) while letting the lookup complete in background if slow.
    pub async fn lookup(self: &Arc<Self>, raw_ip: IpAddr) -> Option<AbuseIpReport> {
        let ip = canonical_ip(raw_ip);
        if !is_public_routable_ip(ip) {
            return None;
        }
        let cfg = self.cfg.read().await.clone();
        if !cfg.enabled || cfg.api_key.trim().is_empty() {
            return None;
        }

        let now = Instant::now();
        if let Some(entry) = self.cache.get(&ip) {
            if now < entry.expires_at {
                return entry.report.clone();
            }
        }

        let now_unix = Utc::now().timestamp().max(0) as u64;
        if now_unix < self.backoff_until_unix.load(Ordering::Relaxed) {
            return None;
        }

        // Single-flight deduplication per IP
        if self.in_flight.insert(ip, ()).is_some() {
            return None;
        }

        // Daily lookup quota enforcement (preserves free-tier 1000/day API keys)
        if !self.consume_daily_quota(cfg.max_daily_lookups.max(1)) {
            self.in_flight.remove(&ip);
            return None;
        }

        let this = Arc::clone(self);
        let handle = tokio::spawn(async move {
            let res = this.fetch_and_cache(ip, &cfg).await;
            this.in_flight.remove(&ip);
            res
        });

        // Wait briefly so first request from an abusive IP gets immediate scoring,
        // without stalling benign traffic if AbuseIPDB has high latency.
        let mut handle = handle;
        match tokio::time::timeout(REQUEST_WAIT_BUDGET, &mut handle).await {
            Ok(Ok(report)) => report,
            Ok(Err(_)) => None,
            Err(_) => {
                // Keep task running in background to populate cache for subsequent requests
                None
            }
        }
    }

    fn consume_daily_quota(&self, limit: u32) -> bool {
        let today = current_utc_day();
        let prev_day = self.daily_day.load(Ordering::Relaxed);
        if prev_day != today
            && self
                .daily_day
                .compare_exchange(prev_day, today, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            self.daily_count.store(0, Ordering::Release);
        }
        let used = self.daily_count.fetch_add(1, Ordering::AcqRel);
        used < limit
    }

    async fn fetch_and_cache(&self, ip: IpAddr, cfg: &AbuseIpDbConfig) -> Option<AbuseIpReport> {
        let max_age = cfg.max_age_days.clamp(1, 365).to_string();
        let ip_str = ip.to_string();
        let resp = match self
            .http
            .get(&self.api_base)
            .query(&[("ipAddress", ip_str.as_str()), ("maxAgeInDays", max_age.as_str())])
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
            let until = (Utc::now().timestamp().max(0) as u64).saturating_add(RATE_LIMIT_BACKOFF_SECS);
            self.backoff_until_unix.store(until, Ordering::Relaxed);
            warn!("abuseipdb returned 429 Too Many Requests; backing off for {RATE_LIMIT_BACKOFF_SECS}s");
            self.insert_cache(ip, None, NEGATIVE_CACHE_TTL);
            return None;
        }

        if !resp.status().is_success() {
            debug!(ip = %ip, status = %resp.status(), "abuseipdb non-2xx status");
            self.insert_cache(ip, None, NEGATIVE_CACHE_TTL);
            return None;
        }

        let parsed = match resp.json::<AbuseApiResp>().await {
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
                self.cache.clear();
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
}
