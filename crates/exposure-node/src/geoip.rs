use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Duration;

use chrono::Utc;
use exposure_core::config::GeoIpConfig;
use exposure_core::geoip::{GeoIpDatabase, GeoLookupResult};
use exposure_core::telemetry::GeoIpStatusSnapshot;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

/// Default free CC0 IPv4 CSV mirrors (`sapics/ip-location-db`, zero registration / zero license fee).
pub const DEFAULT_GEOIP_IPV4_MIRRORS: &[&str] = &[
    "https://cdn.jsdelivr.net/npm/@ip-location-db/geo-whois-asn-country/geo-whois-asn-country-ipv4.csv",
    "https://fastly.jsdelivr.net/npm/@ip-location-db/geo-whois-asn-country/geo-whois-asn-country-ipv4.csv",
    "https://raw.githubusercontent.com/sapics/ip-location-db/main/geo-whois-asn-country/geo-whois-asn-country-ipv4.csv",
];

/// Default free CC0 IPv6 CSV mirrors (`sapics/ip-location-db`).
pub const DEFAULT_GEOIP_IPV6_MIRRORS: &[&str] = &[
    "https://cdn.jsdelivr.net/npm/@ip-location-db/geo-whois-asn-country/geo-whois-asn-country-ipv6.csv",
    "https://fastly.jsdelivr.net/npm/@ip-location-db/geo-whois-asn-country/geo-whois-asn-country-ipv6.csv",
    "https://raw.githubusercontent.com/sapics/ip-location-db/main/geo-whois-asn-country/geo-whois-asn-country-ipv6.csv",
];

const MAX_GEOIP_CSV_BYTES: usize = 24 * 1024 * 1024;
const GEOIP_FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const GEOIP_CACHE_FILENAME: &str = "geoip.bin";

#[derive(Debug, Clone)]
struct GeoIpRuntimeState {
    cfg: GeoIpConfig,
    cache_dir: PathBuf,
    allow_insecure_loopback_http: bool,
}

/// Per-node GeoIP database manager:
/// - Synchronous lock-free-like fast read (`StdRwLock<Arc<GeoIpDatabase>>`) for ~50ns Ingress lookups.
/// - Automatic background sync from free CC0 mirrors with disk binary caching (`geoip.bin`).
pub struct GeoIpManager {
    db: StdRwLock<Arc<GeoIpDatabase>>,
    state: RwLock<GeoIpRuntimeState>,
    sync_lock: Mutex<()>,
    last_error: StdRwLock<Option<String>>,
    http: reqwest::Client,
}

impl GeoIpManager {
    pub fn new(cfg: GeoIpConfig, default_cache_dir: PathBuf) -> Arc<Self> {
        Self::new_inner(cfg, default_cache_dir, false)
    }

    #[cfg(test)]
    pub fn new_for_test(cfg: GeoIpConfig, default_cache_dir: PathBuf) -> Arc<Self> {
        Self::new_inner(cfg, default_cache_dir, true)
    }

    fn new_inner(
        cfg: GeoIpConfig,
        default_cache_dir: PathBuf,
        allow_insecure_loopback_http: bool,
    ) -> Arc<Self> {
        let effective_dir = resolve_cache_dir(&cfg, &default_cache_dir);
        let initial_db = load_cached_db(&effective_dir).unwrap_or_default();
        let http = reqwest::Client::builder()
            .timeout(GEOIP_FETCH_TIMEOUT)
            .user_agent("Exposure-GeoIP-Updater/0.1")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Arc::new(Self {
            db: StdRwLock::new(Arc::new(initial_db)),
            state: RwLock::new(GeoIpRuntimeState {
                cfg,
                cache_dir: default_cache_dir,
                allow_insecure_loopback_http,
            }),
            sync_lock: Mutex::new(()),
            last_error: StdRwLock::new(None),
            http,
        })
    }

    /// Hot-reload GeoIP configuration (and try loading binary cache if directory changed & DB is empty).
    pub async fn update_config(&self, cfg: GeoIpConfig, default_cache_dir: PathBuf) {
        let new_dir = resolve_cache_dir(&cfg, &default_cache_dir);
        let mut st = self.state.write().await;
        st.cfg = cfg;
        st.cache_dir = default_cache_dir;
        drop(st);
        let need_load = self.db.read().map(|g| g.is_empty()).unwrap_or(true);
        if need_load {
            if let Some(loaded) = load_cached_db(&new_dir) {
                if let Ok(mut g) = self.db.write() {
                    *g = Arc::new(loaded);
                }
            }
        }
    }

    /// Synchronous ~50ns local lookup used on every Ingress HTTP request.
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoLookupResult> {
        let enabled = self
            .state
            .try_read()
            .map(|s| s.cfg.enabled)
            .unwrap_or(true);
        if !enabled {
            return None;
        }
        let guard = self.db.read().ok()?;
        if guard.is_empty() {
            return None;
        }
        guard.lookup(ip)
    }

    /// Install an explicit in-memory database (used in unit tests).
    pub fn set_database_for_test(&self, db: GeoIpDatabase) {
        if let Ok(mut g) = self.db.write() {
            *g = Arc::new(db);
        }
    }

    pub fn is_loaded(&self) -> bool {
        self.db.read().map(|g| !g.is_empty()).unwrap_or(false)
    }

    pub fn status(&self) -> GeoIpStatusSnapshot {
        let enabled = self
            .state
            .try_read()
            .map(|s| s.cfg.enabled)
            .unwrap_or(true);
        let db = self
            .db
            .read()
            .map(|g| Arc::clone(&*g))
            .unwrap_or_else(|_| Arc::new(GeoIpDatabase::default()));
        let last_error = self.last_error.read().ok().and_then(|e| e.clone());
        GeoIpStatusSnapshot {
            enabled,
            loaded: !db.is_empty(),
            ipv4_ranges: db.ipv4_len(),
            ipv6_ranges: db.ipv6_len(),
            updated_at: db.updated_at,
            source: db.source.clone(),
            last_error,
        }
    }

    /// Download/refresh free CC0 IPv4/IPv6 CSV databases, compile into sorted ranges,
    /// atomically persist `geoip.bin`, and hot-swap the active database.
    pub async fn sync_now(&self, force: bool) -> Result<GeoIpStatusSnapshot, String> {
        let _guard = self.sync_lock.lock().await;
        let st = self.state.read().await.clone();
        if !st.cfg.enabled {
            return Err("geoip is disabled on this node".into());
        }

        let current_db = self
            .db
            .read()
            .map(|g| Arc::clone(&*g))
            .unwrap_or_else(|_| Arc::new(GeoIpDatabase::default()));
        let max_age_secs = (st.cfg.update_interval_hours.clamp(6, 720) as i64) * 3600;
        let now_ts = Utc::now().timestamp();
        if !force
            && !current_db.is_empty()
            && current_db.updated_at > 0
            && now_ts.saturating_sub(current_db.updated_at) < max_age_secs
        {
            return Ok(self.status());
        }

        let v4_urls = build_url_list(st.cfg.ipv4_url.as_deref(), DEFAULT_GEOIP_IPV4_MIRRORS);
        let v6_urls = build_url_list(st.cfg.ipv6_url.as_deref(), DEFAULT_GEOIP_IPV6_MIRRORS);

        let (v4_csv, v4_src) =
            fetch_first_mirror(&self.http, &v4_urls, st.allow_insecure_loopback_http).await?;
        let v6_csv = match fetch_first_mirror(&self.http, &v6_urls, st.allow_insecure_loopback_http).await {
            Ok((text, _)) => Some(text),
            Err(e) => {
                warn!(error = %e, "geoip IPv6 mirror fetch failed (keeping IPv4 GeoIP coverage)");
                None
            }
        };

        let parsed = tokio::task::spawn_blocking(move || {
            GeoIpDatabase::parse_csv_ranges(Some(&v4_csv), v6_csv.as_deref(), v4_src, now_ts)
        })
        .await
        .map_err(|e| format!("geoip parse join failed: {e}"))?;

        if parsed.is_empty() {
            let msg = "downloaded GeoIP CSV contained zero valid IP ranges".to_string();
            if let Ok(mut le) = self.last_error.write() {
                *le = Some(msg.clone());
            }
            return Err(msg);
        }

        let effective_dir = resolve_cache_dir(&st.cfg, &st.cache_dir);
        let bin_bytes = parsed.encode_binary();
        let save_dir = effective_dir.clone();
        let _ = tokio::task::spawn_blocking(move || write_cached_db(&save_dir, &bin_bytes)).await;

        let v4_count = parsed.ipv4_len();
        let v6_count = parsed.ipv6_len();
        let src = parsed.source.clone();
        if let Ok(mut g) = self.db.write() {
            *g = Arc::new(parsed);
        }
        if let Ok(mut le) = self.last_error.write() {
            *le = None;
        }
        info!(
            ipv4_ranges = v4_count,
            ipv6_ranges = v6_count,
            source = %src,
            "local GeoIP database updated"
        );
        Ok(self.status())
    }

    /// Spawn automatic background updater (2s initial grace, then hourly staleness check).
    pub fn spawn_updater(self: Arc<Self>) {
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            loop {
                let st = self.state.read().await.clone();
                if st.cfg.enabled && st.cfg.auto_update {
                    if let Err(e) = self.sync_now(false).await {
                        if let Ok(mut le) = self.last_error.write() {
                            *le = Some(e.clone());
                        }
                        warn!(error = %e, "background GeoIP auto-update failed (will retry later)");
                    }
                }
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });
    }
}

fn resolve_cache_dir(cfg: &GeoIpConfig, default_dir: &Path) -> PathBuf {
    if let Some(custom) = cfg.cache_dir.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        PathBuf::from(custom)
    } else {
        default_dir.to_path_buf()
    }
}

fn load_cached_db(dir: &Path) -> Option<GeoIpDatabase> {
    let path = dir.join(GEOIP_CACHE_FILENAME);
    let bytes = std::fs::read(path).ok()?;
    GeoIpDatabase::decode_binary(&bytes).ok().filter(|db| !db.is_empty())
}

fn write_cached_db(dir: &Path, data: &[u8]) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join("geoip.bin.tmp");
    let final_path = dir.join(GEOIP_CACHE_FILENAME);
    std::fs::write(&tmp, data)?;
    std::fs::rename(tmp, final_path)?;
    Ok(())
}

fn build_url_list(custom: Option<&str>, defaults: &[&str]) -> Vec<String> {
    if let Some(u) = custom.map(str::trim).filter(|s| !s.is_empty()) {
        vec![u.to_string()]
    } else {
        defaults.iter().map(|s| (*s).to_string()).collect()
    }
}

fn validate_url_scheme(url: &str, allow_loopback_http: bool) -> Result<(), String> {
    if url.starts_with("https://") {
        return Ok(());
    }
    if allow_loopback_http
        && (url.starts_with("http://127.0.0.1:") || url.starts_with("http://[::1]:"))
    {
        return Ok(());
    }
    Err(format!("GeoIP source URL '{url}' must use https://"))
}

async fn fetch_first_mirror(
    client: &reqwest::Client,
    urls: &[String],
    allow_loopback_http: bool,
) -> Result<(String, String), String> {
    let mut last_err = "no GeoIP URLs configured".to_string();
    for url in urls {
        if let Err(e) = validate_url_scheme(url, allow_loopback_http) {
            last_err = e;
            continue;
        }
        let Ok(mut resp) = client.get(url).send().await else {
            last_err = format!("HTTP request failed for {url}");
            continue;
        };
        if !resp.status().is_success() {
            last_err = format!("HTTP {} from {url}", resp.status());
            continue;
        }
        let mut buf = Vec::new();
        let mut overflow = false;
        while let Ok(Some(chunk)) = resp.chunk().await {
            if buf.len().saturating_add(chunk.len()) > MAX_GEOIP_CSV_BYTES {
                overflow = true;
                break;
            }
            buf.extend_from_slice(&chunk);
        }
        if overflow {
            last_err = format!("GeoIP payload from {url} exceeded {MAX_GEOIP_CSV_BYTES} byte limit");
            continue;
        }
        let text = String::from_utf8_lossy(&buf).into_owned();
        return Ok((text, url.clone()));
    }
    Err(last_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn geoip_manager_downloads_caches_and_reloads_from_disk() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            for _ in 0..4 {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut req_buf = [0u8; 2048];
                    let n = sock.read(&mut req_buf).await.unwrap_or(0);
                    let req_s = String::from_utf8_lossy(&req_buf[..n]);
                    let body = if req_s.contains("ipv6") {
                        "2001:4860:4860::,2001:4860:4860:ffff:ffff:ffff:ffff:ffff,US\n"
                    } else {
                        "1.1.1.0,1.1.1.255,AU\n114.114.114.0,114.114.115.255,CN\n"
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/csv\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });

        let tmp = std::env::temp_dir().join(format!("exp-geoip-mgr-{}", uuid::Uuid::new_v4()));
        let cfg = GeoIpConfig {
            enabled: true,
            auto_update: true,
            update_interval_hours: 168,
            ipv4_url: Some(format!("http://{addr}/ipv4.csv")),
            ipv6_url: Some(format!("http://{addr}/ipv6.csv")),
            cache_dir: None,
        };
        let mgr = GeoIpManager::new_for_test(cfg.clone(), tmp.clone());
        assert!(!mgr.is_loaded());

        let snap = mgr.sync_now(true).await.expect("geoip sync should succeed");
        assert!(snap.loaded);
        assert_eq!(snap.ipv4_ranges, 2);
        assert_eq!(snap.ipv6_ranges, 1);

        assert_eq!(
            mgr.lookup("114.114.114.114".parse().unwrap()).unwrap().country_str(),
            "CN"
        );
        assert_eq!(
            mgr.lookup("2001:4860:4860::8888".parse().unwrap()).unwrap().country_str(),
            "US"
        );
        // Private IPs always return None
        assert!(mgr.lookup("127.0.0.1".parse().unwrap()).is_none());

        // Creating a fresh GeoIpManager pointing at the same cache_dir loads `geoip.bin` immediately
        let mgr2 = GeoIpManager::new_for_test(cfg, tmp.clone());
        assert!(mgr2.is_loaded());
        assert_eq!(
            mgr2.lookup("1.1.1.1".parse().unwrap()).unwrap().country_str(),
            "AU"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
