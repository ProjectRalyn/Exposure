use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};

use chrono::{DateTime, Utc};
use exposure_core::config::MaintainerRetentionConfig;
use exposure_core::crypto::{restrict_dir_permissions_0700, restrict_file_permissions_0600};
use exposure_core::segment::read_json_snapshot;
use exposure_core::telemetry::{
    is_cache_served_status, is_mitigated_record, normalize_alert_severity, AlertRecord, BanRecord,
    ClientJsFingerprint, EvilpotEventInfo, EvilpotSessionInfo, FingerprintObservation,
    HyperLogLog, LatencyHistogram, MaintainerStorageStats, MinuteSummary, SessionSummary,
};
use exposure_core::{ExposureError, Result};
use rusqlite::{params, types::Value, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

const MAX_BOUNDED_LIST: usize = 32;

#[derive(Debug, Default, Deserialize)]
struct LegacyMaintainerPersistedState {
    #[serde(default)]
    summaries: Vec<MinuteSummary>,
    #[serde(default)]
    fingerprints: Vec<FingerprintObservation>,
    #[serde(default)]
    recent_logs: Vec<SessionSummary>,
    #[serde(default)]
    alerts: Vec<AlertRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CleanupReport {
    pub expired_bans_marked: usize,
    pub deleted_access_logs: usize,
    pub deleted_summaries: usize,
    pub deleted_fingerprints: usize,
    pub deleted_evilpot_events: usize,
    pub deleted_evilpot_sessions: usize,
    pub deleted_ban_records: usize,
    pub deleted_alerts: usize,
    pub storage_stats: MaintainerStorageStats,
}

fn safe_maintainer_name(node_tag: &str) -> String {
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
    if safe.is_empty() || safe.contains("..") {
        "maintainer".to_string()
    } else {
        safe
    }
}

pub fn maintainer_db_path(dir: &str, node_tag: &str) -> PathBuf {
    let name = safe_maintainer_name(node_tag);
    PathBuf::from(dir).join(format!("maintainer-{name}.db"))
}

fn legacy_state_path(dir: &str, node_tag: &str) -> PathBuf {
    let name = safe_maintainer_name(node_tag);
    PathBuf::from(dir).join(format!("maintainer-state-{name}.json"))
}

fn escape_like_needle(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 8);
    for ch in raw.to_ascii_lowercase().chars() {
        match ch {
            '\\' | '%' | '_' => {
                out.push('\\');
                out.push(ch);
            }
            c => out.push(c),
        }
    }
    format!("%{out}%")
}

fn parse_alert_timestamp_ms(a: &AlertRecord) -> i64 {
    if a.timestamp_ms > 0 {
        return a.timestamp_ms;
    }
    DateTime::parse_from_rfc3339(a.timestamp.trim())
        .map(|dt| dt.timestamp_millis())
        .unwrap_or_else(|_| Utc::now().timestamp_millis())
}

fn compute_access_dedup_key(rec: &SessionSummary) -> String {
    let suffix = rec.ray_id.as_deref().filter(|s| !s.is_empty()).map(str::to_string).unwrap_or_else(|| {
        format!(
            "{}:{}:{}:{}",
            rec.ip_hmac,
            rec.path.as_deref().unwrap_or(""),
            rec.action.as_deref().unwrap_or(""),
            rec.status
        )
    });
    format!("{}|{}|{}|{}", rec.node_tag, rec.role, rec.timestamp_ms, suffix)
}

fn compute_evilpot_event_dedup_key(ev: &EvilpotEventInfo) -> String {
    let mut h = Sha256::new();
    h.update(ev.node_tag.as_bytes());
    h.update(b"|");
    h.update(ev.timestamp_unix.to_be_bytes());
    h.update(b"|");
    h.update(ev.client_ip.as_bytes());
    h.update(b"|");
    h.update(ev.trap_kind.as_bytes());
    h.update(b"|");
    h.update(ev.detail.as_bytes());
    hex::encode(&h.finalize()[..16])
}

fn compute_alert_dedup_key(ts_ms: i64, source: &str, severity: &str, msg: &str) -> String {
    let mut h = Sha256::new();
    h.update(ts_ms.to_be_bytes());
    h.update(b"|");
    h.update(source.as_bytes());
    h.update(b"|");
    h.update(severity.as_bytes());
    h.update(b"|");
    h.update(msg.as_bytes());
    hex::encode(&h.finalize()[..16])
}

fn status_rank(s: &str) -> i64 {
    match s {
        "verified_exploit" => 3,
        "multi_step_exploitation" => 2,
        "probing" => 1,
        _ => 0,
    }
}

fn merge_bounded_string_list(existing: Vec<String>, incoming: Vec<String>, cap: usize) -> Vec<String> {
    let mut out = existing;
    for item in incoming {
        if out.len() >= cap {
            break;
        }
        if !item.is_empty() && !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

fn clean_opt_str(v: Option<&str>) -> Option<String> {
    v.map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("all"))
        .map(str::to_string)
}

fn choose_bucket_secs(from_sec: Option<i64>, to_sec: Option<i64>, min_ep: i64, max_ep: i64) -> i64 {
    let span = match (from_sec, to_sec) {
        (Some(f), Some(t)) if t > f => t - f,
        _ => (max_ep - min_ep).max(60),
    };
    if span <= 6 * 3600 {
        60
    } else if span <= 24 * 3600 {
        300
    } else if span <= 7 * 86_400 {
        3600
    } else {
        21_600
    }
}

fn summary_to_dto_json(s: &MinuteSummary) -> serde_json::Value {
    serde_json::json!({
        "minute_epoch": s.minute_epoch,
        "node_tag": s.node_tag,
        "role": s.role,
        "service_tag": s.service_tag,
        "requests": s.requests,
        "uv_estimate": s.uv_estimate().round(),
        "errors": s.errors,
        "rate_limited": s.rate_limited,
        "challenges_issued": s.challenges_issued,
        "challenges_passed": s.challenges_passed,
        "blocked": s.blocked,
        "evilpot_hits": s.evilpot_hits,
        "autoban_hits": s.autoban_hits,
        "bytes_in": s.bytes_in,
        "bytes_out": s.bytes_out,
        "cached_requests": s.cached_requests,
        "cached_bytes_out": s.cached_bytes_out,
        "p50_ms": s.p50_ms(),
        "p95_ms": s.p95_ms(),
        "p99_ms": s.p99_ms(),
        "device_counts": s.device_counts,
        "browser_counts": s.browser_counts,
        "os_counts": s.os_counts,
        "client_fp_verified": s.client_fp_verified,
    })
}

/// Embedded SQLite WAL persistence store for Maintainer observability, telemetry, Evilpot, Bans & Alerts.
pub struct MaintainerDb {
    node_tag: String,
    db_path: PathBuf,
    write_conn: Arc<StdMutex<Connection>>,
    read_conn: Arc<StdMutex<Connection>>,
}

impl MaintainerDb {
    pub fn open(dir: &str, node_tag: impl Into<String>) -> Result<Arc<Self>> {
        let tag = node_tag.into();
        let db_path = maintainer_db_path(dir, &tag);
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
                let _ = restrict_dir_permissions_0700(parent);
            }
        }

        let write_conn = Connection::open(&db_path)
            .map_err(|e| ExposureError::Storage(format!("open maintainer sqlite {}: {e}", db_path.display())))?;
        let _ = restrict_file_permissions_0600(&db_path);

        write_conn
            .execute_batch(
                "
                PRAGMA auto_vacuum = INCREMENTAL;
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = NORMAL;
                PRAGMA busy_timeout = 5000;
                PRAGMA temp_store = MEMORY;

                CREATE TABLE IF NOT EXISTS meta (
                    k TEXT PRIMARY KEY,
                    v TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS access_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dedup_key TEXT NOT NULL UNIQUE,
                    timestamp_ms INTEGER NOT NULL,
                    node_tag TEXT NOT NULL,
                    role TEXT NOT NULL,
                    service_tag TEXT NOT NULL,
                    status INTEGER NOT NULL,
                    latency_ms REAL NOT NULL,
                    bytes_in INTEGER NOT NULL,
                    bytes_out INTEGER NOT NULL,
                    ip_hmac TEXT NOT NULL,
                    raw_ip TEXT,
                    client_country TEXT,
                    rate_limited INTEGER NOT NULL DEFAULT 0,
                    challenged INTEGER NOT NULL DEFAULT 0,
                    challenge_passed INTEGER NOT NULL DEFAULT 0,
                    error TEXT,
                    device_type TEXT,
                    browser_family TEXT,
                    os_family TEXT,
                    client_fp_verified INTEGER NOT NULL DEFAULT 0,
                    ray_id TEXT,
                    method TEXT,
                    host TEXT,
                    path TEXT,
                    query TEXT,
                    protocol TEXT,
                    scheme TEXT,
                    user_agent TEXT,
                    referer TEXT,
                    action TEXT,
                    cache_status TEXT,
                    tls_ja3 TEXT,
                    waf_rule_id INTEGER,
                    waf_category TEXT,
                    suspicion_score INTEGER,
                    repeat_count INTEGER NOT NULL DEFAULT 1
                );
                CREATE INDEX IF NOT EXISTS idx_access_ts ON access_logs(timestamp_ms DESC, id DESC);
                CREATE INDEX IF NOT EXISTS idx_access_act_ts ON access_logs(action, timestamp_ms DESC);
                CREATE INDEX IF NOT EXISTS idx_access_svc_ts ON access_logs(service_tag, timestamp_ms DESC);
                CREATE INDEX IF NOT EXISTS idx_access_node_ts ON access_logs(node_tag, timestamp_ms DESC);
                CREATE INDEX IF NOT EXISTS idx_access_ip_ts ON access_logs(ip_hmac, timestamp_ms DESC);
                CREATE INDEX IF NOT EXISTS idx_access_ray ON access_logs(ray_id);

                CREATE TABLE IF NOT EXISTS minute_summaries (
                    minute_epoch INTEGER NOT NULL,
                    node_tag TEXT NOT NULL,
                    role TEXT NOT NULL,
                    service_tag TEXT NOT NULL,
                    requests INTEGER NOT NULL DEFAULT 0,
                    errors INTEGER NOT NULL DEFAULT 0,
                    rate_limited INTEGER NOT NULL DEFAULT 0,
                    challenges_issued INTEGER NOT NULL DEFAULT 0,
                    challenges_passed INTEGER NOT NULL DEFAULT 0,
                    blocked INTEGER NOT NULL DEFAULT 0,
                    evilpot_hits INTEGER NOT NULL DEFAULT 0,
                    autoban_hits INTEGER NOT NULL DEFAULT 0,
                    bytes_in INTEGER NOT NULL DEFAULT 0,
                    bytes_out INTEGER NOT NULL DEFAULT 0,
                    cached_requests INTEGER NOT NULL DEFAULT 0,
                    cached_bytes_out INTEGER NOT NULL DEFAULT 0,
                    client_fp_verified INTEGER NOT NULL DEFAULT 0,
                    uv_hll_json TEXT NOT NULL,
                    latency_hist_json TEXT NOT NULL,
                    device_counts_json TEXT NOT NULL,
                    browser_counts_json TEXT NOT NULL,
                    os_counts_json TEXT NOT NULL,
                    PRIMARY KEY (minute_epoch, node_tag, role, service_tag)
                );
                CREATE INDEX IF NOT EXISTS idx_msum_ep ON minute_summaries(minute_epoch DESC);

                CREATE TABLE IF NOT EXISTS fingerprints (
                    id TEXT PRIMARY KEY,
                    ip_hmac TEXT NOT NULL,
                    client_ip TEXT,
                    ip_prefix TEXT NOT NULL DEFAULT '',
                    fp_hash TEXT NOT NULL,
                    js_verified INTEGER NOT NULL DEFAULT 0,
                    fp_source TEXT NOT NULL DEFAULT 'none',
                    node_tag TEXT NOT NULL,
                    service_tag TEXT NOT NULL,
                    host TEXT NOT NULL DEFAULT '',
                    user_agent TEXT NOT NULL DEFAULT '',
                    accept_language TEXT NOT NULL DEFAULT '',
                    device_type TEXT NOT NULL DEFAULT '',
                    browser_family TEXT NOT NULL DEFAULT '',
                    os_family TEXT NOT NULL DEFAULT '',
                    is_bot INTEGER NOT NULL DEFAULT 0,
                    is_headless INTEGER NOT NULL DEFAULT 0,
                    suspicion_score INTEGER NOT NULL DEFAULT 0,
                    tls_cipher_count INTEGER NOT NULL DEFAULT 0,
                    tls_alpn INTEGER NOT NULL DEFAULT 0,
                    tls_ja3 TEXT,
                    tls_grease INTEGER NOT NULL DEFAULT 0,
                    abuse_score INTEGER,
                    abuse_country TEXT,
                    abuse_isp TEXT,
                    abuse_is_tor INTEGER NOT NULL DEFAULT 0,
                    geo_country TEXT,
                    geo_continent TEXT,
                    js_fp_json TEXT,
                    first_seen_ts INTEGER NOT NULL,
                    last_seen_ts INTEGER NOT NULL,
                    request_count INTEGER NOT NULL DEFAULT 0,
                    challenge_count INTEGER NOT NULL DEFAULT 0,
                    rate_limited_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_fp_last ON fingerprints(last_seen_ts DESC);
                CREATE INDEX IF NOT EXISTS idx_fp_ip ON fingerprints(ip_hmac);
                CREATE INDEX IF NOT EXISTS idx_fp_node ON fingerprints(node_tag, last_seen_ts DESC);
                CREATE INDEX IF NOT EXISTS idx_fp_svc ON fingerprints(service_tag, last_seen_ts DESC);

                CREATE TABLE IF NOT EXISTS evilpot_sessions (
                    node_tag TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    epoch_id INTEGER NOT NULL DEFAULT 0,
                    persona_hostname TEXT NOT NULL DEFAULT '',
                    first_seen_unix INTEGER NOT NULL,
                    last_seen_unix INTEGER NOT NULL,
                    total_trapped_requests INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'probing',
                    status_rank INTEGER NOT NULL DEFAULT 1,
                    canary_triggers INTEGER NOT NULL DEFAULT 0,
                    sqli_probes INTEGER NOT NULL DEFAULT 0,
                    sqli_distinct_positions INTEGER NOT NULL DEFAULT 0,
                    rce_commands_json TEXT NOT NULL DEFAULT '[]',
                    captured_iocs_json TEXT NOT NULL DEFAULT '[]',
                    distinct_paths_json TEXT NOT NULL DEFAULT '[]',
                    tarpit_bytes_consumed INTEGER NOT NULL DEFAULT 0,
                    tarpit_max_duration_ms INTEGER NOT NULL DEFAULT 0,
                    evidence_json TEXT NOT NULL DEFAULT '[]',
                    PRIMARY KEY (node_tag, client_ip)
                );
                CREATE INDEX IF NOT EXISTS idx_eps_rank_seen ON evilpot_sessions(status_rank DESC, last_seen_unix DESC);
                CREATE INDEX IF NOT EXISTS idx_eps_seen ON evilpot_sessions(last_seen_unix DESC);

                CREATE TABLE IF NOT EXISTS evilpot_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dedup_key TEXT NOT NULL UNIQUE,
                    timestamp_unix INTEGER NOT NULL,
                    node_tag TEXT NOT NULL,
                    epoch_id INTEGER NOT NULL DEFAULT 0,
                    persona_hostname TEXT NOT NULL DEFAULT '',
                    client_ip TEXT NOT NULL,
                    verification_status TEXT NOT NULL,
                    trap_kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    evidence_json TEXT NOT NULL DEFAULT '[]'
                );
                CREATE INDEX IF NOT EXISTS idx_epe_ts ON evilpot_events(timestamp_unix DESC, id DESC);
                CREATE INDEX IF NOT EXISTS idx_epe_node_ts ON evilpot_events(node_tag, timestamp_unix DESC);
                CREATE INDEX IF NOT EXISTS idx_epe_ip_ts ON evilpot_events(client_ip, timestamp_unix DESC);
                CREATE INDEX IF NOT EXISTS idx_epe_st_ts ON evilpot_events(verification_status, timestamp_unix DESC);

                CREATE TABLE IF NOT EXISTS ban_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    node_tag TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    target TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    service_tag TEXT,
                    host TEXT,
                    offense_level INTEGER NOT NULL DEFAULT 1,
                    banned_at_unix INTEGER NOT NULL,
                    expires_at_unix INTEGER NOT NULL,
                    unbanned_at_unix INTEGER,
                    unbanned_by TEXT,
                    hits_blocked INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'active',
                    UNIQUE(node_tag, kind, target, banned_at_unix)
                );
                CREATE INDEX IF NOT EXISTS idx_ban_st_ts ON ban_records(status, banned_at_unix DESC);
                CREATE INDEX IF NOT EXISTS idx_ban_ts ON ban_records(banned_at_unix DESC, id DESC);
                CREATE INDEX IF NOT EXISTS idx_ban_exp ON ban_records(expires_at_unix);
                CREATE INDEX IF NOT EXISTS idx_ban_target ON ban_records(target);

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dedup_key TEXT NOT NULL UNIQUE,
                    timestamp_ms INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    source TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp_ms DESC, id DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_sev_ts ON alerts(severity, timestamp_ms DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_src_ts ON alerts(source, timestamp_ms DESC);
                ",
            )
            .map_err(|e| ExposureError::Storage(format!("init maintainer sqlite schema: {e}")))?;

        // One-time import from legacy maintainer-state-{tag}.json if DB is brand new
        let legacy_path = legacy_state_path(dir, &tag);
        if legacy_path.exists() {
            let empty_db: bool = write_conn
                .query_row(
                    "SELECT (SELECT COUNT(*) FROM access_logs) + (SELECT COUNT(*) FROM minute_summaries) + (SELECT COUNT(*) FROM alerts) = 0",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(false);
            if empty_db {
                if let Ok(Some(st)) = read_json_snapshot::<LegacyMaintainerPersistedState>(&legacy_path) {
                    let count = st.recent_logs.len() + st.summaries.len() + st.fingerprints.len() + st.alerts.len();
                    if count > 0 {
                        if let Err(e) = Self::ingest_sync(
                            &write_conn,
                            &tag,
                            true,
                            &MaintainerRetentionConfig::default(),
                            st.recent_logs,
                            st.summaries,
                            st.fingerprints,
                            Vec::new(),
                            Vec::new(),
                            Vec::new(),
                            st.alerts,
                        ) {
                            warn!(error = %e, "failed to import legacy maintainer-state json");
                        } else {
                            info!(node = %tag, imported = count, "migrated legacy maintainer state into SQLite WAL");
                        }
                    }
                    let _ = std::fs::remove_file(&legacy_path);
                }
            }
        }

        let wal_path = PathBuf::from(format!("{}-wal", db_path.display()));
        let shm_path = PathBuf::from(format!("{}-shm", db_path.display()));
        let _ = restrict_file_permissions_0600(&wal_path);
        let _ = restrict_file_permissions_0600(&shm_path);

        let read_conn = Connection::open_with_flags(
            &db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| ExposureError::Storage(format!("open maintainer sqlite read conn: {e}")))?;
        let _ = read_conn.execute_batch("PRAGMA busy_timeout = 5000;");

        Ok(Arc::new(Self {
            node_tag: tag,
            db_path,
            write_conn: Arc::new(StdMutex::new(write_conn)),
            read_conn: Arc::new(StdMutex::new(read_conn)),
        }))
    }

    async fn run_write<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let conn = Arc::clone(&self.write_conn);
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock().unwrap_or_else(|e| e.into_inner());
            f(&mut guard)
        })
        .await
        .map_err(|e| ExposureError::Storage(format!("maintainer db write join: {e}")))?
    }

    async fn run_read<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let conn = Arc::clone(&self.read_conn);
        tokio::task::spawn_blocking(move || {
            let guard = conn.lock().unwrap_or_else(|e| e.into_inner());
            f(&guard)
        })
        .await
        .map_err(|e| ExposureError::Storage(format!("maintainer db read join: {e}")))?
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn ingest_batch(
        &self,
        from_node: &str,
        store_raw_ip: bool,
        retention: &MaintainerRetentionConfig,
        records: Vec<SessionSummary>,
        summaries: Vec<MinuteSummary>,
        fingerprints: Vec<FingerprintObservation>,
        evilpot_sessions: Vec<EvilpotSessionInfo>,
        evilpot_events: Vec<EvilpotEventInfo>,
        ban_records: Vec<BanRecord>,
        alerts: Vec<AlertRecord>,
    ) -> Result<usize> {
        let from_owned = from_node.to_string();
        let ret = retention.clone();
        self.run_write(move |conn| {
            Self::ingest_sync(
                conn,
                &from_owned,
                store_raw_ip,
                &ret,
                records,
                summaries,
                fingerprints,
                evilpot_sessions,
                evilpot_events,
                ban_records,
                alerts,
            )
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    fn ingest_sync(
        conn: &Connection,
        from_node: &str,
        store_raw_ip: bool,
        ret: &MaintainerRetentionConfig,
        records: Vec<SessionSummary>,
        summaries: Vec<MinuteSummary>,
        fingerprints: Vec<FingerprintObservation>,
        evilpot_sessions: Vec<EvilpotSessionInfo>,
        evilpot_events: Vec<EvilpotEventInfo>,
        ban_records: Vec<BanRecord>,
        alerts: Vec<AlertRecord>,
    ) -> Result<usize> {
        let now_ts = Utc::now().timestamp();
        let max_allowed = now_ts.saturating_add(300);

        let access_min_ts = if ret.access_logs_retention_hours > 0 {
            now_ts.saturating_sub((ret.access_logs_retention_hours as i64).saturating_mul(3600))
        } else {
            0
        };
        let stats_min_ts = if ret.stats_retention_days > 0 {
            now_ts.saturating_sub((ret.stats_retention_days as i64).saturating_mul(86_400))
        } else {
            0
        };
        let fp_min_ts = if ret.fingerprints_retention_days > 0 {
            now_ts.saturating_sub((ret.fingerprints_retention_days as i64).saturating_mul(86_400))
        } else {
            0
        };
        let ep_min_ts = if ret.evilpot_retention_days > 0 {
            now_ts.saturating_sub((ret.evilpot_retention_days as i64).saturating_mul(86_400))
        } else {
            0
        }
        .max(0) as u64;
        let ban_min_ts = if ret.bans_retention_days > 0 {
            now_ts.saturating_sub((ret.bans_retention_days as i64).saturating_mul(86_400))
        } else {
            0
        }
        .max(0) as u64;
        let alert_min_ms = if ret.alerts_retention_days > 0 {
            now_ts
                .saturating_sub((ret.alerts_retention_days as i64).saturating_mul(86_400))
                .saturating_mul(1000)
        } else {
            0
        };

        conn.execute_batch("BEGIN IMMEDIATE;")
            .map_err(|e| ExposureError::Storage(format!("begin immediate: {e}")))?;

        let res = (|| -> Result<usize> {
            let mut total_accepted = 0usize;

            if !records.is_empty() {
                let mut stmt = conn
                    .prepare_cached(
                        "INSERT INTO access_logs (
                            dedup_key, timestamp_ms, node_tag, role, service_tag, status, latency_ms,
                            bytes_in, bytes_out, ip_hmac, raw_ip, client_country, rate_limited,
                            challenged, challenge_passed, error, device_type, browser_family,
                            os_family, client_fp_verified, ray_id, method, host, path, query,
                            protocol, scheme, user_agent, referer, action, cache_status, tls_ja3,
                            waf_rule_id, waf_category, suspicion_score, repeat_count
                        ) VALUES (
                            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                            ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28,
                            ?29, ?30, ?31, ?32, ?33, ?34, ?35, ?36
                        )
                        ON CONFLICT(dedup_key) DO UPDATE SET
                            repeat_count = MAX(access_logs.repeat_count, excluded.repeat_count)",
                    )
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;

                for mut r in records.into_iter().take(4096) {
                    let rec_sec = r.timestamp_ms / 1000;
                    if rec_sec < access_min_ts || rec_sec > max_allowed {
                        continue;
                    }
                    if !store_raw_ip {
                        r.raw_ip = None;
                    }
                    r.sanitize();
                    if r.node_tag.is_empty() {
                        r.node_tag = from_node.to_string();
                    }
                    let dedup = compute_access_dedup_key(&r);
                    stmt.execute(params![
                        dedup,
                        r.timestamp_ms,
                        r.node_tag,
                        r.role,
                        r.service_tag,
                        i64::from(r.status),
                        r.latency_ms,
                        r.bytes_in as i64,
                        r.bytes_out as i64,
                        r.ip_hmac,
                        r.raw_ip,
                        r.client_country,
                        i64::from(r.rate_limited),
                        i64::from(r.challenged),
                        i64::from(r.challenge_passed),
                        r.error,
                        r.device_type,
                        r.browser_family,
                        r.os_family,
                        i64::from(r.client_fp_verified),
                        r.ray_id,
                        r.method,
                        r.host,
                        r.path,
                        r.query,
                        r.protocol,
                        r.scheme,
                        r.user_agent,
                        r.referer,
                        r.action,
                        r.cache_status,
                        r.tls_ja3,
                        r.waf_rule_id.map(i64::from),
                        r.waf_category,
                        r.suspicion_score.map(i64::from),
                        i64::from(r.repeat_count.max(1)),
                    ])
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
                    total_accepted += 1;
                }
            }

            if !summaries.is_empty() {
                let mut sel = conn
                    .prepare_cached(
                        "SELECT requests, errors, rate_limited, challenges_issued, challenges_passed,
                                blocked, evilpot_hits, autoban_hits, bytes_in, bytes_out,
                                cached_requests, cached_bytes_out, client_fp_verified,
                                uv_hll_json, latency_hist_json, device_counts_json,
                                browser_counts_json, os_counts_json
                         FROM minute_summaries
                         WHERE minute_epoch = ?1 AND node_tag = ?2 AND role = ?3 AND service_tag = ?4",
                    )
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
                let mut up = conn
                    .prepare_cached(
                        "INSERT INTO minute_summaries (
                            minute_epoch, node_tag, role, service_tag, requests, errors,
                            rate_limited, challenges_issued, challenges_passed, blocked,
                            evilpot_hits, autoban_hits, bytes_in, bytes_out, cached_requests,
                            cached_bytes_out, client_fp_verified, uv_hll_json, latency_hist_json,
                            device_counts_json, browser_counts_json, os_counts_json
                        ) VALUES (
                            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                            ?16, ?17, ?18, ?19, ?20, ?21, ?22
                        )
                        ON CONFLICT(minute_epoch, node_tag, role, service_tag) DO UPDATE SET
                            requests = excluded.requests,
                            errors = excluded.errors,
                            rate_limited = excluded.rate_limited,
                            challenges_issued = excluded.challenges_issued,
                            challenges_passed = excluded.challenges_passed,
                            blocked = excluded.blocked,
                            evilpot_hits = excluded.evilpot_hits,
                            autoban_hits = excluded.autoban_hits,
                            bytes_in = excluded.bytes_in,
                            bytes_out = excluded.bytes_out,
                            cached_requests = excluded.cached_requests,
                            cached_bytes_out = excluded.cached_bytes_out,
                            client_fp_verified = excluded.client_fp_verified,
                            uv_hll_json = excluded.uv_hll_json,
                            latency_hist_json = excluded.latency_hist_json,
                            device_counts_json = excluded.device_counts_json,
                            browser_counts_json = excluded.browser_counts_json,
                            os_counts_json = excluded.os_counts_json",
                    )
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;

                for s in summaries.into_iter().take(1024) {
                    if s.minute_epoch < stats_min_ts || s.minute_epoch > max_allowed || !s.uv_hll.is_valid() {
                        continue;
                    }
                    let existing: Option<MinuteSummary> = sel
                        .query_row(
                            params![s.minute_epoch, &s.node_tag, &s.role, &s.service_tag],
                            |row| {
                                let uv_json: String = row.get(13)?;
                                let hist_json: String = row.get(14)?;
                                let dev_json: String = row.get(15)?;
                                let br_json: String = row.get(16)?;
                                let os_json: String = row.get(17)?;
                                Ok(MinuteSummary {
                                    minute_epoch: s.minute_epoch,
                                    node_tag: s.node_tag.clone(),
                                    role: s.role.clone(),
                                    service_tag: s.service_tag.clone(),
                                    requests: row.get::<_, i64>(0)?.max(0) as u64,
                                    errors: row.get::<_, i64>(1)?.max(0) as u64,
                                    rate_limited: row.get::<_, i64>(2)?.max(0) as u64,
                                    challenges_issued: row.get::<_, i64>(3)?.max(0) as u64,
                                    challenges_passed: row.get::<_, i64>(4)?.max(0) as u64,
                                    blocked: row.get::<_, i64>(5)?.max(0) as u64,
                                    evilpot_hits: row.get::<_, i64>(6)?.max(0) as u64,
                                    autoban_hits: row.get::<_, i64>(7)?.max(0) as u64,
                                    bytes_in: row.get::<_, i64>(8)?.max(0) as u64,
                                    bytes_out: row.get::<_, i64>(9)?.max(0) as u64,
                                    cached_requests: row.get::<_, i64>(10)?.max(0) as u64,
                                    cached_bytes_out: row.get::<_, i64>(11)?.max(0) as u64,
                                    client_fp_verified: row.get::<_, i64>(12)?.max(0) as u64,
                                    uv_hll: serde_json::from_str(&uv_json).unwrap_or_else(|_| s.uv_hll.clone()),
                                    latency_hist: serde_json::from_str(&hist_json).unwrap_or_else(|_| s.latency_hist.clone()),
                                    device_counts: serde_json::from_str(&dev_json).unwrap_or_default(),
                                    browser_counts: serde_json::from_str(&br_json).unwrap_or_default(),
                                    os_counts: serde_json::from_str(&os_json).unwrap_or_default(),
                                })
                            },
                        )
                        .optional()
                        .map_err(|e| ExposureError::Storage(e.to_string()))?;

                    let merged = if let Some(mut acc) = existing {
                        acc.merge_from(&s);
                        acc
                    } else {
                        s
                    };
                    let uv_json = serde_json::to_string(&merged.uv_hll).unwrap_or_default();
                    let hist_json = serde_json::to_string(&merged.latency_hist).unwrap_or_default();
                    let dev_json = serde_json::to_string(&merged.device_counts).unwrap_or_else(|_| "{}".into());
                    let br_json = serde_json::to_string(&merged.browser_counts).unwrap_or_else(|_| "{}".into());
                    let os_json = serde_json::to_string(&merged.os_counts).unwrap_or_else(|_| "{}".into());

                    up.execute(params![
                        merged.minute_epoch,
                        merged.node_tag,
                        merged.role,
                        merged.service_tag,
                        merged.requests as i64,
                        merged.errors as i64,
                        merged.rate_limited as i64,
                        merged.challenges_issued as i64,
                        merged.challenges_passed as i64,
                        merged.blocked as i64,
                        merged.evilpot_hits as i64,
                        merged.autoban_hits as i64,
                        merged.bytes_in as i64,
                        merged.bytes_out as i64,
                        merged.cached_requests as i64,
                        merged.cached_bytes_out as i64,
                        merged.client_fp_verified as i64,
                        uv_json,
                        hist_json,
                        dev_json,
                        br_json,
                        os_json,
                    ])
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
                    total_accepted += 1;
                }
            }

            if !fingerprints.is_empty() {
                let mut sel = conn
                    .prepare_cached(
                        "SELECT ip_hmac, client_ip, ip_prefix, fp_hash, js_verified, fp_source,
                                node_tag, service_tag, host, user_agent, accept_language,
                                device_type, browser_family, os_family, is_bot, is_headless,
                                suspicion_score, tls_cipher_count, tls_alpn, tls_ja3, tls_grease,
                                abuse_score, abuse_country, abuse_isp, abuse_is_tor,
                                geo_country, geo_continent, js_fp_json, first_seen_ts,
                                last_seen_ts, request_count, challenge_count, rate_limited_count
                         FROM fingerprints WHERE id = ?1",
                    )
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
                let mut up = conn
                    .prepare_cached(
                        "INSERT INTO fingerprints (
                            id, ip_hmac, client_ip, ip_prefix, fp_hash, js_verified, fp_source,
                            node_tag, service_tag, host, user_agent, accept_language,
                            device_type, browser_family, os_family, is_bot, is_headless,
                            suspicion_score, tls_cipher_count, tls_alpn, tls_ja3, tls_grease,
                            abuse_score, abuse_country, abuse_isp, abuse_is_tor,
                            geo_country, geo_continent, js_fp_json, first_seen_ts,
                            last_seen_ts, request_count, challenge_count, rate_limited_count
                        ) VALUES (
                            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                            ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28,
                            ?29, ?30, ?31, ?32, ?33, ?34
                        )
                        ON CONFLICT(id) DO UPDATE SET
                            ip_hmac = excluded.ip_hmac,
                            client_ip = excluded.client_ip,
                            ip_prefix = excluded.ip_prefix,
                            fp_hash = excluded.fp_hash,
                            js_verified = excluded.js_verified,
                            fp_source = excluded.fp_source,
                            node_tag = excluded.node_tag,
                            service_tag = excluded.service_tag,
                            host = excluded.host,
                            user_agent = excluded.user_agent,
                            accept_language = excluded.accept_language,
                            device_type = excluded.device_type,
                            browser_family = excluded.browser_family,
                            os_family = excluded.os_family,
                            is_bot = excluded.is_bot,
                            is_headless = excluded.is_headless,
                            suspicion_score = excluded.suspicion_score,
                            tls_cipher_count = excluded.tls_cipher_count,
                            tls_alpn = excluded.tls_alpn,
                            tls_ja3 = excluded.tls_ja3,
                            tls_grease = excluded.tls_grease,
                            abuse_score = excluded.abuse_score,
                            abuse_country = excluded.abuse_country,
                            abuse_isp = excluded.abuse_isp,
                            abuse_is_tor = excluded.abuse_is_tor,
                            geo_country = excluded.geo_country,
                            geo_continent = excluded.geo_continent,
                            js_fp_json = excluded.js_fp_json,
                            first_seen_ts = excluded.first_seen_ts,
                            last_seen_ts = excluded.last_seen_ts,
                            request_count = excluded.request_count,
                            challenge_count = excluded.challenge_count,
                            rate_limited_count = excluded.rate_limited_count",
                    )
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;

                for mut fp in fingerprints.into_iter().take(2048) {
                    if fp.last_seen_ts < fp_min_ts || fp.last_seen_ts > max_allowed {
                        continue;
                    }
                    if !store_raw_ip {
                        fp.client_ip = None;
                    }
                    fp.sanitize();
                    if !store_raw_ip {
                        if let Some(ref mut js) = fp.js_fp {
                            js.mask_raw_ips();
                        }
                    }
                    if fp.id.is_empty() {
                        continue;
                    }
                    let existing: Option<FingerprintObservation> = sel
                        .query_row(params![&fp.id], |row| {
                            let js_str: Option<String> = row.get(27)?;
                            let js_fp = js_str.and_then(|s| serde_json::from_str::<ClientJsFingerprint>(&s).ok());
                            Ok(FingerprintObservation {
                                id: fp.id.clone(),
                                ip_hmac: row.get(0)?,
                                client_ip: row.get(1)?,
                                ip_prefix: row.get(2)?,
                                fp_hash: row.get(3)?,
                                js_verified: row.get::<_, i64>(4)? != 0,
                                fp_source: row.get(5)?,
                                node_tag: row.get(6)?,
                                service_tag: row.get(7)?,
                                host: row.get(8)?,
                                user_agent: row.get(9)?,
                                accept_language: row.get(10)?,
                                device_type: row.get(11)?,
                                browser_family: row.get(12)?,
                                os_family: row.get(13)?,
                                is_bot: row.get::<_, i64>(14)? != 0,
                                is_headless: row.get::<_, i64>(15)? != 0,
                                suspicion_score: row.get::<_, i64>(16)?.clamp(0, 255) as u8,
                                tls_cipher_count: row.get::<_, i64>(17)?.clamp(0, u16::MAX as i64) as u16,
                                tls_alpn: row.get::<_, i64>(18)? != 0,
                                tls_ja3: row.get(19)?,
                                tls_grease: row.get::<_, i64>(20)? != 0,
                                abuse_score: row.get::<_, Option<i64>>(21)?.map(|v| v.clamp(0, 100) as u8),
                                abuse_country: row.get(22)?,
                                abuse_isp: row.get(23)?,
                                abuse_is_tor: row.get::<_, i64>(24)? != 0,
                                geo_country: row.get(25)?,
                                geo_continent: row.get(26)?,
                                js_fp,
                                first_seen_ts: row.get(28)?,
                                last_seen_ts: row.get(29)?,
                                request_count: row.get::<_, i64>(30)?.max(0) as u64,
                                challenge_count: row.get::<_, i64>(31)?.max(0) as u64,
                                rate_limited_count: row.get::<_, i64>(32)?.max(0) as u64,
                            })
                        })
                        .optional()
                        .map_err(|e| ExposureError::Storage(e.to_string()))?;

                    let merged = if let Some(mut acc) = existing {
                        acc.merge_from(&fp);
                        acc
                    } else {
                        fp
                    };
                    let js_json = merged
                        .js_fp
                        .as_ref()
                        .and_then(|j| serde_json::to_string(j).ok());
                    up.execute(params![
                        merged.id,
                        merged.ip_hmac,
                        merged.client_ip,
                        merged.ip_prefix,
                        merged.fp_hash,
                        i64::from(merged.js_verified),
                        merged.fp_source,
                        merged.node_tag,
                        merged.service_tag,
                        merged.host,
                        merged.user_agent,
                        merged.accept_language,
                        merged.device_type,
                        merged.browser_family,
                        merged.os_family,
                        i64::from(merged.is_bot),
                        i64::from(merged.is_headless),
                        i64::from(merged.suspicion_score),
                        i64::from(merged.tls_cipher_count),
                        i64::from(merged.tls_alpn),
                        merged.tls_ja3,
                        i64::from(merged.tls_grease),
                        merged.abuse_score.map(i64::from),
                        merged.abuse_country,
                        merged.abuse_isp,
                        i64::from(merged.abuse_is_tor),
                        merged.geo_country,
                        merged.geo_continent,
                        js_json,
                        merged.first_seen_ts,
                        merged.last_seen_ts,
                        merged.request_count as i64,
                        merged.challenge_count as i64,
                        merged.rate_limited_count as i64,
                    ])
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
                    total_accepted += 1;
                }
            }

            if !evilpot_sessions.is_empty() {
                let mut sel = conn
                    .prepare_cached(
                        "SELECT epoch_id, persona_hostname, first_seen_unix, last_seen_unix,
                                total_trapped_requests, status, status_rank, canary_triggers,
                                sqli_probes, sqli_distinct_positions, rce_commands_json,
                                captured_iocs_json, distinct_paths_json, tarpit_bytes_consumed,
                                tarpit_max_duration_ms, evidence_json
                         FROM evilpot_sessions
                         WHERE node_tag = ?1 AND client_ip = ?2",
                    )
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
                let mut up = conn
                    .prepare_cached(
                        "INSERT INTO evilpot_sessions (
                            node_tag, client_ip, epoch_id, persona_hostname, first_seen_unix,
                            last_seen_unix, total_trapped_requests, status, status_rank,
                            canary_triggers, sqli_probes, sqli_distinct_positions,
                            rce_commands_json, captured_iocs_json, distinct_paths_json,
                            tarpit_bytes_consumed, tarpit_max_duration_ms, evidence_json
                        ) VALUES (
                            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                            ?16, ?17, ?18
                        )
                        ON CONFLICT(node_tag, client_ip) DO UPDATE SET
                            epoch_id = excluded.epoch_id,
                            persona_hostname = excluded.persona_hostname,
                            first_seen_unix = excluded.first_seen_unix,
                            last_seen_unix = excluded.last_seen_unix,
                            total_trapped_requests = excluded.total_trapped_requests,
                            status = excluded.status,
                            status_rank = excluded.status_rank,
                            canary_triggers = excluded.canary_triggers,
                            sqli_probes = excluded.sqli_probes,
                            sqli_distinct_positions = excluded.sqli_distinct_positions,
                            rce_commands_json = excluded.rce_commands_json,
                            captured_iocs_json = excluded.captured_iocs_json,
                            distinct_paths_json = excluded.distinct_paths_json,
                            tarpit_bytes_consumed = excluded.tarpit_bytes_consumed,
                            tarpit_max_duration_ms = excluded.tarpit_max_duration_ms,
                            evidence_json = excluded.evidence_json",
                    )
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;

                for mut s in evilpot_sessions.into_iter().take(1024) {
                    if s.last_seen_unix < ep_min_ts || s.last_seen_unix > max_allowed.max(0) as u64 {
                        continue;
                    }
                    if s.node_tag.is_empty() {
                        s.node_tag = from_node.to_string();
                    }
                    let existing: Option<(EvilpotSessionInfo, i64)> = sel
                        .query_row(params![&s.node_tag, &s.client_ip], |row| {
                            let rce_s: String = row.get(10)?;
                            let ioc_s: String = row.get(11)?;
                            let path_s: String = row.get(12)?;
                            let ev_s: String = row.get(15)?;
                            let rank: i64 = row.get(6)?;
                            Ok((
                                EvilpotSessionInfo {
                                    node_tag: s.node_tag.clone(),
                                    client_ip: s.client_ip.clone(),
                                    epoch_id: row.get::<_, i64>(0)?.max(0) as u64,
                                    persona_hostname: row.get(1)?,
                                    first_seen_unix: row.get::<_, i64>(2)?.max(0) as u64,
                                    last_seen_unix: row.get::<_, i64>(3)?.max(0) as u64,
                                    total_trapped_requests: row.get::<_, i64>(4)?.max(0) as u64,
                                    status: row.get(5)?,
                                    canary_triggers: row.get::<_, i64>(7)?.max(0) as u32,
                                    sqli_probes: row.get::<_, i64>(8)?.max(0) as u32,
                                    sqli_distinct_positions: row.get::<_, i64>(9)?.max(0) as usize,
                                    rce_commands_executed: serde_json::from_str(&rce_s).unwrap_or_default(),
                                    captured_iocs: serde_json::from_str(&ioc_s).unwrap_or_default(),
                                    distinct_paths: serde_json::from_str(&path_s).unwrap_or_default(),
                                    tarpit_bytes_consumed: row.get::<_, i64>(13)?.max(0) as u64,
                                    tarpit_max_duration_ms: row.get::<_, i64>(14)?.max(0) as u64,
                                    evidence: serde_json::from_str(&ev_s).unwrap_or_default(),
                                },
                                rank,
                            ))
                        })
                        .optional()
                        .map_err(|e| ExposureError::Storage(e.to_string()))?;

                    let (merged, merged_rank) = if let Some((old, old_rank)) = existing {
                        let new_rank = status_rank(&s.status);
                        let (best_status, best_rank) = if new_rank >= old_rank {
                            (s.status.clone(), new_rank)
                        } else {
                            (old.status.clone(), old_rank)
                        };
                        let first_seen = match (old.first_seen_unix, s.first_seen_unix) {
                            (0, b) => b,
                            (a, 0) => a,
                            (a, b) => a.min(b),
                        };
                        let m = EvilpotSessionInfo {
                            node_tag: s.node_tag.clone(),
                            client_ip: s.client_ip.clone(),
                            epoch_id: s.epoch_id.max(old.epoch_id),
                            persona_hostname: if s.persona_hostname.is_empty() {
                                old.persona_hostname
                            } else {
                                s.persona_hostname
                            },
                            first_seen_unix: first_seen,
                            last_seen_unix: s.last_seen_unix.max(old.last_seen_unix),
                            total_trapped_requests: s.total_trapped_requests.max(old.total_trapped_requests),
                            status: best_status,
                            canary_triggers: s.canary_triggers.max(old.canary_triggers),
                            sqli_probes: s.sqli_probes.max(old.sqli_probes),
                            sqli_distinct_positions: s
                                .sqli_distinct_positions
                                .max(old.sqli_distinct_positions),
                            rce_commands_executed: merge_bounded_string_list(
                                old.rce_commands_executed,
                                s.rce_commands_executed,
                                MAX_BOUNDED_LIST,
                            ),
                            captured_iocs: merge_bounded_string_list(
                                old.captured_iocs,
                                s.captured_iocs,
                                MAX_BOUNDED_LIST,
                            ),
                            distinct_paths: merge_bounded_string_list(
                                old.distinct_paths,
                                s.distinct_paths,
                                MAX_BOUNDED_LIST,
                            ),
                            tarpit_bytes_consumed: s.tarpit_bytes_consumed.max(old.tarpit_bytes_consumed),
                            tarpit_max_duration_ms: s
                                .tarpit_max_duration_ms
                                .max(old.tarpit_max_duration_ms),
                            evidence: merge_bounded_string_list(
                                old.evidence,
                                s.evidence,
                                MAX_BOUNDED_LIST,
                            ),
                        };
                        (m, best_rank)
                    } else {
                        let rk = status_rank(&s.status);
                        (s, rk)
                    };

                    up.execute(params![
                        merged.node_tag,
                        merged.client_ip,
                        merged.epoch_id as i64,
                        merged.persona_hostname,
                        merged.first_seen_unix as i64,
                        merged.last_seen_unix as i64,
                        merged.total_trapped_requests as i64,
                        merged.status,
                        merged_rank,
                        i64::from(merged.canary_triggers),
                        i64::from(merged.sqli_probes),
                        merged.sqli_distinct_positions as i64,
                        serde_json::to_string(&merged.rce_commands_executed).unwrap_or_else(|_| "[]".into()),
                        serde_json::to_string(&merged.captured_iocs).unwrap_or_else(|_| "[]".into()),
                        serde_json::to_string(&merged.distinct_paths).unwrap_or_else(|_| "[]".into()),
                        merged.tarpit_bytes_consumed as i64,
                        merged.tarpit_max_duration_ms as i64,
                        serde_json::to_string(&merged.evidence).unwrap_or_else(|_| "[]".into()),
                    ])
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
                    total_accepted += 1;
                }
            }

            if !evilpot_events.is_empty() {
                let mut stmt = conn
                    .prepare_cached(
                        "INSERT OR IGNORE INTO evilpot_events (
                            dedup_key, timestamp_unix, node_tag, epoch_id, persona_hostname,
                            client_ip, verification_status, trap_kind, detail, evidence_json
                        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    )
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;

                for mut ev in evilpot_events.into_iter().take(2048) {
                    if ev.timestamp_unix < ep_min_ts || ev.timestamp_unix > max_allowed.max(0) as u64 {
                        continue;
                    }
                    if ev.node_tag.is_empty() {
                        ev.node_tag = from_node.to_string();
                    }
                    let dedup = compute_evilpot_event_dedup_key(&ev);
                    stmt.execute(params![
                        dedup,
                        ev.timestamp_unix as i64,
                        ev.node_tag,
                        ev.epoch_id as i64,
                        ev.persona_hostname,
                        ev.client_ip,
                        ev.verification_status,
                        ev.trap_kind,
                        ev.detail,
                        serde_json::to_string(&ev.evidence).unwrap_or_else(|_| "[]".into()),
                    ])
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
                    total_accepted += 1;
                }
            }

            if !ban_records.is_empty() {
                let mut stmt = conn
                    .prepare_cached(
                        "INSERT INTO ban_records (
                            node_tag, kind, target, reason, service_tag, host, offense_level,
                            banned_at_unix, expires_at_unix, unbanned_at_unix, unbanned_by,
                            hits_blocked, status
                        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                        ON CONFLICT(node_tag, kind, target, banned_at_unix) DO UPDATE SET
                            reason = excluded.reason,
                            service_tag = COALESCE(ban_records.service_tag, excluded.service_tag),
                            host = COALESCE(ban_records.host, excluded.host),
                            offense_level = MAX(ban_records.offense_level, excluded.offense_level),
                            expires_at_unix = MAX(ban_records.expires_at_unix, excluded.expires_at_unix),
                            hits_blocked = MAX(ban_records.hits_blocked, excluded.hits_blocked),
                            status = CASE
                                WHEN ban_records.status = 'unbanned' THEN 'unbanned'
                                WHEN MAX(ban_records.expires_at_unix, excluded.expires_at_unix) <= ?14 THEN 'expired'
                                ELSE excluded.status
                            END",
                    )
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;

                let now_u = now_ts.max(0) as u64;
                for mut b in ban_records.into_iter().take(2048) {
                    if b.banned_at_unix < ban_min_ts && b.expires_at_unix < now_u {
                        continue;
                    }
                    if b.node_tag.is_empty() {
                        b.node_tag = from_node.to_string();
                    }
                    let eff_status = if b.status == "unbanned" {
                        "unbanned"
                    } else if b.expires_at_unix <= now_u {
                        "expired"
                    } else {
                        "active"
                    };
                    stmt.execute(params![
                        b.node_tag,
                        b.kind,
                        b.target,
                        b.reason,
                        b.service_tag,
                        b.host,
                        i64::from(b.offense_level),
                        b.banned_at_unix as i64,
                        b.expires_at_unix as i64,
                        b.unbanned_at_unix.map(|v| v as i64),
                        b.unbanned_by,
                        b.hits_blocked as i64,
                        eff_status,
                        now_u as i64,
                    ])
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
                    total_accepted += 1;
                }
            }

            if !alerts.is_empty() {
                let mut stmt = conn
                    .prepare_cached(
                        "INSERT OR IGNORE INTO alerts (dedup_key, timestamp_ms, timestamp, source, severity, message)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    )
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;

                for a in alerts.into_iter().take(1024) {
                    let ts_ms = parse_alert_timestamp_ms(&a);
                    if ts_ms < alert_min_ms || ts_ms > max_allowed.saturating_mul(1000) {
                        continue;
                    }
                    let sev = normalize_alert_severity(&a.severity);
                    let src = if a.source.trim().is_empty() {
                        from_node
                    } else {
                        a.source.trim()
                    };
                    let dedup = compute_alert_dedup_key(ts_ms, src, sev, &a.message);
                    stmt.execute(params![dedup, ts_ms, a.timestamp, src, sev, a.message])
                        .map_err(|e| ExposureError::Storage(e.to_string()))?;
                    total_accepted += 1;
                }
            }

            Ok(total_accepted)
        })();

        match res {
            Ok(n) => {
                conn.execute_batch("COMMIT;")
                    .map_err(|e| ExposureError::Storage(format!("commit batch: {e}")))?;
                Ok(n)
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK;");
                Err(e)
            }
        }
    }

    pub async fn mark_unbanned(
        &self,
        node_tag: Option<String>,
        ban_kind: String,
        target: String,
        actor: String,
        unbanned_at_unix: u64,
    ) -> Result<usize> {
        self.run_write(move |conn| {
            let kind = ban_kind.trim().to_ascii_lowercase();
            let tgt = target.trim().to_string();
            let nt = clean_opt_str(node_tag.as_deref());
            let changed = if kind == "all" {
                if let Some(n) = nt {
                    conn.execute(
                        "UPDATE ban_records SET status = 'unbanned', unbanned_at_unix = ?1, unbanned_by = ?2
                         WHERE status = 'active' AND node_tag = ?3",
                        params![unbanned_at_unix as i64, actor, n],
                    )
                } else {
                    conn.execute(
                        "UPDATE ban_records SET status = 'unbanned', unbanned_at_unix = ?1, unbanned_by = ?2
                         WHERE status = 'active'",
                        params![unbanned_at_unix as i64, actor],
                    )
                }
            } else if let Some(n) = nt {
                conn.execute(
                    "UPDATE ban_records SET status = 'unbanned', unbanned_at_unix = ?1, unbanned_by = ?2
                     WHERE status = 'active' AND kind = ?3 AND target = ?4 AND node_tag = ?5",
                    params![unbanned_at_unix as i64, actor, kind, tgt, n],
                )
            } else {
                conn.execute(
                    "UPDATE ban_records SET status = 'unbanned', unbanned_at_unix = ?1, unbanned_by = ?2
                     WHERE status = 'active' AND kind = ?3 AND target = ?4",
                    params![unbanned_at_unix as i64, actor, kind, tgt],
                )
            }
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
            Ok(changed)
        })
        .await
    }

    pub async fn record_alert(&self, severity: &str, message: String) -> Result<()> {
        let sev = normalize_alert_severity(severity).to_string();
        let src = self.node_tag.clone();
        let now = Utc::now();
        let ts_ms = now.timestamp_millis();
        let ts_str = now.to_rfc3339();
        self.run_write(move |conn| {
            let clean: String = message
                .chars()
                .filter(|c| !c.is_control() || *c == ' ')
                .take(512)
                .collect();
            let dedup = compute_alert_dedup_key(ts_ms, &src, &sev, &clean);
            conn.execute(
                "INSERT OR IGNORE INTO alerts (dedup_key, timestamp_ms, timestamp, source, severity, message)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![dedup, ts_ms, ts_str, src, sev, clean],
            )
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
            Ok(())
        })
        .await
    }

    pub async fn recent_alerts(&self, limit: usize) -> Result<Vec<AlertRecord>> {
        self.run_read(move |conn| {
            let mut stmt = conn
                .prepare_cached(
                    "SELECT timestamp_ms, timestamp, source, severity, message
                     FROM alerts ORDER BY timestamp_ms DESC, id DESC LIMIT ?1",
                )
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let rows = stmt
                .query_map(params![limit.max(1) as i64], |r| {
                    Ok(AlertRecord {
                        timestamp_ms: r.get(0)?,
                        timestamp: r.get(1)?,
                        source: r.get(2)?,
                        severity: r.get(3)?,
                        message: r.get(4)?,
                    })
                })
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.map_err(|e| ExposureError::Storage(e.to_string()))?);
            }
            Ok(out)
        })
        .await
    }

    pub async fn checkpoint_wal(&self) -> Result<()> {
        self.run_write(|conn| {
            conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);")
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            Ok(())
        })
        .await
    }

    pub async fn storage_stats(&self, max_db_bytes: u64) -> Result<MaintainerStorageStats> {
        let tag = self.node_tag.clone();
        let db_path = self.db_path.clone();
        self.run_read(move |conn| Self::collect_storage_stats_sync(conn, &tag, &db_path, max_db_bytes))
            .await
    }

    fn collect_storage_stats_sync(
        conn: &Connection,
        tag: &str,
        db_path: &Path,
        max_db_bytes: u64,
    ) -> Result<MaintainerStorageStats> {
        let count_tbl = |tbl: &str| -> u64 {
            let sql = format!("SELECT COUNT(*) FROM {tbl}");
            conn.query_row(&sql, [], |r| r.get::<_, i64>(0))
                .unwrap_or(0)
                .max(0) as u64
        };
        let now_u = Utc::now().timestamp().max(0) as i64;
        let active_bans_rows = conn
            .query_row(
                "SELECT COUNT(*) FROM ban_records WHERE status = 'active' AND expires_at_unix > ?1",
                params![now_u],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
            .max(0) as u64;
        let last_cleanup_at: Option<String> = conn
            .query_row(
                "SELECT v FROM meta WHERE k = 'last_cleanup_at'",
                [],
                |r| r.get(0),
            )
            .optional()
            .unwrap_or(None);

        let db_bytes = std::fs::metadata(db_path).map(|m| m.len()).unwrap_or(0);
        let wal_path = PathBuf::from(format!("{}-wal", db_path.display()));
        let wal_bytes = std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);

        Ok(MaintainerStorageStats {
            maintainer_tag: tag.to_string(),
            db_bytes,
            wal_bytes,
            access_logs_rows: count_tbl("access_logs"),
            minute_summaries_rows: count_tbl("minute_summaries"),
            fingerprints_rows: count_tbl("fingerprints"),
            evilpot_sessions_rows: count_tbl("evilpot_sessions"),
            evilpot_events_rows: count_tbl("evilpot_events"),
            ban_records_rows: count_tbl("ban_records"),
            active_bans_rows,
            alerts_rows: count_tbl("alerts"),
            last_cleanup_at,
            max_db_bytes,
        })
    }

    pub async fn run_cleanup(&self, retention: &MaintainerRetentionConfig) -> Result<CleanupReport> {
        let ret = retention.clone();
        let tag = self.node_tag.clone();
        let db_path = self.db_path.clone();
        self.run_write(move |conn| {
            let now_ts = Utc::now().timestamp();
            let now_u = now_ts.max(0) as i64;
            let mut rep = CleanupReport::default();

            // 1. Mark expired active bans cleanly
            rep.expired_bans_marked = conn
                .execute(
                    "UPDATE ban_records SET status = 'expired'
                     WHERE status = 'active' AND expires_at_unix <= ?1",
                    params![now_u],
                )
                .map_err(|e| ExposureError::Storage(e.to_string()))?;

            // 2. Age-based deletions
            if ret.access_logs_retention_hours > 0 {
                let cutoff_ms = now_ts
                    .saturating_sub((ret.access_logs_retention_hours as i64).saturating_mul(3600))
                    .saturating_mul(1000);
                rep.deleted_access_logs += conn
                    .execute("DELETE FROM access_logs WHERE timestamp_ms < ?1", params![cutoff_ms])
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
            }
            if ret.stats_retention_days > 0 {
                let cutoff = now_ts.saturating_sub((ret.stats_retention_days as i64).saturating_mul(86_400));
                rep.deleted_summaries += conn
                    .execute("DELETE FROM minute_summaries WHERE minute_epoch < ?1", params![cutoff])
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
            }
            if ret.fingerprints_retention_days > 0 {
                let cutoff = now_ts.saturating_sub((ret.fingerprints_retention_days as i64).saturating_mul(86_400));
                rep.deleted_fingerprints += conn
                    .execute("DELETE FROM fingerprints WHERE last_seen_ts < ?1", params![cutoff])
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
            }
            if ret.evilpot_retention_days > 0 {
                let cutoff = now_ts
                    .saturating_sub((ret.evilpot_retention_days as i64).saturating_mul(86_400))
                    .max(0);
                rep.deleted_evilpot_events += conn
                    .execute("DELETE FROM evilpot_events WHERE timestamp_unix < ?1", params![cutoff])
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
                rep.deleted_evilpot_sessions += conn
                    .execute("DELETE FROM evilpot_sessions WHERE last_seen_unix < ?1", params![cutoff])
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
            }
            if ret.bans_retention_days > 0 {
                let cutoff = now_ts
                    .saturating_sub((ret.bans_retention_days as i64).saturating_mul(86_400))
                    .max(0);
                rep.deleted_ban_records += conn
                    .execute(
                        "DELETE FROM ban_records WHERE status != 'active' AND banned_at_unix < ?1",
                        params![cutoff],
                    )
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
            }
            if ret.alerts_retention_days > 0 {
                let cutoff_ms = now_ts
                    .saturating_sub((ret.alerts_retention_days as i64).saturating_mul(86_400))
                    .saturating_mul(1000);
                rep.deleted_alerts += conn
                    .execute("DELETE FROM alerts WHERE timestamp_ms < ?1", params![cutoff_ms])
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
            }

            // 3. Row-count caps (keeping newest rows)
            if ret.access_logs_max_rows > 0 {
                rep.deleted_access_logs += conn
                    .execute(
                        "DELETE FROM access_logs WHERE id NOT IN (
                            SELECT id FROM access_logs ORDER BY timestamp_ms DESC, id DESC LIMIT ?1
                        )",
                        params![ret.access_logs_max_rows as i64],
                    )
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
            }
            if ret.max_summaries > 0 {
                rep.deleted_summaries += conn
                    .execute(
                        "DELETE FROM minute_summaries WHERE rowid NOT IN (
                            SELECT rowid FROM minute_summaries ORDER BY minute_epoch DESC LIMIT ?1
                        )",
                        params![ret.max_summaries as i64],
                    )
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
            }
            if ret.max_fingerprints > 0 {
                rep.deleted_fingerprints += conn
                    .execute(
                        "DELETE FROM fingerprints WHERE rowid NOT IN (
                            SELECT rowid FROM fingerprints ORDER BY last_seen_ts DESC LIMIT ?1
                        )",
                        params![ret.max_fingerprints as i64],
                    )
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
            }
            if ret.evilpot_max_events > 0 {
                rep.deleted_evilpot_events += conn
                    .execute(
                        "DELETE FROM evilpot_events WHERE id NOT IN (
                            SELECT id FROM evilpot_events ORDER BY timestamp_unix DESC, id DESC LIMIT ?1
                        )",
                        params![ret.evilpot_max_events as i64],
                    )
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
            }
            if ret.evilpot_max_sessions > 0 {
                rep.deleted_evilpot_sessions += conn
                    .execute(
                        "DELETE FROM evilpot_sessions WHERE rowid NOT IN (
                            SELECT rowid FROM evilpot_sessions ORDER BY status_rank DESC, last_seen_unix DESC LIMIT ?1
                        )",
                        params![ret.evilpot_max_sessions as i64],
                    )
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
            }
            if ret.bans_max_rows > 0 {
                rep.deleted_ban_records += conn
                    .execute(
                        "DELETE FROM ban_records WHERE status != 'active' AND id NOT IN (
                            SELECT id FROM ban_records ORDER BY CASE WHEN status = 'active' THEN 0 ELSE 1 END, banned_at_unix DESC, id DESC LIMIT ?1
                        )",
                        params![ret.bans_max_rows as i64],
                    )
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
            }
            if ret.alerts_max_rows > 0 {
                rep.deleted_alerts += conn
                    .execute(
                        "DELETE FROM alerts WHERE id NOT IN (
                            SELECT id FROM alerts ORDER BY timestamp_ms DESC, id DESC LIMIT ?1
                        )",
                        params![ret.alerts_max_rows as i64],
                    )
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
            }

            // 4. Reclaim pages and enforce max_db_bytes budget if exceeded
            let _ = conn.execute_batch("PRAGMA incremental_vacuum(2048); PRAGMA wal_checkpoint(TRUNCATE);");
            if ret.max_db_bytes > 0 {
                for _ in 0..8 {
                    let cur_size = std::fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);
                    if cur_size <= ret.max_db_bytes {
                        break;
                    }
                    let mut trimmed = false;
                    for (sql, counter) in [
                        (
                            "DELETE FROM access_logs WHERE id IN (SELECT id FROM access_logs ORDER BY timestamp_ms ASC, id ASC LIMIT MAX(1, (SELECT COUNT(*) / 5 FROM access_logs)))",
                            &mut rep.deleted_access_logs,
                        ),
                        (
                            "DELETE FROM fingerprints WHERE rowid IN (SELECT rowid FROM fingerprints ORDER BY last_seen_ts ASC LIMIT MAX(1, (SELECT COUNT(*) / 5 FROM fingerprints)))",
                            &mut rep.deleted_fingerprints,
                        ),
                        (
                            "DELETE FROM alerts WHERE id IN (SELECT id FROM alerts ORDER BY timestamp_ms ASC, id ASC LIMIT MAX(1, (SELECT COUNT(*) / 5 FROM alerts)))",
                            &mut rep.deleted_alerts,
                        ),
                        (
                            "DELETE FROM evilpot_events WHERE id IN (SELECT id FROM evilpot_events ORDER BY timestamp_unix ASC, id ASC LIMIT MAX(1, (SELECT COUNT(*) / 5 FROM evilpot_events)))",
                            &mut rep.deleted_evilpot_events,
                        ),
                        (
                            "DELETE FROM ban_records WHERE id IN (SELECT id FROM ban_records WHERE status != 'active' ORDER BY banned_at_unix ASC, id ASC LIMIT MAX(1, (SELECT COUNT(*) / 5 FROM ban_records WHERE status != 'active')))",
                            &mut rep.deleted_ban_records,
                        ),
                        (
                            "DELETE FROM evilpot_sessions WHERE rowid IN (SELECT rowid FROM evilpot_sessions ORDER BY last_seen_unix ASC LIMIT MAX(1, (SELECT COUNT(*) / 5 FROM evilpot_sessions)))",
                            &mut rep.deleted_evilpot_sessions,
                        ),
                        (
                            "DELETE FROM minute_summaries WHERE rowid IN (SELECT rowid FROM minute_summaries ORDER BY minute_epoch ASC LIMIT MAX(1, (SELECT COUNT(*) / 5 FROM minute_summaries)))",
                            &mut rep.deleted_summaries,
                        ),
                    ] {
                        let n = conn.execute(sql, []).unwrap_or(0);
                        if n > 0 {
                            *counter += n;
                            trimmed = true;
                            break;
                        }
                    }
                    let _ = conn.execute_batch("PRAGMA incremental_vacuum(4096); PRAGMA wal_checkpoint(TRUNCATE);");
                    if !trimmed {
                        break;
                    }
                }
            }

            let ts_now = Utc::now().to_rfc3339();
            let _ = conn.execute(
                "INSERT INTO meta (k, v) VALUES ('last_cleanup_at', ?1)
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                params![ts_now],
            );
            rep.storage_stats = Self::collect_storage_stats_sync(conn, &tag, &db_path, ret.max_db_bytes)?;
            Ok(rep)
        })
        .await
    }

    pub async fn snapshot_summaries(&self, since_minute: Option<i64>, limit: usize) -> Result<Vec<MinuteSummary>> {
        self.run_read(move |conn| {
            let mut stmt = if since_minute.is_some() {
                conn.prepare_cached(
                    "SELECT minute_epoch, node_tag, role, service_tag, requests, errors,
                            rate_limited, challenges_issued, challenges_passed, blocked,
                            evilpot_hits, autoban_hits, bytes_in, bytes_out, cached_requests,
                            cached_bytes_out, client_fp_verified, uv_hll_json, latency_hist_json,
                            device_counts_json, browser_counts_json, os_counts_json
                     FROM minute_summaries
                     WHERE minute_epoch >= ?1
                     ORDER BY minute_epoch DESC LIMIT ?2",
                )
            } else {
                conn.prepare_cached(
                    "SELECT minute_epoch, node_tag, role, service_tag, requests, errors,
                            rate_limited, challenges_issued, challenges_passed, blocked,
                            evilpot_hits, autoban_hits, bytes_in, bytes_out, cached_requests,
                            cached_bytes_out, client_fp_verified, uv_hll_json, latency_hist_json,
                            device_counts_json, browser_counts_json, os_counts_json
                     FROM minute_summaries
                     ORDER BY minute_epoch DESC LIMIT ?1",
                )
            }
            .map_err(|e| ExposureError::Storage(e.to_string()))?;

            let mut out = Vec::new();
            let map_row = |row: &rusqlite::Row<'_>| -> rusqlite::Result<MinuteSummary> {
                let uv_json: String = row.get(17)?;
                let hist_json: String = row.get(18)?;
                let dev_json: String = row.get(19)?;
                let br_json: String = row.get(20)?;
                let os_json: String = row.get(21)?;
                Ok(MinuteSummary {
                    minute_epoch: row.get(0)?,
                    node_tag: row.get(1)?,
                    role: row.get(2)?,
                    service_tag: row.get(3)?,
                    requests: row.get::<_, i64>(4)?.max(0) as u64,
                    errors: row.get::<_, i64>(5)?.max(0) as u64,
                    rate_limited: row.get::<_, i64>(6)?.max(0) as u64,
                    challenges_issued: row.get::<_, i64>(7)?.max(0) as u64,
                    challenges_passed: row.get::<_, i64>(8)?.max(0) as u64,
                    blocked: row.get::<_, i64>(9)?.max(0) as u64,
                    evilpot_hits: row.get::<_, i64>(10)?.max(0) as u64,
                    autoban_hits: row.get::<_, i64>(11)?.max(0) as u64,
                    bytes_in: row.get::<_, i64>(12)?.max(0) as u64,
                    bytes_out: row.get::<_, i64>(13)?.max(0) as u64,
                    cached_requests: row.get::<_, i64>(14)?.max(0) as u64,
                    cached_bytes_out: row.get::<_, i64>(15)?.max(0) as u64,
                    client_fp_verified: row.get::<_, i64>(16)?.max(0) as u64,
                    uv_hll: serde_json::from_str(&uv_json).unwrap_or_else(|_| HyperLogLog::new(12, 0)),
                    latency_hist: serde_json::from_str(&hist_json).unwrap_or_else(|_| LatencyHistogram::new(vec![])),
                    device_counts: serde_json::from_str(&dev_json).unwrap_or_default(),
                    browser_counts: serde_json::from_str(&br_json).unwrap_or_default(),
                    os_counts: serde_json::from_str(&os_json).unwrap_or_default(),
                })
            };

            if let Some(m) = since_minute {
                let rows = stmt
                    .query_map(params![m, limit.max(1) as i64], map_row)
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
                for r in rows {
                    out.push(r.map_err(|e| ExposureError::Storage(e.to_string()))?);
                }
            } else {
                let rows = stmt
                    .query_map(params![limit.max(1) as i64], map_row)
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
                for r in rows {
                    out.push(r.map_err(|e| ExposureError::Storage(e.to_string()))?);
                }
            }
            Ok(out)
        })
        .await
    }

    pub async fn query_overview(&self, from_ms: Option<i64>, to_ms: Option<i64>) -> Result<serde_json::Value> {
        self.run_read(move |conn| {
            let from_sec = from_ms.map(|ms| ms.div_euclid(1000));
            let to_sec = to_ms.map(|ms| ms.div_euclid(1000));

            let raw_sums = Self::load_summaries_in_range(conn, from_sec, to_sec, None, None)?;
            let (traffic_buckets, service_summaries, node_summaries) =
                Self::downsample_summaries(&raw_sums, from_sec, to_sec);

            let mut alert_sql = String::from(
                "SELECT timestamp_ms, timestamp, source, severity, message FROM alerts WHERE 1=1",
            );
            let mut alert_params: Vec<Value> = Vec::new();
            if let Some(f) = from_ms {
                alert_sql.push_str(" AND timestamp_ms >= ?");
                alert_params.push(Value::Integer(f));
            }
            if let Some(t) = to_ms {
                alert_sql.push_str(" AND timestamp_ms <= ?");
                alert_params.push(Value::Integer(t));
            }
            alert_sql.push_str(" ORDER BY timestamp_ms DESC, id DESC LIMIT 10");
            let mut stmt = conn
                .prepare(&alert_sql)
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(alert_params), |r| {
                    Ok(AlertRecord {
                        timestamp_ms: r.get(0)?,
                        timestamp: r.get(1)?,
                        source: r.get(2)?,
                        severity: r.get(3)?,
                        message: r.get(4)?,
                    })
                })
                .map_err(|e| ExposureError::Storage(e.to_string()))?;
            let mut alerts = Vec::new();
            for r in rows {
                alerts.push(r.map_err(|e| ExposureError::Storage(e.to_string()))?);
            }

            let mut cnt_sql = String::from("SELECT COUNT(*) FROM alerts WHERE 1=1");
            let mut cnt_params: Vec<Value> = Vec::new();
            if let Some(f) = from_ms {
                cnt_sql.push_str(" AND timestamp_ms >= ?");
                cnt_params.push(Value::Integer(f));
            }
            if let Some(t) = to_ms {
                cnt_sql.push_str(" AND timestamp_ms <= ?");
                cnt_params.push(Value::Integer(t));
            }
            let alerts_total: u64 = conn
                .query_row(&cnt_sql, rusqlite::params_from_iter(cnt_params), |r| {
                    r.get::<_, i64>(0)
                })
                .unwrap_or(0)
                .max(0) as u64;

            Ok(serde_json::json!({
                "traffic_buckets": traffic_buckets,
                "service_summaries": service_summaries,
                "node_summaries": node_summaries,
                "alerts": alerts,
                "alerts_total": alerts_total,
            }))
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn query_telemetry(
        &self,
        from_ms: Option<i64>,
        to_ms: Option<i64>,
        node: Option<String>,
        service: Option<String>,
        bucket_offset: usize,
        bucket_limit: usize,
    ) -> Result<serde_json::Value> {
        self.run_read(move |conn| {
            let from_sec = from_ms.map(|ms| ms.div_euclid(1000));
            let to_sec = to_ms.map(|ms| ms.div_euclid(1000));
            let node_f = clean_opt_str(node.as_deref());
            let svc_f = clean_opt_str(service.as_deref());

            let avail_nodes = Self::distinct_strings(conn, "SELECT DISTINCT node_tag FROM minute_summaries ORDER BY 1")?;
            let avail_svcs = Self::distinct_strings(conn, "SELECT DISTINCT service_tag FROM minute_summaries ORDER BY 1")?;

            let raw_sums = Self::load_summaries_in_range(
                conn,
                from_sec,
                to_sec,
                node_f.as_deref(),
                svc_f.as_deref(),
            )?;
            let (traffic_buckets, service_summaries, node_summaries) =
                Self::downsample_summaries(&raw_sums, from_sec, to_sec);

            let total_buckets = raw_sums.len();
            let lim = bucket_limit.clamp(1, 200);
            let mut sorted_desc = raw_sums;
            sorted_desc.sort_by(|a, b| {
                b.minute_epoch
                    .cmp(&a.minute_epoch)
                    .then_with(|| a.node_tag.cmp(&b.node_tag))
                    .then_with(|| a.service_tag.cmp(&b.service_tag))
            });
            let paged_buckets: Vec<serde_json::Value> = sorted_desc
                .into_iter()
                .skip(bucket_offset)
                .take(lim)
                .map(|s| summary_to_dto_json(&s))
                .collect();

            Ok(serde_json::json!({
                "available_nodes": avail_nodes,
                "available_services": avail_svcs,
                "traffic_buckets": traffic_buckets,
                "service_summaries": service_summaries,
                "node_summaries": node_summaries,
                "buckets": paged_buckets,
                "buckets_total": total_buckets,
                "bucket_offset": bucket_offset,
                "bucket_limit": lim,
            }))
        })
        .await
    }

    fn distinct_strings(conn: &Connection, sql: &str) -> Result<Vec<String>> {
        let mut stmt = conn
            .prepare(sql)
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
        let mut out = Vec::new();
        for r in rows {
            let s = r.map_err(|e| ExposureError::Storage(e.to_string()))?;
            if !s.is_empty() {
                out.push(s);
            }
        }
        Ok(out)
    }

    fn load_summaries_in_range(
        conn: &Connection,
        from_sec: Option<i64>,
        to_sec: Option<i64>,
        node_f: Option<&str>,
        svc_f: Option<&str>,
    ) -> Result<Vec<MinuteSummary>> {
        let mut sql = String::from(
            "SELECT minute_epoch, node_tag, role, service_tag, requests, errors,
                    rate_limited, challenges_issued, challenges_passed, blocked,
                    evilpot_hits, autoban_hits, bytes_in, bytes_out, cached_requests,
                    cached_bytes_out, client_fp_verified, uv_hll_json, latency_hist_json,
                    device_counts_json, browser_counts_json, os_counts_json
             FROM minute_summaries WHERE 1=1",
        );
        let mut args: Vec<Value> = Vec::new();
        if let Some(f) = from_sec {
            // Overlap semantics: a 60s bucket [minute_epoch, minute_epoch + 60) overlaps if minute_epoch + 60 > from_sec
            sql.push_str(" AND (minute_epoch + 60) > ?");
            args.push(Value::Integer(f));
        }
        if let Some(t) = to_sec {
            sql.push_str(" AND minute_epoch <= ?");
            args.push(Value::Integer(t));
        }
        if let Some(n) = node_f {
            sql.push_str(" AND node_tag = ?");
            args.push(Value::Text(n.to_string()));
        }
        if let Some(s) = svc_f {
            sql.push_str(" AND service_tag = ?");
            args.push(Value::Text(s.to_string()));
        }
        sql.push_str(" ORDER BY minute_epoch ASC");

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(args), |row| {
                let uv_json: String = row.get(17)?;
                let hist_json: String = row.get(18)?;
                let dev_json: String = row.get(19)?;
                let br_json: String = row.get(20)?;
                let os_json: String = row.get(21)?;
                Ok(MinuteSummary {
                    minute_epoch: row.get(0)?,
                    node_tag: row.get(1)?,
                    role: row.get(2)?,
                    service_tag: row.get(3)?,
                    requests: row.get::<_, i64>(4)?.max(0) as u64,
                    errors: row.get::<_, i64>(5)?.max(0) as u64,
                    rate_limited: row.get::<_, i64>(6)?.max(0) as u64,
                    challenges_issued: row.get::<_, i64>(7)?.max(0) as u64,
                    challenges_passed: row.get::<_, i64>(8)?.max(0) as u64,
                    blocked: row.get::<_, i64>(9)?.max(0) as u64,
                    evilpot_hits: row.get::<_, i64>(10)?.max(0) as u64,
                    autoban_hits: row.get::<_, i64>(11)?.max(0) as u64,
                    bytes_in: row.get::<_, i64>(12)?.max(0) as u64,
                    bytes_out: row.get::<_, i64>(13)?.max(0) as u64,
                    cached_requests: row.get::<_, i64>(14)?.max(0) as u64,
                    cached_bytes_out: row.get::<_, i64>(15)?.max(0) as u64,
                    client_fp_verified: row.get::<_, i64>(16)?.max(0) as u64,
                    uv_hll: serde_json::from_str(&uv_json).unwrap_or_else(|_| HyperLogLog::new(12, 0)),
                    latency_hist: serde_json::from_str(&hist_json).unwrap_or_else(|_| LatencyHistogram::new(vec![])),
                    device_counts: serde_json::from_str(&dev_json).unwrap_or_default(),
                    browser_counts: serde_json::from_str(&br_json).unwrap_or_default(),
                    os_counts: serde_json::from_str(&os_json).unwrap_or_default(),
                })
            })
            .map_err(|e| ExposureError::Storage(e.to_string()))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| ExposureError::Storage(e.to_string()))?);
        }
        Ok(out)
    }

    fn downsample_summaries(
        raw: &[MinuteSummary],
        from_sec: Option<i64>,
        to_sec: Option<i64>,
    ) -> (Vec<MinuteSummary>, Vec<MinuteSummary>, Vec<MinuteSummary>) {
        if raw.is_empty() {
            return (Vec::new(), Vec::new(), Vec::new());
        }
        let min_ep = raw.iter().map(|s| s.minute_epoch).min().unwrap_or(0);
        let max_ep = raw.iter().map(|s| s.minute_epoch).max().unwrap_or(0);
        let bucket_secs = choose_bucket_secs(from_sec, to_sec, min_ep, max_ep);

        let has_ingress = raw.iter().any(|s| s.role == "ingress");
        let primary: Vec<&MinuteSummary> = if has_ingress {
            raw.iter()
                .filter(|s| s.role == "ingress" || s.role.is_empty())
                .collect()
        } else {
            raw.iter().collect()
        };

        let mut by_bucket: BTreeMap<i64, MinuteSummary> = BTreeMap::new();
        let mut by_service: BTreeMap<String, MinuteSummary> = BTreeMap::new();
        for s in &primary {
            let b_ep = (s.minute_epoch / bucket_secs) * bucket_secs;
            by_bucket
                .entry(b_ep)
                .and_modify(|acc| acc.merge_from(s))
                .or_insert_with(|| {
                    let mut c = (*s).clone();
                    c.minute_epoch = b_ep;
                    c.node_tag = String::new();
                    c.service_tag = String::new();
                    c
                });
            by_service
                .entry(s.service_tag.clone())
                .and_modify(|acc| acc.merge_from(s))
                .or_insert_with(|| {
                    let mut c = (*s).clone();
                    c.minute_epoch = 0;
                    c.node_tag = String::new();
                    c
                });
        }

        let mut node_has_ingress = std::collections::HashSet::new();
        for s in raw {
            if s.role == "ingress" {
                node_has_ingress.insert(s.node_tag.as_str());
            }
        }
        let mut by_node: BTreeMap<String, MinuteSummary> = BTreeMap::new();
        for s in raw {
            if node_has_ingress.contains(s.node_tag.as_str()) && s.role == "egress" {
                continue;
            }
            by_node
                .entry(s.node_tag.clone())
                .and_modify(|acc| acc.merge_from(s))
                .or_insert_with(|| {
                    let mut c = s.clone();
                    c.minute_epoch = 0;
                    c.service_tag = String::new();
                    c
                });
        }

        (
            by_bucket.into_values().collect(),
            by_service.into_values().collect(),
            by_node.into_values().collect(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn query_access_logs(
        &self,
        from_ms: Option<i64>,
        to_ms: Option<i64>,
        node: Option<String>,
        service: Option<String>,
        role: Option<String>,
        method: Option<String>,
        action: Option<String>,
        status: Option<String>,
        host: Option<String>,
        ip: Option<String>,
        ip_hmac: Option<String>,
        country: Option<String>,
        ray_id: Option<String>,
        q: Option<String>,
        q_ip_hmac: Option<String>,
        offset: usize,
        limit: usize,
    ) -> Result<serde_json::Value> {
        self.run_read(move |conn| {
            let mut where_sql = String::from(" WHERE 1=1");
            let mut args: Vec<Value> = Vec::new();
            if let Some(f) = from_ms {
                where_sql.push_str(" AND timestamp_ms >= ?");
                args.push(Value::Integer(f));
            }
            if let Some(t) = to_ms {
                where_sql.push_str(" AND timestamp_ms <= ?");
                args.push(Value::Integer(t));
            }
            if let Some(n) = clean_opt_str(node.as_deref()) {
                where_sql.push_str(" AND node_tag = ?");
                args.push(Value::Text(n));
            }
            if let Some(s) = clean_opt_str(service.as_deref()) {
                where_sql.push_str(" AND service_tag = ?");
                args.push(Value::Text(s));
            }
            if let Some(r) = clean_opt_str(role.as_deref()) {
                where_sql.push_str(" AND LOWER(role) = LOWER(?)");
                args.push(Value::Text(r));
            }
            if let Some(m) = clean_opt_str(method.as_deref()) {
                where_sql.push_str(" AND UPPER(COALESCE(method,'')) = UPPER(?)");
                args.push(Value::Text(m));
            }
            if let Some(c) = clean_opt_str(country.as_deref()) {
                where_sql.push_str(" AND UPPER(COALESCE(client_country,'')) = UPPER(?)");
                args.push(Value::Text(c));
            }
            if let Some(act) = clean_opt_str(action.as_deref()) {
                let al = act.to_ascii_lowercase();
                if al == "blocked" {
                    where_sql.push_str(
                        " AND (rate_limited = 1 OR challenged = 1
                            OR LOWER(COALESCE(action,'')) IN ('autoban','waf_block','evilpot','evilpot_canary','guard_reject','abuseipdb','geo_block','geo_evilpot','rate_limit','challenge','geo_challenge')
                            OR (action IS NULL AND status IN (403, 429)))",
                    );
                } else if al == "allow" {
                    where_sql.push_str(
                        " AND (LOWER(COALESCE(action,'')) = 'allow'
                            OR (action IS NULL AND rate_limited = 0 AND challenged = 0 AND status NOT IN (403, 429)))",
                    );
                } else {
                    where_sql.push_str(" AND LOWER(COALESCE(action,'')) = ?");
                    args.push(Value::Text(al));
                }
            }
            if let Some(st) = clean_opt_str(status.as_deref()) {
                match st.to_ascii_lowercase().as_str() {
                    "2xx" => where_sql.push_str(" AND status >= 200 AND status < 300"),
                    "3xx" => where_sql.push_str(" AND status >= 300 AND status < 400"),
                    "4xx" => where_sql.push_str(" AND status >= 400 AND status < 500"),
                    "5xx" => where_sql.push_str(" AND status >= 500 AND status < 600"),
                    exact => {
                        if let Ok(code) = exact.parse::<i64>() {
                            where_sql.push_str(" AND status = ?");
                            args.push(Value::Integer(code));
                        } else {
                            where_sql.push_str(" AND 1=0");
                        }
                    }
                }
            }
            if let Some(h) = clean_opt_str(host.as_deref()) {
                where_sql.push_str(" AND LOWER(COALESCE(host,'')) LIKE ? ESCAPE '\\'");
                args.push(Value::Text(escape_like_needle(&h)));
            }
            if let Some(rid) = clean_opt_str(ray_id.as_deref()) {
                where_sql.push_str(" AND LOWER(COALESCE(ray_id,'')) LIKE ? ESCAPE '\\'");
                args.push(Value::Text(escape_like_needle(&rid)));
            }
            if let Some(ipq) = clean_opt_str(ip.as_deref()) {
                let pat = escape_like_needle(&ipq);
                if let Some(hmac_ex) = ip_hmac.filter(|s| !s.is_empty()) {
                    where_sql.push_str(" AND (LOWER(COALESCE(raw_ip,'')) LIKE ? ESCAPE '\\' OR LOWER(ip_hmac) LIKE ? ESCAPE '\\' OR LOWER(ip_hmac) = LOWER(?))");
                    args.push(Value::Text(pat.clone()));
                    args.push(Value::Text(pat));
                    args.push(Value::Text(hmac_ex));
                } else {
                    where_sql.push_str(" AND (LOWER(COALESCE(raw_ip,'')) LIKE ? ESCAPE '\\' OR LOWER(ip_hmac) LIKE ? ESCAPE '\\')");
                    args.push(Value::Text(pat.clone()));
                    args.push(Value::Text(pat));
                }
            }
            if let Some(qs) = clean_opt_str(q.as_deref()) {
                let pat = escape_like_needle(&qs);
                let mut clauses = vec![
                    "LOWER(COALESCE(path,'')) LIKE ? ESCAPE '\\'",
                    "LOWER(COALESCE(query,'')) LIKE ? ESCAPE '\\'",
                    "LOWER(COALESCE(host,'')) LIKE ? ESCAPE '\\'",
                    "LOWER(COALESCE(ray_id,'')) LIKE ? ESCAPE '\\'",
                    "LOWER(COALESCE(user_agent,'')) LIKE ? ESCAPE '\\'",
                    "LOWER(COALESCE(referer,'')) LIKE ? ESCAPE '\\'",
                    "LOWER(COALESCE(error,'')) LIKE ? ESCAPE '\\'",
                    "LOWER(COALESCE(waf_category,'')) LIKE ? ESCAPE '\\'",
                    "CAST(COALESCE(waf_rule_id,'') AS TEXT) LIKE ? ESCAPE '\\'",
                    "LOWER(COALESCE(action,'')) LIKE ? ESCAPE '\\'",
                    "LOWER(COALESCE(raw_ip,'')) LIKE ? ESCAPE '\\'",
                    "LOWER(COALESCE(client_country,'')) LIKE ? ESCAPE '\\'",
                    "LOWER(ip_hmac) LIKE ? ESCAPE '\\'",
                    "LOWER(service_tag) LIKE ? ESCAPE '\\'",
                    "LOWER(node_tag) LIKE ? ESCAPE '\\'",
                ];
                for _ in 0..clauses.len() {
                    args.push(Value::Text(pat.clone()));
                }
                if let Some(qh) = q_ip_hmac.filter(|s| !s.is_empty()) {
                    clauses.push("LOWER(ip_hmac) = LOWER(?)");
                    args.push(Value::Text(qh));
                }
                where_sql.push_str(" AND (");
                where_sql.push_str(&clauses.join(" OR "));
                where_sql.push(')');
            }

            let avail_nodes = Self::distinct_strings(conn, "SELECT DISTINCT node_tag FROM access_logs ORDER BY 1")?;
            let avail_svcs = Self::distinct_strings(conn, "SELECT DISTINCT service_tag FROM access_logs ORDER BY 1")?;
            let avail_hosts = Self::distinct_strings(conn, "SELECT DISTINCT host FROM access_logs WHERE host IS NOT NULL AND host != '' ORDER BY 1 LIMIT 200")?;
            let avail_actions = Self::distinct_strings(conn, "SELECT DISTINCT action FROM access_logs WHERE action IS NOT NULL AND action != '' ORDER BY 1")?;
            let avail_countries = Self::distinct_strings(conn, "SELECT DISTINCT UPPER(client_country) FROM access_logs WHERE client_country IS NOT NULL AND client_country != '' ORDER BY 1")?;

            // One client request produces one row per hop (ingress + egress) sharing the same
            // Ray ID. Collapse each Ray ID into a single logical request whose primary row is
            // the ingress hop (falling back to the earliest hop if ingress never logged), and
            // order the list by the ingress arrival time so a request that failed before
            // reaching egress still sorts correctly.
            let cte = format!(
                "WITH filtered AS (SELECT * FROM access_logs{where_sql}),
                      grp AS (
                          SELECT *, COALESCE(NULLIF(ray_id, ''), 'row:' || id) AS ray_key
                          FROM filtered
                      ),
                      primary_rows AS (
                          SELECT * FROM (
                              SELECT g.*,
                                     ROW_NUMBER() OVER (
                                         PARTITION BY ray_key
                                         ORDER BY (LOWER(role) = 'ingress') DESC, timestamp_ms ASC, id ASC
                                     ) AS rn,
                                     COUNT(*) OVER (PARTITION BY ray_key) AS hop_count,
                                     MIN(CASE WHEN LOWER(role) = 'ingress' THEN timestamp_ms END)
                                         OVER (PARTITION BY ray_key) AS ingress_ts_ms,
                                     MIN(timestamp_ms) OVER (PARTITION BY ray_key) AS first_ts_ms,
                                     MAX(CASE WHEN LOWER(role) = 'egress' THEN node_tag END)
                                         OVER (PARTITION BY ray_key) AS egress_node_tag,
                                     MAX(CASE WHEN LOWER(role) = 'egress' THEN status END)
                                         OVER (PARTITION BY ray_key) AS egress_status,
                                     MAX(CASE WHEN LOWER(role) = 'egress' THEN latency_ms END)
                                         OVER (PARTITION BY ray_key) AS egress_latency_ms,
                                     MAX(CASE WHEN LOWER(role) = 'egress' THEN protocol END)
                                         OVER (PARTITION BY ray_key) AS egress_protocol
                              FROM grp g
                          ) WHERE rn = 1
                      )"
            );

            // Aggregate metrics over one primary row per logical request (no ingress+egress double count).
            let count_sql = format!(
                "{cte} SELECT COUNT(*),
                        COALESCE(SUM(MAX(repeat_count, 1)), 0),
                        COALESCE(SUM(MAX(repeat_count - 1, 0)), 0),
                        COALESCE(SUM(CASE WHEN status >= 500 THEN MAX(repeat_count, 1) ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN cache_status IN ('HIT','STALE','REVALIDATED') THEN MAX(repeat_count, 1) ELSE 0 END), 0),
                        COUNT(DISTINCT ip_hmac),
                        COUNT(DISTINCT CASE WHEN path IS NOT NULL AND path != '' THEN COALESCE(host,'') || '|' || path END)
                 FROM primary_rows"
            );
            let (total_matched, total_requests, folded_requests, error_5xx_requests, cache_hits, unique_ips, unique_paths): (
                i64, i64, i64, i64, i64, i64, i64,
            ) = conn
                .query_row(&count_sql, rusqlite::params_from_iter(args.clone()), |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                })
                .map_err(|e| ExposureError::Storage(e.to_string()))?;

            let blocked_sql = format!(
                "{cte} SELECT COALESCE(SUM(MAX(repeat_count, 1)), 0)
                 FROM primary_rows
                 WHERE (rate_limited = 1 OR challenged = 1
                      OR LOWER(COALESCE(action,'')) IN ('autoban','waf_block','evilpot','evilpot_canary','guard_reject','abuseipdb','geo_block','geo_evilpot','rate_limit','challenge','geo_challenge')
                      OR (action IS NULL AND status IN (403, 429)))"
            );
            let blocked_requests: i64 = conn
                .query_row(&blocked_sql, rusqlite::params_from_iter(args.clone()), |r| r.get(0))
                .unwrap_or(0);

            let act_sql = format!(
                "{cte} SELECT COALESCE(NULLIF(action,''), 'allow'), COALESCE(SUM(MAX(repeat_count, 1)), 0)
                 FROM primary_rows
                 GROUP BY 1"
            );
            let mut action_counts: BTreeMap<String, u64> = BTreeMap::new();
            {
                let mut st = conn.prepare(&act_sql).map_err(|e| ExposureError::Storage(e.to_string()))?;
                let rows = st
                    .query_map(rusqlite::params_from_iter(args.clone()), |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?.max(0) as u64))
                    })
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
                for r in rows {
                    let (k, v) = r.map_err(|e| ExposureError::Storage(e.to_string()))?;
                    action_counts.insert(k, v);
                }
            }

            let sc_sql = format!(
                "{cte} SELECT (status / 100) || 'xx', COALESCE(SUM(MAX(repeat_count, 1)), 0)
                 FROM primary_rows
                 GROUP BY 1"
            );
            let mut status_class_counts: BTreeMap<String, u64> = BTreeMap::new();
            {
                let mut st = conn.prepare(&sc_sql).map_err(|e| ExposureError::Storage(e.to_string()))?;
                let rows = st
                    .query_map(rusqlite::params_from_iter(args.clone()), |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?.max(0) as u64))
                    })
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
                for r in rows {
                    let (k, v) = r.map_err(|e| ExposureError::Storage(e.to_string()))?;
                    status_class_counts.insert(k, v);
                }
            }

            let tp_sql = format!(
                "{cte} SELECT COALESCE(host,''), path,
                        COALESCE(SUM(MAX(repeat_count, 1)), 0) AS hits,
                        COALESCE(SUM(CASE WHEN (rate_limited = 1 OR challenged = 1
                            OR LOWER(COALESCE(action,'')) IN ('autoban','waf_block','evilpot','evilpot_canary','guard_reject','abuseipdb','geo_block','geo_evilpot','rate_limit','challenge','geo_challenge')
                            OR (action IS NULL AND status IN (403, 429))) THEN MAX(repeat_count, 1) ELSE 0 END), 0) AS blk,
                        COALESCE(SUM(CASE WHEN status >= 500 THEN MAX(repeat_count, 1) ELSE 0 END), 0) AS e5
                 FROM primary_rows
                 WHERE path IS NOT NULL AND path != ''
                 GROUP BY 1, 2
                 ORDER BY hits DESC
                 LIMIT 12"
            );
            let mut top_paths = Vec::new();
            {
                let mut st = conn.prepare(&tp_sql).map_err(|e| ExposureError::Storage(e.to_string()))?;
                let rows = st
                    .query_map(rusqlite::params_from_iter(args.clone()), |r| {
                        Ok(serde_json::json!({
                            "host": r.get::<_, String>(0)?,
                            "path": r.get::<_, String>(1)?,
                            "hits": r.get::<_, i64>(2)?.max(0) as u64,
                            "blocked": r.get::<_, i64>(3)?.max(0) as u64,
                            "errors_5xx": r.get::<_, i64>(4)?.max(0) as u64,
                        }))
                    })
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
                for r in rows {
                    top_paths.push(r.map_err(|e| ExposureError::Storage(e.to_string()))?);
                }
            }

            let lim = limit.clamp(1, 200);
            let mut page_args = args;
            page_args.push(Value::Integer(lim as i64));
            page_args.push(Value::Integer(offset as i64));
            let page_sql = format!(
                "{cte} SELECT timestamp_ms, node_tag, role, service_tag, status, latency_ms,
                        bytes_in, bytes_out, ip_hmac, raw_ip, client_country, rate_limited,
                        challenged, challenge_passed, error, device_type, browser_family,
                        os_family, client_fp_verified, ray_id, method, host, path, query,
                        protocol, scheme, user_agent, referer, action, cache_status, tls_ja3,
                        waf_rule_id, waf_category, suspicion_score, repeat_count,
                        hop_count, ingress_ts_ms, first_ts_ms,
                        egress_node_tag, egress_status, egress_latency_ms, egress_protocol
                 FROM primary_rows
                 ORDER BY COALESCE(ingress_ts_ms, first_ts_ms) DESC, id DESC
                 LIMIT ? OFFSET ?"
            );
            let mut items: Vec<serde_json::Value> = Vec::new();
            {
                let mut st = conn.prepare(&page_sql).map_err(|e| ExposureError::Storage(e.to_string()))?;
                let rows = st
                    .query_map(rusqlite::params_from_iter(page_args), |r| {
                        let summary = SessionSummary {
                            timestamp_ms: r.get(0)?,
                            node_tag: r.get(1)?,
                            role: r.get(2)?,
                            service_tag: r.get(3)?,
                            status: r.get::<_, i64>(4)?.clamp(0, u16::MAX as i64) as u16,
                            latency_ms: r.get(5)?,
                            bytes_in: r.get::<_, i64>(6)?.max(0) as u64,
                            bytes_out: r.get::<_, i64>(7)?.max(0) as u64,
                            ip_hmac: r.get(8)?,
                            raw_ip: r.get(9)?,
                            client_country: r.get(10)?,
                            rate_limited: r.get::<_, i64>(11)? != 0,
                            challenged: r.get::<_, i64>(12)? != 0,
                            challenge_passed: r.get::<_, i64>(13)? != 0,
                            error: r.get(14)?,
                            device_type: r.get(15)?,
                            browser_family: r.get(16)?,
                            os_family: r.get(17)?,
                            client_fp_verified: r.get::<_, i64>(18)? != 0,
                            ray_id: r.get(19)?,
                            method: r.get(20)?,
                            host: r.get(21)?,
                            path: r.get(22)?,
                            query: r.get(23)?,
                            protocol: r.get(24)?,
                            scheme: r.get(25)?,
                            user_agent: r.get(26)?,
                            referer: r.get(27)?,
                            action: r.get(28)?,
                            cache_status: r.get(29)?,
                            tls_ja3: r.get(30)?,
                            waf_rule_id: r.get::<_, Option<i64>>(31)?.map(|v| v.clamp(0, u32::MAX as i64) as u32),
                            waf_category: r.get(32)?,
                            suspicion_score: r.get::<_, Option<i64>>(33)?.map(|v| v.clamp(0, 255) as u8),
                            repeat_count: r.get::<_, i64>(34)?.clamp(1, u32::MAX as i64) as u32,
                        };
                        let hops = r.get::<_, i64>(35)?.max(1) as u32;
                        let ingress_ts_ms: Option<i64> = r.get(36)?;
                        let first_ts_ms: Option<i64> = r.get(37)?;
                        let egress_node_tag: Option<String> = r.get(38)?;
                        let egress_status: Option<i64> = r.get(39)?;
                        let egress_latency_ms: Option<f64> = r.get(40)?;
                        let egress_protocol: Option<String> = r.get(41)?;

                        let mut val = serde_json::to_value(&summary).unwrap_or_default();
                        if let Some(o) = val.as_object_mut() {
                            o.insert("hops".into(), serde_json::json!(hops));
                            o.insert(
                                "ray_entered_ms".into(),
                                serde_json::json!(
                                    ingress_ts_ms.or(first_ts_ms).unwrap_or(summary.timestamp_ms)
                                ),
                            );
                            if hops > 1 {
                                o.insert(
                                    "egress".into(),
                                    serde_json::json!({
                                        "node_tag": egress_node_tag,
                                        "status": egress_status.map(|v| v.clamp(0, u16::MAX as i64)),
                                        "latency_ms": egress_latency_ms,
                                        "protocol": egress_protocol,
                                    }),
                                );
                            }
                        }
                        Ok(val)
                    })
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
                for r in rows {
                    items.push(r.map_err(|e| ExposureError::Storage(e.to_string()))?);
                }
            }

            let tot = total_matched.max(0) as usize;
            let has_more = offset.saturating_add(items.len()) < tot;
            // keep imports used cleanly in non-test builds
            let _ = (is_mitigated_record, is_cache_served_status);

            Ok(serde_json::json!({
                "total_matched": tot,
                "offset": offset,
                "limit": lim,
                "has_more": has_more,
                "summary": {
                    "total_events": tot,
                    "total_requests": total_requests.max(0) as u64,
                    "blocked_requests": blocked_requests.max(0) as u64,
                    "error_5xx_requests": error_5xx_requests.max(0) as u64,
                    "cache_hits": cache_hits.max(0) as u64,
                    "folded_requests": folded_requests.max(0) as u64,
                    "unique_ips": unique_ips.max(0) as usize,
                    "unique_paths": unique_paths.max(0) as usize,
                },
                "top_paths": top_paths,
                "action_counts": action_counts,
                "status_class_counts": status_class_counts,
                "available_nodes": avail_nodes,
                "available_services": avail_svcs,
                "available_hosts": avail_hosts,
                "available_actions": avail_actions,
                "available_countries": avail_countries,
                "items": items,
            }))
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn query_fingerprints(
        &self,
        from_ms: Option<i64>,
        to_ms: Option<i64>,
        node: Option<String>,
        service: Option<String>,
        country: Option<String>,
        verified: Option<String>,
        risk: Option<String>,
        ip: Option<String>,
        ip_hmac: Option<String>,
        fp: Option<String>,
        q: Option<String>,
        q_ip_hmac: Option<String>,
        offset: usize,
        limit: usize,
    ) -> Result<serde_json::Value> {
        self.run_read(move |conn| {
            let from_sec = from_ms.map(|ms| ms.div_euclid(1000));
            let to_sec = to_ms.map(|ms| ms.div_euclid(1000));
            let node_f = clean_opt_str(node.as_deref());
            let svc_f = clean_opt_str(service.as_deref());
            let country_f = clean_opt_str(country.as_deref()).map(|s| s.to_ascii_uppercase());
            let verified_f = clean_opt_str(verified.as_deref()).unwrap_or_else(|| "all".into()).to_ascii_lowercase();
            let risk_f = clean_opt_str(risk.as_deref()).unwrap_or_else(|| "all".into()).to_ascii_lowercase();
            let ip_f = clean_opt_str(ip.as_deref()).map(|s| s.to_ascii_lowercase());
            let fp_f = clean_opt_str(fp.as_deref()).map(|s| s.to_ascii_lowercase());
            let q_f = clean_opt_str(q.as_deref()).map(|s| s.to_ascii_lowercase());

            let avail_nodes = Self::distinct_strings(conn, "SELECT DISTINCT node_tag FROM fingerprints ORDER BY 1")?;
            let avail_svcs = Self::distinct_strings(conn, "SELECT DISTINCT service_tag FROM fingerprints ORDER BY 1")?;
            let mut avail_countries = BTreeSet::new();
            for c in Self::distinct_strings(
                conn,
                "SELECT DISTINCT UPPER(COALESCE(NULLIF(geo_country,''), abuse_country)) FROM fingerprints WHERE COALESCE(NULLIF(geo_country,''), abuse_country) IS NOT NULL AND COALESCE(NULLIF(geo_country,''), abuse_country) != ''",
            )? {
                avail_countries.insert(c);
            }

            let mut where_sql = String::from(" WHERE 1=1");
            let mut args: Vec<Value> = Vec::new();
            if let Some(f) = from_sec {
                where_sql.push_str(" AND last_seen_ts >= ?");
                args.push(Value::Integer(f));
            }
            if let Some(t) = to_sec {
                where_sql.push_str(" AND last_seen_ts <= ?");
                args.push(Value::Integer(t));
            }
            if let Some(n) = node_f {
                where_sql.push_str(" AND node_tag = ?");
                args.push(Value::Text(n));
            }
            if let Some(s) = svc_f {
                where_sql.push_str(" AND service_tag = ?");
                args.push(Value::Text(s));
            }
            if let Some(c) = country_f {
                where_sql.push_str(" AND UPPER(COALESCE(NULLIF(geo_country,''), abuse_country, '')) = ?");
                args.push(Value::Text(c));
            }
            match verified_f.as_str() {
                "js" => where_sql.push_str(" AND js_verified = 1"),
                "ua" => where_sql.push_str(" AND js_verified = 0"),
                "beacon" => where_sql.push_str(" AND fp_source = 'beacon'"),
                "pow" => where_sql.push_str(" AND fp_source = 'pow'"),
                _ => {}
            }

            let sql = format!(
                "SELECT id, ip_hmac, client_ip, ip_prefix, fp_hash, js_verified, fp_source,
                        node_tag, service_tag, host, user_agent, accept_language,
                        device_type, browser_family, os_family, is_bot, is_headless,
                        suspicion_score, tls_cipher_count, tls_alpn, tls_ja3, tls_grease,
                        abuse_score, abuse_country, abuse_isp, abuse_is_tor,
                        geo_country, geo_continent, js_fp_json, first_seen_ts,
                        last_seen_ts, request_count, challenge_count, rate_limited_count
                 FROM fingerprints{where_sql}
                 ORDER BY last_seen_ts DESC"
            );
            let mut stmt = conn.prepare(&sql).map_err(|e| ExposureError::Storage(e.to_string()))?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(args), |row| {
                    let js_str: Option<String> = row.get(28)?;
                    let js_fp = js_str.and_then(|s| serde_json::from_str::<ClientJsFingerprint>(&s).ok());
                    Ok(FingerprintObservation {
                        id: row.get(0)?,
                        ip_hmac: row.get(1)?,
                        client_ip: row.get(2)?,
                        ip_prefix: row.get(3)?,
                        fp_hash: row.get(4)?,
                        js_verified: row.get::<_, i64>(5)? != 0,
                        fp_source: row.get(6)?,
                        node_tag: row.get(7)?,
                        service_tag: row.get(8)?,
                        host: row.get(9)?,
                        user_agent: row.get(10)?,
                        accept_language: row.get(11)?,
                        device_type: row.get(12)?,
                        browser_family: row.get(13)?,
                        os_family: row.get(14)?,
                        is_bot: row.get::<_, i64>(15)? != 0,
                        is_headless: row.get::<_, i64>(16)? != 0,
                        suspicion_score: row.get::<_, i64>(17)?.clamp(0, 255) as u8,
                        tls_cipher_count: row.get::<_, i64>(18)?.clamp(0, u16::MAX as i64) as u16,
                        tls_alpn: row.get::<_, i64>(19)? != 0,
                        tls_ja3: row.get(20)?,
                        tls_grease: row.get::<_, i64>(21)? != 0,
                        abuse_score: row.get::<_, Option<i64>>(22)?.map(|v| v.clamp(0, 100) as u8),
                        abuse_country: row.get(23)?,
                        abuse_isp: row.get(24)?,
                        abuse_is_tor: row.get::<_, i64>(25)? != 0,
                        geo_country: row.get(26)?,
                        geo_continent: row.get(27)?,
                        js_fp,
                        first_seen_ts: row.get(29)?,
                        last_seen_ts: row.get(30)?,
                        request_count: row.get::<_, i64>(31)?.max(0) as u64,
                        challenge_count: row.get::<_, i64>(32)?.max(0) as u64,
                        rate_limited_count: row.get::<_, i64>(33)?.max(0) as u64,
                    })
                })
                .map_err(|e| ExposureError::Storage(e.to_string()))?;

            let mut matched = Vec::new();
            let mut unique_ips = std::collections::HashSet::new();
            let mut unique_fps = std::collections::HashSet::new();
            let mut js_verified_count = 0usize;
            let mut beacon_count = 0usize;
            let mut pow_count = 0usize;
            let mut bot_count = 0usize;
            let mut headless_count = 0usize;
            let mut webrtc_leak_count = 0usize;
            let mut webrtc_lan_leak_count = 0usize;
            let mut device_counts: BTreeMap<String, u64> = BTreeMap::new();
            let mut browser_counts: BTreeMap<String, u64> = BTreeMap::new();
            let mut os_counts: BTreeMap<String, u64> = BTreeMap::new();

            for r in rows {
                let obs = r.map_err(|e| ExposureError::Storage(e.to_string()))?;
                match risk_f.as_str() {
                    "bot" if !obs.is_bot => continue,
                    "headless" if !obs.is_headless => continue,
                    "webrtc_leak"
                        if !obs
                            .js_fp
                            .as_ref()
                            .map(|j| j.webrtc_ip_mismatch || !j.webrtc_local_ips.is_empty())
                            .unwrap_or(false) =>
                    {
                        continue
                    }
                    "suspicious" if obs.suspicion_score < 40 && !obs.is_bot && !obs.is_headless => continue,
                    "clean" if obs.is_bot || obs.is_headless || obs.suspicion_score >= 40 => continue,
                    _ => {}
                }
                if let Some(ref ipq) = ip_f {
                    let raw_m = obs.client_ip.as_deref().map(|v| v.to_ascii_lowercase().contains(ipq)).unwrap_or(false);
                    let pref_m = obs.ip_prefix.to_ascii_lowercase().contains(ipq);
                    let hm_m = obs.ip_hmac.to_ascii_lowercase().contains(ipq);
                    let hm_ex = ip_hmac.as_deref().map(|h| obs.ip_hmac.eq_ignore_ascii_case(h)).unwrap_or(false);
                    let rtc_m = obs.js_fp.as_ref().map(|j| j.webrtc_public_ips.iter().chain(j.webrtc_local_ips.iter()).any(|w| w.to_ascii_lowercase().contains(ipq))).unwrap_or(false);
                    if !(raw_m || pref_m || hm_m || hm_ex || rtc_m) {
                        continue;
                    }
                }
                if let Some(ref fpq) = fp_f {
                    let hash_m = obs.fp_hash.to_ascii_lowercase().contains(fpq)
                        || obs.tls_ja3.as_deref().map(|j| j.to_ascii_lowercase().contains(fpq)).unwrap_or(false);
                    let cv_m = obs.js_fp.as_ref().map(|j| {
                        j.canvas_hash.to_ascii_lowercase().contains(fpq)
                            || j.webgl.to_ascii_lowercase().contains(fpq)
                            || j.webgl_vendor.to_ascii_lowercase().contains(fpq)
                            || j.audio_hash.to_ascii_lowercase().contains(fpq)
                            || j.fonts_hash.to_ascii_lowercase().contains(fpq)
                            || j.platform.to_ascii_lowercase().contains(fpq)
                            || j.screen.to_ascii_lowercase().contains(fpq)
                    }).unwrap_or(false);
                    if !(hash_m || cv_m) {
                        continue;
                    }
                }
                if let Some(ref qs) = q_f {
                    let hm_ex = q_ip_hmac.as_deref().map(|h| obs.ip_hmac.eq_ignore_ascii_case(h)).unwrap_or(false);
                    let hit = hm_ex
                        || obs.client_ip.as_deref().map(|v| v.to_ascii_lowercase().contains(qs)).unwrap_or(false)
                        || obs.ip_prefix.to_ascii_lowercase().contains(qs)
                        || obs.ip_hmac.to_ascii_lowercase().contains(qs)
                        || obs.fp_hash.to_ascii_lowercase().contains(qs)
                        || obs.tls_ja3.as_deref().map(|v| v.to_ascii_lowercase().contains(qs)).unwrap_or(false)
                        || obs.abuse_country.as_deref().map(|v| v.to_ascii_lowercase().contains(qs)).unwrap_or(false)
                        || obs.geo_country.as_deref().map(|v| v.to_ascii_lowercase().contains(qs)).unwrap_or(false)
                        || obs.geo_continent.as_deref().map(|v| v.to_ascii_lowercase().contains(qs)).unwrap_or(false)
                        || obs.abuse_isp.as_deref().map(|v| v.to_ascii_lowercase().contains(qs)).unwrap_or(false)
                        || obs.user_agent.to_ascii_lowercase().contains(qs)
                        || obs.host.to_ascii_lowercase().contains(qs)
                        || obs.service_tag.to_ascii_lowercase().contains(qs)
                        || obs.node_tag.to_ascii_lowercase().contains(qs)
                        || obs.browser_family.to_ascii_lowercase().contains(qs)
                        || obs.os_family.to_ascii_lowercase().contains(qs)
                        || obs.device_type.to_ascii_lowercase().contains(qs)
                        || obs.js_fp.as_ref().map(|j| {
                            j.webgl.to_ascii_lowercase().contains(qs)
                                || j.webgl_vendor.to_ascii_lowercase().contains(qs)
                                || j.canvas_hash.to_ascii_lowercase().contains(qs)
                                || j.audio_hash.to_ascii_lowercase().contains(qs)
                                || j.fonts_hash.to_ascii_lowercase().contains(qs)
                                || j.ua_brands.to_ascii_lowercase().contains(qs)
                                || j.platform.to_ascii_lowercase().contains(qs)
                                || j.tz.to_ascii_lowercase().contains(qs)
                                || j.screen.to_ascii_lowercase().contains(qs)
                                || j.webrtc_status.to_ascii_lowercase().contains(qs)
                                || j.webrtc_public_ips.iter().chain(j.webrtc_local_ips.iter()).any(|w| w.to_ascii_lowercase().contains(qs))
                        }).unwrap_or(false);
                    if !hit {
                        continue;
                    }
                }

                unique_ips.insert(obs.ip_hmac.clone());
                unique_fps.insert(obs.fp_hash.clone());
                if obs.js_verified {
                    js_verified_count += 1;
                }
                if obs.fp_source == "beacon" {
                    beacon_count += 1;
                } else if obs.fp_source == "pow" {
                    pow_count += 1;
                }
                if obs.is_bot {
                    bot_count += 1;
                }
                if obs.is_headless {
                    headless_count += 1;
                }
                if let Some(ref js) = obs.js_fp {
                    if js.webrtc_ip_mismatch {
                        webrtc_leak_count += 1;
                    }
                    if !js.webrtc_local_ips.is_empty() {
                        webrtc_lan_leak_count += 1;
                    }
                }
                if !obs.device_type.is_empty() {
                    *device_counts.entry(obs.device_type.clone()).or_insert(0) += 1;
                }
                if !obs.browser_family.is_empty() {
                    *browser_counts.entry(obs.browser_family.clone()).or_insert(0) += 1;
                }
                if !obs.os_family.is_empty() {
                    *os_counts.entry(obs.os_family.clone()).or_insert(0) += 1;
                }
                matched.push(obs);
            }

            let total_matched = matched.len();
            let lim = limit.clamp(1, 200);
            let page: Vec<FingerprintObservation> = matched.into_iter().skip(offset).take(lim).collect();
            let has_more = offset.saturating_add(page.len()) < total_matched;

            Ok(serde_json::json!({
                "total_matched": total_matched,
                "offset": offset,
                "limit": lim,
                "has_more": has_more,
                "summary": {
                    "total_visitors": total_matched,
                    "unique_ips": unique_ips.len(),
                    "unique_fps": unique_fps.len(),
                    "js_verified": js_verified_count,
                    "beacon_count": beacon_count,
                    "pow_count": pow_count,
                    "bots": bot_count,
                    "headless": headless_count,
                    "webrtc_leaks": webrtc_leak_count,
                    "webrtc_lan_leaks": webrtc_lan_leak_count,
                },
                "device_counts": device_counts,
                "browser_counts": browser_counts,
                "os_counts": os_counts,
                "available_nodes": avail_nodes,
                "available_services": avail_svcs,
                "available_countries": avail_countries.into_iter().collect::<Vec<_>>(),
                "items": page,
            }))
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn query_evilpot(
        &self,
        from_ms: Option<i64>,
        to_ms: Option<i64>,
        node: Option<String>,
        status: Option<String>,
        ip: Option<String>,
        q: Option<String>,
        sessions_offset: usize,
        sessions_limit: usize,
        events_offset: usize,
        events_limit: usize,
    ) -> Result<serde_json::Value> {
        self.run_read(move |conn| {
            let from_sec = from_ms.map(|ms| ms.div_euclid(1000).max(0));
            let to_sec = to_ms.map(|ms| ms.div_euclid(1000).max(0));
            let node_f = clean_opt_str(node.as_deref());
            let status_f = clean_opt_str(status.as_deref()).map(|s| s.to_ascii_lowercase());
            let ip_f = clean_opt_str(ip.as_deref());
            let q_f = clean_opt_str(q.as_deref());

            let avail_nodes = Self::distinct_strings(
                conn,
                "SELECT node_tag FROM evilpot_sessions UNION SELECT node_tag FROM evilpot_events ORDER BY 1",
            )?;

            // Sessions query
            let mut s_where = String::from(" WHERE 1=1");
            let mut s_args: Vec<Value> = Vec::new();
            if let Some(f) = from_sec {
                s_where.push_str(" AND last_seen_unix >= ?");
                s_args.push(Value::Integer(f));
            }
            if let Some(t) = to_sec {
                s_where.push_str(" AND first_seen_unix <= ?");
                s_args.push(Value::Integer(t));
            }
            if let Some(ref n) = node_f {
                s_where.push_str(" AND node_tag = ?");
                s_args.push(Value::Text(n.clone()));
            }
            if let Some(ref st) = status_f {
                s_where.push_str(" AND status = ?");
                s_args.push(Value::Text(st.clone()));
            }
            if let Some(ref ipq) = ip_f {
                s_where.push_str(" AND LOWER(client_ip) LIKE ? ESCAPE '\\'");
                s_args.push(Value::Text(escape_like_needle(ipq)));
            }
            if let Some(ref qs) = q_f {
                let pat = escape_like_needle(qs);
                s_where.push_str(" AND (LOWER(client_ip) LIKE ? ESCAPE '\\' OR LOWER(persona_hostname) LIKE ? ESCAPE '\\' OR LOWER(rce_commands_json) LIKE ? ESCAPE '\\' OR LOWER(captured_iocs_json) LIKE ? ESCAPE '\\' OR LOWER(distinct_paths_json) LIKE ? ESCAPE '\\' OR LOWER(evidence_json) LIKE ? ESCAPE '\\' OR LOWER(node_tag) LIKE ? ESCAPE '\\')");
                for _ in 0..7 {
                    s_args.push(Value::Text(pat.clone()));
                }
            }

            let s_sum_sql = format!(
                "SELECT COUNT(*),
                        COALESCE(SUM(CASE WHEN status = 'verified_exploit' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN status = 'multi_step_exploitation' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN status = 'probing' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(total_trapped_requests), 0),
                        COALESCE(SUM(canary_triggers), 0),
                        COALESCE(SUM(tarpit_bytes_consumed), 0)
                 FROM evilpot_sessions{s_where}"
            );
            let (s_total, s_verified, s_multi, s_probing, trapped_reqs, canary_hits, tarpit_bytes): (
                i64, i64, i64, i64, i64, i64, i64,
            ) = conn
                .query_row(&s_sum_sql, rusqlite::params_from_iter(s_args.clone()), |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))
                })
                .unwrap_or((0, 0, 0, 0, 0, 0, 0));

            let s_lim = sessions_limit.clamp(1, 200);
            let mut s_page_args = s_args;
            s_page_args.push(Value::Integer(s_lim as i64));
            s_page_args.push(Value::Integer(sessions_offset as i64));
            let s_page_sql = format!(
                "SELECT node_tag, client_ip, epoch_id, persona_hostname, first_seen_unix,
                        last_seen_unix, total_trapped_requests, status, canary_triggers,
                        sqli_probes, sqli_distinct_positions, rce_commands_json,
                        captured_iocs_json, distinct_paths_json, tarpit_bytes_consumed,
                        tarpit_max_duration_ms, evidence_json
                 FROM evilpot_sessions{s_where}
                 ORDER BY status_rank DESC, last_seen_unix DESC
                 LIMIT ? OFFSET ?"
            );
            let mut sessions = Vec::new();
            {
                let mut st = conn.prepare(&s_page_sql).map_err(|e| ExposureError::Storage(e.to_string()))?;
                let rows = st
                    .query_map(rusqlite::params_from_iter(s_page_args), |row| {
                        let rce_s: String = row.get(11)?;
                        let ioc_s: String = row.get(12)?;
                        let path_s: String = row.get(13)?;
                        let ev_s: String = row.get(16)?;
                        Ok(EvilpotSessionInfo {
                            node_tag: row.get(0)?,
                            client_ip: row.get(1)?,
                            epoch_id: row.get::<_, i64>(2)?.max(0) as u64,
                            persona_hostname: row.get(3)?,
                            first_seen_unix: row.get::<_, i64>(4)?.max(0) as u64,
                            last_seen_unix: row.get::<_, i64>(5)?.max(0) as u64,
                            total_trapped_requests: row.get::<_, i64>(6)?.max(0) as u64,
                            status: row.get(7)?,
                            canary_triggers: row.get::<_, i64>(8)?.max(0) as u32,
                            sqli_probes: row.get::<_, i64>(9)?.max(0) as u32,
                            sqli_distinct_positions: row.get::<_, i64>(10)?.max(0) as usize,
                            rce_commands_executed: serde_json::from_str(&rce_s).unwrap_or_default(),
                            captured_iocs: serde_json::from_str(&ioc_s).unwrap_or_default(),
                            distinct_paths: serde_json::from_str(&path_s).unwrap_or_default(),
                            tarpit_bytes_consumed: row.get::<_, i64>(14)?.max(0) as u64,
                            tarpit_max_duration_ms: row.get::<_, i64>(15)?.max(0) as u64,
                            evidence: serde_json::from_str(&ev_s).unwrap_or_default(),
                        })
                    })
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
                for r in rows {
                    sessions.push(r.map_err(|e| ExposureError::Storage(e.to_string()))?);
                }
            }

            // Events query
            let mut e_where = String::from(" WHERE 1=1");
            let mut e_args: Vec<Value> = Vec::new();
            if let Some(f) = from_sec {
                e_where.push_str(" AND timestamp_unix >= ?");
                e_args.push(Value::Integer(f));
            }
            if let Some(t) = to_sec {
                e_where.push_str(" AND timestamp_unix <= ?");
                e_args.push(Value::Integer(t));
            }
            if let Some(ref n) = node_f {
                e_where.push_str(" AND node_tag = ?");
                e_args.push(Value::Text(n.clone()));
            }
            if let Some(ref st) = status_f {
                e_where.push_str(" AND verification_status = ?");
                e_args.push(Value::Text(st.clone()));
            }
            if let Some(ref ipq) = ip_f {
                e_where.push_str(" AND LOWER(client_ip) LIKE ? ESCAPE '\\'");
                e_args.push(Value::Text(escape_like_needle(ipq)));
            }
            if let Some(ref qs) = q_f {
                let pat = escape_like_needle(qs);
                e_where.push_str(" AND (LOWER(client_ip) LIKE ? ESCAPE '\\' OR LOWER(trap_kind) LIKE ? ESCAPE '\\' OR LOWER(detail) LIKE ? ESCAPE '\\' OR LOWER(persona_hostname) LIKE ? ESCAPE '\\' OR LOWER(evidence_json) LIKE ? ESCAPE '\\' OR LOWER(node_tag) LIKE ? ESCAPE '\\')");
                for _ in 0..6 {
                    e_args.push(Value::Text(pat.clone()));
                }
            }

            let e_total: i64 = conn
                .query_row(
                    &format!("SELECT COUNT(*) FROM evilpot_events{e_where}"),
                    rusqlite::params_from_iter(e_args.clone()),
                    |r| r.get(0),
                )
                .unwrap_or(0);
            let e_lim = events_limit.clamp(1, 200);
            let mut e_page_args = e_args;
            e_page_args.push(Value::Integer(e_lim as i64));
            e_page_args.push(Value::Integer(events_offset as i64));
            let e_page_sql = format!(
                "SELECT node_tag, timestamp_unix, epoch_id, persona_hostname, client_ip,
                        verification_status, trap_kind, detail, evidence_json
                 FROM evilpot_events{e_where}
                 ORDER BY timestamp_unix DESC, id DESC
                 LIMIT ? OFFSET ?"
            );
            let mut events = Vec::new();
            {
                let mut st = conn.prepare(&e_page_sql).map_err(|e| ExposureError::Storage(e.to_string()))?;
                let rows = st
                    .query_map(rusqlite::params_from_iter(e_page_args), |row| {
                        let ev_s: String = row.get(8)?;
                        Ok(EvilpotEventInfo {
                            node_tag: row.get(0)?,
                            timestamp_unix: row.get::<_, i64>(1)?.max(0) as u64,
                            epoch_id: row.get::<_, i64>(2)?.max(0) as u64,
                            persona_hostname: row.get(3)?,
                            client_ip: row.get(4)?,
                            verification_status: row.get(5)?,
                            trap_kind: row.get(6)?,
                            detail: row.get(7)?,
                            evidence: serde_json::from_str(&ev_s).unwrap_or_default(),
                        })
                    })
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
                for r in rows {
                    events.push(r.map_err(|e| ExposureError::Storage(e.to_string()))?);
                }
            }

            Ok(serde_json::json!({
                "summary": {
                    "tracked_sessions": s_total.max(0) as u64,
                    "verified_attack_sessions": s_verified.max(0) as u64,
                    "multi_step_sessions": s_multi.max(0) as u64,
                    "probing_sessions": s_probing.max(0) as u64,
                    "traps_triggered": trapped_reqs.max(0) as u64,
                    "canary_verifications": canary_hits.max(0) as u64,
                    "tarpit_bytes_dripped": tarpit_bytes.max(0) as u64,
                    "total_events": e_total.max(0) as u64,
                },
                "available_nodes": avail_nodes,
                "sessions": sessions,
                "sessions_total": s_total.max(0) as usize,
                "sessions_offset": sessions_offset,
                "sessions_limit": s_lim,
                "recent_events": events,
                "events_total": e_total.max(0) as usize,
                "events_offset": events_offset,
                "events_limit": e_lim,
            }))
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn query_bans(
        &self,
        from_ms: Option<i64>,
        to_ms: Option<i64>,
        node: Option<String>,
        status: Option<String>,
        kind: Option<String>,
        target: Option<String>,
        q: Option<String>,
        offset: usize,
        limit: usize,
    ) -> Result<serde_json::Value> {
        self.run_read(move |conn| {
            let now_u = Utc::now().timestamp().max(0);
            let from_sec = from_ms.map(|ms| ms.div_euclid(1000).max(0));
            let to_sec = to_ms.map(|ms| ms.div_euclid(1000).max(0));
            let node_f = clean_opt_str(node.as_deref());
            let status_f = clean_opt_str(status.as_deref()).map(|s| s.to_ascii_lowercase());
            let kind_f = clean_opt_str(kind.as_deref()).map(|s| s.to_ascii_lowercase());
            let target_f = clean_opt_str(target.as_deref());
            let q_f = clean_opt_str(q.as_deref());

            let avail_nodes = Self::distinct_strings(conn, "SELECT DISTINCT node_tag FROM ban_records ORDER BY 1")?;

            let eff_expr = "CASE WHEN status = 'active' AND expires_at_unix <= ? THEN 'expired' ELSE status END";
            let mut where_sql = String::from(" WHERE 1=1");
            let mut args: Vec<Value> = Vec::new();
            if let (Some(f), Some(t)) = (from_sec, to_sec) {
                where_sql.push_str(" AND ((banned_at_unix >= ? AND banned_at_unix <= ?) OR (status = 'active' AND expires_at_unix > ? AND banned_at_unix <= ?))");
                args.push(Value::Integer(f));
                args.push(Value::Integer(t));
                args.push(Value::Integer(now_u));
                args.push(Value::Integer(t));
            } else if let Some(f) = from_sec {
                where_sql.push_str(" AND (banned_at_unix >= ? OR (status = 'active' AND expires_at_unix > ?))");
                args.push(Value::Integer(f));
                args.push(Value::Integer(now_u));
            } else if let Some(t) = to_sec {
                where_sql.push_str(" AND banned_at_unix <= ?");
                args.push(Value::Integer(t));
            }
            if let Some(n) = node_f {
                where_sql.push_str(" AND node_tag = ?");
                args.push(Value::Text(n));
            }
            if let Some(k) = kind_f {
                where_sql.push_str(" AND kind = ?");
                args.push(Value::Text(k));
            }
            if let Some(tgt) = target_f {
                where_sql.push_str(" AND LOWER(target) LIKE ? ESCAPE '\\'");
                args.push(Value::Text(escape_like_needle(&tgt)));
            }
            if let Some(qs) = q_f {
                let pat = escape_like_needle(&qs);
                where_sql.push_str(" AND (LOWER(target) LIKE ? ESCAPE '\\' OR LOWER(reason) LIKE ? ESCAPE '\\' OR LOWER(COALESCE(host,'')) LIKE ? ESCAPE '\\' OR LOWER(COALESCE(service_tag,'')) LIKE ? ESCAPE '\\' OR LOWER(node_tag) LIKE ? ESCAPE '\\' OR LOWER(COALESCE(unbanned_by,'')) LIKE ? ESCAPE '\\')");
                for _ in 0..6 {
                    args.push(Value::Text(pat.clone()));
                }
            }

            // Summary across window (before status filter) so tab/pill counts remain informative
            let sum_sql = format!(
                "SELECT COUNT(*),
                        COALESCE(SUM(CASE WHEN ({eff_expr}) = 'active' AND kind = 'ip' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN ({eff_expr}) = 'active' AND kind != 'ip' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN ({eff_expr}) = 'expired' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(CASE WHEN ({eff_expr}) = 'unbanned' THEN 1 ELSE 0 END), 0),
                        COALESCE(SUM(hits_blocked), 0)
                 FROM ban_records{where_sql}"
            );
            let mut sum_args = vec![Value::Integer(now_u), Value::Integer(now_u), Value::Integer(now_u), Value::Integer(now_u)];
            sum_args.extend(args.clone());
            let (total_bans, active_ip_bans, active_fp_bans, expired_bans, unbanned_bans, total_hits_blocked): (
                i64, i64, i64, i64, i64, i64,
            ) = conn
                .query_row(&sum_sql, rusqlite::params_from_iter(sum_args), |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
                })
                .unwrap_or((0, 0, 0, 0, 0, 0));

            let mut list_where = where_sql;
            let mut list_args = args;
            if let Some(ref st) = status_f {
                list_where.push_str(&format!(" AND ({eff_expr}) = ?"));
                list_args.push(Value::Integer(now_u));
                list_args.push(Value::Text(st.clone()));
            }

            let total_matched: i64 = conn
                .query_row(
                    &format!("SELECT COUNT(*) FROM ban_records{list_where}"),
                    rusqlite::params_from_iter(list_args.clone()),
                    |r| r.get(0),
                )
                .unwrap_or(0);

            let lim = limit.clamp(1, 200);
            let mut page_args = Vec::with_capacity(list_args.len() + 3);
            page_args.push(Value::Integer(now_u));
            page_args.extend(list_args);
            page_args.push(Value::Integer(lim as i64));
            page_args.push(Value::Integer(offset as i64));

            let page_sql = format!(
                "SELECT id, node_tag, kind, target, reason, service_tag, host, offense_level,
                        banned_at_unix, expires_at_unix, unbanned_at_unix, unbanned_by,
                        hits_blocked, ({eff_expr}) AS eff_status
                 FROM ban_records{list_where}
                 ORDER BY CASE WHEN eff_status = 'active' THEN 0 ELSE 1 END, banned_at_unix DESC, id DESC
                 LIMIT ? OFFSET ?"
            );
            let mut items = Vec::new();
            {
                let mut st = conn.prepare(&page_sql).map_err(|e| ExposureError::Storage(e.to_string()))?;
                let rows = st
                    .query_map(rusqlite::params_from_iter(page_args), |r| {
                        Ok(BanRecord {
                            id: r.get(0)?,
                            node_tag: r.get(1)?,
                            kind: r.get(2)?,
                            target: r.get(3)?,
                            reason: r.get(4)?,
                            service_tag: r.get(5)?,
                            host: r.get(6)?,
                            offense_level: r.get::<_, i64>(7)?.clamp(0, 255) as u8,
                            banned_at_unix: r.get::<_, i64>(8)?.max(0) as u64,
                            expires_at_unix: r.get::<_, i64>(9)?.max(0) as u64,
                            unbanned_at_unix: r.get::<_, Option<i64>>(10)?.map(|v| v.max(0) as u64),
                            unbanned_by: r.get(11)?,
                            hits_blocked: r.get::<_, i64>(12)?.max(0) as u64,
                            status: r.get(13)?,
                        })
                    })
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
                for r in rows {
                    items.push(r.map_err(|e| ExposureError::Storage(e.to_string()))?);
                }
            }

            let tot = total_matched.max(0) as usize;
            let has_more = offset.saturating_add(items.len()) < tot;

            Ok(serde_json::json!({
                "total_matched": tot,
                "offset": offset,
                "limit": lim,
                "has_more": has_more,
                "summary": {
                    "total_bans": total_bans.max(0) as u64,
                    "active_ip_bans": active_ip_bans.max(0) as usize,
                    "active_fp_bans": active_fp_bans.max(0) as usize,
                    "expired_bans": expired_bans.max(0) as u64,
                    "unbanned_bans": unbanned_bans.max(0) as u64,
                    "total_hits_blocked": total_hits_blocked.max(0) as u64,
                },
                "available_nodes": avail_nodes,
                "items": items,
            }))
        })
        .await
    }

    pub async fn query_alerts(
        &self,
        from_ms: Option<i64>,
        to_ms: Option<i64>,
        node: Option<String>,
        severity: Option<String>,
        q: Option<String>,
        offset: usize,
        limit: usize,
    ) -> Result<serde_json::Value> {
        self.run_read(move |conn| {
            let node_f = clean_opt_str(node.as_deref());
            let sev_f = clean_opt_str(severity.as_deref()).map(|s| normalize_alert_severity(&s).to_string());
            let q_f = clean_opt_str(q.as_deref());

            let avail_sources = Self::distinct_strings(conn, "SELECT DISTINCT source FROM alerts ORDER BY 1")?;

            let mut where_sql = String::from(" WHERE 1=1");
            let mut args: Vec<Value> = Vec::new();
            if let Some(f) = from_ms {
                where_sql.push_str(" AND timestamp_ms >= ?");
                args.push(Value::Integer(f));
            }
            if let Some(t) = to_ms {
                where_sql.push_str(" AND timestamp_ms <= ?");
                args.push(Value::Integer(t));
            }
            if let Some(n) = node_f {
                where_sql.push_str(" AND source = ?");
                args.push(Value::Text(n));
            }
            if let Some(qs) = q_f {
                let pat = escape_like_needle(&qs);
                where_sql.push_str(" AND (LOWER(message) LIKE ? ESCAPE '\\' OR LOWER(source) LIKE ? ESCAPE '\\' OR LOWER(severity) LIKE ? ESCAPE '\\')");
                for _ in 0..3 {
                    args.push(Value::Text(pat.clone()));
                }
            }

            let mut sev_counts: BTreeMap<String, u64> = BTreeMap::new();
            {
                let mut st = conn
                    .prepare(&format!("SELECT severity, COUNT(*) FROM alerts{where_sql} GROUP BY severity"))
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
                let rows = st
                    .query_map(rusqlite::params_from_iter(args.clone()), |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?.max(0) as u64))
                    })
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
                for r in rows {
                    let (k, v) = r.map_err(|e| ExposureError::Storage(e.to_string()))?;
                    sev_counts.insert(k, v);
                }
            }

            if let Some(sv) = sev_f {
                where_sql.push_str(" AND severity = ?");
                args.push(Value::Text(sv));
            }

            let total_matched: i64 = conn
                .query_row(
                    &format!("SELECT COUNT(*) FROM alerts{where_sql}"),
                    rusqlite::params_from_iter(args.clone()),
                    |r| r.get(0),
                )
                .unwrap_or(0);

            let lim = limit.clamp(1, 200);
            let mut page_args = args;
            page_args.push(Value::Integer(lim as i64));
            page_args.push(Value::Integer(offset as i64));

            let mut items = Vec::new();
            {
                let mut st = conn
                    .prepare(&format!(
                        "SELECT timestamp_ms, timestamp, source, severity, message
                         FROM alerts{where_sql}
                         ORDER BY timestamp_ms DESC, id DESC
                         LIMIT ? OFFSET ?"
                    ))
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
                let rows = st
                    .query_map(rusqlite::params_from_iter(page_args), |r| {
                        Ok(AlertRecord {
                            timestamp_ms: r.get(0)?,
                            timestamp: r.get(1)?,
                            source: r.get(2)?,
                            severity: r.get(3)?,
                            message: r.get(4)?,
                        })
                    })
                    .map_err(|e| ExposureError::Storage(e.to_string()))?;
                for r in rows {
                    items.push(r.map_err(|e| ExposureError::Storage(e.to_string()))?);
                }
            }

            let tot = total_matched.max(0) as usize;
            let has_more = offset.saturating_add(items.len()) < tot;

            Ok(serde_json::json!({
                "total_matched": tot,
                "offset": offset,
                "limit": lim,
                "has_more": has_more,
                "severity_counts": sev_counts,
                "available_sources": avail_sources,
                "items": items,
            }))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn maintainer_db_ingests_all_streams_queries_windows_and_cleans_up_without_jsonl() {
        let dir = std::env::temp_dir().join(format!("exp-mdb-test-{}", uuid::Uuid::new_v4()));
        let dir_s = dir.to_string_lossy().to_string();
        let db = MaintainerDb::open(&dir_s, "maint-1").unwrap();

        let now_ms = Utc::now().timestamp_millis();
        let now_s = (now_ms / 1000).max(1);
        let now_min = (now_s / 60) * 60;

        let rec_evil = SessionSummary {
            timestamp_ms: now_ms - 10_000,
            node_tag: "edge-1".into(),
            role: "ingress".into(),
            service_tag: "www-static".into(),
            status: 200,
            latency_ms: 42.0,
            ip_hmac: "hmac-att".into(),
            raw_ip: Some("64.227.75.77".into()),
            method: Some("GET".into()),
            host: Some("jincaituanwei.com".into()),
            path: Some("/../../../etc/passwd".into()),
            action: Some("evilpot".into()),
            waf_category: Some("path-traversal".into()),
            ray_id: Some("ray-ep-1".into()),
            ..Default::default()
        };
        let mut sum = MinuteSummary::new(now_min, "edge-1", "ingress", "www-static", 12, 42, vec![10.0, 50.0, 100.0]);
        sum.record(&rec_evil);

        let ep_sess = EvilpotSessionInfo {
            node_tag: "edge-1".into(),
            client_ip: "64.227.75.77".into(),
            epoch_id: 1,
            persona_hostname: "srv-decoy".into(),
            first_seen_unix: (now_s - 60) as u64,
            last_seen_unix: now_s as u64,
            total_trapped_requests: 3,
            status: "multi_step_exploitation".into(),
            canary_triggers: 0,
            sqli_probes: 0,
            sqli_distinct_positions: 0,
            rce_commands_executed: vec![],
            captured_iocs: vec![],
            distinct_paths: vec!["/.env".into(), "/etc/passwd".into(), "/wp-config.php".into()],
            tarpit_bytes_consumed: 0,
            tarpit_max_duration_ms: 0,
            evidence: vec!["recon:paths=3".into()],
        };
        let ep_ev = EvilpotEventInfo {
            node_tag: "edge-1".into(),
            timestamp_unix: now_s as u64,
            epoch_id: 1,
            persona_hostname: "srv-decoy".into(),
            client_ip: "64.227.75.77".into(),
            verification_status: "multi_step_exploitation".into(),
            trap_kind: "PathTraversal".into(),
            detail: "GET /../../../etc/passwd".into(),
            evidence: vec!["recon:paths=3".into()],
        };
        let ban = BanRecord {
            id: 0,
            node_tag: "edge-1".into(),
            kind: "ip".into(),
            target: "64.227.75.77".into(),
            reason: "evilpot:multi_step_exploitation:path-traversal".into(),
            service_tag: Some("www-static".into()),
            host: Some("jincaituanwei.com".into()),
            offense_level: 1,
            banned_at_unix: now_s as u64,
            expires_at_unix: (now_s + 1800) as u64,
            unbanned_at_unix: None,
            unbanned_by: None,
            hits_blocked: 5,
            status: "active".into(),
        };
        let alert = AlertRecord {
            timestamp_ms: now_ms,
            timestamp: Utc::now().to_rfc3339(),
            source: "edge-1".into(),
            severity: "warn".into(),
            message: "AutoBan triggered for 64.227.75.77".into(),
        };

        let ingested = db
            .ingest_batch(
                "edge-1",
                true,
                &MaintainerRetentionConfig::default(),
                vec![rec_evil],
                vec![sum],
                vec![],
                vec![ep_sess],
                vec![ep_ev],
                vec![ban],
                vec![alert],
            )
            .await
            .unwrap();
        assert_eq!(ingested, 6);

        // Verify zero .seg.jsonl files created on Maintainer
        let seg_count = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".seg.jsonl"))
            .count();
        assert_eq!(seg_count, 0);

        // Query Evilpot & Bans across 1h window
        let ep_res = db
            .query_evilpot(
                Some(now_ms - 3600_000),
                Some(now_ms + 60_000),
                None,
                None,
                None,
                None,
                0,
                50,
                0,
                50,
            )
            .await
            .unwrap();
        assert_eq!(ep_res["summary"]["tracked_sessions"], 1);
        assert_eq!(ep_res["recent_events"].as_array().unwrap().len(), 1);

        let bans_res = db
            .query_bans(
                Some(now_ms - 3600_000),
                Some(now_ms + 60_000),
                None,
                Some("active".into()),
                None,
                None,
                None,
                0,
                50,
            )
            .await
            .unwrap();
        assert_eq!(bans_res["summary"]["active_ip_bans"], 1);
        assert_eq!(bans_res["items"][0]["target"], "64.227.75.77");

        // Unban and verify status transitions cleanly
        let changed = db
            .mark_unbanned(
                None,
                "ip".into(),
                "64.227.75.77".into(),
                "admin".into(),
                (now_s + 10) as u64,
            )
            .await
            .unwrap();
        assert_eq!(changed, 1);

        let unbanned_res = db
            .query_bans(
                None,
                None,
                None,
                Some("unbanned".into()),
                None,
                None,
                None,
                0,
                50,
            )
            .await
            .unwrap();
        assert_eq!(unbanned_res["items"].as_array().unwrap().len(), 1);
        assert_eq!(unbanned_res["items"][0]["unbanned_by"], "admin");

        // Alerts normalized "warn" -> "warning"
        let alerts_res = db
            .query_alerts(None, None, None, Some("warning".into()), None, 0, 50)
            .await
            .unwrap();
        assert_eq!(alerts_res["total_matched"], 1);
        assert_eq!(alerts_res["items"][0]["severity"], "warning");

        // Run cleanup & verify stats
        let cleanup = db.run_cleanup(&MaintainerRetentionConfig::default()).await.unwrap();
        assert!(cleanup.storage_stats.db_bytes > 0);
        assert_eq!(cleanup.storage_stats.access_logs_rows, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn access_logs_collapse_hops_by_ray_id_and_sort_by_ingress_time() {
        let dir = std::env::temp_dir().join(format!("exp-mdb-ray-{}", uuid::Uuid::new_v4()));
        let dir_s = dir.to_string_lossy().to_string();
        let db = MaintainerDb::open(&dir_s, "maint-1").unwrap();
        let now_ms = Utc::now().timestamp_millis();

        let mk = |role: &'static str, ts: i64, ray: &str, status: u16, latency: f64| SessionSummary {
            timestamp_ms: ts,
            node_tag: if role == "ingress" { "ing-1" } else { "egr-1" }.into(),
            role: role.into(),
            service_tag: "web".into(),
            status,
            latency_ms: latency,
            ip_hmac: "hmac".into(),
            method: Some("GET".into()),
            host: Some("app.test".into()),
            path: Some("/x".into()),
            action: Some("allow".into()),
            ray_id: Some(ray.into()),
            ..Default::default()
        };

        // r1: ingress + egress (one client request, must collapse to a single row)
        // r2: ingress only (upstream failed before egress logged)
        // r3: egress only (ingress record missing) -> must still sort by its own timestamp
        let recs = vec![
            mk("ingress", now_ms - 30_000, "r1", 200, 12.0),
            mk("egress", now_ms - 29_000, "r1", 200, 6.0),
            mk("ingress", now_ms - 20_000, "r2", 502, 40.0),
            mk("egress", now_ms - 10_000, "r3", 200, 5.0),
        ];
        db.ingest_batch(
            "ing-1",
            true,
            &MaintainerRetentionConfig::default(),
            recs,
            Vec::<MinuteSummary>::new(),
            Vec::<FingerprintObservation>::new(),
            Vec::<EvilpotSessionInfo>::new(),
            Vec::<EvilpotEventInfo>::new(),
            Vec::<BanRecord>::new(),
            Vec::<AlertRecord>::new(),
        )
        .await
        .unwrap();

        let res = db
            .query_access_logs(
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, 0, 50,
            )
            .await
            .unwrap();

        assert_eq!(res["total_matched"], 3, "one row per Ray ID, not per hop");
        assert_eq!(
            res["summary"]["total_requests"], 3,
            "ingress+egress hops must not be double counted"
        );
        let items = res["items"].as_array().unwrap();
        assert_eq!(items.len(), 3);
        let rays: Vec<&str> = items.iter().filter_map(|i| i["ray_id"].as_str()).collect();
        assert_eq!(rays, vec!["r3", "r2", "r1"], "newest entry first, ingress time preferred");

        let r1 = items.iter().find(|i| i["ray_id"] == "r1").unwrap();
        assert_eq!(r1["hops"], 2);
        assert_eq!(r1["role"], "ingress");
        assert_eq!(r1["node_tag"], "ing-1");
        assert_eq!(r1["latency_ms"].as_f64().unwrap(), 12.0);
        assert_eq!(r1["egress"]["node_tag"], "egr-1");
        assert_eq!(r1["egress"]["latency_ms"].as_f64().unwrap(), 6.0);

        let r2 = items.iter().find(|i| i["ray_id"] == "r2").unwrap();
        assert_eq!(r2["hops"], 1);
        assert!(r2.get("egress").is_none(), "no egress hop to report");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
