use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;
use std::io::BufReader;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Duration as ChronoDuration, NaiveDate, Utc};
use exposure_core::config::{
    CertOrderConfig, DnsProviderAccountConfig, DomainBindingConfig, MaintainerConfig,
    resolve_domain_binding,
};
use exposure_core::crypto::{NodeKeyPair, validate_dns_domain, write_secret_file_atomic};
use exposure_core::protocol::{
    DnsLineSyncEntry, DnsManageOp, DnsProviderCapabilities, DnsRemoteRecord, DnsSupportLine,
    DnsSyncDomainResult, DnsSyncRecordSpec, MaintainerQuery, MaintainerTelemetrySnapshot,
    SpecialFrame, SpecialPayload, cert_bundle_signing_bytes,
};
use exposure_core::routing::is_public_routable_ip;
use exposure_core::telemetry::{
    AlertRecord, BanRecord, CertStatusInfo, EvilpotEventInfo, EvilpotSessionInfo,
    FingerprintObservation, MinuteSummary, SessionSummary,
};
use exposure_core::{ExposureError, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::process::Command;
use tokio::sync::{Mutex, RwLock, watch};
use tracing::{info, warn};
use uuid::Uuid;

use crate::forwarder::Forwarder;
use crate::maintainer_db::MaintainerDb;
use crate::tls::generate_self_signed_pem;

const EXEC_HOOK_TIMEOUT: Duration = Duration::from_secs(30);
const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(15);
const ALIDNS_API_VERSION: &str = "2015-01-09";
const EMPTY_BODY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn validate_cloudflare_id(val: &str, field: &str) -> Result<()> {
    let s = val.trim();
    if s.is_empty()
        || s.len() > 64
        || !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(ExposureError::Config(format!(
            "invalid Cloudflare {field}: '{val}'"
        )));
    }
    Ok(())
}

fn validate_aliyun_credentials<'a>(
    access_key_id: &'a str,
    access_key_secret: &'a str,
) -> Result<(&'a str, &'a str)> {
    let ak = access_key_id.trim();
    if ak.is_empty()
        || ak.len() > 128
        || ak
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == ',')
    {
        return Err(ExposureError::Config(
            "invalid Aliyun DNS access_key_id".into(),
        ));
    }
    let sk = access_key_secret.trim();
    if sk.is_empty() || sk.len() > 256 || sk.chars().any(|c| c.is_control()) {
        return Err(ExposureError::Config(
            "invalid Aliyun DNS access_key_secret".into(),
        ));
    }
    Ok((ak, sk))
}

fn validate_aliyun_record_id(val: &str) -> Result<()> {
    let s = val.trim();
    if s.is_empty()
        || s.len() > 64
        || !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(ExposureError::Config(format!(
            "invalid Aliyun DNS record_id: '{val}'"
        )));
    }
    Ok(())
}

fn validate_dns_line_code(val: &str) -> Result<String> {
    let s = val.trim();
    if s.is_empty() {
        return Ok("default".to_string());
    }
    if s.len() > 64
        || !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(ExposureError::Config(format!(
            "invalid DNS resolution line code: '{val}'"
        )));
    }
    Ok(s.to_string())
}

fn validate_exposure_dns_record(record_type: &str, value: &str) -> Result<(String, String)> {
    let rt = record_type.trim().to_ascii_uppercase();
    let v = value.trim();
    match rt.as_str() {
        "A" => {
            let ip: Ipv4Addr = v.parse().map_err(|_| {
                ExposureError::Config(format!("invalid IPv4 address '{value}' for A record"))
            })?;
            if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
                return Err(ExposureError::Config(format!(
                    "disallowed IPv4 address '{value}'"
                )));
            }
            Ok(("A".into(), ip.to_string()))
        }
        "AAAA" => {
            let ip: Ipv6Addr = v.parse().map_err(|_| {
                ExposureError::Config(format!("invalid IPv6 address '{value}' for AAAA record"))
            })?;
            if ip.is_unspecified() || ip.is_multicast() {
                return Err(ExposureError::Config(format!(
                    "disallowed IPv6 address '{value}'"
                )));
            }
            Ok(("AAAA".into(), ip.to_string()))
        }
        "CNAME" => {
            let clean = v.trim_end_matches('.');
            if clean.is_empty() || clean.contains('*') {
                return Err(ExposureError::Config(format!(
                    "invalid CNAME target '{value}'"
                )));
            }
            validate_dns_domain(clean)?;
            Ok(("CNAME".into(), clean.to_string()))
        }
        _ => Err(ExposureError::AccessDenied(format!(
            "unsupported DNS record type '{record_type}': Exposure only manages A, AAAA, and CNAME records"
        ))),
    }
}

fn effective_sync_line_entries(spec: &DnsSyncRecordSpec) -> Vec<DnsLineSyncEntry> {
    if !spec.line_entries.is_empty() {
        return spec.line_entries.clone();
    }
    vec![DnsLineSyncEntry {
        line: "default".into(),
        ipv4s: spec.ipv4s.clone(),
        ipv6s: spec.ipv6s.clone(),
        cnames: Vec::new(),
        ttl: spec.ttl,
        proxied: spec.proxied,
    }]
}

fn aliyun_endpoint_host(region_id: Option<&str>) -> Result<String> {
    let Some(raw) = region_id else {
        return Ok("alidns.aliyuncs.com".to_string());
    };
    let r = raw.trim();
    if r.is_empty() {
        return Ok("alidns.aliyuncs.com".to_string());
    }
    if r.len() > 64
        || r.starts_with('-')
        || r.ends_with('-')
        || !r
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(ExposureError::Config(format!(
            "invalid Aliyun DNS region_id: '{raw}'"
        )));
    }
    Ok(format!("alidns.{r}.aliyuncs.com"))
}

/// RFC 3986 percent-encoding required by Alibaba Cloud OpenAPI V3 (ACS3-HMAC-SHA256).
fn aliyun_percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        if matches!(
            byte,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~'
        ) {
            out.push(*byte as char);
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

fn build_aliyun_canonical_query(params: &[(&str, &str)]) -> String {
    let mut pairs: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (aliyun_percent_encode(k), aliyun_percent_encode(v)))
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

struct AliyunV3Auth {
    date: String,
    nonce: String,
    authorization: String,
}

fn sign_aliyun_v3_post(
    host: &str,
    action: &str,
    canonical_query: &str,
    access_key_id: &str,
    access_key_secret: &str,
    date: String,
    nonce: String,
) -> Result<AliyunV3Auth> {
    let canonical_headers = format!(
        "host:{host}\n\
         x-acs-action:{action}\n\
         x-acs-content-sha256:{EMPTY_BODY_SHA256}\n\
         x-acs-date:{date}\n\
         x-acs-signature-nonce:{nonce}\n\
         x-acs-version:{ALIDNS_API_VERSION}\n"
    );
    let signed_headers =
        "host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version";
    let canonical_request = format!(
        "POST\n/\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{EMPTY_BODY_SHA256}"
    );
    let hashed_canonical = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign = format!("ACS3-HMAC-SHA256\n{hashed_canonical}");

    let mut mac = Hmac::<Sha256>::new_from_slice(access_key_secret.as_bytes())
        .map_err(|e| ExposureError::Config(format!("aliyun hmac init: {e}")))?;
    mac.update(string_to_sign.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    let authorization = format!(
        "ACS3-HMAC-SHA256 Credential={access_key_id},SignedHeaders={signed_headers},Signature={signature}"
    );
    Ok(AliyunV3Auth {
        date,
        nonce,
        authorization,
    })
}

fn split_domain_with_zone_mode(
    domain: &str,
    zone: &str,
    for_acme_txt: bool,
) -> Result<(String, String)> {
    let raw = domain.trim().trim_end_matches('.');
    let is_wild = raw.starts_with("*.");
    let base = raw.strip_prefix("*.").unwrap_or(raw);
    if base.is_empty() {
        return Err(ExposureError::Config(format!("invalid domain '{domain}'")));
    }
    validate_dns_domain(base)?;

    let z = zone.trim().trim_end_matches('.');
    if z.is_empty() || z.contains('*') {
        return Err(ExposureError::Config(format!(
            "invalid root_domain '{zone}'"
        )));
    }
    validate_dns_domain(z)?;

    let base_lower = base.to_ascii_lowercase();
    let z_lower = z.to_ascii_lowercase();
    if base_lower == z_lower {
        let rr = if for_acme_txt {
            "_acme-challenge".to_string()
        } else if is_wild {
            "*".to_string()
        } else {
            "@".to_string()
        };
        return Ok((z.to_string(), rr));
    }
    let suffix = format!(".{z_lower}");
    if let Some(sub_len) = base_lower.strip_suffix(&suffix).map(|s| s.len()) {
        let sub = &base[..sub_len];
        let rr = if for_acme_txt {
            format!("_acme-challenge.{sub}")
        } else if is_wild {
            format!("*.{sub}")
        } else {
            sub.to_string()
        };
        return Ok((z.to_string(), rr));
    }
    Err(ExposureError::Config(format!(
        "domain '{domain}' does not belong to configured root_domain '{zone}'"
    )))
}

fn cloudflare_zone_candidates(domain: &str, root_domain: Option<&str>) -> Result<Vec<String>> {
    let mut out = Vec::new();
    if let Some(rd) = root_domain.map(str::trim).filter(|s| !s.is_empty()) {
        let clean_rd = rd.trim_end_matches('.');
        if clean_rd.contains('*') {
            return Err(ExposureError::Config(format!("invalid root_domain '{rd}'")));
        }
        validate_dns_domain(clean_rd)?;
        out.push(clean_rd.to_string());
    }

    let base = domain.trim().trim_start_matches("*.").trim_end_matches('.');
    if base.is_empty() {
        return Err(ExposureError::Config(format!("invalid domain '{domain}'")));
    }
    validate_dns_domain(base)?;

    let labels: Vec<&str> = base.split('.').collect();
    let max_start = if labels.len() >= 2 {
        labels.len() - 1
    } else {
        labels.len()
    };
    for i in 0..max_start {
        let cand = labels[i..].join(".");
        if !out
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&cand))
        {
            out.push(cand);
        }
    }
    Ok(out)
}

async fn build_ssrf_pinned_webhook_client(raw_url: &str) -> Result<reqwest::Client> {
    let url = reqwest::Url::parse(raw_url)
        .map_err(|e| ExposureError::Config(format!("invalid webhook URL '{raw_url}': {e}")))?;
    if url.scheme() != "https" {
        return Err(ExposureError::Config(format!(
            "webhook URL must use https:// (got '{}')",
            url.scheme()
        )));
    }
    let host = url
        .host_str()
        .ok_or_else(|| ExposureError::Config("webhook URL missing host".into()))?;
    let port = url.port_or_known_default().unwrap_or(443);
    let host_owned = host.to_string();
    let addrs: Vec<SocketAddr> = tokio::task::spawn_blocking(move || {
        (host_owned.as_str(), port)
            .to_socket_addrs()
            .map(|iter| iter.collect())
    })
    .await
    .map_err(|e| ExposureError::Link(format!("webhook DNS resolve join: {e}")))?
    .map_err(|e| ExposureError::Link(format!("webhook DNS resolve failed for '{host}': {e}")))?;

    if addrs.is_empty() {
        return Err(ExposureError::Config(format!(
            "webhook host '{host}' resolved to no addresses"
        )));
    }
    for addr in &addrs {
        if !is_public_routable_ip(addr.ip()) {
            return Err(ExposureError::AccessDenied(format!(
                "webhook target '{host}' resolved to forbidden private/internal IP {}",
                addr.ip()
            )));
        }
    }
    reqwest::Client::builder()
        .timeout(WEBHOOK_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(host, &addrs)
        .build()
        .map_err(|e| ExposureError::Link(format!("build webhook http client: {e}")))
}

fn ensure_non_acme_sync_domain(domain: &str) -> Result<String> {
    let clean_dom = domain.trim().trim_end_matches('.');
    let lower = clean_dom.to_ascii_lowercase();
    if clean_dom == "*"
        || lower == "_acme-challenge"
        || lower.starts_with("_acme-challenge.")
        || lower.contains("._acme-challenge.")
    {
        return Err(ExposureError::AccessDenied(format!(
            "domain '{domain}' cannot be modified via Exposure DNS sync or editor"
        )));
    }
    Ok(clean_dom.to_string())
}

fn read_der_tlv(data: &[u8], offset: usize) -> Option<(u8, &[u8], usize)> {
    let tag = *data.get(offset)?;
    let len_byte = *data.get(offset + 1)?;
    let (len, hdr) = if len_byte & 0x80 == 0 {
        (len_byte as usize, 2usize)
    } else {
        let num_octets = (len_byte & 0x7f) as usize;
        if num_octets == 0 || num_octets > 4 || offset + 2 + num_octets > data.len() {
            return None;
        }
        let mut v = 0usize;
        for &b in &data[offset + 2..offset + 2 + num_octets] {
            v = (v << 8) | (b as usize);
        }
        (v, 2 + num_octets)
    };
    let end = offset.checked_add(hdr)?.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some((tag, &data[offset + hdr..end], end))
}

fn parse_asn1_time_unix(tag: u8, bytes: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(bytes).ok()?;
    let (year, rest) = match tag {
        0x17 if s.len() == 13 && s.ends_with('Z') => {
            let yy: i32 = s.get(0..2)?.parse().ok()?;
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            (year, s.get(2..12)?)
        }
        0x18 if s.len() == 15 && s.ends_with('Z') => {
            let year: i32 = s.get(0..4)?.parse().ok()?;
            (year, s.get(4..14)?)
        }
        _ => return None,
    };
    let month: u32 = rest.get(0..2)?.parse().ok()?;
    let day: u32 = rest.get(2..4)?.parse().ok()?;
    let hour: u32 = rest.get(4..6)?.parse().ok()?;
    let min: u32 = rest.get(6..8)?.parse().ok()?;
    let sec: u32 = rest.get(8..10)?.parse().ok()?;
    let dt = NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(hour, min, sec)?;
    Some(dt.and_utc().timestamp())
}

/// Parse X.509 leaf certificate `Validity.notAfter` timestamp directly from DER without external subprocesses.
pub(crate) fn parse_x509_not_after_unix(cert_pem: &str) -> Option<i64> {
    let mut reader = BufReader::new(cert_pem.as_bytes());
    let cert_der = rustls_pemfile::certs(&mut reader).next()?.ok()?;
    let (cert_tag, cert_val, _) = read_der_tlv(cert_der.as_ref(), 0)?;
    if cert_tag != 0x30 {
        return None;
    }
    let (tbs_tag, tbs_val, _) = read_der_tlv(cert_val, 0)?;
    if tbs_tag != 0x30 {
        return None;
    }
    let mut off = 0usize;
    let (tag0, _, next0) = read_der_tlv(tbs_val, off)?;
    if tag0 == 0xA0 {
        off = next0;
    }
    // serialNumber (INTEGER 0x02), signature (SEQUENCE 0x30), issuer (SEQUENCE 0x30)
    let (t_ser, _, n_ser) = read_der_tlv(tbs_val, off)?;
    if t_ser != 0x02 {
        return None;
    }
    let (t_sig, _, n_sig) = read_der_tlv(tbs_val, n_ser)?;
    if t_sig != 0x30 {
        return None;
    }
    let (t_iss, _, n_iss) = read_der_tlv(tbs_val, n_sig)?;
    if t_iss != 0x30 {
        return None;
    }
    let (t_val, val_bytes, _) = read_der_tlv(tbs_val, n_iss)?;
    if t_val != 0x30 {
        return None;
    }
    let (_, _, not_after_off) = read_der_tlv(val_bytes, 0)?;
    let (na_tag, na_bytes, _) = read_der_tlv(val_bytes, not_after_off)?;
    parse_asn1_time_unix(na_tag, na_bytes)
}

/// Maintainer Mode Service (DESIGN.md §4, §12, §13):
/// - Embedded SQLite WAL observability store (`maintainer-{tag}.db`): stores access logs,
///   per-minute traffic/latency summaries, visitor fingerprints, persistent Evilpot sessions/events,
///   AutoBan history, and cluster alerts with configurable per-type retention & size caps.
/// - ACME DNS01 certificate lifecycle (Cloudflare, Aliyun DNS, HTTPS-only SSRF-checked Webhook, timeout-bounded Exec Hook),
///   signing bundles per target node with Maintainer's Ed25519 key and distributing along Hop tables.
pub struct MaintainerService {
    node_tag: String,
    cfg: Arc<RwLock<MaintainerConfig>>,
    db: Arc<RwLock<Arc<MaintainerDb>>>,
    db_dir: Arc<RwLock<String>>,
    cert_statuses: Arc<Mutex<HashMap<String, CertStatusInfo>>>,
    last_merge_latency_ms: Arc<Mutex<f64>>,
    http_client: reqwest::Client,
    shutdown_tx: watch::Sender<bool>,
}

impl MaintainerService {
    pub fn new(node_tag: impl Into<String>, cfg: MaintainerConfig) -> Result<Arc<Self>> {
        let tag = node_tag.into();
        let db_dir = cfg.logger.segment.dir.clone();
        let db = MaintainerDb::open(&db_dir, &tag)?;

        let mut cert_map = HashMap::new();
        for order in &cfg.acme.orders {
            cert_map.insert(
                order.domain.clone(),
                CertStatusInfo {
                    domain: order.domain.clone(),
                    targets: order.target_nodes.clone(),
                    expires_at: None,
                    last_renewed: None,
                    status: "pending".into(),
                },
            );
        }
        let http_client = reqwest::Client::builder()
            .timeout(WEBHOOK_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| ExposureError::Config(format!("build maintainer http client: {e}")))?;
        let (shutdown_tx, _) = watch::channel(false);

        Ok(Arc::new(Self {
            node_tag: tag,
            cfg: Arc::new(RwLock::new(cfg)),
            db: Arc::new(RwLock::new(db)),
            db_dir: Arc::new(RwLock::new(db_dir)),
            cert_statuses: Arc::new(Mutex::new(cert_map)),
            last_merge_latency_ms: Arc::new(Mutex::new(0.0)),
            http_client,
            shutdown_tx,
        }))
    }

    pub fn stop_background_tasks(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    async fn current_db(&self) -> Arc<MaintainerDb> {
        Arc::clone(&*self.db.read().await)
    }

    pub async fn update_config(&self, cfg: MaintainerConfig) -> Result<()> {
        let new_dir = cfg.logger.segment.dir.clone();
        let dir_changed = { *self.db_dir.read().await != new_dir };
        if dir_changed {
            let old_db = self.current_db().await;
            let _ = old_db.checkpoint_wal().await;
            let new_db = MaintainerDb::open(&new_dir, &self.node_tag)?;
            *self.db.write().await = new_db;
            *self.db_dir.write().await = new_dir;
        }

        {
            let mut cs = self.cert_statuses.lock().await;
            let active_domains: HashSet<&str> =
                cfg.acme.orders.iter().map(|o| o.domain.as_str()).collect();
            cs.retain(|dom, _| active_domains.contains(dom.as_str()));
            for order in &cfg.acme.orders {
                cs.entry(order.domain.clone())
                    .and_modify(|existing| {
                        existing.targets = order.target_nodes.clone();
                    })
                    .or_insert_with(|| CertStatusInfo {
                        domain: order.domain.clone(),
                        targets: order.target_nodes.clone(),
                        expires_at: None,
                        last_renewed: None,
                        status: "pending".into(),
                    });
            }
        }
        *self.cfg.write().await = cfg;
        Ok(())
    }

    /// Merge incoming LogBatch from an authenticated Node into Maintainer's SQLite WAL database.
    #[allow(clippy::too_many_arguments)]
    pub async fn ingest_log_batch(
        &self,
        from_node: &str,
        records: Vec<SessionSummary>,
        summaries: Vec<MinuteSummary>,
        fingerprints: Vec<FingerprintObservation>,
        evilpot_sessions: Vec<EvilpotSessionInfo>,
        evilpot_events: Vec<EvilpotEventInfo>,
        ban_records: Vec<BanRecord>,
        alerts: Vec<AlertRecord>,
    ) -> usize {
        let start = Instant::now();
        let (store_raw_ip, retention) = {
            let c = self.cfg.read().await;
            (c.logger.store_raw_ip, c.logger.retention.clone())
        };
        let db = self.current_db().await;
        let accepted = match db
            .ingest_batch(
                from_node,
                store_raw_ip,
                &retention,
                records,
                summaries,
                fingerprints,
                evilpot_sessions,
                evilpot_events,
                ban_records,
                alerts,
            )
            .await
        {
            Ok(n) => n,
            Err(e) => {
                warn!(from = %from_node, error = %e, "maintainer sqlite batch ingest failed");
                0
            }
        };
        *self.last_merge_latency_ms.lock().await = start.elapsed().as_secs_f64() * 1000.0;
        accepted
    }

    pub async fn flush_segments(&self) -> Result<()> {
        let db = self.current_db().await;
        db.checkpoint_wal().await
    }

    /// Execute a time-windowed, paginated query or maintenance action against Maintainer's SQLite store.
    pub async fn handle_query(&self, query: MaintainerQuery) -> Result<serde_json::Value> {
        let db = self.current_db().await;
        let retention = self.cfg.read().await.logger.retention.clone();
        match query {
            MaintainerQuery::Overview { from_ms, to_ms } => db.query_overview(from_ms, to_ms).await,
            MaintainerQuery::Telemetry {
                from_ms,
                to_ms,
                node,
                service,
                bucket_offset,
                bucket_limit,
            } => {
                db.query_telemetry(from_ms, to_ms, node, service, bucket_offset, bucket_limit)
                    .await
            }
            MaintainerQuery::AccessLogs {
                from_ms,
                to_ms,
                node,
                service,
                role,
                method,
                action,
                status,
                host,
                ip,
                ip_hmac,
                country,
                ray_id,
                q,
                q_ip_hmac,
                offset,
                limit,
            } => {
                db.query_access_logs(
                    from_ms, to_ms, node, service, role, method, action, status, host, ip, ip_hmac,
                    country, ray_id, q, q_ip_hmac, offset, limit,
                )
                .await
            }
            MaintainerQuery::Fingerprints {
                from_ms,
                to_ms,
                node,
                service,
                country,
                verified,
                risk,
                ip,
                ip_hmac,
                fp,
                q,
                q_ip_hmac,
                offset,
                limit,
            } => {
                db.query_fingerprints(
                    from_ms, to_ms, node, service, country, verified, risk, ip, ip_hmac, fp, q,
                    q_ip_hmac, offset, limit,
                )
                .await
            }
            MaintainerQuery::Evilpot {
                from_ms,
                to_ms,
                node,
                status,
                ip,
                q,
                sessions_offset,
                sessions_limit,
                events_offset,
                events_limit,
            } => {
                db.query_evilpot(
                    from_ms,
                    to_ms,
                    node,
                    status,
                    ip,
                    q,
                    sessions_offset,
                    sessions_limit,
                    events_offset,
                    events_limit,
                )
                .await
            }
            MaintainerQuery::Bans {
                from_ms,
                to_ms,
                node,
                status,
                kind,
                target,
                q,
                offset,
                limit,
            } => {
                db.query_bans(from_ms, to_ms, node, status, kind, target, q, offset, limit)
                    .await
            }
            MaintainerQuery::Alerts {
                from_ms,
                to_ms,
                node,
                severity,
                q,
                offset,
                limit,
            } => {
                db.query_alerts(from_ms, to_ms, node, severity, q, offset, limit)
                    .await
            }
            MaintainerQuery::StorageStats => {
                let st = db.storage_stats(retention.max_db_bytes).await?;
                Ok(serde_json::to_value(st).unwrap_or_default())
            }
            MaintainerQuery::RunCleanup => {
                let rep = db.run_cleanup(&retention).await?;
                Ok(serde_json::to_value(rep).unwrap_or_default())
            }
            MaintainerQuery::MarkUnbanned {
                node_tag,
                ban_kind,
                target,
                actor,
                unbanned_at_unix,
            } => {
                let updated = db
                    .mark_unbanned(node_tag, ban_kind, target, actor, unbanned_at_unix)
                    .await?;
                Ok(serde_json::json!({ "updated": updated }))
            }
        }
    }

    /// Build compact status & certificate snapshot for Control's periodic background pull.
    pub async fn build_telemetry_snapshot(
        &self,
        since_minute: Option<i64>,
    ) -> MaintainerTelemetrySnapshot {
        let db = self.current_db().await;
        let max_db_bytes = self.cfg.read().await.logger.retention.max_db_bytes;
        let effective_since = since_minute.or_else(|| Some(Utc::now().timestamp() - 6 * 3600));
        let summaries = db
            .snapshot_summaries(effective_since, 1000)
            .await
            .unwrap_or_default();
        let alerts = db.recent_alerts(50).await.unwrap_or_default();
        let storage_stats = db.storage_stats(max_db_bytes).await.ok();
        // The snapshot still carries recent logs & fingerprints for Control's cached telemetry
        // (and protocol compatibility), now sourced from the SQLite WAL instead of the old
        // in-memory ring buffers / dropped JSONL segment files.
        let recent_logs = db
            .query_access_logs(
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, 0, 100,
            )
            .await
            .ok()
            .and_then(|v| v.get("items").cloned())
            .and_then(|v| serde_json::from_value::<Vec<SessionSummary>>(v).ok())
            .unwrap_or_default();
        let fingerprints = db
            .query_fingerprints(
                None, None, None, None, None, None, None, None, None, None, None, None, 0, 200,
            )
            .await
            .ok()
            .and_then(|v| v.get("items").cloned())
            .and_then(|v| serde_json::from_value::<Vec<FingerprintObservation>>(v).ok())
            .unwrap_or_default();
        let certificates = self.cert_statuses.lock().await.values().cloned().collect();
        let merge_latency_ms = *self.last_merge_latency_ms.lock().await;

        MaintainerTelemetrySnapshot {
            maintainer_tag: self.node_tag.clone(),
            summaries,
            fingerprints,
            recent_logs,
            certificates,
            segment_backlog: 0,
            merge_latency_ms,
            alerts,
            storage_stats,
        }
    }

    pub async fn record_alert(&self, severity: &str, message: impl Into<String>) {
        let db = self.current_db().await;
        if let Err(e) = db.record_alert(severity, message.into()).await {
            warn!(error = %e, "failed to record maintainer alert");
        }
    }

    async fn call_alidns_api(
        &self,
        base_url: &str,
        access_key_id: &str,
        access_key_secret: &str,
        action: &str,
        params: &[(&str, &str)],
    ) -> Result<serde_json::Value> {
        let (ak, sk) = validate_aliyun_credentials(access_key_id, access_key_secret)?;
        let parsed = reqwest::Url::parse(base_url).map_err(|e| {
            ExposureError::Config(format!("invalid Aliyun DNS endpoint '{base_url}': {e}"))
        })?;
        let host_name = parsed
            .host_str()
            .ok_or_else(|| ExposureError::Config("Aliyun DNS endpoint missing host".into()))?;
        let host_header = match parsed.port() {
            Some(p) => format!("{host_name}:{p}"),
            None => host_name.to_string(),
        };

        let canonical_query = build_aliyun_canonical_query(params);
        let date = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let nonce = Uuid::new_v4().to_string();
        let auth =
            sign_aliyun_v3_post(&host_header, action, &canonical_query, ak, sk, date, nonce)?;

        let trimmed_base = base_url.trim_end_matches('/');
        let url = if canonical_query.is_empty() {
            format!("{trimmed_base}/")
        } else {
            format!("{trimmed_base}/?{canonical_query}")
        };

        let resp = self
            .http_client
            .post(&url)
            .header(reqwest::header::HOST, &host_header)
            .header("x-acs-action", action)
            .header("x-acs-version", ALIDNS_API_VERSION)
            .header("x-acs-date", &auth.date)
            .header("x-acs-signature-nonce", &auth.nonce)
            .header("x-acs-content-sha256", EMPTY_BODY_SHA256)
            .header(reqwest::header::AUTHORIZATION, &auth.authorization)
            .send()
            .await
            .map_err(|e| ExposureError::Link(format!("aliyun dns01 {action}: {e}")))?;

        let status = resp.status();
        let body_bytes = resp
            .bytes()
            .await
            .map_err(|e| ExposureError::Protocol(format!("aliyun dns01 {action} body: {e}")))?;
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).map_err(|e| {
            ExposureError::Protocol(format!(
                "aliyun dns01 {action} json ({status}): {e}: {}",
                String::from_utf8_lossy(&body_bytes)
            ))
        })?;

        if !status.is_success() || body.get("Code").and_then(|v| v.as_str()).is_some() {
            let code = body["Code"].as_str().unwrap_or("UnknownError");
            let msg = body["Message"].as_str().unwrap_or("request failed");
            return Err(ExposureError::Protocol(format!(
                "aliyun dns01 {action} failed ({status}, {code}): {msg}"
            )));
        }
        Ok(body)
    }

    async fn resolve_aliyun_domain_and_rr(
        &self,
        base_url: &str,
        access_key_id: &str,
        access_key_secret: &str,
        configured_root_domain: Option<&str>,
        domain: &str,
        for_acme_txt: bool,
    ) -> Result<(String, String)> {
        if let Some(zone) = configured_root_domain
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return split_domain_with_zone_mode(domain, zone, for_acme_txt);
        }

        let raw = domain.trim().trim_end_matches('.');
        let is_wild = raw.starts_with("*.");
        let base = raw.strip_prefix("*.").unwrap_or(raw);
        if base.is_empty() {
            return Err(ExposureError::Config(format!("invalid domain '{domain}'")));
        }
        validate_dns_domain(base)?;

        let body = self
            .call_alidns_api(
                base_url,
                access_key_id,
                access_key_secret,
                "GetMainDomainName",
                &[("InputString", base)],
            )
            .await?;

        let domain_name = body["DomainName"]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                ExposureError::Protocol(format!(
                    "aliyun GetMainDomainName missing DomainName for '{domain}': {body}"
                ))
            })?
            .to_string();
        let rr_prefix = body["RR"].as_str().map(str::trim).unwrap_or("");
        let rr = if for_acme_txt {
            if rr_prefix.is_empty() || rr_prefix == "@" {
                "_acme-challenge".to_string()
            } else {
                format!("_acme-challenge.{rr_prefix}")
            }
        } else if is_wild {
            if rr_prefix.is_empty() || rr_prefix == "@" {
                "*".to_string()
            } else {
                format!("*.{rr_prefix}")
            }
        } else if rr_prefix.is_empty() {
            "@".to_string()
        } else {
            rr_prefix.to_string()
        };
        Ok((domain_name, rr))
    }

    async fn aliyun_present_with_base(
        &self,
        base_url: &str,
        access_key_id: &str,
        access_key_secret: &str,
        root_domain_override: Option<&str>,
        domain: &str,
        txt_value: &str,
    ) -> Result<Option<String>> {
        let (root_domain, rr) = self
            .resolve_aliyun_domain_and_rr(
                base_url,
                access_key_id,
                access_key_secret,
                root_domain_override,
                domain,
                true,
            )
            .await?;

        let body = self
            .call_alidns_api(
                base_url,
                access_key_id,
                access_key_secret,
                "AddDomainRecord",
                &[
                    ("DomainName", &root_domain),
                    ("RR", &rr),
                    ("Type", "TXT"),
                    ("Value", txt_value),
                    ("TTL", "600"),
                ],
            )
            .await?;

        let rec_id = body["RecordId"]
            .as_str()
            .map(|s| s.to_string())
            .or_else(|| body["RecordId"].as_u64().map(|n| n.to_string()));
        if let Some(ref id) = rec_id {
            validate_aliyun_record_id(id)?;
        }
        Ok(rec_id)
    }

    async fn aliyun_cleanup_with_base(
        &self,
        base_url: &str,
        access_key_id: &str,
        access_key_secret: &str,
        root_domain_override: Option<&str>,
        domain: &str,
        txt_value: &str,
        record_id: Option<&str>,
    ) -> Result<()> {
        validate_aliyun_credentials(access_key_id, access_key_secret)?;
        if let Some(id) = record_id {
            validate_aliyun_record_id(id)?;
            if let Err(e) = self
                .call_alidns_api(
                    base_url,
                    access_key_id,
                    access_key_secret,
                    "DeleteDomainRecord",
                    &[("RecordId", id)],
                )
                .await
            {
                warn!(record_id = %id, error = %e, "aliyun dns01 DeleteDomainRecord failed");
            }
            return Ok(());
        }

        if let Ok((root_domain, rr)) = self
            .resolve_aliyun_domain_and_rr(
                base_url,
                access_key_id,
                access_key_secret,
                root_domain_override,
                domain,
                true,
            )
            .await
        {
            if let Ok(body) = self
                .call_alidns_api(
                    base_url,
                    access_key_id,
                    access_key_secret,
                    "DescribeDomainRecords",
                    &[
                        ("DomainName", &root_domain),
                        ("RRKeyWord", &rr),
                        ("Type", "TXT"),
                        ("ValueKeyWord", txt_value),
                        ("PageSize", "100"),
                    ],
                )
                .await
            {
                if let Some(records) = body["DomainRecords"]["Record"].as_array() {
                    for rec in records {
                        if rec["RR"].as_str() == Some(rr.as_str())
                            && rec["Type"].as_str() == Some("TXT")
                            && rec["Value"].as_str() == Some(txt_value)
                        {
                            if let Some(id) = rec["RecordId"]
                                .as_str()
                                .map(str::to_string)
                                .or_else(|| rec["RecordId"].as_u64().map(|n| n.to_string()))
                            {
                                if validate_aliyun_record_id(&id).is_ok() {
                                    let _ = self
                                        .call_alidns_api(
                                            base_url,
                                            access_key_id,
                                            access_key_secret,
                                            "DeleteDomainRecord",
                                            &[("RecordId", &id)],
                                        )
                                        .await;
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn aliyun_sync_records_with_base(
        &self,
        base_url: &str,
        access_key_id: &str,
        access_key_secret: &str,
        root_domain_override: Option<&str>,
        spec: &DnsSyncRecordSpec,
    ) -> Result<DnsSyncDomainResult> {
        let (root_domain, rr) = self
            .resolve_aliyun_domain_and_rr(
                base_url,
                access_key_id,
                access_key_secret,
                root_domain_override,
                &spec.domain,
                false,
            )
            .await?;

        let default_ttl = spec.ttl.unwrap_or(600).max(1);
        let line_entries = effective_sync_line_entries(spec);

        // Paginate DescribeDomainRecords to capture all existing Exposure-managed (A / AAAA / CNAME) records for this RR
        let mut existing: Vec<serde_json::Value> = Vec::new();
        let mut page = 1u32;
        loop {
            let page_str = page.to_string();
            let body = self
                .call_alidns_api(
                    base_url,
                    access_key_id,
                    access_key_secret,
                    "DescribeDomainRecords",
                    &[
                        ("DomainName", &root_domain),
                        ("RRKeyWord", &rr),
                        ("PageNumber", &page_str),
                        ("PageSize", "100"),
                    ],
                )
                .await?;
            let batch = body["DomainRecords"]["Record"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let total_count = body["TotalCount"].as_u64().unwrap_or(0);
            let fetched = batch.len();
            for rec in batch {
                let rec_rr = rec["RR"].as_str().unwrap_or("");
                let rec_type = rec["Type"].as_str().unwrap_or("");
                if rec_rr.eq_ignore_ascii_case(&rr) && matches!(rec_type, "A" | "AAAA" | "CNAME") {
                    existing.push(rec);
                }
            }
            if fetched < 100 || (page as u64) * 100 >= total_count {
                break;
            }
            page += 1;
        }

        let mut created = 0usize;
        let mut updated = 0usize;
        let mut deleted = 0usize;
        let mut unchanged = 0usize;
        let mut to_delete: Vec<String> = Vec::new();

        // Group reconciliation strictly per managed Line so unmanaged lines & TXT/MX records are never touched.
        for entry in &line_entries {
            let line = validate_dns_line_code(&entry.line)?;
            let ttl = entry.ttl.unwrap_or(default_ttl).max(1);
            let ttl_str = ttl.to_string();

            let line_records: Vec<&serde_json::Value> = existing
                .iter()
                .filter(|r| {
                    r["Line"]
                        .as_str()
                        .unwrap_or("default")
                        .eq_ignore_ascii_case(&line)
                })
                .collect();

            for (rtype, desired_list) in [
                ("A", &entry.ipv4s),
                ("AAAA", &entry.ipv6s),
                ("CNAME", &entry.cnames),
            ] {
                let desired: BTreeSet<String> = desired_list
                    .iter()
                    .map(|s| {
                        validate_exposure_dns_record(rtype, s)
                            .map(|(_, norm)| norm)
                            .unwrap_or_else(|_| {
                                if rtype == "CNAME" {
                                    s.trim().trim_end_matches('.').to_string()
                                } else {
                                    s.trim().to_string()
                                }
                            })
                    })
                    .filter(|s| !s.is_empty())
                    .collect();
                let mut matched_vals: HashSet<String> = HashSet::new();

                for rec in line_records
                    .iter()
                    .copied()
                    .filter(|r| r["Type"].as_str() == Some(rtype))
                {
                    let raw_val = rec["Value"].as_str().unwrap_or("");
                    let norm_val = validate_exposure_dns_record(rtype, raw_val)
                        .map(|(_, norm)| norm)
                        .unwrap_or_else(|_| {
                            if rtype == "CNAME" {
                                raw_val.trim().trim_end_matches('.').to_string()
                            } else {
                                raw_val.trim().to_string()
                            }
                        });
                    let Some(rec_id) = rec["RecordId"]
                        .as_str()
                        .map(str::to_string)
                        .or_else(|| rec["RecordId"].as_u64().map(|n| n.to_string()))
                    else {
                        continue;
                    };
                    validate_aliyun_record_id(&rec_id)?;

                    if desired.contains(&norm_val) && matched_vals.insert(norm_val.clone()) {
                        let rec_disabled = rec["Status"]
                            .as_str()
                            .map(|s| s.eq_ignore_ascii_case("DISABLE"))
                            .unwrap_or(false);
                        let mut changed = false;
                        if rec["TTL"].as_u64() != Some(ttl as u64) {
                            self.call_alidns_api(
                                base_url,
                                access_key_id,
                                access_key_secret,
                                "UpdateDomainRecord",
                                &[
                                    ("RecordId", &rec_id),
                                    ("RR", &rr),
                                    ("Type", rtype),
                                    ("Value", &norm_val),
                                    ("Line", &line),
                                    ("TTL", &ttl_str),
                                ],
                            )
                            .await?;
                            changed = true;
                        }
                        if rec_disabled {
                            self.call_alidns_api(
                                base_url,
                                access_key_id,
                                access_key_secret,
                                "SetDomainRecordStatus",
                                &[("RecordId", &rec_id), ("Status", "Enable")],
                            )
                            .await?;
                            changed = true;
                        }
                        if changed {
                            updated += 1;
                        } else {
                            unchanged += 1;
                        }
                    } else {
                        to_delete.push(rec_id);
                    }
                }

                // Create missing records before deleting stale ones to avoid resolution gaps
                for val in &desired {
                    if !matched_vals.contains(val) {
                        self.call_alidns_api(
                            base_url,
                            access_key_id,
                            access_key_secret,
                            "AddDomainRecord",
                            &[
                                ("DomainName", &root_domain),
                                ("RR", &rr),
                                ("Type", rtype),
                                ("Value", val),
                                ("Line", &line),
                                ("TTL", &ttl_str),
                            ],
                        )
                        .await?;
                        created += 1;
                    }
                }
            }
        }

        for rec_id in to_delete {
            self.call_alidns_api(
                base_url,
                access_key_id,
                access_key_secret,
                "DeleteDomainRecord",
                &[("RecordId", &rec_id)],
            )
            .await?;
            deleted += 1;
        }

        Ok(DnsSyncDomainResult {
            domain: spec.domain.clone(),
            ok: true,
            created,
            updated,
            deleted,
            unchanged,
            error: None,
        })
    }

    async fn aliyun_manage_with_base(
        &self,
        base_url: &str,
        access_key_id: &str,
        access_key_secret: &str,
        root_domain_override: Option<&str>,
        op: &DnsManageOp,
    ) -> Result<(
        DnsProviderCapabilities,
        Vec<DnsSupportLine>,
        Vec<DnsRemoteRecord>,
        Option<String>,
    )> {
        let caps = DnsProviderCapabilities {
            supports_lines: true,
            supports_proxied: false,
            supports_status_toggle: true,
            supports_remote_edit: true,
        };
        let domain = match op {
            DnsManageOp::Inspect { domain, .. }
            | DnsManageOp::Create { domain, .. }
            | DnsManageOp::Update { domain, .. }
            | DnsManageOp::SetStatus { domain, .. }
            | DnsManageOp::Delete { domain, .. } => domain.as_str(),
        };
        let (root_domain, rr) = self
            .resolve_aliyun_domain_and_rr(
                base_url,
                access_key_id,
                access_key_secret,
                root_domain_override,
                domain,
                false,
            )
            .await?;
        let fqdn = domain.trim().trim_end_matches('.').to_string();

        match op {
            DnsManageOp::Inspect { include_lines, .. } => {
                let mut records = Vec::new();
                let mut page = 1u32;
                loop {
                    let page_str = page.to_string();
                    let body = self
                        .call_alidns_api(
                            base_url,
                            access_key_id,
                            access_key_secret,
                            "DescribeDomainRecords",
                            &[
                                ("DomainName", &root_domain),
                                ("RRKeyWord", &rr),
                                ("PageNumber", &page_str),
                                ("PageSize", "100"),
                            ],
                        )
                        .await?;
                    let batch = body["DomainRecords"]["Record"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default();
                    let total_count = body["TotalCount"].as_u64().unwrap_or(0);
                    let fetched = batch.len();
                    for rec in batch {
                        let rec_rr = rec["RR"].as_str().unwrap_or("");
                        let rec_type = rec["Type"].as_str().unwrap_or("");
                        if !rec_rr.eq_ignore_ascii_case(&rr)
                            || !matches!(rec_type, "A" | "AAAA" | "CNAME")
                        {
                            continue;
                        }
                        let Some(rec_id) = rec["RecordId"]
                            .as_str()
                            .map(str::to_string)
                            .or_else(|| rec["RecordId"].as_u64().map(|n| n.to_string()))
                        else {
                            continue;
                        };
                        records.push(DnsRemoteRecord {
                            record_id: rec_id,
                            rr: rec_rr.to_string(),
                            fqdn: fqdn.clone(),
                            record_type: rec_type.to_string(),
                            value: rec["Value"].as_str().unwrap_or("").to_string(),
                            line: rec["Line"].as_str().unwrap_or("default").to_string(),
                            ttl: rec["TTL"].as_u64().unwrap_or(600) as u32,
                            enabled: !rec["Status"]
                                .as_str()
                                .map(|s| s.eq_ignore_ascii_case("DISABLE"))
                                .unwrap_or(false),
                            proxied: None,
                        });
                    }
                    if fetched < 100 || (page as u64) * 100 >= total_count {
                        break;
                    }
                    page += 1;
                }

                let mut lines = Vec::new();
                if *include_lines {
                    if let Ok(body) = self
                        .call_alidns_api(
                            base_url,
                            access_key_id,
                            access_key_secret,
                            "DescribeSupportLines",
                            &[("DomainName", &root_domain), ("Lang", "zh")],
                        )
                        .await
                    {
                        if let Some(arr) = body["RecordLines"]["RecordLine"].as_array() {
                            for item in arr {
                                let code = item["LineCode"].as_str().unwrap_or("").trim();
                                if code.is_empty() {
                                    continue;
                                }
                                let name = item["LineDisplayName"]
                                    .as_str()
                                    .or_else(|| item["LineName"].as_str())
                                    .unwrap_or(code)
                                    .to_string();
                                let parent = item["FatherCode"]
                                    .as_str()
                                    .map(str::trim)
                                    .filter(|s| !s.is_empty())
                                    .map(str::to_string);
                                lines.push(DnsSupportLine {
                                    code: code.to_string(),
                                    name,
                                    parent_code: parent,
                                });
                            }
                        }
                    }
                    if !lines.iter().any(|l| l.code == "default") {
                        lines.insert(
                            0,
                            DnsSupportLine {
                                code: "default".into(),
                                name: "默认 (Default)".into(),
                                parent_code: None,
                            },
                        );
                    }
                }
                Ok((caps, lines, records, None))
            }
            DnsManageOp::Create {
                record_type,
                value,
                line,
                ttl,
                ..
            } => {
                let (rtype, norm_val) = validate_exposure_dns_record(record_type, value)?;
                let line_code = validate_dns_line_code(line.as_deref().unwrap_or("default"))?;
                let ttl_str = ttl.unwrap_or(600).max(1).to_string();
                let body = self
                    .call_alidns_api(
                        base_url,
                        access_key_id,
                        access_key_secret,
                        "AddDomainRecord",
                        &[
                            ("DomainName", &root_domain),
                            ("RR", &rr),
                            ("Type", &rtype),
                            ("Value", &norm_val),
                            ("Line", &line_code),
                            ("TTL", &ttl_str),
                        ],
                    )
                    .await?;
                let rec_id = body["RecordId"]
                    .as_str()
                    .map(str::to_string)
                    .or_else(|| body["RecordId"].as_u64().map(|n| n.to_string()));
                Ok((caps, Vec::new(), Vec::new(), rec_id))
            }
            DnsManageOp::Update {
                record_id,
                record_type,
                value,
                line,
                ttl,
                ..
            } => {
                validate_aliyun_record_id(record_id)?;
                let (rtype, norm_val) = validate_exposure_dns_record(record_type, value)?;
                let line_code = validate_dns_line_code(line.as_deref().unwrap_or("default"))?;
                let ttl_str = ttl.unwrap_or(600).max(1).to_string();
                // Verify target record belongs to this domain/RR and is Exposure-managed (A/AAAA/CNAME)
                self.aliyun_verify_record_scope(
                    base_url,
                    access_key_id,
                    access_key_secret,
                    &root_domain,
                    &rr,
                    record_id,
                )
                .await?;
                self.call_alidns_api(
                    base_url,
                    access_key_id,
                    access_key_secret,
                    "UpdateDomainRecord",
                    &[
                        ("RecordId", record_id),
                        ("RR", &rr),
                        ("Type", &rtype),
                        ("Value", &norm_val),
                        ("Line", &line_code),
                        ("TTL", &ttl_str),
                    ],
                )
                .await?;
                Ok((caps, Vec::new(), Vec::new(), Some(record_id.clone())))
            }
            DnsManageOp::SetStatus {
                record_id, enabled, ..
            } => {
                validate_aliyun_record_id(record_id)?;
                self.aliyun_verify_record_scope(
                    base_url,
                    access_key_id,
                    access_key_secret,
                    &root_domain,
                    &rr,
                    record_id,
                )
                .await?;
                let status = if *enabled { "Enable" } else { "Disable" };
                self.call_alidns_api(
                    base_url,
                    access_key_id,
                    access_key_secret,
                    "SetDomainRecordStatus",
                    &[("RecordId", record_id), ("Status", status)],
                )
                .await?;
                Ok((caps, Vec::new(), Vec::new(), Some(record_id.clone())))
            }
            DnsManageOp::Delete { record_id, .. } => {
                validate_aliyun_record_id(record_id)?;
                self.aliyun_verify_record_scope(
                    base_url,
                    access_key_id,
                    access_key_secret,
                    &root_domain,
                    &rr,
                    record_id,
                )
                .await?;
                self.call_alidns_api(
                    base_url,
                    access_key_id,
                    access_key_secret,
                    "DeleteDomainRecord",
                    &[("RecordId", record_id)],
                )
                .await?;
                Ok((caps, Vec::new(), Vec::new(), Some(record_id.clone())))
            }
        }
    }

    async fn aliyun_verify_record_scope(
        &self,
        base_url: &str,
        access_key_id: &str,
        access_key_secret: &str,
        expected_root: &str,
        expected_rr: &str,
        record_id: &str,
    ) -> Result<()> {
        let info = self
            .call_alidns_api(
                base_url,
                access_key_id,
                access_key_secret,
                "DescribeDomainRecordInfo",
                &[("RecordId", record_id)],
            )
            .await?;
        let dom = info["DomainName"].as_str().unwrap_or("");
        let rr = info["RR"].as_str().unwrap_or("");
        let rt = info["Type"].as_str().unwrap_or("");
        if !dom.eq_ignore_ascii_case(expected_root) || !rr.eq_ignore_ascii_case(expected_rr) {
            return Err(ExposureError::AccessDenied(format!(
                "record '{record_id}' belongs to '{rr}.{dom}', not '{expected_rr}.{expected_root}'"
            )));
        }
        if !matches!(rt, "A" | "AAAA" | "CNAME") {
            return Err(ExposureError::AccessDenied(format!(
                "refusing to modify non-Exposure record type '{rt}'"
            )));
        }
        Ok(())
    }

    async fn cloudflare_resolve_zone_id_with_base(
        &self,
        cf_base: &str,
        api_token: &str,
        explicit_zone_id: Option<&str>,
        root_domain: Option<&str>,
        domain: &str,
    ) -> Result<String> {
        if let Some(zid) = explicit_zone_id.map(str::trim).filter(|s| !s.is_empty()) {
            validate_cloudflare_id(zid, "zone_id")?;
            return Ok(zid.to_string());
        }
        let base = cf_base.trim_end_matches('/');
        let candidates = cloudflare_zone_candidates(domain, root_domain)?;
        for cand in &candidates {
            let url = format!("{base}/zones?name={cand}");
            let resp = self
                .http_client
                .get(&url)
                .bearer_auth(api_token)
                .send()
                .await
                .map_err(|e| ExposureError::Link(format!("cloudflare zone lookup: {e}")))?;
            let body: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| ExposureError::Protocol(format!("cloudflare zones json: {e}")))?;
            if body["success"].as_bool() != Some(true) {
                return Err(ExposureError::Protocol(format!(
                    "cloudflare zone lookup failed: {body}"
                )));
            }
            if let Some(zid) = body["result"]
                .as_array()
                .and_then(|arr| arr.first())
                .and_then(|z| z["id"].as_str())
            {
                validate_cloudflare_id(zid, "zone_id")?;
                return Ok(zid.to_string());
            }
        }
        Err(ExposureError::Config(format!(
            "cloudflare zone_id not found automatically for '{domain}'; configure `zone_id` on domain binding"
        )))
    }

    async fn cloudflare_present_with_base(
        &self,
        cf_base: &str,
        api_token: &str,
        explicit_zone_id: Option<&str>,
        root_domain: Option<&str>,
        domain: &str,
        txt_value: &str,
    ) -> Result<Option<String>> {
        let zone_id = self
            .cloudflare_resolve_zone_id_with_base(
                cf_base,
                api_token,
                explicit_zone_id,
                root_domain,
                domain,
            )
            .await?;
        let fqdn = format!("_acme-challenge.{}", domain.trim().trim_start_matches("*."));
        let url = format!(
            "{}/zones/{zone_id}/dns_records",
            cf_base.trim_end_matches('/')
        );
        let resp = self
            .http_client
            .post(&url)
            .bearer_auth(api_token)
            .json(&serde_json::json!({
                "type": "TXT",
                "name": fqdn,
                "content": txt_value,
                "ttl": 120,
            }))
            .send()
            .await
            .map_err(|e| ExposureError::Link(format!("cloudflare dns01 present: {e}")))?;
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ExposureError::Protocol(format!("cloudflare json: {e}")))?;
        if body["success"].as_bool() != Some(true) {
            return Err(ExposureError::Protocol(format!(
                "cloudflare dns01 failed: {body}"
            )));
        }
        let rec_id = body["result"]["id"].as_str().map(|s| s.to_string());
        if let Some(ref id) = rec_id {
            validate_cloudflare_id(id, "record_id")?;
        }
        Ok(rec_id)
    }

    async fn cloudflare_cleanup_with_base(
        &self,
        cf_base: &str,
        api_token: &str,
        explicit_zone_id: Option<&str>,
        root_domain: Option<&str>,
        domain: &str,
        record_id: Option<&str>,
    ) -> Result<()> {
        if let Some(id) = record_id {
            validate_cloudflare_id(id, "record_id")?;
            let zone_id = self
                .cloudflare_resolve_zone_id_with_base(
                    cf_base,
                    api_token,
                    explicit_zone_id,
                    root_domain,
                    domain,
                )
                .await?;
            let url = format!(
                "{}/zones/{zone_id}/dns_records/{id}",
                cf_base.trim_end_matches('/')
            );
            let _ = self
                .http_client
                .delete(&url)
                .bearer_auth(api_token)
                .send()
                .await;
        }
        Ok(())
    }

    async fn cloudflare_sync_records_with_base(
        &self,
        cf_base: &str,
        api_token: &str,
        explicit_zone_id: Option<&str>,
        root_domain: Option<&str>,
        spec: &DnsSyncRecordSpec,
    ) -> Result<DnsSyncDomainResult> {
        let zone_id = self
            .cloudflare_resolve_zone_id_with_base(
                cf_base,
                api_token,
                explicit_zone_id,
                root_domain,
                &spec.domain,
            )
            .await?;
        let base = cf_base.trim_end_matches('/');
        let rec_name = spec.domain.trim().trim_end_matches('.');
        let default_ttl = spec.ttl.unwrap_or(600).max(1);
        let default_proxied = spec.proxied.unwrap_or(false);

        // Cloudflare standard DNS has no ISP lines: aggregate all line entries (preferring default when present)
        let entries = effective_sync_line_entries(spec);
        let mut merged_v4: BTreeSet<String> = BTreeSet::new();
        let mut merged_v6: BTreeSet<String> = BTreeSet::new();
        let mut merged_cname: BTreeSet<String> = BTreeSet::new();
        let mut eff_ttl = default_ttl;
        let mut eff_proxied = default_proxied;
        for e in &entries {
            for ip in &e.ipv4s {
                let norm = validate_exposure_dns_record("A", ip)
                    .map(|(_, v)| v)
                    .unwrap_or_else(|_| ip.trim().to_string());
                merged_v4.insert(norm);
            }
            for ip in &e.ipv6s {
                let norm = validate_exposure_dns_record("AAAA", ip)
                    .map(|(_, v)| v)
                    .unwrap_or_else(|_| ip.trim().to_string());
                merged_v6.insert(norm);
            }
            for cn in &e.cnames {
                merged_cname.insert(cn.trim().trim_end_matches('.').to_string());
            }
            if e.line.eq_ignore_ascii_case("default") {
                if let Some(t) = e.ttl {
                    eff_ttl = t.max(1);
                }
                if let Some(p) = e.proxied {
                    eff_proxied = p;
                }
            }
        }
        let ttl = eff_ttl;
        let proxied = eff_proxied;

        let mut created = 0usize;
        let mut updated = 0usize;
        let mut deleted = 0usize;
        let mut unchanged = 0usize;

        let v4_vec: Vec<String> = merged_v4.into_iter().collect();
        let v6_vec: Vec<String> = merged_v6.into_iter().collect();
        let cn_vec: Vec<String> = merged_cname.into_iter().collect();

        for (rtype, desired_list) in [("A", &v4_vec), ("AAAA", &v6_vec), ("CNAME", &cn_vec)] {
            let mut existing = Vec::new();
            let mut page = 1u64;
            loop {
                let list_url = format!(
                    "{base}/zones/{zone_id}/dns_records?type={rtype}&name={}&per_page=100&page={page}",
                    aliyun_percent_encode(rec_name)
                );
                let resp = self
                    .http_client
                    .get(&list_url)
                    .bearer_auth(api_token)
                    .send()
                    .await
                    .map_err(|e| ExposureError::Link(format!("cloudflare list records: {e}")))?;
                let body: serde_json::Value = resp
                    .json()
                    .await
                    .map_err(|e| ExposureError::Protocol(format!("cloudflare list json: {e}")))?;
                if body["success"].as_bool() != Some(true) {
                    return Err(ExposureError::Protocol(format!(
                        "cloudflare list dns_records failed: {body}"
                    )));
                }
                let batch = body["result"].as_array().cloned().unwrap_or_default();
                let batch_len = batch.len();
                existing.extend(batch);
                let total_pages = body["result_info"]["total_pages"].as_u64().unwrap_or(1);
                if page >= total_pages || batch_len == 0 {
                    break;
                }
                page += 1;
            }

            let desired: BTreeSet<&str> = desired_list.iter().map(|s| s.as_str()).collect();
            let mut matched_ips: HashSet<String> = HashSet::new();
            let mut to_delete: Vec<String> = Vec::new();

            for rec in &existing {
                let Some(id) = rec["id"].as_str() else {
                    continue;
                };
                validate_cloudflare_id(id, "record_id")?;
                let raw_content = rec["content"].as_str().unwrap_or("");
                let norm_content = validate_exposure_dns_record(rtype, raw_content)
                    .map(|(_, norm)| norm)
                    .unwrap_or_else(|_| {
                        if rtype == "CNAME" {
                            raw_content.trim().trim_end_matches('.').to_string()
                        } else {
                            raw_content.trim().to_string()
                        }
                    });
                if desired.contains(norm_content.as_str())
                    && matched_ips.insert(norm_content.clone())
                {
                    let cur_ttl = rec["ttl"].as_u64();
                    let cur_proxied = rec["proxied"].as_bool().unwrap_or(false);
                    if cur_ttl != Some(ttl as u64) || cur_proxied != proxied {
                        let patch_url = format!("{base}/zones/{zone_id}/dns_records/{id}");
                        let resp = self
                            .http_client
                            .patch(&patch_url)
                            .bearer_auth(api_token)
                            .json(&serde_json::json!({
                                "type": rtype,
                                "name": rec_name,
                                "content": norm_content,
                                "ttl": ttl,
                                "proxied": proxied,
                            }))
                            .send()
                            .await
                            .map_err(|e| {
                                ExposureError::Link(format!("cloudflare patch record: {e}"))
                            })?;
                        let body: serde_json::Value = resp.json().await.map_err(|e| {
                            ExposureError::Protocol(format!("cloudflare patch json: {e}"))
                        })?;
                        if body["success"].as_bool() != Some(true) {
                            return Err(ExposureError::Protocol(format!(
                                "cloudflare patch dns_record failed: {body}"
                            )));
                        }
                        updated += 1;
                    } else {
                        unchanged += 1;
                    }
                } else {
                    to_delete.push(id.to_string());
                }
            }

            for ip in &desired {
                if !matched_ips.contains(*ip) {
                    let post_url = format!("{base}/zones/{zone_id}/dns_records");
                    let resp = self
                        .http_client
                        .post(&post_url)
                        .bearer_auth(api_token)
                        .json(&serde_json::json!({
                            "type": rtype,
                            "name": rec_name,
                            "content": ip,
                            "ttl": ttl,
                            "proxied": proxied,
                        }))
                        .send()
                        .await
                        .map_err(|e| {
                            ExposureError::Link(format!("cloudflare create record: {e}"))
                        })?;
                    let body: serde_json::Value = resp.json().await.map_err(|e| {
                        ExposureError::Protocol(format!("cloudflare create json: {e}"))
                    })?;
                    if body["success"].as_bool() != Some(true) {
                        return Err(ExposureError::Protocol(format!(
                            "cloudflare create dns_record failed: {body}"
                        )));
                    }
                    created += 1;
                }
            }

            for id in to_delete {
                let del_url = format!("{base}/zones/{zone_id}/dns_records/{id}");
                let resp = self
                    .http_client
                    .delete(&del_url)
                    .bearer_auth(api_token)
                    .send()
                    .await
                    .map_err(|e| ExposureError::Link(format!("cloudflare delete record: {e}")))?;
                let body: serde_json::Value = resp
                    .json()
                    .await
                    .map_err(|e| ExposureError::Protocol(format!("cloudflare delete json: {e}")))?;
                if body["success"].as_bool() != Some(true) {
                    return Err(ExposureError::Protocol(format!(
                        "cloudflare delete dns_record failed: {body}"
                    )));
                }
                deleted += 1;
            }
        }

        Ok(DnsSyncDomainResult {
            domain: spec.domain.clone(),
            ok: true,
            created,
            updated,
            deleted,
            unchanged,
            error: None,
        })
    }

    async fn cloudflare_manage_with_base(
        &self,
        cf_base: &str,
        api_token: &str,
        explicit_zone_id: Option<&str>,
        root_domain: Option<&str>,
        op: &DnsManageOp,
    ) -> Result<(
        DnsProviderCapabilities,
        Vec<DnsSupportLine>,
        Vec<DnsRemoteRecord>,
        Option<String>,
    )> {
        let caps = DnsProviderCapabilities {
            supports_lines: false,
            supports_proxied: true,
            supports_status_toggle: false,
            supports_remote_edit: true,
        };
        let domain = match op {
            DnsManageOp::Inspect { domain, .. }
            | DnsManageOp::Create { domain, .. }
            | DnsManageOp::Update { domain, .. }
            | DnsManageOp::SetStatus { domain, .. }
            | DnsManageOp::Delete { domain, .. } => domain.as_str(),
        };
        let zone_id = self
            .cloudflare_resolve_zone_id_with_base(
                cf_base,
                api_token,
                explicit_zone_id,
                root_domain,
                domain,
            )
            .await?;
        let base = cf_base.trim_end_matches('/');
        let rec_name = domain.trim().trim_end_matches('.');

        match op {
            DnsManageOp::Inspect { .. } => {
                let mut records = Vec::new();
                for rtype in ["A", "AAAA", "CNAME"] {
                    let mut page = 1u64;
                    loop {
                        let list_url = format!(
                            "{base}/zones/{zone_id}/dns_records?type={rtype}&name={}&per_page=100&page={page}",
                            aliyun_percent_encode(rec_name)
                        );
                        let resp = self
                            .http_client
                            .get(&list_url)
                            .bearer_auth(api_token)
                            .send()
                            .await
                            .map_err(|e| {
                                ExposureError::Link(format!("cloudflare list records: {e}"))
                            })?;
                        let body: serde_json::Value = resp.json().await.map_err(|e| {
                            ExposureError::Protocol(format!("cloudflare list json: {e}"))
                        })?;
                        if body["success"].as_bool() != Some(true) {
                            return Err(ExposureError::Protocol(format!(
                                "cloudflare list dns_records failed: {body}"
                            )));
                        }
                        let batch = body["result"].as_array().cloned().unwrap_or_default();
                        let batch_len = batch.len();
                        for rec in batch {
                            let Some(id) = rec["id"].as_str() else {
                                continue;
                            };
                            let name = rec["name"].as_str().unwrap_or(rec_name);
                            records.push(DnsRemoteRecord {
                                record_id: id.to_string(),
                                rr: name.to_string(),
                                fqdn: name.to_string(),
                                record_type: rtype.to_string(),
                                value: rec["content"].as_str().unwrap_or("").to_string(),
                                line: "default".to_string(),
                                ttl: rec["ttl"].as_u64().unwrap_or(1) as u32,
                                enabled: true,
                                proxied: Some(rec["proxied"].as_bool().unwrap_or(false)),
                            });
                        }
                        let total_pages = body["result_info"]["total_pages"].as_u64().unwrap_or(1);
                        if page >= total_pages || batch_len == 0 {
                            break;
                        }
                        page += 1;
                    }
                }
                Ok((caps, Vec::new(), records, None))
            }
            DnsManageOp::Create {
                record_type,
                value,
                ttl,
                proxied,
                ..
            } => {
                let (rtype, norm_val) = validate_exposure_dns_record(record_type, value)?;
                let post_url = format!("{base}/zones/{zone_id}/dns_records");
                let resp = self
                    .http_client
                    .post(&post_url)
                    .bearer_auth(api_token)
                    .json(&serde_json::json!({
                        "type": rtype,
                        "name": rec_name,
                        "content": norm_val,
                        "ttl": ttl.unwrap_or(1).max(1),
                        "proxied": proxied.unwrap_or(false),
                    }))
                    .send()
                    .await
                    .map_err(|e| ExposureError::Link(format!("cloudflare create record: {e}")))?;
                let body: serde_json::Value = resp
                    .json()
                    .await
                    .map_err(|e| ExposureError::Protocol(format!("cloudflare create json: {e}")))?;
                if body["success"].as_bool() != Some(true) {
                    return Err(ExposureError::Protocol(format!(
                        "cloudflare create dns_record failed: {body}"
                    )));
                }
                let rec_id = body["result"]["id"].as_str().map(str::to_string);
                Ok((caps, Vec::new(), Vec::new(), rec_id))
            }
            DnsManageOp::Update {
                record_id,
                record_type,
                value,
                ttl,
                proxied,
                ..
            } => {
                validate_cloudflare_id(record_id, "record_id")?;
                let (rtype, norm_val) = validate_exposure_dns_record(record_type, value)?;
                self.cloudflare_verify_record_scope(base, api_token, &zone_id, rec_name, record_id)
                    .await?;
                let patch_url = format!("{base}/zones/{zone_id}/dns_records/{record_id}");
                let resp = self
                    .http_client
                    .patch(&patch_url)
                    .bearer_auth(api_token)
                    .json(&serde_json::json!({
                        "type": rtype,
                        "name": rec_name,
                        "content": norm_val,
                        "ttl": ttl.unwrap_or(1).max(1),
                        "proxied": proxied.unwrap_or(false),
                    }))
                    .send()
                    .await
                    .map_err(|e| ExposureError::Link(format!("cloudflare patch record: {e}")))?;
                let body: serde_json::Value = resp
                    .json()
                    .await
                    .map_err(|e| ExposureError::Protocol(format!("cloudflare patch json: {e}")))?;
                if body["success"].as_bool() != Some(true) {
                    return Err(ExposureError::Protocol(format!(
                        "cloudflare patch dns_record failed: {body}"
                    )));
                }
                Ok((caps, Vec::new(), Vec::new(), Some(record_id.clone())))
            }
            DnsManageOp::SetStatus { .. } => Err(ExposureError::Config(
                "Cloudflare DNS does not support pausing/disabling individual records".into(),
            )),
            DnsManageOp::Delete { record_id, .. } => {
                validate_cloudflare_id(record_id, "record_id")?;
                self.cloudflare_verify_record_scope(base, api_token, &zone_id, rec_name, record_id)
                    .await?;
                let del_url = format!("{base}/zones/{zone_id}/dns_records/{record_id}");
                let resp = self
                    .http_client
                    .delete(&del_url)
                    .bearer_auth(api_token)
                    .send()
                    .await
                    .map_err(|e| ExposureError::Link(format!("cloudflare delete record: {e}")))?;
                let body: serde_json::Value = resp
                    .json()
                    .await
                    .map_err(|e| ExposureError::Protocol(format!("cloudflare delete json: {e}")))?;
                if body["success"].as_bool() != Some(true) {
                    return Err(ExposureError::Protocol(format!(
                        "cloudflare delete dns_record failed: {body}"
                    )));
                }
                Ok((caps, Vec::new(), Vec::new(), Some(record_id.clone())))
            }
        }
    }

    async fn cloudflare_verify_record_scope(
        &self,
        base: &str,
        api_token: &str,
        zone_id: &str,
        expected_name: &str,
        record_id: &str,
    ) -> Result<()> {
        let url = format!("{base}/zones/{zone_id}/dns_records/{record_id}");
        let resp = self
            .http_client
            .get(&url)
            .bearer_auth(api_token)
            .send()
            .await
            .map_err(|e| ExposureError::Link(format!("cloudflare get record: {e}")))?;
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ExposureError::Protocol(format!("cloudflare get json: {e}")))?;
        if body["success"].as_bool() != Some(true) {
            return Err(ExposureError::Protocol(format!(
                "cloudflare get dns_record failed: {body}"
            )));
        }
        let name = body["result"]["name"].as_str().unwrap_or("");
        let rt = body["result"]["type"].as_str().unwrap_or("");
        if !name.eq_ignore_ascii_case(expected_name) {
            return Err(ExposureError::AccessDenied(format!(
                "record '{record_id}' belongs to '{name}', not '{expected_name}'"
            )));
        }
        if !matches!(rt, "A" | "AAAA" | "CNAME") {
            return Err(ExposureError::AccessDenied(format!(
                "refusing to modify non-Exposure record type '{rt}'"
            )));
        }
        Ok(())
    }

    /// Execute Control-authorized remote DNS inspection or single-record mutation
    /// strictly scoped to Exposure's configured domains and A/AAAA/CNAME records.
    pub async fn manage_dns(
        &self,
        op: &DnsManageOp,
    ) -> Result<(
        DnsProviderCapabilities,
        Vec<DnsSupportLine>,
        Vec<DnsRemoteRecord>,
        Option<String>,
    )> {
        let cfg = self.cfg.read().await.clone();
        let domain = match op {
            DnsManageOp::Inspect { domain, .. }
            | DnsManageOp::Create { domain, .. }
            | DnsManageOp::Update { domain, .. }
            | DnsManageOp::SetStatus { domain, .. }
            | DnsManageOp::Delete { domain, .. } => domain.as_str(),
        };
        validate_dns_domain(domain)?;
        let _clean_dom = ensure_non_acme_sync_domain(domain)?;
        let binding = resolve_domain_binding(&cfg.domains, domain)
            .map(|(_, b)| b)
            .ok_or_else(|| {
                ExposureError::Config(format!(
                    "domain '{domain}' is not bound in Maintainer domains config"
                ))
            })?;
        let provider_name = binding.provider.trim();
        let provider = cfg.dns_providers.get(provider_name).ok_or_else(|| {
            ExposureError::Config(format!(
                "maintainer missing DNS provider credentials for '{provider_name}'"
            ))
        })?;

        match provider {
            DnsProviderAccountConfig::Aliyun {
                access_key_id,
                access_key_secret,
                region_id,
            } => {
                let host = aliyun_endpoint_host(region_id.as_deref())?;
                let base_url = format!("https://{host}");
                self.aliyun_manage_with_base(
                    &base_url,
                    access_key_id,
                    access_key_secret,
                    binding.root_domain.as_deref(),
                    op,
                )
                .await
            }
            DnsProviderAccountConfig::Cloudflare { api_token } => {
                if api_token.trim().is_empty() {
                    return Err(ExposureError::Config(format!(
                        "cloudflare provider '{provider_name}' missing api_token on maintainer"
                    )));
                }
                self.cloudflare_manage_with_base(
                    "https://api.cloudflare.com/client/v4",
                    api_token,
                    binding.zone_id.as_deref(),
                    binding.root_domain.as_deref(),
                    op,
                )
                .await
            }
            DnsProviderAccountConfig::Webhook { .. } | DnsProviderAccountConfig::Exec { .. } => {
                let caps = DnsProviderCapabilities::default();
                match op {
                    DnsManageOp::Inspect { .. } => Ok((caps, Vec::new(), Vec::new(), None)),
                    _ => Err(ExposureError::Config(format!(
                        "DNS provider '{provider_name}' does not support direct remote record editing"
                    ))),
                }
            }
        }
    }

    /// Execute Control-authorized declarative DNS A/AAAA sync for one or more domains
    /// using this Maintainer's local `dns_providers` credentials.
    pub async fn sync_dns_records(
        &self,
        records: &[DnsSyncRecordSpec],
    ) -> Vec<DnsSyncDomainResult> {
        let cfg = self.cfg.read().await.clone();
        let mut results = Vec::with_capacity(records.len());

        for spec in records {
            let res = self.sync_single_domain(&cfg, spec).await;
            match res {
                Ok(r) => results.push(r),
                Err(e) => {
                    let msg = e.to_string();
                    warn!(domain = %spec.domain, error = %msg, "maintainer DNS sync failed");
                    self.record_alert("error", format!("dns sync {} failed: {msg}", spec.domain))
                        .await;
                    results.push(DnsSyncDomainResult {
                        domain: spec.domain.clone(),
                        ok: false,
                        created: 0,
                        updated: 0,
                        deleted: 0,
                        unchanged: 0,
                        error: Some(msg),
                    });
                }
            }
        }
        results
    }

    async fn sync_single_domain(
        &self,
        cfg: &MaintainerConfig,
        spec: &DnsSyncRecordSpec,
    ) -> Result<DnsSyncDomainResult> {
        validate_dns_domain(&spec.domain)?;
        let clean_domain = ensure_non_acme_sync_domain(&spec.domain)?;

        let raw_entries = effective_sync_line_entries(spec);
        let mut canonical_entries: Vec<DnsLineSyncEntry> = Vec::with_capacity(raw_entries.len());
        let mut flat_v4: BTreeSet<String> = BTreeSet::new();
        let mut flat_v6: BTreeSet<String> = BTreeSet::new();
        let mut total_targets = 0usize;

        for entry in &raw_entries {
            let norm_line = validate_dns_line_code(&entry.line)?;
            let mut v4s = Vec::new();
            let mut v6s = Vec::new();
            let mut cnames = Vec::new();
            for raw in &entry.ipv4s {
                let (_, norm) = validate_exposure_dns_record("A", raw)?;
                flat_v4.insert(norm.clone());
                v4s.push(norm);
                total_targets += 1;
            }
            for raw in &entry.ipv6s {
                let (_, norm) = validate_exposure_dns_record("AAAA", raw)?;
                flat_v6.insert(norm.clone());
                v6s.push(norm);
                total_targets += 1;
            }
            for raw in &entry.cnames {
                let (_, norm) = validate_exposure_dns_record("CNAME", raw)?;
                cnames.push(norm);
                total_targets += 1;
            }
            canonical_entries.push(DnsLineSyncEntry {
                line: norm_line,
                ipv4s: v4s,
                ipv6s: v6s,
                cnames,
                ttl: entry.ttl,
                proxied: entry.proxied,
            });
        }
        if total_targets == 0 {
            return Err(ExposureError::Config(format!(
                "refusing to sync '{}' with zero target records",
                spec.domain
            )));
        }

        // Scope enforcement: only domains explicitly configured in `maintainer.domains` may be
        // mutated, and caller-supplied provider / zone_id / root_domain cannot override the binding.
        let binding = resolve_domain_binding(&cfg.domains, &clean_domain).ok_or_else(|| {
            ExposureError::Config(format!(
                "domain '{}' is not authorized in maintainer domains (no DNS provider configured for this zone)",
                spec.domain
            ))
        })?;
        let binding = binding.1;
        let bound_provider = binding.provider.trim();
        let spec_provider = spec
            .provider
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let provider_name = if !bound_provider.is_empty() {
            if let Some(sp) = spec_provider {
                if sp != bound_provider {
                    return Err(ExposureError::AccessDenied(format!(
                        "DNS sync provider '{sp}' does not match configured binding provider '{bound_provider}' for '{}'",
                        spec.domain
                    )));
                }
            }
            bound_provider
        } else {
            spec_provider.ok_or_else(|| {
                ExposureError::Config(format!(
                    "domain '{}' has no DNS provider configured",
                    spec.domain
                ))
            })?
        };
        let provider = cfg.dns_providers.get(provider_name).ok_or_else(|| {
            ExposureError::Config(format!(
                "maintainer missing DNS provider credentials for '{provider_name}'"
            ))
        })?;

        let bound_zone = binding
            .zone_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let spec_zone = spec
            .zone_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if let (Some(bz), Some(sz)) = (bound_zone, spec_zone) {
            if bz != sz {
                return Err(ExposureError::AccessDenied(format!(
                    "DNS sync zone_id '{sz}' does not match configured binding zone_id '{bz}' for '{}'",
                    spec.domain
                )));
            }
        }
        let eff_zone_id = bound_zone.or(spec_zone);

        let bound_root = binding
            .root_domain
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let spec_root = spec
            .root_domain
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if let (Some(br), Some(sr)) = (bound_root, spec_root) {
            if !br.eq_ignore_ascii_case(sr) {
                return Err(ExposureError::AccessDenied(format!(
                    "DNS sync root_domain '{sr}' does not match configured binding root_domain '{br}' for '{}'",
                    spec.domain
                )));
            }
        }
        let eff_root = bound_root.or(spec_root);
        let eff_ttl = spec.ttl.or(Some(binding.ttl));
        let eff_proxied = spec.proxied.or(Some(binding.proxied));

        let eff_spec = DnsSyncRecordSpec {
            domain: clean_domain,
            ipv4s: flat_v4.into_iter().collect(),
            ipv6s: flat_v6.into_iter().collect(),
            line_entries: canonical_entries,
            provider: Some(provider_name.to_string()),
            zone_id: eff_zone_id.map(str::to_string),
            root_domain: eff_root.map(str::to_string),
            ttl: eff_ttl,
            proxied: eff_proxied,
        };

        match provider {
            DnsProviderAccountConfig::Cloudflare { api_token } => {
                if api_token.trim().is_empty() {
                    return Err(ExposureError::Config(format!(
                        "cloudflare provider '{provider_name}' missing api_token on maintainer"
                    )));
                }
                self.cloudflare_sync_records_with_base(
                    "https://api.cloudflare.com/client/v4",
                    api_token,
                    eff_zone_id,
                    eff_root,
                    &eff_spec,
                )
                .await
            }
            DnsProviderAccountConfig::Aliyun {
                access_key_id,
                access_key_secret,
                region_id,
            } => {
                let host = aliyun_endpoint_host(region_id.as_deref())?;
                let base_url = format!("https://{host}");
                self.aliyun_sync_records_with_base(
                    &base_url,
                    access_key_id,
                    access_key_secret,
                    eff_root,
                    &eff_spec,
                )
                .await
            }
            DnsProviderAccountConfig::Webhook {
                sync_url,
                auth_header,
                ..
            } => {
                let url = sync_url
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| {
                        ExposureError::Config(format!(
                            "webhook provider '{provider_name}' missing sync_url for DNS A/AAAA sync"
                        ))
                    })?;
                let webhook_client = build_ssrf_pinned_webhook_client(url).await?;
                let mut req = webhook_client.post(url).json(&serde_json::json!({
                    "action": "sync",
                    "domain": eff_spec.domain,
                    "ipv4s": eff_spec.ipv4s,
                    "ipv6s": eff_spec.ipv6s,
                    "line_entries": eff_spec.line_entries,
                    "ttl": eff_spec.ttl.unwrap_or(600),
                    "proxied": eff_spec.proxied.unwrap_or(false),
                }));
                if let Some(h) = auth_header {
                    req = req.header("Authorization", h);
                }
                let resp = req
                    .send()
                    .await
                    .map_err(|e| ExposureError::Link(format!("webhook dns sync: {e}")))?;
                if !resp.status().is_success() {
                    return Err(ExposureError::Protocol(format!(
                        "webhook dns sync status {}",
                        resp.status()
                    )));
                }
                Ok(DnsSyncDomainResult {
                    domain: eff_spec.domain,
                    ok: true,
                    created: 0,
                    updated: eff_spec.ipv4s.len() + eff_spec.ipv6s.len(),
                    deleted: 0,
                    unchanged: 0,
                    error: None,
                })
            }
            DnsProviderAccountConfig::Exec { command, args } => {
                if std::env::var("EXPOSURE_ALLOW_EXEC_HOOK").ok().as_deref() != Some("1") {
                    return Err(ExposureError::AccessDenied(
                        "DNS exec hook disabled by default; set EXPOSURE_ALLOW_EXEC_HOOK=1 on maintainer host to opt in".into(),
                    ));
                }
                let mut cmd = Command::new(command);
                cmd.kill_on_drop(true)
                    .args(args)
                    .arg("sync")
                    .arg(&eff_spec.domain)
                    .arg(eff_spec.ipv4s.join(","))
                    .arg(eff_spec.ipv6s.join(","));
                let status = tokio::time::timeout(EXEC_HOOK_TIMEOUT, cmd.status())
                    .await
                    .map_err(|_| ExposureError::Link("exec dns sync timed out".into()))??;
                if !status.success() {
                    return Err(ExposureError::Protocol(format!(
                        "exec dns sync exited with {status}"
                    )));
                }
                Ok(DnsSyncDomainResult {
                    domain: eff_spec.domain,
                    ok: true,
                    created: 0,
                    updated: eff_spec.ipv4s.len() + eff_spec.ipv6s.len(),
                    deleted: 0,
                    unchanged: 0,
                    error: None,
                })
            }
        }
    }

    /// Present a DNS-01 TXT record via the configured provider (Cloudflare, Aliyun DNS, HTTPS Webhook, Exec Hook).
    pub async fn dns01_present(
        &self,
        provider: &DnsProviderAccountConfig,
        binding: Option<&DomainBindingConfig>,
        domain: &str,
        txt_value: &str,
    ) -> Result<Option<String>> {
        validate_dns_domain(domain)?;
        let fqdn = format!("_acme-challenge.{}", domain.trim_start_matches("*."));
        let root_domain = binding.and_then(|b| b.root_domain.as_deref());
        let zone_id = binding.and_then(|b| b.zone_id.as_deref());
        match provider {
            DnsProviderAccountConfig::Cloudflare { api_token } => {
                self.cloudflare_present_with_base(
                    "https://api.cloudflare.com/client/v4",
                    api_token,
                    zone_id,
                    root_domain,
                    domain,
                    txt_value,
                )
                .await
            }
            DnsProviderAccountConfig::Aliyun {
                access_key_id,
                access_key_secret,
                region_id,
            } => {
                let host = aliyun_endpoint_host(region_id.as_deref())?;
                let base_url = format!("https://{host}");
                self.aliyun_present_with_base(
                    &base_url,
                    access_key_id,
                    access_key_secret,
                    root_domain,
                    domain,
                    txt_value,
                )
                .await
            }
            DnsProviderAccountConfig::Webhook {
                present_url,
                auth_header,
                ..
            } => {
                let webhook_client = build_ssrf_pinned_webhook_client(present_url).await?;
                let mut req = webhook_client.post(present_url).json(&serde_json::json!({
                    "action": "present",
                    "domain": domain,
                    "fqdn": fqdn,
                    "value": txt_value,
                }));
                if let Some(h) = auth_header {
                    req = req.header("Authorization", h);
                }
                let resp = req
                    .send()
                    .await
                    .map_err(|e| ExposureError::Link(format!("webhook dns01 present: {e}")))?;
                if !resp.status().is_success() {
                    return Err(ExposureError::Protocol(format!(
                        "webhook dns01 present status {}",
                        resp.status()
                    )));
                }
                Ok(None)
            }
            DnsProviderAccountConfig::Exec { command, args } => {
                if std::env::var("EXPOSURE_ALLOW_EXEC_HOOK").ok().as_deref() != Some("1") {
                    return Err(ExposureError::AccessDenied(
                        "DNS-01 exec hook disabled by default; set EXPOSURE_ALLOW_EXEC_HOOK=1 on maintainer host to opt in".into(),
                    ));
                }
                let mut cmd = Command::new(command);
                cmd.kill_on_drop(true)
                    .args(args)
                    .arg("present")
                    .arg(&fqdn)
                    .arg(txt_value);
                let status = tokio::time::timeout(EXEC_HOOK_TIMEOUT, cmd.status())
                    .await
                    .map_err(|_| ExposureError::Link("exec dns01 present timed out".into()))??;
                if !status.success() {
                    return Err(ExposureError::Protocol(format!(
                        "exec dns01 present exited with {status}"
                    )));
                }
                Ok(None)
            }
        }
    }

    pub async fn dns01_cleanup(
        &self,
        provider: &DnsProviderAccountConfig,
        binding: Option<&DomainBindingConfig>,
        domain: &str,
        txt_value: &str,
        record_id: Option<&str>,
    ) -> Result<()> {
        validate_dns_domain(domain)?;
        let fqdn = format!("_acme-challenge.{}", domain.trim_start_matches("*."));
        let root_domain = binding.and_then(|b| b.root_domain.as_deref());
        let zone_id = binding.and_then(|b| b.zone_id.as_deref());
        match provider {
            DnsProviderAccountConfig::Cloudflare { api_token } => {
                self.cloudflare_cleanup_with_base(
                    "https://api.cloudflare.com/client/v4",
                    api_token,
                    zone_id,
                    root_domain,
                    domain,
                    record_id,
                )
                .await
            }
            DnsProviderAccountConfig::Aliyun {
                access_key_id,
                access_key_secret,
                region_id,
            } => {
                let host = aliyun_endpoint_host(region_id.as_deref())?;
                let base_url = format!("https://{host}");
                self.aliyun_cleanup_with_base(
                    &base_url,
                    access_key_id,
                    access_key_secret,
                    root_domain,
                    domain,
                    txt_value,
                    record_id,
                )
                .await
            }
            DnsProviderAccountConfig::Webhook {
                cleanup_url,
                auth_header,
                ..
            } => {
                let webhook_client = build_ssrf_pinned_webhook_client(cleanup_url).await?;
                let mut req = webhook_client.post(cleanup_url).json(&serde_json::json!({
                    "action": "cleanup",
                    "domain": domain,
                    "fqdn": fqdn,
                    "value": txt_value,
                }));
                if let Some(h) = auth_header {
                    req = req.header("Authorization", h);
                }
                let _ = req.send().await;
                Ok(())
            }
            DnsProviderAccountConfig::Exec { command, args } => {
                if std::env::var("EXPOSURE_ALLOW_EXEC_HOOK").ok().as_deref() != Some("1") {
                    return Ok(());
                }
                let mut cmd = Command::new(command);
                cmd.kill_on_drop(true)
                    .args(args)
                    .arg("cleanup")
                    .arg(&fqdn)
                    .arg(txt_value);
                let _ = tokio::time::timeout(EXEC_HOOK_TIMEOUT, cmd.status()).await;
                Ok(())
            }
        }
    }

    /// Issue/renew a certificate order, sign per-target with Maintainer's Ed25519 key,
    /// and distribute along configured Hop Tables to every target ingress node.
    pub async fn issue_and_distribute_order(
        &self,
        order: &CertOrderConfig,
        forwarder: &Arc<Forwarder>,
    ) -> Result<()> {
        validate_dns_domain(&order.domain)?;

        let cfg = self.cfg.read().await.clone();
        let signing_secret = cfg.cert_signing_secret_key.as_deref().ok_or_else(|| {
            ExposureError::Config("maintainer missing cert_signing_secret_key".into())
        })?;
        let kp = NodeKeyPair::from_secret_b64(signing_secret)?;

        let binding = resolve_domain_binding(&cfg.domains, &order.domain).map(|(_, b)| b);
        let explicit_provider = order
            .provider
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let resolved_provider_name = match explicit_provider {
            Some(p) if p.eq_ignore_ascii_case("none") => None,
            Some(p) => Some(p),
            None => binding.map(|b| b.provider.trim()).filter(|s| !s.is_empty()),
        };

        let now = Utc::now();
        let cached = if !cfg.acme.storage_dir.is_empty() {
            load_valid_cached_cert(
                &cfg.acme.storage_dir,
                &order.domain,
                order.renew_before_days,
                now,
            )
        } else {
            None
        };

        let from_cache = cached.is_some();
        let (cert_pem, key_pem, issued_at, expires_at) = if let Some((c, k, iat, exp)) = cached {
            info!(domain = %order.domain, "reusing valid cached certificate from disk; skipping ACME issuance");
            (c, k, iat, exp)
        } else {
            let (c, k) = if cfg.acme.directory_url.eq_ignore_ascii_case("self-signed")
                || cfg.acme.directory_url.is_empty()
            {
                if let Some(pname) = resolved_provider_name {
                    let provider = cfg.dns_providers.get(pname).ok_or_else(|| {
                        ExposureError::Config(format!(
                            "cert order '{}' references unknown dns_provider '{pname}'",
                            order.domain
                        ))
                    })?;
                    let challenge_val = Uuid::new_v4().to_string();
                    let rec_id = self
                        .dns01_present(provider, binding, &order.domain, &challenge_val)
                        .await?;
                    let _ = self
                        .dns01_cleanup(
                            provider,
                            binding,
                            &order.domain,
                            &challenge_val,
                            rec_id.as_deref(),
                        )
                        .await;
                }
                generate_self_signed_pem(&order.domain)?
            } else {
                let pname = resolved_provider_name.ok_or_else(|| {
                    ExposureError::Config(format!(
                        "ACME order '{}' requires a DNS-01 provider (configure `provider` or `domains` binding)",
                        order.domain
                    ))
                })?;
                let provider = cfg.dns_providers.get(pname).ok_or_else(|| {
                    ExposureError::Config(format!(
                        "cert order '{}' references unknown dns_provider '{pname}'",
                        order.domain
                    ))
                })?;
                let acme_http = reqwest::Client::builder()
                    .timeout(Duration::from_secs(30))
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                    .map_err(|e| ExposureError::Link(format!("ACME HTTP client: {e}")))?;
                crate::acme::issue_acme_dns01_cert(
                    acme_http,
                    &cfg.acme.directory_url,
                    &cfg.acme.contact_email,
                    &cfg.acme.storage_dir,
                    &order.domain,
                    |txt_val| {
                        let domain = order.domain.clone();
                        async move {
                            self.dns01_present(provider, binding, &domain, &txt_val)
                                .await
                        }
                    },
                    |txt_val, rec_id| {
                        let domain = order.domain.clone();
                        async move {
                            let _ = self
                                .dns01_cleanup(
                                    provider,
                                    binding,
                                    &domain,
                                    &txt_val,
                                    rec_id.as_deref(),
                                )
                                .await;
                        }
                    },
                )
                .await?
            };

            let iat = now.timestamp();
            let exp = parse_x509_not_after_unix(&c)
                .unwrap_or_else(|| (now + ChronoDuration::days(90)).timestamp());

            // Persist certificate locally on Maintainer (strict domain validation + atomic 0600 private key!)
            if !cfg.acme.storage_dir.is_empty() {
                let dir = Path::new(&cfg.acme.storage_dir);
                std::fs::create_dir_all(dir)?;
                let safe = order.domain.replace('*', "_wildcard_");
                std::fs::write(dir.join(format!("{safe}.crt.pem")), &c)?;
                let key_path = dir.join(format!("{safe}.key.pem"));
                write_secret_file_atomic(&key_path, k.as_bytes())?;
                let meta = serde_json::json!({
                    "domain": order.domain,
                    "issued_at": iat,
                    "expires_at": exp,
                });
                let _ = std::fs::write(dir.join(format!("{safe}.meta.json")), meta.to_string());
            }

            (c, k, iat, exp)
        };

        let mut all_ok = true;
        for target in &order.target_nodes {
            let signing = cert_bundle_signing_bytes(
                &order.domain,
                target,
                &cert_pem,
                &key_pem,
                issued_at,
                expires_at,
                &self.node_tag,
            );
            let signature = kp.sign_b64(&signing);

            let hops = order
                .target_hops
                .get(target)
                .cloned()
                .unwrap_or_else(|| vec![self.node_tag.clone(), target.clone()]);
            let frame = SpecialFrame::new(
                Uuid::new_v4().to_string(),
                hops,
                16,
                SpecialPayload::CertBundle {
                    domain: order.domain.clone(),
                    target_node_tag: target.clone(),
                    cert_pem: cert_pem.clone(),
                    key_pem: key_pem.clone(),
                    issued_at,
                    expires_at,
                    maintainer_tag: self.node_tag.clone(),
                    signature,
                },
            );

            match forwarder
                .send_special_rpc(frame, Duration::from_secs(10))
                .await
            {
                Ok(SpecialFrame {
                    payload:
                        SpecialPayload::CertAck {
                            applied: true,
                            node_tag,
                            ..
                        },
                    ..
                }) => {
                    info!(domain = %order.domain, target = %node_tag, "certificate distributed and hot-reloaded");
                }
                Ok(SpecialFrame {
                    payload:
                        SpecialPayload::CertAck {
                            applied: false,
                            node_tag,
                            error,
                            ..
                        },
                    ..
                }) => {
                    let same_or_newer_on_target = from_cache
                        && error
                            .as_deref()
                            .map(|e| e.contains("cert bundle rollback rejected"))
                            .unwrap_or(false);
                    if same_or_newer_on_target {
                        info!(domain = %order.domain, target = %node_tag, "target already holds current or newer certificate");
                    } else {
                        all_ok = false;
                        let msg = format!(
                            "cert apply failed on {} for {}: {:?}",
                            node_tag, order.domain, error
                        );
                        warn!("{msg}");
                        self.record_alert("error", msg).await;
                    }
                }
                Err(e) => {
                    all_ok = false;
                    let msg = format!(
                        "cert distribution to {} for {} failed: {}",
                        target, order.domain, e
                    );
                    warn!("{msg}");
                    self.record_alert("error", msg).await;
                }
                _ => {
                    all_ok = false;
                }
            }
        }

        let mut cs = self.cert_statuses.lock().await;
        let exp_dt = DateTime::<Utc>::from_timestamp(expires_at, 0).unwrap_or(now);
        cs.insert(
            order.domain.clone(),
            CertStatusInfo {
                domain: order.domain.clone(),
                targets: order.target_nodes.clone(),
                expires_at: Some(exp_dt.to_rfc3339()),
                last_renewed: Some(now.to_rfc3339()),
                status: if all_ok {
                    "valid".into()
                } else {
                    "degraded".into()
                },
            },
        );
        Ok(())
    }

    pub fn spawn_background_tasks(self: &Arc<Self>, forwarder: Arc<Forwarder>) {
        let this = Arc::clone(self);
        let mut rx1 = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
            loop {
                let mins = this
                    .cfg
                    .read()
                    .await
                    .logger
                    .retention
                    .cleanup_interval_mins
                    .clamp(5, 1440);
                tokio::select! {
                    _ = rx1.changed() => {
                        if *rx1.borrow() {
                            return;
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_secs(mins * 60)) => {}
                }
                let retention = this.cfg.read().await.logger.retention.clone();
                let db = this.current_db().await;
                if let Err(e) = db.run_cleanup(&retention).await {
                    warn!(error = %e, "maintainer periodic sqlite retention cleanup failed");
                }
            }
        });

        // Periodic certificate renewal check honoring `order.renew_before_days` + exponential backoff
        let this2 = Arc::clone(self);
        let mut rx2 = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut retry_after: HashMap<String, DateTime<Utc>> = HashMap::new();
            let mut fail_counts: HashMap<String, u32> = HashMap::new();
            loop {
                tokio::select! {
                    _ = rx2.changed() => {
                        if *rx2.borrow() {
                            return;
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {}
                }
                let cfg = this2.cfg.read().await.clone();
                if !cfg.is_primary_cert_manager || cfg.cert_signing_secret_key.is_none() {
                    continue;
                }
                let now = Utc::now();
                for order in &cfg.acme.orders {
                    if let Some(until) = retry_after.get(&order.domain) {
                        if now < *until {
                            continue;
                        }
                    }
                    let needs_issue = {
                        let cs = this2.cert_statuses.lock().await;
                        match cs.get(&order.domain) {
                            None => true,
                            Some(info) => {
                                if info.status != "valid" {
                                    true
                                } else if let Some(ref exp_str) = info.expires_at {
                                    match DateTime::parse_from_rfc3339(exp_str) {
                                        Ok(exp_dt) => {
                                            // Clamp to a sane range so a misconfigured value cannot
                                            // panic (`ChronoDuration::days`) or overflow.
                                            let renew_days =
                                                order.renew_before_days.clamp(1, 89) as i64;
                                            let renew_at = exp_dt.with_timezone(&Utc)
                                                - ChronoDuration::days(renew_days);
                                            now >= renew_at
                                        }
                                        Err(_) => true,
                                    }
                                } else {
                                    true
                                }
                            }
                        }
                    };
                    if needs_issue {
                        if let Err(e) = this2.issue_and_distribute_order(order, &forwarder).await {
                            let fails = fail_counts
                                .entry(order.domain.clone())
                                .and_modify(|c| *c = c.saturating_add(1))
                                .or_insert(1);
                            let backoff_mins = (15i64 << (*fails - 1).min(5)).min(360);
                            retry_after.insert(
                                order.domain.clone(),
                                now + ChronoDuration::minutes(backoff_mins),
                            );
                            warn!(
                                domain = %order.domain,
                                error = %e,
                                backoff_mins,
                                "certificate renewal failed (exponential backoff)"
                            );
                            this2
                                .record_alert(
                                    "error",
                                    format!("cert renew {} failed: {e}", order.domain),
                                )
                                .await;
                        } else {
                            let still_degraded = this2
                                .cert_statuses
                                .lock()
                                .await
                                .get(&order.domain)
                                .map(|s| s.status != "valid")
                                .unwrap_or(false);
                            if still_degraded {
                                retry_after
                                    .insert(order.domain.clone(), now + ChronoDuration::minutes(5));
                            } else {
                                retry_after.remove(&order.domain);
                                fail_counts.remove(&order.domain);
                            }
                        }
                    }
                }
            }
        });
    }
}

fn load_valid_cached_cert(
    storage_dir: &str,
    domain: &str,
    renew_before_days: u32,
    now: DateTime<Utc>,
) -> Option<(String, String, i64, i64)> {
    let dir = Path::new(storage_dir);
    let safe = domain.replace('*', "_wildcard_");
    let crt_path = dir.join(format!("{safe}.crt.pem"));
    let key_path = dir.join(format!("{safe}.key.pem"));
    let cert_pem = std::fs::read_to_string(&crt_path).ok()?;
    let key_pem = std::fs::read_to_string(&key_path).ok()?;
    if cert_pem.trim().is_empty() || key_pem.trim().is_empty() {
        return None;
    }

    let real_exp = parse_x509_not_after_unix(&cert_pem);
    let meta_path = dir.join(format!("{safe}.meta.json"));
    let (issued_at, expires_at) = if let Ok(raw) = std::fs::read_to_string(&meta_path) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
            let iat = val.get("issued_at").and_then(|v| v.as_i64());
            let exp = val.get("expires_at").and_then(|v| v.as_i64());
            match (iat, exp) {
                (Some(i), Some(e)) => (i, real_exp.map_or(e, |re| e.min(re))),
                _ => return None,
            }
        } else {
            return None;
        }
    } else {
        let mtime = std::fs::metadata(&crt_path).ok()?.modified().ok()?;
        let iat = DateTime::<Utc>::from(mtime).timestamp();
        let exp = real_exp.unwrap_or_else(|| iat + 90 * 86_400);
        (iat, exp)
    };

    let renew_at = expires_at - (renew_before_days.clamp(1, 89) as i64) * 86_400;
    if now.timestamp() >= renew_at {
        return None;
    }
    Some((cert_pem, key_pem, issued_at, expires_at))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn aliyun_percent_encode_and_canonical_query() {
        assert_eq!(
            aliyun_percent_encode("abc-123_456.789~"),
            "abc-123_456.789~"
        );
        assert_eq!(aliyun_percent_encode("a b/c+d=e"), "a%20b%2Fc%2Bd%3De");

        let q = build_aliyun_canonical_query(&[
            ("Value", "val+1="),
            ("DomainName", "example.com"),
            ("RR", "_acme-challenge"),
            ("TTL", "600"),
            ("Type", "TXT"),
        ]);
        assert_eq!(
            q,
            "DomainName=example.com&RR=_acme-challenge&TTL=600&Type=TXT&Value=val%2B1%3D"
        );
    }

    #[test]
    fn aliyun_v3_signature_matches_expected_vector() {
        let auth = sign_aliyun_v3_post(
            "alidns.aliyuncs.com",
            "AddDomainRecord",
            "DomainName=example.com&RR=_acme-challenge&TTL=600&Type=TXT&Value=tok",
            "LTAI5tTestKeyId",
            "TestSecretKey",
            "2026-11-21T09:45:00Z".to_string(),
            "nonce-1234".to_string(),
        )
        .expect("sign v3");

        let canonical_req = concat!(
            "POST\n",
            "/\n",
            "DomainName=example.com&RR=_acme-challenge&TTL=600&Type=TXT&Value=tok\n",
            "host:alidns.aliyuncs.com\n",
            "x-acs-action:AddDomainRecord\n",
            "x-acs-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n",
            "x-acs-date:2026-11-21T09:45:00Z\n",
            "x-acs-signature-nonce:nonce-1234\n",
            "x-acs-version:2015-01-09\n",
            "\n",
            "host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version\n",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let string_to_sign = format!(
            "ACS3-HMAC-SHA256\n{}",
            hex::encode(Sha256::digest(canonical_req.as_bytes()))
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(b"TestSecretKey").unwrap();
        mac.update(string_to_sign.as_bytes());
        let expected_sig = hex::encode(mac.finalize().into_bytes());

        assert_eq!(
            auth.authorization,
            format!(
                "ACS3-HMAC-SHA256 Credential=LTAI5tTestKeyId,SignedHeaders=host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version,Signature={expected_sig}"
            )
        );
    }

    #[test]
    fn aliyun_endpoint_and_domain_split_validation() {
        assert_eq!(aliyun_endpoint_host(None).unwrap(), "alidns.aliyuncs.com");
        assert_eq!(
            aliyun_endpoint_host(Some("  ")).unwrap(),
            "alidns.aliyuncs.com"
        );
        assert_eq!(
            aliyun_endpoint_host(Some("cn-hangzhou")).unwrap(),
            "alidns.cn-hangzhou.aliyuncs.com"
        );
        assert!(aliyun_endpoint_host(Some("evil.com/")).is_err());
        assert!(aliyun_endpoint_host(Some("-bad")).is_err());

        assert_eq!(
            split_domain_with_zone_mode("example.com", "example.com", true).unwrap(),
            ("example.com".to_string(), "_acme-challenge".to_string())
        );
        assert_eq!(
            split_domain_with_zone_mode("*.api.example.com", "example.com", true).unwrap(),
            ("example.com".to_string(), "_acme-challenge.api".to_string())
        );
        assert_eq!(
            split_domain_with_zone_mode("*.api.example.com", "example.com", false).unwrap(),
            ("example.com".to_string(), "*.api".to_string())
        );
        assert!(split_domain_with_zone_mode("other.org", "example.com", true).is_err());
    }

    #[derive(Debug, Clone)]
    struct RecordedReq {
        action: String,
        query: String,
        authorization: String,
        host: String,
        content_sha256: String,
    }

    async fn spawn_mock_alidns_server(
        responses: Vec<(u16, String)>,
    ) -> (String, Arc<Mutex<Vec<RecordedReq>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let rec_clone = Arc::clone(&recorded);
        tokio::spawn(async move {
            for (status, body) in responses {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = vec![0u8; 8192];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let req_str = String::from_utf8_lossy(&buf[..n]);
                let mut lines = req_str.split("\r\n");
                let request_line = lines.next().unwrap_or("");
                let target = request_line.split_whitespace().nth(1).unwrap_or("/");
                let query = target
                    .split_once('?')
                    .map(|(_, q)| q)
                    .unwrap_or("")
                    .to_string();

                let mut action = String::new();
                let mut authorization = String::new();
                let mut host = String::new();
                let mut content_sha256 = String::new();
                for line in lines {
                    if line.is_empty() {
                        break;
                    }
                    if let Some((k, v)) = line.split_once(':') {
                        let kl = k.trim().to_ascii_lowercase();
                        let val = v.trim().to_string();
                        match kl.as_str() {
                            "x-acs-action" => action = val,
                            "authorization" => authorization = val,
                            "host" => host = val,
                            "x-acs-content-sha256" => content_sha256 = val,
                            _ => {}
                        }
                    }
                }
                rec_clone.lock().await.push(RecordedReq {
                    action,
                    query,
                    authorization,
                    host,
                    content_sha256,
                });

                let status_text = if status == 200 { "OK" } else { "Bad Request" };
                let resp = format!(
                    "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        });
        (format!("http://{addr}"), recorded)
    }

    #[tokio::test]
    async fn aliyun_present_and_cleanup_with_explicit_domain() {
        let dir = std::env::temp_dir().join(format!("exp-ali-test-{}", Uuid::new_v4()));
        let mut cfg = MaintainerConfig::default();
        cfg.logger.segment.dir = dir.to_string_lossy().to_string();
        let svc = MaintainerService::new("maint-test", cfg).unwrap();

        let (base_url, reqs) = spawn_mock_alidns_server(vec![
            (
                200,
                r#"{"RequestId":"req-1","RecordId":"987654321"}"#.to_string(),
            ),
            (
                200,
                r#"{"RequestId":"req-2","RecordId":"987654321"}"#.to_string(),
            ),
        ])
        .await;

        let rec_id = svc
            .aliyun_present_with_base(
                &base_url,
                "LTAI5tKey",
                "SecretVal",
                Some("example.com"),
                "*.sub.example.com",
                "txt-challenge-value",
            )
            .await
            .expect("present ok");
        assert_eq!(rec_id.as_deref(), Some("987654321"));

        svc.aliyun_cleanup_with_base(
            &base_url,
            "LTAI5tKey",
            "SecretVal",
            Some("example.com"),
            "*.sub.example.com",
            "txt-challenge-value",
            rec_id.as_deref(),
        )
        .await
        .expect("cleanup ok");

        let captured = reqs.lock().await;
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].action, "AddDomainRecord");
        assert_eq!(
            captured[0].query,
            "DomainName=example.com&RR=_acme-challenge.sub&TTL=600&Type=TXT&Value=txt-challenge-value"
        );
        assert_eq!(captured[0].content_sha256, EMPTY_BODY_SHA256);
        assert!(
            captured[0]
                .authorization
                .starts_with("ACS3-HMAC-SHA256 Credential=LTAI5tKey,")
        );
        assert!(!captured[0].host.is_empty());

        assert_eq!(captured[1].action, "DeleteDomainRecord");
        assert_eq!(captured[1].query, "RecordId=987654321");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn aliyun_auto_detect_domain_and_describe_cleanup_fallback() {
        let dir = std::env::temp_dir().join(format!("exp-ali-auto-{}", Uuid::new_v4()));
        let mut cfg = MaintainerConfig::default();
        cfg.logger.segment.dir = dir.to_string_lossy().to_string();
        let svc = MaintainerService::new("maint-test-2", cfg).unwrap();

        let (base_url, reqs) = spawn_mock_alidns_server(vec![
            (
                200,
                r#"{"RequestId":"r1","DomainName":"example.co.uk","RR":"api"}"#.to_string(),
            ),
            (200, r#"{"RequestId":"r2","RecordId":"rec-555"}"#.to_string()),
            (
                200,
                r#"{"RequestId":"r3","DomainName":"example.co.uk","RR":"api"}"#.to_string(),
            ),
            (
                200,
                r#"{"RequestId":"r4","DomainRecords":{"Record":[{"RecordId":"rec-555","RR":"_acme-challenge.api","Type":"TXT","Value":"tok-xyz"}]}}"#.to_string(),
            ),
            (200, r#"{"RequestId":"r5","RecordId":"rec-555"}"#.to_string()),
        ])
        .await;

        let rec_id = svc
            .aliyun_present_with_base(
                &base_url,
                "LTAI5tAuto",
                "SecretAuto",
                None,
                "api.example.co.uk",
                "tok-xyz",
            )
            .await
            .expect("present auto ok");
        assert_eq!(rec_id.as_deref(), Some("rec-555"));

        // Cleanup without record_id exercises DescribeDomainRecords + DeleteDomainRecord fallback
        svc.aliyun_cleanup_with_base(
            &base_url,
            "LTAI5tAuto",
            "SecretAuto",
            None,
            "api.example.co.uk",
            "tok-xyz",
            None,
        )
        .await
        .expect("cleanup fallback ok");

        let captured = reqs.lock().await;
        assert_eq!(captured.len(), 5);
        assert_eq!(captured[0].action, "GetMainDomainName");
        assert_eq!(captured[0].query, "InputString=api.example.co.uk");
        assert_eq!(captured[1].action, "AddDomainRecord");
        assert_eq!(
            captured[1].query,
            "DomainName=example.co.uk&RR=_acme-challenge.api&TTL=600&Type=TXT&Value=tok-xyz"
        );
        assert_eq!(captured[2].action, "GetMainDomainName");
        assert_eq!(captured[3].action, "DescribeDomainRecords");
        assert_eq!(captured[4].action, "DeleteDomainRecord");
        assert_eq!(captured[4].query, "RecordId=rec-555");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn aliyun_present_surfaces_api_error() {
        let dir = std::env::temp_dir().join(format!("exp-ali-err-{}", Uuid::new_v4()));
        let mut cfg = MaintainerConfig::default();
        cfg.logger.segment.dir = dir.to_string_lossy().to_string();
        let svc = MaintainerService::new("maint-test-err", cfg).unwrap();

        let (base_url, _) = spawn_mock_alidns_server(vec![(
            400,
            r#"{"Code":"DomainRecordDuplicate","Message":"The DNS record already exists."}"#
                .to_string(),
        )])
        .await;

        let err = svc
            .aliyun_present_with_base(
                &base_url,
                "LTAI5tKey",
                "SecretVal",
                Some("example.com"),
                "example.com",
                "dup",
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("DomainRecordDuplicate"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cloudflare_zone_candidates_walk_subdomains() {
        assert_eq!(
            cloudflare_zone_candidates("*.a.b.example.com", None).unwrap(),
            vec!["a.b.example.com", "b.example.com", "example.com"]
        );
        assert_eq!(
            cloudflare_zone_candidates("api.example.com", Some("example.com")).unwrap(),
            vec!["example.com", "api.example.com"]
        );
    }

    #[tokio::test]
    async fn aliyun_declarative_dns_sync_creates_updates_and_deletes() {
        let dir = std::env::temp_dir().join(format!("exp-ali-sync-{}", Uuid::new_v4()));
        let mut cfg = MaintainerConfig::default();
        cfg.logger.segment.dir = dir.to_string_lossy().to_string();
        let svc = MaintainerService::new("maint-ali-sync", cfg).unwrap();

        let (base_url, reqs) = spawn_mock_alidns_server(vec![
            (
                200,
                r#"{"RequestId":"1","DomainName":"example.com","RR":"edge"}"#.to_string(),
            ),
            (
                200,
                r#"{"RequestId":"2","TotalCount":3,"DomainRecords":{"Record":[
                    {"RecordId":"r-keep","RR":"edge","Type":"A","Value":"1.1.1.1","TTL":600},
                    {"RecordId":"r-upd","RR":"edge","Type":"A","Value":"2.2.2.2","TTL":120},
                    {"RecordId":"r-stale","RR":"edge","Type":"A","Value":"9.9.9.9","TTL":600}
                ]}}"#
                    .to_string(),
            ),
            // UpdateDomainRecord for 2.2.2.2 (TTL 120 -> 600)
            (200, r#"{"RequestId":"3","RecordId":"r-upd"}"#.to_string()),
            // AddDomainRecord for 3.3.3.3
            (200, r#"{"RequestId":"4","RecordId":"r-new"}"#.to_string()),
            // AddDomainRecord for 2001:db8::1 (AAAA)
            (200, r#"{"RequestId":"5","RecordId":"r-v6"}"#.to_string()),
            // DeleteDomainRecord for stale 9.9.9.9
            (200, r#"{"RequestId":"6","RecordId":"r-stale"}"#.to_string()),
        ])
        .await;

        let spec = DnsSyncRecordSpec {
            domain: "edge.example.com".into(),
            ipv4s: vec!["1.1.1.1".into(), "2.2.2.2".into(), "3.3.3.3".into()],
            ipv6s: vec!["2001:db8::1".into()],
            line_entries: vec![],
            provider: Some("ali-1".into()),
            zone_id: None,
            root_domain: None,
            ttl: Some(600),
            proxied: None,
        };
        let res = svc
            .aliyun_sync_records_with_base(&base_url, "LTAI5tKey", "Secret", None, &spec)
            .await
            .expect("sync ok");
        assert!(res.ok);
        assert_eq!(res.unchanged, 1);
        assert_eq!(res.updated, 1);
        assert_eq!(res.created, 2);
        assert_eq!(res.deleted, 1);

        let captured = reqs.lock().await;
        assert_eq!(captured[0].action, "GetMainDomainName");
        assert_eq!(captured[1].action, "DescribeDomainRecords");
        assert_eq!(captured[2].action, "UpdateDomainRecord");
        assert_eq!(captured[3].action, "AddDomainRecord");
        assert_eq!(captured[4].action, "AddDomainRecord");
        assert_eq!(captured[5].action, "DeleteDomainRecord");
        assert_eq!(captured[5].query, "RecordId=r-stale");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[derive(Debug, Clone)]
    struct CfRecordedReq {
        method: String,
        target: String,
        body: String,
    }

    async fn spawn_mock_cf_server(
        responses: Vec<(u16, String)>,
    ) -> (String, Arc<Mutex<Vec<CfRecordedReq>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let rec_clone = Arc::clone(&recorded);
        tokio::spawn(async move {
            for (status, body) in responses {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = vec![0u8; 16384];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let req_str = String::from_utf8_lossy(&buf[..n]).to_string();
                let (head, req_body) = req_str.split_once("\r\n\r\n").unwrap_or((&req_str, ""));
                let first = head.lines().next().unwrap_or("");
                let mut parts = first.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let target = parts.next().unwrap_or("").to_string();
                rec_clone.lock().await.push(CfRecordedReq {
                    method,
                    target,
                    body: req_body.to_string(),
                });
                let resp = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        });
        (format!("http://{addr}"), recorded)
    }

    #[tokio::test]
    async fn cloudflare_auto_zone_lookup_and_declarative_sync() {
        let dir = std::env::temp_dir().join(format!("exp-cf-sync-{}", Uuid::new_v4()));
        let mut cfg = MaintainerConfig::default();
        cfg.logger.segment.dir = dir.to_string_lossy().to_string();
        let svc = MaintainerService::new("maint-cf-sync", cfg).unwrap();

        let (base_url, reqs) = spawn_mock_cf_server(vec![
            // 1. GET /zones?name=app.example.com -> empty
            (200, r#"{"success":true,"result":[]}"#.to_string()),
            // 2. GET /zones?name=example.com -> found zone-abc
            (
                200,
                r#"{"success":true,"result":[{"id":"zone-abc","name":"example.com"}]}"#.to_string(),
            ),
            // 3. GET A records
            (
                200,
                r#"{"success":true,"result_info":{"total_pages":1},"result":[
                    {"id":"cf-1","type":"A","name":"app.example.com","content":"1.2.3.4","ttl":120,"proxied":false},
                    {"id":"cf-old","type":"A","name":"app.example.com","content":"9.9.9.9","ttl":120,"proxied":false}
                ]}"#
                    .to_string(),
            ),
            // 4. PATCH cf-1 (proxied false -> true)
            (200, r#"{"success":true,"result":{"id":"cf-1"}}"#.to_string()),
            // 5. POST 5.6.7.8
            (200, r#"{"success":true,"result":{"id":"cf-2"}}"#.to_string()),
            // 6. DELETE cf-old
            (200, r#"{"success":true,"result":{"id":"cf-old"}}"#.to_string()),
            // 7. GET AAAA records (empty)
            (
                200,
                r#"{"success":true,"result_info":{"total_pages":1},"result":[]}"#.to_string(),
            ),
            // 8. GET CNAME records (empty)
            (
                200,
                r#"{"success":true,"result_info":{"total_pages":1},"result":[]}"#.to_string(),
            ),
        ])
        .await;

        let spec = DnsSyncRecordSpec {
            domain: "app.example.com".into(),
            ipv4s: vec!["1.2.3.4".into(), "5.6.7.8".into()],
            ipv6s: vec![],
            line_entries: vec![],
            provider: Some("cf-1".into()),
            zone_id: None,
            root_domain: None,
            ttl: Some(120),
            proxied: Some(true),
        };
        let res = svc
            .cloudflare_sync_records_with_base(&base_url, "cf-token", None, None, &spec)
            .await
            .expect("cf sync ok");
        assert!(res.ok);
        assert_eq!(res.updated, 1);
        assert_eq!(res.created, 1);
        assert_eq!(res.deleted, 1);
        assert_eq!(res.unchanged, 0);

        let captured = reqs.lock().await;
        assert_eq!(captured[0].target, "/zones?name=app.example.com");
        assert_eq!(captured[1].target, "/zones?name=example.com");
        assert_eq!(captured[3].method, "PATCH");
        assert!(captured[3].body.contains("\"proxied\":true"));
        assert_eq!(captured[4].method, "POST");
        assert!(captured[4].body.contains("\"content\":\"5.6.7.8\""));
        assert_eq!(captured[5].method, "DELETE");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn sync_dns_records_refuses_empty_ips_and_missing_provider() {
        let dir = std::env::temp_dir().join(format!("exp-sync-guard-{}", Uuid::new_v4()));
        let mut cfg = MaintainerConfig::default();
        cfg.logger.segment.dir = dir.to_string_lossy().to_string();
        let svc = MaintainerService::new("maint-sync-guard", cfg).unwrap();

        let results = svc
            .sync_dns_records(&[
                DnsSyncRecordSpec {
                    domain: "empty.example.com".into(),
                    ipv4s: vec![],
                    ipv6s: vec![],
                    line_entries: vec![],
                    provider: Some("cf".into()),
                    zone_id: None,
                    root_domain: None,
                    ttl: None,
                    proxied: None,
                },
                DnsSyncRecordSpec {
                    domain: "noprov.example.com".into(),
                    ipv4s: vec!["1.1.1.1".into()],
                    ipv6s: vec![],
                    line_entries: vec![],
                    provider: None,
                    zone_id: None,
                    root_domain: None,
                    ttl: None,
                    proxied: None,
                },
            ])
            .await;

        assert_eq!(results.len(), 2);
        assert!(!results[0].ok);
        assert!(results[0].error.as_deref().unwrap().contains("zero target"));
        assert!(!results[1].ok);
        assert!(
            results[1]
                .error
                .as_deref()
                .unwrap()
                .contains("no DNS provider")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn aliyun_split_horizon_lines_and_remote_inspect() {
        let dir = std::env::temp_dir().join(format!("exp-ali-split-{}", Uuid::new_v4()));
        let mut cfg = MaintainerConfig::default();
        cfg.logger.segment.dir = dir.to_string_lossy().to_string();
        let svc = MaintainerService::new("maint-ali-split", cfg).unwrap();

        let (base_url, reqs) = spawn_mock_alidns_server(vec![
            // DescribeDomainRecords: telecom has old IP, oversea is unmanaged and MUST remain untouched!
            (
                200,
                r#"{"TotalCount":3,"DomainRecords":{"Record":[
                    {"RecordId":"r-def","RR":"app","Type":"A","Value":"1.1.1.1","Line":"default","TTL":600,"Status":"ENABLE"},
                    {"RecordId":"r-ct-old","RR":"app","Type":"A","Value":"9.9.9.9","Line":"telecom","TTL":600,"Status":"ENABLE"},
                    {"RecordId":"r-os","RR":"app","Type":"A","Value":"8.8.8.8","Line":"oversea","TTL":600,"Status":"ENABLE"}
                ]}}"#
                    .to_string(),
            ),
            // AddDomainRecord for telecom 2.2.2.2
            (200, r#"{"RequestId":"2","RecordId":"r-ct-new"}"#.to_string()),
            // DeleteDomainRecord for r-ct-old (r-os untouched!)
            (200, r#"{"RequestId":"3","RecordId":"r-ct-old"}"#.to_string()),
        ])
        .await;

        let spec = DnsSyncRecordSpec {
            domain: "app.example.com".into(),
            ipv4s: vec![],
            ipv6s: vec![],
            line_entries: vec![
                DnsLineSyncEntry {
                    line: "default".into(),
                    ipv4s: vec!["1.1.1.1".into()],
                    ipv6s: vec![],
                    cnames: vec![],
                    ttl: Some(600),
                    proxied: None,
                },
                DnsLineSyncEntry {
                    line: "telecom".into(),
                    ipv4s: vec!["2.2.2.2".into()],
                    ipv6s: vec![],
                    cnames: vec![],
                    ttl: Some(600),
                    proxied: None,
                },
            ],
            provider: Some("ali-1".into()),
            zone_id: None,
            root_domain: Some("example.com".into()),
            ttl: Some(600),
            proxied: None,
        };
        let res = svc
            .aliyun_sync_records_with_base(
                &base_url,
                "LTAI5tKey",
                "Secret",
                Some("example.com"),
                &spec,
            )
            .await
            .expect("split sync ok");
        assert!(res.ok);
        assert_eq!(res.unchanged, 1);
        assert_eq!(res.created, 1);
        assert_eq!(res.deleted, 1);

        let captured = reqs.lock().await;
        assert_eq!(captured[1].action, "AddDomainRecord");
        assert!(captured[1].query.contains("Line=telecom"));
        assert!(captured[1].query.contains("Value=2.2.2.2"));
        assert_eq!(captured[2].action, "DeleteDomainRecord");
        assert_eq!(captured[2].query, "RecordId=r-ct-old");

        // Now test Inspect with DescribeSupportLines
        let (base_url2, _) = spawn_mock_alidns_server(vec![
            (
                200,
                r#"{"TotalCount":2,"DomainRecords":{"Record":[
                    {"RecordId":"r-1","RR":"app","Type":"A","Value":"1.1.1.1","Line":"default","TTL":600,"Status":"ENABLE"},
                    {"RecordId":"r-txt","RR":"app","Type":"TXT","Value":"v=spf1","Line":"default","TTL":600,"Status":"ENABLE"}
                ]}}"#
                    .to_string(),
            ),
            (
                200,
                r#"{"RecordLines":{"RecordLine":[
                    {"LineCode":"default","LineDisplayName":"默认"},
                    {"LineCode":"telecom","LineDisplayName":"中国电信","FatherCode":"isp"}
                ]}}"#
                    .to_string(),
            ),
        ])
        .await;

        let (caps, lines, recs, _) = svc
            .aliyun_manage_with_base(
                &base_url2,
                "LTAI5tKey",
                "Secret",
                Some("example.com"),
                &DnsManageOp::Inspect {
                    domain: "app.example.com".into(),
                    include_lines: true,
                },
            )
            .await
            .expect("inspect ok");
        assert!(caps.supports_lines);
        assert!(caps.supports_status_toggle);
        assert_eq!(lines.len(), 2);
        // TXT record MUST be filtered out — Exposure only exposes A/AAAA/CNAME
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].record_id, "r-1");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn maintainer_persists_state_across_restart_and_prunes_limits() {
        use exposure_core::telemetry::{HyperLogLog, LatencyHistogram};
        use std::collections::BTreeMap;

        let dir =
            std::env::temp_dir().join(format!("exposure-maint-persist-{}", uuid::Uuid::new_v4()));
        let mut cfg = MaintainerConfig::default();
        cfg.logger.segment.dir = dir.to_string_lossy().to_string();
        cfg.logger.retention.stats_retention_days = 1;
        cfg.logger.retention.max_summaries = 100;
        cfg.logger.retention.max_fingerprints = 100;

        let svc = MaintainerService::new("maint-1", cfg.clone()).unwrap();
        let now_min = (Utc::now().timestamp() / 60) * 60;
        let fresh_sum = MinuteSummary {
            minute_epoch: now_min,
            node_tag: "edge-1".into(),
            role: "ingress".into(),
            service_tag: "web".into(),
            requests: 42,
            errors: 1,
            rate_limited: 2,
            challenges_issued: 3,
            challenges_passed: 2,
            blocked: 0,
            evilpot_hits: 0,
            autoban_hits: 0,
            bytes_in: 1000,
            bytes_out: 4000,
            uv_hll: HyperLogLog::new(12, 0),
            latency_hist: LatencyHistogram::new(vec![10.0, 50.0, 100.0]),
            device_counts: BTreeMap::new(),
            browser_counts: BTreeMap::new(),
            os_counts: BTreeMap::new(),
            client_fp_verified: 1,
            cached_requests: 0,
            cached_bytes_out: 0,
        };
        let expired_sum = MinuteSummary {
            minute_epoch: now_min - 48 * 3600, // older than 1d stats_retention_days -> MUST be pruned!
            ..fresh_sum.clone()
        };
        let ingested = svc
            .ingest_log_batch(
                "edge-1",
                vec![],
                vec![fresh_sum, expired_sum],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
            )
            .await;
        assert_eq!(
            ingested, 1,
            "expired summary older than stats_retention_days must be dropped"
        );

        svc.flush_segments().await.unwrap();
        drop(svc);

        // Simulate full Maintainer process restart: new instance loads persisted state from SQLite!
        let restored = MaintainerService::new("maint-1", cfg).unwrap();
        let snap = restored.build_telemetry_snapshot(None).await;
        assert_eq!(snap.summaries.len(), 1);
        assert_eq!(snap.summaries[0].requests, 42);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn x509_not_after_der_and_pem_parsing() {
        let (cert_pem, _) = generate_self_signed_pem("cert-parse.example.com").unwrap();
        let exp = parse_x509_not_after_unix(&cert_pem).expect("parse rcgen X.509 notAfter");
        assert!(exp > Utc::now().timestamp());

        // Direct UTCTime & GeneralizedTime vector checks
        let utc_ts = parse_asn1_time_unix(0x17, b"291231235959Z").unwrap();
        let gen_ts = parse_asn1_time_unix(0x18, b"20550615120000Z").unwrap();
        assert!(utc_ts < gen_ts);
        assert!(parse_asn1_time_unix(0x17, b"bad").is_none());

        // ACME challenge domain tamper rejection
        assert!(ensure_non_acme_sync_domain("_acme-challenge.app.example.com").is_err());
        assert!(ensure_non_acme_sync_domain("sub._acme-challenge.example.com").is_err());
        assert!(ensure_non_acme_sync_domain("*").is_err());
        assert!(ensure_non_acme_sync_domain("app.example.com").is_ok());
    }
}
