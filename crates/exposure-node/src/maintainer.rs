use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::path::Path;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use exposure_core::config::{
    resolve_domain_binding, CertOrderConfig, DnsProviderAccountConfig, DomainBindingConfig,
    MaintainerConfig,
};
use exposure_core::crypto::{validate_dns_domain, write_secret_file_atomic, NodeKeyPair};
use exposure_core::protocol::{
    cert_bundle_signing_bytes, DnsSyncDomainResult, DnsSyncRecordSpec, MaintainerTelemetrySnapshot,
    SpecialFrame, SpecialPayload,
};
use exposure_core::routing::canonical_ip;
use exposure_core::segment::SegmentWriter;
use exposure_core::telemetry::{
    AlertRecord, CertStatusInfo, FingerprintObservation, MinuteSummary, SessionSummary,
};
use exposure_core::{ExposureError, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::process::Command;
use tokio::sync::{watch, Mutex, RwLock};
use tracing::{info, warn};
use uuid::Uuid;

use crate::forwarder::Forwarder;
use crate::tls::generate_self_signed_pem;

const MAX_MERGED_SUMMARIES: usize = 50_000;
const MAX_MERGED_FINGERPRINTS: usize = 20_000;
const EXEC_HOOK_TIMEOUT: Duration = Duration::from_secs(30);
const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(15);
const ALIDNS_API_VERSION: &str = "2015-01-09";
const EMPTY_BODY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn validate_cloudflare_id(val: &str, field: &str) -> Result<()> {
    let s = val.trim();
    if s.is_empty()
        || s.len() > 64
        || !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
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
        || ak.chars().any(|c| c.is_control() || c.is_whitespace() || c == ',')
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
        || !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(ExposureError::Config(format!(
            "invalid Aliyun DNS record_id: '{val}'"
        )));
    }
    Ok(())
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
            return Err(ExposureError::Config(format!(
                "invalid root_domain '{rd}'"
            )));
        }
        validate_dns_domain(clean_rd)?;
        out.push(clean_rd.to_string());
    }

    let base = domain
        .trim()
        .trim_start_matches("*.")
        .trim_end_matches('.');
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
        if !out.iter().any(|existing| existing.eq_ignore_ascii_case(&cand)) {
            out.push(cand);
        }
    }
    Ok(out)
}

fn is_forbidden_ssrf_ip(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000) == 64) // CGNAT 100.64.0.0/10
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // Link-local fe80::/10
        }
    }
}

async fn validate_webhook_url(raw_url: &str) -> Result<()> {
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
    let addrs: Vec<std::net::SocketAddr> = tokio::task::spawn_blocking(move || {
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
    for addr in addrs {
        if is_forbidden_ssrf_ip(addr.ip()) {
            return Err(ExposureError::AccessDenied(format!(
                "webhook target '{host}' resolved to forbidden private/internal IP {}",
                addr.ip()
            )));
        }
    }
    Ok(())
}

/// Maintainer Mode Service (DESIGN.md §4, §12, §13):
/// - Aggregation logger: merges per-(node, minute, service) summaries via counter sums, HLL union,
///   and fixed-bucket latency histogram addition, writing merged segments asynchronously via `spawn_blocking`.
/// - ACME DNS01 certificate lifecycle (Cloudflare, Aliyun DNS, HTTPS-only SSRF-checked Webhook, timeout-bounded Exec Hook),
///   signing bundles per target node with Maintainer's Ed25519 key and distributing along Hop tables.
pub struct MaintainerService {
    node_tag: String,
    cfg: Arc<RwLock<MaintainerConfig>>,
    merged_summaries: Arc<Mutex<HashMap<(i64, String, String, String), MinuteSummary>>>,
    merged_fingerprints: Arc<Mutex<HashMap<String, FingerprintObservation>>>,
    segment_writer: Arc<StdMutex<SegmentWriter<SessionSummary>>>,
    cert_statuses: Arc<Mutex<HashMap<String, CertStatusInfo>>>,
    alerts: Arc<Mutex<Vec<AlertRecord>>>,
    last_merge_latency_ms: Arc<Mutex<f64>>,
    http_client: reqwest::Client,
    shutdown_tx: watch::Sender<bool>,
}

impl MaintainerService {
    pub fn new(node_tag: impl Into<String>, cfg: MaintainerConfig) -> Result<Arc<Self>> {
        let tag = node_tag.into();
        let writer = SegmentWriter::new(cfg.logger.segment.clone(), format!("maintainer-{tag}"))?;
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
            merged_summaries: Arc::new(Mutex::new(HashMap::new())),
            merged_fingerprints: Arc::new(Mutex::new(HashMap::new())),
            segment_writer: Arc::new(StdMutex::new(writer)),
            cert_statuses: Arc::new(Mutex::new(cert_map)),
            alerts: Arc::new(Mutex::new(Vec::new())),
            last_merge_latency_ms: Arc::new(Mutex::new(0.0)),
            http_client,
            shutdown_tx,
        }))
    }

    pub fn stop_background_tasks(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    pub async fn update_config(&self, cfg: MaintainerConfig) -> Result<()> {
        let writer = Arc::clone(&self.segment_writer);
        let seg_cfg = cfg.logger.segment.clone();
        let prefix = format!("maintainer-{}", self.node_tag);
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut w = writer.lock().unwrap_or_else(|e| e.into_inner());
            let _ = w.flush();
            *w = SegmentWriter::new(seg_cfg, prefix)?;
            Ok(())
        })
        .await
        .map_err(|e| ExposureError::Storage(format!("maintainer update join: {e}")))??;

        {
            let mut cs = self.cert_statuses.lock().await;
            for order in &cfg.acme.orders {
                cs.entry(order.domain.clone()).or_insert_with(|| CertStatusInfo {
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

    /// Merge incoming LogBatch from an authenticated Node (bounded timestamps, bounded maps, respects `store_raw_ip`).
    pub async fn ingest_log_batch(
        &self,
        from_node: &str,
        mut records: Vec<SessionSummary>,
        summaries: Vec<MinuteSummary>,
        fingerprints: Vec<FingerprintObservation>,
    ) -> usize {
        let start = Instant::now();
        let store_raw_ip = self.cfg.read().await.logger.store_raw_ip;
        let now_ts = Utc::now().timestamp();
        let min_cutoff = now_ts.saturating_sub(86_400);
        let max_allowed = now_ts.saturating_add(300);

        // Enforce Maintainer's `store_raw_ip` privacy policy and cap batch size
        records.truncate(2048);
        if !store_raw_ip {
            for r in &mut records {
                r.raw_ip = None;
            }
        }

        let rec_count = records.len();
        if !records.is_empty() {
            let writer = Arc::clone(&self.segment_writer);
            let from_owned = from_node.to_string();
            let _ = tokio::task::spawn_blocking(move || {
                let mut w = writer.lock().unwrap_or_else(|e| e.into_inner());
                for rec in records {
                    if let Err(e) = w.push(rec) {
                        warn!(from = %from_owned, error = %e, "maintainer segment write failed");
                    }
                }
            })
            .await;
        }

        let mut accepted_summaries = 0usize;
        {
            let mut map = self.merged_summaries.lock().await;
            for s in summaries.into_iter().take(1024) {
                if s.minute_epoch < min_cutoff || s.minute_epoch > max_allowed {
                    continue;
                }
                if !s.uv_hll.is_valid() {
                    continue;
                }
                let key = (
                    s.minute_epoch,
                    s.node_tag.clone(),
                    s.role.clone(),
                    s.service_tag.clone(),
                );
                if map.len() >= MAX_MERGED_SUMMARIES && !map.contains_key(&key) {
                    continue;
                }
                map.entry(key)
                    .and_modify(|existing| existing.merge_from(&s))
                    .or_insert(s);
                accepted_summaries += 1;
            }
            map.retain(|(min, _, _, _), _| *min >= min_cutoff && *min <= max_allowed);
        }

        let mut accepted_fps = 0usize;
        if !fingerprints.is_empty() {
            let mut fp_map = self.merged_fingerprints.lock().await;
            for mut fp in fingerprints.into_iter().take(2048) {
                if fp.last_seen_ts < min_cutoff || fp.last_seen_ts > max_allowed {
                    continue;
                }
                if !store_raw_ip {
                    fp.client_ip = None;
                }
                fp.sanitize();
                if fp.id.is_empty() {
                    continue;
                }
                if fp_map.len() >= MAX_MERGED_FINGERPRINTS && !fp_map.contains_key(&fp.id) {
                    continue;
                }
                fp_map
                    .entry(fp.id.clone())
                    .and_modify(|existing| existing.merge_from(&fp))
                    .or_insert(fp);
                accepted_fps += 1;
            }
            fp_map.retain(|_, v| v.last_seen_ts >= min_cutoff && v.last_seen_ts <= max_allowed);
        }

        *self.last_merge_latency_ms.lock().await = start.elapsed().as_secs_f64() * 1000.0;
        rec_count + accepted_summaries + accepted_fps
    }

    pub async fn flush_segments(&self) -> Result<()> {
        let writer = Arc::clone(&self.segment_writer);
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut w = writer.lock().unwrap_or_else(|e| e.into_inner());
            let _ = w.flush()?;
            Ok(())
        })
        .await
        .map_err(|e| ExposureError::Storage(format!("maintainer flush join: {e}")))?
    }

    /// Build telemetry snapshot for Control's active Pull RPC.
    pub async fn build_telemetry_snapshot(
        &self,
        since_minute: Option<i64>,
    ) -> MaintainerTelemetrySnapshot {
        let summaries = {
            let map = self.merged_summaries.lock().await;
            map.values()
                .filter(|s| since_minute.map(|m| s.minute_epoch >= m).unwrap_or(true))
                .cloned()
                .collect()
        };
        let fingerprints = {
            let fp_map = self.merged_fingerprints.lock().await;
            let mut list: Vec<FingerprintObservation> = fp_map
                .values()
                .filter(|f| since_minute.map(|m| f.last_seen_ts >= m).unwrap_or(true))
                .cloned()
                .collect();
            list.sort_by(|a, b| b.last_seen_ts.cmp(&a.last_seen_ts));
            list.truncate(5000);
            list
        };
        let certificates = self
            .cert_statuses
            .lock()
            .await
            .values()
            .cloned()
            .collect();
        let segment_backlog = self
            .segment_writer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pending_count();
        let merge_latency_ms = *self.last_merge_latency_ms.lock().await;
        let alerts = self.alerts.lock().await.clone();

        MaintainerTelemetrySnapshot {
            maintainer_tag: self.node_tag.clone(),
            summaries,
            fingerprints,
            certificates,
            segment_backlog,
            merge_latency_ms,
            alerts,
        }
    }

    pub async fn record_alert(&self, severity: &str, message: impl Into<String>) {
        let mut a = self.alerts.lock().await;
        let clean: String = message
            .into()
            .chars()
            .filter(|c| !c.is_control() || *c == ' ')
            .take(512)
            .collect();
        a.push(AlertRecord {
            timestamp: Utc::now().to_rfc3339(),
            source: self.node_tag.clone(),
            severity: severity.to_string(),
            message: clean,
        });
        if a.len() > 200 {
            let drain = a.len() - 200;
            a.drain(0..drain);
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
        let auth = sign_aliyun_v3_post(&host_header, action, &canonical_query, ak, sk, date, nonce)?;

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

        let ttl = spec.ttl.unwrap_or(600).max(1);
        let ttl_str = ttl.to_string();

        // Paginate DescribeDomainRecords to capture all existing A / AAAA records for this RR
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
                if rec_rr.eq_ignore_ascii_case(&rr) && (rec_type == "A" || rec_type == "AAAA") {
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

        for (rtype, desired_list) in [("A", &spec.ipv4s), ("AAAA", &spec.ipv6s)] {
            let desired: BTreeSet<&str> = desired_list.iter().map(|s| s.as_str()).collect();
            let mut matched_ips: HashSet<String> = HashSet::new();

            for rec in existing.iter().filter(|r| r["Type"].as_str() == Some(rtype)) {
                let val = rec["Value"].as_str().unwrap_or("");
                let Some(rec_id) = rec["RecordId"]
                    .as_str()
                    .map(str::to_string)
                    .or_else(|| rec["RecordId"].as_u64().map(|n| n.to_string()))
                else {
                    continue;
                };
                validate_aliyun_record_id(&rec_id)?;

                if desired.contains(val) && matched_ips.insert(val.to_string()) {
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
                                ("Value", val),
                                ("TTL", &ttl_str),
                            ],
                        )
                        .await?;
                        updated += 1;
                    } else {
                        unchanged += 1;
                    }
                } else {
                    to_delete.push(rec_id);
                }
            }

            // Create missing records before deleting stale ones to avoid resolution gaps
            for ip in &desired {
                if !matched_ips.contains(*ip) {
                    self.call_alidns_api(
                        base_url,
                        access_key_id,
                        access_key_secret,
                        "AddDomainRecord",
                        &[
                            ("DomainName", &root_domain),
                            ("RR", &rr),
                            ("Type", rtype),
                            ("Value", ip),
                            ("TTL", &ttl_str),
                        ],
                    )
                    .await?;
                    created += 1;
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
        let url = format!("{}/zones/{zone_id}/dns_records", cf_base.trim_end_matches('/'));
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
        let ttl = spec.ttl.unwrap_or(600).max(1);
        let proxied = spec.proxied.unwrap_or(false);

        let mut created = 0usize;
        let mut updated = 0usize;
        let mut deleted = 0usize;
        let mut unchanged = 0usize;

        for (rtype, desired_list) in [("A", &spec.ipv4s), ("AAAA", &spec.ipv6s)] {
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
                let content = rec["content"].as_str().unwrap_or("");
                if desired.contains(content) && matched_ips.insert(content.to_string()) {
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
                                "content": content,
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
                let body: serde_json::Value = resp.json().await.map_err(|e| {
                    ExposureError::Protocol(format!("cloudflare delete json: {e}"))
                })?;
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

    /// Execute Control-authorized declarative DNS A/AAAA sync for one or more domains
    /// using this Maintainer's local `dns_providers` credentials.
    pub async fn sync_dns_records(&self, records: &[DnsSyncRecordSpec]) -> Vec<DnsSyncDomainResult> {
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
        if spec.domain.trim() == "*" {
            return Err(ExposureError::Config(
                "cannot sync DNS records for bare wildcard '*'".into(),
            ));
        }
        for raw in &spec.ipv4s {
            let ip: Ipv4Addr = raw.trim().parse().map_err(|_| {
                ExposureError::Config(format!("invalid IPv4 address '{raw}' in DnsSyncReq"))
            })?;
            if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
                return Err(ExposureError::Config(format!(
                    "disallowed IPv4 address '{raw}' in DnsSyncReq"
                )));
            }
        }
        for raw in &spec.ipv6s {
            let ip: Ipv6Addr = raw.trim().parse().map_err(|_| {
                ExposureError::Config(format!("invalid IPv6 address '{raw}' in DnsSyncReq"))
            })?;
            if ip.is_unspecified() || ip.is_multicast() {
                return Err(ExposureError::Config(format!(
                    "disallowed IPv6 address '{raw}' in DnsSyncReq"
                )));
            }
        }
        if spec.ipv4s.is_empty() && spec.ipv6s.is_empty() {
            return Err(ExposureError::Config(format!(
                "refusing to sync '{}' with zero target IPs",
                spec.domain
            )));
        }

        let binding = resolve_domain_binding(&cfg.domains, &spec.domain).map(|(_, b)| b);
        let provider_name = spec
            .provider
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| binding.map(|b| b.provider.trim()))
            .ok_or_else(|| {
                ExposureError::Config(format!(
                    "domain '{}' has no DNS provider configured",
                    spec.domain
                ))
            })?;
        let provider = cfg.dns_providers.get(provider_name).ok_or_else(|| {
            ExposureError::Config(format!(
                "maintainer missing DNS provider credentials for '{provider_name}'"
            ))
        })?;

        let eff_zone_id = spec
            .zone_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| binding.and_then(|b| b.zone_id.as_deref()));
        let eff_root = spec
            .root_domain
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| binding.and_then(|b| b.root_domain.as_deref()));
        let eff_ttl = spec.ttl.or_else(|| binding.map(|b| b.ttl));
        let eff_proxied = spec.proxied.or_else(|| binding.map(|b| b.proxied));

        let eff_spec = DnsSyncRecordSpec {
            domain: spec.domain.clone(),
            ipv4s: spec.ipv4s.clone(),
            ipv6s: spec.ipv6s.clone(),
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
                validate_webhook_url(url).await?;
                let mut req = self.http_client.post(url).json(&serde_json::json!({
                    "action": "sync",
                    "domain": eff_spec.domain,
                    "ipv4s": eff_spec.ipv4s,
                    "ipv6s": eff_spec.ipv6s,
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
                let status = tokio::time::timeout(
                    EXEC_HOOK_TIMEOUT,
                    Command::new(command)
                        .args(args)
                        .arg("sync")
                        .arg(&eff_spec.domain)
                        .arg(eff_spec.ipv4s.join(","))
                        .arg(eff_spec.ipv6s.join(","))
                        .status(),
                )
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
                validate_webhook_url(present_url).await?;
                let mut req = self.http_client.post(present_url).json(&serde_json::json!({
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
                let status = tokio::time::timeout(
                    EXEC_HOOK_TIMEOUT,
                    Command::new(command)
                        .args(args)
                        .arg("present")
                        .arg(&fqdn)
                        .arg(txt_value)
                        .status(),
                )
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
                validate_webhook_url(cleanup_url).await?;
                let mut req = self.http_client.post(cleanup_url).json(&serde_json::json!({
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
                let _ = tokio::time::timeout(
                    EXEC_HOOK_TIMEOUT,
                    Command::new(command)
                        .args(args)
                        .arg("cleanup")
                        .arg(&fqdn)
                        .arg(txt_value)
                        .status(),
                )
                .await;
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
        let signing_secret = cfg
            .cert_signing_secret_key
            .as_deref()
            .ok_or_else(|| {
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

        let (cert_pem, key_pem) = if cfg.acme.directory_url.eq_ignore_ascii_case("self-signed")
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
            return Err(ExposureError::Config(format!(
                "ACME directory '{}' requires a full ACME client implementation; use directory_url: \"self-signed\" for dev/self-signed issuance",
                cfg.acme.directory_url
            )));
        };

        // Persist certificate locally on Maintainer (strict domain validation + atomic 0600 private key!)
        if !cfg.acme.storage_dir.is_empty() {
            let dir = Path::new(&cfg.acme.storage_dir);
            std::fs::create_dir_all(dir)?;
            let safe = order.domain.replace('*', "_wildcard_");
            std::fs::write(dir.join(format!("{safe}.crt.pem")), &cert_pem)?;
            let key_path = dir.join(format!("{safe}.key.pem"));
            write_secret_file_atomic(&key_path, key_pem.as_bytes())?;
        }

        let now = Utc::now();
        let issued_at = now.timestamp();
        let expires_at = (now + ChronoDuration::days(90)).timestamp();

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
                    all_ok = false;
                    let msg = format!(
                        "cert apply failed on {} for {}: {:?}",
                        node_tag, order.domain, error
                    );
                    warn!("{msg}");
                    self.record_alert("error", msg).await;
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
        cs.insert(
            order.domain.clone(),
            CertStatusInfo {
                domain: order.domain.clone(),
                targets: order.target_nodes.clone(),
                expires_at: Some((now + ChronoDuration::days(90)).to_rfc3339()),
                last_renewed: Some(now.to_rfc3339()),
                status: if all_ok { "valid".into() } else { "degraded".into() },
            },
        );
        Ok(())
    }

    pub fn spawn_background_tasks(self: &Arc<Self>, forwarder: Arc<Forwarder>) {
        let this = Arc::clone(self);
        let mut rx1 = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
            loop {
                let flush_secs = this
                    .cfg
                    .read()
                    .await
                    .logger
                    .segment
                    .flush_interval_secs
                    .max(2);
                tokio::select! {
                    _ = rx1.changed() => {
                        if *rx1.borrow() {
                            return;
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_secs(flush_secs)) => {}
                }
                if let Err(e) = this.flush_segments().await {
                    warn!(error = %e, "maintainer periodic segment flush failed");
                }
            }
        });

        // Periodic certificate renewal check honoring `order.renew_before_days`
        let this2 = Arc::clone(self);
        let mut rx2 = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
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
                                            let renew_at = exp_dt.with_timezone(&Utc)
                                                - ChronoDuration::days(order.renew_before_days as i64);
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
                            warn!(domain = %order.domain, error = %e, "certificate renewal failed");
                            this2
                                .record_alert(
                                    "error",
                                    format!("cert renew {} failed: {e}", order.domain),
                                )
                                .await;
                        }
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn aliyun_percent_encode_and_canonical_query() {
        assert_eq!(aliyun_percent_encode("abc-123_456.789~"), "abc-123_456.789~");
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
                let query = target.split_once('?').map(|(_, q)| q).unwrap_or("").to_string();

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
            (200, r#"{"RequestId":"req-2","RecordId":"987654321"}"#.to_string()),
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
        assert!(captured[0]
            .authorization
            .starts_with("ACS3-HMAC-SHA256 Credential=LTAI5tKey,"));
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
        ])
        .await;

        let spec = DnsSyncRecordSpec {
            domain: "app.example.com".into(),
            ipv4s: vec!["1.2.3.4".into(), "5.6.7.8".into()],
            ipv6s: vec![],
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
        assert!(results[0].error.as_deref().unwrap().contains("zero target IPs"));
        assert!(!results[1].ok);
        assert!(results[1]
            .error
            .as_deref()
            .unwrap()
            .contains("no DNS provider"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
