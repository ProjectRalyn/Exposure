use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use exposure_core::config::{CertOrderConfig, Dns01ProviderConfig, MaintainerConfig};
use exposure_core::crypto::{validate_dns_domain, write_secret_file_atomic, NodeKeyPair};
use exposure_core::protocol::{
    cert_bundle_signing_bytes, MaintainerTelemetrySnapshot, SpecialFrame, SpecialPayload,
};
use exposure_core::routing::canonical_ip;
use exposure_core::segment::SegmentWriter;
use exposure_core::telemetry::{
    AlertRecord, CertStatusInfo, FingerprintObservation, MinuteSummary, SessionSummary,
};
use exposure_core::{ExposureError, Result};
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
/// - ACME DNS01 certificate lifecycle (Cloudflare, HTTPS-only SSRF-checked Webhook, timeout-bounded Exec Hook),
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

    /// Present a DNS-01 TXT record via the configured provider (Cloudflare, HTTPS Webhook, Exec Hook).
    pub async fn dns01_present(
        &self,
        provider: &Dns01ProviderConfig,
        domain: &str,
        txt_value: &str,
    ) -> Result<Option<String>> {
        validate_dns_domain(domain)?;
        let fqdn = format!("_acme-challenge.{}", domain.trim_start_matches("*."));
        match provider {
            Dns01ProviderConfig::Cloudflare { api_token, zone_id } => {
                validate_cloudflare_id(zone_id, "zone_id")?;
                let url = format!(
                    "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
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
            Dns01ProviderConfig::Webhook {
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
                if let Some(ref h) = auth_header {
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
            Dns01ProviderConfig::Exec { command, args } => {
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
        provider: &Dns01ProviderConfig,
        domain: &str,
        txt_value: &str,
        record_id: Option<&str>,
    ) -> Result<()> {
        validate_dns_domain(domain)?;
        let fqdn = format!("_acme-challenge.{}", domain.trim_start_matches("*."));
        match provider {
            Dns01ProviderConfig::Cloudflare { api_token, zone_id } => {
                validate_cloudflare_id(zone_id, "zone_id")?;
                if let Some(id) = record_id {
                    validate_cloudflare_id(id, "record_id")?;
                    let url = format!(
                        "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{id}"
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
            Dns01ProviderConfig::Webhook {
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
                if let Some(ref h) = auth_header {
                    req = req.header("Authorization", h);
                }
                let _ = req.send().await;
                Ok(())
            }
            Dns01ProviderConfig::Exec { command, args } => {
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

        let (cert_pem, key_pem) = if cfg.acme.directory_url.eq_ignore_ascii_case("self-signed")
            || cfg.acme.directory_url.is_empty()
        {
            if let Some(provider) = cfg.acme.providers.get(&order.provider) {
                let challenge_val = Uuid::new_v4().to_string();
                let rec_id = self
                    .dns01_present(provider, &order.domain, &challenge_val)
                    .await?;
                let _ = self
                    .dns01_cleanup(provider, &order.domain, &challenge_val, rec_id.as_deref())
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
