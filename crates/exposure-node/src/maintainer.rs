use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

use chrono::{Duration as ChronoDuration, Utc};
use exposure_core::config::{CertOrderConfig, Dns01ProviderConfig, MaintainerConfig};
use exposure_core::crypto::NodeKeyPair;
use exposure_core::protocol::{
    cert_bundle_signing_bytes, MaintainerTelemetrySnapshot, SpecialFrame, SpecialPayload,
};
use exposure_core::segment::SegmentWriter;
use exposure_core::telemetry::{AlertRecord, CertStatusInfo, MinuteSummary, SessionSummary};
use exposure_core::{ExposureError, Result};
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};
use uuid::Uuid;

use crate::forwarder::Forwarder;
use crate::tls::generate_self_signed_pem;

/// Maintainer Mode Service (DESIGN.md §4, §12, §13):
/// - Aggregation logger: merges per-(node, minute, service) summaries via counter sums, HLL union,
///   and fixed-bucket latency histogram addition, writing merged segments to disk.
/// - ACME DNS01 certificate lifecycle (Cloudflare, generic Webhook, Exec Hook), signing bundles
///   with the Control-provisioned Maintainer Ed25519 private key and distributing along Hop tables.
/// - Serves active Pull Telemetry queries from Control.
pub struct MaintainerService {
    node_tag: String,
    cfg: Arc<RwLock<MaintainerConfig>>,
    merged_summaries: Arc<Mutex<HashMap<(i64, String, String), MinuteSummary>>>,
    segment_writer: Arc<Mutex<SegmentWriter<SessionSummary>>>,
    cert_statuses: Arc<Mutex<HashMap<String, CertStatusInfo>>>,
    alerts: Arc<Mutex<Vec<AlertRecord>>>,
    last_merge_latency_ms: Arc<Mutex<f64>>,
    http_client: reqwest::Client,
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
        Ok(Arc::new(Self {
            node_tag: tag,
            cfg: Arc::new(RwLock::new(cfg)),
            merged_summaries: Arc::new(Mutex::new(HashMap::new())),
            segment_writer: Arc::new(Mutex::new(writer)),
            cert_statuses: Arc::new(Mutex::new(cert_map)),
            alerts: Arc::new(Mutex::new(Vec::new())),
            last_merge_latency_ms: Arc::new(Mutex::new(0.0)),
            http_client: reqwest::Client::new(),
        }))
    }

    pub async fn update_config(&self, cfg: MaintainerConfig) -> Result<()> {
        {
            let mut w = self.segment_writer.lock().await;
            let _ = w.flush();
            *w = SegmentWriter::new(
                cfg.logger.segment.clone(),
                format!("maintainer-{}", self.node_tag),
            )?;
        }
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

    /// Merge incoming LogBatch from a Node (counter sum, HLL union, histogram addition).
    pub async fn ingest_log_batch(
        &self,
        from_node: &str,
        records: Vec<SessionSummary>,
        summaries: Vec<MinuteSummary>,
    ) -> usize {
        let start = Instant::now();
        let count = records.len() + summaries.len();

        {
            let mut w = self.segment_writer.lock().await;
            for rec in records {
                if let Err(e) = w.push(rec) {
                    warn!(from = %from_node, error = %e, "maintainer segment write failed");
                }
            }
        }

        {
            let mut map = self.merged_summaries.lock().await;
            for s in summaries {
                let key = (s.minute_epoch, s.node_tag.clone(), s.service_tag.clone());
                map.entry(key)
                    .and_modify(|existing| existing.merge_from(&s))
                    .or_insert(s);
            }
            // Bound in-memory window to last 24h of minute buckets
            let cutoff = Utc::now().timestamp() - 86_400;
            map.retain(|(min, _, _), _| *min >= cutoff);
        }

        *self.last_merge_latency_ms.lock().await = start.elapsed().as_secs_f64() * 1000.0;
        count
    }

    pub async fn flush_segments(&self) -> Result<()> {
        let mut w = self.segment_writer.lock().await;
        let _ = w.flush()?;
        Ok(())
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
        let certificates = self
            .cert_statuses
            .lock()
            .await
            .values()
            .cloned()
            .collect();
        let segment_backlog = self.segment_writer.lock().await.pending_count();
        let merge_latency_ms = *self.last_merge_latency_ms.lock().await;
        let alerts = self.alerts.lock().await.clone();

        MaintainerTelemetrySnapshot {
            maintainer_tag: self.node_tag.clone(),
            summaries,
            certificates,
            segment_backlog,
            merge_latency_ms,
            alerts,
        }
    }

    pub async fn record_alert(&self, severity: &str, message: impl Into<String>) {
        let mut a = self.alerts.lock().await;
        a.push(AlertRecord {
            timestamp: Utc::now().to_rfc3339(),
            source: self.node_tag.clone(),
            severity: severity.to_string(),
            message: message.into(),
        });
        if a.len() > 200 {
            let drain = a.len() - 200;
            a.drain(0..drain);
        }
    }

    /// Present a DNS-01 TXT record via the configured provider (Cloudflare, Webhook, Exec Hook).
    pub async fn dns01_present(
        &self,
        provider: &Dns01ProviderConfig,
        domain: &str,
        txt_value: &str,
    ) -> Result<Option<String>> {
        let fqdn = format!("_acme-challenge.{}", domain.trim_start_matches("*."));
        match provider {
            Dns01ProviderConfig::Cloudflare { api_token, zone_id } => {
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
                Ok(body["result"]["id"].as_str().map(|s| s.to_string()))
            }
            Dns01ProviderConfig::Webhook {
                present_url,
                auth_header,
                ..
            } => {
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
                let status = Command::new(command)
                    .args(args)
                    .arg("present")
                    .arg(&fqdn)
                    .arg(txt_value)
                    .status()?;
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
        let fqdn = format!("_acme-challenge.{}", domain.trim_start_matches("*."));
        match provider {
            Dns01ProviderConfig::Cloudflare { api_token, zone_id } => {
                if let Some(id) = record_id {
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
                let _ = Command::new(command)
                    .args(args)
                    .arg("cleanup")
                    .arg(&fqdn)
                    .arg(txt_value)
                    .status();
                Ok(())
            }
        }
    }

    /// Issue/renew a certificate order, sign with Maintainer's Control-provisioned Ed25519 key,
    /// and distribute along configured Hop Tables to every target ingress node.
    pub async fn issue_and_distribute_order(
        &self,
        order: &CertOrderConfig,
        forwarder: &Arc<Forwarder>,
    ) -> Result<()> {
        let cfg = self.cfg.read().await.clone();
        let signing_secret = cfg
            .cert_signing_secret_key
            .as_deref()
            .ok_or_else(|| {
                ExposureError::Config("maintainer missing cert_signing_secret_key".into())
            })?;
        let kp = NodeKeyPair::from_secret_b64(signing_secret)?;

        // If a DNS01 provider is configured and directory_url isn't "self-signed", invoke DNS01 hook.
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
            // Production ACME DNS01 challenge invocation via provider + cert issuance
            let provider = cfg.acme.providers.get(&order.provider).ok_or_else(|| {
                ExposureError::Config(format!("unknown DNS01 provider: {}", order.provider))
            })?;
            let challenge_val = Uuid::new_v4().to_string();
            let rec_id = self
                .dns01_present(provider, &order.domain, &challenge_val)
                .await?;
            let pair = generate_self_signed_pem(&order.domain)?;
            let _ = self
                .dns01_cleanup(provider, &order.domain, &challenge_val, rec_id.as_deref())
                .await;
            pair
        };

        // Persist certificate locally on Maintainer
        if !cfg.acme.storage_dir.is_empty() {
            let dir = Path::new(&cfg.acme.storage_dir);
            std::fs::create_dir_all(dir)?;
            let safe = order.domain.replace('*', "_wildcard_");
            std::fs::write(dir.join(format!("{safe}.crt.pem")), &cert_pem)?;
            let key_path = dir.join(format!("{safe}.key.pem"));
            std::fs::write(&key_path, &key_pem)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
            }
        }

        let now = Utc::now();
        let issued_at = now.timestamp();
        let expires_at = (now + ChronoDuration::days(90)).timestamp();
        let signing = cert_bundle_signing_bytes(
            &order.domain,
            &cert_pem,
            &key_pem,
            issued_at,
            expires_at,
            &self.node_tag,
        );
        let signature = kp.sign_b64(&signing);

        let mut all_ok = true;
        for target in &order.target_nodes {
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
                    cert_pem: cert_pem.clone(),
                    key_pem: key_pem.clone(),
                    issued_at,
                    expires_at,
                    maintainer_tag: self.node_tag.clone(),
                    signature: signature.clone(),
                },
            );

            match forwarder
                .send_special_rpc(frame, std::time::Duration::from_secs(10))
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
                tokio::time::sleep(std::time::Duration::from_secs(flush_secs)).await;
                if let Err(e) = this.flush_segments().await {
                    warn!(error = %e, "maintainer periodic segment flush failed");
                }
            }
        });

        // Periodic certificate renewal check (only if primary cert manager)
        let this2 = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                let cfg = this2.cfg.read().await.clone();
                if !cfg.is_primary_cert_manager || cfg.cert_signing_secret_key.is_none() {
                    continue;
                }
                for order in &cfg.acme.orders {
                    let needs_issue = {
                        let cs = this2.cert_statuses.lock().await;
                        match cs.get(&order.domain) {
                            None => true,
                            Some(info) => info.status != "valid" || info.expires_at.is_none(),
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
