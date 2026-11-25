use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use chrono::Utc;
use dashmap::DashMap;
use exposure_core::config::{
    ConfigBundlePurpose, DnsProviderAccountConfig, LinkMode, NodeConfig, SignedConfigBundle,
    TlsCertEntry, TunnelDirection,
};
use exposure_core::crypto::{
    NodeKeyPair, compute_bootstrap_reply_proof, compute_passphrase_proof, validate_dns_domain,
    verify_bootstrap_reply_proof, verify_signature_b64, write_secret_file_atomic,
};
use exposure_core::protocol::{
    DiscoveryNeighbor, DnsManageOp, DnsProviderCapabilities, DnsSyncRecordSpec, NodeStatusSnapshot,
    PreflightCheckItem, PreflightReport, SpecialFrame, SpecialPayload, StreamKind,
    cert_bundle_signing_bytes, dial_enroll_req_signing_bytes, discovery_resp_signing_bytes,
    dns_manage_req_signing_bytes, dns_sync_req_signing_bytes, geoip_sync_req_signing_bytes,
    pull_telemetry_req_signing_bytes, query_maintainer_req_signing_bytes, unban_req_signing_bytes,
};
use exposure_core::routing::is_public_routable_ip;
use exposure_core::telemetry::BanRecord;
use exposure_core::{ExposureError, Result};
use exposure_link::LinkManager;
use rand::RngCore;
use tokio::sync::{Mutex, RwLock, Semaphore};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::egress::EgressHandler;
use crate::forwarder::{Forwarder, IncomingSpecialFrame};
use crate::ingress::IngressServer;
use crate::logger::{DrainedLogBatch, NodeLogger};
use crate::maintainer::MaintainerService;
use crate::tls::DynamicCertResolver;

#[derive(Debug, Clone)]
pub struct OnboardingPassphrase {
    pub phrase: String,
    pub expires_at: i64,
    pub revoked: bool,
}

/// Complete Node Runtime (supports ingress, egress, relay, and maintainer modes simultaneously).
pub struct NodeRuntime {
    config_path: Option<PathBuf>,
    config: Arc<RwLock<NodeConfig>>,
    /// Serializes config hot-reloads and auto-rollbacks to prevent concurrent sequence races.
    config_reload_lock: Arc<Mutex<()>>,
    /// Serializes atomic config file writes.
    config_write_lock: Arc<Mutex<()>>,
    keypair: NodeKeyPair,
    link_manager: Arc<LinkManager>,
    forwarder: Arc<Forwarder>,
    ingress: Arc<IngressServer>,
    egress: Arc<EgressHandler>,
    cert_resolver: Arc<DynamicCertResolver>,
    logger: Arc<NodeLogger>,
    maintainer: Arc<RwLock<Option<Arc<MaintainerService>>>>,
    started_at: Instant,
    last_reload_status: Arc<RwLock<(bool, Option<String>)>>,
    passphrase: Arc<RwLock<Option<OnboardingPassphrase>>>,
    /// Active Control client tag connected to this bootstrap node (for forwarding active enrollments).
    connected_control_tag: Arc<RwLock<Option<String>>>,
    /// Monotonic `issued_at` per domain for `CertBundle` anti-rollback protection.
    cert_last_issued_at: Arc<DashMap<String, i64>>,
    /// Unified spent `request_id` cache for Control-signed command replay protection.
    used_control_cmd_ids: Arc<DashMap<String, i64>>,
    /// Bounds concurrent active bootstrap forwards handled on a bootstrap relay node.
    bootstrap_fwd_sem: Arc<Semaphore>,
    egress_hc_started: AtomicBool,
    geoip_updater_started: AtomicBool,
}

fn load_persisted_certs_from_dir(cert_resolver: &DynamicCertResolver, dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(fname) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some(stem) = fname.strip_suffix(".crt.pem") else {
            continue;
        };
        let key_path = dir.join(format!("{stem}.key.pem"));
        if !key_path.exists() {
            continue;
        }
        let domain = stem.replace("_wildcard_", "*");
        match (
            std::fs::read_to_string(&path),
            std::fs::read_to_string(&key_path),
        ) {
            (Ok(cert_pem), Ok(key_pem)) => {
                if let Err(e) = cert_resolver.load_from_pem(&domain, &cert_pem, &key_pem) {
                    warn!(domain = %domain, error = %e, "skipped invalid persisted TLS cert on startup");
                }
            }
            (Err(e), _) | (_, Err(e)) => {
                warn!(domain = %domain, error = %e, "failed reading persisted TLS cert on startup");
            }
        }
    }
}

fn collect_trusted_control_keys(cfg: &NodeConfig) -> Vec<String> {
    let mut keys = Vec::new();
    if let Some(ref pk) = cfg.control_link_public_key {
        if !pk.trim().is_empty() {
            keys.push(pk.trim().to_string());
        }
    }
    if let Some(ref pk) = cfg.control_public_key {
        if !pk.trim().is_empty() && !keys.iter().any(|k| k == pk.trim()) {
            keys.push(pk.trim().to_string());
        }
    }
    keys
}

impl NodeRuntime {
    pub async fn new(
        config: NodeConfig,
        config_path: Option<PathBuf>,
        initial_passphrase: Option<String>,
    ) -> Result<Arc<Self>> {
        let keypair = NodeKeyPair::from_secret_b64(&config.identity_secret_key)?;
        let logger = NodeLogger::new(&config.node_tag, config.logger.clone())?;
        let cert_resolver = DynamicCertResolver::new();
        if !config.ingress.tls_certs.is_empty() {
            cert_resolver.load_from_files(&config.ingress.tls_certs)?;
        }
        if let Some(ref dir_str) = config.ingress.cert_store_dir {
            load_persisted_certs_from_dir(&cert_resolver, Path::new(dir_str));
        }

        let link_manager = LinkManager::new(
            &config.node_tag,
            keypair.clone(),
            false,
            config.peers.clone(),
            config.probe.clone(),
        );
        let ctrl_keys = collect_trusted_control_keys(&config);
        if !ctrl_keys.is_empty() {
            link_manager.set_trusted_control_pubkeys(ctrl_keys).await;
        }

        let passphrase_state = initial_passphrase.map(|phrase| OnboardingPassphrase {
            phrase,
            expires_at: Utc::now().timestamp() + 600,
            revoked: false,
        });
        if let Some(ref p) = passphrase_state {
            link_manager
                .set_bootstrap_passphrase(Some(p.phrase.clone()))
                .await;
        }

        let egress = EgressHandler::new(
            &config.node_tag,
            config.egress.clone(),
            config.trusted_origins.clone(),
            Arc::clone(&logger),
        );
        let (forwarder, special_rx) = Forwarder::new(
            &config.node_tag,
            config.roles.clone(),
            config.relay.clone(),
            Arc::clone(&link_manager),
            Arc::clone(&egress),
            Arc::clone(&logger),
        );
        let ingress = IngressServer::new(
            &config.node_tag,
            keypair.clone(),
            config.ingress.clone(),
            config.default_ttl,
            Arc::clone(&forwarder),
            Arc::clone(&cert_resolver),
            Arc::clone(&logger),
        );

        let maint_opt = if config.roles.maintainer {
            let mcfg = config.maintainer.clone().unwrap_or_default();
            Some(MaintainerService::new(&config.node_tag, mcfg)?)
        } else {
            None
        };

        let rt = Arc::new(Self {
            config_path,
            config: Arc::new(RwLock::new(config)),
            config_reload_lock: Arc::new(Mutex::new(())),
            config_write_lock: Arc::new(Mutex::new(())),
            keypair,
            link_manager,
            forwarder,
            ingress,
            egress,
            cert_resolver,
            logger,
            maintainer: Arc::new(RwLock::new(maint_opt)),
            started_at: Instant::now(),
            last_reload_status: Arc::new(RwLock::new((true, None))),
            passphrase: Arc::new(RwLock::new(passphrase_state)),
            connected_control_tag: Arc::new(RwLock::new(None)),
            cert_last_issued_at: Arc::new(DashMap::new()),
            used_control_cmd_ids: Arc::new(DashMap::new()),
            bootstrap_fwd_sem: Arc::new(Semaphore::new(16)),
            egress_hc_started: AtomicBool::new(false),
            geoip_updater_started: AtomicBool::new(false),
        });

        rt.spawn_stream_dispatcher();
        rt.spawn_special_frame_handler(special_rx);

        Ok(rt)
    }

    pub fn node_tag(&self) -> String {
        self.link_manager.local_tag().to_string()
    }

    pub fn keypair(&self) -> &NodeKeyPair {
        &self.keypair
    }

    pub fn link_manager(&self) -> &Arc<LinkManager> {
        &self.link_manager
    }

    pub fn forwarder(&self) -> &Arc<Forwarder> {
        &self.forwarder
    }

    pub fn cert_resolver(&self) -> &Arc<DynamicCertResolver> {
        &self.cert_resolver
    }

    pub fn logger(&self) -> &Arc<NodeLogger> {
        &self.logger
    }

    pub async fn maintainer(&self) -> Option<Arc<MaintainerService>> {
        self.maintainer.read().await.clone()
    }

    pub async fn config_snapshot(&self) -> NodeConfig {
        self.config.read().await.clone()
    }

    pub async fn revoke_passphrase(&self) {
        if let Some(ref mut p) = *self.passphrase.write().await {
            p.revoked = true;
        }
        self.link_manager.set_bootstrap_passphrase(None).await;
    }

    /// Start all configured listeners, outbound tunnels, probes, health checks, and log flushers.
    pub async fn start(self: &Arc<Self>) -> Result<(Option<SocketAddr>, Vec<SocketAddr>)> {
        let cfg = self.config.read().await.clone();

        let link_bound = if let Some(ref lc) = cfg.link_listener {
            Some(self.link_manager.start_listener(lc.clone()).await?)
        } else {
            None
        };

        self.link_manager.spawn_outbound_tunnels();
        self.link_manager.spawn_probe_loop();

        if cfg.roles.egress && !self.egress_hc_started.swap(true, Ordering::AcqRel) {
            self.egress.spawn_local_health_checks();
        }

        let mut ingress_addrs = Vec::new();
        if cfg.roles.ingress && !self.geoip_updater_started.swap(true, Ordering::AcqRel) {
            Arc::clone(self.ingress.geoip()).spawn_updater();
        }
        if cfg.roles.ingress && !cfg.roles.maintainer {
            for listener in &cfg.ingress.listeners {
                let bound = self.ingress.start_listener(listener.clone()).await?;
                ingress_addrs.push(bound);
            }
        }

        if let Some(maint) = self.maintainer.read().await.clone() {
            maint.spawn_background_tasks(Arc::clone(&self.forwarder));
        }

        self.spawn_logger_tasks();
        self.spawn_passphrase_expiry_watcher();

        if cfg.control_public_key.is_none() {
            if let Some(ref boot_addr) = cfg.bootstrap_tunnel_addr {
                self.spawn_active_bootstrap_dialer(boot_addr.clone());
            }
        }

        Ok((link_bound, ingress_addrs))
    }

    async fn persist_config_yaml(&self, cfg: &NodeConfig) -> Result<()> {
        let Some(ref path) = self.config_path else {
            return Ok(());
        };
        let _w = self.config_write_lock.lock().await;
        let yaml = serde_yaml::to_string(cfg)
            .map_err(|e| ExposureError::Config(format!("serialize yaml: {e}")))?;
        let path_owned = path.clone();
        tokio::task::spawn_blocking(move || write_secret_file_atomic(&path_owned, yaml.as_bytes()))
            .await
            .map_err(|e| ExposureError::Storage(format!("config write join: {e}")))?
    }

    async fn reload_tls_files(&self, entries: &[TlsCertEntry]) -> Result<()> {
        if entries.is_empty() {
            self.cert_resolver.load_from_files(&[])?;
            return Ok(());
        }
        let resolver = Arc::clone(&self.cert_resolver);
        let owned = entries.to_vec();
        tokio::task::spawn_blocking(move || resolver.load_from_files(&owned))
            .await
            .map_err(|e| ExposureError::Crypto(format!("TLS reload join: {e}")))?
    }

    async fn install_enrolled_control_keys(
        &self,
        signing_pk: String,
        link_pk: Option<String>,
    ) -> Result<()> {
        let (trusted, cfg_snapshot) = {
            let mut cfg = self.config.write().await;
            if cfg.control_public_key.is_some() {
                return Err(ExposureError::Auth(
                    "node is already enrolled with a Control public key".into(),
                ));
            }
            let eff_link_pk = link_pk.unwrap_or_else(|| signing_pk.clone());
            cfg.control_public_key = Some(signing_pk);
            cfg.control_link_public_key = Some(eff_link_pk);
            (collect_trusted_control_keys(&cfg), cfg.clone())
        };
        self.persist_config_yaml(&cfg_snapshot).await?;
        self.link_manager.set_trusted_control_pubkeys(trusted).await;
        self.revoke_passphrase().await;
        Ok(())
    }

    fn spawn_stream_dispatcher(self: &Arc<Self>) {
        let rt = Arc::clone(self);
        tokio::spawn(async move {
            let Some(mut rx) = rt.link_manager.take_incoming_receiver().await else {
                return;
            };
            while let Some(incoming) = rx.recv().await {
                if incoming.is_control && incoming.authenticated {
                    *rt.connected_control_tag.write().await =
                        Some(incoming.remote_node_tag.clone());
                    // If Control authenticated via our one-time local bootstrap passphrase, install Control link key.
                    // Note: signing_pk will be set by BootstrapReply (with mutual proof), or defaults to link key if identical.
                    if incoming.bootstrap_pending {
                        let link_pk = incoming.remote_public_key.clone();
                        let should_install =
                            rt.config.read().await.control_link_public_key.is_none();
                        if should_install {
                            let (trusted, cfg_snapshot) = {
                                let mut cfg = rt.config.write().await;
                                cfg.control_link_public_key = Some(link_pk.clone());
                                if cfg.control_public_key.is_none() {
                                    cfg.control_public_key = Some(link_pk.clone());
                                }
                                (collect_trusted_control_keys(&cfg), cfg.clone())
                            };
                            let _ = rt.persist_config_yaml(&cfg_snapshot).await;
                            rt.link_manager.set_trusted_control_pubkeys(trusted).await;
                            info!(
                                node = %rt.node_tag(),
                                control = %incoming.remote_node_tag,
                                "authenticated Control bootstrap link"
                            );
                        }
                    }
                }
                rt.forwarder.handle_incoming_stream(incoming).await;
            }
        });
    }

    fn spawn_special_frame_handler(
        self: &Arc<Self>,
        mut rx: tokio::sync::mpsc::Receiver<IncomingSpecialFrame>,
    ) {
        let rt = Arc::clone(self);
        tokio::spawn(async move {
            while let Some(incoming) = rx.recv().await {
                let rt2 = Arc::clone(&rt);
                tokio::spawn(async move {
                    rt2.handle_local_special_frame(incoming).await;
                });
            }
        });
    }

    async fn handle_local_special_frame(self: &Arc<Self>, incoming: IncomingSpecialFrame) {
        let frame = incoming.frame;
        let reply_kind = incoming.stream_kind;

        let reply_payload: Option<SpecialPayload> = match frame.payload.clone() {
            SpecialPayload::PreflightReq(bundle) => {
                if !incoming.authenticated {
                    None
                } else {
                    Some(self.handle_preflight_request(*bundle).await)
                }
            }
            SpecialPayload::ConfigPush(bundle) => {
                if !incoming.authenticated {
                    None
                } else {
                    let seq = bundle.sequence;
                    let rev = if bundle.config_revision.is_empty() {
                        bundle.config.config_revision.clone()
                    } else {
                        bundle.config_revision.clone()
                    };
                    match self.apply_signed_config_with_watchdog(*bundle).await {
                        Ok(()) => Some(SpecialPayload::ConfigAck {
                            node_tag: self.node_tag(),
                            sequence: seq,
                            config_revision: rev,
                            applied: true,
                            error: None,
                        }),
                        Err(e) => {
                            error!(node = %self.node_tag(), seq, error = %e, "config hot reload failed, kept previous config");
                            *self.last_reload_status.write().await = (false, Some(e.to_string()));
                            Some(SpecialPayload::ConfigAck {
                                node_tag: self.node_tag(),
                                sequence: seq,
                                config_revision: rev,
                                applied: false,
                                error: Some(e.to_string()),
                            })
                        }
                    }
                }
            }
            SpecialPayload::DiscoveryReq { request_id, .. } => {
                if !incoming.authenticated {
                    None
                } else {
                    let cfg = self.config.read().await.clone();
                    let snaps = self.link_manager.link_snapshots().await;
                    let neighbors: Vec<DiscoveryNeighbor> = cfg
                        .peers
                        .iter()
                        .map(|p| {
                            let st = snaps
                                .iter()
                                .find(|s| s.peer_tag == p.peer_tag)
                                .map(|s| s.state.to_string())
                                .unwrap_or_else(|| "UNKNOWN".into());
                            DiscoveryNeighbor {
                                peer_tag: p.peer_tag.clone(),
                                node_tag: p.node_tag.clone(),
                                state: st,
                            }
                        })
                        .collect();
                    let pk = self.keypair.public_key_b64();
                    let signing = discovery_resp_signing_bytes(
                        &request_id,
                        &cfg.node_tag,
                        &cfg.roles,
                        &pk,
                        cfg.config_sequence,
                        &neighbors,
                    );
                    let signature = self.keypair.sign_b64(&signing);
                    Some(SpecialPayload::DiscoveryResp {
                        request_id,
                        node_tag: cfg.node_tag,
                        roles: cfg.roles,
                        public_key: pk,
                        config_sequence: cfg.config_sequence,
                        config_revision: cfg.config_revision,
                        neighbors,
                        signature,
                    })
                }
            }
            SpecialPayload::LogBatch {
                from_node,
                records,
                minute_summaries,
                fingerprints,
                evilpot_sessions,
                evilpot_events,
                ban_records,
                alerts,
            } => {
                if !incoming.authenticated {
                    None
                } else if let Some(maint) = self.maintainer.read().await.clone() {
                    let accepted = maint
                        .ingest_log_batch(
                            &from_node,
                            records,
                            minute_summaries,
                            fingerprints,
                            evilpot_sessions,
                            evilpot_events,
                            ban_records,
                            alerts,
                        )
                        .await;
                    Some(SpecialPayload::LogAck { accepted })
                } else {
                    Some(SpecialPayload::ErrorReply {
                        message: "node is not running maintainer mode".into(),
                    })
                }
            }
            SpecialPayload::CertBundle {
                domain,
                target_node_tag,
                cert_pem,
                key_pem,
                issued_at,
                expires_at,
                maintainer_tag,
                signature,
            } => {
                if !incoming.authenticated {
                    None
                } else {
                    match self
                        .apply_cert_bundle(
                            &domain,
                            &target_node_tag,
                            &cert_pem,
                            &key_pem,
                            issued_at,
                            expires_at,
                            &maintainer_tag,
                            &signature,
                        )
                        .await
                    {
                        Ok(()) => Some(SpecialPayload::CertAck {
                            node_tag: self.node_tag(),
                            domain,
                            applied: true,
                            error: None,
                        }),
                        Err(e) => Some(SpecialPayload::CertAck {
                            node_tag: self.node_tag(),
                            domain,
                            applied: false,
                            error: Some(e.to_string()),
                        }),
                    }
                }
            }
            SpecialPayload::StatusReq => {
                if !incoming.authenticated {
                    None
                } else {
                    let cfg = self.config.read().await.clone();
                    let links = self.link_manager.link_snapshots().await;
                    let (ok, err) = self.last_reload_status.read().await.clone();
                    let alerts = self.logger.recent_alerts().await;
                    let evilpot = self.ingress.evilpot_report().await;
                    let geoip = if cfg.roles.ingress {
                        Some(self.ingress.geoip().status())
                    } else {
                        None
                    };
                    let log_stats = self.logger.protection_stats();
                    Some(SpecialPayload::StatusResp(NodeStatusSnapshot {
                        node_tag: cfg.node_tag,
                        roles: cfg.roles,
                        config_sequence: cfg.config_sequence,
                        config_revision: cfg.config_revision,
                        last_reload_ok: ok,
                        last_reload_error: err,
                        uptime_secs: self.started_at.elapsed().as_secs(),
                        links,
                        alerts,
                        evilpot,
                        geoip,
                        log_stats,
                    }))
                }
            }
            SpecialPayload::PullTelemetryReq {
                request_id,
                issued_at,
                expires_at,
                maintainer_tag,
                since_minute,
                control_signature,
            } => {
                if !incoming.authenticated {
                    None
                } else {
                    let signing = pull_telemetry_req_signing_bytes(
                        &request_id,
                        issued_at,
                        expires_at,
                        &maintainer_tag,
                        since_minute,
                    );
                    if let Err(msg) = self
                        .verify_control_signed_cmd(
                            "PullTelemetryReq",
                            &request_id,
                            issued_at,
                            expires_at,
                            &maintainer_tag,
                            &signing,
                            &control_signature,
                        )
                        .await
                    {
                        Some(SpecialPayload::ErrorReply { message: msg })
                    } else if let Some(maint) = self.maintainer.read().await.clone() {
                        let snap = maint.build_telemetry_snapshot(since_minute).await;
                        Some(SpecialPayload::PullTelemetryResp(snap))
                    } else {
                        Some(SpecialPayload::ErrorReply {
                            message: "node is not maintainer".into(),
                        })
                    }
                }
            }
            SpecialPayload::QueryMaintainerReq {
                request_id,
                issued_at,
                expires_at,
                maintainer_tag,
                query,
                control_signature,
            } => {
                if !incoming.authenticated {
                    None
                } else {
                    let signing = query_maintainer_req_signing_bytes(
                        &request_id,
                        issued_at,
                        expires_at,
                        &maintainer_tag,
                        &query,
                    );
                    if let Err(msg) = self
                        .verify_control_signed_cmd(
                            "QueryMaintainerReq",
                            &request_id,
                            issued_at,
                            expires_at,
                            &maintainer_tag,
                            &signing,
                            &control_signature,
                        )
                        .await
                    {
                        Some(SpecialPayload::QueryMaintainerResp {
                            request_id,
                            maintainer_tag: self.node_tag(),
                            ok: false,
                            data: serde_json::Value::Null,
                            error: Some(msg),
                        })
                    } else if let Some(maint) = self.maintainer.read().await.clone() {
                        match maint.handle_query(query).await {
                            Ok(data) => Some(SpecialPayload::QueryMaintainerResp {
                                request_id,
                                maintainer_tag: self.node_tag(),
                                ok: true,
                                data,
                                error: None,
                            }),
                            Err(e) => Some(SpecialPayload::QueryMaintainerResp {
                                request_id,
                                maintainer_tag: self.node_tag(),
                                ok: false,
                                data: serde_json::Value::Null,
                                error: Some(e.to_string()),
                            }),
                        }
                    } else {
                        Some(SpecialPayload::QueryMaintainerResp {
                            request_id,
                            maintainer_tag: self.node_tag(),
                            ok: false,
                            data: serde_json::Value::Null,
                            error: Some("node is not maintainer".into()),
                        })
                    }
                }
            }
            SpecialPayload::BootstrapForward {
                node_tag,
                public_key,
                nonce,
                proof,
                via_node,
            } => {
                // Only bootstrap listeners with allow_bootstrap enabled forward active enrollments to Control
                let allow_boot = self
                    .config
                    .read()
                    .await
                    .link_listener
                    .as_ref()
                    .map(|l| l.effective_allow_bootstrap())
                    .unwrap_or(false);
                if !allow_boot {
                    Some(SpecialPayload::BootstrapReply {
                        accepted: false,
                        control_public_key: None,
                        control_link_public_key: None,
                        reply_proof: None,
                        nonce: vec![],
                        error: Some("bootstrap forwarding disabled on this node".into()),
                    })
                } else if via_node.trim().is_empty() || via_node != self.node_tag() {
                    Some(SpecialPayload::BootstrapReply {
                        accepted: false,
                        control_public_key: None,
                        control_link_public_key: None,
                        reply_proof: None,
                        nonce: vec![],
                        error: Some("bootstrap via_node does not match relay node".into()),
                    })
                } else if let Ok(_fwd_permit) =
                    Arc::clone(&self.bootstrap_fwd_sem).try_acquire_owned()
                {
                    let ctrl_tag = self.connected_control_tag.read().await.clone();
                    if let Some(ctrl) = ctrl_tag {
                        let fwd_frame = SpecialFrame::new(
                            Uuid::new_v4().to_string(),
                            vec![self.node_tag(), ctrl],
                            8,
                            SpecialPayload::BootstrapForward {
                                node_tag,
                                public_key,
                                nonce,
                                proof,
                                via_node: self.node_tag(),
                            },
                        );
                        match self
                            .forwarder
                            .send_special_rpc(fwd_frame, Duration::from_secs(10))
                            .await
                        {
                            Ok(reply) => Some(reply.payload),
                            Err(e) => Some(SpecialPayload::BootstrapReply {
                                accepted: false,
                                control_public_key: None,
                                control_link_public_key: None,
                                reply_proof: None,
                                nonce: vec![],
                                error: Some(format!("control forward failed: {e}")),
                            }),
                        }
                    } else {
                        Some(SpecialPayload::BootstrapReply {
                            accepted: false,
                            control_public_key: None,
                            control_link_public_key: None,
                            reply_proof: None,
                            nonce: vec![],
                            error: Some("no active control connected to bootstrap node".into()),
                        })
                    }
                } else {
                    Some(SpecialPayload::BootstrapReply {
                        accepted: false,
                        control_public_key: None,
                        control_link_public_key: None,
                        reply_proof: None,
                        nonce: vec![],
                        error: Some("bootstrap forwarding busy; retry shortly".into()),
                    })
                }
            }
            SpecialPayload::DialEnrollReq {
                request_id,
                issued_at,
                expires_at,
                target_node_tag,
                target_addr,
                passphrase,
                control_public_key,
                control_link_public_key,
                control_signature,
            } => {
                if !incoming.authenticated {
                    None
                } else {
                    Some(
                        self.handle_dial_enroll_req(
                            request_id,
                            issued_at,
                            expires_at,
                            target_node_tag,
                            target_addr,
                            passphrase,
                            control_public_key,
                            control_link_public_key,
                            control_signature,
                        )
                        .await,
                    )
                }
            }
            SpecialPayload::DnsSyncReq {
                request_id,
                issued_at,
                expires_at,
                maintainer_tag,
                records,
                control_signature,
            } => {
                if !incoming.authenticated {
                    None
                } else {
                    Some(
                        self.handle_dns_sync_req(
                            request_id,
                            issued_at,
                            expires_at,
                            maintainer_tag,
                            records,
                            control_signature,
                        )
                        .await,
                    )
                }
            }
            SpecialPayload::DnsManageReq {
                request_id,
                issued_at,
                expires_at,
                maintainer_tag,
                op,
                control_signature,
            } => {
                if !incoming.authenticated {
                    None
                } else {
                    Some(
                        self.handle_dns_manage_req(
                            request_id,
                            issued_at,
                            expires_at,
                            maintainer_tag,
                            op,
                            control_signature,
                        )
                        .await,
                    )
                }
            }
            SpecialPayload::UnbanReq {
                request_id,
                issued_at,
                expires_at,
                target_node_tag,
                ban_kind,
                target,
                control_signature,
            } => {
                if !incoming.authenticated {
                    None
                } else {
                    Some(
                        self.handle_unban_req(
                            request_id,
                            issued_at,
                            expires_at,
                            target_node_tag,
                            ban_kind,
                            target,
                            control_signature,
                        )
                        .await,
                    )
                }
            }
            SpecialPayload::GeoIpSyncReq {
                request_id,
                issued_at,
                expires_at,
                target_node_tag,
                force,
                control_signature,
            } => {
                if !incoming.authenticated {
                    None
                } else {
                    Some(
                        self.handle_geoip_sync_req(
                            request_id,
                            issued_at,
                            expires_at,
                            target_node_tag,
                            force,
                            control_signature,
                        )
                        .await,
                    )
                }
            }
            SpecialPayload::GeoIpLookupReq { ip } => {
                if !incoming.authenticated {
                    None
                } else {
                    Some(self.handle_geoip_lookup_req(&ip))
                }
            }
            SpecialPayload::BootstrapReply {
                accepted: true,
                control_public_key: Some(pk),
                control_link_public_key,
                reply_proof,
                nonce,
                ..
            } => {
                // CRITICAL SECURITY CHECK:
                // 1) Refuse to overwrite an existing control_public_key!
                // 2) Verify mutual passphrase proof (or trusted Control link) before trusting keys!
                let already_enrolled = self.config.read().await.control_public_key.is_some();
                if already_enrolled && !incoming.is_control {
                    warn!(
                        node = %self.node_tag(),
                        remote = %incoming.remote_node_tag,
                        "rejected unsolicited BootstrapReply attempting to overwrite existing control_public_key"
                    );
                    return;
                }

                let link_pk = control_link_public_key
                    .clone()
                    .unwrap_or_else(|| pk.clone());

                // Verify passphrase proof when not already authenticated directly as Control
                let verified = if incoming.is_control && incoming.authenticated {
                    // Direct Control connection already authenticated via local passphrase or trusted link key
                    let cur_pass = self.passphrase.read().await.clone();
                    match (cur_pass, reply_proof.as_deref()) {
                        (Some(p), Some(rp)) if !p.revoked => verify_bootstrap_reply_proof(
                            &p.phrase,
                            &pk,
                            &link_pk,
                            &self.node_tag(),
                            &nonce,
                            rp,
                        ),
                        // If Control already matched trusted_control_pubkeys on reconnect, allow only
                        // the already-pinned signing key. When no signing key is pinned yet, fail
                        // closed (the passphrase-proof arm above is the only way to install one).
                        _ => self
                            .config
                            .read()
                            .await
                            .control_public_key
                            .as_deref()
                            .map(|existing| existing == pk)
                            .unwrap_or(false),
                    }
                } else {
                    let cur_pass = self.passphrase.read().await.clone();
                    match (cur_pass, reply_proof.as_deref()) {
                        (Some(p), Some(rp))
                            if !p.revoked && Utc::now().timestamp() <= p.expires_at =>
                        {
                            verify_bootstrap_reply_proof(
                                &p.phrase,
                                &pk,
                                &link_pk,
                                &self.node_tag(),
                                &nonce,
                                rp,
                            )
                        }
                        _ => false,
                    }
                };

                if !verified {
                    warn!(
                        node = %self.node_tag(),
                        remote = %incoming.remote_node_tag,
                        "rejected BootstrapReply with missing or invalid passphrase proof"
                    );
                    return;
                }

                if already_enrolled {
                    // Allow updating signing key during initial Control-authenticated bootstrap handshake if link_pk was set first
                    let update_snap = {
                        let mut cfg = self.config.write().await;
                        if cfg.control_public_key.as_deref()
                            == cfg.control_link_public_key.as_deref()
                        {
                            cfg.control_public_key = Some(pk);
                            cfg.control_link_public_key = Some(link_pk);
                            Some((collect_trusted_control_keys(&cfg), cfg.clone()))
                        } else {
                            None
                        }
                    };
                    if let Some((trusted, cfg_snapshot)) = update_snap {
                        let _ = self.persist_config_yaml(&cfg_snapshot).await;
                        self.link_manager.set_trusted_control_pubkeys(trusted).await;
                        self.revoke_passphrase().await;
                    }
                } else if let Err(e) = self.install_enrolled_control_keys(pk, Some(link_pk)).await {
                    warn!(node = %self.node_tag(), error = %e, "failed to install enrolled control keys");
                } else {
                    info!(node = %self.node_tag(), "enrolled with Control and revoked passphrase");
                }
                None
            }
            _ => None,
        };

        if let Some(payload) = reply_payload {
            let reply = frame.reverse_for_reply(payload);
            let res = if reply_kind == StreamKind::Bootstrap {
                self.forwarder.send_bootstrap(reply).await
            } else {
                self.forwarder.send_special(reply).await
            };
            if let Err(e) = res {
                warn!(id = %frame.id, error = %e, "failed to send reversed-hop reply");
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_dial_enroll_req(
        &self,
        request_id: String,
        issued_at: i64,
        expires_at: i64,
        target_node_tag: String,
        target_addr: String,
        passphrase: String,
        control_public_key: String,
        control_link_public_key: String,
        control_signature: String,
    ) -> SpecialPayload {
        // 1. Verify Control authorization signature & replay using unified Control command verifier
        let relay_tag = self.node_tag();
        let signing = dial_enroll_req_signing_bytes(
            &request_id,
            issued_at,
            expires_at,
            &relay_tag,
            &target_node_tag,
            &target_addr,
            &passphrase,
            &control_public_key,
            &control_link_public_key,
        );
        if let Err(msg) = self
            .verify_control_signed_cmd(
                "DialEnrollReq",
                &request_id,
                issued_at,
                expires_at,
                &relay_tag,
                &signing,
                &control_signature,
            )
            .await
        {
            return SpecialPayload::DialEnrollResp {
                success: false,
                node_public_key: None,
                error: Some(msg),
            };
        }

        // 2. Dial the listening node, enforcing expected node_tag & mutual authentication
        let mut nonce = vec![0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce);
        let proof = compute_passphrase_proof(
            &passphrase,
            &self.node_tag(),
            &self.keypair.public_key_b64(),
            &nonce,
        );
        match self
            .link_manager
            .dial_endpoint(
                &target_addr,
                Some(&target_node_tag),
                None,
                None,
                Some((nonce.clone(), proof)),
                false,
            )
            .await
        {
            Ok((sess, outcome)) => {
                if !outcome.authenticated {
                    sess.close().await;
                    return SpecialPayload::DialEnrollResp {
                        success: false,
                        node_public_key: None,
                        error: Some("target node did not authenticate bootstrap passphrase".into()),
                    };
                }
                let node_pk = outcome.remote_public_key.clone();
                self.link_manager
                    .register_outbound_session(
                        target_addr,
                        target_node_tag.clone(),
                        node_pk.clone(),
                        sess,
                        true,
                    )
                    .await;

                // Send mutual-auth BootstrapReply proving knowledge of the passphrase
                let reply_proof = compute_bootstrap_reply_proof(
                    &passphrase,
                    &control_public_key,
                    &control_link_public_key,
                    &target_node_tag,
                    &nonce,
                );
                let install = SpecialFrame::new(
                    Uuid::new_v4().to_string(),
                    vec![self.node_tag(), target_node_tag],
                    4,
                    SpecialPayload::BootstrapReply {
                        accepted: true,
                        control_public_key: Some(control_public_key),
                        control_link_public_key: Some(control_link_public_key),
                        reply_proof: Some(reply_proof),
                        nonce,
                        error: None,
                    },
                );
                if let Err(e) = self.forwarder.send_bootstrap(install).await {
                    return SpecialPayload::DialEnrollResp {
                        success: false,
                        node_public_key: None,
                        error: Some(format!("failed to deliver BootstrapReply: {e}")),
                    };
                }
                SpecialPayload::DialEnrollResp {
                    success: true,
                    node_public_key: Some(node_pk),
                    error: None,
                }
            }
            Err(e) => SpecialPayload::DialEnrollResp {
                success: false,
                node_public_key: None,
                error: Some(e.to_string()),
            },
        }
    }

    async fn handle_dns_sync_req(
        &self,
        request_id: String,
        issued_at: i64,
        expires_at: i64,
        maintainer_tag: String,
        records: Vec<DnsSyncRecordSpec>,
        control_signature: String,
    ) -> SpecialPayload {
        let reject = |msg: String| SpecialPayload::DnsSyncResp {
            request_id: request_id.clone(),
            maintainer_tag: self.node_tag(),
            ok: false,
            results: Vec::new(),
            error: Some(msg),
        };

        let signing = dns_sync_req_signing_bytes(
            &request_id,
            issued_at,
            expires_at,
            &maintainer_tag,
            &records,
        );
        if let Err(msg) = self
            .verify_control_signed_cmd(
                "DnsSyncReq",
                &request_id,
                issued_at,
                expires_at,
                &maintainer_tag,
                &signing,
                &control_signature,
            )
            .await
        {
            return reject(msg);
        }

        let maint = self.maintainer.read().await.clone();
        let Some(maint) = maint else {
            return reject("node is not running maintainer mode".into());
        };

        let results = maint.sync_dns_records(&records).await;
        let all_ok = results.iter().all(|r| r.ok);
        SpecialPayload::DnsSyncResp {
            request_id,
            maintainer_tag: self.node_tag(),
            ok: all_ok,
            results,
            error: None,
        }
    }

    async fn handle_dns_manage_req(
        &self,
        request_id: String,
        issued_at: i64,
        expires_at: i64,
        maintainer_tag: String,
        op: DnsManageOp,
        control_signature: String,
    ) -> SpecialPayload {
        let reject = |msg: String| SpecialPayload::DnsManageResp {
            request_id: request_id.clone(),
            maintainer_tag: self.node_tag(),
            ok: false,
            capabilities: DnsProviderCapabilities::default(),
            lines: Vec::new(),
            records: Vec::new(),
            record_id: None,
            error: Some(msg),
        };

        let signing =
            dns_manage_req_signing_bytes(&request_id, issued_at, expires_at, &maintainer_tag, &op);
        if let Err(msg) = self
            .verify_control_signed_cmd(
                "DnsManageReq",
                &request_id,
                issued_at,
                expires_at,
                &maintainer_tag,
                &signing,
                &control_signature,
            )
            .await
        {
            return reject(msg);
        }

        let maint = self.maintainer.read().await.clone();
        let Some(maint) = maint else {
            return reject("node is not running maintainer mode".into());
        };

        match maint.manage_dns(&op).await {
            Ok((capabilities, lines, records, record_id)) => SpecialPayload::DnsManageResp {
                request_id,
                maintainer_tag: self.node_tag(),
                ok: true,
                capabilities,
                lines,
                records,
                record_id,
                error: None,
            },
            Err(e) => reject(e.to_string()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn verify_control_signed_cmd(
        &self,
        cmd_name: &str,
        request_id: &str,
        issued_at: i64,
        expires_at: i64,
        target_node_tag: &str,
        signing_bytes: &[u8],
        control_signature: &str,
    ) -> std::result::Result<(), String> {
        if target_node_tag != self.node_tag() {
            return Err(format!(
                "{cmd_name} target '{target_node_tag}' != local node '{}'",
                self.node_tag()
            ));
        }
        let local_ctrl_pk = self
            .config
            .read()
            .await
            .control_public_key
            .clone()
            .ok_or_else(|| "node has no Control public key configured".to_string())?;
        let now = Utc::now().timestamp();
        if now > expires_at || issued_at > now + 60 {
            return Err(format!("{cmd_name} expired or invalid timestamp"));
        }
        verify_signature_b64(&local_ctrl_pk, signing_bytes, control_signature)
            .map_err(|e| format!("{cmd_name} signature invalid: {e}"))?;
        if self.used_control_cmd_ids.len() > 4096 {
            self.used_control_cmd_ids.retain(|_, exp| *exp >= now);
            if self.used_control_cmd_ids.len() > 4096 {
                crate::ban::evict_half(&self.used_control_cmd_ids);
            }
        }
        let mut is_new = false;
        self.used_control_cmd_ids
            .entry(request_id.to_string())
            .or_insert_with(|| {
                is_new = true;
                expires_at
            });
        if !is_new {
            return Err(format!("{cmd_name} replay rejected"));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_unban_req(
        &self,
        request_id: String,
        issued_at: i64,
        expires_at: i64,
        target_node_tag: String,
        kind: String,
        target: String,
        control_signature: String,
    ) -> SpecialPayload {
        let signing = unban_req_signing_bytes(
            &request_id,
            issued_at,
            expires_at,
            &target_node_tag,
            &kind,
            &target,
        );
        if let Err(err) = self
            .verify_control_signed_cmd(
                "UnbanReq",
                &request_id,
                issued_at,
                expires_at,
                &target_node_tag,
                &signing,
                &control_signature,
            )
            .await
        {
            return SpecialPayload::UnbanResp {
                request_id,
                node_tag: self.node_tag(),
                ok: false,
                removed: false,
                error: Some(err),
            };
        }
        let removed = self.ingress.auto_ban().unban(&kind, &target);
        if removed {
            self.ingress.persist_active_bans_async();
        }
        info!(
            node = %self.node_tag(),
            kind = %kind,
            target = %target,
            removed,
            "processed dashboard unban request"
        );
        SpecialPayload::UnbanResp {
            request_id,
            node_tag: self.node_tag(),
            ok: true,
            removed,
            error: None,
        }
    }

    async fn handle_geoip_sync_req(
        &self,
        request_id: String,
        issued_at: i64,
        expires_at: i64,
        target_node_tag: String,
        force: bool,
        control_signature: String,
    ) -> SpecialPayload {
        let signing = geoip_sync_req_signing_bytes(
            &request_id,
            issued_at,
            expires_at,
            &target_node_tag,
            force,
        );
        if let Err(err) = self
            .verify_control_signed_cmd(
                "GeoIpSyncReq",
                &request_id,
                issued_at,
                expires_at,
                &target_node_tag,
                &signing,
                &control_signature,
            )
            .await
        {
            return SpecialPayload::GeoIpSyncResp {
                request_id,
                node_tag: self.node_tag(),
                ok: false,
                status: None,
                error: Some(err),
            };
        }
        match self.ingress.geoip().sync_now(force).await {
            Ok(status) => SpecialPayload::GeoIpSyncResp {
                request_id,
                node_tag: self.node_tag(),
                ok: true,
                status: Some(status),
                error: None,
            },
            Err(err) => SpecialPayload::GeoIpSyncResp {
                request_id,
                node_tag: self.node_tag(),
                ok: false,
                status: Some(self.ingress.geoip().status()),
                error: Some(err),
            },
        }
    }

    fn handle_geoip_lookup_req(&self, raw_ip: &str) -> SpecialPayload {
        let trimmed = raw_ip.trim();
        let Ok(addr) = trimmed.parse::<IpAddr>() else {
            return SpecialPayload::GeoIpLookupResp {
                node_tag: self.node_tag(),
                ip: trimmed.to_string(),
                country: None,
                continent: None,
                is_private: false,
                db_loaded: self.ingress.geoip().is_loaded(),
                error: Some(format!("invalid IP address '{trimmed}'")),
            };
        };
        let is_priv = !is_public_routable_ip(addr);
        let res = self.ingress.geoip().lookup(addr);
        SpecialPayload::GeoIpLookupResp {
            node_tag: self.node_tag(),
            ip: addr.to_string(),
            country: res.as_ref().map(|r| r.country_str().to_string()),
            continent: res.as_ref().map(|r| r.continent.to_string()),
            is_private: is_priv,
            db_loaded: self.ingress.geoip().is_loaded(),
            error: None,
        }
    }

    /// Run non-mutating preflight connectivity & port checks for a candidate Control-signed Preflight bundle.
    pub async fn handle_preflight_request(&self, bundle: SignedConfigBundle) -> SpecialPayload {
        let mut checks = Vec::new();
        let (control_pk, current_seq, cur_listeners) = {
            let cfg = self.config.read().await;
            let listeners: Vec<String> = cfg
                .ingress
                .listeners
                .iter()
                .map(|l| l.listen_addr.clone())
                .collect();
            (
                cfg.control_public_key.clone(),
                cfg.config_sequence,
                listeners,
            )
        };
        let Some(control_pk) = control_pk else {
            return SpecialPayload::PreflightResp(PreflightReport {
                node_tag: self.node_tag(),
                ok: false,
                checks: vec![PreflightCheckItem {
                    target: "signature".into(),
                    ok: false,
                    detail: "node has no Control public key configured".into(),
                }],
            });
        };
        if let Err(e) = bundle.verify(
            &control_pk,
            &self.node_tag(),
            ConfigBundlePurpose::Preflight,
            current_seq,
            Utc::now().timestamp(),
        ) {
            return SpecialPayload::PreflightResp(PreflightReport {
                node_tag: self.node_tag(),
                ok: false,
                checks: vec![PreflightCheckItem {
                    target: "signature".into(),
                    ok: false,
                    detail: e.to_string(),
                }],
            });
        }

        let cand = bundle.config;

        for peer in &cand.peers {
            let needs_dial = peer.mode == LinkMode::OnDemand
                || (peer.mode == LinkMode::Tunnel
                    && peer.tunnel_direction != Some(TunnelDirection::Inbound));
            if !needs_dial {
                checks.push(PreflightCheckItem {
                    target: format!("peer:{}", peer.peer_tag),
                    ok: true,
                    detail: "inbound tunnel (waits for remote dial)".into(),
                });
                continue;
            }
            if peer.endpoints.is_empty() {
                checks.push(PreflightCheckItem {
                    target: format!("peer:{}", peer.peer_tag),
                    ok: false,
                    detail: "no endpoints configured for outbound/on-demand peer".into(),
                });
                continue;
            }
            let already_connected = self.link_manager.has_connected_peer(&peer.peer_tag).await;
            for ep in &peer.endpoints {
                if already_connected {
                    checks.push(PreflightCheckItem {
                        target: format!("peer:{} ({})", peer.peer_tag, ep.address),
                        ok: true,
                        detail: "active link session already connected".into(),
                    });
                    continue;
                }
                match tokio::time::timeout(
                    Duration::from_millis(1500),
                    tokio::net::TcpStream::connect(&ep.address),
                )
                .await
                {
                    Ok(Ok(_)) => checks.push(PreflightCheckItem {
                        target: format!("peer:{} ({})", peer.peer_tag, ep.address),
                        ok: true,
                        detail: "TCP reachable".into(),
                    }),
                    Ok(Err(e)) => checks.push(PreflightCheckItem {
                        target: format!("peer:{} ({})", peer.peer_tag, ep.address),
                        ok: false,
                        detail: format!("TCP connect failed: {e}"),
                    }),
                    Err(_) => checks.push(PreflightCheckItem {
                        target: format!("peer:{} ({})", peer.peer_tag, ep.address),
                        ok: false,
                        detail: "TCP connect timed out (1500ms)".into(),
                    }),
                }
            }
        }

        for l in &cand.ingress.listeners {
            if cur_listeners.contains(&l.listen_addr) {
                checks.push(PreflightCheckItem {
                    target: format!("ingress:{}", l.listen_addr),
                    ok: true,
                    detail: "already bound by this node".into(),
                });
            } else {
                match tokio::net::TcpListener::bind(&l.listen_addr).await {
                    Ok(_) => checks.push(PreflightCheckItem {
                        target: format!("ingress:{}", l.listen_addr),
                        ok: true,
                        detail: "port available".into(),
                    }),
                    Err(e) => checks.push(PreflightCheckItem {
                        target: format!("ingress:{}", l.listen_addr),
                        ok: false,
                        detail: format!("port bind failed: {e}"),
                    }),
                }
            }
        }

        for (svc_tag, svc) in &cand.egress.services {
            let target = format!("egress:{} -> {}", svc_tag, svc.backend);
            match tokio::time::timeout(
                Duration::from_millis(1500),
                tokio::net::TcpStream::connect(&svc.backend),
            )
            .await
            {
                Ok(Ok(tcp)) => {
                    if svc.tls.unwrap_or(false) {
                        // `auto`/`h2` both offer h2 via ALPN; only an explicit `http1` service
                        // must not advertise h2.
                        let offer_h2 = svc.protocol
                            != exposure_core::config::BackendProtocol::Http1;
                        match self.egress.get_tls_client_config(svc, offer_h2).await {
                            Ok(tls_cfg) => {
                                match tokio::time::timeout(
                                    Duration::from_millis(2000),
                                    crate::egress::connect_backend_tls(tcp, svc, &tls_cfg),
                                )
                                .await
                                {
                                    Ok(Ok(_)) => checks.push(PreflightCheckItem {
                                        target,
                                        ok: true,
                                        detail: if svc.effective_insecure_skip_verify() {
                                            "backend TLS reachable (insecure skip-verify)".into()
                                        } else {
                                            "backend TLS verified & reachable".into()
                                        },
                                    }),
                                    Ok(Err(e)) => checks.push(PreflightCheckItem {
                                        target,
                                        ok: false,
                                        detail: format!("backend TLS check failed: {e}"),
                                    }),
                                    Err(_) => checks.push(PreflightCheckItem {
                                        target,
                                        ok: false,
                                        detail: "backend TLS handshake timed out (2000ms)".into(),
                                    }),
                                }
                            }
                            Err(e) => checks.push(PreflightCheckItem {
                                target,
                                ok: false,
                                detail: format!("backend TLS config failed: {e}"),
                            }),
                        }
                    } else {
                        checks.push(PreflightCheckItem {
                            target,
                            ok: true,
                            detail: "backend TCP reachable".into(),
                        });
                    }
                }
                Ok(Err(e)) => checks.push(PreflightCheckItem {
                    target,
                    ok: false,
                    detail: format!("backend connect failed: {e}"),
                }),
                Err(_) => checks.push(PreflightCheckItem {
                    target,
                    ok: false,
                    detail: "backend connect timed out (1500ms)".into(),
                }),
            }
        }

        let all_ok = checks.iter().all(|c| c.ok);
        SpecialPayload::PreflightResp(PreflightReport {
            node_tag: self.node_tag(),
            ok: all_ok,
            checks,
        })
    }

    /// Apply a Control-signed config with an automatic 25s link-isolation rollback watchdog.
    pub async fn apply_signed_config_with_watchdog(
        self: &Arc<Self>,
        bundle: SignedConfigBundle,
    ) -> Result<()> {
        let prev_cfg = self.config.read().await.clone();
        let had_peers = !prev_cfg.peers.is_empty();
        let applied_seq = bundle.sequence;

        self.apply_signed_config(bundle).await?;

        if had_peers {
            let rt = Arc::clone(self);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(25)).await;
                let cur_seq = rt.config.read().await.config_sequence;
                if cur_seq != applied_seq {
                    return;
                }
                if !rt.link_manager.has_any_connected_session() {
                    error!(
                        node = %rt.node_tag(),
                        seq = applied_seq,
                        "node isolated from all peers 25s after config reload; auto-rolling back to previous valid config"
                    );
                    if let Err(e) = rt.restore_previous_config(prev_cfg, applied_seq).await {
                        error!(node = %rt.node_tag(), error = %e, "auto-rollback failed");
                    }
                }
            });
        }
        Ok(())
    }

    async fn restore_previous_config(&self, mut prev_cfg: NodeConfig, keep_seq: u64) -> Result<()> {
        let _lock = self.config_reload_lock.lock().await;
        prev_cfg.config_sequence = keep_seq;
        self.reload_tls_files(&prev_cfg.ingress.tls_certs).await?;
        self.persist_config_yaml(&prev_cfg).await?;
        let trusted_ctrl = collect_trusted_control_keys(&prev_cfg);
        if !trusted_ctrl.is_empty() {
            self.link_manager
                .set_trusted_control_pubkeys(trusted_ctrl)
                .await;
        }
        if let Some(ref lp) = prev_cfg.link_listener {
            self.link_manager.update_listener_policy(lp.clone()).await;
        }
        self.link_manager
            .update_peers(prev_cfg.peers.clone(), prev_cfg.probe.clone())
            .await;
        self.forwarder
            .update_config(prev_cfg.roles.clone(), prev_cfg.relay.clone())
            .await;
        self.egress
            .update_config(prev_cfg.egress.clone(), prev_cfg.trusted_origins.clone())
            .await;
        self.ingress.update_default_ttl(prev_cfg.default_ttl);
        self.ingress
            .update_config(
                prev_cfg.ingress.clone(),
                prev_cfg.roles.ingress && !prev_cfg.roles.maintainer,
            )
            .await?;
        self.logger.update_config(prev_cfg.logger.clone()).await?;
        self.reconcile_maintainer(&prev_cfg).await?;
        if prev_cfg.roles.egress && !self.egress_hc_started.swap(true, Ordering::AcqRel) {
            self.egress.spawn_local_health_checks();
        }
        if prev_cfg.roles.ingress && !self.geoip_updater_started.swap(true, Ordering::AcqRel) {
            Arc::clone(self.ingress.geoip()).spawn_updater();
        }
        *self.config.write().await = prev_cfg;
        let msg = "auto-rolled back: node isolated from all peers after config push".to_string();
        self.logger.emit_alert("error", msg.clone()).await;
        *self.last_reload_status.write().await = (false, Some(msg));
        Ok(())
    }

    async fn reconcile_maintainer(&self, cfg: &NodeConfig) -> Result<()> {
        let mut mlock = self.maintainer.write().await;
        if cfg.roles.maintainer {
            let mcfg = cfg.maintainer.clone().unwrap_or_default();
            if let Some(ref existing) = *mlock {
                existing.update_config(mcfg).await?;
            } else {
                let svc = MaintainerService::new(&cfg.node_tag, mcfg)?;
                svc.spawn_background_tasks(Arc::clone(&self.forwarder));
                *mlock = Some(svc);
            }
        } else if let Some(old) = mlock.take() {
            old.stop_background_tasks();
            let _ = old.flush_segments().await;
        }
        Ok(())
    }

    /// Serialized, validated hot-reload: validates all fallible operations before mutating runtime state.
    pub async fn apply_signed_config(&self, bundle: SignedConfigBundle) -> Result<()> {
        let _lock = self.config_reload_lock.lock().await;

        let (control_pk, control_link_pk, current_seq, prev_maint) = {
            let cfg = self.config.read().await;
            (
                cfg.control_public_key.clone(),
                cfg.control_link_public_key.clone(),
                cfg.config_sequence,
                cfg.maintainer.clone(),
            )
        };
        let control_pk = control_pk.ok_or_else(|| {
            ExposureError::Auth("node has no Control public key configured".into())
        })?;

        bundle.verify(
            &control_pk,
            &self.node_tag(),
            ConfigBundlePurpose::Apply,
            current_seq,
            Utc::now().timestamp(),
        )?;

        let mut new_cfg = bundle.config;
        // Preserve Maintainer-local DNS provider credentials when Control leaves secret fields blank
        if let (Some(new_m), Some(old_m)) = (&mut new_cfg.maintainer, &prev_maint) {
            for (pname, new_p) in &mut new_m.dns_providers {
                if let Some(old_p) = old_m.dns_providers.get(pname) {
                    match (new_p, old_p) {
                        (
                            DnsProviderAccountConfig::Cloudflare { api_token },
                            DnsProviderAccountConfig::Cloudflare { api_token: old_tok },
                        ) if api_token.trim().is_empty() && !old_tok.trim().is_empty() => {
                            *api_token = old_tok.clone();
                        }
                        (
                            DnsProviderAccountConfig::Aliyun {
                                access_key_id,
                                access_key_secret,
                                ..
                            },
                            DnsProviderAccountConfig::Aliyun {
                                access_key_id: old_ak,
                                access_key_secret: old_sk,
                                ..
                            },
                        ) => {
                            if access_key_id.trim().is_empty() && !old_ak.trim().is_empty() {
                                *access_key_id = old_ak.clone();
                            }
                            if access_key_secret.trim().is_empty() && !old_sk.trim().is_empty() {
                                *access_key_secret = old_sk.clone();
                            }
                        }
                        (
                            DnsProviderAccountConfig::Webhook { auth_header, .. },
                            DnsProviderAccountConfig::Webhook {
                                auth_header: old_auth,
                                ..
                            },
                        ) if auth_header.is_none() && old_auth.is_some() => {
                            *auth_header = old_auth.clone();
                        }
                        _ => {}
                    }
                }
            }
        }
        new_cfg.config_sequence = bundle.sequence;
        if !bundle.config_revision.is_empty() {
            new_cfg.config_revision = bundle.config_revision;
        }
        if new_cfg.control_public_key.is_none() {
            new_cfg.control_public_key = Some(control_pk);
        }
        if new_cfg.control_link_public_key.is_none() {
            new_cfg.control_link_public_key = control_link_pk;
        }
        if new_cfg.identity_secret_key.is_empty() {
            new_cfg.identity_secret_key = self.keypair.secret_key_b64();
        }

        // Pre-validate TLS cert files and YAML serialization atomically before mutating live components
        self.reload_tls_files(&new_cfg.ingress.tls_certs).await?;
        self.persist_config_yaml(&new_cfg).await?;

        // Update logger & maintainer (fallible) before mutating forwarding planes
        self.logger.update_config(new_cfg.logger.clone()).await?;
        self.reconcile_maintainer(&new_cfg).await?;

        let trusted_ctrl = collect_trusted_control_keys(&new_cfg);
        if !trusted_ctrl.is_empty() {
            self.link_manager
                .set_trusted_control_pubkeys(trusted_ctrl)
                .await;
        }
        if let Some(ref lp) = new_cfg.link_listener {
            self.link_manager.update_listener_policy(lp.clone()).await;
        }
        self.link_manager
            .update_peers(new_cfg.peers.clone(), new_cfg.probe.clone())
            .await;
        self.forwarder
            .update_config(new_cfg.roles.clone(), new_cfg.relay.clone())
            .await;
        self.egress
            .update_config(new_cfg.egress.clone(), new_cfg.trusted_origins.clone())
            .await;
        self.ingress.update_default_ttl(new_cfg.default_ttl);
        self.ingress
            .update_config(
                new_cfg.ingress.clone(),
                new_cfg.roles.ingress && !new_cfg.roles.maintainer,
            )
            .await?;

        if new_cfg.roles.egress && !self.egress_hc_started.swap(true, Ordering::AcqRel) {
            self.egress.spawn_local_health_checks();
        }
        if new_cfg.roles.ingress && !self.geoip_updater_started.swap(true, Ordering::AcqRel) {
            Arc::clone(self.ingress.geoip()).spawn_updater();
        }

        *self.config.write().await = new_cfg;
        *self.last_reload_status.write().await = (true, None);
        info!(node = %self.node_tag(), seq = bundle.sequence, "applied signed config hot reload");
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply_cert_bundle(
        &self,
        domain: &str,
        target_node_tag: &str,
        cert_pem: &str,
        key_pem: &str,
        issued_at: i64,
        expires_at: i64,
        maintainer_tag: &str,
        signature: &str,
    ) -> Result<()> {
        validate_dns_domain(domain)?;
        if target_node_tag != self.node_tag() {
            return Err(ExposureError::Auth(format!(
                "cert bundle target '{target_node_tag}' != local node '{}'",
                self.node_tag()
            )));
        }
        let now = Utc::now().timestamp();
        if expires_at <= now {
            return Err(ExposureError::Auth(format!(
                "cert bundle for '{domain}' already expired"
            )));
        }
        if issued_at > now + 300 {
            return Err(ExposureError::Auth(format!(
                "cert bundle for '{domain}' issued_at is too far in the future"
            )));
        }

        let norm_domain = domain.trim().to_ascii_lowercase();
        if let Some(prev_issued) = self.cert_last_issued_at.get(&norm_domain) {
            if issued_at <= *prev_issued {
                return Err(ExposureError::Auth(format!(
                    "cert bundle rollback rejected for '{domain}': issued_at {issued_at} <= {}",
                    *prev_issued
                )));
            }
        }

        let cfg = self.config.read().await.clone();
        let trusted = cfg
            .trusted_maintainers
            .iter()
            .find(|m| m.node_tag == maintainer_tag)
            .ok_or_else(|| ExposureError::Auth(format!("untrusted maintainer {maintainer_tag}")))?;

        let signing = cert_bundle_signing_bytes(
            domain,
            target_node_tag,
            cert_pem,
            key_pem,
            issued_at,
            expires_at,
            maintainer_tag,
        );
        verify_signature_b64(&trusted.public_key, &signing, signature)?;

        // Hot-reload into TLS SNI resolver first (validates PEM + keys_match before touching disk)
        self.cert_resolver
            .load_from_pem(domain, cert_pem, key_pem)?;
        self.cert_last_issued_at.insert(norm_domain, issued_at);

        // Persist to disk with atomic 0600 permissions for private key
        if let Some(ref dir_str) = cfg.ingress.cert_store_dir {
            let dir = PathBuf::from(dir_str);
            let safe = domain.replace('*', "_wildcard_");
            let cert_owned = cert_pem.to_string();
            let key_owned = key_pem.to_string();
            tokio::task::spawn_blocking(move || -> Result<()> {
                std::fs::create_dir_all(&dir)?;
                write_secret_file_atomic(
                    &dir.join(format!("{safe}.crt.pem")),
                    cert_owned.as_bytes(),
                )?;
                write_secret_file_atomic(
                    &dir.join(format!("{safe}.key.pem")),
                    key_owned.as_bytes(),
                )?;
                Ok(())
            })
            .await
            .map_err(|e| ExposureError::Storage(format!("cert persist join: {e}")))??;
        }
        Ok(())
    }

    fn spawn_active_bootstrap_dialer(self: &Arc<Self>, boot_addr: String) {
        let rt = Arc::clone(self);
        tokio::spawn(async move {
            for attempt in 1..=30 {
                if rt.config.read().await.control_public_key.is_some() {
                    return;
                }
                let pass = match rt.passphrase.read().await.clone() {
                    Some(p) if !p.revoked && Utc::now().timestamp() <= p.expires_at => p.phrase,
                    _ => return,
                };
                let mut nonce = vec![0u8; 24];
                rand::thread_rng().fill_bytes(&mut nonce);
                let pk = rt.keypair.public_key_b64();
                let proof = compute_passphrase_proof(&pass, &rt.node_tag(), &pk, &nonce);

                if let Ok((sess, outcome)) = rt
                    .link_manager
                    .dial_endpoint(
                        &boot_addr,
                        None,
                        None,
                        None,
                        Some((nonce.clone(), proof.clone())),
                        true,
                    )
                    .await
                {
                    let boot_tag = outcome.remote_node_tag.clone();
                    rt.link_manager
                        .register_outbound_session(
                            boot_addr.clone(),
                            boot_tag.clone(),
                            outcome.remote_public_key.clone(),
                            sess,
                            outcome.authenticated,
                        )
                        .await;
                    let req = SpecialFrame::new(
                        Uuid::new_v4().to_string(),
                        vec![rt.node_tag(), boot_tag.clone()],
                        8,
                        SpecialPayload::BootstrapForward {
                            node_tag: rt.node_tag(),
                            public_key: pk,
                            nonce: nonce.clone(),
                            proof,
                            via_node: boot_tag,
                        },
                    );
                    if let Ok(SpecialFrame {
                        payload:
                            SpecialPayload::BootstrapReply {
                                accepted: true,
                                control_public_key: Some(ctrl_pk),
                                control_link_public_key,
                                reply_proof: Some(rp),
                                nonce: reply_nonce,
                                ..
                            },
                        ..
                    }) = rt
                        .forwarder
                        .send_bootstrap_rpc(req, Duration::from_secs(10))
                        .await
                    {
                        let ctrl_link_pk =
                            control_link_public_key.unwrap_or_else(|| ctrl_pk.clone());
                        // Mutual authentication: verify Control proved knowledge of our onboarding passphrase!
                        if verify_bootstrap_reply_proof(
                            &pass,
                            &ctrl_pk,
                            &ctrl_link_pk,
                            &rt.node_tag(),
                            &reply_nonce,
                            &rp,
                        ) {
                            if let Err(e) = rt
                                .install_enrolled_control_keys(ctrl_pk, Some(ctrl_link_pk))
                                .await
                            {
                                warn!(node = %rt.node_tag(), error = %e, "active bootstrap key install failed");
                            } else {
                                info!(node = %rt.node_tag(), "active bootstrap onboarding succeeded");
                                return;
                            }
                        } else {
                            warn!(node = %rt.node_tag(), "active bootstrap rejected forged BootstrapReply (invalid passphrase proof)");
                        }
                    }
                }
                warn!(node = %rt.node_tag(), attempt, "active bootstrap attempt pending");
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });
    }

    async fn push_pending_logs_to_maintainer(&self) {
        const MAX_RECS_PER_BATCH: usize = 250;
        const MAX_SUMS_PER_BATCH: usize = 200;
        const MAX_FPS_PER_BATCH: usize = 200;
        const MAX_MISC_PER_BATCH: usize = 250;

        let self_tag = self.node_tag();
        let hops = self.config.read().await.maintainer_hops.clone();
        let local_maint = self.maintainer.read().await.clone();
        let is_local_maint =
            local_maint.is_some() && (hops.len() < 2 || hops.last() == Some(&self_tag));
        if !is_local_maint && hops.len() < 2 {
            return;
        }

        let mut batch = self.logger.drain_batch_for_maintainer().await;
        let active_bans = self.ingress.auto_ban().active_ban_records(&self_tag);
        if !active_bans.is_empty() || !batch.ban_records.is_empty() {
            let mut merged: HashMap<(String, String, String, u64), BanRecord> = HashMap::new();
            for b in batch.ban_records.drain(..).chain(active_bans.into_iter()) {
                let k = (
                    b.node_tag.clone(),
                    b.kind.clone(),
                    b.target.clone(),
                    b.banned_at_unix,
                );
                merged
                    .entry(k)
                    .and_modify(|cur| {
                        cur.hits_blocked = cur.hits_blocked.max(b.hits_blocked);
                        cur.expires_at_unix = cur.expires_at_unix.max(b.expires_at_unix);
                        cur.offense_level = cur.offense_level.max(b.offense_level);
                        if cur.service_tag.is_none() {
                            cur.service_tag = b.service_tag.clone();
                        }
                        if cur.host.is_none() {
                            cur.host = b.host.clone();
                        }
                    })
                    .or_insert(b);
            }
            batch.ban_records = merged.into_values().collect();
        }
        if batch.is_empty() {
            return;
        }

        if is_local_maint {
            if let Some(maint) = local_maint {
                let _ = maint
                    .ingest_log_batch(
                        &self_tag,
                        batch.records,
                        batch.summaries,
                        batch.fingerprints,
                        batch.evilpot_sessions,
                        batch.evilpot_events,
                        batch.ban_records,
                        batch.alerts,
                    )
                    .await;
            }
            return;
        }

        while !batch.is_empty() {
            let r_n = batch.records.len().min(MAX_RECS_PER_BATCH);
            let s_n = batch.summaries.len().min(MAX_SUMS_PER_BATCH);
            let f_n = batch.fingerprints.len().min(MAX_FPS_PER_BATCH);
            let es_n = batch.evilpot_sessions.len().min(MAX_MISC_PER_BATCH);
            let ee_n = batch.evilpot_events.len().min(MAX_MISC_PER_BATCH);
            let b_n = batch.ban_records.len().min(MAX_MISC_PER_BATCH);
            let a_n = batch.alerts.len().min(MAX_MISC_PER_BATCH);

            let rec_chunk: Vec<_> = batch.records.drain(..r_n).collect();
            let sum_chunk: Vec<_> = batch.summaries.drain(..s_n).collect();
            let fp_chunk: Vec<_> = batch.fingerprints.drain(..f_n).collect();
            let es_chunk: Vec<_> = batch.evilpot_sessions.drain(..es_n).collect();
            let ee_chunk: Vec<_> = batch.evilpot_events.drain(..ee_n).collect();
            let ban_chunk: Vec<_> = batch.ban_records.drain(..b_n).collect();
            let alert_chunk: Vec<_> = batch.alerts.drain(..a_n).collect();

            let frame = SpecialFrame::new(
                Uuid::new_v4().to_string(),
                hops.clone(),
                16,
                SpecialPayload::LogBatch {
                    from_node: self_tag.clone(),
                    records: rec_chunk.clone(),
                    minute_summaries: sum_chunk.clone(),
                    fingerprints: fp_chunk.clone(),
                    evilpot_sessions: es_chunk.clone(),
                    evilpot_events: ee_chunk.clone(),
                    ban_records: ban_chunk.clone(),
                    alerts: alert_chunk.clone(),
                },
            );
            let acked = match self
                .forwarder
                .send_special_rpc(frame, Duration::from_secs(10))
                .await
            {
                Ok(SpecialFrame {
                    payload: SpecialPayload::LogAck { .. },
                    ..
                }) => true,
                Ok(other) => {
                    warn!(reply = ?other.payload, "unexpected reply to LogBatch; requeuing unsent batches");
                    false
                }
                Err(e) => {
                    warn!(error = %e, "failed to push log batch to maintainer; requeuing unsent batches");
                    false
                }
            };
            if !acked {
                fn prepend<T>(mut head: Vec<T>, mut tail: Vec<T>) -> Vec<T> {
                    head.append(&mut tail);
                    head
                }
                self.logger
                    .requeue_batch_for_maintainer(DrainedLogBatch {
                        records: prepend(rec_chunk, batch.records),
                        summaries: prepend(sum_chunk, batch.summaries),
                        fingerprints: prepend(fp_chunk, batch.fingerprints),
                        evilpot_sessions: prepend(es_chunk, batch.evilpot_sessions),
                        evilpot_events: prepend(ee_chunk, batch.evilpot_events),
                        ban_records: prepend(ban_chunk, batch.ban_records),
                        alerts: prepend(alert_chunk, batch.alerts),
                    })
                    .await;
                break;
            }
        }
    }

    fn spawn_logger_tasks(self: &Arc<Self>) {
        let rt = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                let flush_secs = rt
                    .config
                    .read()
                    .await
                    .logger
                    .segment
                    .flush_interval_secs
                    .max(2);
                // Wake up either on periodic flush interval OR immediately when batch records/bytes hit max threshold
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(flush_secs)) => {}
                    _ = rt.logger.wait_early_flush() => {
                        // Short coalesce window so high-TPS bursts batch efficiently into one frame
                        tokio::time::sleep(Duration::from_millis(300)).await;
                    }
                }
                rt.push_pending_logs_to_maintainer().await;
                if let Err(e) = rt.logger.flush_segments().await {
                    warn!(error = %e, "periodic node segment flush failed");
                }
            }
        });
    }

    fn spawn_passphrase_expiry_watcher(self: &Arc<Self>) {
        let rt = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(15)).await;
                let expired = rt
                    .passphrase
                    .read()
                    .await
                    .as_ref()
                    .map(|p| !p.revoked && Utc::now().timestamp() > p.expires_at)
                    .unwrap_or(false);
                if expired {
                    rt.revoke_passphrase().await;
                    info!(node = %rt.node_tag(), "one-time onboarding passphrase expired and revoked");
                }
            }
        });
    }

    /// Graceful shutdown hook (SIGINT / SIGTERM): pushes pending logs and flushes segments & checkpoints atomically.
    pub async fn shutdown(&self) {
        info!(node = %self.node_tag(), "flushing logs and segments before shutdown");
        let ingress = Arc::clone(&self.ingress);
        let _ = tokio::task::spawn_blocking(move || {
            let _ = ingress.persist_active_bans_blocking();
        })
        .await;
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            self.push_pending_logs_to_maintainer(),
        )
        .await;
        let _ = self.logger.flush_all().await;
        if let Some(maint) = self.maintainer.read().await.clone() {
            maint.stop_background_tasks();
            let _ = maint.flush_segments().await;
        }
    }
}
