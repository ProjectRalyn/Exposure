use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use dashmap::DashMap;
use exposure_core::config::{
    ConfigBundlePurpose, DnsProviderAccountConfig, LinkMode, NodeConfig, SignedConfigBundle,
    TunnelDirection,
};
use exposure_core::crypto::{
    compute_bootstrap_reply_proof, compute_passphrase_proof, generate_five_word_passphrase,
    validate_dns_domain, verify_bootstrap_reply_proof, verify_signature_b64,
    write_secret_file_atomic, NodeKeyPair,
};
use exposure_core::protocol::{
    cert_bundle_signing_bytes, dial_enroll_req_signing_bytes, discovery_resp_signing_bytes,
    dns_manage_req_signing_bytes, dns_sync_req_signing_bytes, DiscoveryNeighbor, DnsManageOp,
    DnsProviderCapabilities, DnsSyncRecordSpec, NodeStatusSnapshot, PreflightCheckItem,
    PreflightReport, SpecialFrame, SpecialPayload, StreamKind,
};
use exposure_core::{ExposureError, Result};
use exposure_link::LinkManager;
use rand::RngCore;
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::egress::EgressHandler;
use crate::forwarder::{Forwarder, IncomingSpecialFrame};
use crate::ingress::IngressServer;
use crate::logger::NodeLogger;
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
    /// Spent `DialEnrollReq.request_id` cache for replay protection.
    used_dial_enroll_ids: Arc<DashMap<String, i64>>,
    /// Spent `DnsSyncReq.request_id` cache for replay protection.
    used_dns_sync_ids: Arc<DashMap<String, i64>>,
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
            used_dial_enroll_ids: Arc::new(DashMap::new()),
            used_dns_sync_ids: Arc::new(DashMap::new()),
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

    /// Generate or reset a high-entropy one-time passphrase valid for 10 minutes.
    pub async fn reset_passphrase(&self) -> String {
        let phrase = generate_five_word_passphrase();
        let entry = OnboardingPassphrase {
            phrase: phrase.clone(),
            expires_at: Utc::now().timestamp() + 600,
            revoked: false,
        };
        *self.passphrase.write().await = Some(entry);
        self.link_manager
            .set_bootstrap_passphrase(Some(phrase.clone()))
            .await;
        phrase
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

        if cfg.roles.egress {
            self.egress.spawn_local_health_checks();
        }

        let mut ingress_addrs = Vec::new();
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

    async fn install_enrolled_control_keys(
        &self,
        signing_pk: String,
        link_pk: Option<String>,
    ) -> Result<()> {
        let mut cfg = self.config.write().await;
        if cfg.control_public_key.is_some() {
            return Err(ExposureError::Auth(
                "node is already enrolled with a Control public key".into(),
            ));
        }
        let eff_link_pk = link_pk.unwrap_or_else(|| signing_pk.clone());
        cfg.control_public_key = Some(signing_pk);
        cfg.control_link_public_key = Some(eff_link_pk);
        let trusted = collect_trusted_control_keys(&cfg);
        if let Some(ref path) = self.config_path {
            atomic_write_yaml(path, &*cfg)?;
        }
        drop(cfg);
        self.link_manager
            .set_trusted_control_pubkeys(trusted)
            .await;
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
                            let mut cfg = rt.config.write().await;
                            cfg.control_link_public_key = Some(link_pk.clone());
                            if cfg.control_public_key.is_none() {
                                cfg.control_public_key = Some(link_pk.clone());
                            }
                            let trusted = collect_trusted_control_keys(&cfg);
                            if let Some(ref path) = rt.config_path {
                                let _ = atomic_write_yaml(path, &*cfg);
                            }
                            drop(cfg);
                            rt.link_manager
                                .set_trusted_control_pubkeys(trusted)
                                .await;
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
                    match self.apply_signed_config_with_watchdog(*bundle).await {
                        Ok(()) => Some(SpecialPayload::ConfigAck {
                            node_tag: self.node_tag(),
                            sequence: seq,
                            applied: true,
                            error: None,
                        }),
                        Err(e) => {
                            error!(node = %self.node_tag(), seq, error = %e, "config hot reload failed, kept previous config");
                            *self.last_reload_status.write().await = (false, Some(e.to_string()));
                            Some(SpecialPayload::ConfigAck {
                                node_tag: self.node_tag(),
                                sequence: seq,
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
            } => {
                if !incoming.authenticated {
                    None
                } else if let Some(maint) = self.maintainer.read().await.clone() {
                    let accepted = maint
                        .ingest_log_batch(&from_node, records, minute_summaries, fingerprints)
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
                    Some(SpecialPayload::StatusResp(NodeStatusSnapshot {
                        node_tag: cfg.node_tag,
                        roles: cfg.roles,
                        config_sequence: cfg.config_sequence,
                        last_reload_ok: ok,
                        last_reload_error: err,
                        uptime_secs: self.started_at.elapsed().as_secs(),
                        links,
                        alerts,
                        evilpot,
                    }))
                }
            }
            SpecialPayload::PullTelemetryReq { since_minute } => {
                if !incoming.authenticated {
                    None
                } else if let Some(maint) = self.maintainer.read().await.clone() {
                    let snap = maint.build_telemetry_snapshot(since_minute).await;
                    Some(SpecialPayload::PullTelemetryResp(snap))
                } else {
                    Some(SpecialPayload::ErrorReply {
                        message: "node is not maintainer".into(),
                    })
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
                } else {
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
                                via_node,
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

                let link_pk = control_link_public_key.clone().unwrap_or_else(|| pk.clone());

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
                        // If Control already matched trusted_control_pubkeys on reconnect, allow only matching key
                        _ => self
                            .config
                            .read()
                            .await
                            .control_public_key
                            .as_deref()
                            .map(|existing| existing == pk)
                            .unwrap_or(true),
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
                    let mut cfg = self.config.write().await;
                    if cfg.control_public_key.as_deref() == cfg.control_link_public_key.as_deref() {
                        cfg.control_public_key = Some(pk);
                        cfg.control_link_public_key = Some(link_pk);
                        let trusted = collect_trusted_control_keys(&cfg);
                        if let Some(ref path) = self.config_path {
                            let _ = atomic_write_yaml(path, &*cfg);
                        }
                        drop(cfg);
                        self.link_manager
                            .set_trusted_control_pubkeys(trusted)
                            .await;
                        self.revoke_passphrase().await;
                    }
                } else if let Err(e) = self
                    .install_enrolled_control_keys(pk, Some(link_pk))
                    .await
                {
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
        // 1. Verify Control authorization signature using this node's pinned control_public_key!
        let local_ctrl_pk = self.config.read().await.control_public_key.clone();
        let Some(local_ctrl_pk) = local_ctrl_pk else {
            return SpecialPayload::DialEnrollResp {
                success: false,
                node_public_key: None,
                error: Some("relay node has no Control public key configured".into()),
            };
        };
        let now = Utc::now().timestamp();
        if now > expires_at || issued_at > now + 60 {
            return SpecialPayload::DialEnrollResp {
                success: false,
                node_public_key: None,
                error: Some("DialEnrollReq expired or invalid timestamp".into()),
            };
        }
        let signing = dial_enroll_req_signing_bytes(
            &request_id,
            issued_at,
            expires_at,
            &self.node_tag(),
            &target_node_tag,
            &target_addr,
            &passphrase,
            &control_public_key,
            &control_link_public_key,
        );
        if let Err(e) = verify_signature_b64(&local_ctrl_pk, &signing, &control_signature) {
            return SpecialPayload::DialEnrollResp {
                success: false,
                node_public_key: None,
                error: Some(format!("DialEnrollReq signature invalid: {e}")),
            };
        }

        // 2. Single-use request_id anti-replay check
        if self.used_dial_enroll_ids.len() > 4096 {
            self.used_dial_enroll_ids.retain(|_, exp| *exp >= now);
        }
        let mut is_new = false;
        self.used_dial_enroll_ids
            .entry(request_id)
            .or_insert_with(|| {
                is_new = true;
                expires_at
            });
        if !is_new {
            return SpecialPayload::DialEnrollResp {
                success: false,
                node_public_key: None,
                error: Some("DialEnrollReq replay rejected".into()),
            };
        }

        // 3. Dial the listening node, enforcing expected node_tag & mutual authentication
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
                let _ = self.forwarder.send_bootstrap(install).await;
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

        if maintainer_tag != self.node_tag() {
            return reject(format!(
                "DnsSyncReq target '{maintainer_tag}' != local node '{}'",
                self.node_tag()
            ));
        }

        let local_ctrl_pk = self.config.read().await.control_public_key.clone();
        let Some(local_ctrl_pk) = local_ctrl_pk else {
            return reject("node has no Control public key configured".into());
        };

        let now = Utc::now().timestamp();
        if now > expires_at || issued_at > now + 60 {
            return reject("DnsSyncReq expired or invalid timestamp".into());
        }

        let signing = dns_sync_req_signing_bytes(
            &request_id,
            issued_at,
            expires_at,
            &maintainer_tag,
            &records,
        );
        if let Err(e) = verify_signature_b64(&local_ctrl_pk, &signing, &control_signature) {
            return reject(format!("DnsSyncReq signature invalid: {e}"));
        }

        if self.used_dns_sync_ids.len() > 4096 {
            self.used_dns_sync_ids.retain(|_, exp| *exp >= now);
        }
        let mut is_new = false;
        self.used_dns_sync_ids
            .entry(request_id.clone())
            .or_insert_with(|| {
                is_new = true;
                expires_at
            });
        if !is_new {
            return reject("DnsSyncReq replay rejected".into());
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

        if maintainer_tag != self.node_tag() {
            return reject(format!(
                "DnsManageReq target '{maintainer_tag}' != local node '{}'",
                self.node_tag()
            ));
        }

        let local_ctrl_pk = self.config.read().await.control_public_key.clone();
        let Some(local_ctrl_pk) = local_ctrl_pk else {
            return reject("node has no Control public key configured".into());
        };

        let now = Utc::now().timestamp();
        if now > expires_at || issued_at > now + 60 {
            return reject("DnsManageReq expired or invalid timestamp".into());
        }

        let signing = dns_manage_req_signing_bytes(
            &request_id,
            issued_at,
            expires_at,
            &maintainer_tag,
            &op,
        );
        if let Err(e) = verify_signature_b64(&local_ctrl_pk, &signing, &control_signature) {
            return reject(format!("DnsManageReq signature invalid: {e}"));
        }

        if self.used_dns_sync_ids.len() > 4096 {
            self.used_dns_sync_ids.retain(|_, exp| *exp >= now);
        }
        let mut is_new = false;
        self.used_dns_sync_ids
            .entry(request_id.clone())
            .or_insert_with(|| {
                is_new = true;
                expires_at
            });
        if !is_new {
            return reject("DnsManageReq replay rejected".into());
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
            (cfg.control_public_key.clone(), cfg.config_sequence, listeners)
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
                        let use_h2 = svc.protocol == exposure_core::config::BackendProtocol::H2;
                        match tokio::time::timeout(
                            Duration::from_millis(2000),
                            crate::egress::connect_backend_tls(tcp, svc, use_h2),
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
        let trusted_ctrl = collect_trusted_control_keys(&prev_cfg);
        if !trusted_ctrl.is_empty() {
            self.link_manager
                .set_trusted_control_pubkeys(trusted_ctrl)
                .await;
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
        self.ingress
            .update_config(
                prev_cfg.ingress.clone(),
                prev_cfg.roles.ingress && !prev_cfg.roles.maintainer,
            )
            .await?;
        self.logger.update_config(prev_cfg.logger.clone()).await?;
        self.reconcile_maintainer(&prev_cfg).await?;
        if let Some(ref path) = self.config_path {
            atomic_write_yaml(path, &prev_cfg)?;
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
        if new_cfg.control_public_key.is_none() {
            new_cfg.control_public_key = Some(control_pk);
        }
        if new_cfg.control_link_public_key.is_none() {
            new_cfg.control_link_public_key = control_link_pk;
        }
        if new_cfg.identity_secret_key.is_empty() {
            new_cfg.identity_secret_key = self.keypair.secret_key_b64();
        }

        // Pre-validate YAML serialization and TLS cert files before mutating live components
        let yaml_bytes = serde_yaml::to_string(&new_cfg)
            .map_err(|e| ExposureError::Config(format!("serialize yaml: {e}")))?;
        self.cert_resolver
            .load_from_files(&new_cfg.ingress.tls_certs)?;

        // Persist atomically with 0o600 permissions before applying to memory
        if let Some(ref path) = self.config_path {
            write_secret_file_atomic(path, yaml_bytes.as_bytes())?;
        }

        // Update logger & maintainer (fallible) before mutating forwarding planes
        self.logger.update_config(new_cfg.logger.clone()).await?;
        self.reconcile_maintainer(&new_cfg).await?;

        let trusted_ctrl = collect_trusted_control_keys(&new_cfg);
        if !trusted_ctrl.is_empty() {
            self.link_manager
                .set_trusted_control_pubkeys(trusted_ctrl)
                .await;
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
        self.ingress
            .update_config(
                new_cfg.ingress.clone(),
                new_cfg.roles.ingress && !new_cfg.roles.maintainer,
            )
            .await?;

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
            .ok_or_else(|| {
                ExposureError::Auth(format!("untrusted maintainer {maintainer_tag}"))
            })?;

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
        self.cert_resolver.load_from_pem(domain, cert_pem, key_pem)?;
        self.cert_last_issued_at.insert(norm_domain, issued_at);

        // Persist to disk with atomic 0600 permissions for private key
        if let Some(ref dir_str) = cfg.ingress.cert_store_dir {
            let dir = Path::new(dir_str);
            std::fs::create_dir_all(dir)?;
            let safe = domain.replace('*', "_wildcard_");
            std::fs::write(dir.join(format!("{safe}.crt.pem")), cert_pem)?;
            let key_path = dir.join(format!("{safe}.key.pem"));
            write_secret_file_atomic(&key_path, key_pem.as_bytes())?;
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
                        let ctrl_link_pk = control_link_public_key.unwrap_or_else(|| ctrl_pk.clone());
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
        let hops = self.config.read().await.maintainer_hops.clone();
        if hops.len() < 2 {
            return;
        }
        let (records, summaries, fingerprints) = self.logger.drain_for_maintainer().await;
        if records.is_empty() && summaries.is_empty() && fingerprints.is_empty() {
            return;
        }
        let frame = SpecialFrame::new(
            Uuid::new_v4().to_string(),
            hops,
            16,
            SpecialPayload::LogBatch {
                from_node: self.node_tag(),
                records: records.clone(),
                minute_summaries: summaries.clone(),
                fingerprints: fingerprints.clone(),
            },
        );
        if let Err(e) = self.forwarder.send_special(frame).await {
            warn!(error = %e, "failed to push log batch to maintainer; requeuing");
            self.logger
                .requeue_for_maintainer(records, summaries, fingerprints)
                .await;
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
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            self.push_pending_logs_to_maintainer(),
        )
        .await;
        let _ = self.logger.flush_segments().await;
        if let Some(maint) = self.maintainer.read().await.clone() {
            maint.stop_background_tasks();
            let _ = maint.flush_segments().await;
        }
    }
}

fn atomic_write_yaml<T: serde::Serialize>(path: &Path, val: &T) -> Result<()> {
    let yaml = serde_yaml::to_string(val)
        .map_err(|e| ExposureError::Config(format!("serialize yaml: {e}")))?;
    write_secret_file_atomic(path, yaml.as_bytes())
}
