use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use exposure_core::config::{LinkMode, NodeConfig, SignedConfigBundle, TunnelDirection};
use exposure_core::crypto::{
    compute_passphrase_proof, generate_five_word_passphrase, verify_signature_b64, NodeKeyPair,
};
use exposure_core::protocol::{
    cert_bundle_signing_bytes, discovery_resp_signing_bytes, DiscoveryNeighbor, NodeStatusSnapshot,
    PreflightCheckItem, PreflightReport, SpecialFrame, SpecialPayload,
};
use exposure_core::{ExposureError, Result};
use exposure_link::LinkManager;
use rand::RngCore;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::egress::EgressHandler;
use crate::forwarder::Forwarder;
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
        if let Some(ref ctrl_pk) = config.control_public_key {
            link_manager
                .set_trusted_control_pubkeys(vec![ctrl_pk.clone()])
                .await;
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

        let egress = EgressHandler::new(&config.node_tag, config.egress.clone(), Arc::clone(&logger));
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

    /// Generate or reset a 5-word one-time passphrase valid for 10 minutes.
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

        // Active onboarding if bootstrap_tunnel_addr + passphrase are present and control_public_key is unset
        if cfg.control_public_key.is_none() {
            if let Some(ref boot_addr) = cfg.bootstrap_tunnel_addr {
                self.spawn_active_bootstrap_dialer(boot_addr.clone());
            }
        }

        Ok((link_bound, ingress_addrs))
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
                    // If Control authenticated via our local bootstrap passphrase, install Control pubkey & revoke passphrase!
                    if incoming.bootstrap_pending {
                        let pk = incoming.remote_public_key.clone();
                        let mut cfg = rt.config.write().await;
                        if cfg.control_public_key.is_none() {
                            cfg.control_public_key = Some(pk.clone());
                            rt.link_manager
                                .set_trusted_control_pubkeys(vec![pk])
                                .await;
                            drop(cfg);
                            rt.revoke_passphrase().await;
                            info!(
                                node = %rt.node_tag(),
                                control = %incoming.remote_node_tag,
                                "installed Control public key and revoked onboarding passphrase"
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
        mut rx: tokio::sync::mpsc::Receiver<SpecialFrame>,
    ) {
        let rt = Arc::clone(self);
        tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                let rt2 = Arc::clone(&rt);
                tokio::spawn(async move {
                    rt2.handle_local_special_frame(frame).await;
                });
            }
        });
    }

    async fn handle_local_special_frame(self: &Arc<Self>, frame: SpecialFrame) {
        let reply_payload: Option<SpecialPayload> = match frame.payload.clone() {
            SpecialPayload::PreflightReq(bundle) => {
                Some(self.handle_preflight_request(*bundle).await)
            }
            SpecialPayload::ConfigPush(bundle) => {
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
            SpecialPayload::DiscoveryReq { request_id, .. } => {
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
            SpecialPayload::LogBatch {
                from_node,
                records,
                minute_summaries,
            } => {
                if let Some(maint) = self.maintainer.read().await.clone() {
                    let accepted = maint
                        .ingest_log_batch(&from_node, records, minute_summaries)
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
                cert_pem,
                key_pem,
                issued_at,
                expires_at,
                maintainer_tag,
                signature,
            } => {
                match self
                    .apply_cert_bundle(
                        &domain,
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
            SpecialPayload::StatusReq => {
                let cfg = self.config.read().await.clone();
                let links = self.link_manager.link_snapshots().await;
                let (ok, err) = self.last_reload_status.read().await.clone();
                let alerts = self.logger.recent_alerts().await;
                Some(SpecialPayload::StatusResp(NodeStatusSnapshot {
                    node_tag: cfg.node_tag,
                    roles: cfg.roles,
                    config_sequence: cfg.config_sequence,
                    last_reload_ok: ok,
                    last_reload_error: err,
                    uptime_secs: self.started_at.elapsed().as_secs(),
                    links,
                    alerts,
                }))
            }
            SpecialPayload::PullTelemetryReq { since_minute } => {
                if let Some(maint) = self.maintainer.read().await.clone() {
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
                // Relay bootstrap enrollment request to connected Control
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
                            error: Some(format!("control forward failed: {e}")),
                        }),
                    }
                } else {
                    Some(SpecialPayload::BootstrapReply {
                        accepted: false,
                        control_public_key: None,
                        error: Some("no active control connected to bootstrap node".into()),
                    })
                }
            }
            SpecialPayload::DialEnrollReq {
                target_node_tag,
                target_addr,
                passphrase,
                control_public_key,
            } => {
                // Relay node dials a listening new node on Control's behalf using passphrase proof
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
                    .dial_endpoint(&target_addr, None, None, Some((nonce, proof)))
                    .await
                {
                    Ok((sess, outcome)) => {
                        let node_pk = outcome.remote_public_key.clone();
                        self.link_manager.register_outbound_session(
                            target_addr,
                            target_node_tag.clone(),
                            sess,
                            true,
                        );
                        // Notify enrolled node of Control public key via BootstrapReply
                        let install = SpecialFrame::new(
                            Uuid::new_v4().to_string(),
                            vec![self.node_tag(), target_node_tag],
                            4,
                            SpecialPayload::BootstrapReply {
                                accepted: true,
                                control_public_key: Some(control_public_key),
                                error: None,
                            },
                        );
                        let _ = self.forwarder.send_special(install).await;
                        Some(SpecialPayload::DialEnrollResp {
                            success: true,
                            node_public_key: Some(node_pk),
                            error: None,
                        })
                    }
                    Err(e) => Some(SpecialPayload::DialEnrollResp {
                        success: false,
                        node_public_key: None,
                        error: Some(e.to_string()),
                    }),
                }
            }
            SpecialPayload::BootstrapReply {
                accepted: true,
                control_public_key: Some(pk),
                ..
            } => {
                let mut cfg = self.config.write().await;
                cfg.control_public_key = Some(pk.clone());
                self.link_manager
                    .set_trusted_control_pubkeys(vec![pk])
                    .await;
                drop(cfg);
                self.revoke_passphrase().await;
                info!(node = %self.node_tag(), "enrolled with Control and revoked passphrase");
                None
            }
            _ => None,
        };

        if let Some(payload) = reply_payload {
            let reply = frame.reverse_for_reply(payload);
            if let Err(e) = self.forwarder.send_special(reply).await {
                warn!(id = %frame.id, error = %e, "failed to send reversed-hop reply");
            }
        }
    }

    /// Verify Control signature, sequence anti-rollback, and expiry, then atomically hot-reload config.
    /// Run non-mutating preflight connectivity & port checks for a candidate Control-signed config.
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
        if let Err(e) = bundle.verify(&control_pk, current_seq, Utc::now().timestamp()) {
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

        // 1. Check peer endpoints reachability (outbound tunnels & on-demand)
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

        // 2. Check new ingress listener bindability
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

        // 3. Check egress backends reachability
        for (svc_tag, svc) in &cand.egress.services {
            match tokio::time::timeout(
                Duration::from_millis(1500),
                tokio::net::TcpStream::connect(&svc.backend),
            )
            .await
            {
                Ok(Ok(_)) => checks.push(PreflightCheckItem {
                    target: format!("egress:{} -> {}", svc_tag, svc.backend),
                    ok: true,
                    detail: "backend TCP reachable".into(),
                }),
                Ok(Err(e)) => checks.push(PreflightCheckItem {
                    target: format!("egress:{} -> {}", svc_tag, svc.backend),
                    ok: false,
                    detail: format!("backend connect failed: {e}"),
                }),
                Err(_) => checks.push(PreflightCheckItem {
                    target: format!("egress:{} -> {}", svc_tag, svc.backend),
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
        prev_cfg.config_sequence = keep_seq;
        self.link_manager
            .update_peers(prev_cfg.peers.clone(), prev_cfg.probe.clone())
            .await;
        self.forwarder
            .update_config(prev_cfg.roles.clone(), prev_cfg.relay.clone())
            .await;
        self.egress.update_config(prev_cfg.egress.clone()).await;
        self.ingress.update_config(prev_cfg.ingress.clone()).await?;
        self.logger.update_config(prev_cfg.logger.clone()).await?;
        if let Some(ref path) = self.config_path {
            atomic_write_yaml(path, &prev_cfg)?;
        }
        *self.config.write().await = prev_cfg;
        let msg = "auto-rolled back: node isolated from all peers after config push".to_string();
        self.logger.emit_alert("error", msg.clone()).await;
        *self.last_reload_status.write().await = (false, Some(msg));
        Ok(())
    }

    /// On failure, previous valid config remains completely untouched!
    pub async fn apply_signed_config(&self, bundle: SignedConfigBundle) -> Result<()> {
        let (control_pk, current_seq) = {
            let cfg = self.config.read().await;
            (cfg.control_public_key.clone(), cfg.config_sequence)
        };
        let control_pk = control_pk.ok_or_else(|| {
            ExposureError::Auth("node has no Control public key configured".into())
        })?;
        if bundle.node_tag != self.node_tag() {
            return Err(ExposureError::Auth(format!(
                "config bundle target {} != local node {}",
                bundle.node_tag,
                self.node_tag()
            )));
        }

        bundle.verify(&control_pk, current_seq, Utc::now().timestamp())?;

        // Validate new config before mutating runtime state
        let mut new_cfg = bundle.config;
        new_cfg.config_sequence = bundle.sequence;
        if new_cfg.control_public_key.is_none() {
            new_cfg.control_public_key = Some(control_pk);
        }
        // Preserve local identity secret key if omitted by compiler
        if new_cfg.identity_secret_key.is_empty() {
            new_cfg.identity_secret_key = self.keypair.secret_key_b64();
        }
        // Validate TLS certs if specified
        if !new_cfg.ingress.tls_certs.is_empty() {
            self.cert_resolver
                .load_from_files(&new_cfg.ingress.tls_certs)?;
        }

        // Apply to runtime components
        self.link_manager
            .update_peers(new_cfg.peers.clone(), new_cfg.probe.clone())
            .await;
        self.forwarder
            .update_config(new_cfg.roles.clone(), new_cfg.relay.clone())
            .await;
        self.egress.update_config(new_cfg.egress.clone()).await;
        self.ingress.update_config(new_cfg.ingress.clone()).await?;
        self.logger.update_config(new_cfg.logger.clone()).await?;

        if new_cfg.roles.maintainer {
            let mcfg = new_cfg.maintainer.clone().unwrap_or_default();
            let mut mlock = self.maintainer.write().await;
            if let Some(ref existing) = *mlock {
                existing.update_config(mcfg).await?;
            } else {
                let svc = MaintainerService::new(&new_cfg.node_tag, mcfg)?;
                svc.spawn_background_tasks(Arc::clone(&self.forwarder));
                *mlock = Some(svc);
            }
        }

        // Persist config atomically to disk if config_path is configured (no local encryption per user decision)
        if let Some(ref path) = self.config_path {
            atomic_write_yaml(path, &new_cfg)?;
        }

        *self.config.write().await = new_cfg;
        *self.last_reload_status.write().await = (true, None);
        info!(node = %self.node_tag(), seq = bundle.sequence, "applied signed config hot reload");
        Ok(())
    }

    async fn apply_cert_bundle(
        &self,
        domain: &str,
        cert_pem: &str,
        key_pem: &str,
        issued_at: i64,
        expires_at: i64,
        maintainer_tag: &str,
        signature: &str,
    ) -> Result<()> {
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
            cert_pem,
            key_pem,
            issued_at,
            expires_at,
            maintainer_tag,
        );
        verify_signature_b64(&trusted.public_key, &signing, signature)?;

        // Hot-reload into TLS SNI resolver first (validates PEM before touching disk)
        self.cert_resolver.load_from_pem(domain, cert_pem, key_pem)?;

        // Persist to disk with 0600 permissions for private key
        if let Some(ref dir_str) = cfg.ingress.cert_store_dir {
            let dir = Path::new(dir_str);
            std::fs::create_dir_all(dir)?;
            let safe = domain.replace('*', "_wildcard_");
            std::fs::write(dir.join(format!("{safe}.crt.pem")), cert_pem)?;
            let key_path = dir.join(format!("{safe}.key.pem"));
            std::fs::write(&key_path, key_pem)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
            }
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
                    .dial_endpoint(&boot_addr, None, None, Some((nonce.clone(), proof.clone())))
                    .await
                {
                    let boot_tag = outcome.remote_node_tag.clone();
                    rt.link_manager.register_outbound_session(
                        boot_addr.clone(),
                        boot_tag.clone(),
                        sess,
                        outcome.authenticated,
                    );
                    let req = SpecialFrame::new(
                        Uuid::new_v4().to_string(),
                        vec![rt.node_tag(), boot_tag.clone()],
                        8,
                        SpecialPayload::BootstrapForward {
                            node_tag: rt.node_tag(),
                            public_key: pk,
                            nonce,
                            proof,
                            via_node: boot_tag,
                        },
                    );
                    if let Ok(SpecialFrame {
                        payload:
                            SpecialPayload::BootstrapReply {
                                accepted: true,
                                control_public_key: Some(ctrl_pk),
                                ..
                            },
                        ..
                    }) = rt
                        .forwarder
                        .send_special_rpc(req, Duration::from_secs(10))
                        .await
                    {
                        rt.config.write().await.control_public_key = Some(ctrl_pk.clone());
                        rt.link_manager
                            .set_trusted_control_pubkeys(vec![ctrl_pk])
                            .await;
                        rt.revoke_passphrase().await;
                        info!(node = %rt.node_tag(), "active bootstrap onboarding succeeded");
                        return;
                    }
                }
                warn!(node = %rt.node_tag(), attempt, "active bootstrap attempt pending");
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });
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
                tokio::time::sleep(Duration::from_secs(flush_secs)).await;
                if let Err(e) = rt.logger.flush_segments().await {
                    warn!(error = %e, "periodic node segment flush failed");
                }
                let hops = rt.config.read().await.maintainer_hops.clone();
                if hops.len() >= 2 {
                    let (records, summaries) = rt.logger.drain_for_maintainer().await;
                    if !records.is_empty() || !summaries.is_empty() {
                        let frame = SpecialFrame::new(
                            Uuid::new_v4().to_string(),
                            hops,
                            16,
                            SpecialPayload::LogBatch {
                                from_node: rt.node_tag(),
                                records,
                                minute_summaries: summaries,
                            },
                        );
                        if let Err(e) = rt.forwarder.send_special(frame).await {
                            warn!(error = %e, "failed to push log batch to maintainer");
                        }
                    }
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

    /// Graceful shutdown hook (SIGINT / SIGTERM): flushes pending log segments atomically.
    pub async fn shutdown(&self) {
        info!(node = %self.node_tag(), "flushing segments before shutdown");
        let _ = self.logger.flush_segments().await;
        if let Some(maint) = self.maintainer.read().await.clone() {
            let _ = maint.flush_segments().await;
        }
    }
}

fn atomic_write_yaml<T: serde::Serialize>(path: &Path, val: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let yaml = serde_yaml::to_string(val)
        .map_err(|e| ExposureError::Config(format!("serialize yaml: {e}")))?;
    let tmp = path.with_extension("yaml.tmp");
    std::fs::write(&tmp, yaml)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
