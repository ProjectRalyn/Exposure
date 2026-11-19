use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use dashmap::DashMap;
use exposure_core::config::{
    BootstrapNodeTarget, ControlConfig, NodeConfig, NodeRoles, ProbeConfig, SignedConfigBundle,
    TopologySpec,
};
use exposure_core::crypto::{
    compute_passphrase_proof, verify_passphrase_proof, verify_signature_b64, NodeKeyPair,
};
use exposure_core::protocol::{
    discovery_resp_signing_bytes, read_json_frame, write_json_frame, MaintainerTelemetrySnapshot,
    NodeStatusSnapshot, SpecialFrame, SpecialPayload, StreamKind,
};
use exposure_core::telemetry::{AlertRecord, CertStatusInfo, LinkStatusSnapshot, MinuteSummary};
use exposure_core::{ExposureError, Result};
use exposure_link::LinkManager;
use rand::RngCore;
use tokio::sync::{oneshot, RwLock};
use tracing::{info, warn};
use uuid::Uuid;

use crate::compiler::{compile_topology, compute_control_hops, CompileReport};
use crate::db::ControlDb;

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct MaintainerHealthInfo {
    pub maintainer_tag: String,
    pub segment_backlog: usize,
    pub merge_latency_ms: f64,
}

#[derive(Debug, Default, Clone)]
pub struct CachedTelemetry {
    pub links: Vec<LinkStatusSnapshot>,
    pub summaries: Vec<MinuteSummary>,
    pub certificates: Vec<CertStatusInfo>,
    pub alerts: Vec<AlertRecord>,
    pub maintainers: Vec<MaintainerHealthInfo>,
    pub node_uptimes: HashMap<String, u64>,
    pub last_pulled_at: Option<String>,
}

/// Control Mesh Client (DESIGN.md §5, §9, §10):
/// Connects as a special client to one or more tunnel-listening bootstrap Nodes,
/// orchestrates all Nodes & Maintainers along explicit Hop Tables, and actively pulls telemetry.
pub struct ControlClient {
    cfg: ControlConfig,
    signing_kp: NodeKeyPair,
    link_manager: Arc<LinkManager>,
    db: Arc<ControlDb>,
    active_bootstrap_node: Arc<RwLock<Option<String>>>,
    pending_replies: Arc<DashMap<String, oneshot::Sender<SpecialFrame>>>,
    telemetry_cache: Arc<RwLock<CachedTelemetry>>,
}

impl ControlClient {
    pub fn new(cfg: ControlConfig, db: Arc<ControlDb>) -> Result<Arc<Self>> {
        let signing_kp = NodeKeyPair::from_secret_b64(&cfg.signing_secret_key)?;
        let link_kp = if cfg.link_secret_key.is_empty() {
            signing_kp.clone()
        } else {
            NodeKeyPair::from_secret_b64(&cfg.link_secret_key)?
        };

        let link_manager = LinkManager::new(
            &cfg.control_id,
            link_kp,
            true, // is_control = true
            vec![],
            ProbeConfig::default(),
        );

        let client = Arc::new(Self {
            cfg,
            signing_kp,
            link_manager,
            db,
            active_bootstrap_node: Arc::new(RwLock::new(None)),
            pending_replies: Arc::new(DashMap::new()),
            telemetry_cache: Arc::new(RwLock::new(CachedTelemetry::default())),
        });

        client.spawn_incoming_dispatcher();
        Ok(client)
    }

    pub fn control_id(&self) -> &str {
        &self.cfg.control_id
    }

    pub fn signing_public_key_b64(&self) -> String {
        self.signing_kp.public_key_b64()
    }

    pub fn db(&self) -> &Arc<ControlDb> {
        &self.db
    }

    pub async fn cached_telemetry(&self) -> CachedTelemetry {
        self.telemetry_cache.read().await.clone()
    }

    pub async fn active_bootstrap_tag(&self) -> Option<String> {
        self.active_bootstrap_node.read().await.clone()
    }

    pub async fn is_bootstrap_connected(&self) -> bool {
        let Some(tag) = self.active_bootstrap_tag().await else {
            return false;
        };
        self.link_manager.has_connected_peer(&tag).await
    }

    /// Connect to the first reachable bootstrap tunnel-listening Node (supports primary + backups).
    pub async fn connect_bootstrap(&self) -> Result<String> {
        let mut last_err = None;
        for target in &self.cfg.bootstrap_nodes {
            match self.connect_single_bootstrap(target).await {
                Ok(tag) => {
                    *self.active_bootstrap_node.write().await = Some(tag.clone());
                    return Ok(tag);
                }
                Err(e) => {
                    warn!(node = %target.node_tag, addr = %target.address, error = %e, "bootstrap tunnel connect failed, trying next");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err
            .unwrap_or_else(|| ExposureError::Config("no bootstrap_nodes configured".into())))
    }

    pub async fn connect_single_bootstrap(&self, target: &BootstrapNodeTarget) -> Result<String> {
        let proof_pair = if let Some(ref pass) = target.passphrase {
            let mut nonce = vec![0u8; 24];
            rand::thread_rng().fill_bytes(&mut nonce);
            let proof = compute_passphrase_proof(
                pass,
                &self.cfg.control_id,
                &self.link_manager.keypair().public_key_b64(),
                &nonce,
            );
            Some((nonce, proof))
        } else {
            None
        };

        // Check if we already pinned this bootstrap node's pubkey in SQLite
        let expected_pk = if let Some(ref pk) = target.public_key {
            Some(pk.clone())
        } else {
            self.db
                .get_node(&target.node_tag)
                .await?
                .map(|r| r.public_key)
                .filter(|s| !s.is_empty())
        };

        let (session, outcome) = self
            .link_manager
            .dial_endpoint(&target.address, expected_pk.as_deref(), None, proof_pair)
            .await?;

        self.link_manager.register_outbound_session(
            target.address.clone(),
            outcome.remote_node_tag.clone(),
            session,
            outcome.authenticated,
        );

        // Pin bootstrap node's public key in SQLite
        self.db
            .upsert_node(
                &outcome.remote_node_tag,
                &outcome.remote_public_key,
                &NodeRoles::default(),
                true,
            )
            .await?;

        // If we authenticated with passphrase, ensure bootstrap node receives our config-signing public key
        if target.passphrase.is_some() {
            let install = SpecialFrame::new(
                Uuid::new_v4().to_string(),
                vec![self.cfg.control_id.clone(), outcome.remote_node_tag.clone()],
                4,
                SpecialPayload::BootstrapReply {
                    accepted: true,
                    control_public_key: Some(self.signing_kp.public_key_b64()),
                    error: None,
                },
            );
            let _ = self.send_special(install).await;
        }

        info!(
            control = %self.cfg.control_id,
            bootstrap = %outcome.remote_node_tag,
            addr = %target.address,
            "Control connected to bootstrap tunnel node"
        );
        Ok(outcome.remote_node_tag)
    }

    fn spawn_incoming_dispatcher(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let Some(mut rx) = this.link_manager.take_incoming_receiver().await else {
                return;
            };
            while let Some(mut incoming) = rx.recv().await {
                if incoming.kind != StreamKind::Special && incoming.kind != StreamKind::Bootstrap {
                    continue;
                }
                let this2 = Arc::clone(&this);
                tokio::spawn(async move {
                    let frame: SpecialFrame = match read_json_frame(&mut incoming.stream).await {
                        Ok(f) => f,
                        Err(_) => return,
                    };
                    if let Some((_, waiter)) = this2.pending_replies.remove(&frame.id) {
                        let _ = waiter.send(frame);
                        return;
                    }
                    this2.handle_unsolicited_special(frame).await;
                });
            }
        });
    }

    async fn handle_unsolicited_special(&self, frame: SpecialFrame) {
        if let SpecialPayload::BootstrapForward {
            ref node_tag,
            ref public_key,
            ref nonce,
            ref proof,
            ref via_node,
        } = frame.payload
        {
            let res = self
                .verify_and_accept_onboarding(node_tag, public_key, nonce, proof, via_node)
                .await;
            let reply_payload = match res {
                Ok(()) => SpecialPayload::BootstrapReply {
                    accepted: true,
                    control_public_key: Some(self.signing_kp.public_key_b64()),
                    error: None,
                },
                Err(e) => SpecialPayload::BootstrapReply {
                    accepted: false,
                    control_public_key: None,
                    error: Some(e.to_string()),
                },
            };
            let reply = frame.reverse_for_reply(reply_payload);
            let _ = self.send_special(reply).await;
        }
    }

    async fn verify_and_accept_onboarding(
        &self,
        node_tag: &str,
        public_key: &str,
        nonce: &[u8],
        proof: &str,
        via_node: &str,
    ) -> Result<()> {
        let items = self.db.list_passphrases().await?;
        let rec = items
            .into_iter()
            .find(|p| p.node_tag == node_tag)
            .ok_or_else(|| ExposureError::Auth(format!("no passphrase registered for {node_tag}")))?;

        if rec.revoked {
            return Err(ExposureError::Auth("passphrase already revoked".into()));
        }
        if Utc::now().timestamp() > rec.expires_ts {
            return Err(ExposureError::Auth("passphrase expired".into()));
        }
        if !verify_passphrase_proof(&rec.passphrase, node_tag, public_key, nonce, proof) {
            self.db
                .append_audit(
                    "bootstrap",
                    "enroll",
                    node_tag,
                    false,
                    &format!("invalid passphrase proof via {via_node}"),
                )
                .await;
            return Err(ExposureError::Auth("invalid passphrase proof".into()));
        }

        self.db
            .upsert_node(node_tag, public_key, &NodeRoles::default(), true)
            .await?;
        self.db.revoke_passphrase(node_tag).await?;
        self.db
            .append_audit(
                "bootstrap",
                "enroll",
                node_tag,
                true,
                &format!("enrolled via {via_node}, passphrase revoked"),
            )
            .await;
        Ok(())
    }

    pub async fn send_special(&self, mut frame: SpecialFrame) -> Result<()> {
        if frame.current_target() == Some(self.cfg.control_id.as_str()) {
            frame.advance()?;
        }
        let next = frame
            .current_target()
            .ok_or_else(|| ExposureError::Routing("control special frame missing next hop".into()))?
            .to_string();
        let mut stream = self
            .link_manager
            .open_stream_to_node(&next, StreamKind::Special)
            .await?;
        write_json_frame(&mut stream, &frame).await?;
        Ok(())
    }

    pub async fn send_special_rpc(
        &self,
        frame: SpecialFrame,
        timeout: Duration,
    ) -> Result<SpecialFrame> {
        let id = frame.id.clone();
        let (tx, rx) = oneshot::channel();
        self.pending_replies.insert(id.clone(), tx);

        if let Err(e) = self.send_special(frame).await {
            self.pending_replies.remove(&id);
            return Err(e);
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(_)) => Err(ExposureError::Link("control RPC cancelled".into())),
            Err(_) => {
                self.pending_replies.remove(&id);
                Err(ExposureError::Link(format!(
                    "control RPC {id} timed out"
                )))
            }
        }
    }

    /// Sign a compiled `NodeConfig` into a `SignedConfigBundle`.
    pub fn sign_config_bundle(
        &self,
        node_tag: &str,
        sequence: u64,
        config: NodeConfig,
    ) -> Result<SignedConfigBundle> {
        let now = Utc::now().timestamp();
        let mut bundle = SignedConfigBundle {
            node_tag: node_tag.to_string(),
            sequence,
            min_sequence: sequence,
            issued_at: now,
            expires_at: now + 3600,
            config,
            signature: String::new(),
        };
        let bytes = bundle.canonical_bytes()?;
        bundle.signature = self.signing_kp.sign_b64(&bytes);
        Ok(bundle)
    }

    /// Compile current topology (or provided YAML) with stored node & maintainer keys.
    pub async fn compile_yaml(
        &self,
        yaml: &str,
    ) -> Result<(TopologySpec, CompileReport, std::collections::BTreeMap<String, NodeConfig>)> {
        let topo: TopologySpec = serde_yaml::from_str(yaml)
            .map_err(|e| ExposureError::Config(format!("parse topology yaml: {e}")))?;

        let db_nodes = self.db.list_nodes().await?;
        let mut node_pubkeys = HashMap::new();
        for n in &db_nodes {
            if !n.public_key.is_empty() {
                node_pubkeys.insert(n.node_tag.clone(), n.public_key.clone());
            }
        }

        let mut maint_keys = HashMap::new();
        for (tag, spec) in &topo.nodes {
            if spec.roles.maintainer {
                let pair = self.db.get_or_create_maintainer_keypair(tag).await?;
                maint_keys.insert(tag.clone(), pair);
            }
        }

        let (report, compiled) = compile_topology(
            &topo,
            &self.signing_kp.public_key_b64(),
            &node_pubkeys,
            &maint_keys,
        );
        Ok((topo, report, compiled))
    }

    /// Push a signed config bundle to a single target Node along the computed Hop Table.
    /// Send a candidate signed config to a Node for non-mutating preflight connectivity & port checks.
    pub async fn preflight_node_config(
        &self,
        topo: &TopologySpec,
        node_tag: &str,
        cfg: NodeConfig,
    ) -> exposure_core::protocol::PreflightReport {
        use exposure_core::protocol::{PreflightCheckItem, PreflightReport};
        let Some(boot) = self.active_bootstrap_tag().await else {
            return PreflightReport {
                node_tag: node_tag.to_string(),
                ok: false,
                checks: vec![PreflightCheckItem {
                    target: "bootstrap".into(),
                    ok: false,
                    detail: "Control not connected to any bootstrap node".into(),
                }],
            };
        };
        let Some(hops) = compute_control_hops(&self.cfg.control_id, &boot, node_tag, topo) else {
            return PreflightReport {
                node_tag: node_tag.to_string(),
                ok: false,
                checks: vec![PreflightCheckItem {
                    target: "routing".into(),
                    ok: false,
                    detail: format!("no hop path from bootstrap '{boot}' to '{node_tag}'"),
                }],
            };
        };

        let seq = self.db.latest_config_sequence().await.unwrap_or(0) + 1;
        let bundle = match self.sign_config_bundle(node_tag, seq, cfg) {
            Ok(b) => b,
            Err(e) => {
                return PreflightReport {
                    node_tag: node_tag.to_string(),
                    ok: false,
                    checks: vec![PreflightCheckItem {
                        target: "sign".into(),
                        ok: false,
                        detail: e.to_string(),
                    }],
                };
            }
        };

        let frame = SpecialFrame::new(
            Uuid::new_v4().to_string(),
            hops,
            16,
            SpecialPayload::PreflightReq(Box::new(bundle)),
        );

        match self.send_special_rpc(frame, Duration::from_secs(6)).await {
            Ok(SpecialFrame {
                payload: SpecialPayload::PreflightResp(report),
                ..
            }) => report,
            Ok(other) => PreflightReport {
                node_tag: node_tag.to_string(),
                ok: false,
                checks: vec![PreflightCheckItem {
                    target: "rpc".into(),
                    ok: false,
                    detail: format!("unexpected preflight reply: {:?}", other.payload),
                }],
            },
            Err(e) => PreflightReport {
                node_tag: node_tag.to_string(),
                ok: false,
                checks: vec![PreflightCheckItem {
                    target: "rpc".into(),
                    ok: false,
                    detail: e.to_string(),
                }],
            },
        }
    }

    pub async fn push_node_config(
        &self,
        actor: &str,
        topo: &TopologySpec,
        node_tag: &str,
        cfg: NodeConfig,
    ) -> Result<u64> {
        let boot = self
            .active_bootstrap_tag()
            .await
            .ok_or_else(|| ExposureError::Link("Control not connected to any bootstrap node".into()))?;
        let hops = compute_control_hops(&self.cfg.control_id, &boot, node_tag, topo).ok_or_else(
            || {
                ExposureError::Routing(format!(
                    "no hop path from bootstrap '{boot}' to '{node_tag}'"
                ))
            },
        )?;

        let seq = self.db.next_config_sequence().await?;
        let bundle = self.sign_config_bundle(node_tag, seq, cfg.clone())?;
        let cfg_json = serde_json::to_string(&cfg).unwrap_or_default();
        let ver_id = self
            .db
            .record_config_version(seq, node_tag, &cfg_json, "pending")
            .await?;

        let frame = SpecialFrame::new(
            Uuid::new_v4().to_string(),
            hops,
            16,
            SpecialPayload::ConfigPush(Box::new(bundle)),
        );

        match self.send_special_rpc(frame, Duration::from_secs(10)).await {
            Ok(SpecialFrame {
                payload:
                    SpecialPayload::ConfigAck {
                        applied: true, ..
                    },
                ..
            }) => {
                self.db
                    .update_config_version_status(ver_id, "applied")
                    .await?;
                self.db
                    .set_node_reload_result(node_tag, seq, true, None)
                    .await?;
                self.db
                    .append_audit(actor, "config_push", node_tag, true, &format!("seq={seq}"))
                    .await;
                Ok(seq)
            }
            Ok(SpecialFrame {
                payload:
                    SpecialPayload::ConfigAck {
                        applied: false,
                        error,
                        ..
                    },
                ..
            }) => {
                let err_s = error.unwrap_or_else(|| "node rejected config".into());
                self.db
                    .update_config_version_status(ver_id, "failed")
                    .await?;
                self.db
                    .set_node_reload_result(node_tag, seq, false, Some(&err_s))
                    .await?;
                self.db
                    .append_audit(actor, "config_push", node_tag, false, &err_s)
                    .await;
                Err(ExposureError::Config(err_s))
            }
            Err(e) => {
                self.db
                    .update_config_version_status(ver_id, "failed")
                    .await?;
                self.db
                    .append_audit(actor, "config_push", node_tag, false, &e.to_string())
                    .await;
                Err(e)
            }
            _ => Err(ExposureError::Protocol("unexpected reply to ConfigPush".into())),
        }
    }

    /// Run multi-hop BFS Discovery starting from the connected bootstrap tunnel Node (DESIGN.md §9.4).
    pub async fn run_discovery(&self, actor: &str) -> Result<usize> {
        let boot = self
            .active_bootstrap_tag()
            .await
            .ok_or_else(|| ExposureError::Link("no connected bootstrap node".into()))?;

        let mut visited: HashSet<String> = HashSet::new();
        let mut seen_pubkeys: HashMap<String, String> = HashMap::new();
        let mut queue: VecDeque<Vec<String>> = VecDeque::new();
        queue.push_back(vec![self.cfg.control_id.clone(), boot.clone()]);
        visited.insert(boot);

        let mut discovered = 0usize;
        while let Some(hops) = queue.pop_front() {
            let target = hops.last().unwrap().clone();
            let req_id = Uuid::new_v4().to_string();
            let frame = SpecialFrame::new(
                req_id.clone(),
                hops.clone(),
                16,
                SpecialPayload::DiscoveryReq {
                    request_id: req_id.clone(),
                    initiator: self.cfg.control_id.clone(),
                },
            );

            match self.send_special_rpc(frame, Duration::from_secs(6)).await {
                Ok(SpecialFrame {
                    payload:
                        SpecialPayload::DiscoveryResp {
                            request_id,
                            node_tag,
                            roles,
                            public_key,
                            config_sequence,
                            neighbors,
                            signature,
                        },
                    ..
                }) => {
                    let signing = discovery_resp_signing_bytes(
                        &request_id,
                        &node_tag,
                        &public_key,
                        config_sequence,
                        &neighbors,
                    );
                    if let Err(e) = verify_signature_b64(&public_key, &signing, &signature) {
                        warn!(node = %node_tag, error = %e, "discovery signature invalid, ignoring");
                        continue;
                    }
                    // Detect duplicate Node Tag with different public keys
                    if let Some(prev_pk) = seen_pubkeys.get(&node_tag) {
                        if prev_pk != &public_key {
                            warn!(node = %node_tag, "duplicate node_tag detected with conflicting public key");
                            continue;
                        }
                    } else {
                        seen_pubkeys.insert(node_tag.clone(), public_key.clone());
                    }

                    self.db
                        .upsert_node(&node_tag, &public_key, &roles, true)
                        .await?;
                    discovered += 1;

                    for nb in neighbors {
                        if visited.insert(nb.node_tag.clone()) {
                            let mut next_hops = hops.clone();
                            next_hops.push(nb.node_tag);
                            queue.push_back(next_hops);
                        }
                    }
                }
                Err(e) => {
                    warn!(target = %target, error = %e, "discovery RPC failed");
                }
                _ => {}
            }
        }

        self.db
            .append_audit(
                actor,
                "discovery",
                "mesh",
                true,
                &format!("discovered {discovered} nodes"),
            )
            .await;
        Ok(discovered)
    }

    /// Actively pull node status from all Nodes and aggregated stats/certs from all Maintainers.
    pub async fn pull_all_telemetry(&self) -> Result<usize> {
        let Some(boot) = self.active_bootstrap_tag().await else {
            return Ok(0);
        };
        let yaml = self.db.get_topology_yaml().await?;
        let topo: TopologySpec = if yaml.trim().is_empty() {
            TopologySpec::default()
        } else {
            serde_yaml::from_str(&yaml).unwrap_or_default()
        };

        let mut cache = CachedTelemetry::default();
        let mut pulled = 0usize;

        let mut tag_set: HashSet<String> = topo.nodes.keys().cloned().collect();
        tag_set.insert(boot.clone());
        if let Ok(db_nodes) = self.db.list_nodes().await {
            for n in db_nodes {
                tag_set.insert(n.node_tag);
            }
        }
        let node_tags: Vec<String> = tag_set.into_iter().collect();

        for tag in &node_tags {
            let hops = compute_control_hops(&self.cfg.control_id, &boot, tag, &topo)
                .unwrap_or_else(|| vec![self.cfg.control_id.clone(), tag.clone()]);

            // Pull StatusResp
            let status_frame = SpecialFrame::new(
                Uuid::new_v4().to_string(),
                hops.clone(),
                16,
                SpecialPayload::StatusReq,
            );
            if let Ok(SpecialFrame {
                payload: SpecialPayload::StatusResp(NodeStatusSnapshot {
                    node_tag,
                    roles,
                    config_sequence,
                    last_reload_ok,
                    last_reload_error,
                    uptime_secs,
                    links,
                    alerts,
                }),
                ..
            }) = self
                .send_special_rpc(status_frame, Duration::from_secs(5))
                .await
            {
                let _ = self.db.upsert_node(&node_tag, "", &roles, true).await;
                let _ = self
                    .db
                    .set_node_reload_result(
                        &node_tag,
                        config_sequence,
                        last_reload_ok,
                        last_reload_error.as_deref(),
                    )
                    .await;
                cache.node_uptimes.insert(node_tag.clone(), uptime_secs);
                cache.links.extend(links);
                cache.alerts.extend(alerts);
                pulled += 1;

                // If Maintainer, actively pull aggregated summaries & certificate status
                if roles.maintainer {
                    let pull_frame = SpecialFrame::new(
                        Uuid::new_v4().to_string(),
                        hops,
                        16,
                        SpecialPayload::PullTelemetryReq { since_minute: None },
                    );
                    if let Ok(SpecialFrame {
                        payload:
                            SpecialPayload::PullTelemetryResp(MaintainerTelemetrySnapshot {
                                maintainer_tag,
                                summaries,
                                certificates,
                                segment_backlog,
                                merge_latency_ms,
                                alerts: m_alerts,
                            }),
                        ..
                    }) = self
                        .send_special_rpc(pull_frame, Duration::from_secs(6))
                        .await
                    {
                        cache.maintainers.push(MaintainerHealthInfo {
                            maintainer_tag,
                            segment_backlog,
                            merge_latency_ms,
                        });
                        cache.summaries.extend(summaries);
                        cache.certificates.extend(certificates);
                        cache.alerts.extend(m_alerts);
                    }
                }
            }
        }

        cache.last_pulled_at = Some(Utc::now().to_rfc3339());
        *self.telemetry_cache.write().await = cache;
        Ok(pulled)
    }

    /// Trigger enrollment of a listening node via a relay/bootstrap node (Hop Table `DialEnrollReq`).
    pub async fn trigger_listening_enroll(
        &self,
        target_node_tag: &str,
        target_addr: &str,
        passphrase: &str,
        via_hops: &[String],
    ) -> Result<()> {
        let boot = self
            .active_bootstrap_tag()
            .await
            .ok_or_else(|| ExposureError::Link("no connected bootstrap node".into()))?;
        let mut hops = vec![self.cfg.control_id.clone()];
        if via_hops.is_empty() {
            hops.push(boot);
        } else {
            hops.extend(via_hops.iter().cloned());
        }
        let frame = SpecialFrame::new(
            Uuid::new_v4().to_string(),
            hops,
            16,
            SpecialPayload::DialEnrollReq {
                target_node_tag: target_node_tag.to_string(),
                target_addr: target_addr.to_string(),
                passphrase: passphrase.to_string(),
                control_public_key: self.signing_kp.public_key_b64(),
            },
        );
        match self.send_special_rpc(frame, Duration::from_secs(10)).await? {
            SpecialFrame {
                payload:
                    SpecialPayload::DialEnrollResp {
                        success: true,
                        node_public_key: Some(pk),
                        ..
                    },
                ..
            } => {
                self.db
                    .upsert_node(target_node_tag, &pk, &NodeRoles::default(), true)
                    .await?;
                self.db.revoke_passphrase(target_node_tag).await?;
                self.db
                    .append_audit(
                        "admin",
                        "dial_enroll",
                        target_node_tag,
                        true,
                        &format!("enrolled listening node at {target_addr}"),
                    )
                    .await;
                Ok(())
            }
            SpecialFrame {
                payload: SpecialPayload::DialEnrollResp { error, .. },
                ..
            } => Err(ExposureError::Auth(
                error.unwrap_or_else(|| "dial enrollment failed".into()),
            )),
            _ => Err(ExposureError::Protocol("unexpected DialEnroll reply".into())),
        }
    }
}
