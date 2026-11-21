use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use dashmap::DashMap;
use exposure_core::config::{
    BootstrapNodeTarget, ConfigBundlePurpose, ControlConfig, ControlRole, NodeConfig, NodeRoles,
    ProbeConfig, SignedConfigBundle, TopologySpec,
};
use exposure_core::crypto::{
    compute_bootstrap_reply_proof, compute_passphrase_proof, verify_signature_b64, NodeKeyPair,
};
use exposure_core::protocol::{
    dial_enroll_req_signing_bytes, discovery_resp_signing_bytes, dns_sync_req_signing_bytes,
    read_json_frame, write_json_frame, DnsSyncDomainResult, DnsSyncRecordSpec,
    MaintainerTelemetrySnapshot, NodeStatusSnapshot, SpecialFrame, SpecialPayload, StreamKind,
};
use exposure_core::routing::canonical_ip;
use exposure_core::telemetry::{
    AlertRecord, CertStatusInfo, FingerprintObservation, LinkStatusSnapshot, MinuteSummary,
};
use exposure_core::{ExposureError, Result};
use exposure_link::LinkManager;
use futures::stream::{FuturesUnordered, StreamExt};
use rand::RngCore;
use tokio::sync::{oneshot, Mutex, RwLock, Semaphore};
use tracing::{info, warn};
use uuid::Uuid;

use crate::compiler::{compile_topology_full, compute_control_hops, CompileReport};
use crate::db::ControlDb;

const MAX_INCOMING_DISPATCH_TASKS: usize = 128;
const INCOMING_FRAME_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_DISCOVERY_DEPTH: usize = 16;
const MAX_DISCOVERY_NODES: usize = 512;

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
    pub fingerprints: Vec<FingerprintObservation>,
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
    incoming_sem: Arc<Semaphore>,
    /// Per-node push lock serializing concurrent `push_node_config` calls for the same node.
    node_push_locks: Arc<DashMap<String, Arc<Mutex<()>>>>,
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
            incoming_sem: Arc::new(Semaphore::new(MAX_INCOMING_DISPATCH_TASKS)),
            node_push_locks: Arc::new(DashMap::new()),
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

    pub fn link_public_key_b64(&self) -> String {
        self.link_manager.keypair().public_key_b64()
    }

    pub fn db(&self) -> &Arc<ControlDb> {
        &self.db
    }

    /// Return the effective cluster-wide logger IP HMAC key (from topology `global_logger` or persisted SQLite key).
    pub async fn effective_logger_hmac_key(&self) -> Option<String> {
        if let Ok(yaml) = self.db.get_topology_yaml().await {
            if let Ok(topo) = serde_yaml::from_str::<TopologySpec>(&yaml) {
                if let Some(gl) = topo.global_logger {
                    if !gl.hmac_key.trim().is_empty() {
                        return Some(gl.hmac_key);
                    }
                }
            }
        }
        self.db.get_cluster_hmac_key().await.ok().flatten()
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
        // Directly checks authenticated active sessions even though Control's LinkManager `peers` is empty!
        self.link_manager.has_active_session_for_node(&tag)
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
        let mut bootstrap_nonce = Vec::new();
        let proof_pair = if let Some(ref pass) = target.passphrase {
            let mut nonce = vec![0u8; 24];
            rand::thread_rng().fill_bytes(&mut nonce);
            let proof = compute_passphrase_proof(
                pass,
                &self.cfg.control_id,
                &self.link_manager.keypair().public_key_b64(),
                &nonce,
            );
            bootstrap_nonce = nonce.clone();
            Some((nonce, proof))
        } else {
            None
        };

        let expected_pk = if let Some(ref pk) = target.public_key {
            Some(pk.clone())
        } else {
            self.db
                .get_node(&target.node_tag)
                .await?
                .map(|r| r.public_key)
                .filter(|s| !s.is_empty())
        };

        // Enforce expected bootstrap node_tag & authenticated handshake!
        let (session, outcome) = self
            .link_manager
            .dial_endpoint(
                &target.address,
                Some(&target.node_tag),
                expected_pk.as_deref(),
                None,
                proof_pair,
                false,
            )
            .await?;

        if !outcome.authenticated {
            session.close().await;
            return Err(ExposureError::Auth(format!(
                "bootstrap node '{}' did not authenticate Control",
                target.node_tag
            )));
        }

        // Pin bootstrap node's public key WITHOUT overwriting an already-pinned differing key or wiping roles
        if let Err(e) = self
            .db
            .upsert_node_if_unpinned(
                &target.node_tag,
                &outcome.remote_public_key,
                &NodeRoles::default(),
                true,
            )
            .await
        {
            session.close().await;
            return Err(e);
        }

        self.link_manager
            .register_outbound_session(
                target.address.clone(),
                target.node_tag.clone(),
                outcome.remote_public_key.clone(),
                session,
                true,
            )
            .await;

        // If authenticated with passphrase, send mutual-auth BootstrapReply carrying both Control signing & link pubkeys
        if let Some(ref pass) = target.passphrase {
            let sig_pk = self.signing_kp.public_key_b64();
            let link_pk = self.link_public_key_b64();
            let reply_proof = compute_bootstrap_reply_proof(
                pass,
                &sig_pk,
                &link_pk,
                &target.node_tag,
                &bootstrap_nonce,
            );
            let install = SpecialFrame::new(
                Uuid::new_v4().to_string(),
                vec![self.cfg.control_id.clone(), target.node_tag.clone()],
                4,
                SpecialPayload::BootstrapReply {
                    accepted: true,
                    control_public_key: Some(sig_pk),
                    control_link_public_key: Some(link_pk),
                    reply_proof: Some(reply_proof),
                    nonce: bootstrap_nonce,
                    error: None,
                },
            );
            if let Err(e) = self.send_special(install).await {
                warn!(node = %target.node_tag, error = %e, "failed to send BootstrapReply to bootstrap node");
            }
        }

        info!(
            control = %self.cfg.control_id,
            bootstrap = %target.node_tag,
            addr = %target.address,
            "Control connected to bootstrap tunnel node"
        );
        Ok(target.node_tag.clone())
    }

    fn spawn_incoming_dispatcher(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let Some(mut rx) = this.link_manager.take_incoming_receiver().await else {
                return;
            };
            while let Some(mut incoming) = rx.recv().await {
                if !incoming.authenticated {
                    continue;
                }
                if incoming.kind != StreamKind::Special && incoming.kind != StreamKind::Bootstrap {
                    continue;
                }
                let permit = match Arc::clone(&this.incoming_sem).try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!("control incoming stream handler limit reached; dropping stream");
                        continue;
                    }
                };
                let this2 = Arc::clone(&this);
                tokio::spawn(async move {
                    let _permit = permit;
                    let frame: SpecialFrame = match tokio::time::timeout(
                        INCOMING_FRAME_TIMEOUT,
                        read_json_frame(&mut incoming.stream),
                    )
                    .await
                    {
                        Ok(Ok(f)) => f,
                        _ => return,
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
            if self.cfg.role != ControlRole::Active {
                let reply = frame.reverse_for_reply(SpecialPayload::BootstrapReply {
                    accepted: false,
                    control_public_key: None,
                    control_link_public_key: None,
                    reply_proof: None,
                    nonce: vec![],
                    error: Some("control instance is in standby mode".into()),
                });
                let _ = self.send_special(reply).await;
                return;
            }

            let res = self
                .verify_and_accept_onboarding(node_tag, public_key, nonce, proof, via_node)
                .await;
            let reply_payload = match res {
                Ok(passphrase) => {
                    let sig_pk = self.signing_kp.public_key_b64();
                    let link_pk = self.link_public_key_b64();
                    let reply_proof = compute_bootstrap_reply_proof(
                        &passphrase,
                        &sig_pk,
                        &link_pk,
                        node_tag,
                        nonce,
                    );
                    SpecialPayload::BootstrapReply {
                        accepted: true,
                        control_public_key: Some(sig_pk),
                        control_link_public_key: Some(link_pk),
                        reply_proof: Some(reply_proof),
                        nonce: nonce.clone(),
                        error: None,
                    }
                }
                Err(e) => SpecialPayload::BootstrapReply {
                    accepted: false,
                    control_public_key: None,
                    control_link_public_key: None,
                    reply_proof: None,
                    nonce: vec![],
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
    ) -> Result<String> {
        match self
            .db
            .consume_passphrase_and_enroll(node_tag, public_key, nonce, proof)
            .await
        {
            Ok(passphrase) => {
                self.db
                    .append_audit(
                        "bootstrap",
                        "enroll",
                        node_tag,
                        true,
                        &format!("enrolled via {via_node}, passphrase revoked"),
                    )
                    .await;
                Ok(passphrase)
            }
            Err(e) => {
                self.db
                    .append_audit(
                        "bootstrap",
                        "enroll",
                        node_tag,
                        false,
                        &format!("onboarding failed via {via_node}: {e}"),
                    )
                    .await;
                Err(e)
            }
        }
    }

    pub async fn send_special(&self, mut frame: SpecialFrame) -> Result<()> {
        frame.validate_hops()?;
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

    /// Sign a compiled `NodeConfig` into a `SignedConfigBundle` for `Apply`.
    pub fn sign_config_bundle(
        &self,
        node_tag: &str,
        sequence: u64,
        config: NodeConfig,
    ) -> Result<SignedConfigBundle> {
        self.sign_config_bundle_with_purpose(
            node_tag,
            sequence,
            config,
            ConfigBundlePurpose::Apply,
            3600,
        )
    }

    /// Sign a `NodeConfig` with explicit domain-separated `ConfigBundlePurpose` (`Apply` vs `Preflight`).
    pub fn sign_config_bundle_with_purpose(
        &self,
        node_tag: &str,
        sequence: u64,
        config: NodeConfig,
        purpose: ConfigBundlePurpose,
        ttl_secs: i64,
    ) -> Result<SignedConfigBundle> {
        let now = Utc::now().timestamp();
        let mut bundle = SignedConfigBundle {
            purpose,
            node_tag: node_tag.to_string(),
            sequence,
            min_sequence: sequence,
            issued_at: now,
            expires_at: now + ttl_secs,
            config,
            signature: String::new(),
        };
        let bytes = bundle.canonical_bytes()?;
        bundle.signature = self.signing_kp.sign_b64(&bytes);
        Ok(bundle)
    }

    /// Read-only compilation for `GET /api/topology`, `POST /api/topology/validate`, and `preflight`:
    /// NEVER mutates SQLite (uses existing maintainer keys or ephemeral preview keys).
    pub async fn compile_yaml_readonly(
        &self,
        yaml: &str,
    ) -> Result<(TopologySpec, CompileReport, BTreeMap<String, NodeConfig>)> {
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
                if let Some(pair) = self.db.get_maintainer_keypair(tag).await? {
                    maint_keys.insert(tag.clone(), pair);
                }
            }
        }

        let cluster_hmac = self.db.get_cluster_hmac_key().await.ok().flatten();
        let (report, compiled) = compile_topology_full(
            &topo,
            &self.signing_kp.public_key_b64(),
            &self.link_public_key_b64(),
            &node_pubkeys,
            &maint_keys,
            true,
            cluster_hmac.as_deref(),
        );
        Ok((topo, report, compiled))
    }

    /// Compile topology AND provision persistent maintainer keypairs & cluster logger HMAC key (Active role ONLY).
    pub async fn compile_yaml_and_provision(
        &self,
        yaml: &str,
    ) -> Result<(TopologySpec, CompileReport, BTreeMap<String, NodeConfig>)> {
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

        let cluster_hmac = self.db.get_or_create_cluster_hmac_key().await?;
        let (report, compiled) = compile_topology_full(
            &topo,
            &self.signing_kp.public_key_b64(),
            &self.link_public_key_b64(),
            &node_pubkeys,
            &maint_keys,
            true,
            Some(&cluster_hmac),
        );
        Ok((topo, report, compiled))
    }

    /// Send a candidate Preflight-domain-separated signed config to a Node for non-mutating checks.
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
        // Domain-separated Preflight bundle (30s TTL) CANNOT be replayed as ConfigPush!
        let bundle = match self.sign_config_bundle_with_purpose(
            node_tag,
            seq,
            cfg,
            ConfigBundlePurpose::Preflight,
            30,
        ) {
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
        let push_lock = self
            .node_push_locks
            .entry(node_tag.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _guard = push_lock.lock().await;

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

        let cfg_json = serde_json::to_string(&cfg)
            .map_err(|e| ExposureError::Config(format!("serialize node config: {e}")))?;
        let (seq, ver_id) = self
            .db
            .allocate_and_record_config_version(node_tag, &cfg_json)
            .await?;
        let bundle = self.sign_config_bundle(node_tag, seq, cfg)?;

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
            _ => {
                let err_s = "unexpected reply to ConfigPush";
                self.db
                    .update_config_version_status(ver_id, "failed")
                    .await?;
                self.db
                    .append_audit(actor, "config_push", node_tag, false, err_s)
                    .await;
                Err(ExposureError::Protocol(err_s.into()))
            }
        }
    }

    /// Run bounded multi-hop BFS Discovery starting from the connected bootstrap tunnel Node (DESIGN.md §9.4).
    /// NEVER overwrites an already-pinned public key in SQLite!
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
            if discovered >= MAX_DISCOVERY_NODES || hops.len() > MAX_DISCOVERY_DEPTH {
                continue;
            }
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
                    if request_id != req_id {
                        warn!(expected = %req_id, got = %request_id, "discovery response request_id mismatch");
                        continue;
                    }
                    if node_tag != target {
                        warn!(expected = %target, got = %node_tag, "discovery response node_tag mismatch");
                        continue;
                    }
                    let signing = discovery_resp_signing_bytes(
                        &request_id,
                        &node_tag,
                        &roles,
                        &public_key,
                        config_sequence,
                        &neighbors,
                    );
                    if let Err(e) = verify_signature_b64(&public_key, &signing, &signature) {
                        warn!(node = %node_tag, error = %e, "discovery signature invalid, ignoring");
                        continue;
                    }
                    if let Some(prev_pk) = seen_pubkeys.get(&node_tag) {
                        if prev_pk != &public_key {
                            warn!(node = %node_tag, "duplicate node_tag detected with conflicting public key");
                            continue;
                        }
                    } else {
                        seen_pubkeys.insert(node_tag.clone(), public_key.clone());
                    }

                    if let Err(e) = self
                        .db
                        .upsert_node_if_unpinned(&node_tag, &public_key, &roles, true)
                        .await
                    {
                        warn!(node = %node_tag, error = %e, "discovery rejected conflicting public key against pinned DB");
                        self.db
                            .append_audit(actor, "discovery_conflict", &node_tag, false, &e.to_string())
                            .await;
                        continue;
                    }
                    discovered += 1;

                    if hops.len() < MAX_DISCOVERY_DEPTH {
                        for nb in neighbors {
                            if visited.len() < MAX_DISCOVERY_NODES
                                && visited.insert(nb.node_tag.clone())
                            {
                                let mut next_hops = hops.clone();
                                next_hops.push(nb.node_tag);
                                queue.push_back(next_hops);
                            }
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

    /// Concurrently pull node status from all Nodes and aggregated stats/certs from all Maintainers.
    pub async fn pull_all_telemetry(self: &Arc<Self>) -> Result<usize> {
        let Some(boot) = self.active_bootstrap_tag().await else {
            return Ok(0);
        };
        let yaml = self.db.get_topology_yaml().await?;
        let topo: TopologySpec = if yaml.trim().is_empty() {
            TopologySpec::default()
        } else {
            serde_yaml::from_str(&yaml).unwrap_or_default()
        };

        let mut tag_set: HashSet<String> = topo.nodes.keys().cloned().collect();
        tag_set.insert(boot.clone());
        if let Ok(db_nodes) = self.db.list_nodes().await {
            for n in db_nodes {
                tag_set.insert(n.node_tag);
            }
        }

        let mut futs = FuturesUnordered::new();
        for tag in tag_set {
            let Some(hops) = compute_control_hops(&self.cfg.control_id, &boot, &tag, &topo)
                .or_else(|| {
                    if tag == boot {
                        Some(vec![self.cfg.control_id.clone(), boot.clone()])
                    } else {
                        None
                    }
                })
            else {
                let _ = self.db.set_node_online(&tag, false).await;
                continue;
            };
            let this = Arc::clone(self);
            futs.push(tokio::spawn(async move {
                let status_frame = SpecialFrame::new(
                    Uuid::new_v4().to_string(),
                    hops.clone(),
                    16,
                    SpecialPayload::StatusReq,
                );
                match this
                    .send_special_rpc(status_frame, Duration::from_secs(5))
                    .await
                {
                    Ok(SpecialFrame {
                        payload: SpecialPayload::StatusResp(snap),
                        ..
                    }) => {
                        if snap.node_tag != tag {
                            warn!(expected = %tag, got = %snap.node_tag, "spoofed StatusResp node_tag rejected");
                            return None;
                        }
                        let _ = this
                            .db
                            .upsert_node_if_unpinned(&tag, "", &snap.roles, true)
                            .await;
                        let _ = this
                            .db
                            .set_node_reload_result(
                                &tag,
                                snap.config_sequence,
                                snap.last_reload_ok,
                                snap.last_reload_error.as_deref(),
                            )
                            .await;

                        let maint_snap = if snap.roles.maintainer {
                            let pull_frame = SpecialFrame::new(
                                Uuid::new_v4().to_string(),
                                hops,
                                16,
                                SpecialPayload::PullTelemetryReq { since_minute: None },
                            );
                            match this
                                .send_special_rpc(pull_frame, Duration::from_secs(6))
                                .await
                            {
                                Ok(SpecialFrame {
                                    payload: SpecialPayload::PullTelemetryResp(ms),
                                    ..
                                }) if ms.maintainer_tag == tag => Some(ms),
                                _ => None,
                            }
                        } else {
                            None
                        };
                        Some((snap, maint_snap))
                    }
                    _ => {
                        let _ = this.db.set_node_online(&tag, false).await;
                        None
                    }
                }
            }));
        }

        let mut cache = CachedTelemetry::default();
        let mut pulled = 0usize;
        let mut dedup_summaries: HashMap<(i64, String, String, String), MinuteSummary> =
            HashMap::new();
        let mut dedup_fingerprints: HashMap<String, FingerprintObservation> = HashMap::new();
        let mut dedup_certs: HashMap<String, CertStatusInfo> = HashMap::new();

        while let Some(res) = futs.next().await {
            if let Ok(Some((snap, maint_opt))) = res {
                let NodeStatusSnapshot {
                    node_tag,
                    uptime_secs,
                    links,
                    alerts,
                    ..
                } = snap;
                cache.node_uptimes.insert(node_tag, uptime_secs);
                cache.links.extend(links);
                cache.alerts.extend(alerts);
                pulled += 1;

                if let Some(MaintainerTelemetrySnapshot {
                    maintainer_tag,
                    summaries,
                    fingerprints,
                    certificates,
                    segment_backlog,
                    merge_latency_ms,
                    alerts: m_alerts,
                }) = maint_opt
                {
                    cache.maintainers.push(MaintainerHealthInfo {
                        maintainer_tag,
                        segment_backlog,
                        merge_latency_ms,
                    });
                    for s in summaries {
                        // Deduplicate summaries reported by multiple maintainers by keeping the highest-count entry
                        let key = (
                            s.minute_epoch,
                            s.node_tag.clone(),
                            s.role.clone(),
                            s.service_tag.clone(),
                        );
                        dedup_summaries
                            .entry(key)
                            .and_modify(|existing| {
                                if s.requests > existing.requests {
                                    *existing = s.clone();
                                }
                            })
                            .or_insert(s);
                    }
                    for fp in fingerprints {
                        dedup_fingerprints
                            .entry(fp.id.clone())
                            .and_modify(|existing| {
                                if fp.request_count > existing.request_count
                                    || (fp.js_verified && !existing.js_verified)
                                    || fp.last_seen_ts > existing.last_seen_ts
                                {
                                    existing.merge_from(&fp);
                                }
                            })
                            .or_insert(fp);
                    }
                    for c in certificates {
                        dedup_certs.insert(c.domain.clone(), c);
                    }
                    cache.alerts.extend(m_alerts);
                }
            }
        }

        cache.summaries = dedup_summaries.into_values().collect();
        let mut fps: Vec<FingerprintObservation> = dedup_fingerprints.into_values().collect();
        fps.sort_by(|a, b| b.last_seen_ts.cmp(&a.last_seen_ts));
        fps.truncate(10_000);
        cache.fingerprints = fps;
        cache.certificates = dedup_certs.into_values().collect();
        cache.last_pulled_at = Some(Utc::now().to_rfc3339());
        *self.telemetry_cache.write().await = cache;
        Ok(pulled)
    }

    /// Trigger enrollment of a listening node via a relay/bootstrap node using Control-signed `DialEnrollReq`.
    pub async fn trigger_listening_enroll(
        &self,
        actor: &str,
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
            if via_hops.first().map(|s| s.as_str()) != Some(boot.as_str()) {
                hops.push(boot);
            }
            hops.extend(via_hops.iter().cloned());
        }
        let relay_node_tag = hops
            .last()
            .cloned()
            .ok_or_else(|| ExposureError::Routing("missing relay hop for DialEnrollReq".into()))?;

        let request_id = Uuid::new_v4().to_string();
        let now = Utc::now().timestamp();
        let expires_at = now + 60;
        let sig_pk = self.signing_kp.public_key_b64();
        let link_pk = self.link_public_key_b64();
        let signing = dial_enroll_req_signing_bytes(
            &request_id,
            now,
            expires_at,
            &relay_node_tag,
            target_node_tag,
            target_addr,
            passphrase,
            &sig_pk,
            &link_pk,
        );
        let control_signature = self.signing_kp.sign_b64(&signing);

        let frame = SpecialFrame::new(
            Uuid::new_v4().to_string(),
            hops,
            16,
            SpecialPayload::DialEnrollReq {
                request_id,
                issued_at: now,
                expires_at,
                target_node_tag: target_node_tag.to_string(),
                target_addr: target_addr.to_string(),
                passphrase: passphrase.to_string(),
                control_public_key: sig_pk,
                control_link_public_key: link_pk,
                control_signature,
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
                    .upsert_node_if_unpinned(target_node_tag, &pk, &NodeRoles::default(), true)
                    .await?;
                self.db.revoke_passphrase(target_node_tag).await?;
                self.db
                    .append_audit(
                        actor,
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
            } => {
                let _ = self.db.revoke_passphrase(target_node_tag).await;
                Err(ExposureError::Auth(
                    error.unwrap_or_else(|| "dial enrollment failed".into()),
                ))
            }
            _ => {
                let _ = self.db.revoke_passphrase(target_node_tag).await;
                Err(ExposureError::Protocol("unexpected DialEnroll reply".into()))
            }
        }
    }

    /// Issue a Control-signed `DnsSyncReq` command to a Maintainer node to declaratively sync
    /// A/AAAA records for configured `domains` using target nodes' `external_ips`.
    pub async fn sync_dns(
        &self,
        actor: &str,
        filter_domains: Option<Vec<String>>,
        maintainer_tag: Option<String>,
    ) -> Result<(String, Vec<DnsSyncDomainResult>)> {
        let yaml = self.db.get_topology_yaml().await?;
        if yaml.trim().is_empty() {
            return Err(ExposureError::Config("no topology saved in Control".into()));
        }
        let topo: TopologySpec = serde_yaml::from_str(&yaml)
            .map_err(|e| ExposureError::Config(format!("parse topology yaml: {e}")))?;

        let target_maint = if let Some(ref mt) = maintainer_tag {
            let trimmed = mt.trim();
            let spec = topo.nodes.get(trimmed).ok_or_else(|| {
                ExposureError::Config(format!("maintainer '{trimmed}' not found in topology"))
            })?;
            if !spec.roles.maintainer {
                return Err(ExposureError::Config(format!(
                    "node '{trimmed}' does not have maintainer role"
                )));
            }
            trimmed.to_string()
        } else {
            let primary = topo
                .nodes
                .iter()
                .find(|(_, spec)| {
                    spec.roles.maintainer
                        && spec
                            .maintainer_template
                            .as_deref()
                            .and_then(|t| topo.maintainer_templates.get(t))
                            .map(|mc| mc.is_primary_cert_manager)
                            .unwrap_or(false)
                })
                .map(|(tag, _)| tag.clone());
            primary
                .or_else(|| {
                    topo.nodes
                        .iter()
                        .find(|(_, spec)| spec.roles.maintainer)
                        .map(|(tag, _)| tag.clone())
                })
                .ok_or_else(|| {
                    ExposureError::Config("no maintainer node found in topology".into())
                })?
        };

        let filter_set: Option<HashSet<String>> = filter_domains.map(|list| {
            list.into_iter()
                .map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        });

        let mut records = Vec::new();
        for (dom, binding) in &topo.domains {
            let dom_norm = dom.trim().trim_end_matches('.').to_ascii_lowercase();
            let explicitly_requested = filter_set
                .as_ref()
                .map(|s| s.contains(&dom_norm))
                .unwrap_or(false);
            if filter_set.is_some() && !explicitly_requested {
                continue;
            }
            if binding.target_nodes.is_empty() {
                if explicitly_requested {
                    return Err(ExposureError::Config(format!(
                        "domain '{dom}' has no target_nodes configured for DNS sync"
                    )));
                }
                continue;
            }

            let mut v4 = BTreeSet::new();
            let mut v6 = BTreeSet::new();
            for node_tag in &binding.target_nodes {
                let node_spec = topo.nodes.get(node_tag).ok_or_else(|| {
                    ExposureError::Config(format!(
                        "domain '{dom}' references unknown target node '{node_tag}'"
                    ))
                })?;
                for raw_ip in &node_spec.external_ips {
                    let ip: IpAddr = raw_ip.trim().parse().map_err(|_| {
                        ExposureError::Config(format!(
                            "node '{node_tag}' has invalid external_ip '{raw_ip}'"
                        ))
                    })?;
                    match canonical_ip(ip) {
                        IpAddr::V4(addr) => {
                            v4.insert(addr.to_string());
                        }
                        IpAddr::V6(addr) => {
                            v6.insert(addr.to_string());
                        }
                    }
                }
            }

            if v4.is_empty() && v6.is_empty() {
                return Err(ExposureError::Config(format!(
                    "domain '{dom}' target_nodes ({}) have no external_ips configured",
                    binding.target_nodes.join(", ")
                )));
            }

            records.push(DnsSyncRecordSpec {
                domain: dom.clone(),
                ipv4s: v4.into_iter().collect(),
                ipv6s: v6.into_iter().collect(),
                provider: Some(binding.provider.clone()),
                zone_id: binding.zone_id.clone(),
                root_domain: binding.root_domain.clone(),
                ttl: Some(binding.ttl),
                proxied: Some(binding.proxied),
            });
        }

        if records.is_empty() {
            return Err(ExposureError::Config(
                "no domains with target_nodes configured for DNS sync".into(),
            ));
        }

        let boot = self
            .active_bootstrap_tag()
            .await
            .ok_or_else(|| ExposureError::Link("Control not connected to any bootstrap node".into()))?;
        let hops = compute_control_hops(&self.cfg.control_id, &boot, &target_maint, &topo)
            .ok_or_else(|| {
                ExposureError::Routing(format!(
                    "no hop path from bootstrap '{boot}' to maintainer '{target_maint}'"
                ))
            })?;

        let now = Utc::now().timestamp();
        let expires_at = now + 60;
        let request_id = Uuid::new_v4().to_string();
        let signing = dns_sync_req_signing_bytes(
            &request_id,
            now,
            expires_at,
            &target_maint,
            &records,
        );
        let control_signature = self.signing_kp.sign_b64(&signing);

        let frame = SpecialFrame::new(
            Uuid::new_v4().to_string(),
            hops,
            16,
            SpecialPayload::DnsSyncReq {
                request_id: request_id.clone(),
                issued_at: now,
                expires_at,
                maintainer_tag: target_maint.clone(),
                records,
                control_signature,
            },
        );

        match self.send_special_rpc(frame, Duration::from_secs(30)).await? {
            SpecialFrame {
                payload:
                    SpecialPayload::DnsSyncResp {
                        request_id: resp_id,
                        ok,
                        results,
                        error,
                        ..
                    },
                ..
            } => {
                if resp_id != request_id {
                    return Err(ExposureError::Protocol(
                        "DnsSyncResp request_id mismatch".into(),
                    ));
                }
                let detail = if ok {
                    format!("synced {} domain(s)", results.len())
                } else {
                    error
                        .clone()
                        .unwrap_or_else(|| "one or more domains failed DNS sync".into())
                };
                self.db
                    .append_audit(actor, "dns_sync", &target_maint, ok, &detail)
                    .await;
                if !ok && results.is_empty() {
                    return Err(ExposureError::Protocol(detail));
                }
                Ok((target_maint, results))
            }
            SpecialFrame {
                payload: SpecialPayload::ErrorReply { message },
                ..
            } => {
                self.db
                    .append_audit(actor, "dns_sync", &target_maint, false, &message)
                    .await;
                Err(ExposureError::Protocol(message))
            }
            _ => Err(ExposureError::Protocol("unexpected DnsSync reply".into())),
        }
    }
}
