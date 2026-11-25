use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use dashmap::DashMap;
use exposure_core::config::{
    BootstrapNodeTarget, ConfigBundlePurpose, ControlConfig, ControlRole, DomainLineRecordType,
    NodeConfig, NodeRoles, ProbeConfig, SignedConfigBundle, TopologySpec,
};
use exposure_core::crypto::{
    compute_bootstrap_reply_proof, compute_passphrase_proof, verify_signature_b64, NodeKeyPair,
};
use exposure_core::protocol::{
    dial_enroll_req_signing_bytes, discovery_resp_signing_bytes, dns_manage_req_signing_bytes,
    dns_sync_req_signing_bytes, geoip_sync_req_signing_bytes, pull_telemetry_req_signing_bytes,
    query_maintainer_req_signing_bytes, read_json_frame, unban_req_signing_bytes, write_json_frame,
    DnsLineSyncEntry, DnsManageOp, DnsProviderCapabilities, DnsRemoteRecord, DnsSupportLine,
    DnsSyncDomainResult, DnsSyncRecordSpec, MaintainerQuery, MaintainerTelemetrySnapshot,
    NodeStatusSnapshot, SpecialFrame, SpecialPayload, StreamKind,
};
use exposure_core::routing::canonical_ip;
use exposure_core::telemetry::{
    AlertRecord, CertStatusInfo, EvilpotNodeReport, FingerprintObservation, GeoIpStatusSnapshot,
    LinkStatusSnapshot, LogProtectionStats, MaintainerStorageStats, MinuteSummary, SessionSummary,
};
use exposure_core::{ExposureError, Result};
use exposure_link::LinkManager;
use futures::stream::{FuturesUnordered, StreamExt};
use rand::RngCore;
use tokio::sync::{oneshot, Mutex, RwLock, Semaphore};
use tracing::{info, warn};
use uuid::Uuid;

use crate::compiler::{compile_topology_full, compute_control_hops, inject_crs_rules, CompileReport};
use crate::db::ControlDb;
use exposure_core::crs::{builtin_crs_snapshot, merge_crs_snapshots, CrsRulesetSnapshot};

const KV_TELEMETRY_CACHE: &str = "telemetry_cache_json";
pub const KV_CRS_RULESET: &str = "crs_ruleset_json";
const MAX_PERSISTED_SUMMARIES: usize = 10_000;
const MAX_PERSISTED_FINGERPRINTS: usize = 5_000;
const MAX_PERSISTED_LOGS: usize = 2_000;
const MAX_PERSISTED_ALERTS: usize = 500;

const MAX_INCOMING_DISPATCH_TASKS: usize = 128;
const INCOMING_FRAME_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_DISCOVERY_DEPTH: usize = 16;
const MAX_DISCOVERY_NODES: usize = 512;

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct MaintainerHealthInfo {
    #[serde(default)]
    pub maintainer_tag: String,
    #[serde(default)]
    pub segment_backlog: usize,
    #[serde(default)]
    pub merge_latency_ms: f64,
    #[serde(default)]
    pub storage_stats: Option<MaintainerStorageStats>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeployReleaseResult {
    pub release_seq: u64,
    pub revision: String,
    pub revision_full: String,
    pub parent_revision: Option<String>,
    pub results: Vec<serde_json::Value>,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct CachedTelemetry {
    #[serde(default)]
    pub links: Vec<LinkStatusSnapshot>,
    #[serde(default)]
    pub summaries: Vec<MinuteSummary>,
    #[serde(default)]
    pub fingerprints: Vec<FingerprintObservation>,
    #[serde(default)]
    pub recent_logs: Vec<SessionSummary>,
    #[serde(default)]
    pub certificates: Vec<CertStatusInfo>,
    #[serde(default)]
    pub alerts: Vec<AlertRecord>,
    #[serde(default)]
    pub maintainers: Vec<MaintainerHealthInfo>,
    #[serde(default)]
    pub node_uptimes: HashMap<String, u64>,
    #[serde(default)]
    pub log_stats: HashMap<String, LogProtectionStats>,
    #[serde(default)]
    pub evilpot_reports: Vec<EvilpotNodeReport>,
    #[serde(default)]
    pub geoip_status: HashMap<String, GeoIpStatusSnapshot>,
    #[serde(default)]
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
    telemetry_cache: Arc<RwLock<Arc<CachedTelemetry>>>,
    cached_topology: Arc<RwLock<Option<(String, Arc<TopologySpec>)>>>,
    cached_crs: Arc<RwLock<Option<Arc<CrsRulesetSnapshot>>>>,
    pull_telemetry_lock: Arc<Mutex<()>>,
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
            telemetry_cache: Arc::new(RwLock::new(Arc::new(CachedTelemetry::default()))),
            cached_topology: Arc::new(RwLock::new(None)),
            cached_crs: Arc::new(RwLock::new(None)),
            pull_telemetry_lock: Arc::new(Mutex::new(())),
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

    /// Return parsed `TopologySpec` using string-equality cached YAML to avoid repeated deep parses.
    async fn cached_topology_spec(&self) -> Result<Arc<TopologySpec>> {
        let yaml = self.db.get_topology_yaml().await?;
        if let Some((ref cached_yaml, ref spec)) = *self.cached_topology.read().await {
            if cached_yaml == &yaml {
                return Ok(Arc::clone(spec));
            }
        }
        let spec: TopologySpec = if yaml.trim().is_empty() {
            TopologySpec::default()
        } else {
            serde_yaml::from_str(&yaml)
                .map_err(|e| ExposureError::Config(format!("parse topology yaml: {e}")))?
        };
        let arc_spec = Arc::new(spec);
        *self.cached_topology.write().await = Some((yaml, Arc::clone(&arc_spec)));
        Ok(arc_spec)
    }

    /// Return the effective cluster-wide logger IP HMAC key (from topology `global_logger` or persisted SQLite key).
    pub async fn effective_logger_hmac_key(&self) -> Option<String> {
        if let Ok(topo) = self.cached_topology_spec().await {
            if let Some(ref gl) = topo.global_logger {
                if !gl.hmac_key.trim().is_empty() {
                    return Some(gl.hmac_key.clone());
                }
            }
        }
        self.db.get_cluster_hmac_key().await.ok().flatten()
    }

    pub async fn cached_telemetry(&self) -> Arc<CachedTelemetry> {
        Arc::clone(&*self.telemetry_cache.read().await)
    }

    /// Restore previously persisted telemetry cache from SQLite on Control startup so dashboards
    /// and analytics retain historical data across restarts even before the next mesh pull.
    pub async fn restore_telemetry_cache(&self) {
        match self.db.get_kv_json::<CachedTelemetry>(KV_TELEMETRY_CACHE).await {
            Ok(Some(saved)) => {
                info!(
                    summaries = saved.summaries.len(),
                    fingerprints = saved.fingerprints.len(),
                    last_pulled_at = ?saved.last_pulled_at,
                    "restored persisted telemetry cache from SQLite"
                );
                *self.telemetry_cache.write().await = Arc::new(saved);
            }
            Ok(None) => {}
            Err(e) => {
                warn!(error = %e, "failed to restore persisted telemetry cache from SQLite");
            }
        }
    }

    /// Return the active OWASP CRS ruleset snapshot (cached in RAM; synced from GitHub merged with the built-in
    /// baseline). The built-in rules are always unioned in so a partial/limited upstream sync can
    /// never silently remove SQLi/XSS/RCE detection coverage.
    pub async fn active_crs_snapshot(&self) -> Arc<CrsRulesetSnapshot> {
        if let Some(ref cached) = *self.cached_crs.read().await {
            return Arc::clone(cached);
        }
        let snap = match self.db.get_kv_json::<CrsRulesetSnapshot>(KV_CRS_RULESET).await {
            Ok(Some(snap)) if !snap.rules.is_empty() => {
                merge_crs_snapshots(snap, builtin_crs_snapshot())
            }
            _ => builtin_crs_snapshot(),
        };
        let arc_snap = Arc::new(snap);
        *self.cached_crs.write().await = Some(Arc::clone(&arc_snap));
        arc_snap
    }

    /// Sync the latest OWASP Core Rule Set from `coreruleset.org` / GitHub and persist to SQLite.
    pub async fn sync_owasp_crs(&self, actor: &str) -> Result<CrsRulesetSnapshot> {
        let raw = crate::crs_sync::sync_owasp_crs_from_github().await?;
        let snap = merge_crs_snapshots(raw, builtin_crs_snapshot());
        self.db.set_kv_json(KV_CRS_RULESET, &snap).await?;
        *self.cached_crs.write().await = Some(Arc::new(snap.clone()));
        self.db
            .append_audit(
                actor,
                "crs_sync",
                "waf",
                true,
                &format!(
                    "synced OWASP CRS {} ({} rules active, {} PCRE-only skipped)",
                    snap.version,
                    snap.rules.len(),
                    snap.skipped_pcre
                ),
            )
            .await;
        Ok(snap)
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

        // Remove the pending waiter even if this future is cancelled/dropped, preventing an
        // unbounded leak of `pending_replies` entries on request cancellation.
        struct PendingGuard {
            map: Arc<DashMap<String, oneshot::Sender<SpecialFrame>>>,
            id: String,
        }
        impl Drop for PendingGuard {
            fn drop(&mut self) {
                self.map.remove(&self.id);
            }
        }
        let _pending_guard = PendingGuard {
            map: Arc::clone(&self.pending_replies),
            id: id.clone(),
        };

        if let Err(e) = self.send_special(frame).await {
            return Err(e);
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(_)) => Err(ExposureError::Link("control RPC cancelled".into())),
            Err(_) => Err(ExposureError::Link(format!(
                "control RPC {id} timed out"
            ))),
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
        let rev = config.config_revision.clone();
        self.sign_config_bundle_with_revision(node_tag, sequence, &rev, config, purpose, ttl_secs)
    }

    /// Sign a `NodeConfig` with an explicit Git-style cluster `config_revision`.
    pub fn sign_config_bundle_with_revision(
        &self,
        node_tag: &str,
        sequence: u64,
        config_revision: &str,
        mut config: NodeConfig,
        purpose: ConfigBundlePurpose,
        ttl_secs: i64,
    ) -> Result<SignedConfigBundle> {
        config.config_revision = config_revision.to_string();
        let now = Utc::now().timestamp();
        let mut bundle = SignedConfigBundle {
            purpose,
            node_tag: node_tag.to_string(),
            sequence,
            config_revision: config_revision.to_string(),
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
        let crs = self.active_crs_snapshot().await;
        let (report, mut compiled) = compile_topology_full(
            &topo,
            &self.signing_kp.public_key_b64(),
            &self.link_public_key_b64(),
            &node_pubkeys,
            &maint_keys,
            true,
            cluster_hmac.as_deref(),
        );
        inject_crs_rules(&mut compiled, &crs.rules);
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
        let crs = self.active_crs_snapshot().await;
        let (report, mut compiled) = compile_topology_full(
            &topo,
            &self.signing_kp.public_key_b64(),
            &self.link_public_key_b64(),
            &node_pubkeys,
            &maint_keys,
            true,
            Some(&cluster_hmac),
        );
        inject_crs_rules(&mut compiled, &crs.rules);
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
            }) => {
                if report.node_tag != node_tag {
                    PreflightReport {
                        node_tag: node_tag.to_string(),
                        ok: false,
                        checks: vec![PreflightCheckItem {
                            target: "rpc".into(),
                            ok: false,
                            detail: format!(
                                "preflight response node_tag mismatch: expected {}, got {}",
                                node_tag, report.node_tag
                            ),
                        }],
                    }
                } else {
                    report
                }
            }
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

    async fn send_config_push_with_seq(
        &self,
        actor: &str,
        topo: &TopologySpec,
        node_tag: &str,
        cfg: NodeConfig,
        seq: u64,
        revision: Option<&str>,
    ) -> Result<()> {
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
        let hops = compute_control_hops(&self.cfg.control_id, &boot, node_tag, topo)
            .or_else(|| {
                if node_tag == boot {
                    Some(vec![self.cfg.control_id.clone(), boot.clone()])
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                ExposureError::Routing(format!(
                    "no hop path from bootstrap '{boot}' to '{node_tag}'"
                ))
            })?;

        let rev_str = revision.unwrap_or("");
        let bundle = self.sign_config_bundle_with_revision(
            node_tag,
            seq,
            rev_str,
            cfg,
            ConfigBundlePurpose::Apply,
            3600,
        )?;

        let frame = SpecialFrame::new(
            Uuid::new_v4().to_string(),
            hops,
            16,
            SpecialPayload::ConfigPush(Box::new(bundle)),
        );

        let rev_label = if rev_str.is_empty() {
            format!("seq={seq}")
        } else {
            format!("seq={seq} rev={rev_str}")
        };

        match self.send_special_rpc(frame, Duration::from_secs(10)).await {
            Ok(SpecialFrame {
                payload:
                    SpecialPayload::ConfigAck {
                        node_tag: ack_node,
                        sequence: ack_seq,
                        applied: true,
                        ..
                    },
                ..
            }) if ack_node == node_tag && ack_seq == seq => {
                if revision.is_some() {
                    let _ = self
                        .db
                        .update_release_node_status(seq, node_tag, "applied", None)
                        .await;
                }
                self.db
                    .set_node_reload_result(node_tag, seq, revision, true, None)
                    .await?;
                self.db
                    .append_audit(actor, "config_push", node_tag, true, &rev_label)
                    .await;
                Ok(())
            }
            Ok(SpecialFrame {
                payload:
                    SpecialPayload::ConfigAck {
                        node_tag: ack_node,
                        sequence: ack_seq,
                        applied: false,
                        error,
                        ..
                    },
                ..
            }) if ack_node == node_tag && ack_seq == seq => {
                let err_s = error.unwrap_or_else(|| "node rejected config".into());
                if revision.is_some() {
                    let _ = self
                        .db
                        .update_release_node_status(seq, node_tag, "failed", Some(&err_s))
                        .await;
                }
                self.db
                    .set_node_reload_result(node_tag, seq, revision, false, Some(&err_s))
                    .await?;
                self.db
                    .append_audit(actor, "config_push", node_tag, false, &err_s)
                    .await;
                Err(ExposureError::Config(err_s))
            }
            Err(e) => {
                if revision.is_some() {
                    let _ = self
                        .db
                        .update_release_node_status(seq, node_tag, "failed", Some(&e.to_string()))
                        .await;
                }
                self.db
                    .append_audit(actor, "config_push", node_tag, false, &e.to_string())
                    .await;
                Err(e)
            }
            _ => {
                let err_s = "unexpected reply to ConfigPush";
                if revision.is_some() {
                    let _ = self
                        .db
                        .update_release_node_status(seq, node_tag, "failed", Some(err_s))
                        .await;
                }
                self.db
                    .append_audit(actor, "config_push", node_tag, false, err_s)
                    .await;
                Err(ExposureError::Protocol(err_s.into()))
            }
        }
    }

    pub async fn push_node_config(
        &self,
        actor: &str,
        topo: &TopologySpec,
        node_tag: &str,
        cfg: NodeConfig,
    ) -> Result<u64> {
        let cfg_json = serde_json::to_string(&cfg)
            .map_err(|e| ExposureError::Config(format!("serialize node config: {e}")))?;
        let (seq, ver_id) = self
            .db
            .allocate_and_record_config_version(node_tag, &cfg_json)
            .await?;
        let res = self
            .send_config_push_with_seq(actor, topo, node_tag, cfg, seq, None)
            .await;
        let _ = self
            .db
            .update_config_version_status(ver_id, if res.is_ok() { "applied" } else { "failed" })
            .await;
        res.map(|()| seq)
    }

    /// Deploy a single global Git-style `(release_seq, revision)` to all compiled nodes concurrently.
    pub async fn deploy_topology_release(
        self: &Arc<Self>,
        actor: &str,
        topology_yaml: &str,
        topo: &TopologySpec,
        compiled: BTreeMap<String, NodeConfig>,
        trigger_kind: &str,
        message: &str,
    ) -> Result<DeployReleaseResult> {
        let target_nodes: Vec<String> = compiled.keys().cloned().collect();
        let crs_version = self.active_crs_snapshot().await.version.clone();
        let rel = self
            .db
            .allocate_release(
                trigger_kind,
                message,
                topology_yaml,
                &crs_version,
                actor,
                &target_nodes,
            )
            .await?;

        let mut futs = FuturesUnordered::new();
        for (tag, cfg) in compiled {
            let client = Arc::clone(self);
            let topo_c = topo.clone();
            let rev = rel.revision.clone();
            let seq = rel.release_seq;
            let actor_s = actor.to_string();
            futs.push(tokio::spawn(async move {
                let res = client
                    .send_config_push_with_seq(&actor_s, &topo_c, &tag, cfg, seq, Some(&rev))
                    .await;
                (tag, res)
            }));
        }

        let mut results = Vec::new();
        while let Some(joined) = futs.next().await {
            if let Ok((tag, res)) = joined {
                match res {
                    Ok(()) => results.push(serde_json::json!({
                        "node_tag": tag,
                        "ok": true,
                        "sequence": rel.release_seq,
                        "revision": rel.revision,
                    })),
                    Err(e) => results.push(serde_json::json!({
                        "node_tag": tag,
                        "ok": false,
                        "sequence": rel.release_seq,
                        "revision": rel.revision,
                        "error": e.to_string(),
                    })),
                }
            }
        }
        results.sort_by(|a, b| a["node_tag"].as_str().cmp(&b["node_tag"].as_str()));

        Ok(DeployReleaseResult {
            release_seq: rel.release_seq,
            revision: rel.revision,
            revision_full: rel.revision_full,
            parent_revision: rel.parent_revision,
            results,
        })
    }

    /// Push to a single node, reusing the latest cluster release's `(release_seq, revision)`
    /// if the node is behind (`node.config_seq < latest.release_seq`) and the topology/CRS matches.
    pub async fn push_single_node_latest(
        self: &Arc<Self>,
        actor: &str,
        topo: &TopologySpec,
        topology_yaml: &str,
        node_tag: &str,
        cfg: NodeConfig,
        is_custom_override: bool,
    ) -> Result<(u64, String)> {
        let cur_crs_ver = self.active_crs_snapshot().await.version.clone();
        if !is_custom_override {
            if let Ok(Some(latest)) = self.db.get_latest_config_release().await {
                if latest.topology_yaml.trim() == topology_yaml.trim()
                    && latest.crs_version == cur_crs_ver
                {
                    let node_seq = self
                        .db
                        .get_node(node_tag)
                        .await
                        .ok()
                        .flatten()
                        .map(|n| n.config_seq)
                        .unwrap_or(0);
                    if node_seq < latest.release_seq {
                        self.send_config_push_with_seq(
                            actor,
                            topo,
                            node_tag,
                            cfg,
                            latest.release_seq,
                            Some(&latest.revision),
                        )
                        .await?;
                        return Ok((latest.release_seq, latest.revision));
                    }
                }
            }
        }

        let rel = self
            .db
            .allocate_release(
                "single_node",
                &format!("Push config to {node_tag}"),
                topology_yaml,
                &cur_crs_ver,
                actor,
                &[node_tag.to_string()],
            )
            .await?;
        self.send_config_push_with_seq(
            actor,
            topo,
            node_tag,
            cfg,
            rel.release_seq,
            Some(&rel.revision),
        )
        .await?;
        Ok((rel.release_seq, rel.revision))
    }

    /// Rollback cluster topology to a historical Git revision or release sequence by creating a new forward revert release.
    pub async fn rollback_to_release(
        self: &Arc<Self>,
        actor: &str,
        rev_or_seq: &str,
    ) -> Result<DeployReleaseResult> {
        let target = self
            .db
            .get_config_release(rev_or_seq)
            .await?
            .ok_or_else(|| {
                ExposureError::Config(format!("config release '{rev_or_seq}' not found"))
            })?;
        let (topo, report, compiled) = self
            .compile_yaml_and_provision(&target.topology_yaml)
            .await?;
        if !report.valid {
            return Err(ExposureError::Config(format!(
                "rollback target '{}' no longer compiles cleanly: {}",
                target.revision,
                report.errors.join("; ")
            )));
        }
        self.db.set_topology_yaml(&target.topology_yaml).await?;
        *self.cached_topology.write().await = None;

        let msg = format!("Rollback to {}", target.revision);
        let deploy = self
            .deploy_topology_release(
                actor,
                &target.topology_yaml,
                &topo,
                compiled,
                "rollback",
                &msg,
            )
            .await?;
        self.db
            .append_audit(
                actor,
                "config_rollback",
                &target.revision,
                true,
                &format!("created release #{} rev={}", deploy.release_seq, deploy.revision),
            )
            .await;
        Ok(deploy)
    }

    /// Query all reachable Maintainer nodes concurrently using Control-signed `QueryMaintainerReq`.
    pub async fn query_maintainers(
        self: &Arc<Self>,
        query: MaintainerQuery,
    ) -> Vec<(String, Result<serde_json::Value>)> {
        let Some(boot) = self.active_bootstrap_tag().await else {
            return Vec::new();
        };
        let topo = self
            .cached_topology_spec()
            .await
            .unwrap_or_else(|_| Arc::new(TopologySpec::default()));

        let mut tags: BTreeSet<String> = topo
            .nodes
            .iter()
            .filter(|(_, spec)| spec.roles.maintainer)
            .map(|(tag, _)| tag.clone())
            .collect();
        if let Ok(db_nodes) = self.db.list_nodes().await {
            for n in db_nodes {
                if n.roles.iter().any(|r| r == "maintainer") {
                    tags.insert(n.node_tag);
                }
            }
        }
        if tags.is_empty() {
            return Vec::new();
        }

        let mut futs = FuturesUnordered::new();
        for tag in tags {
            let Some(hops) = compute_control_hops(&self.cfg.control_id, &boot, &tag, &topo)
                .or_else(|| {
                    if tag == boot {
                        Some(vec![self.cfg.control_id.clone(), boot.clone()])
                    } else {
                        None
                    }
                })
            else {
                continue;
            };
            let this = Arc::clone(self);
            let q = query.clone();
            futs.push(tokio::spawn(async move {
                let now = Utc::now().timestamp();
                let expires_at = now + 60;
                let request_id = Uuid::new_v4().to_string();
                let signing = query_maintainer_req_signing_bytes(
                    &request_id,
                    now,
                    expires_at,
                    &tag,
                    &q,
                );
                let control_signature = this.signing_kp.sign_b64(&signing);
                let frame = SpecialFrame::new(
                    Uuid::new_v4().to_string(),
                    hops,
                    16,
                    SpecialPayload::QueryMaintainerReq {
                        request_id: request_id.clone(),
                        issued_at: now,
                        expires_at,
                        maintainer_tag: tag.clone(),
                        query: q,
                        control_signature,
                    },
                );
                let res = match this.send_special_rpc(frame, Duration::from_secs(10)).await {
                    Ok(SpecialFrame {
                        payload:
                            SpecialPayload::QueryMaintainerResp {
                                request_id: resp_id,
                                ok,
                                data,
                                error,
                                ..
                            },
                        ..
                    }) => {
                        if resp_id != request_id {
                            Err(ExposureError::Protocol(
                                "QueryMaintainerResp request_id mismatch".into(),
                            ))
                        } else if ok {
                            Ok(data)
                        } else {
                            Err(ExposureError::Storage(
                                error.unwrap_or_else(|| "maintainer query rejected".into()),
                            ))
                        }
                    }
                    Ok(SpecialFrame {
                        payload: SpecialPayload::ErrorReply { message },
                        ..
                    }) => Err(ExposureError::Storage(message)),
                    Ok(_) => Err(ExposureError::Protocol(
                        "unexpected reply to QueryMaintainerReq".into(),
                    )),
                    Err(e) => Err(e),
                };
                (tag, res)
            }));
        }

        let mut out = Vec::new();
        while let Some(joined) = futs.next().await {
            if let Ok(item) = joined {
                out.push(item);
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
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
                            config_revision,
                            neighbors,
                            signature,
                        },
                    ..
                }) => {
                    if request_id != req_id {
                        warn!(expected = %req_id, got = %request_id, "discovery response request_id mismatch");
                        continue;
                    }
                    if node_tag != target || public_key.trim().is_empty() {
                        warn!(expected = %target, got = %node_tag, "discovery response node_tag or empty public key mismatch");
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
                    let _ = self
                        .db
                        .sync_node_reported_version(&node_tag, config_sequence, &config_revision)
                        .await;
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
        let _pull_guard = self.pull_telemetry_lock.lock().await;
        let Some(boot) = self.active_bootstrap_tag().await else {
            return Ok(0);
        };
        let topo = self
            .cached_topology_spec()
            .await
            .unwrap_or_else(|_| Arc::new(TopologySpec::default()));

        let mut tag_set: HashSet<String> = topo.nodes.keys().cloned().collect();
        tag_set.insert(boot.clone());
        if let Ok(db_nodes) = self.db.list_nodes().await {
            for n in db_nodes {
                tag_set.insert(n.node_tag);
            }
        }

        let mut expected_maintainers = 0usize;
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
            if topo.nodes.get(&tag).map(|s| s.roles.maintainer).unwrap_or(false) {
                expected_maintainers += 1;
            }
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
                        let rev_opt = if snap.config_revision.trim().is_empty() {
                            None
                        } else {
                            Some(snap.config_revision.as_str())
                        };
                        let _ = this
                            .db
                            .set_node_reload_result(
                                &tag,
                                snap.config_sequence,
                                rev_opt,
                                snap.last_reload_ok,
                                snap.last_reload_error.as_deref(),
                            )
                            .await;

                        let maint_snap = if snap.roles.maintainer {
                            let request_id = Uuid::new_v4().to_string();
                            let now = Utc::now().timestamp();
                            let expires_at = now + 60;
                            let signing = pull_telemetry_req_signing_bytes(
                                &request_id,
                                now,
                                expires_at,
                                &tag,
                                None,
                            );
                            let control_signature = this.signing_kp.sign_b64(&signing);
                            let pull_frame = SpecialFrame::new(
                                Uuid::new_v4().to_string(),
                                hops,
                                16,
                                SpecialPayload::PullTelemetryReq {
                                    request_id,
                                    issued_at: now,
                                    expires_at,
                                    maintainer_tag: tag.clone(),
                                    since_minute: None,
                                    control_signature,
                                },
                            );
                            match this
                                .send_special_rpc(pull_frame, Duration::from_secs(6))
                                .await
                            {
                                Ok(SpecialFrame {
                                    payload: SpecialPayload::PullTelemetryResp(ms),
                                    ..
                                }) if ms.maintainer_tag == tag => Some(Some(ms)),
                                _ => Some(None),
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

        let prev = Arc::clone(&*self.telemetry_cache.read().await);
        let mut cache = CachedTelemetry::default();
        let mut pulled = 0usize;
        let mut succeeded_nodes: HashSet<String> = HashSet::new();
        let mut succeeded_maintainers: HashSet<String> = HashSet::new();
        let mut failed_maintainers = false;

        let mut dedup_summaries: HashMap<(i64, String, String, String), MinuteSummary> =
            HashMap::new();
        let mut dedup_fingerprints: HashMap<String, FingerprintObservation> = HashMap::new();
        let mut dedup_logs: HashMap<(String, String, i64, String), SessionSummary> =
            HashMap::new();
        let mut dedup_certs: HashMap<String, CertStatusInfo> = HashMap::new();

        while let Some(res) = futs.next().await {
            if let Ok(Some((snap, maint_state))) = res {
                let NodeStatusSnapshot {
                    node_tag,
                    uptime_secs,
                    links,
                    alerts,
                    evilpot,
                    geoip,
                    log_stats,
                    ..
                } = snap;
                succeeded_nodes.insert(node_tag.clone());
                cache.node_uptimes.insert(node_tag.clone(), uptime_secs);
                if let Some(gs) = geoip {
                    cache.geoip_status.insert(node_tag.clone(), gs);
                }
                cache.log_stats.insert(node_tag, log_stats);
                cache.links.extend(links);
                cache.alerts.extend(alerts);
                if let Some(ep) = evilpot {
                    cache.evilpot_reports.push(ep);
                }
                pulled += 1;

                match maint_state {
                    Some(Some(MaintainerTelemetrySnapshot {
                        maintainer_tag,
                        summaries,
                        fingerprints,
                        recent_logs,
                        certificates,
                        segment_backlog,
                        merge_latency_ms,
                        alerts: m_alerts,
                        storage_stats,
                    })) => {
                        succeeded_maintainers.insert(maintainer_tag.clone());
                        cache.maintainers.push(MaintainerHealthInfo {
                            maintainer_tag,
                            segment_backlog,
                            merge_latency_ms,
                            storage_stats,
                        });
                        for s in summaries {
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
                            // Non-additive reconciliation across maintainers holding overlapping observations
                            dedup_fingerprints
                                .entry(fp.id.clone())
                                .and_modify(|existing| {
                                    let prefer_new = fp.request_count > existing.request_count
                                        || (fp.request_count == existing.request_count
                                            && fp.last_seen_ts > existing.last_seen_ts);
                                    let max_req = existing.request_count.max(fp.request_count);
                                    let max_ch = existing.challenge_count.max(fp.challenge_count);
                                    let max_rl = existing.rate_limited_count.max(fp.rate_limited_count);
                                    let max_ab = match (existing.abuse_score, fp.abuse_score) {
                                        (Some(a), Some(b)) => Some(a.max(b)),
                                        (a, b) => a.or(b),
                                    };
                                    if prefer_new {
                                        let mut merged = fp.clone();
                                        if !merged.js_verified && existing.js_verified {
                                            merged.js_verified = true;
                                            merged.fp_source = existing.fp_source.clone();
                                            merged.js_fp = existing.js_fp.clone();
                                        } else if merged.js_fp.is_none() {
                                            merged.js_fp = existing.js_fp.clone();
                                        }
                                        *existing = merged;
                                    } else if !existing.js_verified && fp.js_verified {
                                        existing.js_verified = true;
                                        existing.fp_source = fp.fp_source.clone();
                                        existing.js_fp = fp.js_fp.clone();
                                    } else if existing.js_fp.is_none() {
                                        existing.js_fp = fp.js_fp.clone();
                                    }
                                    existing.request_count = max_req;
                                    existing.challenge_count = max_ch;
                                    existing.rate_limited_count = max_rl;
                                    existing.abuse_score = max_ab;
                                })
                                .or_insert(fp);
                        }
                        for rec in recent_logs {
                            let key = (
                                rec.node_tag.clone(),
                                rec.role.clone(),
                                rec.timestamp_ms,
                                rec.ray_id.clone().unwrap_or_else(|| {
                                    format!(
                                        "{}:{}:{}",
                                        rec.ip_hmac,
                                        rec.path.as_deref().unwrap_or(""),
                                        rec.status
                                    )
                                }),
                            );
                            dedup_logs
                                .entry(key)
                                .and_modify(|existing| {
                                    if rec.repeat_count > existing.repeat_count {
                                        *existing = rec.clone();
                                    }
                                })
                                .or_insert(rec);
                        }
                        for c in certificates {
                            dedup_certs.insert(c.domain.clone(), c);
                        }
                        cache.alerts.extend(m_alerts);
                    }
                    Some(None) => {
                        failed_maintainers = true;
                    }
                    None => {}
                }
            }
        }

        if pulled == 0 {
            return Ok(0);
        }

        // Preserve last-known telemetry slices for nodes/maintainers that were temporarily unreachable.
        for (k, v) in &prev.node_uptimes {
            if !succeeded_nodes.contains(k) {
                cache.node_uptimes.insert(k.clone(), *v);
            }
        }
        for (k, v) in &prev.geoip_status {
            if !succeeded_nodes.contains(k) {
                cache.geoip_status.insert(k.clone(), v.clone());
            }
        }
        for (k, v) in &prev.log_stats {
            if !succeeded_nodes.contains(k) {
                cache.log_stats.insert(k.clone(), v.clone());
            }
        }
        for l in &prev.links {
            if !succeeded_nodes.contains(&l.node_tag) {
                cache.links.push(l.clone());
            }
        }
        for ep in &prev.evilpot_reports {
            if !succeeded_nodes.contains(&ep.node_tag) {
                cache.evilpot_reports.push(ep.clone());
            }
        }

        if failed_maintainers || succeeded_maintainers.len() < expected_maintainers {
            for m in &prev.maintainers {
                if !succeeded_maintainers.contains(&m.maintainer_tag) {
                    cache.maintainers.push(m.clone());
                }
            }
            for s in &prev.summaries {
                let key = (
                    s.minute_epoch,
                    s.node_tag.clone(),
                    s.role.clone(),
                    s.service_tag.clone(),
                );
                dedup_summaries.entry(key).or_insert_with(|| s.clone());
            }
            for fp in &prev.fingerprints {
                dedup_fingerprints
                    .entry(fp.id.clone())
                    .or_insert_with(|| fp.clone());
            }
            for rec in &prev.recent_logs {
                let key = (
                    rec.node_tag.clone(),
                    rec.role.clone(),
                    rec.timestamp_ms,
                    rec.ray_id.clone().unwrap_or_else(|| {
                        format!(
                            "{}:{}:{}",
                            rec.ip_hmac,
                            rec.path.as_deref().unwrap_or(""),
                            rec.status
                        )
                    }),
                );
                dedup_logs.entry(key).or_insert_with(|| rec.clone());
            }
            for c in &prev.certificates {
                dedup_certs
                    .entry(c.domain.clone())
                    .or_insert_with(|| c.clone());
            }
        }

        cache.summaries = dedup_summaries.into_values().collect();
        let mut fps: Vec<FingerprintObservation> = dedup_fingerprints.into_values().collect();
        fps.sort_by(|a, b| b.last_seen_ts.cmp(&a.last_seen_ts));
        fps.truncate(10_000);
        cache.fingerprints = fps;
        let mut logs: Vec<SessionSummary> = dedup_logs.into_values().collect();
        logs.sort_by(|a, b| b.timestamp_ms.cmp(&a.timestamp_ms));
        logs.truncate(MAX_PERSISTED_LOGS);
        cache.recent_logs = logs;
        cache.certificates = dedup_certs.into_values().collect();
        cache.last_pulled_at = Some(Utc::now().to_rfc3339());

        let arc_cache = Arc::new(cache.clone());
        *self.telemetry_cache.write().await = arc_cache;

        // Persist bounded telemetry snapshot to SQLite so Control restarts keep recent telemetry.
        let mut persisted = cache;
        if persisted.summaries.len() > MAX_PERSISTED_SUMMARIES {
            persisted
                .summaries
                .sort_by(|a, b| b.minute_epoch.cmp(&a.minute_epoch));
            persisted.summaries.truncate(MAX_PERSISTED_SUMMARIES);
        }
        if persisted.fingerprints.len() > MAX_PERSISTED_FINGERPRINTS {
            persisted.fingerprints.truncate(MAX_PERSISTED_FINGERPRINTS);
        }
        if persisted.recent_logs.len() > MAX_PERSISTED_LOGS {
            persisted.recent_logs.truncate(MAX_PERSISTED_LOGS);
        }
        if persisted.alerts.len() > MAX_PERSISTED_ALERTS {
            persisted.alerts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
            persisted.alerts.truncate(MAX_PERSISTED_ALERTS);
        }
        if let Err(e) = self.db.set_kv_json(KV_TELEMETRY_CACHE, &persisted).await {
            warn!(error = %e, "failed to persist telemetry cache to SQLite");
        }
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

            let mut line_entries = Vec::new();
            let mut flat_v4 = BTreeSet::new();
            let mut flat_v6 = BTreeSet::new();

            if !binding.line_routes.is_empty() {
                for lr in &binding.line_routes {
                    if !lr.enabled {
                        continue;
                    }
                    let mut v4 = BTreeSet::new();
                    let mut v6 = BTreeSet::new();
                    let mut cnames = BTreeSet::new();

                    if lr.record_type == DomainLineRecordType::Cname {
                        for raw in &lr.values {
                            let clean = raw.trim().trim_end_matches('.');
                            if !clean.is_empty() {
                                cnames.insert(clean.to_string());
                            }
                        }
                    } else {
                        for node_tag in &lr.target_nodes {
                            let node_spec = topo.nodes.get(node_tag).ok_or_else(|| {
                                ExposureError::Config(format!(
                                    "domain '{dom}' line '{}' references unknown target node '{node_tag}'",
                                    lr.line
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
                                        flat_v4.insert(addr.to_string());
                                    }
                                    IpAddr::V6(addr) => {
                                        v6.insert(addr.to_string());
                                        flat_v6.insert(addr.to_string());
                                    }
                                }
                            }
                        }
                        for raw_val in &lr.values {
                            let ip: IpAddr = raw_val.trim().parse().map_err(|_| {
                                ExposureError::Config(format!(
                                    "domain '{dom}' line '{}' has invalid IP '{raw_val}'",
                                    lr.line
                                ))
                            })?;
                            match canonical_ip(ip) {
                                IpAddr::V4(addr) => {
                                    v4.insert(addr.to_string());
                                    flat_v4.insert(addr.to_string());
                                }
                                IpAddr::V6(addr) => {
                                    v6.insert(addr.to_string());
                                    flat_v6.insert(addr.to_string());
                                }
                            }
                        }
                    }

                    if v4.is_empty() && v6.is_empty() && cnames.is_empty() {
                        continue;
                    }
                    line_entries.push(DnsLineSyncEntry {
                        line: if lr.line.trim().is_empty() {
                            "default".into()
                        } else {
                            lr.line.trim().to_string()
                        },
                        ipv4s: v4.into_iter().collect(),
                        ipv6s: v6.into_iter().collect(),
                        cnames: cnames.into_iter().collect(),
                        ttl: lr.ttl.or(Some(binding.ttl)),
                        proxied: lr.proxied.or(Some(binding.proxied)),
                    });
                }

                if line_entries.is_empty() {
                    if explicitly_requested {
                        return Err(ExposureError::Config(format!(
                            "domain '{dom}' line_routes resolved to zero target records"
                        )));
                    }
                    continue;
                }
            } else {
                if binding.target_nodes.is_empty() {
                    if explicitly_requested {
                        return Err(ExposureError::Config(format!(
                            "domain '{dom}' has no target_nodes or line_routes configured for DNS sync"
                        )));
                    }
                    continue;
                }

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
                                flat_v4.insert(addr.to_string());
                            }
                            IpAddr::V6(addr) => {
                                flat_v6.insert(addr.to_string());
                            }
                        }
                    }
                }

                if flat_v4.is_empty() && flat_v6.is_empty() {
                    if explicitly_requested {
                        return Err(ExposureError::Config(format!(
                            "domain '{dom}' target_nodes ({}) have no external_ips configured",
                            binding.target_nodes.join(", ")
                        )));
                    }
                    // Don't let a single misconfigured, unrequested domain abort the whole sync.
                    continue;
                }
            }

            records.push(DnsSyncRecordSpec {
                domain: dom.clone(),
                ipv4s: flat_v4.into_iter().collect(),
                ipv6s: flat_v6.into_iter().collect(),
                line_entries,
                provider: Some(binding.provider.clone()),
                zone_id: binding.zone_id.clone(),
                root_domain: binding.root_domain.clone(),
                ttl: Some(binding.ttl),
                proxied: Some(binding.proxied),
            });
        }

        if records.is_empty() {
            return Err(ExposureError::Config(
                "no domains with target_nodes or line_routes configured for DNS sync".into(),
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

    /// Issue a Control-signed `DnsManageReq` to Primary Maintainer to inspect supported lines /
    /// live remote records or create/update/toggle/delete a single Exposure-scoped A/AAAA/CNAME record.
    #[allow(clippy::type_complexity)]
    pub async fn manage_dns(
        &self,
        actor: &str,
        op: DnsManageOp,
        maintainer_tag: Option<String>,
    ) -> Result<(
        String,
        DnsProviderCapabilities,
        Vec<DnsSupportLine>,
        Vec<DnsRemoteRecord>,
        Option<String>,
    )> {
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

        let is_mutating = !matches!(op, DnsManageOp::Inspect { .. });
        let audit_target = match &op {
            DnsManageOp::Inspect { domain, .. }
            | DnsManageOp::Create { domain, .. }
            | DnsManageOp::Update { domain, .. }
            | DnsManageOp::SetStatus { domain, .. }
            | DnsManageOp::Delete { domain, .. } => domain.clone(),
        };

        let now = Utc::now().timestamp();
        let expires_at = now + 60;
        let request_id = Uuid::new_v4().to_string();
        let signing =
            dns_manage_req_signing_bytes(&request_id, now, expires_at, &target_maint, &op);
        let control_signature = self.signing_kp.sign_b64(&signing);

        let frame = SpecialFrame::new(
            Uuid::new_v4().to_string(),
            hops,
            16,
            SpecialPayload::DnsManageReq {
                request_id: request_id.clone(),
                issued_at: now,
                expires_at,
                maintainer_tag: target_maint.clone(),
                op,
                control_signature,
            },
        );

        match self.send_special_rpc(frame, Duration::from_secs(30)).await? {
            SpecialFrame {
                payload:
                    SpecialPayload::DnsManageResp {
                        request_id: resp_id,
                        ok,
                        capabilities,
                        lines,
                        records,
                        record_id,
                        error,
                        ..
                    },
                ..
            } => {
                if resp_id != request_id {
                    return Err(ExposureError::Protocol(
                        "DnsManageResp request_id mismatch".into(),
                    ));
                }
                if is_mutating {
                    self.db
                        .append_audit(
                            actor,
                            "dns_manage",
                            &audit_target,
                            ok,
                            error.as_deref().unwrap_or("remote DNS record updated"),
                        )
                        .await;
                }
                if !ok {
                    return Err(ExposureError::Protocol(
                        error.unwrap_or_else(|| "remote DNS operation failed".into()),
                    ));
                }
                Ok((target_maint, capabilities, lines, records, record_id))
            }
            SpecialFrame {
                payload: SpecialPayload::ErrorReply { message },
                ..
            } => {
                if is_mutating {
                    self.db
                        .append_audit(actor, "dns_manage", &audit_target, false, &message)
                        .await;
                }
                Err(ExposureError::Protocol(message))
            }
            _ => Err(ExposureError::Protocol("unexpected DnsManage reply".into())),
        }
    }

    async fn resolve_target_ingress_hops(
        &self,
        target_node: Option<&str>,
    ) -> Result<Vec<(String, Vec<String>)>> {
        let boot = self
            .active_bootstrap_tag()
            .await
            .ok_or_else(|| ExposureError::Link("Control not connected to any bootstrap node".into()))?;
        let topo = self.cached_topology_spec().await?;

        let mut tags: Vec<String> = Vec::new();
        if let Some(specific) = target_node.map(str::trim).filter(|s| !s.is_empty() && *s != "all") {
            let is_ingress = if let Some(spec) = topo.nodes.get(specific) {
                spec.roles.ingress
            } else if let Ok(Some(rec)) = self.db.get_node(specific).await {
                rec.roles.iter().any(|r| r == "ingress")
            } else {
                false
            };
            if !is_ingress {
                return Err(ExposureError::Config(format!(
                    "target node '{specific}' is not a known ingress node"
                )));
            }
            tags.push(specific.to_string());
        } else {
            for (tag, spec) in &topo.nodes {
                if spec.roles.ingress {
                    tags.push(tag.clone());
                }
            }
            if tags.is_empty() {
                if let Ok(db_nodes) = self.db.list_nodes().await {
                    for n in db_nodes {
                        if n.online && n.roles.iter().any(|r| r == "ingress") {
                            tags.push(n.node_tag);
                        }
                    }
                }
            }
        }
        if tags.is_empty() {
            return Err(ExposureError::Config("no ingress nodes found in topology".into()));
        }
        let mut out = Vec::with_capacity(tags.len());
        for tag in tags {
            if let Some(hops) = compute_control_hops(&self.cfg.control_id, &boot, &tag, &topo) {
                out.push((tag, hops));
            }
        }
        if out.is_empty() {
            return Err(ExposureError::Routing(format!(
                "no reachable hop path from bootstrap '{boot}' to target ingress node(s)"
            )));
        }
        Ok(out)
    }

    /// Issue a Control-signed `UnbanReq` to the specified or all online Ingress node(s),
    /// and prune unbanned entries from the cached Evilpot/AutoBan telemetry immediately.
    pub async fn unban_target(
        self: &Arc<Self>,
        actor: &str,
        ban_kind: &str,
        target: &str,
        node_tag: Option<&str>,
    ) -> Result<serde_json::Value> {
        let kind_norm = ban_kind.trim().to_ascii_lowercase();
        if !matches!(
            kind_norm.as_str(),
            "ip" | "js_fp" | "composite_fp" | "all"
        ) {
            return Err(ExposureError::Config(format!(
                "unsupported unban kind '{ban_kind}' (expected ip, js_fp, composite_fp, all)"
            )));
        }
        let clean_target = if kind_norm == "ip" {
            let ip: IpAddr = target
                .trim()
                .parse()
                .map_err(|_| ExposureError::Config(format!("invalid IP address '{target}'")))?;
            canonical_ip(ip).to_string()
        } else if kind_norm == "all" {
            "*".to_string()
        } else {
            let t = target.trim();
            if t.is_empty() {
                return Err(ExposureError::Config("unban target must not be empty".into()));
            }
            t.to_string()
        };

        let targets = self.resolve_target_ingress_hops(node_tag).await?;
        let mut futs = FuturesUnordered::new();
        for (tag, hops) in targets {
            let this = Arc::clone(self);
            let k = kind_norm.clone();
            let t = clean_target.clone();
            futs.push(tokio::spawn(async move {
                let now = Utc::now().timestamp();
                let expires_at = now + 60;
                let request_id = Uuid::new_v4().to_string();
                let signing =
                    unban_req_signing_bytes(&request_id, now, expires_at, &tag, &k, &t);
                let control_signature = this.signing_kp.sign_b64(&signing);
                let frame = SpecialFrame::new(
                    Uuid::new_v4().to_string(),
                    hops,
                    16,
                    SpecialPayload::UnbanReq {
                        request_id: request_id.clone(),
                        issued_at: now,
                        expires_at,
                        target_node_tag: tag.clone(),
                        ban_kind: k,
                        target: t,
                        control_signature,
                    },
                );
                match this.send_special_rpc(frame, Duration::from_secs(8)).await {
                    Ok(SpecialFrame {
                        payload:
                            SpecialPayload::UnbanResp {
                                request_id: resp_id,
                                node_tag: resp_node,
                                ok,
                                removed,
                                error,
                            },
                        ..
                    }) => {
                        if resp_id != request_id {
                            (tag, false, false, Some("UnbanResp request_id mismatch".into()))
                        } else {
                            (resp_node, ok, removed, error)
                        }
                    }
                    Ok(SpecialFrame {
                        payload: SpecialPayload::ErrorReply { message },
                        ..
                    }) => (tag, false, false, Some(message)),
                    Ok(_) => (tag, false, false, Some("unexpected UnbanReq reply".into())),
                    Err(e) => (tag, false, false, Some(e.to_string())),
                }
            }));
        }

        let mut results = Vec::new();
        let mut succeeded_nodes = HashSet::new();
        let mut any_removed = false;
        while let Some(res) = futs.next().await {
            if let Ok((ntag, ok, removed, err)) = res {
                if ok {
                    succeeded_nodes.insert(ntag.clone());
                }
                if removed {
                    any_removed = true;
                }
                results.push(serde_json::json!({
                    "node_tag": ntag,
                    "ok": ok,
                    "removed": removed,
                    "error": err,
                }));
            }
        }

        if !succeeded_nodes.is_empty() {
            let mut guard = self.telemetry_cache.write().await;
            let mut updated = (**guard).clone();
            for rep in &mut updated.evilpot_reports {
                if !succeeded_nodes.contains(&rep.node_tag) {
                    continue;
                }
                if kind_norm == "all" {
                    rep.active_bans.clear();
                    rep.active_ip_bans = 0;
                    rep.active_fp_bans = 0;
                } else {
                    rep.active_bans.retain(|b| {
                        !(b.kind == kind_norm && b.target == clean_target)
                    });
                    rep.active_ip_bans = rep
                        .active_bans
                        .iter()
                        .filter(|b| b.kind == "ip")
                        .count();
                    rep.active_fp_bans = rep
                        .active_bans
                        .iter()
                        .filter(|b| b.kind != "ip")
                        .count();
                }
            }
            *guard = Arc::new(updated);
        }

        let all_ok = !results.is_empty()
            && results
                .iter()
                .all(|r| r["ok"].as_bool().unwrap_or(false));

        if !succeeded_nodes.is_empty() {
            let unbanned_at_unix = Utc::now().timestamp().max(0) as u64;
            let _ = self
                .query_maintainers(MaintainerQuery::MarkUnbanned {
                    node_tag: node_tag.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
                    ban_kind: kind_norm.clone(),
                    target: clean_target.clone(),
                    actor: actor.to_string(),
                    unbanned_at_unix,
                })
                .await;
        }

        self.db
            .append_audit(
                actor,
                "security.unban",
                &format!("{kind_norm}:{clean_target}"),
                all_ok,
                &format!(
                    "dispatched to {} ingress node(s), removed={any_removed}",
                    results.len()
                ),
            )
            .await;

        Ok(serde_json::json!({
            "ok": all_ok,
            "kind": kind_norm,
            "target": clean_target,
            "removed": any_removed,
            "nodes": results,
        }))
    }

    pub async fn geoip_status(&self) -> serde_json::Value {
        let yaml = self.db.get_topology_yaml().await.unwrap_or_default();
        let topo: TopologySpec = serde_yaml::from_str(&yaml).unwrap_or_default();
        let cache = self.telemetry_cache.read().await.clone();

        let mut node_tags: BTreeSet<String> = topo
            .nodes
            .iter()
            .filter(|(_, s)| s.roles.ingress)
            .map(|(k, _)| k.clone())
            .collect();
        for k in cache.geoip_status.keys() {
            node_tags.insert(k.clone());
        }

        let mut nodes_out = Vec::new();
        let mut loaded_nodes = 0usize;
        let mut max_v4 = 0usize;
        let mut max_v6 = 0usize;
        for tag in &node_tags {
            let st = cache.geoip_status.get(tag).cloned().unwrap_or_default();
            if st.loaded {
                loaded_nodes += 1;
            }
            max_v4 = max_v4.max(st.ipv4_ranges);
            max_v6 = max_v6.max(st.ipv6_ranges);
            nodes_out.push(serde_json::json!({
                "node_tag": tag,
                "enabled": st.enabled,
                "loaded": st.loaded,
                "ipv4_ranges": st.ipv4_ranges,
                "ipv6_ranges": st.ipv6_ranges,
                "updated_at": st.updated_at,
                "source": st.source,
                "last_error": st.last_error,
            }));
        }

        serde_json::json!({
            "last_pulled_at": cache.last_pulled_at,
            "summary": {
                "total_ingress_nodes": node_tags.len(),
                "loaded_nodes": loaded_nodes,
                "max_ipv4_ranges": max_v4,
                "max_ipv6_ranges": max_v6,
            },
            "nodes": nodes_out,
        })
    }

    pub async fn sync_geoip_nodes(
        self: &Arc<Self>,
        actor: &str,
        node_tag: Option<&str>,
        force: bool,
    ) -> Result<serde_json::Value> {
        let targets = self.resolve_target_ingress_hops(node_tag).await?;
        let mut futs = FuturesUnordered::new();
        for (tag, hops) in targets {
            let this = Arc::clone(self);
            futs.push(tokio::spawn(async move {
                let now = Utc::now().timestamp();
                let expires_at = now + 90;
                let request_id = Uuid::new_v4().to_string();
                let signing =
                    geoip_sync_req_signing_bytes(&request_id, now, expires_at, &tag, force);
                let control_signature = this.signing_kp.sign_b64(&signing);
                let frame = SpecialFrame::new(
                    Uuid::new_v4().to_string(),
                    hops,
                    16,
                    SpecialPayload::GeoIpSyncReq {
                        request_id: request_id.clone(),
                        issued_at: now,
                        expires_at,
                        target_node_tag: tag.clone(),
                        force,
                        control_signature,
                    },
                );
                match this.send_special_rpc(frame, Duration::from_secs(35)).await {
                    Ok(SpecialFrame {
                        payload:
                            SpecialPayload::GeoIpSyncResp {
                                request_id: resp_id,
                                node_tag: resp_node,
                                ok,
                                status,
                                error,
                            },
                        ..
                    }) => {
                        if resp_id != request_id {
                            (tag, false, None, Some("GeoIpSyncResp request_id mismatch".into()))
                        } else {
                            (resp_node, ok, status, error)
                        }
                    }
                    Ok(SpecialFrame {
                        payload: SpecialPayload::ErrorReply { message },
                        ..
                    }) => (tag, false, None, Some(message)),
                    Ok(_) => (tag, false, None, Some("unexpected GeoIpSyncReq reply".into())),
                    Err(e) => (tag, false, None, Some(e.to_string())),
                }
            }));
        }

        let mut results = Vec::new();
        let mut updates: Vec<(String, GeoIpStatusSnapshot)> = Vec::new();
        while let Some(res) = futs.next().await {
            if let Ok((ntag, ok, st_opt, err)) = res {
                if let Some(ref st) = st_opt {
                    updates.push((ntag.clone(), st.clone()));
                }
                results.push(serde_json::json!({
                    "node_tag": ntag,
                    "ok": ok,
                    "status": st_opt,
                    "error": err,
                }));
            }
        }
        if !updates.is_empty() {
            let mut guard = self.telemetry_cache.write().await;
            let mut updated = (**guard).clone();
            for (k, v) in updates {
                updated.geoip_status.insert(k, v);
            }
            *guard = Arc::new(updated);
        }
        let all_ok = !results.is_empty()
            && results
                .iter()
                .all(|r| r["ok"].as_bool().unwrap_or(false));
        self.db
            .append_audit(
                actor,
                "security.geoip_sync",
                node_tag.unwrap_or("all"),
                all_ok,
                &format!("force={force}, synced {} node(s)", results.len()),
            )
            .await;

        Ok(serde_json::json!({
            "ok": all_ok,
            "nodes": results,
        }))
    }

    pub async fn lookup_geoip_on_node(
        &self,
        ip: &str,
        node_tag: Option<&str>,
    ) -> Result<serde_json::Value> {
        let addr: IpAddr = ip
            .trim()
            .parse()
            .map_err(|_| ExposureError::Config(format!("invalid IP address '{ip}'")))?;
        let canon = canonical_ip(addr).to_string();
        let targets = self.resolve_target_ingress_hops(node_tag).await?;

        let cache = self.telemetry_cache.read().await;
        let (chosen_tag, hops) = targets
            .iter()
            .find(|(t, _)| {
                cache
                    .geoip_status
                    .get(t)
                    .map(|s| s.loaded)
                    .unwrap_or(false)
            })
            .cloned()
            .unwrap_or_else(|| targets[0].clone());
        drop(cache);

        let frame = SpecialFrame::new(
            Uuid::new_v4().to_string(),
            hops,
            16,
            SpecialPayload::GeoIpLookupReq { ip: canon.clone() },
        );
        match self.send_special_rpc(frame, Duration::from_secs(8)).await? {
            SpecialFrame {
                payload:
                    SpecialPayload::GeoIpLookupResp {
                        node_tag,
                        ip,
                        country,
                        continent,
                        is_private,
                        db_loaded,
                        error,
                    },
                ..
            } => Ok(serde_json::json!({
                "ok": error.is_none(),
                "node_tag": node_tag,
                "ip": ip,
                "country": country,
                "continent": continent,
                "is_private": is_private,
                "db_loaded": db_loaded,
                "error": error,
            })),
            SpecialFrame {
                payload: SpecialPayload::ErrorReply { message },
                ..
            } => Err(ExposureError::Protocol(format!(
                "GeoIP lookup on '{chosen_tag}' failed: {message}"
            ))),
            _ => Err(ExposureError::Protocol("unexpected GeoIpLookupReq reply".into())),
        }
    }
}
