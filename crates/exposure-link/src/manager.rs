use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use exposure_core::config::{LinkListenConfig, LinkMode, PeerConfig, ProbeConfig, TunnelDirection};
use exposure_core::crypto::{pubkey_fingerprint_b64, NodeKeyPair};
use exposure_core::protocol::StreamKind;
use exposure_core::routing::{select_endpoint, LinkHealthState};
use exposure_core::telemetry::LinkStatusSnapshot;
use exposure_core::{ExposureError, Result};
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::{mpsc, Mutex, RwLock, Semaphore};
use tracing::{debug, info, warn};

use crate::handshake::{
    client_hello, server_hello, BootstrapAuthState, HandshakeOutcome, NonceReplayCache,
};
use crate::mux::{IncomingMuxStream, MuxSession, MuxStream};
use crate::noise::NoiseStream;
use crate::probe::EndpointProbeTracker;
use crate::transport::{TcpTransport, Transport};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONCURRENT_HANDSHAKES: usize = 256;
const MAX_BOOTSTRAP_SESSIONS: usize = 128;
const INBOUND_TUNNEL_TRACKER_KEY: &str = "inbound-tunnel";

#[derive(Clone)]
struct ActiveSession {
    session: MuxSession,
    authenticated: bool,
    is_control: bool,
    remote_public_key: String,
    endpoint: String,
}

/// Link layer manager (DESIGN.md §6):
/// Owns transport, channel-bound Noise+Ed25519 handshakes, Yamux sessions, active probes, and tunnel/on-demand lifecycles.
pub struct LinkManager {
    local_tag: String,
    is_control: bool,
    keypair: NodeKeyPair,
    transport: Arc<dyn Transport>,
    peers: Arc<RwLock<Vec<PeerConfig>>>,
    trusted_control_pubkeys: Arc<RwLock<Vec<String>>>,
    bootstrap_state: Arc<BootstrapAuthState>,
    nonce_cache: Arc<NonceReplayCache>,
    probe_cfg: Arc<RwLock<ProbeConfig>>,
    /// Keyed by endpoint address (for authenticated outbound sessions).
    outbound_sessions: Arc<DashMap<String, ActiveSession>>,
    /// Keyed by remote `node_tag` (ONLY authenticated inbound / control / registered outbound sessions).
    inbound_sessions: Arc<DashMap<String, ActiveSession>>,
    /// Isolated bounded map for unauthenticated pending bootstrap sessions (ONLY StreamKind::Bootstrap).
    bootstrap_sessions: Arc<DashMap<String, ActiveSession>>,
    /// Per-endpoint singleflight lock to prevent thundering-herd lazy dials.
    dial_locks: Arc<DashMap<String, Arc<Mutex<()>>>>,
    /// Concurrency limit for inbound Noise+Hello handshakes.
    handshake_sem: Arc<Semaphore>,
    /// Keyed by `(peer_tag, endpoint_key)`.
    probe_trackers: Arc<DashMap<(String, String), EndpointProbeTracker>>,
    incoming_tx: mpsc::Sender<IncomingMuxStream>,
    incoming_rx: Arc<Mutex<Option<mpsc::Receiver<IncomingMuxStream>>>>,
    rr_ticket: AtomicU64,
    /// Generation counter to stop old outbound tunnel tasks on reload.
    tunnel_gen: Arc<AtomicU64>,
}

fn is_inbound_tunnel(peer: &PeerConfig) -> bool {
    peer.mode == LinkMode::Tunnel && peer.tunnel_direction == Some(TunnelDirection::Inbound)
}

fn peer_matches_pubkey(peer: &PeerConfig, pubkey_b64: &str) -> bool {
    let has_pk = peer
        .public_key
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty());
    let has_fp = peer
        .pubkey_fingerprint
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty());
    if !has_pk && !has_fp {
        return false;
    }
    if let Some(exp_pk) = peer.public_key.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if exp_pk != pubkey_b64.trim() {
            return false;
        }
    }
    if let Some(exp_fp) = peer
        .pubkey_fingerprint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let Ok(actual) = pubkey_fingerprint_b64(pubkey_b64) else {
            return false;
        };
        if !actual.eq_ignore_ascii_case(exp_fp) {
            return false;
        }
    }
    true
}

impl LinkManager {
    pub fn new(
        local_tag: impl Into<String>,
        keypair: NodeKeyPair,
        is_control: bool,
        peers: Vec<PeerConfig>,
        probe_cfg: ProbeConfig,
    ) -> Arc<Self> {
        Self::with_transport(
            local_tag,
            keypair,
            is_control,
            peers,
            probe_cfg,
            Arc::new(TcpTransport),
        )
    }

    pub fn with_transport(
        local_tag: impl Into<String>,
        keypair: NodeKeyPair,
        is_control: bool,
        peers: Vec<PeerConfig>,
        probe_cfg: ProbeConfig,
        transport: Arc<dyn Transport>,
    ) -> Arc<Self> {
        let (incoming_tx, incoming_rx) = mpsc::channel(512);
        Arc::new(Self {
            local_tag: local_tag.into(),
            is_control,
            keypair,
            transport,
            peers: Arc::new(RwLock::new(peers)),
            trusted_control_pubkeys: Arc::new(RwLock::new(Vec::new())),
            bootstrap_state: Arc::new(BootstrapAuthState::new()),
            nonce_cache: Arc::new(NonceReplayCache::new()),
            probe_cfg: Arc::new(RwLock::new(probe_cfg)),
            outbound_sessions: Arc::new(DashMap::new()),
            inbound_sessions: Arc::new(DashMap::new()),
            bootstrap_sessions: Arc::new(DashMap::new()),
            dial_locks: Arc::new(DashMap::new()),
            handshake_sem: Arc::new(Semaphore::new(MAX_CONCURRENT_HANDSHAKES)),
            probe_trackers: Arc::new(DashMap::new()),
            incoming_tx,
            incoming_rx: Arc::new(Mutex::new(Some(incoming_rx))),
            rr_ticket: AtomicU64::new(0),
            tunnel_gen: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn local_tag(&self) -> &str {
        &self.local_tag
    }

    pub fn keypair(&self) -> &NodeKeyPair {
        &self.keypair
    }

    pub async fn take_incoming_receiver(&self) -> Option<mpsc::Receiver<IncomingMuxStream>> {
        self.incoming_rx.lock().await.take()
    }

    pub async fn set_trusted_control_pubkeys(&self, keys: Vec<String>) {
        let cleaned: Vec<String> = keys
            .into_iter()
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
            .collect();
        *self.trusted_control_pubkeys.write().await = cleaned.clone();

        // Immediately evict and close any active Control sessions whose key is no longer trusted
        let mut to_close = Vec::new();
        self.inbound_sessions.retain(|_, v| {
            if v.is_control && !cleaned.iter().any(|k| k == v.remote_public_key.trim()) {
                to_close.push(v.session.clone());
                false
            } else {
                true
            }
        });
        for sess in to_close {
            sess.close().await;
        }
    }

    pub async fn set_bootstrap_passphrase(&self, pass: Option<String>) {
        self.bootstrap_state.set(pass).await;
    }

    pub async fn peers_snapshot(&self) -> Vec<PeerConfig> {
        self.peers.read().await.clone()
    }

    pub async fn update_peers(self: &Arc<Self>, peers: Vec<PeerConfig>, probe_cfg: ProbeConfig) {
        let ctrl_keys = self.trusted_control_pubkeys.read().await.clone();
        *self.peers.write().await = peers.clone();
        *self.probe_cfg.write().await = probe_cfg;

        // Close & evict revoked or key-rotated inbound and outbound sessions immediately!
        let mut to_close = Vec::new();
        self.inbound_sessions.retain(|node_tag, sess| {
            if sess.session.is_closed() {
                return false;
            }
            if sess.is_control {
                if ctrl_keys
                    .iter()
                    .any(|k| k.trim() == sess.remote_public_key.trim())
                {
                    return true;
                }
                to_close.push(sess.session.clone());
                return false;
            }
            let valid = peers
                .iter()
                .any(|p| p.node_tag == *node_tag && peer_matches_pubkey(p, &sess.remote_public_key));
            if !valid {
                to_close.push(sess.session.clone());
            }
            valid
        });

        let valid_endpoints: HashSet<String> = peers
            .iter()
            .flat_map(|p| p.endpoints.iter().map(|e| e.address.clone()))
            .collect();
        self.outbound_sessions.retain(|addr, sess| {
            if sess.session.is_closed() {
                return false;
            }
            let valid = valid_endpoints.contains(addr)
                && peers.iter().any(|p| {
                    p.endpoints.iter().any(|e| e.address == *addr)
                        && peer_matches_pubkey(p, &sess.remote_public_key)
                });
            if !valid {
                to_close.push(sess.session.clone());
            }
            valid
        });

        // Prune stale probe trackers for removed peers/endpoints
        let valid_peer_tags: HashSet<String> = peers.iter().map(|p| p.peer_tag.clone()).collect();
        self.probe_trackers
            .retain(|(pt, _), _| valid_peer_tags.contains(pt));

        for sess in to_close {
            sess.close().await;
        }

        self.spawn_outbound_tunnels();
    }

    /// Start listening for inbound on-demand, tunnel, and (when permitted) bootstrap connections.
    pub async fn start_listener(self: &Arc<Self>, cfg: LinkListenConfig) -> Result<SocketAddr> {
        let listener = self.transport.bind(&cfg.listen_addr).await?;
        let bound = listener.local_addr()?;
        info!(
            node = %self.local_tag,
            addr = %bound,
            allow_on_demand = cfg.allow_on_demand,
            allow_tunnel = cfg.allow_tunnel,
            allow_bootstrap = cfg.allow_bootstrap,
            "link listener started"
        );

        let mgr = Arc::clone(self);
        let listen_policy = Arc::new(cfg);
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, remote_addr)) => {
                        let permit = match Arc::clone(&mgr.handshake_sem).try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                warn!(remote = %remote_addr, "inbound link handshake concurrency limit reached, dropping connection");
                                continue;
                            }
                        };
                        let mgr2 = Arc::clone(&mgr);
                        let policy2 = Arc::clone(&listen_policy);
                        tokio::spawn(async move {
                            let res = tokio::time::timeout(
                                HANDSHAKE_TIMEOUT,
                                mgr2.handle_inbound_connection(stream, remote_addr, &policy2),
                            )
                            .await;
                            drop(permit);
                            match res {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => {
                                    debug!(remote = %remote_addr, error = %e, "inbound link handshake ended");
                                }
                                Err(_) => {
                                    debug!(remote = %remote_addr, "inbound link handshake timed out");
                                }
                            }
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, "link listener accept error");
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
            }
        });
        Ok(bound)
    }

    async fn handle_inbound_connection(
        self: &Arc<Self>,
        stream: crate::transport::BoxedStream,
        remote_addr: SocketAddr,
        listen_policy: &LinkListenConfig,
    ) -> Result<()> {
        let mut noise = NoiseStream::handshake_responder(stream).await?;
        let hs_hash = noise.handshake_hash().to_vec();
        let peers = self.peers.read().await.clone();
        let ctrl_keys = self.trusted_control_pubkeys.read().await.clone();

        let outcome = server_hello(
            &mut noise,
            &hs_hash,
            remote_addr,
            &self.local_tag,
            &self.keypair,
            listen_policy,
            &peers,
            &ctrl_keys,
            &self.bootstrap_state,
            &self.nonce_cache,
        )
        .await?;

        info!(
            local = %self.local_tag,
            remote = %outcome.remote_node_tag,
            addr = %remote_addr,
            authenticated = outcome.authenticated,
            bootstrap_pending = outcome.bootstrap_pending,
            is_control = outcome.is_control,
            "inbound link established"
        );

        let session = MuxSession::spawn(
            noise,
            yamux::Mode::Server,
            outcome.remote_node_tag.clone(),
            outcome.remote_public_key.clone(),
            Some(remote_addr),
            outcome.authenticated,
            outcome.bootstrap_pending,
            outcome.is_control,
            self.incoming_tx.clone(),
        );

        let active = ActiveSession {
            session,
            authenticated: outcome.authenticated,
            is_control: outcome.is_control,
            remote_public_key: outcome.remote_public_key.clone(),
            endpoint: remote_addr.to_string(),
        };

        if outcome.authenticated {
            if let Some(old) = self
                .inbound_sessions
                .insert(outcome.remote_node_tag.clone(), active)
            {
                old.session.close().await;
            }
        } else if outcome.bootstrap_pending && listen_policy.allow_bootstrap {
            // Strictly isolate unauthenticated bootstrap sessions so they can NEVER overwrite inbound_sessions
            self.bootstrap_sessions.retain(|_, v| !v.session.is_closed());
            if self.bootstrap_sessions.len() >= MAX_BOOTSTRAP_SESSIONS {
                active.session.close().await;
                return Err(ExposureError::Link("bootstrap session pool full".into()));
            }
            if let Some(old) = self
                .bootstrap_sessions
                .insert(outcome.remote_node_tag.clone(), active)
            {
                old.session.close().await;
            }
        } else {
            active.session.close().await;
            return Err(ExposureError::Auth("unauthenticated link rejected".into()));
        }

        Ok(())
    }

    /// Spawn persistent outbound tunnel connectors for all configured outbound tunnel peers.
    pub fn spawn_outbound_tunnels(self: &Arc<Self>) {
        let gen = self.tunnel_gen.fetch_add(1, Ordering::SeqCst) + 1;
        let mgr = Arc::clone(self);
        tokio::spawn(async move {
            let peers = mgr.peers.read().await.clone();
            for peer in peers {
                if peer.mode == LinkMode::Tunnel
                    && peer.tunnel_direction == Some(TunnelDirection::Outbound)
                {
                    for ep in peer.endpoints.clone() {
                        let mgr2 = Arc::clone(&mgr);
                        let peer_clone = peer.clone();
                        tokio::spawn(async move {
                            mgr2.maintain_outbound_tunnel(peer_clone, ep.address, gen)
                                .await;
                        });
                    }
                }
            }
        });
    }

    async fn maintain_outbound_tunnel(
        self: &Arc<Self>,
        peer: PeerConfig,
        addr: String,
        gen: u64,
    ) {
        let mut backoff_ms = 250u64;
        loop {
            if self.tunnel_gen.load(Ordering::SeqCst) != gen {
                return;
            }
            let existing_alive = self
                .outbound_sessions
                .get(&addr)
                .map(|s| s.authenticated && !s.session.is_closed())
                .unwrap_or(false);

            if !existing_alive {
                match self
                    .dial_endpoint(
                        &addr,
                        Some(&peer.node_tag),
                        peer.public_key.as_deref(),
                        peer.pubkey_fingerprint.as_deref(),
                        None,
                        false,
                    )
                    .await
                {
                    Ok((session, outcome)) => {
                        // Re-check generation after async dial so stale tasks never clobber new config
                        if self.tunnel_gen.load(Ordering::SeqCst) != gen {
                            session.close().await;
                            return;
                        }
                        info!(
                            local = %self.local_tag,
                            peer = %peer.node_tag,
                            addr = %addr,
                            "outbound tunnel established"
                        );
                        if let Some(old) = self.outbound_sessions.insert(
                            addr.clone(),
                            ActiveSession {
                                session,
                                authenticated: outcome.authenticated,
                                is_control: false,
                                remote_public_key: outcome.remote_public_key,
                                endpoint: addr.clone(),
                            },
                        ) {
                            old.session.close().await;
                        }
                        let cfg = self.probe_cfg.read().await.clone();
                        self.probe_trackers
                            .entry((peer.peer_tag.clone(), addr.clone()))
                            .or_default()
                            .record_success(0, &cfg);
                        backoff_ms = 250;
                    }
                    Err(e) => {
                        warn!(peer = %peer.node_tag, addr = %addr, error = %e, "outbound tunnel dial failed");
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        backoff_ms = (backoff_ms * 2).min(10_000);
                        continue;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Spawn background concurrent active probing loop updating UP / DEGRADED / DOWN states
    /// and reaping closed sessions.
    pub fn spawn_probe_loop(self: &Arc<Self>) {
        let mgr = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                // Reap dead sessions to prevent unbounded DashMap growth
                mgr.inbound_sessions.retain(|_, v| !v.session.is_closed());
                mgr.outbound_sessions.retain(|_, v| !v.session.is_closed());
                mgr.bootstrap_sessions.retain(|_, v| !v.session.is_closed());

                let cfg = mgr.probe_cfg.read().await.clone();
                let peers = mgr.peers.read().await.clone();

                let mut tasks = FuturesUnordered::new();

                for peer in peers {
                    if is_inbound_tunnel(&peer) {
                        let mgr2 = Arc::clone(&mgr);
                        let cfg2 = cfg.clone();
                        tasks.push(tokio::spawn(async move {
                            let sess_opt = mgr2
                                .inbound_sessions
                                .get(&peer.node_tag)
                                .filter(|s| s.authenticated && !s.session.is_closed())
                                .map(|s| s.session.clone());
                            let res = match sess_opt {
                                Some(session) => session.probe_rtt_ms(cfg2.timeout_ms).await,
                                None => Err(ExposureError::Link("inbound tunnel disconnected".into())),
                            };
                            let mut tr = mgr2
                                .probe_trackers
                                .entry((peer.peer_tag.clone(), INBOUND_TUNNEL_TRACKER_KEY.to_string()))
                                .or_default();
                            match res {
                                Ok(rtt) => tr.record_success(rtt, &cfg2),
                                Err(_) => tr.record_failure(&cfg2),
                            }
                        }));
                        continue;
                    }

                    for ep in peer.endpoints.clone() {
                        let mgr2 = Arc::clone(&mgr);
                        let cfg2 = cfg.clone();
                        let peer_tag = peer.peer_tag.clone();
                        let mode = peer.mode;
                        tasks.push(tokio::spawn(async move {
                            let maybe_sess = mgr2
                                .outbound_sessions
                                .get(&ep.address)
                                .filter(|s| s.authenticated && !s.session.is_closed())
                                .map(|s| s.session.clone());

                            let res = if let Some(sess) = maybe_sess {
                                sess.probe_rtt_ms(cfg2.timeout_ms).await
                            } else if mode == LinkMode::OnDemand {
                                // Only probe idle on-demand links via lightweight TCP connect
                                let start = std::time::Instant::now();
                                match tokio::time::timeout(
                                    Duration::from_millis(cfg2.timeout_ms),
                                    mgr2.transport.connect(&ep.address),
                                )
                                .await
                                {
                                    Ok(Ok(_)) => Ok(start.elapsed().as_millis() as u64),
                                    _ => Err(ExposureError::Link("on-demand probe failed".into())),
                                }
                            } else {
                                Err(ExposureError::Link("tunnel disconnected".into()))
                            };

                            let mut tr = mgr2
                                .probe_trackers
                                .entry((peer_tag, ep.address))
                                .or_default();
                            match res {
                                Ok(rtt) => tr.record_success(rtt, &cfg2),
                                Err(_) => tr.record_failure(&cfg2),
                            }
                        }));
                    }
                }

                while tasks.next().await.is_some() {}
                tokio::time::sleep(Duration::from_millis(cfg.interval_ms.max(200))).await;
            }
        });
    }

    /// Dial a specific address with channel-bound Noise + Ed25519 Hello and return a live MuxSession.
    pub async fn dial_endpoint(
        &self,
        addr: &str,
        expected_node_tag: Option<&str>,
        expected_pubkey: Option<&str>,
        expected_fp: Option<&str>,
        bootstrap_proof: Option<(Vec<u8>, String)>,
        allow_unauthenticated: bool,
    ) -> Result<(MuxSession, HandshakeOutcome)> {
        let fut = async {
            let raw = self.transport.connect(addr).await?;
            let mut noise = NoiseStream::handshake_initiator(raw).await?;
            let hs_hash = noise.handshake_hash().to_vec();
            let outcome = client_hello(
                &mut noise,
                &hs_hash,
                &self.local_tag,
                &self.keypair,
                self.is_control,
                bootstrap_proof,
                expected_node_tag,
                expected_pubkey,
                expected_fp,
                allow_unauthenticated,
            )
            .await?;

            let session = MuxSession::spawn(
                noise,
                yamux::Mode::Client,
                outcome.remote_node_tag.clone(),
                outcome.remote_public_key.clone(),
                None,
                outcome.authenticated,
                outcome.bootstrap_pending,
                false,
                self.incoming_tx.clone(),
            );
            Ok((session, outcome))
        };
        tokio::time::timeout(HANDSHAKE_TIMEOUT, fut)
            .await
            .map_err(|_| ExposureError::Link(format!("dial {addr} handshake timed out")))?
    }

    /// Register an already-dialed outbound session for a target address/node (used by Control bootstrap).
    pub async fn register_outbound_session(
        &self,
        addr: String,
        node_tag: String,
        remote_public_key: String,
        session: MuxSession,
        authenticated: bool,
    ) {
        let active = ActiveSession {
            session: session.clone(),
            authenticated,
            is_control: false,
            remote_public_key: remote_public_key.clone(),
            endpoint: addr.clone(),
        };
        if authenticated {
            if let Some(old) = self.outbound_sessions.insert(addr.clone(), active.clone()) {
                old.session.close().await;
            }
            if let Some(old) = self.inbound_sessions.insert(node_tag, active) {
                old.session.close().await;
            }
        } else {
            if let Some(old) = self.bootstrap_sessions.insert(node_tag, active) {
                old.session.close().await;
            }
        }
    }

    /// Open a stream to a Peer Tag (used by the Forwarding Layer for service traffic).
    /// Applies priority, weight, weight-0 backup, live probe health states, and automatic multi-endpoint failover.
    pub async fn open_stream_to_peer(
        &self,
        peer_tag: &str,
        kind: StreamKind,
    ) -> Result<MuxStream> {
        let peers = self.peers.read().await.clone();
        // Prioritize exact peer_tag match before falling back to node_tag match
        let peer = peers
            .iter()
            .find(|p| p.peer_tag == peer_tag)
            .or_else(|| peers.iter().find(|p| p.node_tag == peer_tag))
            .cloned()
            .ok_or_else(|| ExposureError::Routing(format!("unknown peer_tag: {peer_tag}")))?;

        if is_inbound_tunnel(&peer) {
            if let Some(entry) = self.inbound_sessions.get(&peer.node_tag) {
                if !entry.session.is_closed() {
                    if !entry.authenticated {
                        return Err(ExposureError::Auth(format!(
                            "inbound tunnel {} is not authenticated",
                            peer.node_tag
                        )));
                    }
                    let sess = entry.session.clone();
                    drop(entry);
                    return sess.open_stream(kind).await;
                }
            }
            return Err(ExposureError::Link(format!(
                "no active inbound tunnel from peer {}",
                peer.node_tag
            )));
        }

        if peer.endpoints.is_empty() {
            return Err(ExposureError::Link(format!(
                "peer {} has no configured endpoints",
                peer.peer_tag
            )));
        }

        // Build health map for this peer's endpoints
        let mut health_map = HashMap::new();
        for ep in &peer.endpoints {
            let st = self
                .probe_trackers
                .get(&(peer.peer_tag.clone(), ep.address.clone()))
                .map(|t| t.state)
                .unwrap_or(LinkHealthState::Up);
            health_map.insert(ep.address.clone(), st);
        }

        let ticket = self.rr_ticket.fetch_add(1, Ordering::Relaxed);
        let mut ordered_addrs: Vec<String> = Vec::with_capacity(peer.endpoints.len());
        if let Some(primary) = select_endpoint(&peer.endpoints, &health_map, ticket) {
            ordered_addrs.push(primary.address.clone());
        }
        let mut remaining = peer.endpoints.clone();
        remaining.sort_by_key(|e| (e.weight == 0, e.priority));
        for ep in remaining {
            if !ordered_addrs.contains(&ep.address) {
                ordered_addrs.push(ep.address);
            }
        }

        let mut last_err = None;
        for addr in ordered_addrs {
            match self.open_stream_to_endpoint(&peer, &addr, kind).await {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    let cfg = self.probe_cfg.read().await.clone();
                    self.probe_trackers
                        .entry((peer.peer_tag.clone(), addr))
                        .or_default()
                        .record_failure(&cfg);
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            ExposureError::Link(format!("all endpoints failed for peer {}", peer.peer_tag))
        }))
    }

    async fn open_stream_to_endpoint(
        &self,
        peer: &PeerConfig,
        addr: &str,
        kind: StreamKind,
    ) -> Result<MuxStream> {
        if let Some(entry) = self.outbound_sessions.get(addr) {
            if entry.authenticated && !entry.session.is_closed() {
                let sess = entry.session.clone();
                drop(entry);
                if let Ok(stream) = sess.open_stream(kind).await {
                    return Ok(stream);
                }
            }
        }

        // Singleflight per-endpoint lock to avoid thundering-herd parallel dials
        let lock = self
            .dial_locks
            .entry(addr.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _guard = lock.lock().await;

        // Re-check after acquiring lock
        if let Some(entry) = self.outbound_sessions.get(addr) {
            if entry.authenticated && !entry.session.is_closed() {
                let sess = entry.session.clone();
                drop(entry);
                if let Ok(stream) = sess.open_stream(kind).await {
                    return Ok(stream);
                }
            }
        }

        let (session, outcome) = self
            .dial_endpoint(
                addr,
                Some(&peer.node_tag),
                peer.public_key.as_deref(),
                peer.pubkey_fingerprint.as_deref(),
                None,
                false,
            )
            .await?;

        if let Some(old) = self.outbound_sessions.insert(
            addr.to_string(),
            ActiveSession {
                session: session.clone(),
                authenticated: outcome.authenticated,
                is_control: false,
                remote_public_key: outcome.remote_public_key,
                endpoint: addr.to_string(),
            },
        ) {
            old.session.close().await;
        }
        session.open_stream(kind).await
    }

    /// Open a stream to a target `node_tag` (used for Hop Table routing, including Control replies).
    pub async fn open_stream_to_node(
        &self,
        node_tag: &str,
        kind: StreamKind,
    ) -> Result<MuxStream> {
        // Check authenticated inbound/registered sessions first
        if let Some(entry) = self.inbound_sessions.get(node_tag) {
            if entry.authenticated && !entry.session.is_closed() {
                let sess = entry.session.clone();
                drop(entry);
                if let Ok(stream) = sess.open_stream(kind).await {
                    return Ok(stream);
                }
            }
        }
        // Only Bootstrap streams may use the isolated unauthenticated bootstrap session pool
        if kind == StreamKind::Bootstrap {
            if let Some(entry) = self.bootstrap_sessions.get(node_tag) {
                if !entry.session.is_closed() {
                    let sess = entry.session.clone();
                    drop(entry);
                    if let Ok(stream) = sess.open_stream(StreamKind::Bootstrap).await {
                        return Ok(stream);
                    }
                }
            }
        }
        self.open_stream_to_peer(node_tag, kind).await
    }

    /// Returns true if an active authenticated session exists directly for `node_tag` (even when `peers` is empty, e.g. Control).
    pub fn has_active_session_for_node(&self, node_tag: &str) -> bool {
        self.inbound_sessions
            .get(node_tag)
            .map(|s| s.authenticated && !s.session.is_closed())
            .unwrap_or(false)
    }

    /// Returns true if an active authenticated outbound or inbound session exists for `peer_tag`.
    pub async fn has_connected_peer(&self, peer_tag: &str) -> bool {
        if self.has_active_session_for_node(peer_tag) {
            return true;
        }
        let peers = self.peers.read().await.clone();
        for peer in peers
            .into_iter()
            .filter(|p| p.peer_tag == peer_tag || p.node_tag == peer_tag)
        {
            if let Some(sess) = self.inbound_sessions.get(&peer.node_tag) {
                if sess.authenticated && !sess.session.is_closed() {
                    return true;
                }
            }
            for ep in &peer.endpoints {
                if let Some(sess) = self.outbound_sessions.get(&ep.address) {
                    if sess.authenticated && !sess.session.is_closed() {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Returns true if any active authenticated inbound or outbound link session exists.
    pub fn has_any_connected_session(&self) -> bool {
        self.inbound_sessions
            .iter()
            .any(|s| s.authenticated && !s.session.is_closed())
            || self
                .outbound_sessions
                .iter()
                .any(|s| s.authenticated && !s.session.is_closed())
    }

    pub async fn link_snapshots(&self) -> Vec<LinkStatusSnapshot> {
        let peers = self.peers.read().await.clone();
        let mut out = Vec::new();
        for peer in peers {
            if is_inbound_tunnel(&peer) {
                let (state, ep, rtt, loss) = if let Some(sess) =
                    self.inbound_sessions.get(&peer.node_tag)
                {
                    let ep = sess.endpoint.clone();
                    let alive = sess.authenticated && !sess.session.is_closed();
                    let tr = self
                        .probe_trackers
                        .get(&(peer.peer_tag.clone(), INBOUND_TUNNEL_TRACKER_KEY.to_string()))
                        .map(|t| (t.state, t.last_rtt_ms, t.loss_rate()));
                    match tr {
                        Some((st, r, l)) => {
                            (if alive { st } else { LinkHealthState::Down }, ep, r, l)
                        }
                        None => (
                            if alive {
                                LinkHealthState::Up
                            } else {
                                LinkHealthState::Down
                            },
                            ep,
                            None,
                            0.0,
                        ),
                    }
                } else {
                    (
                        LinkHealthState::Down,
                        INBOUND_TUNNEL_TRACKER_KEY.into(),
                        None,
                        1.0,
                    )
                };
                out.push(LinkStatusSnapshot {
                    node_tag: self.local_tag.clone(),
                    peer_tag: peer.peer_tag,
                    endpoint: ep,
                    state,
                    rtt_ms: rtt,
                    loss_rate: loss,
                });
            } else {
                for ep in peer.endpoints {
                    let tr = self
                        .probe_trackers
                        .get(&(peer.peer_tag.clone(), ep.address.clone()))
                        .map(|t| (t.state, t.last_rtt_ms, t.loss_rate()));
                    let (state, rtt_ms, loss_rate) =
                        tr.unwrap_or((LinkHealthState::Up, None, 0.0));
                    out.push(LinkStatusSnapshot {
                        node_tag: self.local_tag.clone(),
                        peer_tag: peer.peer_tag.clone(),
                        endpoint: ep.address,
                        state,
                        rtt_ms,
                        loss_rate,
                    });
                }
            }
        }
        out
    }
}
