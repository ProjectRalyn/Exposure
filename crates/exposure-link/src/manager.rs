use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use exposure_core::config::{LinkListenConfig, LinkMode, PeerConfig, ProbeConfig, TunnelDirection};
use exposure_core::crypto::NodeKeyPair;
use exposure_core::protocol::StreamKind;
use exposure_core::routing::{select_endpoint, LinkHealthState};
use exposure_core::telemetry::LinkStatusSnapshot;
use exposure_core::{ExposureError, Result};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use crate::handshake::{client_hello, server_hello, HandshakeOutcome};
use crate::mux::{IncomingMuxStream, MuxSession, MuxStream};
use crate::noise::NoiseStream;
use crate::probe::EndpointProbeTracker;
use crate::transport::{TcpTransport, Transport};

#[derive(Clone)]
struct ActiveSession {
    session: MuxSession,
    authenticated: bool,
    endpoint: String,
}

/// Link layer manager (DESIGN.md §6):
/// Owns transport, Noise+Ed25519 handshakes, Yamux sessions, active probes, and tunnel/on-demand lifecycles.
/// Completely decoupled from L7 parsing, Service Tag routing tables, and Control plane logic.
pub struct LinkManager {
    local_tag: String,
    is_control: bool,
    keypair: NodeKeyPair,
    transport: Arc<dyn Transport>,
    peers: Arc<RwLock<Vec<PeerConfig>>>,
    trusted_control_pubkeys: Arc<RwLock<Vec<String>>>,
    bootstrap_passphrase: Arc<RwLock<Option<String>>>,
    probe_cfg: Arc<RwLock<ProbeConfig>>,
    /// Keyed by endpoint address (for outbound sessions).
    outbound_sessions: Arc<DashMap<String, ActiveSession>>,
    /// Keyed by remote `node_tag` (for inbound tunnel / control / on-demand sessions).
    inbound_sessions: Arc<DashMap<String, ActiveSession>>,
    /// Keyed by `(peer_tag, endpoint_address)`.
    probe_trackers: Arc<DashMap<(String, String), EndpointProbeTracker>>,
    incoming_tx: mpsc::Sender<IncomingMuxStream>,
    incoming_rx: Arc<tokio::sync::Mutex<Option<mpsc::Receiver<IncomingMuxStream>>>>,
    rr_ticket: AtomicU64,
    /// Generation counter to stop old outbound tunnel tasks on reload.
    tunnel_gen: Arc<AtomicU64>,
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
            bootstrap_passphrase: Arc::new(RwLock::new(None)),
            probe_cfg: Arc::new(RwLock::new(probe_cfg)),
            outbound_sessions: Arc::new(DashMap::new()),
            inbound_sessions: Arc::new(DashMap::new()),
            probe_trackers: Arc::new(DashMap::new()),
            incoming_tx,
            incoming_rx: Arc::new(tokio::sync::Mutex::new(Some(incoming_rx))),
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
        *self.trusted_control_pubkeys.write().await = keys;
    }

    pub async fn set_bootstrap_passphrase(&self, pass: Option<String>) {
        *self.bootstrap_passphrase.write().await = pass;
    }

    pub async fn peers_snapshot(&self) -> Vec<PeerConfig> {
        self.peers.read().await.clone()
    }

    pub async fn update_peers(self: &Arc<Self>, peers: Vec<PeerConfig>, probe_cfg: ProbeConfig) {
        *self.peers.write().await = peers;
        *self.probe_cfg.write().await = probe_cfg;
        self.spawn_outbound_tunnels();
    }

    /// Start listening for inbound on-demand and tunnel connections.
    pub async fn start_listener(self: &Arc<Self>, cfg: LinkListenConfig) -> Result<SocketAddr> {
        let listener = self.transport.bind(&cfg.listen_addr).await?;
        let bound = listener.local_addr()?;
        info!(node = %self.local_tag, addr = %bound, "link listener started");

        let mgr = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, remote_addr)) => {
                        let mgr2 = Arc::clone(&mgr);
                        tokio::spawn(async move {
                            if let Err(e) = mgr2.handle_inbound_connection(stream, remote_addr).await
                            {
                                debug!(remote = %remote_addr, error = %e, "inbound link handshake ended");
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
    ) -> Result<()> {
        let mut noise = NoiseStream::handshake_responder(stream).await?;
        let peers = self.peers.read().await.clone();
        let ctrl_keys = self.trusted_control_pubkeys.read().await.clone();
        let pass = self.bootstrap_passphrase.read().await.clone();

        let outcome = server_hello(
            &mut noise,
            remote_addr,
            &self.local_tag,
            &self.keypair,
            &peers,
            &ctrl_keys,
            pass.as_deref(),
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

        self.inbound_sessions.insert(
            outcome.remote_node_tag.clone(),
            ActiveSession {
                session,
                authenticated: outcome.authenticated,
                endpoint: remote_addr.to_string(),
            },
        );
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
                            mgr2.maintain_outbound_tunnel(peer_clone, ep.address, gen).await;
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
                .map(|s| !s.session.is_closed())
                .unwrap_or(false);

            if !existing_alive {
                match self
                    .dial_endpoint(
                        &addr,
                        peer.public_key.as_deref(),
                        peer.pubkey_fingerprint.as_deref(),
                        None,
                    )
                    .await
                {
                    Ok((session, outcome)) => {
                        info!(
                            local = %self.local_tag,
                            peer = %peer.node_tag,
                            addr = %addr,
                            "outbound tunnel established"
                        );
                        self.outbound_sessions.insert(
                            addr.clone(),
                            ActiveSession {
                                session,
                                authenticated: outcome.authenticated,
                                endpoint: addr.clone(),
                            },
                        );
                        backoff_ms = 250;
                    }
                    Err(e) => {
                        warn!(peer = %peer.node_tag, addr = %addr, error = %e, "outbound tunnel dial failed");
                        let cfg = self.probe_cfg.read().await.clone();
                        self.probe_trackers
                            .entry((peer.peer_tag.clone(), addr.clone()))
                            .or_default()
                            .record_failure(&cfg);
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        backoff_ms = (backoff_ms * 2).min(10_000);
                        continue;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Spawn background active probing loop updating UP / DEGRADED / DOWN states.
    pub fn spawn_probe_loop(self: &Arc<Self>) {
        let mgr = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                let cfg = mgr.probe_cfg.read().await.clone();
                let peers = mgr.peers.read().await.clone();

                for peer in peers {
                    if peer.mode == LinkMode::Tunnel
                        && peer.tunnel_direction == Some(TunnelDirection::Inbound)
                    {
                        if let Some(sess) = mgr.inbound_sessions.get(&peer.node_tag) {
                            let ep = sess.endpoint.clone();
                            let session = sess.session.clone();
                            drop(sess);
                            let res = session.probe_rtt_ms(cfg.timeout_ms).await;
                            let mut tr = mgr
                                .probe_trackers
                                .entry((peer.peer_tag.clone(), ep))
                                .or_default();
                            match res {
                                Ok(rtt) => tr.record_success(rtt, &cfg),
                                Err(_) => tr.record_failure(&cfg),
                            }
                        }
                        continue;
                    }

                    for ep in &peer.endpoints {
                        let maybe_sess = mgr
                            .outbound_sessions
                            .get(&ep.address)
                            .filter(|s| !s.session.is_closed())
                            .map(|s| s.session.clone());

                        let res = if let Some(sess) = maybe_sess {
                            sess.probe_rtt_ms(cfg.timeout_ms).await
                        } else if peer.mode == LinkMode::OnDemand {
                            // Lightweight TCP connect probe for idle on-demand links
                            let start = std::time::Instant::now();
                            match tokio::time::timeout(
                                Duration::from_millis(cfg.timeout_ms),
                                mgr.transport.connect(&ep.address),
                            )
                            .await
                            {
                                Ok(Ok(_)) => Ok(start.elapsed().as_millis() as u64),
                                _ => Err(ExposureError::Link("on-demand probe failed".into())),
                            }
                        } else {
                            Err(ExposureError::Link("tunnel disconnected".into()))
                        };

                        let mut tr = mgr
                            .probe_trackers
                            .entry((peer.peer_tag.clone(), ep.address.clone()))
                            .or_default();
                        match res {
                            Ok(rtt) => tr.record_success(rtt, &cfg),
                            Err(_) => tr.record_failure(&cfg),
                        }
                    }
                }

                tokio::time::sleep(Duration::from_millis(cfg.interval_ms.max(200))).await;
            }
        });
    }

    /// Dial a specific address with Noise + Ed25519 Hello and return a live MuxSession.
    pub async fn dial_endpoint(
        &self,
        addr: &str,
        expected_pubkey: Option<&str>,
        expected_fp: Option<&str>,
        bootstrap_proof: Option<(Vec<u8>, String)>,
    ) -> Result<(MuxSession, HandshakeOutcome)> {
        let raw = self.transport.connect(addr).await?;
        let mut noise = NoiseStream::handshake_initiator(raw).await?;
        let outcome = client_hello(
            &mut noise,
            &self.local_tag,
            &self.keypair,
            self.is_control,
            bootstrap_proof,
            expected_pubkey,
            expected_fp,
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
    }

    /// Register an already-dialed outbound session for a target address/node (used by Control bootstrap).
    pub fn register_outbound_session(
        &self,
        addr: String,
        node_tag: String,
        session: MuxSession,
        authenticated: bool,
    ) {
        self.outbound_sessions.insert(
            addr.clone(),
            ActiveSession {
                session: session.clone(),
                authenticated,
                endpoint: addr.clone(),
            },
        );
        self.inbound_sessions.insert(
            node_tag,
            ActiveSession {
                session,
                authenticated,
                endpoint: addr,
            },
        );
    }

    /// Open a stream to a Peer Tag (used by the Forwarding Layer for service traffic).
    /// Applies priority, weight, weight-0 backup, and live probe health states.
    pub async fn open_stream_to_peer(
        &self,
        peer_tag: &str,
        kind: StreamKind,
    ) -> Result<MuxStream> {
        let peers = self.peers.read().await.clone();
        let peer = peers
            .iter()
            .find(|p| p.peer_tag == peer_tag || p.node_tag == peer_tag)
            .cloned()
            .ok_or_else(|| ExposureError::Routing(format!("unknown peer_tag: {peer_tag}")))?;

        // Inbound tunnel peer: use the active inbound session initiated by that peer.
        if peer.mode == LinkMode::Tunnel && peer.tunnel_direction == Some(TunnelDirection::Inbound)
        {
            if let Some(entry) = self.inbound_sessions.get(&peer.node_tag) {
                if !entry.session.is_closed() {
                    if kind == StreamKind::Service && !entry.authenticated {
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
        let selected = select_endpoint(&peer.endpoints, &health_map, ticket)
            .or_else(|| peer.endpoints.first())
            .ok_or_else(|| {
                ExposureError::Link(format!("peer {} has no configured endpoints", peer.peer_tag))
            })?;

        self.open_stream_to_endpoint(&peer, &selected.address, kind)
            .await
    }

    async fn open_stream_to_endpoint(
        &self,
        peer: &PeerConfig,
        addr: &str,
        kind: StreamKind,
    ) -> Result<MuxStream> {
        if let Some(entry) = self.outbound_sessions.get(addr) {
            if !entry.session.is_closed() {
                let sess = entry.session.clone();
                drop(entry);
                if let Ok(stream) = sess.open_stream(kind).await {
                    return Ok(stream);
                }
            }
        }

        // Lazy dial for on-demand (or reconnect attempt for outbound tunnel)
        let (session, outcome) = self
            .dial_endpoint(
                addr,
                peer.public_key.as_deref(),
                peer.pubkey_fingerprint.as_deref(),
                None,
            )
            .await?;

        self.outbound_sessions.insert(
            addr.to_string(),
            ActiveSession {
                session: session.clone(),
                authenticated: outcome.authenticated,
                endpoint: addr.to_string(),
            },
        );
        session.open_stream(kind).await
    }

    /// Open a stream to a target `node_tag` (used for Hop Table routing, including Control replies!).
    pub async fn open_stream_to_node(
        &self,
        node_tag: &str,
        kind: StreamKind,
    ) -> Result<MuxStream> {
        // First check active inbound sessions (covers inbound tunnels AND Control client connections!)
        if let Some(entry) = self.inbound_sessions.get(node_tag) {
            if !entry.session.is_closed() {
                let sess = entry.session.clone();
                drop(entry);
                if let Ok(stream) = sess.open_stream(kind).await {
                    return Ok(stream);
                }
            }
        }
        // Fallback to peer list lookup by node_tag
        self.open_stream_to_peer(node_tag, kind).await
    }

    /// Returns true if an active (non-closed) outbound or inbound session exists for `peer_tag`.
    pub async fn has_connected_peer(&self, peer_tag: &str) -> bool {
        let peers = self.peers.read().await.clone();
        for peer in peers.into_iter().filter(|p| p.peer_tag == peer_tag || p.node_tag == peer_tag) {
            if let Some(sess) = self.inbound_sessions.get(&peer.node_tag) {
                if !sess.session.is_closed() {
                    return true;
                }
            }
            for ep in &peer.endpoints {
                if let Some(sess) = self.outbound_sessions.get(&ep.address) {
                    if !sess.session.is_closed() {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Returns true if any active (non-closed) inbound or outbound link session exists.
    pub fn has_any_connected_session(&self) -> bool {
        self.inbound_sessions.iter().any(|s| !s.session.is_closed())
            || self.outbound_sessions.iter().any(|s| !s.session.is_closed())
    }

    pub async fn link_snapshots(&self) -> Vec<LinkStatusSnapshot> {
        let peers = self.peers.read().await.clone();
        let mut out = Vec::new();
        for peer in peers {
            if peer.endpoints.is_empty() {
                let (state, ep, rtt, loss) = if let Some(sess) =
                    self.inbound_sessions.get(&peer.node_tag)
                {
                    let ep = sess.endpoint.clone();
                    let alive = !sess.session.is_closed();
                    let tr = self
                        .probe_trackers
                        .get(&(peer.peer_tag.clone(), ep.clone()))
                        .map(|t| (t.state, t.last_rtt_ms, t.loss_rate()));
                    match tr {
                        Some((st, r, l)) => (if alive { st } else { LinkHealthState::Down }, ep, r, l),
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
                    (LinkHealthState::Down, "inbound-tunnel".into(), None, 1.0)
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
                    let (state, rtt_ms, loss_rate) = tr.unwrap_or((LinkHealthState::Up, None, 0.0));
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
