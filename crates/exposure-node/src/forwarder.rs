use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use exposure_core::config::{NodeRoles, RelayConfig};
use exposure_core::protocol::{
    read_json_frame, read_json_frame_bounded, write_json_frame, ServiceStreamHeader, SpecialFrame,
    SpecialPayload, StreamKind, MAX_HEADER_FRAME_BYTES, MAX_TTL,
};
use exposure_core::{ExposureError, Result};
use exposure_link::{IncomingMuxStream, LinkManager};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot, RwLock};
use tracing::{debug, warn};

use crate::egress::EgressHandler;
use crate::logger::NodeLogger;

const FRAME_READ_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BOOTSTRAP_FRAME_BYTES: usize = 64 * 1024;
const RELAY_COPY_TIMEOUT: Duration = Duration::from_secs(3600);

pub trait ServiceIo: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> ServiceIo for T {}
pub type BoxedServiceIo = Pin<Box<dyn ServiceIo>>;

/// Incoming `SpecialFrame` paired with verified link-layer authentication metadata.
#[derive(Debug, Clone)]
pub struct IncomingSpecialFrame {
    pub frame: SpecialFrame,
    pub authenticated: bool,
    pub is_control: bool,
    pub remote_node_tag: String,
    pub remote_public_key: String,
    pub stream_kind: StreamKind,
}

/// Decoupled Forwarding Layer (DESIGN.md §6.4 & §7):
/// - Routes normal service frames by `ServiceTag` (local egress OR remote Peer Tag via LinkManager)
/// - Enforces authentication, hop validation, and loop prevention on all `Service` and `Special` streams
/// - Routes special data frames by explicit `Hop Table` (`Node Tag` sequence) with TTL & cycle protection
pub struct Forwarder {
    node_tag: String,
    roles: Arc<RwLock<NodeRoles>>,
    relay_cfg: Arc<RwLock<RelayConfig>>,
    link_manager: Arc<LinkManager>,
    egress: Arc<EgressHandler>,
    logger: Arc<NodeLogger>,
    special_tx: mpsc::Sender<IncomingSpecialFrame>,
    pending_replies: Arc<DashMap<String, oneshot::Sender<SpecialFrame>>>,
}

impl Forwarder {
    pub fn new(
        node_tag: impl Into<String>,
        roles: NodeRoles,
        relay_cfg: RelayConfig,
        link_manager: Arc<LinkManager>,
        egress: Arc<EgressHandler>,
        logger: Arc<NodeLogger>,
    ) -> (Arc<Self>, mpsc::Receiver<IncomingSpecialFrame>) {
        let (special_tx, special_rx) = mpsc::channel(256);
        let fwd = Arc::new(Self {
            node_tag: node_tag.into(),
            roles: Arc::new(RwLock::new(roles)),
            relay_cfg: Arc::new(RwLock::new(relay_cfg)),
            link_manager,
            egress,
            logger,
            special_tx,
            pending_replies: Arc::new(DashMap::new()),
        });
        (fwd, special_rx)
    }

    pub async fn update_config(&self, roles: NodeRoles, relay_cfg: RelayConfig) {
        *self.roles.write().await = roles;
        *self.relay_cfg.write().await = relay_cfg;
    }

    /// Open a service stream to `next_peer`.
    /// If `next_peer` equals this node's own `node_tag` (or `"local"`), dispatches directly into
    /// local `EgressHandler` via an in-memory duplex pipe using the exact same ServiceTag + ACL path.
    pub async fn open_service_stream(
        &self,
        next_peer: &str,
        header: ServiceStreamHeader,
    ) -> Result<BoxedServiceIo> {
        if next_peer == self.node_tag || next_peer.eq_ignore_ascii_case("local") {
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let egress = Arc::clone(&self.egress);
            let self_tag = self.node_tag.clone();
            tokio::spawn(async move {
                if let Err(e) = egress.handle_stream(header, Some(self_tag), server_io).await {
                    debug!(error = %e, "local egress service stream ended");
                }
            });
            return Ok(Box::pin(client_io));
        }

        let mut stream = self
            .link_manager
            .open_stream_to_peer(next_peer, StreamKind::Service)
            .await?;
        write_json_frame(&mut stream, &header).await?;
        Ok(Box::pin(stream))
    }

    /// Send a `SpecialFrame` along its Hop Table using `StreamKind::Special` (authenticated links only).
    pub async fn send_special(&self, frame: SpecialFrame) -> Result<()> {
        self.send_special_with_kind(frame, StreamKind::Special).await
    }

    /// Send a bootstrap frame (`BootstrapForward` / `BootstrapReply`) using `StreamKind::Bootstrap`.
    pub async fn send_bootstrap(&self, frame: SpecialFrame) -> Result<()> {
        self.send_special_with_kind(frame, StreamKind::Bootstrap).await
    }

    async fn send_special_with_kind(&self, mut frame: SpecialFrame, kind: StreamKind) -> Result<()> {
        frame.validate_hops()?;
        if frame.is_final_hop(&self.node_tag) {
            // Locally-originated request terminating here: enqueue as an *incoming request*
            // (never match our own pending RPC waiter, whose id equals this request's id).
            self.deliver_local_special(
                IncomingSpecialFrame {
                    frame,
                    authenticated: true,
                    is_control: false,
                    remote_node_tag: self.node_tag.clone(),
                    remote_public_key: self.link_manager.keypair().public_key_b64(),
                    stream_kind: kind,
                },
                false,
            )
            .await;
            return Ok(());
        }

        if frame.current_target() == Some(self.node_tag.as_str()) {
            frame.advance()?;
        }

        let next_node = frame
            .current_target()
            .ok_or_else(|| ExposureError::Routing("special frame has no next hop".into()))?
            .to_string();

        let mut stream = self
            .link_manager
            .open_stream_to_node(&next_node, kind)
            .await?;
        write_json_frame(&mut stream, &frame).await?;
        Ok(())
    }

    /// Send a `SpecialFrame` and wait for a symmetric reversed-hop reply matching `frame.id`.
    pub async fn send_special_rpc(
        &self,
        frame: SpecialFrame,
        timeout: Duration,
    ) -> Result<SpecialFrame> {
        self.send_rpc_with_kind(frame, StreamKind::Special, timeout)
            .await
    }

    /// Send a `BootstrapForward` frame over `StreamKind::Bootstrap` and await `BootstrapReply`.
    pub async fn send_bootstrap_rpc(
        &self,
        frame: SpecialFrame,
        timeout: Duration,
    ) -> Result<SpecialFrame> {
        self.send_rpc_with_kind(frame, StreamKind::Bootstrap, timeout)
            .await
    }

    async fn send_rpc_with_kind(
        &self,
        frame: SpecialFrame,
        kind: StreamKind,
        timeout: Duration,
    ) -> Result<SpecialFrame> {
        let id = frame.id.clone();
        let (tx, rx) = oneshot::channel();
        self.pending_replies.insert(id.clone(), tx);

        if let Err(e) = self.send_special_with_kind(frame, kind).await {
            self.pending_replies.remove(&id);
            return Err(e);
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(_)) => Err(ExposureError::Link("special RPC waiter cancelled".into())),
            Err(_) => {
                self.pending_replies.remove(&id);
                Err(ExposureError::Link(format!(
                    "special RPC {id} timed out after {:?}",
                    timeout
                )))
            }
        }
    }

    /// Deliver a locally-terminated special frame.
    ///
    /// `match_pending` must be `false` for frames **originated by this node** (e.g. a request whose
    /// final hop is this node). Otherwise the request id collides with our own pending RPC waiter
    /// (replies reuse the request id) and the waiter would receive the request as its "reply".
    async fn deliver_local_special(&self, incoming: IncomingSpecialFrame, match_pending: bool) {
        if match_pending {
            if let Some((_, waiter)) = self.pending_replies.remove(&incoming.frame.id) {
                let _ = waiter.send(incoming.frame);
                return;
            }
        }
        if let Err(e) = self.special_tx.send(incoming).await {
            warn!(error = %e, "dropped incoming special frame (local receiver closed)");
        }
    }

    /// Dispatch an incoming multiplexed stream from `LinkManager`.
    pub async fn handle_incoming_stream(self: &Arc<Self>, incoming: IncomingMuxStream) {
        match incoming.kind {
            StreamKind::Service => {
                if !incoming.authenticated {
                    warn!(
                        remote = %incoming.remote_node_tag,
                        "rejected service stream on unauthenticated link"
                    );
                    return;
                }
                let roles = self.roles.read().await.clone();
                if roles.maintainer && !roles.egress && !roles.relay {
                    warn!(
                        node = %self.node_tag,
                        "maintainer node rejected user service stream"
                    );
                    return;
                }
                let fwd = Arc::clone(self);
                let remote_tag = incoming.remote_node_tag;
                tokio::spawn(async move {
                    if let Err(e) = fwd
                        .process_service_stream(remote_tag, incoming.stream)
                        .await
                    {
                        debug!(error = %e, "service stream ended");
                    }
                });
            }
            StreamKind::Special => {
                if !incoming.authenticated {
                    warn!(
                        remote = %incoming.remote_node_tag,
                        "rejected special stream on unauthenticated link"
                    );
                    return;
                }
                let fwd = Arc::clone(self);
                tokio::spawn(async move {
                    if let Err(e) = fwd.process_special_stream(incoming).await {
                        warn!(error = %e, "special frame processing failed");
                    }
                });
            }
            StreamKind::Bootstrap => {
                let fwd = Arc::clone(self);
                tokio::spawn(async move {
                    if let Err(e) = fwd.process_bootstrap_stream(incoming).await {
                        warn!(error = %e, "bootstrap stream processing failed");
                    }
                });
            }
            StreamKind::Probe => {}
        }
    }

    async fn process_service_stream(
        &self,
        remote_node_tag: String,
        mut stream: exposure_link::MuxStream,
    ) -> Result<()> {
        let mut header: ServiceStreamHeader = tokio::time::timeout(
            FRAME_READ_TIMEOUT,
            read_json_frame_bounded(&mut stream, MAX_HEADER_FRAME_BYTES),
        )
        .await
        .map_err(|_| ExposureError::Protocol("service stream header read timed out".into()))??;

        header.ttl = header.ttl.min(MAX_TTL);
        if header.ttl == 0 {
            let msg = format!(
                "TTL exhausted for service={} origin={} at node={} (possible routing loop)",
                header.service_tag, header.origin_node_tag, self.node_tag
            );
            warn!("{msg}");
            self.logger.emit_alert("error", msg.clone()).await;
            return Err(ExposureError::Routing(msg));
        }

        if header.visited.len() >= MAX_TTL as usize || header.visited.contains(&self.node_tag) {
            let msg = format!(
                "routing loop detected for service={} origin={} at node={}",
                header.service_tag, header.origin_node_tag, self.node_tag
            );
            warn!("{msg}");
            self.logger.emit_alert("error", msg.clone()).await;
            return Err(ExposureError::Routing(msg));
        }
        header.visited.push(self.node_tag.clone());

        let roles = self.roles.read().await.clone();

        // If this node is egress and owns the Service Tag, handle it directly.
        if roles.egress && self.egress.has_service(&header.service_tag).await {
            return self
                .egress
                .handle_stream(header, Some(remote_node_tag), stream)
                .await;
        }

        // Otherwise relay according to local relay rules (`ServiceTag -> next_peer`).
        if roles.relay {
            let next_peer = {
                let relay = self.relay_cfg.read().await;
                relay
                    .rules
                    .iter()
                    .find(|r| r.service_tag == header.service_tag)
                    .map(|r| r.next_peer.clone())
            };

            if let Some(peer) = next_peer {
                header.ttl -= 1;
                header.hop_count = header.hop_count.saturating_add(1);
                let mut outbound = self.open_service_stream(&peer, header).await?;
                let _ = tokio::time::timeout(
                    RELAY_COPY_TIMEOUT,
                    tokio::io::copy_bidirectional(&mut stream, &mut outbound),
                )
                .await;
                return Ok(());
            }
        }

        Err(ExposureError::Routing(format!(
            "node {} has no egress service or relay rule for service_tag={}",
            self.node_tag, header.service_tag
        )))
    }

    async fn process_bootstrap_stream(&self, mut incoming: IncomingMuxStream) -> Result<()> {
        let frame: SpecialFrame = tokio::time::timeout(
            FRAME_READ_TIMEOUT,
            read_json_frame_bounded(&mut incoming.stream, MAX_BOOTSTRAP_FRAME_BYTES),
        )
        .await
        .map_err(|_| ExposureError::Protocol("bootstrap frame read timed out".into()))??;

        frame.validate_hops()?;

        // Bootstrap streams may ONLY carry BootstrapForward or BootstrapReply and NEVER relay arbitrary hops!
        if !matches!(
            frame.payload,
            SpecialPayload::BootstrapForward { .. } | SpecialPayload::BootstrapReply { .. }
        ) {
            return Err(ExposureError::Auth(
                "non-bootstrap payload rejected on StreamKind::Bootstrap".into(),
            ));
        }

        if !frame.is_final_hop(&self.node_tag) {
            return Err(ExposureError::Auth(
                "bootstrap stream may only target the directly connected node".into(),
            ));
        }

        self.deliver_local_special(
            IncomingSpecialFrame {
                frame,
                authenticated: incoming.authenticated,
                is_control: incoming.is_control,
                remote_node_tag: incoming.remote_node_tag,
                remote_public_key: incoming.remote_public_key,
                stream_kind: StreamKind::Bootstrap,
            },
            true,
        )
        .await;
        Ok(())
    }

    async fn process_special_stream(&self, mut incoming: IncomingMuxStream) -> Result<()> {
        let mut frame: SpecialFrame =
            tokio::time::timeout(FRAME_READ_TIMEOUT, read_json_frame(&mut incoming.stream))
                .await
                .map_err(|_| ExposureError::Protocol("special frame read timed out".into()))??;

        frame.validate_hops()?;

        // Verify this node is the expected hop and the previous hop matches the authenticated peer
        if frame.current_target() != Some(self.node_tag.as_str()) {
            return Err(ExposureError::Routing(format!(
                "special frame {} target {:?} != local node {}",
                frame.id,
                frame.current_target(),
                self.node_tag
            )));
        }
        if let Some(prev) = frame.prev_hop() {
            if prev != incoming.remote_node_tag {
                return Err(ExposureError::Auth(format!(
                    "special frame {} prev_hop '{}' != authenticated link peer '{}'",
                    frame.id, prev, incoming.remote_node_tag
                )));
            }
        }

        if frame.is_final_hop(&self.node_tag) {
            self.deliver_local_special(
                IncomingSpecialFrame {
                    frame,
                    authenticated: incoming.authenticated,
                    is_control: incoming.is_control,
                    remote_node_tag: incoming.remote_node_tag,
                    remote_public_key: incoming.remote_public_key,
                    stream_kind: StreamKind::Special,
                },
                true,
            )
            .await;
            return Ok(());
        }

        if frame.ttl == 0 {
            let msg = format!(
                "special frame {} TTL exhausted at node={} (hops={:?})",
                frame.id, self.node_tag, frame.hops
            );
            warn!("{msg}");
            self.logger.emit_alert("error", msg.clone()).await;
            return Err(ExposureError::Routing(msg));
        }

        frame.advance()?;
        let next_node = frame
            .current_target()
            .ok_or_else(|| ExposureError::Routing("special frame missing next hop".into()))?
            .to_string();

        let mut next_stream = self
            .link_manager
            .open_stream_to_node(&next_node, StreamKind::Special)
            .await?;
        write_json_frame(&mut next_stream, &frame).await?;
        Ok(())
    }
}
