use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use exposure_core::config::{NodeRoles, RelayConfig};
use exposure_core::protocol::{
    read_json_frame, write_json_frame, ServiceStreamHeader, SpecialFrame, StreamKind,
};
use exposure_core::{ExposureError, Result};
use exposure_link::{IncomingMuxStream, LinkManager};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot, RwLock};
use tracing::{debug, warn};

use crate::egress::EgressHandler;
use crate::logger::NodeLogger;

pub trait ServiceIo: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> ServiceIo for T {}
pub type BoxedServiceIo = Pin<Box<dyn ServiceIo>>;

/// Decoupled Forwarding Layer (DESIGN.md §6.4 & §7):
/// - Routes normal service frames by `ServiceTag` (local egress OR remote Peer Tag via LinkManager)
/// - Routes special data frames by explicit `Hop Table` (`Node Tag` sequence) with TTL loop protection
/// - Supports symmetric reversed-hop replies for Control RPCs and Maintainer acknowledgements
pub struct Forwarder {
    node_tag: String,
    roles: Arc<RwLock<NodeRoles>>,
    relay_cfg: Arc<RwLock<RelayConfig>>,
    link_manager: Arc<LinkManager>,
    egress: Arc<EgressHandler>,
    logger: Arc<NodeLogger>,
    special_tx: mpsc::Sender<SpecialFrame>,
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
    ) -> (Arc<Self>, mpsc::Receiver<SpecialFrame>) {
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
            tokio::spawn(async move {
                if let Err(e) = egress.handle_stream(header, server_io).await {
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

    /// Send a `SpecialFrame` along its Hop Table (advancing `hop_index` to the next hop).
    pub async fn send_special(&self, mut frame: SpecialFrame) -> Result<()> {
        if frame.is_final_hop(&self.node_tag) {
            self.deliver_local_special(frame).await;
            return Ok(());
        }

        // If `hop_index == 0` points to self, advance to hop 1.
        if frame.current_target() == Some(self.node_tag.as_str()) {
            frame.advance()?;
        }

        let next_node = frame
            .current_target()
            .ok_or_else(|| ExposureError::Routing("special frame has no next hop".into()))?
            .to_string();

        let mut stream = self
            .link_manager
            .open_stream_to_node(&next_node, StreamKind::Special)
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
        let id = frame.id.clone();
        let (tx, rx) = oneshot::channel();
        self.pending_replies.insert(id.clone(), tx);

        if let Err(e) = self.send_special(frame).await {
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

    async fn deliver_local_special(&self, frame: SpecialFrame) {
        if let Some((_, waiter)) = self.pending_replies.remove(&frame.id) {
            let _ = waiter.send(frame);
            return;
        }
        if let Err(e) = self.special_tx.send(frame).await {
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
                tokio::spawn(async move {
                    if let Err(e) = fwd.process_service_stream(incoming.stream).await {
                        debug!(error = %e, "service stream ended");
                    }
                });
            }
            StreamKind::Special => {
                let fwd = Arc::clone(self);
                tokio::spawn(async move {
                    if let Err(e) = fwd.process_special_stream(incoming.stream).await {
                        warn!(error = %e, "special frame processing failed");
                    }
                });
            }
            StreamKind::Bootstrap => {
                let fwd = Arc::clone(self);
                tokio::spawn(async move {
                    if let Err(e) = fwd.process_special_stream(incoming.stream).await {
                        warn!(error = %e, "bootstrap stream processing failed");
                    }
                });
            }
            StreamKind::Probe => {}
        }
    }

    async fn process_service_stream(
        &self,
        mut stream: exposure_link::MuxStream,
    ) -> Result<()> {
        let mut header: ServiceStreamHeader = read_json_frame(&mut stream).await?;
        if header.ttl == 0 {
            let msg = format!(
                "TTL exhausted for service={} origin={} at node={} (possible routing loop)",
                header.service_tag, header.origin_node_tag, self.node_tag
            );
            warn!("{msg}");
            self.logger.emit_alert("error", msg.clone()).await;
            return Err(ExposureError::Routing(msg));
        }

        let roles = self.roles.read().await.clone();

        // If this node is egress and owns the Service Tag, handle it directly.
        if roles.egress && self.egress.has_service(&header.service_tag).await {
            return self.egress.handle_stream(header, stream).await;
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
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut outbound).await;
                return Ok(());
            }
        }

        Err(ExposureError::Routing(format!(
            "node {} has no egress service or relay rule for service_tag={}",
            self.node_tag, header.service_tag
        )))
    }

    async fn process_special_stream(
        &self,
        mut stream: exposure_link::MuxStream,
    ) -> Result<()> {
        let mut frame: SpecialFrame = read_json_frame(&mut stream).await?;

        if frame.is_final_hop(&self.node_tag) {
            self.deliver_local_special(frame).await;
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

        // Advance to next hop along the explicit Hop Table
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
