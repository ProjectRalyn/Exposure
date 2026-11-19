use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use exposure_core::protocol::StreamKind;
use exposure_core::{ExposureError, Result};
use futures::future::poll_fn;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;

use crate::noise::NoiseStream;
use crate::transport::BoxedStream;

pub type MuxStream = Compat<yamux::Stream>;

pub struct IncomingMuxStream {
    pub remote_node_tag: String,
    pub remote_public_key: String,
    pub remote_addr: Option<SocketAddr>,
    pub authenticated: bool,
    pub bootstrap_pending: bool,
    pub is_control: bool,
    pub kind: StreamKind,
    pub stream: MuxStream,
}

enum MuxCommand {
    OpenStream {
        kind: StreamKind,
        reply: oneshot::Sender<Result<MuxStream>>,
    },
    Close,
}

#[derive(Clone)]
pub struct MuxSession {
    remote_node_tag: String,
    cmd_tx: mpsc::Sender<MuxCommand>,
    closed: Arc<AtomicBool>,
}

impl MuxSession {
    pub fn spawn(
        noise_stream: NoiseStream<BoxedStream>,
        mode: yamux::Mode,
        remote_node_tag: String,
        remote_public_key: String,
        remote_addr: Option<SocketAddr>,
        authenticated: bool,
        bootstrap_pending: bool,
        is_control: bool,
        incoming_tx: mpsc::Sender<IncomingMuxStream>,
    ) -> Self {
        let mut cfg = yamux::Config::default();
        cfg.set_max_num_streams(4096);
        let mut conn = yamux::Connection::new(noise_stream.compat(), cfg, mode);

        let (cmd_tx, mut cmd_rx) = mpsc::channel::<MuxCommand>(128);
        let closed = Arc::new(AtomicBool::new(false));
        let closed_flag = closed.clone();
        let peer_tag = remote_node_tag.clone();

        tokio::spawn(async move {
            let mut pending_opens: Vec<(StreamKind, oneshot::Sender<Result<MuxStream>>)> =
                Vec::new();

            loop {
                // Drive outbound opens and inbound streams concurrently via poll_fn.
                let mut open_req: Option<(StreamKind, oneshot::Sender<Result<MuxStream>>)> = None;
                if let Some(req) = pending_opens.pop() {
                    open_req = Some(req);
                }

                tokio::select! {
                    biased;
                    cmd = cmd_rx.recv(), if open_req.is_none() => {
                        match cmd {
                            Some(MuxCommand::OpenStream { kind, reply }) => {
                                pending_opens.push((kind, reply));
                            }
                            Some(MuxCommand::Close) | None => {
                                let _ = poll_fn(|cx| conn.poll_close(cx)).await;
                                break;
                            }
                        }
                    }
                    res = poll_fn(|cx| {
                        // First try to satisfy an outbound open if requested
                        if let Some((_, _)) = open_req.as_ref() {
                            if let std::task::Poll::Ready(out) = conn.poll_new_outbound(cx) {
                                return std::task::Poll::Ready(Ok(Some(Either::Outbound(out))));
                            }
                        }
                        match conn.poll_next_inbound(cx) {
                            std::task::Poll::Ready(Some(Ok(stream))) => {
                                std::task::Poll::Ready(Ok(Some(Either::Inbound(stream))))
                            }
                            std::task::Poll::Ready(Some(Err(e))) => {
                                std::task::Poll::Ready(Err(e))
                            }
                            std::task::Poll::Ready(None) => {
                                std::task::Poll::Ready(Ok(None))
                            }
                            std::task::Poll::Pending => std::task::Poll::Pending,
                        }
                    }) => {
                        match res {
                            Ok(Some(Either::Outbound(Ok(stream)))) => {
                                if let Some((kind, reply)) = open_req.take() {
                                    tokio::spawn(async move {
                                        let mut compat = stream.compat();
                                        if let Err(e) = compat.write_u8(kind as u8).await {
                                            let _ = reply.send(Err(ExposureError::Link(format!("write stream kind: {e}"))));
                                            return;
                                        }
                                        let _ = compat.flush().await;
                                        let _ = reply.send(Ok(compat));
                                    });
                                }
                            }
                            Ok(Some(Either::Outbound(Err(e)))) => {
                                if let Some((_, reply)) = open_req.take() {
                                    let _ = reply.send(Err(ExposureError::Link(format!("yamux open: {e}"))));
                                }
                                break;
                            }
                            Ok(Some(Either::Inbound(stream))) => {
                                // Put open_req back if it wasn't consumed
                                if let Some(req) = open_req.take() {
                                    pending_opens.push(req);
                                }
                                let tx = incoming_tx.clone();
                                let tag = peer_tag.clone();
                                let pk = remote_public_key.clone();
                                tokio::spawn(async move {
                                    let mut compat = stream.compat();
                                    let kind_byte = match compat.read_u8().await {
                                        Ok(b) => b,
                                        Err(_) => return,
                                    };
                                    let kind = match StreamKind::from_byte(kind_byte) {
                                        Ok(k) => k,
                                        Err(_) => return,
                                    };
                                    // Handle Probe pings directly inside link layer
                                    if kind == StreamKind::Probe {
                                        let mut buf = [0u8; 8];
                                        if compat.read_exact(&mut buf).await.is_ok() {
                                            let _ = compat.write_all(&buf).await;
                                            let _ = compat.flush().await;
                                        }
                                        return;
                                    }
                                    let _ = tx.send(IncomingMuxStream {
                                        remote_node_tag: tag,
                                        remote_public_key: pk,
                                        remote_addr,
                                        authenticated,
                                        bootstrap_pending,
                                        is_control,
                                        kind,
                                        stream: compat,
                                    }).await;
                                });
                            }
                            Ok(None) => {
                                if let Some((_, reply)) = open_req.take() {
                                    let _ = reply.send(Err(ExposureError::Link("yamux session closed".into())));
                                }
                                break;
                            }
                            Err(e) => {
                                debug!(peer = %peer_tag, error = %e, "yamux connection ended");
                                if let Some((_, reply)) = open_req.take() {
                                    let _ = reply.send(Err(ExposureError::Link(format!("yamux error: {e}"))));
                                }
                                break;
                            }
                        }
                    }
                }
            }

            closed_flag.store(true, Ordering::SeqCst);
            for (_, reply) in pending_opens {
                let _ = reply.send(Err(ExposureError::Link("yamux session closed".into())));
            }
        });

        Self {
            remote_node_tag,
            cmd_tx,
            closed,
        }
    }

    pub fn remote_node_tag(&self) -> &str {
        &self.remote_node_tag
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst) || self.cmd_tx.is_closed()
    }

    pub async fn open_stream(&self, kind: StreamKind) -> Result<MuxStream> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(MuxCommand::OpenStream { kind, reply: tx })
            .await
            .map_err(|_| ExposureError::Link("mux session closed".into()))?;
        rx.await
            .map_err(|_| ExposureError::Link("mux open stream cancelled".into()))?
    }

    /// Execute an active link probe ping/pong over Yamux and measure RTT in ms.
    pub async fn probe_rtt_ms(&self, timeout_ms: u64) -> Result<u64> {
        let fut = async {
            let start = Instant::now();
            let mut s = self.open_stream(StreamKind::Probe).await?;
            let token: [u8; 8] = start.elapsed().as_nanos().to_be_bytes()[8..16]
                .try_into()
                .unwrap();
            s.write_all(&token).await?;
            s.flush().await?;
            let mut resp = [0u8; 8];
            s.read_exact(&mut resp).await?;
            if resp != token {
                return Err(ExposureError::Link("probe echo mismatch".into()));
            }
            Ok(start.elapsed().as_millis() as u64)
        };
        tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), fut)
            .await
            .map_err(|_| ExposureError::Link("probe timeout".into()))?
    }

    pub async fn close(&self) {
        let _ = self.cmd_tx.send(MuxCommand::Close).await;
    }
}

enum Either {
    Outbound(std::result::Result<yamux::Stream, yamux::ConnectionError>),
    Inbound(yamux::Stream),
}
