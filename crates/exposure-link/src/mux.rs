use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

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

const STREAM_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_ECHO_TIMEOUT: Duration = Duration::from_secs(5);
const MUX_CLOSE_TIMEOUT: Duration = Duration::from_secs(2);
const UNAUTH_SESSION_TTL: Duration = Duration::from_secs(30);

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
    #[allow(clippy::too_many_arguments)]
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
        // Severely bound stream count on unauthenticated bootstrap sessions
        cfg.set_max_num_streams(if authenticated { 4096 } else { 8 });
        let mut conn = yamux::Connection::new(noise_stream.compat(), cfg, mode);

        let (cmd_tx, mut cmd_rx) = mpsc::channel::<MuxCommand>(128);
        let closed = Arc::new(AtomicBool::new(false));
        let closed_flag = closed.clone();
        let peer_tag = remote_node_tag.clone();

        tokio::spawn(async move {
            let mut pending_opens: VecDeque<(StreamKind, oneshot::Sender<Result<MuxStream>>)> =
                VecDeque::new();
            let mut prefer_inbound = true;
            let unauth_deadline = if !authenticated {
                Some(tokio::time::Instant::now() + UNAUTH_SESSION_TTL)
            } else {
                None
            };

            loop {
                let has_pending_open = !pending_opens.is_empty();
                let deadline_fut = async {
                    match unauth_deadline {
                        Some(d) => tokio::time::sleep_until(d).await,
                        None => std::future::pending::<()>().await,
                    }
                };

                tokio::select! {
                    _ = deadline_fut => {
                        debug!(peer = %peer_tag, "unauthenticated bootstrap session TTL expired");
                        let _ = tokio::time::timeout(
                            MUX_CLOSE_TIMEOUT,
                            poll_fn(|cx| conn.poll_close(cx)),
                        )
                        .await;
                        break;
                    }
                    cmd = cmd_rx.recv() => {
                        match cmd {
                            Some(MuxCommand::OpenStream { kind, reply }) => {
                                pending_opens.push_back((kind, reply));
                            }
                            Some(MuxCommand::Close) | None => {
                                let _ = tokio::time::timeout(
                                    MUX_CLOSE_TIMEOUT,
                                    poll_fn(|cx| conn.poll_close(cx)),
                                )
                                .await;
                                break;
                            }
                        }
                    }
                    res = poll_fn(|cx| {
                        // Alternate polling order so sustained outbound opens never starve inbound I/O & window updates
                        let check_inbound = |conn: &mut yamux::Connection<Compat<NoiseStream<BoxedStream>>>, cx: &mut std::task::Context<'_>| {
                            match conn.poll_next_inbound(cx) {
                                std::task::Poll::Ready(Some(Ok(stream))) => {
                                    Some(Ok(Some(Either::Inbound(stream))))
                                }
                                std::task::Poll::Ready(Some(Err(e))) => Some(Err(e)),
                                std::task::Poll::Ready(None) => Some(Ok(None)),
                                std::task::Poll::Pending => None,
                            }
                        };
                        let check_outbound = |conn: &mut yamux::Connection<Compat<NoiseStream<BoxedStream>>>, cx: &mut std::task::Context<'_>| {
                            if has_pending_open {
                                if let std::task::Poll::Ready(out) = conn.poll_new_outbound(cx) {
                                    return Some(Ok(Some(Either::Outbound(out))));
                                }
                            }
                            None
                        };

                        if prefer_inbound {
                            if let Some(r) = check_inbound(&mut conn, cx) {
                                return std::task::Poll::Ready(r);
                            }
                            if let Some(r) = check_outbound(&mut conn, cx) {
                                return std::task::Poll::Ready(r);
                            }
                        } else {
                            if let Some(r) = check_outbound(&mut conn, cx) {
                                return std::task::Poll::Ready(r);
                            }
                            if let Some(r) = check_inbound(&mut conn, cx) {
                                return std::task::Poll::Ready(r);
                            }
                        }
                        std::task::Poll::Pending
                    }) => {
                        prefer_inbound = !prefer_inbound;
                        match res {
                            Ok(Some(Either::Outbound(Ok(stream)))) => {
                                if let Some((kind, reply)) = pending_opens.pop_front() {
                                    tokio::spawn(async move {
                                        let mut compat = stream.compat();
                                        let write_res = tokio::time::timeout(
                                            STREAM_HEADER_TIMEOUT,
                                            async {
                                                compat.write_u8(kind as u8).await?;
                                                compat.flush().await
                                            },
                                        )
                                        .await;
                                        match write_res {
                                            Ok(Ok(())) => {
                                                let _ = reply.send(Ok(compat));
                                            }
                                            Ok(Err(e)) => {
                                                let _ = reply.send(Err(ExposureError::Link(format!(
                                                    "write stream kind: {e}"
                                                ))));
                                            }
                                            Err(_) => {
                                                let _ = reply.send(Err(ExposureError::Link(
                                                    "write stream kind timed out".into(),
                                                )));
                                            }
                                        }
                                    });
                                }
                            }
                            Ok(Some(Either::Outbound(Err(e)))) => {
                                if let Some((_, reply)) = pending_opens.pop_front() {
                                    let _ = reply.send(Err(ExposureError::Link(format!(
                                        "yamux open: {e}"
                                    ))));
                                }
                                break;
                            }
                            Ok(Some(Either::Inbound(stream))) => {
                                let tx = incoming_tx.clone();
                                let tag = peer_tag.clone();
                                let pk = remote_public_key.clone();
                                tokio::spawn(async move {
                                    let mut compat = stream.compat();
                                    let kind_byte = match tokio::time::timeout(
                                        STREAM_HEADER_TIMEOUT,
                                        compat.read_u8(),
                                    )
                                    .await
                                    {
                                        Ok(Ok(b)) => b,
                                        _ => return,
                                    };
                                    let kind = match StreamKind::from_byte(kind_byte) {
                                        Ok(k) => k,
                                        Err(_) => return,
                                    };
                                    // Unauthenticated sessions may ONLY send StreamKind::Bootstrap!
                                    if !authenticated && kind != StreamKind::Bootstrap {
                                        debug!(
                                            peer = %tag,
                                            ?kind,
                                            "dropped non-bootstrap stream on unauthenticated mux session"
                                        );
                                        return;
                                    }
                                    // Handle Probe pings directly inside link layer
                                    if kind == StreamKind::Probe {
                                        let mut buf = [0u8; 8];
                                        let _ = tokio::time::timeout(PROBE_ECHO_TIMEOUT, async {
                                            compat.read_exact(&mut buf).await?;
                                            compat.write_all(&buf).await?;
                                            compat.flush().await
                                        })
                                        .await;
                                        return;
                                    }
                                    let _ = tx
                                        .send(IncomingMuxStream {
                                            remote_node_tag: tag,
                                            remote_public_key: pk,
                                            remote_addr,
                                            authenticated,
                                            bootstrap_pending,
                                            is_control,
                                            kind,
                                            stream: compat,
                                        })
                                        .await;
                                });
                            }
                            Ok(None) => {
                                break;
                            }
                            Err(e) => {
                                debug!(peer = %peer_tag, error = %e, "yamux connection ended");
                                break;
                            }
                        }
                    }
                }
            }

            closed_flag.store(true, Ordering::SeqCst);
            while let Some((_, reply)) = pending_opens.pop_front() {
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
        tokio::time::timeout(Duration::from_millis(timeout_ms), fut)
            .await
            .map_err(|_| ExposureError::Link("probe timeout".into()))?
    }

    pub async fn close(&self) {
        // Mark the session closed immediately so callers stop scheduling new streams.
        self.closed.store(true, Ordering::SeqCst);
        // `try_send` can fail when the bounded command channel is momentarily full (e.g. many
        // concurrent `open_stream` calls). Dropping `Close` here would leave revoked/evicted
        // peers' authenticated streams alive, so fall back to a blocking send on a task.
        if self.cmd_tx.try_send(MuxCommand::Close).is_err() {
            let tx = self.cmd_tx.clone();
            tokio::spawn(async move {
                let _ = tx.send(MuxCommand::Close).await;
            });
        }
    }
}

enum Either {
    Outbound(std::result::Result<yamux::Stream, yamux::ConnectionError>),
    Inbound(yamux::Stream),
}
