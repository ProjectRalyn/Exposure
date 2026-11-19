use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use exposure_core::config::{BackendProtocol, EgressConfig, EgressServiceConfig};
use exposure_core::protocol::ServiceStreamHeader;
use exposure_core::{ExposureError, Result};
use http::{header, Request, Response, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use crate::logger::NodeLogger;

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

pub fn full_body(data: impl Into<Bytes>) -> ProxyBody {
    Full::new(data.into())
        .map_err(|never| match never {})
        .boxed()
}

/// Egress role runtime (DESIGN.md §3.3 & §8):
/// - Resolves `ServiceTag -> backend`
/// - Enforces `allow_from` ACL against `origin_node_tag` (default deny unless `allow_any_origin`)
/// - Proxies HTTP/1.1, HTTP/2 (h2c/h2), and WebSocket upgrades
/// - Runs optional active health checks strictly for local backends
pub struct EgressHandler {
    node_tag: String,
    cfg: Arc<RwLock<EgressConfig>>,
    logger: Arc<NodeLogger>,
    /// Local backend health status (true = healthy, false = unhealthy).
    local_health: Arc<DashMap<String, bool>>,
}

impl EgressHandler {
    pub fn new(
        node_tag: impl Into<String>,
        cfg: EgressConfig,
        logger: Arc<NodeLogger>,
    ) -> Arc<Self> {
        Arc::new(Self {
            node_tag: node_tag.into(),
            cfg: Arc::new(RwLock::new(cfg)),
            logger,
            local_health: Arc::new(DashMap::new()),
        })
    }

    pub async fn update_config(&self, cfg: EgressConfig) {
        *self.cfg.write().await = cfg;
    }

    pub async fn has_service(&self, service_tag: &str) -> bool {
        self.cfg.read().await.services.contains_key(service_tag)
    }

    pub fn is_local_backend_healthy(&self, service_tag: &str) -> bool {
        self.local_health
            .get(service_tag)
            .map(|v| *v)
            .unwrap_or(true)
    }

    /// Spawn local active health check loop for services configured with `local_health_check`.
    pub fn spawn_local_health_checks(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                let services = this.cfg.read().await.services.clone();
                for (tag, svc) in services {
                    if let Some(ref hc) = svc.local_health_check {
                        if !hc.enabled {
                            continue;
                        }
                        let timeout = Duration::from_millis(hc.timeout_ms);
                        let healthy = matches!(
                            tokio::time::timeout(timeout, TcpStream::connect(&svc.backend)).await,
                            Ok(Ok(_))
                        );
                        let prev = this.local_health.insert(tag.clone(), healthy);
                        if !healthy && prev != Some(false) {
                            let msg = format!(
                                "local egress backend unhealthy: service={} backend={}",
                                tag, svc.backend
                            );
                            warn!("{msg}");
                            this.logger.emit_alert("warn", msg).await;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
    }

    /// Handle an incoming L7 service stream (from remote Yamux OR local duplex pipe).
    pub async fn handle_stream<S>(
        self: &Arc<Self>,
        header: ServiceStreamHeader,
        stream: S,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let svc = {
            let cfg = self.cfg.read().await;
            cfg.services.get(&header.service_tag).cloned()
        };

        let svc = match svc {
            Some(s) => s,
            None => {
                let msg = format!(
                    "egress {} unknown service_tag {}",
                    self.node_tag, header.service_tag
                );
                warn!("{msg}");
                self.logger.emit_alert("warn", msg.clone()).await;
                return Err(ExposureError::Routing(msg));
            }
        };

        // Enforce origin Node Tag ACL (default deny unless explicitly allowed or allow_any_origin)
        if !svc.allow_any_origin
            && !svc.allow_from.iter().any(|allowed| allowed == &header.origin_node_tag)
        {
            let msg = format!(
                "egress {} ACL denied service={} from origin={}",
                self.node_tag, header.service_tag, header.origin_node_tag
            );
            warn!("{msg}");
            self.logger.emit_alert("warn", msg.clone()).await;
            return Err(ExposureError::AccessDenied(msg));
        }

        let this = Arc::clone(self);
        let svc_arc = Arc::new(svc);
        let hdr_arc = Arc::new(header);

        let service = service_fn(move |req: Request<Incoming>| {
            let this2 = Arc::clone(&this);
            let svc2 = Arc::clone(&svc_arc);
            let hdr2 = Arc::clone(&hdr_arc);
            async move { Ok::<_, hyper::Error>(this2.proxy_http_request(req, &svc2, &hdr2).await) }
        });

        let io = TokioIo::new(stream);
        let builder = AutoServerBuilder::new(TokioExecutor::new());
        if let Err(e) = builder.serve_connection_with_upgrades(io, service).await {
            debug!(error = %e, "egress stream connection closed");
        }
        Ok(())
    }

    async fn proxy_http_request(
        &self,
        mut req: Request<Incoming>,
        svc: &EgressServiceConfig,
        hdr: &ServiceStreamHeader,
    ) -> Response<ProxyBody> {
        let start = Instant::now();
        let client_ip = hdr.client_ip.as_deref().unwrap_or("0.0.0.0");

        let is_upgrade = req
            .headers()
            .get(header::UPGRADE)
            .is_some();

        let timeout = Duration::from_millis(svc.timeout_ms.max(1000));
        let tcp = match tokio::time::timeout(timeout, TcpStream::connect(&svc.backend)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                s
            }
            Ok(Err(e)) => {
                let msg = format!(
                    "egress backend connect failed service={} backend={}: {}",
                    hdr.service_tag, svc.backend, e
                );
                warn!("{msg}");
                self.logger.emit_alert("error", msg.clone()).await;
                self.logger
                    .record_session(
                        "egress",
                        &hdr.service_tag,
                        client_ip,
                        502,
                        start.elapsed().as_secs_f64() * 1000.0,
                        0,
                        0,
                        false,
                        false,
                        false,
                        Some(msg),
                    )
                    .await;
                return Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(full_body("Bad Gateway: backend connect failed"))
                    .unwrap();
            }
            Err(_) => {
                let msg = format!(
                    "egress backend connect timeout service={} backend={}",
                    hdr.service_tag, svc.backend
                );
                warn!("{msg}");
                self.logger.emit_alert("error", msg.clone()).await;
                self.logger
                    .record_session(
                        "egress",
                        &hdr.service_tag,
                        client_ip,
                        504,
                        start.elapsed().as_secs_f64() * 1000.0,
                        0,
                        0,
                        false,
                        false,
                        false,
                        Some(msg),
                    )
                    .await;
                if svc.intercept_errors {
                    let ray_id: String = uuid::Uuid::new_v4().simple().to_string()[..16].to_string();
                    let html = exposure_core::assets::render_exposure_error_html(
                        504,
                        "Gateway Timeout",
                        "The upstream server did not respond in time.",
                        &ray_id,
                        None,
                    );
                    return Response::builder()
                        .status(StatusCode::GATEWAY_TIMEOUT)
                        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                        .header(header::CACHE_CONTROL, "no-store")
                        .body(full_body(html))
                        .unwrap();
                }
                return Response::builder()
                    .status(StatusCode::GATEWAY_TIMEOUT)
                    .body(full_body("Gateway Timeout"))
                    .unwrap();
            }
        };

        // Ensure Host header is present for HTTP/1.1 backends
        if !req.headers().contains_key(header::HOST) {
            if let Ok(hv) = svc.backend.parse() {
                req.headers_mut().insert(header::HOST, hv);
            }
        }

        let use_h2 = svc.protocol == BackendProtocol::H2
            || (svc.protocol == BackendProtocol::Auto && req.version() == http::Version::HTTP_2 && !is_upgrade);

        let resp_res: std::result::Result<Response<ProxyBody>, String> = if svc.tls {
            match connect_backend_tls(tcp, &svc.backend, use_h2).await {
                Ok(tls_stream) => forward_http_stream(tls_stream, req, use_h2, is_upgrade, timeout).await,
                Err(e) => Err(e),
            }
        } else {
            forward_http_stream(tcp, req, use_h2, is_upgrade, timeout).await
        };

        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
        match resp_res {
            Ok(resp) => {
                let status = resp.status().as_u16();
                self.logger
                    .record_session(
                        "egress",
                        &hdr.service_tag,
                        client_ip,
                        status,
                        elapsed_ms,
                        0,
                        0,
                        false,
                        false,
                        false,
                        if status >= 500 {
                            Some(format!("backend status {status}"))
                        } else {
                            None
                        },
                    )
                    .await;
                resp
            }
            Err(err_msg) => {
                warn!(service = %hdr.service_tag, backend = %svc.backend, error = %err_msg, "egress request failed");
                self.logger.emit_alert("error", err_msg.clone()).await;
                self.logger
                    .record_session(
                        "egress",
                        &hdr.service_tag,
                        client_ip,
                        502,
                        elapsed_ms,
                        0,
                        0,
                        false,
                        false,
                        false,
                        Some(err_msg.clone()),
                    )
                    .await;
                if svc.intercept_errors {
                    let ray_id: String = uuid::Uuid::new_v4().simple().to_string()[..16].to_string();
                    let html = exposure_core::assets::render_exposure_error_html(
                        504,
                        "Gateway Timeout",
                        "The upstream server is temporarily unavailable.",
                        &ray_id,
                        None,
                    );
                    return Response::builder()
                        .status(StatusCode::GATEWAY_TIMEOUT)
                        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                        .header(header::CACHE_CONTROL, "no-store")
                        .body(full_body(html))
                        .unwrap();
                }
                Response::builder()
                    .status(StatusCode::GATEWAY_TIMEOUT)
                    .body(full_body("504 Gateway Time-out"))
                    .unwrap()
            }
        }
    }
}

async fn forward_http_stream<S>(
    stream: S,
    mut req: Request<Incoming>,
    use_h2: bool,
    is_upgrade: bool,
    timeout: Duration,
) -> std::result::Result<Response<ProxyBody>, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if use_h2 {
        *req.version_mut() = http::Version::HTTP_2;
        req.headers_mut().remove(header::CONNECTION);
        req.headers_mut().remove("keep-alive");
        req.headers_mut().remove("proxy-connection");
        req.headers_mut().remove(header::TRANSFER_ENCODING);
        req.headers_mut().remove(header::UPGRADE);

        match hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream)).await {
            Ok((mut sender, conn)) => {
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                match tokio::time::timeout(timeout, sender.send_request(req)).await {
                    Ok(Ok(resp)) => Ok(resp.map(|b| b.boxed())),
                    Ok(Err(e)) => Err(format!("h2 upstream error: {e}")),
                    Err(_) => Err("h2 upstream timeout".into()),
                }
            }
            Err(e) => Err(format!("h2 handshake failed: {e}")),
        }
    } else {
        *req.version_mut() = http::Version::HTTP_11;
        let client_upgrade = if is_upgrade {
            Some(hyper::upgrade::on(&mut req))
        } else {
            None
        };

        match hyper::client::conn::http1::Builder::new()
            .preserve_header_case(true)
            .handshake(TokioIo::new(stream))
            .await
        {
            Ok((mut sender, conn)) => {
                tokio::spawn(async move {
                    let _ = conn.with_upgrades().await;
                });
                match tokio::time::timeout(timeout, sender.send_request(req)).await {
                    Ok(Ok(mut resp)) => {
                        if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
                            if let Some(in_upg) = client_upgrade {
                                let out_upg = hyper::upgrade::on(&mut resp);
                                tokio::spawn(async move {
                                    if let Ok((u_in, u_out)) = tokio::try_join!(in_upg, out_upg) {
                                        let mut io_in = TokioIo::new(u_in);
                                        let mut io_out = TokioIo::new(u_out);
                                        let _ = tokio::io::copy_bidirectional(
                                            &mut io_in,
                                            &mut io_out,
                                        )
                                        .await;
                                    }
                                });
                            }
                        }
                        Ok(resp.map(|b| b.boxed()))
                    }
                    Ok(Err(e)) => Err(format!("http1 upstream error: {e}")),
                    Err(_) => Err("http1 upstream timeout".into()),
                }
            }
            Err(e) => Err(format!("http1 handshake failed: {e}")),
        }
    }
}

async fn connect_backend_tls(
    tcp: TcpStream,
    backend_addr: &str,
    use_h2: bool,
) -> std::result::Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoBackendCertVerifier))
        .with_no_client_auth();
    cfg.alpn_protocols = if use_h2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };

    let host = backend_addr
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(backend_addr)
        .trim_matches(|c| c == '[' || c == ']');
    let server_name = ServerName::try_from(host.to_string())
        .unwrap_or_else(|_| ServerName::try_from("localhost".to_string()).unwrap());

    TlsConnector::from(Arc::new(cfg))
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("tls handshake with backend {backend_addr} failed: {e}"))
}

#[derive(Debug)]
struct NoBackendCertVerifier;

impl ServerCertVerifier for NoBackendCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}
