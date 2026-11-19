use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashSet;
use exposure_core::config::{IngressConfig, IngressListener};
use exposure_core::protocol::{ServiceStreamHeader, ServiceStreamProtocol};
use exposure_core::routing::match_ingress_rule;
use exposure_core::Result;
use http::{header, HeaderValue, Request, Response, StatusCode, Version};
use http_body_util::BodyExt;
use hyper::body::{Body, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::egress::{full_body, ProxyBody};
use crate::forwarder::Forwarder;
use crate::guard::{GuardDecision, GuardEngine};
use crate::logger::NodeLogger;
use crate::tls::{peek_client_hello, ClientHelloSignal, DynamicCertResolver};

/// L7 Ingress Server (DESIGN.md §3.2, §8, §11):
/// - Supports HTTP/1.1, HTTP/2 (TLS ALPN `h2` & plaintext `h2c`), and WebSocket upgrades
/// - Dynamic SNI TLS termination with pre-TLS ClientHello peeking
/// - Rule matching by Host, URL prefix, Source CIDR, SNI
/// - Entry Guard (CIDR, named token bucket rate limiting, fingerprint scoring, `/cdn-cgi/` PoW)
/// - Dispatches via Forwarder (either local self-tag egress or remote mesh link)
pub struct IngressServer {
    node_tag: String,
    cfg: Arc<RwLock<IngressConfig>>,
    default_ttl: u8,
    forwarder: Arc<Forwarder>,
    guard: Arc<GuardEngine>,
    cert_resolver: Arc<DynamicCertResolver>,
    logger: Arc<NodeLogger>,
    started_listeners: DashSet<String>,
}

impl IngressServer {
    pub fn new(
        node_tag: impl Into<String>,
        cfg: IngressConfig,
        default_ttl: u8,
        forwarder: Arc<Forwarder>,
        cert_resolver: Arc<DynamicCertResolver>,
        logger: Arc<NodeLogger>,
    ) -> Arc<Self> {
        Arc::new(Self {
            node_tag: node_tag.into(),
            cfg: Arc::new(RwLock::new(cfg)),
            default_ttl,
            forwarder,
            guard: Arc::new(GuardEngine::new()),
            cert_resolver,
            logger,
            started_listeners: DashSet::new(),
        })
    }

    pub async fn update_config(self: &Arc<Self>, cfg: IngressConfig) -> Result<()> {
        if !cfg.tls_certs.is_empty() {
            self.cert_resolver.load_from_files(&cfg.tls_certs)?;
        }
        let listeners = cfg.listeners.clone();
        *self.cfg.write().await = cfg;
        for l in listeners {
            let key = format!("{}|{}", l.listen_addr, l.tls);
            if !self.started_listeners.contains(&key) {
                if let Err(e) = self.start_listener(l.clone()).await {
                    warn!(addr = %l.listen_addr, error = %e, "failed to start newly added ingress listener on hot reload");
                }
            }
        }
        Ok(())
    }

    pub async fn start_listener(self: &Arc<Self>, listener_cfg: IngressListener) -> Result<SocketAddr> {
        let key = format!("{}|{}", listener_cfg.listen_addr, listener_cfg.tls);
        let tcp_listener = TcpListener::bind(&listener_cfg.listen_addr).await?;
        self.started_listeners.insert(key);
        let bound = tcp_listener.local_addr()?;
        info!(
            node = %self.node_tag,
            addr = %bound,
            tls = listener_cfg.tls,
            "ingress L7 listener started"
        );

        let tls_acceptor = if listener_cfg.tls {
            let server_cfg = self.cert_resolver.build_server_config()?;
            Some(TlsAcceptor::from(server_cfg))
        } else {
            None
        };

        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                let (tcp, peer_addr) = match tcp_listener.accept().await {
                    Ok(pair) => pair,
                    Err(e) => {
                        warn!(error = %e, "ingress accept error");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let _ = tcp.set_nodelay(true);
                let this2 = Arc::clone(&this);
                let acceptor2 = tls_acceptor.clone();

                tokio::spawn(async move {
                    if let Some(acceptor) = acceptor2 {
                        // Non-destructively peek ClientHello for SNI & JA3-style bot signal
                        let hello_sig = peek_client_hello(&tcp).await;
                        match acceptor.accept(tcp).await {
                            Ok(tls_stream) => {
                                this2
                                    .serve_conn(tls_stream, peer_addr, true, Some(hello_sig))
                                    .await;
                            }
                            Err(e) => {
                                debug!(peer = %peer_addr, error = %e, "ingress TLS handshake failed");
                            }
                        }
                    } else {
                        this2.serve_conn(tcp, peer_addr, false, None).await;
                    }
                });
            }
        });

        Ok(bound)
    }

    async fn serve_conn<S>(
        self: Arc<Self>,
        io_stream: S,
        peer_addr: SocketAddr,
        is_tls: bool,
        tls_signal: Option<ClientHelloSignal>,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let tls_sig_arc = Arc::new(tls_signal);
        let service = service_fn(move |req: Request<Incoming>| {
            let this2 = Arc::clone(&self);
            let sig2 = Arc::clone(&tls_sig_arc);
            async move {
                Ok::<_, hyper::Error>(
                    this2
                        .handle_http_request(req, peer_addr, is_tls, sig2.as_ref().as_ref())
                        .await,
                )
            }
        });

        let io = TokioIo::new(io_stream);
        // AutoServerBuilder serves BOTH HTTP/1.1 (with WebSocket upgrades) AND HTTP/2!
        let builder = AutoServerBuilder::new(TokioExecutor::new());
        if let Err(e) = builder.serve_connection_with_upgrades(io, service).await {
            debug!(peer = %peer_addr, error = %e, "ingress connection closed");
        }
    }

    async fn handle_http_request(
        &self,
        req: Request<Incoming>,
        peer_addr: SocketAddr,
        is_tls: bool,
        tls_signal: Option<&ClientHelloSignal>,
    ) -> Response<ProxyBody> {
        let server_hdr = self.cfg.read().await.server_header.clone();
        let mut resp = self
            .handle_http_request_inner(req, peer_addr, is_tls, tls_signal)
            .await;
        if !server_hdr.trim().is_empty() {
            if let Ok(hv) = HeaderValue::from_str(server_hdr.trim()) {
                resp.headers_mut().insert(header::SERVER, hv);
            }
        }
        resp
    }

    async fn handle_http_request_inner(
        &self,
        mut req: Request<Incoming>,
        peer_addr: SocketAddr,
        is_tls: bool,
        tls_signal: Option<&ClientHelloSignal>,
    ) -> Response<ProxyBody> {
        let start = Instant::now();
        let cfg = self.cfg.read().await.clone();
        let ray_id: String = Uuid::new_v4().simple().to_string()[..16].to_string();

        let host = extract_host(&req, tls_signal.and_then(|s| s.sni.as_deref()));
        let path = req.uri().path().to_string();
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".into());
        let sni = tls_signal.and_then(|s| s.sni.as_deref());

        // Built-in `/cdn-cgi/` PoW challenge endpoints
        if path.starts_with("/cdn-cgi") {
            let matched_rule = match_ingress_rule(&cfg.rules, &host, "/", peer_addr.ip(), sni);
            let guard_profile = matched_rule
                .and_then(|r| r.guard.as_ref())
                .and_then(|g| cfg.guards.get(g));

            let method = req.method().clone();
            let headers = req.headers().clone();
            let body_bytes = match req.into_body().collect().await {
                Ok(c) => c.to_bytes(),
                Err(_) => bytes::Bytes::new(),
            };
            let g_resp = self.guard.handle_cdn_cgi(
                &method,
                &path,
                &body_bytes,
                &headers,
                &host,
                peer_addr.ip(),
                guard_profile,
                &cfg.clearance_secret,
            );

            let passed = path == "/cdn-cgi/verify" && g_resp.status == StatusCode::OK;
            if passed {
                let svc_tag = matched_rule
                    .map(|r| r.service_tag.as_str())
                    .unwrap_or("_cdn_cgi");
                self.logger
                    .record_session(
                        "ingress",
                        svc_tag,
                        &peer_addr.ip().to_string(),
                        200,
                        start.elapsed().as_secs_f64() * 1000.0,
                        0,
                        g_resp.body.len() as u64,
                        false,
                        false,
                        true,
                        None,
                    )
                    .await;
            }

            let mut rb = Response::builder()
                .status(g_resp.status)
                .header(header::CONTENT_TYPE, g_resp.content_type);
            for (k, v) in g_resp.extra_headers {
                rb = rb.header(k, v);
            }
            return rb.body(full_body(g_resp.body)).unwrap();
        }

        // Identify service and next hop via local rules
        let rule = match match_ingress_rule(&cfg.rules, &host, &path, peer_addr.ip(), sni) {
            Some(r) => r.clone(),
            None => {
                return Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(full_body("404 Not Found"))
                    .unwrap();
            }
        };

        // Evaluate Entry Guard if attached to this route
        if let Some(ref guard_name) = rule.guard {
            if !guard_name.trim().is_empty() {
                if let Some(profile) = cfg.guards.get(guard_name) {
                    match self.guard.evaluate(
                        profile,
                        &cfg.rate_limit_buckets,
                        &cfg.clearance_secret,
                        peer_addr.ip(),
                        &host,
                        &path_and_query,
                        req.headers(),
                        tls_signal,
                    ) {
                        GuardDecision::Allow => {}
                        GuardDecision::RateLimited { retry_after_secs } => {
                            self.logger
                                .record_session(
                                    "ingress",
                                    &rule.service_tag,
                                    &peer_addr.ip().to_string(),
                                    429,
                                    start.elapsed().as_secs_f64() * 1000.0,
                                    0,
                                    0,
                                    true,
                                    false,
                                    false,
                                    None,
                                )
                                .await;
                            if rule.intercept_errors {
                                let html = exposure_core::assets::render_exposure_error_html(
                                    429,
                                    "Too Many Requests",
                                    "Rate limit exceeded. Please try again shortly.",
                                    &ray_id,
                                    Some(retry_after_secs),
                                );
                                return Response::builder()
                                    .status(StatusCode::TOO_MANY_REQUESTS)
                                    .header(header::RETRY_AFTER, retry_after_secs.to_string())
                                    .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                                    .header(header::CACHE_CONTROL, "no-store")
                                    .body(full_body(html))
                                    .unwrap();
                            }
                            return Response::builder()
                                .status(StatusCode::TOO_MANY_REQUESTS)
                                .header(header::RETRY_AFTER, retry_after_secs.to_string())
                                .body(full_body("Too Many Requests"))
                                .unwrap();
                        }
                        GuardDecision::Reject { status, reason } => {
                            self.logger
                                .record_session(
                                    "ingress",
                                    &rule.service_tag,
                                    &peer_addr.ip().to_string(),
                                    status.as_u16(),
                                    start.elapsed().as_secs_f64() * 1000.0,
                                    0,
                                    0,
                                    false,
                                    true,
                                    false,
                                    Some(reason),
                                )
                                .await;
                            return Response::builder()
                                .status(status)
                                .body(full_body("Access Denied"))
                                .unwrap();
                        }
                        GuardDecision::ChallengeRedirect { location } => {
                            self.logger
                                .record_session(
                                    "ingress",
                                    &rule.service_tag,
                                    &peer_addr.ip().to_string(),
                                    200,
                                    start.elapsed().as_secs_f64() * 1000.0,
                                    0,
                                    0,
                                    false,
                                    true,
                                    false,
                                    None,
                                )
                                .await;
                            if let Some((bytes, mime)) = exposure_core::assets::load_web_asset(
                                exposure_core::assets::WebApp::Challenge,
                                "index.html",
                            ) {
                                return Response::builder()
                                    .status(StatusCode::OK)
                                    .header(header::CONTENT_TYPE, mime)
                                    .header(header::CACHE_CONTROL, "no-store")
                                    .body(full_body(bytes))
                                    .unwrap();
                            }
                            return Response::builder()
                                .status(StatusCode::FOUND)
                                .header(header::LOCATION, location)
                                .header(header::CACHE_CONTROL, "no-store")
                                .body(full_body(""))
                                .unwrap();
                        }
                    }
                } else {
                    warn!(
                        node = %self.node_tag,
                        service = %rule.service_tag,
                        guard = %guard_name,
                        "ingress rule references undefined guard profile"
                    );
                }
            }
        }

        let client_fp = crate::guard::classify_client(req.headers());
        let fp_verified = self
            .guard
            .has_valid_fp_clearance(&cfg.clearance_secret, &host, req.headers());

        // Inject forwarding headers
        if let Ok(hv) = HeaderValue::from_str(&peer_addr.ip().to_string()) {
            req.headers_mut().insert("x-forwarded-for", hv);
        }
        req.headers_mut().insert(
            "x-forwarded-proto",
            HeaderValue::from_static(if is_tls { "https" } else { "http" }),
        );
        if let Ok(hv) = HeaderValue::from_str(&host) {
            if !req.headers().contains_key(header::HOST) {
                req.headers_mut().insert(header::HOST, hv);
            }
        }

        let req_bytes_in = req
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or_else(|| req.body().size_hint().lower());

        let is_upgrade = req.headers().contains_key(header::UPGRADE);
        let use_h2_mesh = req.version() == Version::HTTP_2 && !is_upgrade;

        let stream_hdr = ServiceStreamHeader {
            service_tag: rule.service_tag.clone(),
            origin_node_tag: self.node_tag.clone(),
            ttl: self.default_ttl,
            hop_count: 0,
            request_id: Uuid::new_v4().to_string(),
            client_ip: Some(peer_addr.ip().to_string()),
            is_tls,
            sni: sni.map(|s| s.to_string()),
            protocol: if use_h2_mesh {
                ServiceStreamProtocol::H2
            } else {
                ServiceStreamProtocol::Http1
            },
        };

        let mesh_stream = match self
            .forwarder
            .open_service_stream(&rule.next_peer, stream_hdr)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                let msg = format!(
                    "ingress forward to peer={} service={} failed: {}",
                    rule.next_peer, rule.service_tag, e
                );
                warn!("{msg}");
                self.logger
                    .record_session(
                        "ingress",
                        &rule.service_tag,
                        &peer_addr.ip().to_string(),
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
                    .body(full_body("Bad Gateway: mesh forward failed"))
                    .unwrap();
            }
        };

        let proxy_res: std::result::Result<Response<ProxyBody>, String> = if use_h2_mesh {
            *req.version_mut() = Version::HTTP_2;
            match hyper::client::conn::http2::handshake(
                TokioExecutor::new(),
                TokioIo::new(mesh_stream),
            )
            .await
            {
                Ok((mut sender, conn)) => {
                    tokio::spawn(async move {
                        let _ = conn.await;
                    });
                    match sender.send_request(req).await {
                        Ok(resp) => Ok(resp.map(|b| b.boxed())),
                        Err(e) => Err(format!("mesh h2 send: {e}")),
                    }
                }
                Err(e) => Err(format!("mesh h2 handshake: {e}")),
            }
        } else {
            *req.version_mut() = Version::HTTP_11;
            let client_upg = if is_upgrade {
                Some(hyper::upgrade::on(&mut req))
            } else {
                None
            };
            match hyper::client::conn::http1::Builder::new()
                .preserve_header_case(true)
                .handshake(TokioIo::new(mesh_stream))
                .await
            {
                Ok((mut sender, conn)) => {
                    tokio::spawn(async move {
                        let _ = conn.with_upgrades().await;
                    });
                    match sender.send_request(req).await {
                        Ok(mut resp) => {
                            if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
                                if let Some(in_upg) = client_upg {
                                    let out_upg = hyper::upgrade::on(&mut resp);
                                    tokio::spawn(async move {
                                        if let Ok((u_in, u_out)) =
                                            tokio::try_join!(in_upg, out_upg)
                                        {
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
                        Err(e) => Err(format!("mesh http1 send: {e}")),
                    }
                }
                Err(e) => Err(format!("mesh http1 handshake: {e}")),
            }
        };

        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        match proxy_res {
            Ok(resp) => {
                let resp_bytes_out = resp
                    .headers()
                    .get(header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or_else(|| resp.body().size_hint().lower());
                self.logger
                    .record_session_with_fp(
                        "ingress",
                        &rule.service_tag,
                        &peer_addr.ip().to_string(),
                        resp.status().as_u16(),
                        latency_ms,
                        req_bytes_in,
                        resp_bytes_out,
                        false,
                        false,
                        false,
                        None,
                        Some(client_fp.device_type.to_string()),
                        Some(client_fp.browser_family.to_string()),
                        Some(client_fp.os_family.to_string()),
                        fp_verified,
                    )
                    .await;
                resp
            }
            Err(err) => {
                warn!(ray_id = %ray_id, service = %rule.service_tag, error = %err, "ingress proxy error");
                self.logger
                    .record_session(
                        "ingress",
                        &rule.service_tag,
                        &peer_addr.ip().to_string(),
                        504,
                        latency_ms,
                        req_bytes_in,
                        0,
                        false,
                        false,
                        false,
                        Some(err),
                    )
                    .await;
                if rule.intercept_errors {
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
                Response::builder()
                    .status(StatusCode::GATEWAY_TIMEOUT)
                    .body(full_body("504 Gateway Time-out"))
                    .unwrap()
            }
        }
    }
}

fn extract_host(req: &Request<Incoming>, sni: Option<&str>) -> String {
    if let Some(h) = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()) {
        return h.to_string();
    }
    if let Some(auth) = req.uri().authority() {
        return auth.as_str().to_string();
    }
    sni.unwrap_or("").to_string()
}
