use std::collections::HashMap;
use std::io::BufReader;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use chrono::Utc;
use dashmap::DashMap;
use exposure_core::config::{BackendProtocol, EgressConfig, EgressServiceConfig, TrustedOrigin};
use exposure_core::crypto::verify_signature_b64;
use exposure_core::protocol::ServiceStreamHeader;
use exposure_core::{ExposureError, Result};
use http::header::HeaderName;
use http::{header, HeaderMap, Request, Response, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::{Body, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use crate::logger::{AccessLogMeta, NodeLogger};

const ORIGIN_SIG_MAX_SKEW_SECS: u64 = 120;
const MAX_ORIGIN_REPLAY_ENTRIES: usize = 65_536;
const WS_IDLE_TIMEOUT: Duration = Duration::from_secs(3600);

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

pub fn full_body(data: impl Into<Bytes>) -> ProxyBody {
    Full::new(data.into())
        .map_err(|never| match never {})
        .boxed()
}

/// Headers the proxy authoritatively sets; these must never be removed via `Connection` tokens,
/// otherwise a client could strip `Host`/`X-Forwarded-*` and bypass origin IP policies or vhost routing.
fn is_protected_proxy_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "host"
            | "content-length"
            | "x-forwarded-for"
            | "x-forwarded-proto"
            | "x-forwarded-host"
            | "x-forwarded-port"
            | "x-real-ip"
    )
}

/// Strip RFC 9110 static + dynamic `Connection`-listed hop-by-hop headers (and invalid `TE` for H2).
pub fn strip_hop_by_hop_headers(headers: &mut HeaderMap, for_h2: bool, preserve_upgrade: bool) {
    let mut dynamic_names: Vec<HeaderName> = Vec::new();
    for val in headers.get_all(header::CONNECTION) {
        if let Ok(s) = val.to_str() {
            for token in s.split(',') {
                let t = token.trim();
                if preserve_upgrade && t.eq_ignore_ascii_case("upgrade") {
                    continue;
                }
                if let Ok(name) = HeaderName::from_bytes(t.as_bytes()) {
                    if !is_protected_proxy_header(&name) {
                        dynamic_names.push(name);
                    }
                }
            }
        }
    }
    for name in dynamic_names {
        headers.remove(&name);
    }
    if !preserve_upgrade {
        headers.remove(header::CONNECTION);
        headers.remove(header::UPGRADE);
    }
    headers.remove("keep-alive");
    headers.remove("proxy-connection");
    headers.remove(header::PROXY_AUTHENTICATE);
    headers.remove(header::PROXY_AUTHORIZATION);
    if for_h2 {
        headers.remove(header::TRANSFER_ENCODING);
        let valid_te = headers
            .get(header::TE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().eq_ignore_ascii_case("trailers"))
            .unwrap_or(false);
        if !valid_te {
            headers.remove(header::TE);
        }
    }
}

/// Egress role runtime (DESIGN.md §3.3 & §8):
/// - Resolves `ServiceTag -> backend`
/// - Enforces cryptographically authenticated `allow_from` ACL against `origin_node_tag` (default deny)
/// - Verifies backend TLS certificates by default (with optional custom CA or explicit `insecure_skip_verify`)
/// - Proxies HTTP/1.1, HTTP/2 (`h2c`/`h2`), and WebSocket upgrades
/// - Runs optional active TCP/HTTP health checks strictly for local backends
pub struct EgressHandler {
    node_tag: String,
    cfg: Arc<RwLock<EgressConfig>>,
    trusted_origins: Arc<RwLock<HashMap<String, String>>>,
    logger: Arc<NodeLogger>,
    /// Local backend health status (true = healthy, false = unhealthy).
    local_health: Arc<DashMap<String, bool>>,
    last_hc_run: Arc<DashMap<String, Instant>>,
    /// Cached backend TLS ClientConfigs keyed by `(insecure_skip_verify, ca_cert_path, offer_h2)`.
    tls_client_configs: Arc<DashMap<(bool, Option<String>, bool), Arc<ClientConfig>>>,
    /// Multi-hop origin signature replay guard keyed by `(origin_node_tag, request_id) -> expires_at`.
    origin_replay_cache: Arc<DashMap<(String, String), i64>>,
}

impl EgressHandler {
    pub fn new(
        node_tag: impl Into<String>,
        cfg: EgressConfig,
        trusted_origins: Vec<TrustedOrigin>,
        logger: Arc<NodeLogger>,
    ) -> Arc<Self> {
        let origin_map = trusted_origins
            .into_iter()
            .map(|o| (o.node_tag, o.public_key))
            .collect();
        Arc::new(Self {
            node_tag: node_tag.into(),
            cfg: Arc::new(RwLock::new(cfg)),
            trusted_origins: Arc::new(RwLock::new(origin_map)),
            logger,
            local_health: Arc::new(DashMap::new()),
            last_hc_run: Arc::new(DashMap::new()),
            tls_client_configs: Arc::new(DashMap::new()),
            origin_replay_cache: Arc::new(DashMap::new()),
        })
    }

    pub async fn update_config(&self, cfg: EgressConfig, trusted_origins: Vec<TrustedOrigin>) {
        *self.cfg.write().await = cfg;
        *self.trusted_origins.write().await = trusted_origins
            .into_iter()
            .map(|o| (o.node_tag, o.public_key))
            .collect();
        self.tls_client_configs.clear();
        self.local_health.clear();
        self.last_hc_run.clear();
    }

    pub(crate) async fn get_tls_client_config(
        &self,
        svc: &EgressServiceConfig,
        offer_h2: bool,
    ) -> std::result::Result<Arc<ClientConfig>, String> {
        let insecure = svc.effective_insecure_skip_verify();
        let ca_path = svc
            .ca_cert_path
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let key = (insecure, ca_path.clone(), offer_h2);
        if let Some(cached) = self.tls_client_configs.get(&key) {
            return Ok(Arc::clone(&cached));
        }
        let cfg = tokio::task::spawn_blocking(move || {
            build_backend_tls_client_config(insecure, ca_path.as_deref(), offer_h2)
        })
        .await
        .map_err(|e| format!("backend TLS config task failed: {e}"))??;
        let arc_cfg = Arc::new(cfg);
        if self.tls_client_configs.len() >= 1024 {
            self.tls_client_configs.clear();
        }
        self.tls_client_configs.insert(key, Arc::clone(&arc_cfg));
        Ok(arc_cfg)
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
                let now = Instant::now();
                for (tag, svc) in services {
                    if let Some(ref hc) = svc.local_health_check {
                        if !hc.enabled {
                            continue;
                        }
                        let interval = Duration::from_secs(hc.interval_secs.max(1));
                        let due = this
                            .last_hc_run
                            .get(&tag)
                            .map(|last| now.duration_since(*last) >= interval)
                            .unwrap_or(true);
                        if !due {
                            continue;
                        }
                        this.last_hc_run.insert(tag.clone(), now);

                        let timeout = Duration::from_millis(hc.timeout_ms.max(200));
                        let healthy = if let Some(ref http_path) = hc.http_path {
                            this.check_http_health(&svc, http_path, timeout).await
                        } else {
                            matches!(
                                tokio::time::timeout(timeout, TcpStream::connect(&svc.backend)).await,
                                Ok(Ok(_))
                            )
                        };
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
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    async fn check_http_health(
        &self,
        svc: &EgressServiceConfig,
        http_path: &str,
        timeout: Duration,
    ) -> bool {
        let path = if http_path.starts_with('/') {
            http_path
        } else {
            "/"
        };
        let fut = async {
            let tcp = TcpStream::connect(&svc.backend).await.ok()?;
            let req = Request::builder()
                .method(http::Method::GET)
                .uri(path)
                .header(header::HOST, &svc.backend)
                .header(header::CONNECTION, "close")
                .header(header::USER_AGENT, "Exposure-HealthCheck/1.0")
                .body(Empty::<Bytes>::new())
                .ok()?;
            if svc.effective_tls() {
                let tls_cfg = self.get_tls_client_config(svc, false).await.ok()?;
                let tls_stream = connect_backend_tls(tcp, svc, &tls_cfg).await.ok()?;
                let (mut sender, conn) =
                    hyper::client::conn::http1::handshake(TokioIo::new(tls_stream))
                        .await
                        .ok()?;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                let resp = sender.send_request(req).await.ok()?;
                Some(resp.status().as_u16() < 500)
            } else {
                let (mut sender, conn) =
                    hyper::client::conn::http1::handshake(TokioIo::new(tcp))
                        .await
                        .ok()?;
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                let resp = sender.send_request(req).await.ok()?;
                Some(resp.status().as_u16() < 500)
            }
        };
        tokio::time::timeout(timeout, fut)
            .await
            .ok()
            .flatten()
            .unwrap_or(false)
    }

    /// Verify cryptographic origin authenticity for `ServiceStreamHeader`.
    async fn verify_origin_authenticity(
        &self,
        header: &ServiceStreamHeader,
        authenticated_peer_tag: Option<&str>,
    ) -> Result<()> {
        // Co-located local duplex pipe from this same node
        if authenticated_peer_tag == Some(self.node_tag.as_str())
            && header.origin_node_tag == self.node_tag
        {
            return Ok(());
        }
        // Direct 1-hop stream: the authenticated Noise+Ed25519 link peer MUST equal origin_node_tag
        if header.hop_count == 0 {
            match authenticated_peer_tag {
                Some(peer) if peer == header.origin_node_tag => return Ok(()),
                other => {
                    return Err(ExposureError::AccessDenied(format!(
                        "egress {} rejected spoofed direct origin_node_tag={} from authenticated peer {:?}",
                        self.node_tag, header.origin_node_tag, other
                    )));
                }
            }
        }
        // Multi-hop stream via relays: verify origin's Ed25519 signature against trusted_origins
        let origins = self.trusted_origins.read().await;
        let origin_pk = origins.get(&header.origin_node_tag).ok_or_else(|| {
            ExposureError::AccessDenied(format!(
                "egress {} has no trusted public key for multi-hop origin {}",
                self.node_tag, header.origin_node_tag
            ))
        })?;
        let sig = header.origin_signature.as_deref().ok_or_else(|| {
            ExposureError::AccessDenied(format!(
                "egress {} rejected unsigned multi-hop stream from origin {}",
                self.node_tag, header.origin_node_tag
            ))
        })?;
        let now = Utc::now().timestamp();
        if now.abs_diff(header.timestamp) > ORIGIN_SIG_MAX_SKEW_SECS {
            return Err(ExposureError::AccessDenied(format!(
                "egress {} rejected stale origin signature from {}",
                self.node_tag, header.origin_node_tag
            )));
        }
        let signing = ServiceStreamHeader::origin_signing_bytes(
            &header.service_tag,
            &header.origin_node_tag,
            &header.request_id,
            header.timestamp,
        );
        verify_signature_b64(origin_pk, &signing, sig).map_err(|_| {
            ExposureError::AccessDenied(format!(
                "egress {} invalid origin signature for origin {}",
                self.node_tag, header.origin_node_tag
            ))
        })?;

        // Check replay cache ONLY after signature verification so forged traffic cannot poison it
        let replay_key = (header.origin_node_tag.clone(), header.request_id.clone());
        let exp = header
            .timestamp
            .saturating_add(ORIGIN_SIG_MAX_SKEW_SECS as i64);
        if self.origin_replay_cache.len() >= MAX_ORIGIN_REPLAY_ENTRIES {
            self.origin_replay_cache.retain(|_, v| *v > now);
            if self.origin_replay_cache.len() >= MAX_ORIGIN_REPLAY_ENTRIES {
                crate::ban::evict_half(&self.origin_replay_cache);
            }
        }
        if let Some(prev_exp) = self.origin_replay_cache.get(&replay_key) {
            if *prev_exp > now {
                return Err(ExposureError::AccessDenied(format!(
                    "egress {} rejected replayed origin request {} from {}",
                    self.node_tag, header.request_id, header.origin_node_tag
                )));
            }
        }
        self.origin_replay_cache.insert(replay_key, exp);
        Ok(())
    }

    /// Handle an incoming L7 service stream (from remote Yamux OR local duplex pipe).
    pub async fn handle_stream<S>(
        self: &Arc<Self>,
        header: ServiceStreamHeader,
        authenticated_peer_tag: Option<String>,
        stream: S,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (svc, error_html_tpl) = {
            let cfg = self.cfg.read().await;
            (
                cfg.services.get(&header.service_tag).cloned(),
                cfg.pages.error_html.clone(),
            )
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
        if !svc.effective_allow_any_origin() {
            if !svc
                .allow_from
                .iter()
                .any(|allowed| allowed == &header.origin_node_tag)
            {
                let msg = format!(
                    "egress {} ACL denied service={} from origin={}",
                    self.node_tag, header.service_tag, header.origin_node_tag
                );
                warn!("{msg}");
                self.logger.emit_alert("warn", msg.clone()).await;
                return Err(ExposureError::AccessDenied(msg));
            }
            if let Err(e) = self
                .verify_origin_authenticity(&header, authenticated_peer_tag.as_deref())
                .await
            {
                warn!("{e}");
                self.logger.emit_alert("warn", e.to_string()).await;
                return Err(e);
            }
        }

        let this = Arc::clone(self);
        let svc_arc = Arc::new(svc);
        let hdr_arc = Arc::new(header);
        let tpl_arc = Arc::new(error_html_tpl);

        let service = service_fn(move |req: Request<Incoming>| {
            let this2 = Arc::clone(&this);
            let svc2 = Arc::clone(&svc_arc);
            let hdr2 = Arc::clone(&hdr_arc);
            let tpl2 = Arc::clone(&tpl_arc);
            async move {
                Ok::<_, hyper::Error>(
                    this2
                        .proxy_http_request(req, &svc2, &hdr2, tpl2.as_deref())
                        .await,
                )
            }
        });

        let io = TokioIo::new(stream);
        let mut builder = AutoServerBuilder::new(TokioExecutor::new());
        builder
            .http1()
            .timer(TokioTimer::new())
            .header_read_timeout(Duration::from_secs(10))
            .max_headers(100);
        builder
            .http2()
            .timer(TokioTimer::new())
            .keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(15));
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
        error_html_tpl: Option<&str>,
    ) -> Response<ProxyBody> {
        let start = Instant::now();
        let client_ip = hdr.client_ip.as_deref().unwrap_or("0.0.0.0");
        let method_str = req.method().as_str().to_string();
        let host_str = hdr
            .sni
            .clone()
            .or_else(|| {
                req.headers()
                    .get(header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
            })
            .unwrap_or_default();
        let path_str = req.uri().path().to_string();
        let query_opt = req.uri().query().map(str::to_string);
        let is_upgrade = req.headers().get(header::UPGRADE).is_some();
        let use_h2 = svc.protocol == BackendProtocol::H2
            || (svc.protocol == BackendProtocol::Auto
                && req.version() == http::Version::HTTP_2
                && !is_upgrade);
        let proto_str: &'static str = if is_upgrade {
            "WS"
        } else if use_h2 {
            "HTTP/2"
        } else {
            "HTTP/1.1"
        };
        let scheme_str = if svc.effective_tls() { "https" } else { "http" };
        let ua_str = req
            .headers()
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let referer_opt = req
            .headers()
            .get(header::REFERER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let make_meta = |action: &'static str| AccessLogMeta {
            ray_id: Some(&hdr.request_id),
            method: Some(&method_str),
            host: (!host_str.is_empty()).then_some(host_str.as_str()),
            path: Some(&path_str),
            query: query_opt.as_deref(),
            protocol: Some(proto_str),
            scheme: Some(scheme_str),
            user_agent: (!ua_str.is_empty()).then_some(ua_str.as_str()),
            referer: referer_opt.as_deref(),
            action: Some(action),
            cache_status: None,
            tls_ja3: None,
            waf_rule_id: None,
            waf_category: None,
            suspicion_score: None,
            client_country: None,
        };

        if !self.is_local_backend_healthy(&hdr.service_tag) {
            self.logger
                .record_access_log(
                    "egress",
                    &hdr.service_tag,
                    client_ip,
                    503,
                    start.elapsed().as_secs_f64() * 1000.0,
                    0,
                    0,
                    false,
                    false,
                    false,
                    Some("backend unhealthy".into()),
                    None,
                    None,
                    None,
                    false,
                    make_meta("upstream_error"),
                )
                .await;
            return self
                .build_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service Unavailable",
                    "The upstream backend failed local health checks.",
                    svc.effective_intercept_errors(),
                    error_html_tpl,
                    &hdr.request_id,
                );
        }

        let req_bytes_in = req
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or_else(|| req.body().size_hint().lower());

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
                if let Some(suppressed) = self
                    .logger
                    .should_log_warn(&format!("egress:conn_err:{}", hdr.service_tag))
                {
                    warn!(suppressed, "{msg}");
                }
                self.logger.emit_alert("error", msg.clone()).await;
                self.logger
                    .record_access_log(
                        "egress",
                        &hdr.service_tag,
                        client_ip,
                        502,
                        start.elapsed().as_secs_f64() * 1000.0,
                        req_bytes_in,
                        0,
                        false,
                        false,
                        false,
                        Some(msg),
                        None,
                        None,
                        None,
                        false,
                        make_meta("upstream_error"),
                    )
                    .await;
                return self.build_error_response(
                    StatusCode::BAD_GATEWAY,
                    "Bad Gateway",
                    "Could not connect to the upstream server.",
                    svc.effective_intercept_errors(),
                    error_html_tpl,
                    &hdr.request_id,
                );
            }
            Err(_) => {
                let msg = format!(
                    "egress backend connect timeout service={} backend={}",
                    hdr.service_tag, svc.backend
                );
                if let Some(suppressed) = self
                    .logger
                    .should_log_warn(&format!("egress:conn_to:{}", hdr.service_tag))
                {
                    warn!(suppressed, "{msg}");
                }
                self.logger.emit_alert("error", msg.clone()).await;
                self.logger
                    .record_access_log(
                        "egress",
                        &hdr.service_tag,
                        client_ip,
                        504,
                        start.elapsed().as_secs_f64() * 1000.0,
                        req_bytes_in,
                        0,
                        false,
                        false,
                        false,
                        Some(msg),
                        None,
                        None,
                        None,
                        false,
                        make_meta("upstream_error"),
                    )
                    .await;
                return self.build_error_response(
                    StatusCode::GATEWAY_TIMEOUT,
                    "Gateway Timeout",
                    "The upstream server did not respond in time.",
                    svc.effective_intercept_errors(),
                    error_html_tpl,
                    &hdr.request_id,
                );
            }
        };

        // Ensure Host header is present for HTTP/1.1 backends (HTTP/2 uses :authority below)
        if !use_h2 && !req.headers().contains_key(header::HOST) {
            if let Ok(hv) = svc.backend.parse() {
                req.headers_mut().insert(header::HOST, hv);
            }
        }

        let resp_res: std::result::Result<Response<ProxyBody>, (StatusCode, String)> = if svc.effective_tls() {
            match self.get_tls_client_config(svc, use_h2).await {
                Ok(tls_cfg) => {
                    match tokio::time::timeout(timeout, connect_backend_tls(tcp, svc, &tls_cfg)).await {
                        Ok(Ok(tls_stream)) => {
                            let negotiated_h2 =
                                tls_stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
                            let actual_use_h2 = if svc.protocol == BackendProtocol::Auto {
                                negotiated_h2
                            } else {
                                use_h2
                            };
                            forward_http_stream(
                                tls_stream,
                                req,
                                actual_use_h2,
                                is_upgrade,
                                true,
                                &svc.backend,
                                timeout,
                            )
                            .await
                        }
                        Ok(Err(e)) => Err((StatusCode::BAD_GATEWAY, e)),
                        Err(_) => Err((
                            StatusCode::GATEWAY_TIMEOUT,
                            format!("tls handshake timeout with backend {}", svc.backend),
                        )),
                    }
                }
                Err(e) => Err((StatusCode::BAD_GATEWAY, e)),
            }
        } else {
            forward_http_stream(tcp, req, use_h2, is_upgrade, false, &svc.backend, timeout).await
        };

        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
        match resp_res {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let resp_bytes_out = resp
                    .headers()
                    .get(header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or_else(|| resp.body().size_hint().lower());
                self.logger
                    .record_access_log(
                        "egress",
                        &hdr.service_tag,
                        client_ip,
                        status,
                        elapsed_ms,
                        req_bytes_in,
                        resp_bytes_out,
                        false,
                        false,
                        false,
                        if status >= 500 {
                            Some(format!("backend status {status}"))
                        } else {
                            None
                        },
                        None,
                        None,
                        None,
                        false,
                        make_meta("allow"),
                    )
                    .await;
                resp
            }
            Err((err_status, err_msg)) => {
                if let Some(suppressed) = self
                    .logger
                    .should_log_warn(&format!("egress:req_err:{}", hdr.service_tag))
                {
                    warn!(service = %hdr.service_tag, backend = %svc.backend, error = %err_msg, suppressed, "egress request failed");
                }
                self.logger.emit_alert("error", err_msg.clone()).await;
                self.logger
                    .record_access_log(
                        "egress",
                        &hdr.service_tag,
                        client_ip,
                        err_status.as_u16(),
                        elapsed_ms,
                        req_bytes_in,
                        0,
                        false,
                        false,
                        false,
                        Some(err_msg),
                        None,
                        None,
                        None,
                        false,
                        make_meta("upstream_error"),
                    )
                    .await;
                let (title, detail) = if err_status == StatusCode::GATEWAY_TIMEOUT {
                    ("Gateway Timeout", "The upstream server did not respond in time.")
                } else {
                    ("Bad Gateway", "The upstream server is temporarily unavailable.")
                };
                self.build_error_response(
                    err_status,
                    title,
                    detail,
                    svc.effective_intercept_errors(),
                    error_html_tpl,
                    &hdr.request_id,
                )
            }
        }
    }

    fn build_error_response(
        &self,
        status: StatusCode,
        title: &str,
        detail: &str,
        intercept: bool,
        error_html_tpl: Option<&str>,
        ray_id: &str,
    ) -> Response<ProxyBody> {
        if intercept {
            let html = exposure_core::assets::render_exposure_error_html_with_template(
                error_html_tpl,
                status.as_u16(),
                title,
                detail,
                ray_id,
                None,
            );
            return Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                .header(header::CACHE_CONTROL, "no-store")
                .header("x-exposure-ray", ray_id)
                .body(full_body(html))
                .unwrap();
        }
        Response::builder()
            .status(status)
            .header("x-exposure-ray", ray_id)
            .body(full_body(format!("{} {title}", status.as_u16())))
            .unwrap()
    }
}

/// Normalize an HTTP/2 or absolute-form request for HTTP/1.1 origin servers:
/// - Merge multiple `cookie` header fields into a single `Cookie` header joined by `"; "` (RFC 9113 §8.2.3).
/// - Ensure `Host` header is populated from URI authority if absent, and rewrite URI to origin-form (`/path?query`).
pub(crate) fn normalize_request_for_http1<B>(req: &mut Request<B>) {
    let cookie_vals: Vec<String> = req
        .headers()
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();
    if cookie_vals.len() > 1 {
        let merged = cookie_vals.join("; ");
        if let Ok(hv) = header::HeaderValue::from_str(&merged) {
            req.headers_mut().insert(header::COOKIE, hv);
        }
    }

    if req.uri().scheme().is_some() || req.uri().authority().is_some() {
        if !req.headers().contains_key(header::HOST) {
            if let Some(auth) = req.uri().authority() {
                if let Ok(hv) = header::HeaderValue::from_str(auth.as_str()) {
                    req.headers_mut().insert(header::HOST, hv);
                }
            }
        }
        let pq = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        if let Ok(origin_uri) = pq.parse() {
            *req.uri_mut() = origin_uri;
        }
    }
}

async fn forward_http_stream<S>(
    stream: S,
    mut req: Request<Incoming>,
    use_h2: bool,
    is_upgrade: bool,
    use_tls: bool,
    backend_addr: &str,
    timeout: Duration,
) -> std::result::Result<Response<ProxyBody>, (StatusCode, String)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if use_h2 {
        *req.version_mut() = http::Version::HTTP_2;
        strip_hop_by_hop_headers(req.headers_mut(), true, false);
        // Ensure :scheme and :authority are populated when upgrading HTTP/1.1 -> H2, and strip Host header
        // so HTTP/2 pseudo-header :authority is authoritative.
        if req.uri().scheme().is_none() || req.uri().authority().is_none() {
            let authority = req
                .headers()
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(backend_addr)
                .to_string();
            let path_q = req
                .uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/");
            let scheme = if use_tls { "https" } else { "http" };
            if let Ok(new_uri) = format!("{scheme}://{authority}{path_q}").parse() {
                *req.uri_mut() = new_uri;
            }
        }
        req.headers_mut().remove(header::HOST);

        let hs = tokio::time::timeout(
            timeout,
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream)),
        )
        .await;
        match hs {
            Ok(Ok((mut sender, conn))) => {
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                match tokio::time::timeout(timeout, sender.send_request(req)).await {
                    Ok(Ok(mut resp)) => {
                        strip_hop_by_hop_headers(resp.headers_mut(), true, false);
                        Ok(resp.map(|b| b.boxed()))
                    }
                    Ok(Err(e)) => Err((StatusCode::BAD_GATEWAY, format!("h2 upstream error: {e}"))),
                    Err(_) => Err((StatusCode::GATEWAY_TIMEOUT, "h2 upstream timeout".into())),
                }
            }
            Ok(Err(e)) => Err((StatusCode::BAD_GATEWAY, format!("h2 handshake failed: {e}"))),
            Err(_) => Err((StatusCode::GATEWAY_TIMEOUT, "h2 handshake timeout".into())),
        }
    } else {
        *req.version_mut() = http::Version::HTTP_11;
        normalize_request_for_http1(&mut req);
        strip_hop_by_hop_headers(req.headers_mut(), false, is_upgrade);
        let client_upgrade = if is_upgrade {
            Some(hyper::upgrade::on(&mut req))
        } else {
            None
        };

        let hs = tokio::time::timeout(
            timeout,
            hyper::client::conn::http1::Builder::new()
                .preserve_header_case(true)
                .handshake(TokioIo::new(stream)),
        )
        .await;
        match hs {
            Ok(Ok((mut sender, conn))) => {
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
                                        let _ = tokio::time::timeout(
                                            WS_IDLE_TIMEOUT,
                                            tokio::io::copy_bidirectional(&mut io_in, &mut io_out),
                                        )
                                        .await;
                                    }
                                });
                            }
                        } else {
                            strip_hop_by_hop_headers(resp.headers_mut(), false, false);
                        }
                        Ok(resp.map(|b| b.boxed()))
                    }
                    Ok(Err(e)) => Err((StatusCode::BAD_GATEWAY, format!("http1 upstream error: {e}"))),
                    Err(_) => Err((StatusCode::GATEWAY_TIMEOUT, "http1 upstream timeout".into())),
                }
            }
            Ok(Err(e)) => Err((StatusCode::BAD_GATEWAY, format!("http1 handshake failed: {e}"))),
            Err(_) => Err((StatusCode::GATEWAY_TIMEOUT, "http1 handshake timeout".into())),
        }
    }
}

fn build_backend_tls_client_config(
    insecure_skip_verify: bool,
    ca_cert_path: Option<&str>,
    offer_h2: bool,
) -> std::result::Result<ClientConfig, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut cfg = if insecure_skip_verify {
        let algos = rustls::crypto::ring::default_provider().signature_verification_algorithms;
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureBackendCertVerifier { algos }))
            .with_no_client_auth()
    } else {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(ca_path) = ca_cert_path {
            if !ca_path.trim().is_empty() {
                let ca_bytes = std::fs::read(ca_path)
                    .map_err(|e| format!("read backend ca_cert_path '{ca_path}': {e}"))?;
                let mut reader = BufReader::new(&ca_bytes[..]);
                let mut added = 0usize;
                for cert in rustls_pemfile::certs(&mut reader) {
                    let cert =
                        cert.map_err(|e| format!("parse backend CA cert '{ca_path}': {e}"))?;
                    root_store
                        .add(cert)
                        .map_err(|e| format!("add backend CA cert '{ca_path}': {e}"))?;
                    added += 1;
                }
                if added == 0 {
                    return Err(format!("no valid CA certificates found in '{ca_path}'"));
                }
            }
        }
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    cfg.alpn_protocols = if offer_h2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    Ok(cfg)
}

pub(crate) async fn connect_backend_tls(
    tcp: TcpStream,
    svc: &EgressServiceConfig,
    cfg: &Arc<ClientConfig>,
) -> std::result::Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let host = svc
        .backend
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(&svc.backend)
        .trim_matches(|c| c == '[' || c == ']');
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| format!("invalid backend TLS server name '{host}': {e}"))?;

    TlsConnector::from(Arc::clone(cfg))
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("tls handshake with backend {} failed: {e}", svc.backend))
}

/// Explicit opt-in verifier for `insecure_skip_verify: true`:
/// Skips server certificate chain/hostname validation ONLY, while STILL cryptographically verifying
/// TLS 1.2 & TLS 1.3 handshake signatures against the presented certificate's public key!
#[derive(Debug)]
struct InsecureBackendCertVerifier {
    algos: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for InsecureBackendCertVerifier {
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
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, cert, dss, &self.algos)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, cert, dss, &self.algos)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algos.supported_schemes()
    }
}
