use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use chrono::Utc;
use dashmap::DashMap;
use exposure_core::config::{IngressConfig, IngressListener};
use exposure_core::crypto::{
    generate_random_secret_hex, is_weak_secret, short_sha256_hex, NodeKeyPair,
};
use exposure_core::protocol::{ServiceStreamHeader, ServiceStreamProtocol};
use exposure_core::routing::{any_rule_matches_host, canonical_ip, match_ingress_rule, normalize_host};
use exposure_core::Result;
use http::{header, HeaderValue, Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Limited};
use hyper::body::{Body, Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use tokio::net::TcpListener;
use tokio::sync::{RwLock, Semaphore};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::egress::{full_body, strip_hop_by_hop_headers, ProxyBody};
use crate::forwarder::Forwarder;
use crate::guard::{compute_suspicion_score, sanitize_redirect, GuardDecision, GuardEngine};
use crate::logger::NodeLogger;
use crate::tls::{peek_client_hello, ClientHelloSignal, DynamicCertResolver};

const MAX_CONCURRENT_INGRESS_CONNS: usize = 4096;
const MAX_CONNS_PER_IP: usize = 128;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP1_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP1_MAX_HEADERS: usize = 100;
const HTTP1_MAX_BUF_SIZE: usize = 32 * 1024;
const HTTP2_MAX_HEADER_LIST_SIZE: u32 = 32 * 1024;
const HTTP2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
const HTTP2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(15);
const MESH_PROXY_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CDN_CGI_BODY_BYTES: usize = 4096;
const MAX_HTML_INJECT_BYTES: usize = 2 * 1024 * 1024;
const WS_IDLE_TIMEOUT: Duration = Duration::from_secs(3600);

struct PerIpConnGuard {
    map: Arc<DashMap<IpAddr, Arc<AtomicUsize>>>,
    ip: IpAddr,
    counter: Arc<AtomicUsize>,
}

impl PerIpConnGuard {
    fn try_acquire(map: &Arc<DashMap<IpAddr, Arc<AtomicUsize>>>, ip: IpAddr) -> Option<Self> {
        let counter = map
            .entry(ip)
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .clone();
        loop {
            let cur = counter.load(Ordering::Acquire);
            if cur >= MAX_CONNS_PER_IP {
                return None;
            }
            if counter
                .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(Self {
                    map: Arc::clone(map),
                    ip,
                    counter,
                });
            }
        }
    }
}

impl Drop for PerIpConnGuard {
    fn drop(&mut self) {
        if self.counter.fetch_sub(1, Ordering::AcqRel) == 1 {
            // Remove entry only if still zero so concurrent acquires don't race
            self.map.remove_if(&self.ip, |_, c| c.load(Ordering::Acquire) == 0);
        }
    }
}

fn ensure_strong_clearance_secret(mut cfg: IngressConfig, node_tag: &str) -> IngressConfig {
    if is_weak_secret(&cfg.clearance_secret) {
        warn!(
            node = %node_tag,
            "ingress clearance_secret missing or weak; generating ephemeral random secret"
        );
        cfg.clearance_secret = generate_random_secret_hex(32);
    }
    cfg
}

/// L7 Ingress Server (DESIGN.md §3.2, §8, §11):
/// - Supports HTTP/1.1, HTTP/2 (TLS ALPN `h2` & plaintext `h2c`), and WebSocket upgrades
/// - Dynamic SNI TLS termination using authoritative rustls SNI + pre-TLS ClientHello bot signal
/// - Rule matching by normalized Host, normalized URL prefix, canonical Source CIDR, authoritative SNI
/// - Entry Guard (CIDR, bounded token bucket rate limiting, fingerprint scoring, `/cdn-cgi/` single-use PoW)
/// - Signs `ServiceStreamHeader` with node Ed25519 key for multi-hop Egress ACL authentication
pub struct IngressServer {
    node_tag: String,
    keypair: NodeKeyPair,
    cfg: Arc<RwLock<Arc<IngressConfig>>>,
    default_ttl: u8,
    forwarder: Arc<Forwarder>,
    guard: Arc<GuardEngine>,
    cert_resolver: Arc<DynamicCertResolver>,
    logger: Arc<NodeLogger>,
    started_listeners: DashMap<String, JoinHandle<()>>,
    conn_sem: Arc<Semaphore>,
    per_ip_conns: Arc<DashMap<IpAddr, Arc<AtomicUsize>>>,
}

impl IngressServer {
    pub fn new(
        node_tag: impl Into<String>,
        keypair: NodeKeyPair,
        cfg: IngressConfig,
        default_ttl: u8,
        forwarder: Arc<Forwarder>,
        cert_resolver: Arc<DynamicCertResolver>,
        logger: Arc<NodeLogger>,
    ) -> Arc<Self> {
        let tag = node_tag.into();
        let cfg = ensure_strong_clearance_secret(cfg, &tag);
        Arc::new(Self {
            node_tag: tag,
            keypair,
            cfg: Arc::new(RwLock::new(Arc::new(cfg))),
            default_ttl,
            forwarder,
            guard: Arc::new(GuardEngine::new()),
            cert_resolver,
            logger,
            started_listeners: DashMap::new(),
            conn_sem: Arc::new(Semaphore::new(MAX_CONCURRENT_INGRESS_CONNS)),
            per_ip_conns: Arc::new(DashMap::new()),
        })
    }

    pub async fn update_config(
        self: &Arc<Self>,
        cfg: IngressConfig,
        ingress_enabled: bool,
    ) -> Result<()> {
        self.cert_resolver.load_from_files(&cfg.tls_certs)?;
        let cfg = ensure_strong_clearance_secret(cfg, &self.node_tag);
        let desired_listeners = if ingress_enabled {
            cfg.listeners.clone()
        } else {
            Vec::new()
        };
        *self.cfg.write().await = Arc::new(cfg);

        // Stop listeners that were removed or when ingress role is disabled
        let desired_keys: HashSet<String> = desired_listeners
            .iter()
            .map(|l| format!("{}|{}", l.listen_addr, l.tls))
            .collect();
        let existing_keys: Vec<String> = self
            .started_listeners
            .iter()
            .map(|e| e.key().clone())
            .collect();
        for k in existing_keys {
            if !desired_keys.contains(&k) {
                if let Some((_, handle)) = self.started_listeners.remove(&k) {
                    handle.abort();
                    info!(node = %self.node_tag, listener = %k, "stopped removed ingress listener");
                }
            }
        }

        // Start newly added listeners
        for l in desired_listeners {
            let key = format!("{}|{}", l.listen_addr, l.tls);
            if !self.started_listeners.contains_key(&key) {
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
        let handle = tokio::spawn(async move {
            loop {
                let (tcp, peer_addr) = match tcp_listener.accept().await {
                    Ok(pair) => pair,
                    Err(e) => {
                        warn!(error = %e, "ingress accept error");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let canon_ip = canonical_ip(peer_addr.ip());
                let ip_guard = match PerIpConnGuard::try_acquire(&this.per_ip_conns, canon_ip) {
                    Some(g) => g,
                    None => {
                        debug!(peer = %peer_addr, "ingress per-IP max connection limit reached, dropping");
                        continue;
                    }
                };
                let permit = match Arc::clone(&this.conn_sem).try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        debug!(peer = %peer_addr, "ingress max connection limit reached, dropping");
                        continue;
                    }
                };
                let _ = tcp.set_nodelay(true);
                let canon_addr = SocketAddr::new(canon_ip, peer_addr.port());
                let this2 = Arc::clone(&this);
                let acceptor2 = tls_acceptor.clone();

                tokio::spawn(async move {
                    let _permit = permit;
                    let _ip_guard = ip_guard;
                    if let Some(acceptor) = acceptor2 {
                        let mut hello_sig = peek_client_hello(&tcp).await;
                        match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await
                        {
                            Ok(Ok(tls_stream)) => {
                                // Always use authoritative rustls-negotiated SNI (never fragmented peek bytes!)
                                let auth_sni = tls_stream
                                    .get_ref()
                                    .1
                                    .server_name()
                                    .map(normalize_host);
                                hello_sig.sni = auth_sni.clone();
                                this2
                                    .serve_conn(
                                        tls_stream,
                                        canon_addr,
                                        true,
                                        auth_sni,
                                        Some(hello_sig),
                                    )
                                    .await;
                            }
                            Ok(Err(e)) => {
                                debug!(peer = %canon_addr, error = %e, "ingress TLS handshake failed");
                            }
                            Err(_) => {
                                debug!(peer = %canon_addr, "ingress TLS handshake timed out");
                            }
                        }
                    } else {
                        this2.serve_conn(tcp, canon_addr, false, None, None).await;
                    }
                });
            }
        });

        self.started_listeners.insert(key, handle);
        Ok(bound)
    }

    async fn serve_conn<S>(
        self: Arc<Self>,
        io_stream: S,
        peer_addr: SocketAddr,
        is_tls: bool,
        auth_sni: Option<String>,
        tls_signal: Option<ClientHelloSignal>,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let tls_sig_arc = Arc::new(tls_signal);
        let auth_sni_arc = Arc::new(auth_sni);
        let service = service_fn(move |req: Request<Incoming>| {
            let this2 = Arc::clone(&self);
            let sig2 = Arc::clone(&tls_sig_arc);
            let sni2 = Arc::clone(&auth_sni_arc);
            async move {
                Ok::<_, hyper::Error>(
                    this2
                        .handle_http_request(
                            req,
                            peer_addr,
                            is_tls,
                            sni2.as_deref(),
                            sig2.as_ref().as_ref(),
                        )
                        .await,
                )
            }
        });

        let io = TokioIo::new(io_stream);
        let mut builder = AutoServerBuilder::new(TokioExecutor::new());
        builder
            .http1()
            .timer(TokioTimer::new())
            .header_read_timeout(HTTP1_HEADER_READ_TIMEOUT)
            .max_headers(HTTP1_MAX_HEADERS)
            .max_buf_size(HTTP1_MAX_BUF_SIZE)
            .keep_alive(true);
        builder
            .http2()
            .timer(TokioTimer::new())
            .max_header_list_size(HTTP2_MAX_HEADER_LIST_SIZE)
            .keep_alive_interval(HTTP2_KEEP_ALIVE_INTERVAL)
            .keep_alive_timeout(HTTP2_KEEP_ALIVE_TIMEOUT);
        if let Err(e) = builder.serve_connection_with_upgrades(io, service).await {
            debug!(peer = %peer_addr, error = %e, "ingress connection closed");
        }
    }

    async fn handle_http_request(
        &self,
        req: Request<Incoming>,
        peer_addr: SocketAddr,
        is_tls: bool,
        auth_sni: Option<&str>,
        tls_signal: Option<&ClientHelloSignal>,
    ) -> Response<ProxyBody> {
        let cfg = Arc::clone(&*self.cfg.read().await);
        let mut resp = self
            .handle_http_request_inner(req, peer_addr, is_tls, auth_sni, tls_signal, &cfg)
            .await;
        if !cfg.server_header.trim().is_empty() {
            if let Ok(hv) = HeaderValue::from_str(cfg.server_header.trim()) {
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
        auth_sni: Option<&str>,
        tls_signal: Option<&ClientHelloSignal>,
        cfg: &IngressConfig,
    ) -> Response<ProxyBody> {
        let start = Instant::now();
        let ray_id: String = Uuid::new_v4().simple().to_string()[..16].to_string();

        // Reject requests where HTTP Host header and URI :authority disagree (prevents vhost confusion)
        let host = match extract_and_validate_host(&req, auth_sni) {
            Ok(h) => h,
            Err(msg) => {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(full_body(msg))
                    .unwrap();
            }
        };

        let path = req.uri().path().to_string();
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".into());
        let client_ip = canonical_ip(peer_addr.ip());

        // Built-in `/cdn-cgi` or `/cdn-cgi/*` PoW challenge endpoints (never matches `/cdn-cgi-foo`)
        if path == "/cdn-cgi" || path.starts_with("/cdn-cgi/") {
            let method = req.method().clone();
            let headers = req.headers().clone();
            let query_redirect = req
                .uri()
                .query()
                .and_then(|q| extract_query_param(q, "redirect"))
                .map(|r| sanitize_redirect(&r));

            // Strictly cap body reads BEFORE buffering to prevent pre-auth OOM DoS!
            let body_bytes = match Limited::new(req.into_body(), MAX_CDN_CGI_BODY_BYTES)
                .collect()
                .await
            {
                Ok(c) => c.to_bytes(),
                Err(_) => {
                    return Response::builder()
                        .status(StatusCode::PAYLOAD_TOO_LARGE)
                        .body(full_body("Payload Too Large"))
                        .unwrap();
                }
            };

            // Resolve the target route's GuardProfile (respects `url_prefix`-scoped guards!)
            let body_redirect = if method == http::Method::POST && path == "/cdn-cgi/verify" {
                serde_json::from_slice::<serde_json::Value>(&body_bytes)
                    .ok()
                    .and_then(|v| v.get("redirect").and_then(|r| r.as_str()).map(sanitize_redirect))
            } else {
                None
            };
            let target_path = body_redirect
                .or(query_redirect)
                .unwrap_or_else(|| "/".to_string());
            let target_path_only = target_path.split('?').next().unwrap_or("/");

            let matched_rule = match_ingress_rule(&cfg.rules, &host, target_path_only, client_ip, auth_sni)
                .or_else(|| match_ingress_rule(&cfg.rules, &host, "/", client_ip, auth_sni))
                .or_else(|| {
                    cfg.rules.iter().find(|r| {
                        r.r#match
                            .host
                            .as_deref()
                            .map(str::trim)
                            .filter(|pat| !pat.is_empty())
                            .map(|pat| exposure_core::routing::host_matches(pat, &host))
                            .unwrap_or(false)
                    })
                });
            if matched_rule.is_none() && !cfg.rules.is_empty() && !any_rule_matches_host(&cfg.rules, &host) {
                return Response::builder()
                    .status(StatusCode::MISDIRECTED_REQUEST)
                    .body(full_body("421 Misdirected Request"))
                    .unwrap();
            }
            let guard_profile = matched_rule
                .and_then(|r| r.guard.as_ref())
                .and_then(|g| cfg.guards.get(g));

            // Enforce CIDR policy on `/cdn-cgi/*`, and block PoW endpoints once the route bucket enters degraded mode
            if let Some(profile) = guard_profile {
                match self.guard.evaluate_access_cidrs(profile, client_ip) {
                    GuardDecision::Allow => {}
                    GuardDecision::RateLimited {
                        retry_after_secs,
                        show_error_page,
                    } => {
                        return build_rate_limit_response(
                            retry_after_secs,
                            show_error_page,
                            false,
                            &ray_id,
                            cfg.pages.error_html.as_deref(),
                        );
                    }
                    GuardDecision::Reject { status, .. } => {
                        return Response::builder()
                            .status(status)
                            .body(full_body("Access Denied"))
                            .unwrap();
                    }
                    GuardDecision::ChallengeRedirect { .. } => {}
                }
                if let Some(retry_after_secs) =
                    self.guard
                        .is_bucket_degraded(profile, &cfg.rate_limit_buckets, client_ip)
                {
                    return build_rate_limit_response(
                        retry_after_secs,
                        false,
                        false,
                        &ray_id,
                        cfg.pages.error_html.as_deref(),
                    );
                }
            }

            let (g_resp, verified_fp_sub) = self.guard.handle_cdn_cgi_with_pages(
                &method,
                &path,
                &body_bytes,
                &headers,
                &host,
                client_ip,
                is_tls,
                tls_signal,
                guard_profile,
                &cfg.clearance_secret,
                cfg.effective_js_fp_ttl_secs(),
                Some(&cfg.pages),
            );

            let passed = path == "/cdn-cgi/verify" && g_resp.status == StatusCode::OK;
            let ua_str = headers
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let al_str = headers
                .get(header::ACCEPT_LANGUAGE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let cfp_cls = crate::guard::classify_client(&headers);
            let score = compute_suspicion_score(&headers, tls_signal);

            if let Some(sub) = verified_fp_sub {
                let svc_tag = sub
                    .service_tag
                    .as_deref()
                    .or_else(|| matched_rule.map(|r| r.service_tag.as_str()))
                    .unwrap_or("_cdn_cgi");
                self.logger
                    .record_fingerprint(
                        svc_tag,
                        &host,
                        &client_ip.to_string(),
                        &sub.fp_hash,
                        true,
                        sub.fp_source,
                        ua_str,
                        al_str,
                        cfp_cls.device_type,
                        cfp_cls.browser_family,
                        cfp_cls.os_family,
                        cfp_cls.is_bot,
                        sub.is_headless,
                        score,
                        tls_signal.map(|s| s.cipher_count as u16).unwrap_or(0),
                        tls_signal.map(|s| s.has_alpn).unwrap_or(false),
                        Some(sub.js_fp),
                        if sub.fp_source == "pow" { 1 } else { 0 },
                        0,
                        0,
                    )
                    .await;
            }

            if passed {
                let svc_tag = matched_rule
                    .map(|r| r.service_tag.as_str())
                    .unwrap_or("_cdn_cgi");
                self.logger
                    .record_session_with_fp(
                        "ingress",
                        svc_tag,
                        &client_ip.to_string(),
                        200,
                        start.elapsed().as_secs_f64() * 1000.0,
                        0,
                        g_resp.body.len() as u64,
                        false,
                        false,
                        true,
                        None,
                        Some(cfp_cls.device_type.to_string()),
                        Some(cfp_cls.browser_family.to_string()),
                        Some(cfp_cls.os_family.to_string()),
                        true,
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
        let rule = match match_ingress_rule(&cfg.rules, &host, &path, client_ip, auth_sni) {
            Some(r) => r.clone(),
            None => {
                if !cfg.rules.is_empty() && !any_rule_matches_host(&cfg.rules, &host) {
                    return Response::builder()
                        .status(StatusCode::MISDIRECTED_REQUEST)
                        .body(full_body("421 Misdirected Request"))
                        .unwrap();
                }
                return Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(full_body("404 Not Found"))
                    .unwrap();
            }
        };

        let client_fp = crate::guard::classify_client(req.headers());
        let ua_str = req
            .headers()
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let al_str = req
            .headers()
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let suspicion_score = compute_suspicion_score(req.headers(), tls_signal);
        let fallback_fp_hash = short_sha256_hex(&format!("ua|{ua_str}|{al_str}"));

        let mut active_profile = None;
        // Evaluate Entry Guard if attached to this route (fail closed on undefined guard name!)
        if let Some(ref guard_name) = rule.guard {
            if !guard_name.trim().is_empty() {
                if let Some(profile) = cfg.guards.get(guard_name) {
                    active_profile = Some(profile);
                    match self.guard.evaluate(
                        profile,
                        &cfg.rate_limit_buckets,
                        &cfg.clearance_secret,
                        client_ip,
                        &host,
                        &path_and_query,
                        req.headers(),
                        tls_signal,
                    ) {
                        GuardDecision::Allow => {}
                        GuardDecision::RateLimited {
                            retry_after_secs,
                            show_error_page,
                        } => {
                            self.logger
                                .record_session_with_fp(
                                    "ingress",
                                    &rule.service_tag,
                                    &client_ip.to_string(),
                                    429,
                                    start.elapsed().as_secs_f64() * 1000.0,
                                    0,
                                    0,
                                    true,
                                    false,
                                    false,
                                    None,
                                    Some(client_fp.device_type.to_string()),
                                    Some(client_fp.browser_family.to_string()),
                                    Some(client_fp.os_family.to_string()),
                                    false,
                                )
                                .await;
                            self.logger
                                .record_fingerprint(
                                    &rule.service_tag,
                                    &host,
                                    &client_ip.to_string(),
                                    &fallback_fp_hash,
                                    false,
                                    "none",
                                    &ua_str,
                                    &al_str,
                                    client_fp.device_type,
                                    client_fp.browser_family,
                                    client_fp.os_family,
                                    client_fp.is_bot,
                                    false,
                                    suspicion_score,
                                    tls_signal.map(|s| s.cipher_count as u16).unwrap_or(0),
                                    tls_signal.map(|s| s.has_alpn).unwrap_or(false),
                                    None,
                                    1,
                                    0,
                                    1,
                                )
                                .await;
                            return build_rate_limit_response(
                                retry_after_secs,
                                show_error_page,
                                rule.effective_intercept_errors(),
                                &ray_id,
                                cfg.pages.error_html.as_deref(),
                            );
                        }
                        GuardDecision::Reject { status, reason } => {
                            self.logger
                                .record_session_with_fp(
                                    "ingress",
                                    &rule.service_tag,
                                    &client_ip.to_string(),
                                    status.as_u16(),
                                    start.elapsed().as_secs_f64() * 1000.0,
                                    0,
                                    0,
                                    false,
                                    true,
                                    false,
                                    Some(reason),
                                    Some(client_fp.device_type.to_string()),
                                    Some(client_fp.browser_family.to_string()),
                                    Some(client_fp.os_family.to_string()),
                                    false,
                                )
                                .await;
                            self.logger
                                .record_fingerprint(
                                    &rule.service_tag,
                                    &host,
                                    &client_ip.to_string(),
                                    &fallback_fp_hash,
                                    false,
                                    "none",
                                    &ua_str,
                                    &al_str,
                                    client_fp.device_type,
                                    client_fp.browser_family,
                                    client_fp.os_family,
                                    client_fp.is_bot,
                                    false,
                                    suspicion_score,
                                    tls_signal.map(|s| s.cipher_count as u16).unwrap_or(0),
                                    tls_signal.map(|s| s.has_alpn).unwrap_or(false),
                                    None,
                                    1,
                                    1,
                                    0,
                                )
                                .await;
                            return Response::builder()
                                .status(status)
                                .body(full_body("Access Denied"))
                                .unwrap();
                        }
                        GuardDecision::ChallengeRedirect { location } => {
                            if !is_browser_navigation(req.method(), req.headers()) {
                                self.logger
                                    .record_session_with_fp(
                                        "ingress",
                                        &rule.service_tag,
                                        &client_ip.to_string(),
                                        403,
                                        start.elapsed().as_secs_f64() * 1000.0,
                                        0,
                                        0,
                                        false,
                                        true,
                                        false,
                                        Some("verification_required".into()),
                                        Some(client_fp.device_type.to_string()),
                                        Some(client_fp.browser_family.to_string()),
                                        Some(client_fp.os_family.to_string()),
                                        false,
                                    )
                                    .await;
                                return Response::builder()
                                    .status(StatusCode::FORBIDDEN)
                                    .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
                                    .header(header::CACHE_CONTROL, "no-store")
                                    .body(full_body(r#"{"error":"verification_required"}"#))
                                    .unwrap();
                            }
                            self.logger
                                .record_session_with_fp(
                                    "ingress",
                                    &rule.service_tag,
                                    &client_ip.to_string(),
                                    302,
                                    start.elapsed().as_secs_f64() * 1000.0,
                                    0,
                                    0,
                                    false,
                                    true,
                                    false,
                                    None,
                                    Some(client_fp.device_type.to_string()),
                                    Some(client_fp.browser_family.to_string()),
                                    Some(client_fp.os_family.to_string()),
                                    false,
                                )
                                .await;
                            self.logger
                                .record_fingerprint(
                                    &rule.service_tag,
                                    &host,
                                    &client_ip.to_string(),
                                    &fallback_fp_hash,
                                    false,
                                    "none",
                                    &ua_str,
                                    &al_str,
                                    client_fp.device_type,
                                    client_fp.browser_family,
                                    client_fp.os_family,
                                    client_fp.is_bot,
                                    false,
                                    suspicion_score,
                                    tls_signal.map(|s| s.cipher_count as u16).unwrap_or(0),
                                    tls_signal.map(|s| s.has_alpn).unwrap_or(false),
                                    None,
                                    1,
                                    1,
                                    0,
                                )
                                .await;
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
                        "ingress rule references undefined guard profile; failing closed"
                    );
                    return Response::builder()
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .body(full_body("503 Service Unavailable"))
                        .unwrap();
                }
            }
        }

        let verified_info = self.guard.verified_fp_info(
            active_profile,
            &cfg.clearance_secret,
            &host,
            client_ip,
            req.headers(),
        );
        let fp_verified = verified_info.is_some();
        let (obs_fp_hash, obs_fp_source, obs_is_headless) = match verified_info {
            Some((h, src, hl)) => (h, src, hl),
            None => (fallback_fp_hash, "none", false),
        };

        let is_upgrade = req.headers().contains_key(header::UPGRADE);
        // Decide BEFORE upstream forwarding whether this single HTML navigation needs passive JS FP beacon injection
        let fp_inject_token = if self.guard.should_inject_fp_beacon(
            req.method(),
            is_upgrade,
            client_ip,
            &host,
            req.headers(),
            &cfg.clearance_secret,
            active_profile,
            cfg.effective_js_fp_beacon(),
            rule.js_fp_beacon,
        ) {
            // Request fresh uncompressed HTML from upstream for this single probe request only (once per TTL per browser)
            req.headers_mut().remove(header::ACCEPT_ENCODING);
            req.headers_mut().remove(header::IF_NONE_MATCH);
            req.headers_mut().remove(header::IF_MODIFIED_SINCE);
            Some(self.guard.mint_fp_token(
                &cfg.clearance_secret,
                &host,
                client_ip,
                req.headers(),
                &rule.service_tag,
            ))
        } else {
            None
        };

        // Strip untrusted client-supplied forwarding headers before injecting authoritative values
        for h in [
            "x-real-ip",
            "forwarded",
            "true-client-ip",
            "cf-connecting-ip",
            "x-forwarded-host",
            "x-forwarded-port",
        ] {
            req.headers_mut().remove(h);
        }
        if let Ok(hv) = HeaderValue::from_str(&client_ip.to_string()) {
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

        let use_h2_mesh = req.version() == Version::HTTP_2 && !is_upgrade;
        strip_hop_by_hop_headers(req.headers_mut(), use_h2_mesh, is_upgrade);

        let request_id = Uuid::new_v4().to_string();
        let now_ts = Utc::now().timestamp();
        let origin_signing = ServiceStreamHeader::origin_signing_bytes(
            &rule.service_tag,
            &self.node_tag,
            &request_id,
            now_ts,
        );
        let origin_signature = Some(self.keypair.sign_b64(&origin_signing));

        let stream_hdr = ServiceStreamHeader {
            service_tag: rule.service_tag.clone(),
            origin_node_tag: self.node_tag.clone(),
            ttl: self.default_ttl,
            hop_count: 0,
            request_id,
            client_ip: Some(client_ip.to_string()),
            is_tls,
            sni: auth_sni.map(|s| s.to_string()),
            protocol: if use_h2_mesh {
                ServiceStreamProtocol::H2
            } else {
                ServiceStreamProtocol::Http1
            },
            visited: vec![self.node_tag.clone()],
            timestamp: now_ts,
            origin_signature,
        };

        let mesh_stream = match tokio::time::timeout(
            MESH_PROXY_TIMEOUT,
            self.forwarder.open_service_stream(&rule.next_peer, stream_hdr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                let msg = format!(
                    "ingress forward to peer={} service={} failed: {}",
                    rule.next_peer, rule.service_tag, e
                );
                warn!("{msg}");
                self.logger
                    .record_session(
                        "ingress",
                        &rule.service_tag,
                        &client_ip.to_string(),
                        502,
                        start.elapsed().as_secs_f64() * 1000.0,
                        req_bytes_in,
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
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::GATEWAY_TIMEOUT)
                    .body(full_body("504 Gateway Time-out"))
                    .unwrap();
            }
        };

        let proxy_res: std::result::Result<Response<ProxyBody>, (StatusCode, String)> =
            if use_h2_mesh {
                *req.version_mut() = Version::HTTP_2;
                match tokio::time::timeout(
                    MESH_PROXY_TIMEOUT,
                    hyper::client::conn::http2::handshake(
                        TokioExecutor::new(),
                        TokioIo::new(mesh_stream),
                    ),
                )
                .await
                {
                    Ok(Ok((mut sender, conn))) => {
                        tokio::spawn(async move {
                            let _ = conn.await;
                        });
                        match tokio::time::timeout(MESH_PROXY_TIMEOUT, sender.send_request(req))
                            .await
                        {
                            Ok(Ok(resp)) => Ok(resp.map(|b| b.boxed())),
                            Ok(Err(e)) => {
                                Err((StatusCode::BAD_GATEWAY, format!("mesh h2 send: {e}")))
                            }
                            Err(_) => {
                                Err((StatusCode::GATEWAY_TIMEOUT, "mesh h2 request timed out".into()))
                            }
                        }
                    }
                    Ok(Err(e)) => Err((StatusCode::BAD_GATEWAY, format!("mesh h2 handshake: {e}"))),
                    Err(_) => {
                        Err((StatusCode::GATEWAY_TIMEOUT, "mesh h2 handshake timed out".into()))
                    }
                }
            } else {
                *req.version_mut() = Version::HTTP_11;
                let client_upg = if is_upgrade {
                    Some(hyper::upgrade::on(&mut req))
                } else {
                    None
                };
                match tokio::time::timeout(
                    MESH_PROXY_TIMEOUT,
                    hyper::client::conn::http1::Builder::new()
                        .preserve_header_case(true)
                        .handshake(TokioIo::new(mesh_stream)),
                )
                .await
                {
                    Ok(Ok((mut sender, conn))) => {
                        tokio::spawn(async move {
                            let _ = conn.with_upgrades().await;
                        });
                        match tokio::time::timeout(MESH_PROXY_TIMEOUT, sender.send_request(req))
                            .await
                        {
                            Ok(Ok(mut resp)) => {
                                if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
                                    if let Some(in_upg) = client_upg {
                                        let out_upg = hyper::upgrade::on(&mut resp);
                                        tokio::spawn(async move {
                                            if let Ok((u_in, u_out)) =
                                                tokio::try_join!(in_upg, out_upg)
                                            {
                                                let mut io_in = TokioIo::new(u_in);
                                                let mut io_out = TokioIo::new(u_out);
                                                let _ = tokio::time::timeout(
                                                    WS_IDLE_TIMEOUT,
                                                    tokio::io::copy_bidirectional(
                                                        &mut io_in,
                                                        &mut io_out,
                                                    ),
                                                )
                                                .await;
                                            }
                                        });
                                    }
                                }
                                Ok(resp.map(|b| b.boxed()))
                            }
                            Ok(Err(e)) => {
                                Err((StatusCode::BAD_GATEWAY, format!("mesh http1 send: {e}")))
                            }
                            Err(_) => Err((
                                StatusCode::GATEWAY_TIMEOUT,
                                "mesh http1 request timed out".into(),
                            )),
                        }
                    }
                    Ok(Err(e)) => {
                        Err((StatusCode::BAD_GATEWAY, format!("mesh http1 handshake: {e}")))
                    }
                    Err(_) => Err((
                        StatusCode::GATEWAY_TIMEOUT,
                        "mesh http1 handshake timed out".into(),
                    )),
                }
            };

        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        match proxy_res {
            Ok(mut resp) => {
                if let Some(ref fp_token) = fp_inject_token {
                    resp = maybe_inject_fp_beacon(resp, fp_token).await;
                }
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
                        &client_ip.to_string(),
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
                self.logger
                    .record_fingerprint(
                        &rule.service_tag,
                        &host,
                        &client_ip.to_string(),
                        &obs_fp_hash,
                        fp_verified,
                        obs_fp_source,
                        &ua_str,
                        &al_str,
                        client_fp.device_type,
                        client_fp.browser_family,
                        client_fp.os_family,
                        client_fp.is_bot,
                        obs_is_headless,
                        suspicion_score,
                        tls_signal.map(|s| s.cipher_count as u16).unwrap_or(0),
                        tls_signal.map(|s| s.has_alpn).unwrap_or(false),
                        None,
                        1,
                        0,
                        0,
                    )
                    .await;
                resp
            }
            Err((err_status, err)) => {
                warn!(ray_id = %ray_id, service = %rule.service_tag, error = %err, "ingress proxy error");
                self.logger
                    .record_session(
                        "ingress",
                        &rule.service_tag,
                        &client_ip.to_string(),
                        err_status.as_u16(),
                        latency_ms,
                        req_bytes_in,
                        0,
                        false,
                        false,
                        false,
                        Some(err),
                    )
                    .await;
                let (title, detail) = if err_status == StatusCode::GATEWAY_TIMEOUT {
                    ("Gateway Timeout", "The upstream server did not respond in time.")
                } else {
                    ("Bad Gateway", "The upstream server is temporarily unavailable.")
                };
                if rule.effective_intercept_errors() {
                    let html = exposure_core::assets::render_exposure_error_html_with_template(
                        cfg.pages.error_html.as_deref(),
                        err_status.as_u16(),
                        title,
                        detail,
                        &ray_id,
                        None,
                    );
                    return Response::builder()
                        .status(err_status)
                        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                        .header(header::CACHE_CONTROL, "no-store")
                        .body(full_body(html))
                        .unwrap();
                }
                Response::builder()
                    .status(err_status)
                    .body(full_body(format!("{} {title}", err_status.as_u16())))
                    .unwrap()
            }
        }
    }
}

/// Pass-through body wrapper prepending already-buffered bytes ahead of an unconsumed stream.
struct PrefixBody {
    prefix: Option<Bytes>,
    rest: ProxyBody,
}

impl Body for PrefixBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        if let Some(buf) = self.prefix.take() {
            if !buf.is_empty() {
                return Poll::Ready(Some(Ok(Frame::data(buf))));
            }
        }
        Pin::new(&mut self.rest).poll_frame(cx)
    }
}

/// Inject `<script defer src="/cdn-cgi/fp.js" data-t="..."></script>` into eligible uncompressed 2xx HTML responses.
/// Safely passes through oversized or non-HTML responses untouched.
async fn maybe_inject_fp_beacon(resp: Response<ProxyBody>, fp_token: &str) -> Response<ProxyBody> {
    if !resp.status().is_success()
        || resp.status() == StatusCode::NO_CONTENT
        || resp.status() == StatusCode::RESET_CONTENT
    {
        return resp;
    }
    let is_safe_html = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| {
            let ct_l = ct.to_ascii_lowercase();
            ct_l.starts_with("text/html")
                && !ct_l.contains("utf-16")
                && !ct_l.contains("utf-32")
        })
        .unwrap_or(false);
    if !is_safe_html {
        return resp;
    }
    let is_uncompressed = resp
        .headers()
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|ce| ce.trim().is_empty() || ce.eq_ignore_ascii_case("identity"))
        .unwrap_or(true);
    if !is_uncompressed {
        return resp;
    }
    if let Some(cl) = resp
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
    {
        if cl > MAX_HTML_INJECT_BYTES {
            return resp;
        }
    }

    let (mut parts, mut body) = resp.into_parts();
    let mut collected = Vec::new();
    let mut exceeded = false;
    while let Some(frame_res) = body.frame().await {
        match frame_res {
            Ok(frame) => {
                if let Some(data) = frame.data_ref() {
                    collected.extend_from_slice(data);
                    if collected.len() > MAX_HTML_INJECT_BYTES {
                        exceeded = true;
                        break;
                    }
                }
            }
            Err(_) => {
                return Response::from_parts(parts, full_body(collected));
            }
        }
    }

    if exceeded {
        let chained = PrefixBody {
            prefix: Some(Bytes::from(collected)),
            rest: body,
        };
        return Response::from_parts(parts, chained.boxed());
    }

    let snippet = format!(
        r#"<script defer src="/cdn-cgi/fp.js" data-t="{fp_token}"></script>"#
    );
    let injected = inject_script_into_html(&collected, snippet.as_bytes());
    parts.headers.remove(header::ETAG);
    parts.headers.remove(header::LAST_MODIFIED);
    parts.headers.remove(header::EXPIRES);
    parts.headers.remove(header::TRANSFER_ENCODING);
    if let Ok(hv) = HeaderValue::from_str(&injected.len().to_string()) {
        parts.headers.insert(header::CONTENT_LENGTH, hv);
    }
    // Use `no-store` so browsers NEVER cache HTML containing a single-use `data-t` token
    // (otherwise reload -> 304 Not Modified replays the spent token and triggers 403).
    parts.headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    Response::from_parts(parts, full_body(injected))
}

fn rfind_ascii_case_insensitive(haystack: &[u8], needle_lower: &[u8]) -> Option<usize> {
    if needle_lower.is_empty() || haystack.len() < needle_lower.len() {
        return None;
    }
    haystack
        .windows(needle_lower.len())
        .rposition(|w| w.iter().zip(needle_lower).all(|(a, b)| a.to_ascii_lowercase() == *b))
}

fn inject_script_into_html(html: &[u8], snippet: &[u8]) -> Vec<u8> {
    // Search backwards for the FINAL `</body>` (or `</head>`) so literal `"</body>"` inside
    // inline `<script>` blocks or HTML comments earlier in the document is never corrupted.
    let pos = rfind_ascii_case_insensitive(html, b"</body>")
        .or_else(|| rfind_ascii_case_insensitive(html, b"</head>"))
        .unwrap_or(html.len());
    let mut out = Vec::with_capacity(html.len() + snippet.len());
    out.extend_from_slice(&html[..pos]);
    out.extend_from_slice(snippet);
    out.extend_from_slice(&html[pos..]);
    out
}

fn extract_and_validate_host(
    req: &Request<Incoming>,
    sni: Option<&str>,
) -> std::result::Result<String, &'static str> {
    let hdr_host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let uri_auth = req.uri().authority().map(|a| a.as_str());

    if let (Some(h), Some(a)) = (hdr_host, uri_auth) {
        if normalize_host(h) != normalize_host(a) {
            return Err("400 Bad Request: Host and authority mismatch");
        }
    }
    if let Some(h) = hdr_host {
        if normalize_host(h).is_empty() {
            return Err("400 Bad Request: Invalid Host header");
        }
        return Ok(h.to_string());
    }
    if let Some(a) = uri_auth {
        if normalize_host(a).is_empty() {
            return Err("400 Bad Request: Invalid authority");
        }
        return Ok(a.to_string());
    }
    Ok(sni.unwrap_or("").to_string())
}

fn extract_query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(percent_decode_simple(v));
            }
        }
    }
    None
}

fn percent_decode_simple(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn build_rate_limit_response(
    retry_after_secs: u64,
    show_error_page: bool,
    intercept_errors: bool,
    ray_id: &str,
    error_html_template: Option<&str>,
) -> Response<ProxyBody> {
    if intercept_errors && show_error_page {
        let html = exposure_core::assets::render_exposure_error_html_with_template(
            error_html_template,
            429,
            "Too Many Requests",
            "Rate limit exceeded. Please try again shortly.",
            ray_id,
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
    let body = if show_error_page {
        "Too Many Requests"
    } else {
        "429"
    };
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header(header::RETRY_AFTER, retry_after_secs.to_string())
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(full_body(body))
        .unwrap()
}

fn is_browser_navigation(method: &http::Method, headers: &http::HeaderMap) -> bool {
    if method != http::Method::GET && method != http::Method::HEAD {
        return false;
    }
    if let Some(xrw) = headers.get("x-requested-with").and_then(|v| v.to_str().ok()) {
        if xrw.eq_ignore_ascii_case("xmlhttprequest") {
            return false;
        }
    }
    if let Some(mode) = headers.get("sec-fetch-mode").and_then(|v| v.to_str().ok()) {
        return mode.eq_ignore_ascii_case("navigate");
    }
    if let Some(dest) = headers.get("sec-fetch-dest").and_then(|v| v.to_str().ok()) {
        return dest.eq_ignore_ascii_case("document");
    }
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    accept.contains("text/html") || accept.is_empty() || accept == "*/*"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_injection_targets_last_closing_body_tag() {
        let html = b"<html><body><script>var s = '</body>';</script><p>ok</p></body></html>";
        let out = inject_script_into_html(html, b"<script src=\"/cdn-cgi/fp.js\"></script>");
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("<script>var s = '</body>';</script>"));
        assert!(s.ends_with("<p>ok</p><script src=\"/cdn-cgi/fp.js\"></script></body></html>"));
    }

    #[tokio::test]
    async fn rate_limit_response_degrades_after_initial_error_pages() {
        let html_resp = build_rate_limit_response(5, true, true, "ray1", None);
        assert_eq!(html_resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            html_resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        let html_bytes = html_resp.into_body().collect().await.unwrap().to_bytes();
        let html_str = String::from_utf8(html_bytes.to_vec()).unwrap();
        assert!(html_str.contains("<!DOCTYPE html>"));

        let custom_resp = build_rate_limit_response(
            5,
            true,
            true,
            "rayc",
            Some("<html>custom {{status}} {{ray_id}}</html>"),
        );
        let custom_bytes = custom_resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            String::from_utf8(custom_bytes.to_vec()).unwrap(),
            "<html>custom 429 rayc</html>"
        );

        let degraded_resp = build_rate_limit_response(5, false, true, "ray2", None);
        assert_eq!(degraded_resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            degraded_resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        let degraded_bytes = degraded_resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&degraded_bytes[..], b"429");
    }
}
