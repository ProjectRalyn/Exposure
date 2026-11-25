use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use chrono::Utc;
use dashmap::DashMap;
use evilpot::ExploitVerificationStatus;
use exposure_core::Result;
use exposure_core::config::{
    AbuseIpDbAction, GeoRuleAction, GuardProfile, IngressConfig, IngressListener, WafConfig,
    WafMode,
};
use exposure_core::crypto::{
    NodeKeyPair, generate_random_secret_hex, is_weak_secret, short_sha256_hex,
};
use exposure_core::geoip::{GeoDecision, evaluate_geo_policy};
use exposure_core::protocol::{ServiceStreamHeader, ServiceStreamProtocol};
use exposure_core::routing::{
    any_rule_matches_host, canonical_ip, is_public_routable_ip, match_ingress_rule, normalize_host,
    parse_valid_host,
};
use exposure_core::telemetry::EvilpotNodeReport;
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode, Version, header};
use http_body_util::{BodyExt, Limited};
use hyper::body::{Body, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, RwLock, Semaphore};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::abuseipdb::AbuseIpDbClient;
use crate::ban::{AutoBanManager, OffenseContext, OffenseKind};
use crate::cache::{
    CacheLookup, CachedEntry, EdgeCache, EffectiveCachePolicy, build_response_from_cache,
};
use crate::egress::{
    INTERNAL_UPSTREAM_ERR_HEADER, PrefixBody, ProxyBody, RAY_ID_HEADER, attach_ray_id_header,
    capture_5xx_response_error, full_body, status_title_and_detail, strip_hop_by_hop_headers,
};
use crate::forwarder::Forwarder;
use crate::geoip::GeoIpManager;
use crate::guard::{
    ClientFingerprint, GuardDecision, GuardEngine, compute_server_suspicion_score_for_mode,
    compute_suspicion_score, matches_api_bypass, sanitize_redirect,
};
use crate::honeypot::{
    EVILPOT_HANDLE_TIMEOUT, EvilpotManager, MAX_EVILPOT_PATH_CHARS, MAX_EVILPOT_QUERY_CHARS,
    TarpitBanHook, build_attack_signal, clamp_input_slice, into_proxy_response_with_ban_hook,
    session_report_to_info, trap_outcome_to_event_info, verification_status_label,
};
use crate::logger::{AccessLogMeta, FpServerExtras, NodeLogger};
use crate::tls::{ClientHelloSignal, DynamicCertResolver, peek_client_hello};
use crate::waf::{CompiledCrsEngine, WafFinding, WafVerdict, is_path_exempt, should_inspect_body};

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
const WAF_BODY_READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CDN_CGI_BODY_BYTES: usize = 8192;
const MAX_HTML_INJECT_BYTES: usize = 2 * 1024 * 1024;
/// Global cap on concurrently buffered cacheable responses & HTML beacon injections.
/// Each buffer may hold up to `cache.max_object_bytes` (default 4 MiB), so this bounds worst-case
/// transient memory instead of letting it scale with `MAX_CONCURRENT_INGRESS_CONNS`.
const MAX_CONCURRENT_RESPONSE_BUFFERS: usize = 256;
/// Global cap on concurrently buffered WAF request body prefixes (default 32 KiB each -> <= 16 MiB).
const MAX_CONCURRENT_WAF_BODY_BUFFERS: usize = 512;
const WS_IDLE_TIMEOUT: Duration = Duration::from_secs(3600);

pub fn node_bans_path(dir: &Path, node_tag: &str) -> PathBuf {
    let safe: String = node_tag
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    let tag = if safe.is_empty() || safe.contains("..") {
        "node"
    } else {
        &safe
    };
    dir.join(format!("node-bans-{tag}.json"))
}

struct PerIpConnGuard {
    map: Arc<DashMap<IpAddr, usize>>,
    ip: IpAddr,
}

impl PerIpConnGuard {
    fn try_acquire(map: &Arc<DashMap<IpAddr, usize>>, ip: IpAddr) -> Option<Self> {
        let mut entry = map.entry(ip).or_insert(0);
        if *entry >= MAX_CONNS_PER_IP {
            return None;
        }
        *entry += 1;
        drop(entry);
        Some(Self {
            map: Arc::clone(map),
            ip,
        })
    }
}

impl Drop for PerIpConnGuard {
    fn drop(&mut self) {
        if let dashmap::mapref::entry::Entry::Occupied(mut e) = self.map.entry(self.ip) {
            let val = *e.get();
            if val <= 1 {
                e.remove();
            } else {
                *e.get_mut() = val - 1;
            }
        }
    }
}

struct ConnPermits {
    _conn: OwnedSemaphorePermit,
    _ip: PerIpConnGuard,
}

fn ensure_strong_clearance_secret(
    mut cfg: IngressConfig,
    node_tag: &str,
    prev_secret: Option<&str>,
) -> IngressConfig {
    if is_weak_secret(&cfg.clearance_secret) {
        if let Some(prev) = prev_secret.filter(|s| !is_weak_secret(s)) {
            cfg.clearance_secret = prev.to_string();
        } else {
            warn!(
                node = %node_tag,
                "ingress clearance_secret missing or weak; generating ephemeral random secret"
            );
            cfg.clearance_secret = generate_random_secret_hex(32);
        }
    }
    cfg
}

struct RequestLogCtx<'a> {
    ray_id: &'a str,
    method: &'a str,
    host: &'a str,
    path: &'a str,
    query: Option<&'a str>,
    protocol: &'a str,
    scheme: &'a str,
    user_agent: &'a str,
    referer: Option<&'a str>,
    tls_ja3: Option<&'a str>,
    suspicion_score: Option<u8>,
    client_country: Option<&'a str>,
}

impl<'a> RequestLogCtx<'a> {
    fn meta(
        &self,
        action: &'static str,
        cache_status: Option<&'a str>,
        waf_rule_id: Option<u32>,
        waf_category: Option<&'a str>,
    ) -> AccessLogMeta<'_> {
        AccessLogMeta {
            ray_id: Some(self.ray_id),
            method: Some(self.method),
            host: Some(self.host),
            path: Some(self.path),
            query: self.query,
            protocol: Some(self.protocol),
            scheme: Some(self.scheme),
            user_agent: Some(self.user_agent),
            referer: self.referer,
            action: Some(action),
            cache_status,
            tls_ja3: self.tls_ja3,
            waf_rule_id,
            waf_category,
            suspicion_score: self.suspicion_score,
            client_country: self.client_country,
        }
    }
}

pub struct IngressServer {
    node_tag: String,
    keypair: NodeKeyPair,
    cfg: Arc<RwLock<Arc<IngressConfig>>>,
    default_ttl: AtomicU8,
    forwarder: Arc<Forwarder>,
    guard: Arc<GuardEngine>,
    cache: Arc<EdgeCache>,
    evilpot: Arc<EvilpotManager>,
    auto_ban: Arc<AutoBanManager>,
    abuseipdb: Arc<AbuseIpDbClient>,
    geoip: Arc<GeoIpManager>,
    crs: Arc<RwLock<Arc<CompiledCrsEngine>>>,
    cert_resolver: Arc<DynamicCertResolver>,
    logger: Arc<NodeLogger>,
    started_listeners: DashMap<String, JoinHandle<()>>,
    conn_sem: Arc<Semaphore>,
    buffer_sem: Arc<Semaphore>,
    waf_body_sem: Arc<Semaphore>,
    per_ip_conns: Arc<DashMap<IpAddr, usize>>,
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
        let cfg = ensure_strong_clearance_secret(cfg, &tag, None);
        let abuseipdb = AbuseIpDbClient::new(cfg.abuseipdb.clone());
        Self::new_with_abuseipdb(
            tag,
            keypair,
            cfg,
            default_ttl,
            forwarder,
            cert_resolver,
            logger,
            abuseipdb,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_abuseipdb(
        node_tag: impl Into<String>,
        keypair: NodeKeyPair,
        cfg: IngressConfig,
        default_ttl: u8,
        forwarder: Arc<Forwarder>,
        cert_resolver: Arc<DynamicCertResolver>,
        logger: Arc<NodeLogger>,
        abuseipdb: Arc<AbuseIpDbClient>,
    ) -> Arc<Self> {
        let tag = node_tag.into();
        let cache = Arc::new(EdgeCache::new(
            cfg.cache.max_memory_bytes,
            cfg.cache.max_entries,
        ));
        let evilpot = Arc::new(EvilpotManager::new(tag.clone()));
        let auto_ban = Arc::new(AutoBanManager::new(&cfg.auto_ban));
        let bans_path = node_bans_path(&logger.segment_dir(), &tag);
        match auto_ban.load_from_file(&bans_path) {
            Ok(n) if n > 0 => {
                info!(node = %tag, loaded_bans = n, path = %bans_path.display(), "restored persisted auto-ban entries from disk")
            }
            Ok(_) => {}
            Err(e) => {
                warn!(node = %tag, error = %e, path = %bans_path.display(), "failed to restore persisted auto-ban entries")
            }
        }
        let geoip = GeoIpManager::new(cfg.geoip.clone(), logger.segment_dir().join("geoip"));
        let crs = Arc::new(CompiledCrsEngine::compile(
            &cfg.crs_rules,
            &cfg.crs.disabled_rule_ids,
        ));
        // Read the configured single-file pages into memory once, up front.
        let mut cfg = cfg;
        cfg.resolved_pages = cfg.pages.resolve();
        Arc::new(Self {
            node_tag: tag,
            keypair,
            cfg: Arc::new(RwLock::new(Arc::new(cfg))),
            default_ttl: AtomicU8::new(default_ttl),
            forwarder,
            guard: Arc::new(GuardEngine::new()),
            cache,
            evilpot,
            auto_ban,
            abuseipdb,
            geoip,
            crs: Arc::new(RwLock::new(crs)),
            cert_resolver,
            logger,
            started_listeners: DashMap::new(),
            conn_sem: Arc::new(Semaphore::new(MAX_CONCURRENT_INGRESS_CONNS)),
            buffer_sem: Arc::new(Semaphore::new(MAX_CONCURRENT_RESPONSE_BUFFERS)),
            waf_body_sem: Arc::new(Semaphore::new(MAX_CONCURRENT_WAF_BODY_BUFFERS)),
            per_ip_conns: Arc::new(DashMap::new()),
        })
    }

    pub fn update_default_ttl(&self, ttl: u8) {
        self.default_ttl.store(ttl.max(1), Ordering::Relaxed);
    }

    pub fn edge_cache(&self) -> &Arc<EdgeCache> {
        &self.cache
    }

    pub fn auto_ban(&self) -> &Arc<AutoBanManager> {
        &self.auto_ban
    }

    pub fn bans_file_path(&self) -> PathBuf {
        node_bans_path(&self.logger.segment_dir(), &self.node_tag)
    }

    pub fn persist_active_bans_async(&self) {
        let ab = Arc::clone(&self.auto_ban);
        let path = self.bans_file_path();
        if let Ok(h) = tokio::runtime::Handle::try_current() {
            h.spawn_blocking(move || {
                if let Err(e) = ab.save_to_file(&path) {
                    warn!(error = %e, path = %path.display(), "failed to persist auto-ban snapshot");
                }
            });
        }
    }

    pub fn persist_active_bans_blocking(&self) -> Result<()> {
        self.auto_ban.save_to_file(&self.bans_file_path())
    }

    pub fn geoip(&self) -> &Arc<GeoIpManager> {
        &self.geoip
    }

    pub async fn evilpot_report(&self) -> Option<EvilpotNodeReport> {
        self.evilpot
            .build_report_with_bans(Some(&self.auto_ban))
            .await
    }

    pub async fn update_config(
        self: &Arc<Self>,
        cfg: IngressConfig,
        ingress_enabled: bool,
    ) -> Result<()> {
        self.cert_resolver.load_from_files(&cfg.tls_certs)?;
        let prev_secret = self.cfg.read().await.clearance_secret.clone();
        let mut cfg = ensure_strong_clearance_secret(cfg, &self.node_tag, Some(&prev_secret));
        cfg.resolved_pages = cfg.pages.resolve();
        let any_cache_enabled = ingress_enabled
            && (cfg.cache.enabled
                || cfg
                    .rules
                    .iter()
                    .any(|r| r.cache.as_ref().and_then(|c| c.enabled) == Some(true)));
        self.cache.reconfigure(
            cfg.cache.max_memory_bytes,
            cfg.cache.max_entries,
            !any_cache_enabled,
        );
        let any_evilpot_enabled = ingress_enabled
            && (cfg.guards.values().any(|g| {
                g.waf
                    .as_ref()
                    .map(|w| w.mode == WafMode::Evilpot)
                    .unwrap_or(false)
                    || g.geo
                        .as_ref()
                        .map(|gp| {
                            gp.enabled
                                && (gp.deny_action == GeoRuleAction::Evilpot
                                    || gp.default_action == GeoRuleAction::Evilpot
                                    || gp.unknown_action == GeoRuleAction::Evilpot
                                    || gp.rules.iter().any(|r| r.action == GeoRuleAction::Evilpot))
                        })
                        .unwrap_or(false)
            }) || (cfg.abuseipdb.enabled
                && cfg.abuseipdb.high_risk_action == AbuseIpDbAction::Evilpot));
        self.evilpot
            .reconfigure(&cfg.evilpot, &cfg.server_header, any_evilpot_enabled)
            .await;
        self.auto_ban.reconfigure(&cfg.auto_ban);
        self.abuseipdb.reconfigure(cfg.abuseipdb.clone()).await;
        self.geoip
            .update_config(cfg.geoip.clone(), self.logger.segment_dir().join("geoip"))
            .await;
        let rules_for_compile = cfg.crs_rules.clone();
        let disabled_for_compile = cfg.crs.disabled_rule_ids.clone();
        let compiled_crs = tokio::task::spawn_blocking(move || {
            Arc::new(CompiledCrsEngine::compile(
                &rules_for_compile,
                &disabled_for_compile,
            ))
        })
        .await
        .map_err(|e| {
            exposure_core::ExposureError::Config(format!("compile CRS join failed: {e}"))
        })?;
        *self.crs.write().await = compiled_crs;
        let desired_listeners = if ingress_enabled {
            cfg.listeners.clone()
        } else {
            Vec::new()
        };
        *self.cfg.write().await = Arc::new(cfg);

        // Stop listeners that were removed or when ingress role is disabled, awaiting handle shutdown
        // so quick port re-binds on hot reload do not race into EADDRINUSE.
        let desired_keys: HashSet<String> = desired_listeners
            .iter()
            .map(|l| format!("{}|{}|{}", l.listen_addr, l.tls, l.redirect_https))
            .collect();
        let existing_keys: Vec<String> = self
            .started_listeners
            .iter()
            .map(|e| e.key().clone())
            .collect();
        let mut stopped_handles = Vec::new();
        for k in existing_keys {
            if !desired_keys.contains(&k) {
                if let Some((_, handle)) = self.started_listeners.remove(&k) {
                    handle.abort();
                    stopped_handles.push(handle);
                    info!(node = %self.node_tag, listener = %k, "stopped removed ingress listener");
                }
            }
        }
        for h in stopped_handles {
            let _ = tokio::time::timeout(Duration::from_millis(500), h).await;
        }

        // Start newly added listeners
        for l in desired_listeners {
            let key = format!("{}|{}|{}", l.listen_addr, l.tls, l.redirect_https);
            if !self.started_listeners.contains_key(&key) {
                if let Err(e) = self.start_listener(l.clone()).await {
                    warn!(addr = %l.listen_addr, error = %e, "failed to start newly added ingress listener on hot reload");
                }
            }
        }
        Ok(())
    }

    pub async fn start_listener(
        self: &Arc<Self>,
        listener_cfg: IngressListener,
    ) -> Result<SocketAddr> {
        let key = format!(
            "{}|{}|{}",
            listener_cfg.listen_addr, listener_cfg.tls, listener_cfg.redirect_https
        );
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
                if this.auto_ban.is_ip_banned_for_tcp(canon_ip) {
                    debug!(peer = %peer_addr, "ingress dropped confirmed-banned IP at TCP accept");
                    continue;
                }
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
                let redirect_https = !listener_cfg.tls && listener_cfg.redirect_https;
                let conn_permits = Arc::new(ConnPermits {
                    _conn: permit,
                    _ip: ip_guard,
                });

                tokio::spawn(async move {
                    if let Some(acceptor) = acceptor2 {
                        let mut hello_sig = peek_client_hello(&tcp).await;
                        match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp))
                            .await
                        {
                            Ok(Ok(tls_stream)) => {
                                // Always use authoritative rustls-negotiated SNI (never fragmented peek bytes!)
                                let auth_sni =
                                    tls_stream.get_ref().1.server_name().map(normalize_host);
                                hello_sig.sni = auth_sni.clone();
                                this2
                                    .serve_conn_with_permits(
                                        tls_stream,
                                        canon_addr,
                                        true,
                                        false,
                                        auth_sni,
                                        Some(hello_sig),
                                        Some(conn_permits),
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
                        this2
                            .serve_conn_with_permits(
                                tcp,
                                canon_addr,
                                false,
                                redirect_https,
                                None,
                                None,
                                Some(conn_permits),
                            )
                            .await;
                    }
                });
            }
        });

        self.started_listeners.insert(key, handle);
        Ok(bound)
    }

    #[cfg(test)]
    async fn serve_conn<S>(
        self: Arc<Self>,
        io_stream: S,
        peer_addr: SocketAddr,
        is_tls: bool,
        redirect_https: bool,
        auth_sni: Option<String>,
        tls_signal: Option<ClientHelloSignal>,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        self.serve_conn_with_permits(
            io_stream,
            peer_addr,
            is_tls,
            redirect_https,
            auth_sni,
            tls_signal,
            None,
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn serve_conn_with_permits<S>(
        self: Arc<Self>,
        io_stream: S,
        peer_addr: SocketAddr,
        is_tls: bool,
        redirect_https: bool,
        auth_sni: Option<String>,
        tls_signal: Option<ClientHelloSignal>,
        conn_permits: Option<Arc<ConnPermits>>,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let tls_sig_arc = Arc::new(tls_signal);
        let auth_sni_arc = Arc::new(auth_sni);
        let service = service_fn(move |req: Request<Incoming>| {
            let this2 = Arc::clone(&self);
            let sig2 = Arc::clone(&tls_sig_arc);
            let sni2 = Arc::clone(&auth_sni_arc);
            let permits2 = conn_permits.clone();
            async move {
                Ok::<_, hyper::Error>(
                    this2
                        .handle_http_request(
                            req,
                            peer_addr,
                            is_tls,
                            redirect_https,
                            sni2.as_deref(),
                            sig2.as_ref().as_ref(),
                            permits2,
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

    #[allow(clippy::too_many_arguments)]
    async fn handle_http_request(
        &self,
        req: Request<Incoming>,
        peer_addr: SocketAddr,
        is_tls: bool,
        redirect_https: bool,
        auth_sni: Option<&str>,
        tls_signal: Option<&ClientHelloSignal>,
        conn_permits: Option<Arc<ConnPermits>>,
    ) -> Response<ProxyBody> {
        let cfg = Arc::clone(&*self.cfg.read().await);
        let mut resp = self
            .handle_http_request_inner(
                req,
                peer_addr,
                is_tls,
                redirect_https,
                auth_sni,
                tls_signal,
                &cfg,
                conn_permits,
            )
            .await;
        if !cfg.server_header.trim().is_empty() {
            if let Ok(hv) = HeaderValue::from_str(cfg.server_header.trim()) {
                resp.headers_mut().insert(header::SERVER, hv);
            }
        }
        resp
    }

    #[allow(clippy::too_many_arguments)]
    async fn record_offense_and_maybe_alert(
        &self,
        service_tag: &str,
        host: &str,
        client_ip: IpAddr,
        tls_ja3: Option<&str>,
        ua_str: &str,
        js_fp_hash: Option<&str>,
        kind: OffenseKind,
        reason: &str,
    ) {
        let mut out = self.auto_ban.record_offense(OffenseContext {
            client_ip,
            tls_ja3,
            user_agent: ua_str,
            js_fp_hash,
            service_tag: Some(service_tag),
            host: Some(host),
            kind,
            reason,
        });
        let any_banned = out.any_banned();
        if !out.created_bans.is_empty() {
            for b in &mut out.created_bans {
                b.node_tag = self.node_tag.clone();
            }
            self.logger.record_ban_records(out.created_bans).await;
            self.persist_active_bans_async();
        }
        if any_banned {
            if let Some(suppressed) = self.logger.should_log_warn(&format!("autoban:{client_ip}")) {
                warn!(
                    node = %self.node_tag,
                    service = %service_tag,
                    host = %host,
                    client = %client_ip,
                    reason = %reason,
                    ttl_secs = out.ban_ttl_secs,
                    level = out.offense_level,
                    banned_ip = out.newly_banned_ip,
                    banned_js_fp = out.newly_banned_js_fp,
                    banned_comp_fp = out.newly_banned_composite_fp,
                    suppressed,
                    "auto-banned confirmed attacker IP/fingerprint"
                );
            }
            self.logger
                .emit_alert(
                    "warning",
                    format!(
                        "AutoBan triggered for {} on {} [service={}, reason={}, ttl={}s, ip={}, js_fp={}, comp_fp={}]",
                        client_ip,
                        host,
                        service_tag,
                        reason,
                        out.ban_ttl_secs,
                        out.newly_banned_ip,
                        out.newly_banned_js_fp,
                        out.newly_banned_composite_fp,
                    ),
                )
                .await;
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn try_handle_evilpot_canary(
        &self,
        waf_cfg: &WafConfig,
        service_tag: &str,
        host: &str,
        path: &str,
        query: Option<&str>,
        method_str: &str,
        headers: &HeaderMap,
        client_ip: IpAddr,
        ray_id: &str,
        start: Instant,
        client_fp: &ClientFingerprint,
        fallback_fp_hash: &str,
        req_js_fp_hash: Option<&str>,
        ua_str: &str,
        al_str: &str,
        protocol_str: &str,
        scheme_str: &str,
        referer_opt: Option<&str>,
        suspicion_score: u8,
        tls_signal: Option<&ClientHelloSignal>,
        fp_extras: &FpServerExtras<'_>,
    ) -> Option<Response<ProxyBody>> {
        if waf_cfg.mode != WafMode::Evilpot || is_path_exempt(path, &waf_cfg.exempt_paths) {
            return None;
        }
        let ep_engine = self.evilpot.engine().await?;
        if !EvilpotManager::has_triggered_traps(&ep_engine) {
            return None;
        }
        let ep_path = clamp_input_slice(path, MAX_EVILPOT_PATH_CHARS);
        let ep_query = query.map(|q| clamp_input_slice(q, MAX_EVILPOT_QUERY_CHARS));
        ep_engine.check_canary_trigger(client_ip, ep_path, ep_query, headers)?;

        let Some(permit) = self.evilpot.try_admit(client_ip) else {
            self.record_offense_and_maybe_alert(
                service_tag,
                host,
                client_ip,
                tls_signal.and_then(|s| s.fingerprint.as_deref()),
                ua_str,
                req_js_fp_hash,
                OffenseKind::VerifiedExploit,
                "evilpot:canary_flood",
            )
            .await;
            return Some(
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header(header::CACHE_CONTROL, "no-store")
                    .body(full_body("Forbidden"))
                    .unwrap(),
            );
        };
        let outcome = match tokio::time::timeout(
            EVILPOT_HANDLE_TIMEOUT,
            ep_engine.handle_canary_if_present(client_ip, method_str, ep_path, ep_query, headers),
        )
        .await
        {
            Ok(Some(o)) => o,
            _ => return None,
        };

        let status_lbl = verification_status_label(outcome.session.status);
        if let Some(suppressed) = self
            .logger
            .should_log_warn(&format!("ep:canary:{client_ip}"))
        {
            warn!(
                node = %self.node_tag,
                service = %service_tag,
                host = %host,
                client = %client_ip,
                ray_id = %ray_id,
                status = status_lbl,
                canary_triggers = outcome.session.canary_triggers,
                persona = %outcome.session.persona_hostname,
                suppressed,
                "evilpot canary triggered — verified active exploit"
            );
        }
        if self
            .evilpot
            .should_emit_alert(client_ip, outcome.session.status)
        {
            self.logger
                .emit_alert(
                    "critical",
                    format!(
                        "Evilpot VerifiedExploit (canary replay) from {} on {} [service={}, triggers={}]",
                        client_ip, host, service_tag, outcome.session.canary_triggers
                    ),
                )
                .await;
        }
        // Canary replay is 100% confirmed active exploitation: let this final trap response
        // return to waste attacker time, while immediately banning IP & fingerprints for all
        // subsequent requests!
        self.record_offense_and_maybe_alert(
            service_tag,
            host,
            client_ip,
            tls_signal.and_then(|s| s.fingerprint.as_deref()),
            ua_str,
            req_js_fp_hash,
            OffenseKind::VerifiedExploit,
            "evilpot:verified_exploit:canary",
        )
        .await;
        let resp_status = outcome.response.status().as_u16();
        let tls_ja3 = tls_signal.and_then(|s| s.fingerprint.as_deref());
        self.logger
            .record_access_log(
                "ingress",
                service_tag,
                &client_ip.to_string(),
                resp_status,
                start.elapsed().as_secs_f64() * 1000.0,
                0,
                0,
                false,
                false,
                false,
                Some(format!("evilpot:{status_lbl}:canary")),
                Some(client_fp.device_type.to_string()),
                Some(client_fp.browser_family.to_string()),
                Some(client_fp.os_family.to_string()),
                false,
                AccessLogMeta {
                    ray_id: Some(ray_id),
                    method: Some(method_str),
                    host: Some(host),
                    path: Some(path),
                    query,
                    protocol: Some(protocol_str),
                    scheme: Some(scheme_str),
                    user_agent: Some(ua_str),
                    referer: referer_opt,
                    action: Some("evilpot_canary"),
                    cache_status: None,
                    tls_ja3,
                    waf_rule_id: None,
                    waf_category: Some("canary"),
                    suspicion_score: Some(suspicion_score),
                    client_country: fp_extras.geo_country,
                },
            )
            .await;
        self.logger
            .record_fingerprint_with_extras(
                service_tag,
                host,
                &client_ip.to_string(),
                fallback_fp_hash,
                false,
                "none",
                ua_str,
                al_str,
                client_fp.device_type,
                client_fp.browser_family,
                client_fp.os_family,
                client_fp.is_bot,
                false,
                suspicion_score,
                tls_signal.map(|s| s.cipher_count as u16).unwrap_or(0),
                tls_signal.map(|s| s.has_alpn).unwrap_or(false),
                fp_extras.clone(),
                None,
                1,
                1,
                0,
            )
            .await;
        let sess_info = session_report_to_info(&self.node_tag, &outcome.session);
        let ev_info = trap_outcome_to_event_info(
            &self.node_tag,
            &outcome.session,
            &outcome.verdict,
            &format!("{method_str} {path}"),
        );
        self.logger
            .record_evilpot_interaction(sess_info, ev_info)
            .await;
        let ban_hook = TarpitBanHook {
            engine: ep_engine,
            auto_ban: Arc::clone(&self.auto_ban),
            logger: Arc::clone(&self.logger),
            node_tag: self.node_tag.clone(),
            service_tag: service_tag.to_string(),
            host: host.to_string(),
            ban_file: self.bans_file_path(),
            client_ip,
            tls_ja3: tls_signal.and_then(|s| s.fingerprint.clone()),
            user_agent: ua_str.to_string(),
            js_fp_hash: req_js_fp_hash.map(str::to_string),
        };
        Some(into_proxy_response_with_ban_hook(
            outcome.response,
            Some(permit),
            Some(ban_hook),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    async fn divert_to_evilpot(
        &self,
        cfg: &IngressConfig,
        service_tag: &str,
        host: &str,
        path: &str,
        query: Option<&str>,
        method_str: &str,
        headers: &HeaderMap,
        client_ip: IpAddr,
        ray_id: &str,
        start: Instant,
        client_fp: &ClientFingerprint,
        fallback_fp_hash: &str,
        req_js_fp_hash: Option<&str>,
        ua_str: &str,
        al_str: &str,
        suspicion_score: u8,
        tls_signal: Option<&ClientHelloSignal>,
        fp_extras: &FpServerExtras<'_>,
        log_ctx: &RequestLogCtx<'_>,
        action: &'static str,
        finding: WafFinding,
    ) -> Response<ProxyBody> {
        let Some(permit) = self.evilpot.try_admit(client_ip) else {
            let reason = format!("evilpot:flood:{}", finding.category);
            self.record_offense_and_maybe_alert(
                service_tag,
                host,
                client_ip,
                log_ctx.tls_ja3,
                ua_str,
                req_js_fp_hash,
                OffenseKind::EvilpotFlood,
                &reason,
            )
            .await;
            self.logger
                .record_access_log(
                    "ingress",
                    service_tag,
                    &client_ip.to_string(),
                    403,
                    start.elapsed().as_secs_f64() * 1000.0,
                    0,
                    0,
                    false,
                    false,
                    false,
                    Some(reason),
                    Some(client_fp.device_type.to_string()),
                    Some(client_fp.browser_family.to_string()),
                    Some(client_fp.os_family.to_string()),
                    false,
                    log_ctx.meta("waf_block", None, finding.rule_id, Some(finding.category)),
                )
                .await;
            return build_waf_block_response(
                &finding,
                false,
                false,
                ray_id,
                None,
                accept_encoding(headers),
            );
        };
        let ep_engine = self
            .evilpot
            .get_or_init(&cfg.evilpot, &cfg.server_header)
            .await;
        let ep_path = clamp_input_slice(path, MAX_EVILPOT_PATH_CHARS);
        let ep_query = query.map(|q| clamp_input_slice(q, MAX_EVILPOT_QUERY_CHARS));
        let signal = build_attack_signal(&finding, ep_query.or(Some(ep_path)));
        let Ok(outcome) = tokio::time::timeout(
            EVILPOT_HANDLE_TIMEOUT,
            ep_engine.handle_attack(client_ip, method_str, ep_path, ep_query, headers, signal),
        )
        .await
        else {
            self.logger
                .record_access_log(
                    "ingress",
                    service_tag,
                    &client_ip.to_string(),
                    403,
                    start.elapsed().as_secs_f64() * 1000.0,
                    0,
                    0,
                    false,
                    false,
                    false,
                    Some(format!("evilpot:timeout:{}", finding.category)),
                    Some(client_fp.device_type.to_string()),
                    Some(client_fp.browser_family.to_string()),
                    Some(client_fp.os_family.to_string()),
                    false,
                    log_ctx.meta("waf_block", None, finding.rule_id, Some(finding.category)),
                )
                .await;
            return build_waf_block_response(
                &finding,
                false,
                false,
                ray_id,
                None,
                accept_encoding(headers),
            );
        };
        let status_lbl = verification_status_label(outcome.session.status);
        if let Some(suppressed) = self
            .logger
            .should_log_warn(&format!("ep:divert:{}:{}", client_ip, finding.category))
        {
            warn!(
                node = %self.node_tag,
                service = %service_tag,
                host = %host,
                client = %client_ip,
                ray_id = %ray_id,
                mode = action,
                category = finding.category,
                location = finding.location,
                confidence = finding.confidence,
                verification_status = status_lbl,
                persona = %outcome.session.persona_hostname,
                trapped_reqs = outcome.session.total_trapped_requests,
                sqli_probes = outcome.session.sqli_probes,
                rce_cmds = outcome.session.rce_commands_executed.len(),
                iocs = ?outcome.session.captured_iocs,
                suppressed,
                "security diverted request into evilpot honeypot"
            );
        }
        if self
            .evilpot
            .should_emit_alert(client_ip, outcome.session.status)
        {
            match outcome.session.status {
                ExploitVerificationStatus::VerifiedExploit => {
                    self.logger
                        .emit_alert(
                            "critical",
                            format!(
                                "Evilpot VerifiedExploit ({}) from {} on {} [service={}, reqs={}, iocs={}]",
                                finding.category,
                                client_ip,
                                host,
                                service_tag,
                                outcome.session.total_trapped_requests,
                                outcome.session.captured_iocs.len(),
                            ),
                        )
                        .await;
                }
                ExploitVerificationStatus::MultiStepExploitation => {
                    self.logger
                        .emit_alert(
                            "warning",
                            format!(
                                "Evilpot MultiStepExploitation ({}) from {} on {} [service={}, reqs={}, sqli_pos={}]",
                                finding.category,
                                client_ip,
                                host,
                                service_tag,
                                outcome.session.total_trapped_requests,
                                outcome.session.sqli_distinct_positions,
                            ),
                        )
                        .await;
                }
                ExploitVerificationStatus::Probing => {}
            }
        }
        let offense_kind = match outcome.session.status {
            ExploitVerificationStatus::VerifiedExploit => OffenseKind::VerifiedExploit,
            ExploitVerificationStatus::MultiStepExploitation => {
                OffenseKind::MultiStepExploitation {
                    trapped_requests: outcome.session.total_trapped_requests,
                }
            }
            ExploitVerificationStatus::Probing => {
                if finding.category == "scanner" || client_fp.is_scanner {
                    OffenseKind::AttackScannerProbe
                } else {
                    OffenseKind::WafAttackProbe
                }
            }
        };
        let ban_reason = format!("evilpot:{status_lbl}:{}", finding.category);
        self.record_offense_and_maybe_alert(
            service_tag,
            host,
            client_ip,
            log_ctx.tls_ja3,
            ua_str,
            req_js_fp_hash,
            offense_kind,
            &ban_reason,
        )
        .await;
        let resp_status = outcome.response.status().as_u16();
        self.logger
            .record_access_log(
                "ingress",
                service_tag,
                &client_ip.to_string(),
                resp_status,
                start.elapsed().as_secs_f64() * 1000.0,
                0,
                0,
                false,
                false,
                false,
                Some(ban_reason),
                Some(client_fp.device_type.to_string()),
                Some(client_fp.browser_family.to_string()),
                Some(client_fp.os_family.to_string()),
                false,
                log_ctx.meta(action, None, finding.rule_id, Some(finding.category)),
            )
            .await;
        self.logger
            .record_fingerprint_with_extras(
                service_tag,
                host,
                &client_ip.to_string(),
                fallback_fp_hash,
                false,
                "none",
                ua_str,
                al_str,
                client_fp.device_type,
                client_fp.browser_family,
                client_fp.os_family,
                client_fp.is_bot,
                false,
                suspicion_score,
                tls_signal.map(|s| s.cipher_count as u16).unwrap_or(0),
                tls_signal.map(|s| s.has_alpn).unwrap_or(false),
                fp_extras.clone(),
                None,
                1,
                1,
                0,
            )
            .await;
        let sess_info = session_report_to_info(&self.node_tag, &outcome.session);
        let ev_info = trap_outcome_to_event_info(
            &self.node_tag,
            &outcome.session,
            &outcome.verdict,
            &format!("{method_str} {path}"),
        );
        self.logger
            .record_evilpot_interaction(sess_info, ev_info)
            .await;
        let ban_hook = if outcome.session.status == ExploitVerificationStatus::VerifiedExploit {
            None
        } else {
            Some(TarpitBanHook {
                engine: ep_engine,
                auto_ban: Arc::clone(&self.auto_ban),
                logger: Arc::clone(&self.logger),
                node_tag: self.node_tag.clone(),
                service_tag: service_tag.to_string(),
                host: host.to_string(),
                ban_file: self.bans_file_path(),
                client_ip,
                tls_ja3: log_ctx.tls_ja3.map(str::to_string),
                user_agent: ua_str.to_string(),
                js_fp_hash: req_js_fp_hash.map(str::to_string),
            })
        };
        into_proxy_response_with_ban_hook(outcome.response, Some(permit), ban_hook)
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_http_request_inner(
        &self,
        req: Request<Incoming>,
        peer_addr: SocketAddr,
        is_tls: bool,
        redirect_https: bool,
        auth_sni: Option<&str>,
        tls_signal: Option<&ClientHelloSignal>,
        cfg: &IngressConfig,
        conn_permits: Option<Arc<ConnPermits>>,
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
        let query_opt = req.uri().query().map(str::to_string);
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".into());
        let method_str = req.method().as_str().to_string();
        let is_upgrade_hdr = req.headers().contains_key(header::UPGRADE);
        let protocol_str = if is_upgrade_hdr {
            "WS"
        } else if req.version() == Version::HTTP_2 {
            "HTTP/2"
        } else {
            "HTTP/1.1"
        };
        let scheme_str = if is_tls { "https" } else { "http" };
        let client_ip = canonical_ip(peer_addr.ip());
        let tls_ja3 = tls_signal.and_then(|s| s.fingerprint.as_deref());
        // Captured once, before `req` is moved into a forwarder, so intercept pages can be gzipped.
        let accept_enc = req
            .headers()
            .get(header::ACCEPT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
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
        let referer_opt = req
            .headers()
            .get(header::REFERER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let is_cdn_cgi = path == "/cdn-cgi" || path.starts_with("/cdn-cgi/");

        // Resolve matched route early (pure in-memory O(rules)) so we can check AutoBan
        // BEFORE spending AbuseIPDB API quota, WAF CPU, or Evilpot slots, while still honoring
        // explicit `api_bypass_headers` and `allow_cidrs` on the target route.
        let pre_matched_rule = if is_cdn_cgi {
            None
        } else {
            match_ingress_rule(&cfg.rules, &host, &path, client_ip, auth_sni).cloned()
        };
        let pre_profile = pre_matched_rule
            .as_ref()
            .and_then(|r| r.guard.as_ref())
            .filter(|g| !g.trim().is_empty())
            .and_then(|g| cfg.guards.get(g));
        let pre_verified_fp = self.guard.verified_fp_info(
            pre_profile,
            &cfg.clearance_secret,
            &host,
            client_ip,
            req.headers(),
        );
        let req_js_fp_hash = pre_verified_fp.as_ref().map(|(h, _, _)| h.clone());
        let is_api_bypassed = pre_profile
            .map(|p| matches_api_bypass(p, req.headers()))
            .unwrap_or(false);
        let is_allowlisted_cidr = pre_profile
            .map(|p| {
                !p.allow_cidrs.is_empty()
                    && exposure_core::routing::ip_matches_cidrs(client_ip, &p.allow_cidrs)
            })
            .unwrap_or(false);

        // Zero-cost early rejection for confirmed-banned IPs, JS fingerprints, and attacker-exclusive
        // composite TLS+UA fingerprints (catches keep-alive connections and rotating-IP attackers).
        if !is_api_bypassed && !is_allowlisted_cidr {
            if let Some(ban_hit) =
                self.auto_ban
                    .check_request(client_ip, tls_ja3, &ua_str, req_js_fp_hash.as_deref())
            {
                let svc_tag = pre_matched_rule
                    .as_ref()
                    .map(|r| r.service_tag.as_str())
                    .unwrap_or(if is_cdn_cgi { "_cdn_cgi" } else { "_banned" });
                self.logger
                    .record_access_log(
                        "ingress",
                        svc_tag,
                        &client_ip.to_string(),
                        403,
                        start.elapsed().as_secs_f64() * 1000.0,
                        0,
                        0,
                        false,
                        false,
                        false,
                        Some(format!(
                            "autoban:{}:{}",
                            ban_hit.kind.as_str(),
                            ban_hit.reason
                        )),
                        None,
                        None,
                        None,
                        false,
                        AccessLogMeta {
                            ray_id: Some(&ray_id),
                            method: Some(&method_str),
                            host: Some(&host),
                            path: Some(&path),
                            query: query_opt.as_deref(),
                            protocol: Some(protocol_str),
                            scheme: Some(scheme_str),
                            user_agent: Some(&ua_str),
                            referer: referer_opt.as_deref(),
                            action: Some("autoban"),
                            cache_status: None,
                            tls_ja3,
                            waf_rule_id: None,
                            waf_category: None,
                            suspicion_score: None,
                            client_country: None,
                        },
                    )
                    .await;
                return Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header(header::CACHE_CONTROL, "no-store")
                    .header(header::CONNECTION, "close")
                    .header(RAY_ID_HEADER, &ray_id)
                    .body(full_body("Forbidden"))
                    .unwrap();
            }
        }

        if redirect_https && !is_tls && !host.is_empty() {
            if !cfg.rules.is_empty() && !any_rule_matches_host(&cfg.rules, &host) {
                return Response::builder()
                    .status(StatusCode::MISDIRECTED_REQUEST)
                    .body(full_body("421 Misdirected Request"))
                    .unwrap();
            }
            let clean_host = host.strip_suffix(":80").unwrap_or(&host);
            let location = format!("https://{clean_host}{path_and_query}");
            if let Ok(hv) = HeaderValue::from_str(&location) {
                return Response::builder()
                    .status(StatusCode::PERMANENT_REDIRECT)
                    .header(header::LOCATION, hv)
                    .body(full_body(""))
                    .unwrap();
            }
        }

        // Local synchronous O(log N) GeoIP resolution (~50ns, zero network call)
        let local_geo = self.geoip.lookup(client_ip);
        let local_country = local_geo.as_ref().map(|g| g.country_str().to_string());
        let local_continent = local_geo.as_ref().map(|g| g.continent);

        // Proactively look up client IP reputation (cache hit -> immediate, miss -> AbuseIPDB v2 API)
        // for non-banned public IPs, with background backfill when upstream API exceeds REQUEST_WAIT_BUDGET.
        let abuse_rep = if cfg.abuseipdb.enabled && !cfg.abuseipdb.api_key.trim().is_empty() {
            let logger_bf = Arc::clone(&self.logger);
            let ip_str_bf = client_ip.to_string();
            self.abuseipdb
                .lookup_with_backfill(client_ip, move |rep| async move {
                    logger_bf
                        .backfill_abuse_report(
                            &ip_str_bf,
                            rep.abuse_confidence_score,
                            rep.country_code.as_deref(),
                            rep.isp.as_deref(),
                            rep.is_tor,
                        )
                        .await;
                })
                .await
        } else {
            None
        };
        let abuse_score = abuse_rep.as_ref().map(|r| r.abuse_confidence_score);
        let fp_extras = FpServerExtras {
            tls_ja3,
            tls_grease: tls_signal.map(|s| s.has_grease).unwrap_or(false),
            abuse_score,
            abuse_country: abuse_rep.as_ref().and_then(|r| r.country_code.as_deref()),
            abuse_isp: abuse_rep.as_ref().and_then(|r| r.isp.as_deref()),
            abuse_is_tor: abuse_rep.as_ref().map(|r| r.is_tor).unwrap_or(false),
            geo_country: local_country.as_deref(),
            geo_continent: local_continent,
        };

        // Built-in `/cdn-cgi` or `/cdn-cgi/*` PoW challenge endpoints (never matches `/cdn-cgi-foo`)
        if is_cdn_cgi {
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
                    .and_then(|v| {
                        v.get("redirect")
                            .and_then(|r| r.as_str())
                            .map(sanitize_redirect)
                    })
            } else {
                None
            };
            let target_path = body_redirect
                .or(query_redirect)
                .unwrap_or_else(|| "/".to_string());
            let target_path_only = target_path.split('?').next().unwrap_or("/");

            let matched_rule =
                match_ingress_rule(&cfg.rules, &host, target_path_only, client_ip, auth_sni)
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
            if matched_rule.is_none()
                && !cfg.rules.is_empty()
                && !any_rule_matches_host(&cfg.rules, &host)
            {
                return Response::builder()
                    .status(StatusCode::MISDIRECTED_REQUEST)
                    .body(full_body("421 Misdirected Request"))
                    .unwrap();
            }
            let guard_profile = matched_rule
                .and_then(|r| r.guard.as_ref())
                .and_then(|g| cfg.guards.get(g));
            let is_cdn_cgi_bypassed = guard_profile
                .map(|p| matches_api_bypass(p, &headers))
                .unwrap_or(false);

            // Enforce CIDR & Geo block policy on `/cdn-cgi/*`, and block PoW endpoints once the route bucket enters degraded mode
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
                            cfg.resolved_pages.error.as_deref(),
                            accept_encoding(&headers),
                        );
                    }
                    GuardDecision::Reject { status, .. } => {
                        return Response::builder()
                            .status(status)
                            .header(RAY_ID_HEADER, &ray_id)
                            .body(full_body("Access Denied"))
                            .unwrap();
                    }
                    GuardDecision::ChallengeRedirect { .. } => {}
                }
                if !is_cdn_cgi_bypassed {
                    if let Some(gp) = profile.geo.as_ref().filter(|gp| gp.enabled) {
                        if let GeoDecision::Block { .. } = evaluate_geo_policy(
                            gp,
                            local_geo.as_ref(),
                            !is_public_routable_ip(client_ip),
                        ) {
                            return Response::builder()
                                .status(StatusCode::FORBIDDEN)
                                .header(header::CACHE_CONTROL, "no-store")
                                .header(RAY_ID_HEADER, &ray_id)
                                .body(full_body("Access Denied by Region Policy"))
                                .unwrap();
                        }
                    }
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
                        cfg.resolved_pages.error.as_deref(),
                        accept_encoding(&headers),
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
                Some(&cfg.resolved_pages),
            );

            let passed = path == "/cdn-cgi/verify" && g_resp.status == StatusCode::OK;
            let verify_rejected = path == "/cdn-cgi/verify" && g_resp.record_verify_offense;
            let cfp_cls = crate::guard::classify_client(&headers);
            let score = compute_suspicion_score(&headers, tls_signal);

            if verify_rejected {
                let svc_tag = matched_rule
                    .map(|r| r.service_tag.as_str())
                    .unwrap_or("_cdn_cgi");
                self.record_offense_and_maybe_alert(
                    svc_tag,
                    &host,
                    client_ip,
                    tls_ja3,
                    &ua_str,
                    req_js_fp_hash.as_deref(),
                    OffenseKind::HeadlessOrVerifyAbuse,
                    "guard:pow_verify_rejected",
                )
                .await;
            }

            if let Some(sub) = verified_fp_sub {
                let svc_tag = sub
                    .service_tag
                    .as_deref()
                    .or_else(|| matched_rule.map(|r| r.service_tag.as_str()))
                    .unwrap_or("_cdn_cgi");
                if sub.is_headless {
                    self.record_offense_and_maybe_alert(
                        svc_tag,
                        &host,
                        client_ip,
                        tls_ja3,
                        &ua_str,
                        Some(&sub.fp_hash),
                        OffenseKind::HeadlessOrVerifyAbuse,
                        "guard:headless_fp_detected",
                    )
                    .await;
                }
                self.logger
                    .record_fingerprint_with_extras(
                        svc_tag,
                        &host,
                        &client_ip.to_string(),
                        &sub.fp_hash,
                        true,
                        sub.fp_source,
                        &ua_str,
                        &al_str,
                        cfp_cls.device_type,
                        cfp_cls.browser_family,
                        cfp_cls.os_family,
                        cfp_cls.is_bot,
                        sub.is_headless,
                        score,
                        tls_signal.map(|s| s.cipher_count as u16).unwrap_or(0),
                        tls_signal.map(|s| s.has_alpn).unwrap_or(false),
                        fp_extras.clone(),
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
                    .record_access_log(
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
                        AccessLogMeta {
                            ray_id: Some(&ray_id),
                            method: Some(&method_str),
                            host: Some(&host),
                            path: Some(&path),
                            query: query_opt.as_deref(),
                            protocol: Some(protocol_str),
                            scheme: Some(scheme_str),
                            user_agent: Some(&ua_str),
                            referer: referer_opt.as_deref(),
                            action: Some("challenge_pass"),
                            cache_status: None,
                            tls_ja3,
                            waf_rule_id: None,
                            waf_category: None,
                            suspicion_score: Some(score),
                            client_country: local_country.as_deref(),
                        },
                    )
                    .await;
            }

            let mut rb = Response::builder()
                .status(g_resp.status)
                .header(header::CONTENT_TYPE, g_resp.content_type)
                .header(RAY_ID_HEADER, &ray_id);
            for (k, v) in g_resp.extra_headers {
                rb = rb.header(k, v);
            }
            return rb.body(full_body(g_resp.body)).unwrap();
        }

        // Identify service and next hop via local rules (reusing early match)
        let rule = match pre_matched_rule {
            Some(r) => r,
            None => {
                let cfp = crate::guard::classify_client(req.headers());
                let susp = compute_server_suspicion_score_for_mode(
                    req.headers(),
                    tls_signal,
                    abuse_score,
                    false,
                );
                let unmatched_status =
                    if !cfg.rules.is_empty() && !any_rule_matches_host(&cfg.rules, &host) {
                        StatusCode::MISDIRECTED_REQUEST
                    } else {
                        StatusCode::NOT_FOUND
                    };
                self.logger
                    .record_access_log(
                        "ingress",
                        "_unmatched",
                        &client_ip.to_string(),
                        unmatched_status.as_u16(),
                        start.elapsed().as_secs_f64() * 1000.0,
                        0,
                        0,
                        false,
                        false,
                        false,
                        None,
                        Some(cfp.device_type.to_string()),
                        Some(cfp.browser_family.to_string()),
                        Some(cfp.os_family.to_string()),
                        false,
                        AccessLogMeta {
                            ray_id: Some(&ray_id),
                            method: Some(&method_str),
                            host: Some(&host),
                            path: Some(&path),
                            query: query_opt.as_deref(),
                            protocol: Some(protocol_str),
                            scheme: Some(scheme_str),
                            user_agent: Some(&ua_str),
                            referer: referer_opt.as_deref(),
                            action: Some("unmatched"),
                            cache_status: None,
                            tls_ja3,
                            waf_rule_id: None,
                            waf_category: None,
                            suspicion_score: Some(susp),
                            client_country: local_country.as_deref(),
                        },
                    )
                    .await;
                if abuse_rep.is_some() {
                    let fph = short_sha256_hex(&format!("ua|{ua_str}|{al_str}"));
                    self.logger
                        .record_fingerprint_with_extras(
                            "_unmatched",
                            &host,
                            &client_ip.to_string(),
                            &fph,
                            false,
                            "none",
                            &ua_str,
                            &al_str,
                            cfp.device_type,
                            cfp.browser_family,
                            cfp.os_family,
                            cfp.is_bot,
                            false,
                            susp,
                            tls_signal.map(|s| s.cipher_count as u16).unwrap_or(0),
                            tls_signal.map(|s| s.has_alpn).unwrap_or(false),
                            fp_extras.clone(),
                            None,
                            1,
                            0,
                            0,
                        )
                        .await;
                }
                if unmatched_status == StatusCode::MISDIRECTED_REQUEST {
                    return Response::builder()
                        .status(StatusCode::MISDIRECTED_REQUEST)
                        .header(RAY_ID_HEADER, &ray_id)
                        .body(full_body("421 Misdirected Request"))
                        .unwrap();
                }
                return Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header(RAY_ID_HEADER, &ray_id)
                    .body(full_body("404 Not Found"))
                    .unwrap();
            }
        };

        let client_fp = crate::guard::classify_client(req.headers());
        let fallback_fp_hash = short_sha256_hex(&format!("ua|{ua_str}|{al_str}"));

        // Resolve attached Guard profile (fail closed on undefined guard name!)
        let active_profile = if let Some(ref guard_name) = rule.guard {
            if !guard_name.trim().is_empty() {
                match cfg.guards.get(guard_name) {
                    Some(p) => Some(p),
                    None => {
                        warn!(
                            node = %self.node_tag,
                            service = %rule.service_tag,
                            guard = %guard_name,
                            ray_id = %ray_id,
                            "ingress rule references undefined guard profile; failing closed"
                        );
                        self.logger
                            .record_access_log(
                                "ingress",
                                &rule.service_tag,
                                &client_ip.to_string(),
                                503,
                                start.elapsed().as_secs_f64() * 1000.0,
                                0,
                                0,
                                false,
                                false,
                                false,
                                Some(format!("undefined guard profile: {guard_name}")),
                                Some(client_fp.device_type.to_string()),
                                Some(client_fp.browser_family.to_string()),
                                Some(client_fp.os_family.to_string()),
                                false,
                                AccessLogMeta {
                                    ray_id: Some(&ray_id),
                                    method: Some(&method_str),
                                    host: Some(&host),
                                    path: Some(&path),
                                    query: query_opt.as_deref(),
                                    protocol: Some(protocol_str),
                                    scheme: Some(scheme_str),
                                    user_agent: Some(&ua_str),
                                    referer: referer_opt.as_deref(),
                                    action: Some("config_error"),
                                    cache_status: None,
                                    tls_ja3,
                                    waf_rule_id: None,
                                    waf_category: None,
                                    suspicion_score: None,
                                    client_country: local_country.as_deref(),
                                },
                            )
                            .await;
                        return build_ingress_5xx_response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            &ray_id,
                            rule.effective_intercept_errors(),
                            cfg.resolved_pages.error.as_deref(),
                            &accept_enc,
                        );
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        let mut suspicion_score = compute_server_suspicion_score_for_mode(
            req.headers(),
            tls_signal,
            abuse_score,
            active_profile
                .map(|p| p.effective_browser_only())
                .unwrap_or(false),
        );
        let mut geo_score_boost: i16 = 0;
        let geo_eval = active_profile.and_then(|profile| {
            if is_api_bypassed {
                return None;
            }
            profile.geo.as_ref().filter(|gp| gp.enabled).map(|gp| {
                evaluate_geo_policy(gp, local_geo.as_ref(), !is_public_routable_ip(client_ip))
            })
        });
        if let Some(ref gd) = geo_eval {
            let b = match gd {
                GeoDecision::Allow { suspicion_boost }
                | GeoDecision::Monitor {
                    suspicion_boost, ..
                }
                | GeoDecision::Challenge {
                    suspicion_boost, ..
                } => *suspicion_boost,
                GeoDecision::Block { .. } | GeoDecision::Evilpot { .. } => 0,
            };
            geo_score_boost = b;
            suspicion_score = (i32::from(suspicion_score) + i32::from(b)).clamp(0, 100) as u8;
        }
        let log_ctx = RequestLogCtx {
            ray_id: &ray_id,
            method: &method_str,
            host: &host,
            path: &path,
            query: query_opt.as_deref(),
            protocol: protocol_str,
            scheme: scheme_str,
            user_agent: &ua_str,
            referer: referer_opt.as_deref(),
            tls_ja3,
            suspicion_score: Some(suspicion_score),
            client_country: local_country.as_deref(),
        };

        // Phase A: Fast O(1) CIDR allow/deny + Token-Bucket Rate Limiting (stops volumetric floods
        // and denied CIDRs BEFORE WAF body buffering or honeypot slot allocation).
        if let Some(profile) = active_profile {
            match self.guard.evaluate_access_and_rate_limit(
                profile,
                &cfg.rate_limit_buckets,
                client_ip,
            ) {
                GuardDecision::Allow => {}
                GuardDecision::RateLimited {
                    retry_after_secs,
                    show_error_page,
                } => {
                    self.logger
                        .record_access_log(
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
                            log_ctx.meta("rate_limit", None, None, None),
                        )
                        .await;
                    self.logger
                        .record_fingerprint_with_extras(
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
                            fp_extras.clone(),
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
                        cfg.resolved_pages.error.as_deref(),
                        &accept_enc,
                    );
                }
                GuardDecision::Reject { status, reason } => {
                    self.logger
                        .record_access_log(
                            "ingress",
                            &rule.service_tag,
                            &client_ip.to_string(),
                            status.as_u16(),
                            start.elapsed().as_secs_f64() * 1000.0,
                            0,
                            0,
                            false,
                            false,
                            false,
                            Some(reason),
                            Some(client_fp.device_type.to_string()),
                            Some(client_fp.browser_family.to_string()),
                            Some(client_fp.os_family.to_string()),
                            false,
                            log_ctx.meta("guard_reject", None, None, None),
                        )
                        .await;
                    self.logger
                        .record_fingerprint_with_extras(
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
                            fp_extras.clone(),
                            None,
                            1,
                            1,
                            0,
                        )
                        .await;
                    return Response::builder()
                        .status(status)
                        .header(RAY_ID_HEADER, &ray_id)
                        .body(full_body("Access Denied"))
                        .unwrap();
                }
                GuardDecision::ChallengeRedirect { .. } => {}
            }
        }

        // Phase A.5: Local Zero-Network GeoIP Region-Targeting Enforcement
        if let (Some(profile), Some(gd)) = (active_profile, geo_eval) {
            match gd {
                GeoDecision::Allow { .. } => {}
                GeoDecision::Monitor { reason, .. } => {
                    if let Some(suppressed) = self
                        .logger
                        .should_log_warn(&format!("geo:mon:{}:{}", rule.service_tag, reason))
                    {
                        warn!(
                            node = %self.node_tag,
                            service = %rule.service_tag,
                            host = %host,
                            client = %client_ip,
                            country = local_country.as_deref().unwrap_or("XX"),
                            reason = %reason,
                            suppressed,
                            "geoip policy matched (monitor)"
                        );
                    }
                }
                GeoDecision::Block { reason } => {
                    self.logger
                        .record_access_log(
                            "ingress",
                            &rule.service_tag,
                            &client_ip.to_string(),
                            403,
                            start.elapsed().as_secs_f64() * 1000.0,
                            0,
                            0,
                            false,
                            false,
                            false,
                            Some(reason),
                            Some(client_fp.device_type.to_string()),
                            Some(client_fp.browser_family.to_string()),
                            Some(client_fp.os_family.to_string()),
                            false,
                            log_ctx.meta("geo_block", None, None, Some("geo-policy")),
                        )
                        .await;
                    self.logger
                        .record_fingerprint_with_extras(
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
                            fp_extras.clone(),
                            None,
                            1,
                            1,
                            0,
                        )
                        .await;
                    return Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .header(header::CACHE_CONTROL, "no-store")
                        .header(RAY_ID_HEADER, &ray_id)
                        .body(full_body("Access Denied by Region Policy"))
                        .unwrap();
                }
                GeoDecision::Challenge { reason, .. } => {
                    if !self.guard.has_valid_clearance(
                        profile,
                        &cfg.clearance_secret,
                        &host,
                        client_ip,
                        req.headers(),
                    ) {
                        let is_nav = is_browser_navigation(req.method(), req.headers());
                        let challenge_status = if is_nav { 302 } else { 403 };
                        self.logger
                            .record_access_log(
                                "ingress",
                                &rule.service_tag,
                                &client_ip.to_string(),
                                challenge_status,
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
                                log_ctx.meta("geo_challenge", None, None, Some("geo-policy")),
                            )
                            .await;
                        self.logger
                            .record_fingerprint_with_extras(
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
                                fp_extras.clone(),
                                None,
                                1,
                                1,
                                0,
                            )
                            .await;
                        if is_nav {
                            let location = format!(
                                "/cdn-cgi/?redirect={}",
                                crate::guard::url_encode(&path_and_query)
                            );
                            return Response::builder()
                                .status(StatusCode::FOUND)
                                .header(header::LOCATION, location)
                                .header(header::CACHE_CONTROL, "no-store")
                                .header(RAY_ID_HEADER, &ray_id)
                                .body(full_body(""))
                                .unwrap();
                        }
                        return Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
                            .header(header::CACHE_CONTROL, "no-store")
                            .header(RAY_ID_HEADER, &ray_id)
                            .body(full_body(
                                r#"{"error":"verification_required","reason":"geo_challenge"}"#,
                            ))
                            .unwrap();
                    }
                }
                GeoDecision::Evilpot { reason } => {
                    let finding = WafFinding {
                        category: "geo-policy",
                        location: "geoip",
                        confidence: 0.90,
                        reasons: vec!["geo-region-evilpot"],
                        matched_payload: Some(reason),
                        rule_id: None,
                        rule_msg: Some("Region Policy diverted request to Evilpot".into()),
                    };
                    return self
                        .divert_to_evilpot(
                            cfg,
                            &rule.service_tag,
                            &host,
                            &path,
                            query_opt.as_deref(),
                            &method_str,
                            req.headers(),
                            client_ip,
                            &ray_id,
                            start,
                            &client_fp,
                            &fallback_fp_hash,
                            req_js_fp_hash.as_deref(),
                            &ua_str,
                            &al_str,
                            suspicion_score,
                            tls_signal,
                            &fp_extras,
                            &log_ctx,
                            "geo_evilpot",
                            finding,
                        )
                        .await;
                }
            }
        }

        let is_upgrade = req.headers().contains_key(header::UPGRADE);
        let mut req: Request<ProxyBody> = req.map(|b| b.boxed());

        let mut waf_monitor_hit: Option<(Option<u32>, &'static str)> = None;

        // Phase B: Attack Identification -> Evilpot Time-Wasting -> Behavior Confirmation -> Auto-Ban!
        // Runs BEFORE Guard Antibot Challenge/Reject so attack payloads & offensive scanners (including
        // non-browser tools like sqlmap/curl/python) are diverted into Evilpot to waste attacker time,
        // verify exploit intent, and auto-ban IP + fingerprints instead of getting an instant 403.
        if let Some(profile) = active_profile {
            if let Some(waf_cfg) = profile.effective_waf() {
                if !is_api_bypassed {
                    // 1. O(1) Canary Replay check (0-ns skip before any trap has fired)
                    if let Some(canary_resp) = self
                        .try_handle_evilpot_canary(
                            waf_cfg,
                            &rule.service_tag,
                            &host,
                            &path,
                            query_opt.as_deref(),
                            &method_str,
                            req.headers(),
                            client_ip,
                            &ray_id,
                            start,
                            &client_fp,
                            &fallback_fp_hash,
                            req_js_fp_hash.as_deref(),
                            &ua_str,
                            &al_str,
                            protocol_str,
                            scheme_str,
                            referer_opt.as_deref(),
                            suspicion_score,
                            tls_signal,
                            &fp_extras,
                        )
                        .await
                    {
                        return canary_resp;
                    }

                    // 2. WAF inspection (pure linear-time OWASP CRS ruleset)
                    let crs_engine = Arc::clone(&*self.crs.read().await);
                    let mut verdict =
                        crs_engine.inspect_head(waf_cfg, &path, req.uri().query(), req.headers());
                    // 3. Unambiguous offensive vulnerability scanner UA (e.g. sqlmap, nikto, nuclei, ffuf)
                    if matches!(verdict, WafVerdict::Allow)
                        && client_fp.is_scanner
                        && !is_path_exempt(&path, &waf_cfg.exempt_paths)
                    {
                        let scanner_finding = WafFinding {
                            category: "scanner",
                            location: "header:user-agent",
                            confidence: 0.95,
                            reasons: vec!["offensive-scanner-user-agent"],
                            matched_payload: Some(ua_str.chars().take(256).collect()),
                            rule_id: None,
                            rule_msg: Some("Offensive vulnerability scanner User-Agent".into()),
                        };
                        verdict = match waf_cfg.mode {
                            WafMode::Off => WafVerdict::Allow,
                            WafMode::Monitor => WafVerdict::Monitor(scanner_finding),
                            WafMode::Block => WafVerdict::Block(scanner_finding),
                            WafMode::Evilpot => WafVerdict::Evilpot(scanner_finding),
                        };
                    }
                    // 4. Bounded request body inspection (concurrency-capped by `waf_body_sem`)
                    if matches!(verdict, WafVerdict::Allow)
                        && !is_path_exempt(&path, &waf_cfg.exempt_paths)
                    {
                        if let Some(body_limit) =
                            should_inspect_body(waf_cfg, req.method(), req.headers(), is_upgrade)
                        {
                            let ct = req
                                .headers()
                                .get(header::CONTENT_TYPE)
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_string);
                            let Ok(_waf_buf_permit) = tokio::time::timeout(
                                Duration::from_secs(2),
                                self.waf_body_sem.clone().acquire_owned(),
                            )
                            .await
                            .map_err(|_| ())
                            .and_then(|res| res.map_err(|_| ())) else {
                                self.logger
                                    .record_access_log(
                                        "ingress",
                                        &rule.service_tag,
                                        &client_ip.to_string(),
                                        503,
                                        start.elapsed().as_secs_f64() * 1000.0,
                                        0,
                                        0,
                                        false,
                                        false,
                                        false,
                                        Some("waf:body_buffer_busy".into()),
                                        Some(client_fp.device_type.to_string()),
                                        Some(client_fp.browser_family.to_string()),
                                        Some(client_fp.os_family.to_string()),
                                        false,
                                        log_ctx.meta(
                                            "waf_overload",
                                            None,
                                            None,
                                            Some("waf-overload"),
                                        ),
                                    )
                                    .await;
                                return build_ingress_5xx_response(
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    &ray_id,
                                    rule.effective_intercept_errors(),
                                    cfg.resolved_pages.error.as_deref(),
                                    &accept_enc,
                                );
                            };
                            match buffer_prefix_for_waf(req, body_limit).await {
                                Ok((rebuilt_req, inspected_bytes)) => {
                                    req = rebuilt_req;
                                    if !inspected_bytes.is_empty() {
                                        verdict = crs_engine.inspect_body(
                                            waf_cfg,
                                            ct.as_deref(),
                                            &inspected_bytes,
                                        );
                                    }
                                }
                                Err(WafBodyReadError::Timeout) => {
                                    // Slow-POST / R.U.D.Y. timeout while reading request body prefix
                                    self.logger
                                        .record_access_log(
                                            "ingress",
                                            &rule.service_tag,
                                            &client_ip.to_string(),
                                            408,
                                            start.elapsed().as_secs_f64() * 1000.0,
                                            0,
                                            0,
                                            false,
                                            false,
                                            false,
                                            Some("waf:slow_post_timeout".into()),
                                            Some(client_fp.device_type.to_string()),
                                            Some(client_fp.browser_family.to_string()),
                                            Some(client_fp.os_family.to_string()),
                                            false,
                                            log_ctx.meta(
                                                "waf_block",
                                                None,
                                                None,
                                                Some("slow-post"),
                                            ),
                                        )
                                        .await;
                                    return Response::builder()
                                        .status(StatusCode::REQUEST_TIMEOUT)
                                        .header(header::CACHE_CONTROL, "no-store")
                                        .header(RAY_ID_HEADER, &ray_id)
                                        .body(full_body("408 Request Timeout"))
                                        .unwrap();
                                }
                                Err(WafBodyReadError::Io) => {
                                    self.logger
                                        .record_access_log(
                                            "ingress",
                                            &rule.service_tag,
                                            &client_ip.to_string(),
                                            400,
                                            start.elapsed().as_secs_f64() * 1000.0,
                                            0,
                                            0,
                                            false,
                                            false,
                                            false,
                                            Some("waf:body_read_error".into()),
                                            Some(client_fp.device_type.to_string()),
                                            Some(client_fp.browser_family.to_string()),
                                            Some(client_fp.os_family.to_string()),
                                            false,
                                            log_ctx.meta(
                                                "waf_block",
                                                None,
                                                None,
                                                Some("protocol-attack"),
                                            ),
                                        )
                                        .await;
                                    return Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .header(header::CACHE_CONTROL, "no-store")
                                        .header(RAY_ID_HEADER, &ray_id)
                                        .body(full_body("400 Bad Request"))
                                        .unwrap();
                                }
                            }
                        }
                    }

                    match verdict {
                        WafVerdict::Allow => {}
                        WafVerdict::Monitor(finding) => {
                            waf_monitor_hit = Some((finding.rule_id, finding.category));
                            if let Some(suppressed) = self.logger.should_log_warn(&format!(
                                "waf:mon:{}:{}",
                                rule.service_tag, finding.category
                            )) {
                                warn!(
                                    node = %self.node_tag,
                                    service = %rule.service_tag,
                                    host = %host,
                                    client = %client_ip,
                                    ray_id = %ray_id,
                                    mode = "monitor",
                                    category = finding.category,
                                    location = finding.location,
                                    confidence = finding.confidence,
                                    reasons = ?finding.reasons,
                                    suppressed,
                                    "waf matched suspicious payload (monitor mode)"
                                );
                            }
                        }
                        WafVerdict::Block(finding) => {
                            if let Some(suppressed) = self.logger.should_log_warn(&format!(
                                "waf:blk:{}:{}",
                                client_ip, finding.category
                            )) {
                                warn!(
                                    node = %self.node_tag,
                                    service = %rule.service_tag,
                                    host = %host,
                                    client = %client_ip,
                                    ray_id = %ray_id,
                                    mode = "block",
                                    category = finding.category,
                                    location = finding.location,
                                    confidence = finding.confidence,
                                    reasons = ?finding.reasons,
                                    suppressed,
                                    "waf blocked malicious request"
                                );
                            }
                            let reason = finding.telemetry_reason();
                            let offense_kind =
                                if finding.category == "scanner" || client_fp.is_scanner {
                                    OffenseKind::AttackScannerProbe
                                } else {
                                    OffenseKind::WafAttackProbe
                                };
                            self.record_offense_and_maybe_alert(
                                &rule.service_tag,
                                &host,
                                client_ip,
                                tls_ja3,
                                &ua_str,
                                req_js_fp_hash.as_deref(),
                                offense_kind,
                                &reason,
                            )
                            .await;
                            self.logger
                                .record_access_log(
                                    "ingress",
                                    &rule.service_tag,
                                    &client_ip.to_string(),
                                    403,
                                    start.elapsed().as_secs_f64() * 1000.0,
                                    0,
                                    0,
                                    false,
                                    false,
                                    false,
                                    Some(reason),
                                    Some(client_fp.device_type.to_string()),
                                    Some(client_fp.browser_family.to_string()),
                                    Some(client_fp.os_family.to_string()),
                                    false,
                                    log_ctx.meta(
                                        "waf_block",
                                        None,
                                        finding.rule_id,
                                        Some(finding.category),
                                    ),
                                )
                                .await;
                            self.logger
                                .record_fingerprint_with_extras(
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
                                    fp_extras.clone(),
                                    None,
                                    1,
                                    1,
                                    0,
                                )
                                .await;
                            return build_waf_block_response(
                                &finding,
                                rule.effective_intercept_errors(),
                                is_browser_navigation(req.method(), req.headers()),
                                &ray_id,
                                cfg.resolved_pages.error.as_deref(),
                                accept_encoding(req.headers()),
                            );
                        }
                        WafVerdict::Evilpot(finding) => {
                            return self
                                .divert_to_evilpot(
                                    cfg,
                                    &rule.service_tag,
                                    &host,
                                    &path,
                                    query_opt.as_deref(),
                                    &method_str,
                                    req.headers(),
                                    client_ip,
                                    &ray_id,
                                    start,
                                    &client_fp,
                                    &fallback_fp_hash,
                                    req_js_fp_hash.as_deref(),
                                    &ua_str,
                                    &al_str,
                                    suspicion_score,
                                    tls_signal,
                                    &fp_extras,
                                    &log_ctx,
                                    "evilpot",
                                    finding,
                                )
                                .await;
                        }
                    }
                }
            }
        }

        // Phase C: Entry Guard Antibot / Suspicion Scoring (non-browser-safe unless `browser_only: true`).
        if let Some(profile) = active_profile {
            match self.guard.evaluate_antibot_only_with_boost(
                profile,
                &cfg.clearance_secret,
                client_ip,
                &host,
                &path_and_query,
                req.headers(),
                tls_signal,
                abuse_score,
                geo_score_boost,
            ) {
                GuardDecision::Allow | GuardDecision::RateLimited { .. } => {}
                GuardDecision::Reject { status, reason } => {
                    if reason.contains("headless") {
                        self.record_offense_and_maybe_alert(
                            &rule.service_tag,
                            &host,
                            client_ip,
                            tls_ja3,
                            &ua_str,
                            req_js_fp_hash.as_deref(),
                            OffenseKind::HeadlessOrVerifyAbuse,
                            "guard:headless_blocked",
                        )
                        .await;
                    }
                    self.logger
                        .record_access_log(
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
                            log_ctx.meta("guard_reject", None, None, None),
                        )
                        .await;
                    self.logger
                        .record_fingerprint_with_extras(
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
                            fp_extras.clone(),
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
                            .record_access_log(
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
                                log_ctx.meta("challenge", None, None, None),
                            )
                            .await;
                        self.logger
                            .record_fingerprint_with_extras(
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
                                fp_extras.clone(),
                                None,
                                1,
                                1,
                                0,
                            )
                            .await;
                        return Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
                            .header(header::CACHE_CONTROL, "no-store")
                            .header(RAY_ID_HEADER, &ray_id)
                            .body(full_body(r#"{"error":"verification_required"}"#))
                            .unwrap();
                    }
                    self.logger
                        .record_access_log(
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
                            log_ctx.meta("challenge", None, None, None),
                        )
                        .await;
                    self.logger
                        .record_fingerprint_with_extras(
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
                            fp_extras.clone(),
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
                        .header(RAY_ID_HEADER, &ray_id)
                        .body(full_body(""))
                        .unwrap();
                }
            }
        }

        // Phase D: Enforce AbuseIPDB automatic high-risk IP mitigation (before Edge Cache & upstream)
        if let Some(ab_score) = abuse_score {
            if !is_api_bypassed
                && cfg.abuseipdb.enabled
                && cfg.abuseipdb.high_risk_action != AbuseIpDbAction::Off
            {
                let eff_action = if ab_score >= cfg.abuseipdb.block_threshold {
                    Some(cfg.abuseipdb.high_risk_action)
                } else if cfg.abuseipdb.challenge_threshold > 0
                    && ab_score >= cfg.abuseipdb.challenge_threshold
                    && cfg.abuseipdb.high_risk_action != AbuseIpDbAction::Monitor
                {
                    Some(AbuseIpDbAction::Challenge)
                } else {
                    None
                };
                if let Some(eff_action) = eff_action {
                    match eff_action {
                        AbuseIpDbAction::Off => {}
                        AbuseIpDbAction::Monitor => {
                            if let Some(suppressed) = self
                                .logger
                                .should_log_warn(&format!("abuse:mon:{client_ip}"))
                            {
                                warn!(
                                    node = %self.node_tag,
                                    service = %rule.service_tag,
                                    client = %client_ip,
                                    abuse_score = ab_score,
                                    suppressed,
                                    "abuseipdb high-risk IP detected (monitor mode)"
                                );
                            }
                        }
                        AbuseIpDbAction::Challenge => {
                            let default_guard = GuardProfile::default();
                            let eff_profile = active_profile.unwrap_or(&default_guard);
                            if !self.guard.has_valid_clearance(
                                eff_profile,
                                &cfg.clearance_secret,
                                &host,
                                client_ip,
                                req.headers(),
                            ) {
                                self.logger
                                    .record_fingerprint_with_extras(
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
                                        fp_extras.clone(),
                                        None,
                                        1,
                                        1,
                                        0,
                                    )
                                    .await;
                                let is_nav = is_browser_navigation(req.method(), req.headers());
                                let challenge_status = if is_nav { 302 } else { 403 };
                                self.logger
                                    .record_access_log(
                                        "ingress",
                                        &rule.service_tag,
                                        &client_ip.to_string(),
                                        challenge_status,
                                        start.elapsed().as_secs_f64() * 1000.0,
                                        0,
                                        0,
                                        false,
                                        true,
                                        false,
                                        Some(format!("abuseipdb:challenge:score={ab_score}")),
                                        Some(client_fp.device_type.to_string()),
                                        Some(client_fp.browser_family.to_string()),
                                        Some(client_fp.os_family.to_string()),
                                        false,
                                        log_ctx.meta(
                                            "abuseipdb",
                                            None,
                                            None,
                                            Some("ip-reputation"),
                                        ),
                                    )
                                    .await;
                                if !is_nav {
                                    return Response::builder()
                                        .status(StatusCode::FORBIDDEN)
                                        .header(
                                            header::CONTENT_TYPE,
                                            "application/json; charset=utf-8",
                                        )
                                        .header(header::CACHE_CONTROL, "no-store")
                                        .header(RAY_ID_HEADER, &ray_id)
                                        .body(full_body(
                                            serde_json::json!({
                                                "error": "abuseipdb_verification_required",
                                                "abuse_score": ab_score,
                                                "ray_id": ray_id,
                                            })
                                            .to_string(),
                                        ))
                                        .unwrap();
                                }
                                let location = format!(
                                    "/cdn-cgi/?redirect={}",
                                    crate::guard::url_encode(&path_and_query)
                                );
                                return Response::builder()
                                    .status(StatusCode::FOUND)
                                    .header(header::LOCATION, location)
                                    .header(header::CACHE_CONTROL, "no-store")
                                    .header(RAY_ID_HEADER, &ray_id)
                                    .body(full_body(""))
                                    .unwrap();
                            }
                        }
                        AbuseIpDbAction::Evilpot => {
                            let finding = WafFinding {
                                category: "ip-reputation",
                                location: "abuseipdb",
                                confidence: (ab_score as f32 / 100.0).clamp(0.5, 1.0),
                                reasons: vec!["abuseipdb-high-risk"],
                                matched_payload: Some(format!("abuseipdb_score={ab_score}")),
                                rule_id: None,
                                rule_msg: Some("AbuseIPDB high-risk IP diverted to Evilpot".into()),
                            };
                            return self
                                .divert_to_evilpot(
                                    cfg,
                                    &rule.service_tag,
                                    &host,
                                    &path,
                                    query_opt.as_deref(),
                                    &method_str,
                                    req.headers(),
                                    client_ip,
                                    &ray_id,
                                    start,
                                    &client_fp,
                                    &fallback_fp_hash,
                                    req_js_fp_hash.as_deref(),
                                    &ua_str,
                                    &al_str,
                                    suspicion_score,
                                    tls_signal,
                                    &fp_extras,
                                    &log_ctx,
                                    "evilpot",
                                    finding,
                                )
                                .await;
                        }
                        AbuseIpDbAction::Block => {
                            if let Some(suppressed) = self
                                .logger
                                .should_log_warn(&format!("abuse:blk:{client_ip}"))
                            {
                                warn!(
                                    node = %self.node_tag,
                                    service = %rule.service_tag,
                                    client = %client_ip,
                                    abuse_score = ab_score,
                                    suppressed,
                                    "abuseipdb blocked high-risk IP"
                                );
                            }
                            self.logger
                                .record_access_log(
                                    "ingress",
                                    &rule.service_tag,
                                    &client_ip.to_string(),
                                    403,
                                    start.elapsed().as_secs_f64() * 1000.0,
                                    0,
                                    0,
                                    false,
                                    false,
                                    false,
                                    Some(format!("abuseipdb:score={ab_score}")),
                                    Some(client_fp.device_type.to_string()),
                                    Some(client_fp.browser_family.to_string()),
                                    Some(client_fp.os_family.to_string()),
                                    false,
                                    log_ctx.meta("abuseipdb", None, None, Some("ip-reputation")),
                                )
                                .await;
                            self.logger
                                .record_fingerprint_with_extras(
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
                                    fp_extras.clone(),
                                    None,
                                    1,
                                    1,
                                    0,
                                )
                                .await;
                            return Response::builder()
                                .status(StatusCode::FORBIDDEN)
                                .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
                                .header(header::CACHE_CONTROL, "no-store")
                                .header("x-exposure-ray", &ray_id)
                                .body(full_body(
                                    serde_json::json!({
                                        "error": "abuseipdb_blocked",
                                        "abuse_score": ab_score,
                                        "ray_id": ray_id,
                                    })
                                    .to_string(),
                                ))
                                .unwrap();
                        }
                    }
                }
            }
        }

        let fp_verified = pre_verified_fp.is_some();
        let (obs_fp_hash, obs_fp_source, obs_is_headless) = match pre_verified_fp {
            Some((h, src, hl)) => (h, src, hl),
            None => (fallback_fp_hash, "none", false),
        };

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

        // Evaluate Edge HTTP Cache AFTER Entry Guard (so ACL/RateLimit/PoW/WAF are never bypassed)
        let cache_policy = EffectiveCachePolicy::resolve(&cfg.cache, rule.cache.as_ref());
        let orig_method = req.method().clone();
        let orig_req_headers = if cache_policy.enabled {
            Some(req.headers().clone())
        } else {
            None
        };
        let mut cache_store_key: Option<String> = None;
        let mut stale_fallback: Option<(String, Arc<CachedEntry>)> = None;
        let mut sent_cache_revalidation = false;

        if cache_policy.enabled {
            let lookup_headers = orig_req_headers.as_ref().unwrap();
            match self.cache.lookup(
                &cache_policy,
                &rule.service_tag,
                &orig_method,
                &host,
                &path_and_query,
                lookup_headers,
            ) {
                CacheLookup::Hit { entry, .. } => {
                    // If this single probe needs passive FP beacon injection and the cached HTML is compressed,
                    // bypass cache once so upstream serves uncompressed HTML; otherwise serve straight from RAM!
                    let is_compressed_html = entry
                        .headers
                        .get(header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .map(|ct| ct.to_ascii_lowercase().starts_with("text/html"))
                        .unwrap_or(false)
                        && entry
                            .headers
                            .get(header::CONTENT_ENCODING)
                            .and_then(|v| v.to_str().ok())
                            .map(|ce| !ce.trim().is_empty() && !ce.eq_ignore_ascii_case("identity"))
                            .unwrap_or(false);

                    if fp_inject_token.is_none() || !is_compressed_html {
                        self.cache.record_hit();
                        let mut resp =
                            build_response_from_cache(&entry, &orig_method, lookup_headers, "HIT");
                        if let Some(ref fp_token) = fp_inject_token {
                            resp = maybe_inject_fp_beacon(resp, fp_token, &self.buffer_sem).await;
                        }
                        if !client_fp.is_scanner
                            && suspicion_score < 50
                            && resp.status().as_u16() < 400
                        {
                            self.auto_ban.record_benign_request_with_js_fp(
                                client_ip,
                                tls_ja3,
                                &ua_str,
                                req_js_fp_hash.as_deref(),
                            );
                        }
                        let resp_bytes_out = resp
                            .headers()
                            .get(header::CONTENT_LENGTH)
                            .and_then(|v| v.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or_else(|| resp.body().size_hint().lower());
                        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
                        self.logger
                            .record_access_log(
                                "ingress",
                                &rule.service_tag,
                                &client_ip.to_string(),
                                resp.status().as_u16(),
                                latency_ms,
                                0,
                                resp_bytes_out,
                                false,
                                false,
                                false,
                                None,
                                Some(client_fp.device_type.to_string()),
                                Some(client_fp.browser_family.to_string()),
                                Some(client_fp.os_family.to_string()),
                                fp_verified,
                                log_ctx.meta("cache_hit", Some("HIT"), None, None),
                            )
                            .await;
                        self.logger
                            .record_fingerprint_with_extras(
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
                                fp_extras.clone(),
                                None,
                                1,
                                0,
                                0,
                            )
                            .await;
                        attach_ray_id_header(&mut resp, &ray_id);
                        return resp;
                    }
                    self.cache.record_bypass();
                }
                CacheLookup::Stale { base_key, entry } => {
                    // Attach conditional revalidation headers if client didn't send its own
                    if fp_inject_token.is_none()
                        && !req.headers().contains_key(header::IF_NONE_MATCH)
                        && !req.headers().contains_key(header::IF_MODIFIED_SINCE)
                    {
                        if let Some(ref etag) = entry.etag {
                            if let Ok(hv) = HeaderValue::from_str(etag) {
                                req.headers_mut().insert(header::IF_NONE_MATCH, hv);
                                sent_cache_revalidation = true;
                            }
                        }
                        if let Some(ref lm) = entry.last_modified {
                            if let Ok(hv) = HeaderValue::from_str(lm) {
                                req.headers_mut().insert(header::IF_MODIFIED_SINCE, hv);
                                sent_cache_revalidation = true;
                            }
                        }
                    }
                    cache_store_key = Some(base_key.clone());
                    stale_fallback = Some((base_key, entry));
                }
                CacheLookup::Miss { base_key } => {
                    self.cache.record_miss();
                    cache_store_key = Some(base_key);
                }
                CacheLookup::Bypass => {
                    self.cache.record_bypass();
                }
            }
        }

        if fp_inject_token.is_some() {
            // Request fresh uncompressed HTML from upstream for this single probe request only (once per TTL per browser)
            // and never store the uncompressed/probe response in edge cache.
            cache_store_key = None;
            req.headers_mut().remove(header::ACCEPT_ENCODING);
            req.headers_mut().remove(header::IF_NONE_MATCH);
            req.headers_mut().remove(header::IF_MODIFIED_SINCE);
            sent_cache_revalidation = false;
        }

        let use_h2_mesh = req.version() == Version::HTTP_2 && !is_upgrade;

        // Strip untrusted client-supplied forwarding headers BEFORE injecting authoritative values.
        for h in [
            "x-real-ip",
            "forwarded",
            "true-client-ip",
            "cf-connecting-ip",
            "x-forwarded-host",
            "x-forwarded-port",
            "x-original-url",
            "x-rewrite-url",
        ] {
            req.headers_mut().remove(h);
        }
        // Strip hop-by-hop (incl. dynamic `Connection` tokens) BEFORE injecting authoritative
        // headers, so a client `Connection: host, x-forwarded-for` can never delete the
        // proxy-injected Host / X-Forwarded-* headers (gateway integrity bypass).
        strip_hop_by_hop_headers(req.headers_mut(), use_h2_mesh, is_upgrade);

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

        let request_id = ray_id.clone();
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
            ttl: self.default_ttl.load(Ordering::Relaxed),
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
            self.forwarder
                .open_service_stream(&rule.next_peer, stream_hdr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                if let Some((_, ref stale_entry)) = stale_fallback {
                    if stale_entry.is_usable_stale(Instant::now()) {
                        self.cache.record_stale();
                        let lookup_h = orig_req_headers.as_ref().unwrap();
                        let mut stale_resp =
                            build_response_from_cache(stale_entry, &orig_method, lookup_h, "STALE");
                        let stale_bytes_out = stale_resp
                            .headers()
                            .get(header::CONTENT_LENGTH)
                            .and_then(|v| v.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or_else(|| stale_resp.body().size_hint().lower());
                        self.logger
                            .record_access_log(
                                "ingress",
                                &rule.service_tag,
                                &client_ip.to_string(),
                                stale_resp.status().as_u16(),
                                start.elapsed().as_secs_f64() * 1000.0,
                                req_bytes_in,
                                stale_bytes_out,
                                false,
                                false,
                                false,
                                None,
                                Some(client_fp.device_type.to_string()),
                                Some(client_fp.browser_family.to_string()),
                                Some(client_fp.os_family.to_string()),
                                fp_verified,
                                log_ctx.meta("cache_stale", Some("STALE"), None, None),
                            )
                            .await;
                        attach_ray_id_header(&mut stale_resp, &ray_id);
                        return stale_resp;
                    }
                }
                let msg = format!(
                    "ingress forward to peer={} service={} failed: {}",
                    rule.next_peer, rule.service_tag, e
                );
                if let Some(suppressed) = self
                    .logger
                    .should_log_warn(&format!("mesh:fwd_err:{}", rule.service_tag))
                {
                    warn!(suppressed, "{msg}");
                }
                self.logger
                    .record_access_log(
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
                        Some(client_fp.device_type.to_string()),
                        Some(client_fp.browser_family.to_string()),
                        Some(client_fp.os_family.to_string()),
                        fp_verified,
                        log_ctx.meta("upstream_error", None, None, None),
                    )
                    .await;
                return build_ingress_5xx_response(
                    StatusCode::BAD_GATEWAY,
                    &ray_id,
                    rule.effective_intercept_errors(),
                    cfg.resolved_pages.error.as_deref(),
                    &accept_enc,
                );
            }
            Err(_) => {
                if let Some((_, ref stale_entry)) = stale_fallback {
                    if stale_entry.is_usable_stale(Instant::now()) {
                        self.cache.record_stale();
                        let lookup_h = orig_req_headers.as_ref().unwrap();
                        let mut stale_resp =
                            build_response_from_cache(stale_entry, &orig_method, lookup_h, "STALE");
                        let stale_bytes_out = stale_resp
                            .headers()
                            .get(header::CONTENT_LENGTH)
                            .and_then(|v| v.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or_else(|| stale_resp.body().size_hint().lower());
                        self.logger
                            .record_access_log(
                                "ingress",
                                &rule.service_tag,
                                &client_ip.to_string(),
                                stale_resp.status().as_u16(),
                                start.elapsed().as_secs_f64() * 1000.0,
                                req_bytes_in,
                                stale_bytes_out,
                                false,
                                false,
                                false,
                                None,
                                Some(client_fp.device_type.to_string()),
                                Some(client_fp.browser_family.to_string()),
                                Some(client_fp.os_family.to_string()),
                                fp_verified,
                                log_ctx.meta("cache_stale", Some("STALE"), None, None),
                            )
                            .await;
                        attach_ray_id_header(&mut stale_resp, &ray_id);
                        return stale_resp;
                    }
                }
                self.logger
                    .record_access_log(
                        "ingress",
                        &rule.service_tag,
                        &client_ip.to_string(),
                        504,
                        start.elapsed().as_secs_f64() * 1000.0,
                        req_bytes_in,
                        0,
                        false,
                        false,
                        false,
                        Some("mesh forward timeout".into()),
                        Some(client_fp.device_type.to_string()),
                        Some(client_fp.browser_family.to_string()),
                        Some(client_fp.os_family.to_string()),
                        fp_verified,
                        log_ctx.meta("upstream_error", None, None, None),
                    )
                    .await;
                return build_ingress_5xx_response(
                    StatusCode::GATEWAY_TIMEOUT,
                    &ray_id,
                    rule.effective_intercept_errors(),
                    cfg.resolved_pages.error.as_deref(),
                    &accept_enc,
                );
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
                            Err(_) => Err((
                                StatusCode::GATEWAY_TIMEOUT,
                                "mesh h2 request timed out".into(),
                            )),
                        }
                    }
                    Ok(Err(e)) => Err((StatusCode::BAD_GATEWAY, format!("mesh h2 handshake: {e}"))),
                    Err(_) => Err((
                        StatusCode::GATEWAY_TIMEOUT,
                        "mesh h2 handshake timed out".into(),
                    )),
                }
            } else {
                *req.version_mut() = Version::HTTP_11;
                crate::egress::normalize_request_for_http1(&mut req);
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
                                        let ws_permits = conn_permits.clone();
                                        tokio::spawn(async move {
                                            let _ws_permits = ws_permits;
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
                    Ok(Err(e)) => Err((
                        StatusCode::BAD_GATEWAY,
                        format!("mesh http1 handshake: {e}"),
                    )),
                    Err(_) => Err((
                        StatusCode::GATEWAY_TIMEOUT,
                        "mesh http1 handshake timed out".into(),
                    )),
                }
            };

        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        match proxy_res {
            Ok(mut resp) => {
                // Always strip internal mesh header before caching or returning to external clients.
                let upstream_err_hdr = resp
                    .headers_mut()
                    .remove(INTERNAL_UPSTREAM_ERR_HEADER)
                    .as_ref()
                    .and_then(|v| v.to_str().ok())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                if cache_policy.enabled {
                    let lookup_h = orig_req_headers.as_ref().unwrap();
                    if sent_cache_revalidation && resp.status() == StatusCode::NOT_MODIFIED {
                        if let Some((ref base_key, ref stale_entry)) = stale_fallback {
                            match self.cache.revalidate_304(
                                &cache_policy,
                                base_key,
                                stale_entry,
                                resp.headers(),
                            ) {
                                Some(refreshed) => {
                                    self.cache.record_revalidated();
                                    resp = build_response_from_cache(
                                        &refreshed,
                                        &orig_method,
                                        lookup_h,
                                        "REVALIDATED",
                                    );
                                }
                                None => {
                                    self.cache.record_bypass();
                                    if resp.headers().contains_key(header::SET_COOKIE)
                                        || lookup_h.contains_key(header::IF_NONE_MATCH)
                                        || lookup_h.contains_key(header::IF_MODIFIED_SINCE)
                                    {
                                        resp.headers_mut().insert(
                                            "x-exposure-cache",
                                            HeaderValue::from_static("BYPASS"),
                                        );
                                    } else {
                                        resp = build_response_from_cache(
                                            stale_entry,
                                            &orig_method,
                                            lookup_h,
                                            "BYPASS",
                                        );
                                        resp.headers_mut().insert(
                                            header::CACHE_CONTROL,
                                            HeaderValue::from_static("no-store"),
                                        );
                                    }
                                }
                            }
                        }
                    } else if resp.status().is_server_error() {
                        if let Some((_, ref stale_entry)) = stale_fallback {
                            if stale_entry.is_usable_stale(Instant::now()) {
                                self.cache.record_stale();
                                resp = build_response_from_cache(
                                    stale_entry,
                                    &orig_method,
                                    lookup_h,
                                    "STALE",
                                );
                            }
                        }
                    } else if orig_method == http::Method::GET
                        && cache_store_key.is_some()
                        && EdgeCache::response_headers_cacheable(
                            &cache_policy,
                            resp.status(),
                            resp.headers(),
                        )
                    {
                        let base_key = cache_store_key.as_ref().unwrap();
                        resp = maybe_store_in_cache(
                            &self.cache,
                            &cache_policy,
                            base_key,
                            lookup_h,
                            Arc::clone(&self.buffer_sem),
                            resp,
                        )
                        .await;
                    } else {
                        let status_hdr = if cache_store_key.is_some() {
                            "MISS"
                        } else {
                            "BYPASS"
                        };
                        resp.headers_mut()
                            .insert("x-exposure-cache", HeaderValue::from_static(status_hdr));
                    }
                }
                if let Some(ref fp_token) = fp_inject_token {
                    resp = maybe_inject_fp_beacon(resp, fp_token, &self.buffer_sem).await;
                }
                if !client_fp.is_scanner && suspicion_score < 50 && resp.status().as_u16() < 400 {
                    self.auto_ban.record_benign_request_with_js_fp(
                        client_ip,
                        tls_ja3,
                        &ua_str,
                        req_js_fp_hash.as_deref(),
                    );
                }
                let cache_hdr = resp
                    .headers()
                    .get("x-exposure-cache")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let logged_err = if resp.status().is_server_error() {
                    let err_msg = match upstream_err_hdr {
                        Some(msg) => msg,
                        None => {
                            let (rebuilt_resp, summary) = capture_5xx_response_error(resp).await;
                            resp = rebuilt_resp;
                            summary
                        }
                    };
                    if rule.effective_intercept_errors() {
                        resp = build_ingress_5xx_response(
                            resp.status(),
                            &ray_id,
                            true,
                            cfg.resolved_pages.error.as_deref(),
                            &accept_enc,
                        );
                    }
                    Some(err_msg)
                } else {
                    None
                };
                if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
                    attach_ray_id_header(&mut resp, &ray_id);
                }
                let resp_bytes_out = resp
                    .headers()
                    .get(header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or_else(|| resp.body().size_hint().lower());
                let (log_action, w_rule_id, w_category) = match waf_monitor_hit {
                    Some((rid, cat)) => ("waf_monitor", rid, Some(cat)),
                    None if cache_hdr.as_deref() == Some("STALE") => ("cache_stale", None, None),
                    None if resp.status().is_server_error() => ("upstream_error", None, None),
                    None => ("allow", None, None),
                };
                self.logger
                    .record_access_log(
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
                        logged_err,
                        Some(client_fp.device_type.to_string()),
                        Some(client_fp.browser_family.to_string()),
                        Some(client_fp.os_family.to_string()),
                        fp_verified,
                        log_ctx.meta(log_action, cache_hdr.as_deref(), w_rule_id, w_category),
                    )
                    .await;
                self.logger
                    .record_fingerprint_with_extras(
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
                        fp_extras.clone(),
                        None,
                        1,
                        0,
                        0,
                    )
                    .await;
                resp
            }
            Err((err_status, err)) => {
                if let Some((_, ref stale_entry)) = stale_fallback {
                    if stale_entry.is_usable_stale(Instant::now()) {
                        self.cache.record_stale();
                        let lookup_h = orig_req_headers.as_ref().unwrap();
                        let mut stale_resp =
                            build_response_from_cache(stale_entry, &orig_method, lookup_h, "STALE");
                        let stale_bytes_out = stale_resp
                            .headers()
                            .get(header::CONTENT_LENGTH)
                            .and_then(|v| v.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or_else(|| stale_resp.body().size_hint().lower());
                        self.logger
                            .record_access_log(
                                "ingress",
                                &rule.service_tag,
                                &client_ip.to_string(),
                                stale_resp.status().as_u16(),
                                latency_ms,
                                req_bytes_in,
                                stale_bytes_out,
                                false,
                                false,
                                false,
                                None,
                                Some(client_fp.device_type.to_string()),
                                Some(client_fp.browser_family.to_string()),
                                Some(client_fp.os_family.to_string()),
                                fp_verified,
                                log_ctx.meta("cache_stale", Some("STALE"), None, None),
                            )
                            .await;
                        attach_ray_id_header(&mut stale_resp, &ray_id);
                        return stale_resp;
                    }
                }
                if let Some(suppressed) = self
                    .logger
                    .should_log_warn(&format!("ingress:proxy_err:{}", rule.service_tag))
                {
                    warn!(ray_id = %ray_id, service = %rule.service_tag, error = %err, suppressed, "ingress proxy error");
                }
                self.logger
                    .record_access_log(
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
                        Some(client_fp.device_type.to_string()),
                        Some(client_fp.browser_family.to_string()),
                        Some(client_fp.os_family.to_string()),
                        fp_verified,
                        log_ctx.meta("upstream_error", None, None, None),
                    )
                    .await;
                build_ingress_5xx_response(
                    err_status,
                    &ray_id,
                    rule.effective_intercept_errors(),
                    cfg.resolved_pages.error.as_deref(),
                    &accept_enc,
                )
            }
        }
    }
}

/// Client `Accept-Encoding`, used to gzip locally rendered intercept pages.
fn accept_encoding(headers: &HeaderMap) -> &str {
    headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

fn build_ingress_5xx_response(
    status: StatusCode,
    ray_id: &str,
    intercept_errors: bool,
    error_html_template: Option<&str>,
    accept_enc: &str,
) -> Response<ProxyBody> {
    let (title, detail) = status_title_and_detail(status);
    if intercept_errors {
        let html = exposure_core::assets::render_exposure_error_html_with_template(
            error_html_template,
            status.as_u16(),
            title,
            detail,
            ray_id,
            None,
        );
        // The built-in page inlines a ~64 KiB SVG; gzip keeps the intercept path cheap in bytes.
        let (body, encoding) =
            exposure_core::assets::maybe_gzip_body(html.into_bytes(), accept_enc);
        let mut builder = Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-store")
            .header(RAY_ID_HEADER, ray_id)
            .header(header::VARY, "Accept-Encoding");
        if let Some(encoding) = encoding {
            builder = builder.header(header::CONTENT_ENCODING, encoding);
        }
        return builder.body(full_body(body)).unwrap();
    }
    Response::builder()
        .status(status)
        .header(RAY_ID_HEADER, ray_id)
        .body(full_body(format!("{} {title}", status.as_u16())))
        .unwrap()
}

/// Collect up to `policy.max_object_bytes` from an eligible upstream response to store in `EdgeCache`.
/// If the response exceeds the single-object limit mid-stream, transparently falls back to streaming via `PrefixBody`.
async fn maybe_store_in_cache(
    cache: &EdgeCache,
    policy: &EffectiveCachePolicy,
    base_key: &str,
    req_headers: &http::HeaderMap,
    buffer_sem: Arc<Semaphore>,
    resp: Response<ProxyBody>,
) -> Response<ProxyBody> {
    let limit = policy.max_object_bytes as usize;
    // Bound concurrent in-flight buffering globally (memory-amplification DoS protection).
    // Under heavy buffering load, bypass cache instead of blocking upstream response streaming.
    let Ok(_buffer_permit) = buffer_sem.try_acquire_owned() else {
        let mut resp = resp;
        resp.headers_mut()
            .insert("x-exposure-cache", HeaderValue::from_static("BYPASS"));
        return resp;
    };
    let (mut parts, mut body) = resp.into_parts();
    let mut collected = Vec::new();
    let mut exceeded = false;
    let mut stream_err = false;

    while let Some(frame_res) = body.frame().await {
        match frame_res {
            Ok(frame) => {
                if let Some(data) = frame.data_ref() {
                    if collected.len().saturating_add(data.len()) > limit {
                        collected.extend_from_slice(data);
                        exceeded = true;
                        break;
                    }
                    collected.extend_from_slice(data);
                }
            }
            Err(_) => {
                stream_err = true;
                break;
            }
        }
    }

    if stream_err {
        return Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header(header::CACHE_CONTROL, "no-store")
            .body(full_body("502 Bad Gateway: upstream body stream truncated"))
            .unwrap();
    }

    if exceeded {
        parts
            .headers
            .insert("x-exposure-cache", HeaderValue::from_static("BYPASS"));
        let chained = PrefixBody {
            prefix: Some(Bytes::from(collected)),
            rest: body,
        };
        return Response::from_parts(parts, chained.boxed());
    }

    let bytes = Bytes::from(collected);
    let stored = cache.store(
        policy,
        base_key,
        req_headers,
        parts.status,
        &parts.headers,
        bytes.clone(),
    );
    parts.headers.remove(header::TRANSFER_ENCODING);
    if let Ok(hv) = HeaderValue::from_str(&bytes.len().to_string()) {
        parts.headers.insert(header::CONTENT_LENGTH, hv);
    }
    // Only report MISS when the object actually entered the cache; otherwise the response was
    // streamed but rejected by the cacheability guards (Vary/cookie/TTL), which is a BYPASS.
    parts.headers.insert(
        "x-exposure-cache",
        HeaderValue::from_static(if stored { "MISS" } else { "BYPASS" }),
    );
    Response::from_parts(parts, full_body(bytes))
}

/// Inject `<script defer src="/cdn-cgi/fp.js" data-t="..."></script>` into eligible uncompressed 2xx HTML responses.
/// Safely passes through oversized, non-HTML, or high-load responses untouched without stalling normal traffic.
async fn maybe_inject_fp_beacon(
    resp: Response<ProxyBody>,
    fp_token: &str,
    buffer_sem: &Arc<Semaphore>,
) -> Response<ProxyBody> {
    // Non-blocking memory pressure guard: under heavy load, skip passive beacon injection and stream directly!
    let Ok(_buf_permit) = Arc::clone(buffer_sem).try_acquire_owned() else {
        return resp;
    };
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
            ct_l.starts_with("text/html") && !ct_l.contains("utf-16") && !ct_l.contains("utf-32")
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
                return Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .header(header::CACHE_CONTROL, "no-store")
                    .body(full_body("502 Bad Gateway: upstream body stream truncated"))
                    .unwrap();
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

    let snippet = format!(r#"<script defer src="/cdn-cgi/fp.js" data-t="{fp_token}"></script>"#);
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
    parts
        .headers
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Response::from_parts(parts, full_body(injected))
}

fn rfind_ascii_case_insensitive(haystack: &[u8], needle_lower: &[u8]) -> Option<usize> {
    if needle_lower.is_empty() || haystack.len() < needle_lower.len() {
        return None;
    }
    haystack.windows(needle_lower.len()).rposition(|w| {
        w.iter()
            .zip(needle_lower)
            .all(|(a, b)| a.to_ascii_lowercase() == *b)
    })
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
    let mut host_iter = req.headers().get_all(header::HOST).iter();
    let first_host = host_iter.next();
    if host_iter.next().is_some() {
        return Err("400 Bad Request: Multiple Host headers");
    }
    let hdr_host = first_host
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let uri_auth = req.uri().authority().map(|a| a.as_str());

    if let (Some(h), Some(a)) = (hdr_host, uri_auth) {
        let Some(nh) = parse_valid_host(h) else {
            return Err("400 Bad Request: Invalid Host header");
        };
        let Some(na) = parse_valid_host(a) else {
            return Err("400 Bad Request: Invalid authority");
        };
        if nh != na {
            return Err("400 Bad Request: Host and authority mismatch");
        }
    }
    if let Some(h) = hdr_host {
        if parse_valid_host(h).is_none() {
            return Err("400 Bad Request: Invalid Host header");
        }
        return Ok(h.to_string());
    }
    if let Some(a) = uri_auth {
        if parse_valid_host(a).is_none() {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WafBodyReadError {
    Timeout,
    Io,
}

async fn buffer_prefix_for_waf(
    req: Request<ProxyBody>,
    limit: usize,
) -> std::result::Result<(Request<ProxyBody>, Bytes), WafBodyReadError> {
    let (parts, mut body) = req.into_parts();
    let mut collected = Vec::new();
    let mut exceeded = false;
    let mut io_failed = false;
    let read_res = tokio::time::timeout(WAF_BODY_READ_TIMEOUT, async {
        while let Some(frame_res) = body.frame().await {
            match frame_res {
                Ok(frame) => {
                    if let Some(data) = frame.data_ref() {
                        collected.extend_from_slice(data);
                        if collected.len() >= limit {
                            exceeded = true;
                            break;
                        }
                    }
                }
                Err(_) => {
                    io_failed = true;
                    break;
                }
            }
        }
    })
    .await;
    if read_res.is_err() {
        return Err(WafBodyReadError::Timeout);
    }
    if io_failed {
        return Err(WafBodyReadError::Io);
    }
    let inspected_len = collected.len().min(limit);
    let prefix = Bytes::from(collected);
    let inspected = prefix.slice(..inspected_len);
    let rebuilt_body = if exceeded {
        PrefixBody {
            prefix: Some(prefix),
            rest: body,
        }
        .boxed()
    } else {
        full_body(prefix)
    };
    Ok((Request::from_parts(parts, rebuilt_body), inspected))
}

fn build_waf_block_response(
    finding: &WafFinding,
    intercept_errors: bool,
    browser_nav: bool,
    ray_id: &str,
    error_html_template: Option<&str>,
    accept_enc: &str,
) -> Response<ProxyBody> {
    if intercept_errors && browser_nav {
        let html = exposure_core::assets::render_exposure_error_html_with_template(
            error_html_template,
            403,
            "Request Blocked",
            "Your request was blocked by the edge web application firewall.",
            ray_id,
            None,
        );
        let (body, encoding) =
            exposure_core::assets::maybe_gzip_body(html.into_bytes(), accept_enc);
        let mut builder = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-store")
            .header("x-exposure-waf", "BLOCK")
            .header("x-exposure-ray", ray_id)
            .header(header::VARY, "Accept-Encoding");
        if let Some(encoding) = encoding {
            builder = builder.header(header::CONTENT_ENCODING, encoding);
        }
        return builder.body(full_body(body)).unwrap();
    }
    let body = serde_json::json!({
        "error": "waf_blocked",
        "category": finding.category,
        "rule_id": finding.rule_id,
        "ray_id": ray_id,
    })
    .to_string();
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-exposure-waf", "BLOCK")
        .header("x-exposure-ray", ray_id)
        .body(full_body(body))
        .unwrap()
}

fn build_rate_limit_response(
    retry_after_secs: u64,
    show_error_page: bool,
    intercept_errors: bool,
    ray_id: &str,
    error_html_template: Option<&str>,
    accept_enc: &str,
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
        let (body, encoding) =
            exposure_core::assets::maybe_gzip_body(html.into_bytes(), accept_enc);
        let mut builder = Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header(header::RETRY_AFTER, retry_after_secs.to_string())
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-store")
            .header(RAY_ID_HEADER, ray_id)
            .header(header::VARY, "Accept-Encoding");
        if let Some(encoding) = encoding {
            builder = builder.header(header::CONTENT_ENCODING, encoding);
        }
        return builder.body(full_body(body)).unwrap();
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
        .header(RAY_ID_HEADER, ray_id)
        .body(full_body(body))
        .unwrap()
}

fn is_browser_navigation(method: &http::Method, headers: &http::HeaderMap) -> bool {
    if method != http::Method::GET && method != http::Method::HEAD {
        return false;
    }
    if let Some(xrw) = headers
        .get("x-requested-with")
        .and_then(|v| v.to_str().ok())
    {
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
    use hyper::body::Frame;

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
        let html_resp = build_rate_limit_response(5, true, true, "ray1", None, "");
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
            "",
        );
        let custom_bytes = custom_resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            String::from_utf8(custom_bytes.to_vec()).unwrap(),
            "<html>custom 429 rayc</html>"
        );

        let degraded_resp = build_rate_limit_response(5, false, true, "ray2", None, "");
        assert_eq!(degraded_resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            degraded_resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        let degraded_bytes = degraded_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(&degraded_bytes[..], b"429");
    }

    #[tokio::test]
    async fn intercept_page_is_gzipped_only_when_client_accepts_it() {
        let plain = build_rate_limit_response(5, true, true, "ray-gz", None, "");
        assert!(plain.headers().get(header::CONTENT_ENCODING).is_none());
        assert_eq!(
            plain.headers().get(header::VARY).unwrap(),
            "Accept-Encoding"
        );

        let gz = build_rate_limit_response(5, true, true, "ray-gz", None, "gzip, deflate");
        assert_eq!(gz.headers().get(header::CONTENT_ENCODING).unwrap(), "gzip");
        let body = gz.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..2], &[0x1f, 0x8b]);

        let refused = build_rate_limit_response(5, true, true, "ray-gz", None, "gzip;q=0");
        assert!(refused.headers().get(header::CONTENT_ENCODING).is_none());
    }

    #[tokio::test]
    async fn waf_block_response_renders_json_or_custom_html() {
        let finding = WafFinding {
            category: "sql-injection",
            location: "query",
            confidence: 0.96,
            reasons: vec!["SQL boolean tautology"],
            matched_payload: None,
            rule_id: None,
            rule_msg: None,
        };
        let api_resp = build_waf_block_response(&finding, true, false, "raywaf1", None, "");
        assert_eq!(api_resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(api_resp.headers().get("x-exposure-waf").unwrap(), "BLOCK");
        assert_eq!(
            api_resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json; charset=utf-8"
        );
        let api_bytes = api_resp.into_body().collect().await.unwrap().to_bytes();
        let api_str = String::from_utf8(api_bytes.to_vec()).unwrap();
        assert!(api_str.contains("\"waf_blocked\""));
        assert!(api_str.contains("\"sql-injection\""));
        assert!(api_str.contains("\"raywaf1\""));

        let html_resp = build_waf_block_response(
            &finding,
            true,
            true,
            "raywaf2",
            Some("<html>blocked {{status}} {{ray_id}}</html>"),
            "",
        );
        assert_eq!(html_resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            html_resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        let html_bytes = html_resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            String::from_utf8(html_bytes.to_vec()).unwrap(),
            "<html>blocked 403 raywaf2</html>"
        );
    }

    #[tokio::test]
    async fn buffer_prefix_for_waf_preserves_full_streaming_body() {
        use futures::stream::iter;
        use http_body_util::StreamBody;

        let chunks = vec![
            Ok::<_, hyper::Error>(Frame::data(Bytes::from_static(b"hello-"))),
            Ok(Frame::data(Bytes::from_static(b"world-"))),
            Ok(Frame::data(Bytes::from_static(b"1234567890"))),
        ];
        let body: ProxyBody = StreamBody::new(iter(chunks)).boxed();
        let req = Request::builder()
            .method("POST")
            .uri("/submit")
            .body(body)
            .unwrap();

        // Limit smaller than total body -> inspects first 10 bytes, preserves entire 22 bytes on rebuilt req
        let (rebuilt, inspected) = buffer_prefix_for_waf(req, 10).await.unwrap();
        assert_eq!(&inspected[..], b"hello-worl");
        let full = rebuilt.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&full[..], b"hello-world-1234567890");
    }

    #[tokio::test]
    async fn live_ingress_waf_evilpot_diverts_verifies_canary_and_caps_cc_flood() {
        use exposure_core::config::{
            EgressConfig, GuardProfile, IngressRule, LoggerConfig, NodeRoles, RelayConfig,
            RuleMatch, SegmentConfig, WafConfig,
        };
        use exposure_link::LinkManager;
        use std::collections::BTreeMap;

        let tmp_dir = std::env::temp_dir().join(format!("exp-ep-test-{}", Uuid::new_v4()));
        let logger = NodeLogger::new(
            "ing-ep",
            LoggerConfig {
                hmac_key: generate_random_secret_hex(32),
                store_raw_ip: false,
                sample_rate: 1.0,
                hll_precision: 10,
                segment: SegmentConfig {
                    dir: tmp_dir.to_string_lossy().to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();

        let kp = NodeKeyPair::generate();
        let lm = LinkManager::new("ing-ep", kp.clone(), false, vec![], Default::default());
        let egress = crate::egress::EgressHandler::new(
            "ing-ep",
            EgressConfig::default(),
            vec![],
            Arc::clone(&logger),
        );
        let (fwd, _rx) = Forwarder::new(
            "ing-ep",
            NodeRoles {
                ingress: true,
                egress: false,
                relay: false,
                maintainer: false,
            },
            RelayConfig::default(),
            lm,
            egress,
            Arc::clone(&logger),
        );

        let mut guards = BTreeMap::new();
        guards.insert(
            "ep-guard".to_string(),
            GuardProfile {
                waf: Some(WafConfig {
                    mode: WafMode::Evilpot,
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let cfg = IngressConfig {
            rules: vec![IngressRule {
                name: Some("main".into()),
                r#match: RuleMatch {
                    host: Some("victim.test".into()),
                    ..Default::default()
                },
                service_tag: "svc-web".into(),
                next_peer: "missing-peer".into(),
                guard: Some("ep-guard".into()),
                intercept_errors: Some(false),
                js_fp_beacon: Some(false),
                cache: None,
                ..Default::default()
            }],
            guards,
            server_header: "exposure-custom-sentinel".into(),
            ..Default::default()
        };

        let server = IngressServer::new(
            "ing-ep",
            kp,
            cfg.clone(),
            8,
            fwd,
            DynamicCertResolver::new(),
            Arc::clone(&logger),
        );
        let bound = server
            .start_listener(IngressListener {
                listen_addr: "127.0.0.1:0".into(),
                tls: false,
                redirect_https: false,
            })
            .await
            .unwrap();

        let client = reqwest::Client::new();
        let base = format!("http://{bound}");

        // 1. Attack triggers WAF -> diverted to Evilpot (stealthy: no X-Exposure-Waf, exact proxy Server header preserved, no backend leak headers)
        let r1 = client
            .get(format!("{base}/download?file=../../../../.env"))
            .header("Host", "victim.test")
            .send()
            .await
            .unwrap();
        assert_eq!(r1.status(), 200);
        assert!(r1.headers().get("x-exposure-waf").is_none());
        assert!(r1.headers().get("x-powered-by").is_none());
        assert!(r1.headers().get("x-backend-node").is_none());
        assert_eq!(
            r1.headers()
                .get("server")
                .and_then(|v| v.to_str().ok())
                .unwrap_or(""),
            "exposure-custom-sentinel",
            "evilpot response must match proxy Server header to avoid single-request fingerprinting"
        );
        let env_body = r1.text().await.unwrap();
        let canary_key = env_body
            .lines()
            .find_map(|l| l.strip_prefix("ADMIN_BYPASS_TOKEN="))
            .expect("decoy .env must embed canary token")
            .trim()
            .to_string();
        assert!(canary_key.len() >= 16);
        assert!(!canary_key.starts_with("epk_"));

        // 2. Follow-up benign-looking request replaying stolen canary token -> caught & VerifiedExploit!
        let r2 = client
            .get(format!("{base}/api/v1/users"))
            .header("Host", "victim.test")
            .header("Authorization", format!("Bearer {canary_key}"))
            .send()
            .await
            .unwrap();
        assert_eq!(r2.status(), 200);

        let report = server
            .evilpot_report()
            .await
            .expect("evilpot report active");
        assert_eq!(report.canary_verifications, 1);
        assert_eq!(report.verified_attack_sessions, 1);
        assert_eq!(report.sessions.len(), 1);
        assert_eq!(report.sessions[0].status, "verified_exploit");

        let alerts = logger.recent_alerts().await;
        assert!(
            alerts
                .iter()
                .any(|a| a.severity == "critical" && a.message.contains("VerifiedExploit")),
            "expected critical alert for VerifiedExploit, got: {alerts:?}"
        );

        // 3. CC flood (>45 requests/min from same IP) degrades cleanly to fast 403
        let mut saw_403 = false;
        for i in 0..50 {
            let r = client
                .get(format!("{base}/search?q=admin'+OR+'1'='1'+--&i={i}"))
                .header("Host", "victim.test")
                .send()
                .await
                .unwrap();
            if r.status() == 403 {
                saw_403 = true;
                break;
            }
        }
        assert!(saw_403, "CC flood against evilpot must degrade to fast 403");

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[tokio::test]
    async fn live_ingress_evilpot_closes_rule_gaps_and_preserves_xss_session_chain() {
        use exposure_core::config::{
            AntibotMode, EgressConfig, GuardProfile, IngressRule, LoggerConfig, NodeRoles,
            RelayConfig, RuleMatch, SegmentConfig, WafConfig,
        };
        use exposure_link::LinkManager;
        use std::collections::BTreeMap;

        let tmp_dir = std::env::temp_dir().join(format!("exp-ep-chain-{}", Uuid::new_v4()));
        let logger = NodeLogger::new(
            "ing-ep2",
            LoggerConfig {
                hmac_key: generate_random_secret_hex(32),
                store_raw_ip: false,
                sample_rate: 1.0,
                hll_precision: 10,
                segment: SegmentConfig {
                    dir: tmp_dir.to_string_lossy().to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();

        let kp = NodeKeyPair::generate();
        let lm = LinkManager::new("ing-ep2", kp.clone(), false, vec![], Default::default());
        let egress = crate::egress::EgressHandler::new(
            "ing-ep2",
            EgressConfig::default(),
            vec![],
            Arc::clone(&logger),
        );
        let (fwd, _rx) = Forwarder::new(
            "ing-ep2",
            NodeRoles {
                ingress: true,
                egress: false,
                relay: false,
                maintainer: false,
            },
            RelayConfig::default(),
            lm,
            egress,
            Arc::clone(&logger),
        );

        let mut guards = BTreeMap::new();
        guards.insert(
            "ep-challenge-guard".to_string(),
            GuardProfile {
                antibot: AntibotMode::Challenge,
                challenge_threshold: 50,
                waf: Some(WafConfig {
                    mode: WafMode::Evilpot,
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let cfg = IngressConfig {
            rules: vec![IngressRule {
                name: Some("main".into()),
                r#match: RuleMatch {
                    host: Some("victim.test".into()),
                    ..Default::default()
                },
                service_tag: "svc-web".into(),
                next_peer: "missing-peer".into(),
                guard: Some("ep-challenge-guard".into()),
                intercept_errors: Some(false),
                js_fp_beacon: Some(false),
                cache: None,
                ..Default::default()
            }],
            guards,
            server_header: "nginx".into(),
            // Disable auto-ban in this multi-payload rule-coverage test so one loopback client
            // can exercise all 6 sequential SQLi/CMDi/XSS/canary traps in a row.
            auto_ban: exposure_core::config::AutoBanConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };

        let server = IngressServer::new(
            "ing-ep2",
            kp,
            cfg.clone(),
            8,
            fwd,
            DynamicCertResolver::new(),
            Arc::clone(&logger),
        );
        let bound = server
            .start_listener(IngressListener {
                listen_addr: "127.0.0.1:0".into(),
                tls: false,
                redirect_https: false,
            })
            .await
            .unwrap();

        // Client that will NOT auto-follow 302 redirects so we verify no 302 is returned
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let base = format!("http://{bound}");

        // Browser headers that pass default Guard challenge threshold (0 + 0 + 0 = 0 < 50)
        let browser_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0 Safari/537.36";

        // 1. SQLi tautology `1 OR 1=1`, CMDi `;id;#`, `;ls`, `;echo ok` must ALL hit Evilpot (200), not fall through to missing-peer (502)
        for (q, expected_sub) in [
            ("client_id=1%20OR%201%3D1", "FOUND"),
            ("client_id=%3Bid%3B%23", "uid=1000"),
            ("client_id=%3Bls", "deploy_notes.txt"),
            ("client_id=%3Becho%20ok_rce", "ok_rce"),
        ] {
            let r = client
                .get(format!("{base}/oauth/authorize?{q}"))
                .header("Host", "victim.test")
                .header("User-Agent", browser_ua)
                .header("Accept", "text/html")
                .header("Accept-Language", "en-US,en;q=0.9")
                .header("Sec-Fetch-Mode", "navigate")
                .send()
                .await
                .unwrap();
            assert_eq!(r.status(), 200, "query `{q}` must hit evilpot");
            assert_eq!(r.headers().get("server").unwrap(), "nginx");
            let body = r.text().await.unwrap();
            assert!(
                body.contains(expected_sub),
                "query `{q}` expected `{expected_sub}`, got `{body}`"
            );
        }

        // 2. XSS reflects payload and sets admin_session_id; replaying admin_session_id even WITHOUT
        // Accept-Language / Sec-Fetch-Mode (which would normally trigger Guard 302 /cdn-cgi/) returns 200 Admin Console!
        let xss_r = client
            .get(format!(
                "{base}/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
            ))
            .header("Host", "victim.test")
            .header("User-Agent", browser_ua)
            .header("Accept", "text/html")
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("Sec-Fetch-Mode", "navigate")
            .send()
            .await
            .unwrap();
        assert_eq!(xss_r.status(), 200);
        let set_cookie = xss_r
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        assert!(set_cookie.starts_with("admin_session_id="));
        let xss_body = xss_r.text().await.unwrap();
        assert!(xss_body.contains("<script>alert(1)</script>"));

        // Replay admin_session_id without Accept-Language / Sec-Fetch-Mode (score=50 >= challenge_threshold)
        let replay_r = client
            .get(format!("{base}/admin"))
            .header("Host", "victim.test")
            .header("User-Agent", browser_ua)
            .header("Accept", "text/html")
            .header("Cookie", &set_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(
            replay_r.status(),
            200,
            "replayed admin_session_id must not 302 to /cdn-cgi/"
        );
        let admin_html = replay_r.text().await.unwrap();
        assert!(admin_html.contains("Admin Console"));

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[tokio::test]
    async fn abuseipdb_proactively_queries_on_any_request_and_records_in_fingerprints() {
        use exposure_core::config::{
            AbuseIpDbConfig, AntibotMode, EgressConfig, GuardProfile, IngressRule, LoggerConfig,
            NodeRoles, RelayConfig, RuleMatch, SegmentConfig, WafConfig,
        };
        use exposure_link::LinkManager;
        use std::collections::BTreeMap;
        use std::sync::atomic::AtomicU32;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let abuse_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let abuse_addr = abuse_listener.local_addr().unwrap();
        let hits = Arc::new(AtomicU32::new(0));
        let hits_srv = Arc::clone(&hits);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = abuse_listener.accept().await else {
                    break;
                };
                hits_srv.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let body = r#"{"data":{"ipAddress":"118.25.6.39","abuseConfidenceScore":88,"countryCode":"US","isp":"ScannerNet","usageType":"Data Center","isTor":true,"totalReports":25}}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });

        let tmp_dir = std::env::temp_dir().join(format!("exp-ab-test-{}", Uuid::new_v4()));
        let logger = NodeLogger::new(
            "ing-ab",
            LoggerConfig {
                hmac_key: generate_random_secret_hex(32),
                store_raw_ip: false,
                sample_rate: 1.0,
                hll_precision: 10,
                segment: SegmentConfig {
                    dir: tmp_dir.to_string_lossy().to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();

        let kp = NodeKeyPair::generate();
        let lm = LinkManager::new("ing-ab", kp.clone(), false, vec![], Default::default());
        let egress = crate::egress::EgressHandler::new(
            "ing-ab",
            EgressConfig::default(),
            vec![],
            Arc::clone(&logger),
        );
        let (fwd, _rx) = Forwarder::new(
            "ing-ab",
            NodeRoles {
                ingress: true,
                egress: false,
                relay: false,
                maintainer: false,
            },
            RelayConfig::default(),
            lm,
            egress,
            Arc::clone(&logger),
        );

        let abuse_cfg = AbuseIpDbConfig {
            enabled: true,
            api_key: "mock-key".into(),
            challenge_threshold: 25,
            block_threshold: 95, // allow reaching Guard/WAF/404 with score 88 so we test all non-HTML paths
            high_risk_action: AbuseIpDbAction::Monitor,
            cache_ttl_secs: 3600,
            ..Default::default()
        };
        let abuse_client = AbuseIpDbClient::with_endpoint(
            abuse_cfg.clone(),
            format!("http://{abuse_addr}/api/v2/check"),
        );

        let mut guards = BTreeMap::new();
        guards.insert(
            "bot-guard".to_string(),
            GuardProfile {
                antibot: AntibotMode::Challenge,
                block_bots: Some(true),
                waf: Some(WafConfig {
                    mode: WafMode::Evilpot,
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let cfg = IngressConfig {
            rules: vec![IngressRule {
                name: Some("main".into()),
                r#match: RuleMatch {
                    host: Some("victim.test".into()),
                    url_prefix: Some("/api".into()),
                    ..Default::default()
                },
                service_tag: "svc-api".into(),
                next_peer: "missing-peer".into(),
                guard: Some("bot-guard".into()),
                intercept_errors: Some(false),
                js_fp_beacon: Some(false),
                cache: None,
                ..Default::default()
            }],
            guards,
            abuseipdb: abuse_cfg,
            ..Default::default()
        };

        let server = IngressServer::new_with_abuseipdb(
            "ing-ab",
            kp,
            cfg,
            8,
            fwd,
            DynamicCertResolver::new(),
            Arc::clone(&logger),
            abuse_client,
        );

        let public_peer: SocketAddr = "118.25.6.39:54321".parse().unwrap();

        // 1. Unmatched 404 request (no HTML, no matched route) STILL queries AbuseIPDB immediately!
        let (client_io1, server_io1) = tokio::io::duplex(8192);
        let srv1 = Arc::clone(&server);
        tokio::spawn(async move {
            srv1.serve_conn(server_io1, public_peer, false, false, None, None)
                .await;
        });
        let (mut r1, mut w1) = tokio::io::split(client_io1);
        w1.write_all(b"GET /does-not-exist HTTP/1.1\r\nHost: victim.test\r\nUser-Agent: custom-probe/1.0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut raw_resp1 = Vec::new();
        r1.read_to_end(&mut raw_resp1).await.unwrap();
        let resp1_str = String::from_utf8_lossy(&raw_resp1);
        assert!(
            resp1_str.starts_with("HTTP/1.1 404"),
            "expected 404, got: {resp1_str}"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "first appearance must query AbuseIPDB"
        );

        // 2. Second request (Guard 403 on curl) uses cache (hits stays 1) and keeps abuse_score=88 in fingerprint
        let (client_io2, server_io2) = tokio::io::duplex(8192);
        let srv2 = Arc::clone(&server);
        tokio::spawn(async move {
            srv2.serve_conn(server_io2, public_peer, false, false, None, None)
                .await;
        });
        let (mut r2, mut w2) = tokio::io::split(client_io2);
        w2.write_all(b"GET /api/v1/users HTTP/1.1\r\nHost: victim.test\r\nUser-Agent: curl/8.5.0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut raw_resp2 = Vec::new();
        r2.read_to_end(&mut raw_resp2).await.unwrap();
        let resp2_str = String::from_utf8_lossy(&raw_resp2);
        assert!(
            resp2_str.starts_with("HTTP/1.1 403"),
            "expected 403, got: {resp2_str}"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "second request must hit AbuseIPDB cache"
        );

        let (_, _, fps) = logger.drain_for_maintainer().await;
        assert_eq!(
            fps.len(),
            2,
            "expected fingerprints for both 404 and Guard 403"
        );
        for fp in &fps {
            assert_eq!(fp.abuse_score, Some(88));
            assert_eq!(fp.abuse_country.as_deref(), Some("US"));
            assert_eq!(fp.abuse_isp.as_deref(), Some("ScannerNet"));
            assert!(fp.abuse_is_tor);
        }

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[tokio::test]
    async fn non_browser_clients_pass_while_attacks_tarpit_confirm_and_autoban_ip_and_fingerprint()
    {
        use exposure_core::config::{
            AntibotMode, AutoBanConfig, EgressConfig, GuardProfile, IngressRule, LoggerConfig,
            NodeRoles, RelayConfig, RuleMatch, SegmentConfig, WafConfig,
        };
        use exposure_link::LinkManager;
        use std::collections::BTreeMap;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let tmp_dir = std::env::temp_dir().join(format!("exp-autoban-test-{}", Uuid::new_v4()));
        let logger = NodeLogger::new(
            "ing-ab-flow",
            LoggerConfig {
                hmac_key: generate_random_secret_hex(32),
                store_raw_ip: false,
                sample_rate: 1.0,
                hll_precision: 10,
                segment: SegmentConfig {
                    dir: tmp_dir.to_string_lossy().to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();

        let kp = NodeKeyPair::generate();
        let lm = LinkManager::new("ing-ab-flow", kp.clone(), false, vec![], Default::default());
        let egress = crate::egress::EgressHandler::new(
            "ing-ab-flow",
            EgressConfig::default(),
            vec![],
            Arc::clone(&logger),
        );
        let (fwd, _rx) = Forwarder::new(
            "ing-ab-flow",
            NodeRoles {
                ingress: true,
                egress: false,
                relay: false,
                maintainer: false,
            },
            RelayConfig::default(),
            lm,
            egress,
            Arc::clone(&logger),
        );

        let mut guards = BTreeMap::new();
        guards.insert(
            "api-and-web".to_string(),
            GuardProfile {
                antibot: AntibotMode::Challenge,
                // browser_only defaults to false: non-browser API/CLI clients MUST NOT be blindly blocked!
                waf: Some(WafConfig {
                    mode: WafMode::Evilpot,
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let cfg = IngressConfig {
            rules: vec![IngressRule {
                name: Some("api".into()),
                r#match: RuleMatch {
                    host: Some("api.example.test".into()),
                    ..Default::default()
                },
                service_tag: "svc-api".into(),
                next_peer: "missing-peer".into(),
                guard: Some("api-and-web".into()),
                intercept_errors: Some(false),
                js_fp_beacon: Some(false),
                cache: None,
                ..Default::default()
            }],
            guards,
            auto_ban: AutoBanConfig {
                enabled: true,
                ban_ttl_secs: 600,
                max_ban_ttl_secs: 3600,
                confirm_hits: 3,
                ban_fingerprints: true,
                drop_at_tcp: true,
            },
            ..Default::default()
        };

        let server = IngressServer::new(
            "ing-ab-flow",
            kp,
            cfg,
            8,
            fwd,
            DynamicCertResolver::new(),
            Arc::clone(&logger),
        );

        let send_raw = |srv: Arc<IngressServer>,
                        peer: SocketAddr,
                        tls_sig: Option<ClientHelloSignal>,
                        raw_req: String| async move {
            let (client_io, server_io) = tokio::io::duplex(16384);
            tokio::spawn(async move {
                srv.serve_conn(server_io, peer, tls_sig.is_some(), false, None, tls_sig)
                    .await;
            });
            let (mut r, mut w) = tokio::io::split(client_io);
            w.write_all(raw_req.as_bytes()).await.unwrap();
            let mut buf = Vec::new();
            r.read_to_end(&mut buf).await.unwrap();
            String::from_utf8_lossy(&buf).into_owned()
        };

        let benign_api_peer: SocketAddr = "198.51.100.11:40001".parse().unwrap();
        let attacker_peer: SocketAddr = "198.51.100.66:40002".parse().unwrap();
        let attacker_rotated_peer: SocketAddr = "203.0.113.88:40003".parse().unwrap();

        let attacker_tls = ClientHelloSignal {
            sni: Some("api.example.test".into()),
            tls_version: 0x0303,
            cipher_count: 6,
            extension_count: 5,
            has_alpn: true,
            alpn_h2: false,
            has_grease: false,
            supported_groups_count: 2,
            fingerprint: Some("beef00112233445566778899".into()),
        };

        // 1. Honest non-browser API client (`curl/8.5.0`) passes Guard & WAF cleanly (reaches mesh forward -> 502 missing-peer, NOT 403/302!)
        let benign_resp = send_raw(
            Arc::clone(&server),
            benign_api_peer,
            None,
            "GET /v1/health HTTP/1.1\r\nHost: api.example.test\r\nUser-Agent: curl/8.5.0\r\nAccept: application/json\r\nConnection: close\r\n\r\n".into(),
        )
        .await;
        assert!(
            benign_resp.starts_with("HTTP/1.1 502"),
            "honest curl API client must pass Guard+WAF and reach forwarder, got: {benign_resp}"
        );

        // 2. Non-browser attacker sends path traversal -> diverted to Evilpot FIRST (200 fake .env with canary, NOT instant 403!)
        let probe_resp = send_raw(
            Arc::clone(&server),
            attacker_peer,
            Some(attacker_tls.clone()),
            "GET /download?file=../../../../.env HTTP/1.1\r\nHost: api.example.test\r\nUser-Agent: ExploitKit/9.0\r\nAccept: */*\r\nConnection: close\r\n\r\n".into(),
        )
        .await;
        assert!(
            probe_resp.starts_with("HTTP/1.1 200"),
            "initial attack must be diverted to evilpot to waste time, got: {probe_resp}"
        );
        let canary_key = probe_resp
            .lines()
            .find_map(|l| l.strip_prefix("ADMIN_BYPASS_TOKEN="))
            .expect("decoy .env must embed canary token")
            .trim()
            .to_string();
        assert!(
            !server.auto_ban().is_ip_banned_for_tcp(attacker_peer.ip()),
            "single probe must not ban yet before behavior confirmation"
        );

        // 3. Attacker replays stolen canary token -> Evilpot confirms VerifiedExploit and AUTO-BANS IP + composite TLS+UA fingerprint!
        let canary_resp = send_raw(
            Arc::clone(&server),
            attacker_peer,
            Some(attacker_tls.clone()),
            format!(
                "GET /v1/admin/keys HTTP/1.1\r\nHost: api.example.test\r\nUser-Agent: ExploitKit/9.0\r\nAuthorization: Bearer {canary_key}\r\nConnection: close\r\n\r\n"
            ),
        )
        .await;
        assert!(
            canary_resp.starts_with("HTTP/1.1 200"),
            "confirming canary replay returns trap response while registering ban, got: {canary_resp}"
        );
        assert!(
            server.auto_ban().is_ip_banned_for_tcp(attacker_peer.ip()),
            "confirmed attacker IP must now be auto-banned at TCP layer"
        );

        // 4. Subsequent benign-looking request from banned attacker IP -> immediately 403 Forbidden (zero upstream / Evilpot cost)!
        let blocked_ip_resp = send_raw(
            Arc::clone(&server),
            attacker_peer,
            Some(attacker_tls.clone()),
            "GET /v1/health HTTP/1.1\r\nHost: api.example.test\r\nUser-Agent: curl/8.5.0\r\nConnection: close\r\n\r\n".into(),
        )
        .await;
        assert!(
            blocked_ip_resp.starts_with("HTTP/1.1 403"),
            "banned attacker IP must be immediately blocked on all routes, got: {blocked_ip_resp}"
        );

        // 5. Attacker rotates to a BRAND-NEW IP with the same custom TLS+UA fingerprint -> immediately 403 Forbidden!
        let blocked_fp_resp = send_raw(
            Arc::clone(&server),
            attacker_rotated_peer,
            Some(attacker_tls.clone()),
            "GET /v1/health HTTP/1.1\r\nHost: api.example.test\r\nUser-Agent: ExploitKit/9.0\r\nConnection: close\r\n\r\n".into(),
        )
        .await;
        assert!(
            blocked_fp_resp.starts_with("HTTP/1.1 403"),
            "rotating-IP attacker matching banned composite TLS+UA fingerprint must be blocked, got: {blocked_fp_resp}"
        );

        // 6. Legitimate API client remains 100% unaffected!
        let still_ok = send_raw(
            Arc::clone(&server),
            benign_api_peer,
            None,
            "GET /v1/health HTTP/1.1\r\nHost: api.example.test\r\nUser-Agent: curl/8.5.0\r\nConnection: close\r\n\r\n".into(),
        )
        .await;
        assert!(
            still_ok.starts_with("HTTP/1.1 502"),
            "legitimate non-browser client must remain unaffected, got: {still_ok}"
        );

        // 7. Evilpot report surfaces active IP & fingerprint bans + drops
        let report = server.evilpot_report().await.expect("report active");
        assert!(report.active_ip_bans >= 1);
        assert!(report.active_fp_bans >= 1);
        assert!(report.total_ban_drops >= 3);
        assert!(!report.active_bans.is_empty());

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[tokio::test]
    async fn ingress_access_logs_record_urls_redacted_query_and_security_actions() {
        use exposure_core::config::{
            AntibotMode, EgressConfig, GuardProfile, IngressRule, LoggerConfig, NodeRoles,
            RelayConfig, RuleMatch, SegmentConfig, WafConfig,
        };
        use exposure_link::LinkManager;
        use std::collections::BTreeMap;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let tmp_dir = std::env::temp_dir().join(format!("exp-url-log-test-{}", Uuid::new_v4()));
        let logger = NodeLogger::new(
            "ing-url-log",
            LoggerConfig {
                hmac_key: generate_random_secret_hex(32),
                store_raw_ip: false,
                sample_rate: 1.0,
                hll_precision: 10,
                segment: SegmentConfig {
                    dir: tmp_dir.to_string_lossy().to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();

        let kp = NodeKeyPair::generate();
        let lm = LinkManager::new("ing-url-log", kp.clone(), false, vec![], Default::default());
        let egress = crate::egress::EgressHandler::new(
            "ing-url-log",
            EgressConfig::default(),
            vec![],
            Arc::clone(&logger),
        );
        let (fwd, _rx) = Forwarder::new(
            "ing-url-log",
            NodeRoles {
                ingress: true,
                egress: false,
                relay: false,
                maintainer: false,
            },
            RelayConfig::default(),
            lm,
            egress,
            Arc::clone(&logger),
        );

        let mut guards = BTreeMap::new();
        guards.insert(
            "api-guard".to_string(),
            GuardProfile {
                antibot: AntibotMode::Challenge,
                waf: Some(WafConfig {
                    mode: WafMode::Evilpot,
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let cfg = IngressConfig {
            rules: vec![IngressRule {
                name: Some("api".into()),
                r#match: RuleMatch {
                    host: Some("api.example.test".into()),
                    ..Default::default()
                },
                service_tag: "svc-api".into(),
                next_peer: "missing-peer".into(),
                guard: Some("api-guard".into()),
                intercept_errors: Some(false),
                js_fp_beacon: Some(false),
                cache: None,
                ..Default::default()
            }],
            guards,
            ..Default::default()
        };

        let server = IngressServer::new(
            "ing-url-log",
            kp,
            cfg,
            8,
            fwd,
            DynamicCertResolver::new(),
            Arc::clone(&logger),
        );

        let send_raw = |srv: Arc<IngressServer>, peer: SocketAddr, raw_req: String| async move {
            let (client_io, server_io) = tokio::io::duplex(16384);
            tokio::spawn(async move {
                srv.serve_conn(server_io, peer, false, false, None, None)
                    .await;
            });
            let (mut r, mut w) = tokio::io::split(client_io);
            w.write_all(raw_req.as_bytes()).await.unwrap();
            let mut buf = Vec::new();
            r.read_to_end(&mut buf).await.unwrap();
            String::from_utf8_lossy(&buf).into_owned()
        };

        // 1. Matched host request carrying sensitive query params & referer query
        let _ = send_raw(
            Arc::clone(&server),
            "198.51.100.21:41001".parse().unwrap(),
            "GET /v1/orders?token=supersecret999&page=2 HTTP/1.1\r\nHost: api.example.test\r\nUser-Agent: curl/8.5.0\r\nReferer: https://app.example.test/checkout?api_key=leak123\r\nConnection: close\r\n\r\n".into(),
        )
        .await;

        // 2. Unmatched host -> 421 Misdirected Request logged under `_unmatched` with `action = "unmatched"`
        let unmatched_resp = send_raw(
            Arc::clone(&server),
            "198.51.100.22:41002".parse().unwrap(),
            "GET /unknown-route?foo=bar HTTP/1.1\r\nHost: unknown.example.test\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".into(),
        )
        .await;
        assert!(
            unmatched_resp.starts_with("HTTP/1.1 421"),
            "{unmatched_resp}"
        );

        // 3. Attack payload -> Evilpot diversion logged with `action = "evilpot"` & `waf_category`
        let _ = send_raw(
            Arc::clone(&server),
            "198.51.100.23:41003".parse().unwrap(),
            "GET /.env?id=1%20UNION%20SELECT%201 HTTP/1.1\r\nHost: api.example.test\r\nUser-Agent: sqlmap/1.8\r\nConnection: close\r\n\r\n".into(),
        )
        .await;

        let (records, _summaries, _fps) = logger.drain_for_maintainer().await;
        assert!(
            records.len() >= 3,
            "expected >=3 URL log records, got {}",
            records.len()
        );

        let r_orders = records
            .iter()
            .find(|r| r.path.as_deref() == Some("/v1/orders"))
            .expect("missing /v1/orders log record");
        assert_eq!(r_orders.method.as_deref(), Some("GET"));
        assert_eq!(r_orders.host.as_deref(), Some("api.example.test"));
        assert_eq!(r_orders.scheme.as_deref(), Some("http"));
        assert_eq!(r_orders.protocol.as_deref(), Some("HTTP/1.1"));
        assert_eq!(r_orders.query.as_deref(), Some("token=[REDACTED]&page=2"));
        assert_eq!(
            r_orders.referer.as_deref(),
            Some("https://app.example.test/checkout")
        );
        assert!(
            r_orders
                .ray_id
                .as_deref()
                .map(|s| !s.is_empty())
                .unwrap_or(false)
        );

        let r_unmatched = records
            .iter()
            .find(|r| r.path.as_deref() == Some("/unknown-route"))
            .expect("missing /unknown-route unmatched record");
        assert_eq!(r_unmatched.status, 421);
        assert_eq!(r_unmatched.service_tag, "_unmatched");
        assert_eq!(r_unmatched.action.as_deref(), Some("unmatched"));
        assert_eq!(r_unmatched.host.as_deref(), Some("unknown.example.test"));

        let r_evilpot = records
            .iter()
            .find(|r| r.path.as_deref() == Some("/.env"))
            .expect("missing /.env evilpot record");
        assert_eq!(r_evilpot.action.as_deref(), Some("evilpot"));
        assert!(r_evilpot.waf_category.is_some());

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[tokio::test]
    async fn ingress_local_geoip_enforces_region_block_challenge_evilpot_and_logs_country() {
        use exposure_core::config::{
            AutoBanConfig, EgressConfig, GeoPolicyConfig, GeoRule, GeoRuleAction, GuardProfile,
            IngressRule, LoggerConfig, NodeRoles, RelayConfig, RuleMatch, SegmentConfig,
        };
        use exposure_core::geoip::GeoIpDatabase;
        use exposure_link::LinkManager;
        use std::collections::BTreeMap;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let tmp_dir = std::env::temp_dir().join(format!("exp-geo-ing-{}", Uuid::new_v4()));
        let logger = NodeLogger::new(
            "ing-geo",
            LoggerConfig {
                hmac_key: generate_random_secret_hex(32),
                store_raw_ip: true,
                sample_rate: 1.0,
                hll_precision: 10,
                segment: SegmentConfig {
                    dir: tmp_dir.to_string_lossy().to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();

        let kp = NodeKeyPair::generate();
        let lm = LinkManager::new("ing-geo", kp.clone(), false, vec![], Default::default());
        let egress = crate::egress::EgressHandler::new(
            "ing-geo",
            EgressConfig::default(),
            vec![],
            Arc::clone(&logger),
        );
        let (fwd, _rx) = Forwarder::new(
            "ing-geo",
            NodeRoles {
                ingress: true,
                ..Default::default()
            },
            RelayConfig::default(),
            lm,
            egress,
            Arc::clone(&logger),
        );

        let mut guards = BTreeMap::new();
        guards.insert(
            "geo-guard".to_string(),
            GuardProfile {
                geo: Some(GeoPolicyConfig {
                    enabled: true,
                    deny_regions: vec!["AU".into()],
                    deny_action: GeoRuleAction::Block,
                    rules: vec![
                        GeoRule {
                            regions: vec!["US".into()],
                            action: GeoRuleAction::Challenge,
                            suspicion_boost: 0,
                            note: Some("verify-us".into()),
                        },
                        GeoRule {
                            regions: vec!["CH".into()],
                            action: GeoRuleAction::Evilpot,
                            suspicion_boost: 0,
                            note: Some("trap-ch".into()),
                        },
                        GeoRule {
                            regions: vec!["CN".into()],
                            action: GeoRuleAction::Allow,
                            suspicion_boost: 0,
                            note: None,
                        },
                    ],
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let cfg = IngressConfig {
            clearance_secret: "super-secret-geo-clearance-key-0123456789abcdef".into(),
            rules: vec![IngressRule {
                name: Some("web".into()),
                r#match: RuleMatch {
                    host: Some("geo.example.test".into()),
                    ..Default::default()
                },
                service_tag: "svc-geo".into(),
                next_peer: "missing-peer".into(),
                guard: Some("geo-guard".into()),
                intercept_errors: Some(false),
                js_fp_beacon: Some(false),
                ..Default::default()
            }],
            guards,
            auto_ban: AutoBanConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };

        let server = IngressServer::new(
            "ing-geo",
            kp,
            cfg,
            8,
            fwd,
            DynamicCertResolver::new(),
            Arc::clone(&logger),
        );
        let v4_csv = "\
1.1.1.0,1.1.1.255,AU
8.8.8.0,8.8.8.255,US
9.9.9.0,9.9.9.255,CH
114.114.114.0,114.114.115.255,CN
";
        server
            .geoip()
            .set_database_for_test(GeoIpDatabase::parse_csv_ranges(
                Some(v4_csv),
                None,
                "test",
                1_700_000_000,
            ));

        let send_browser = |srv: Arc<IngressServer>, ip: &str| {
            let addr: SocketAddr = format!("{ip}:42000").parse().unwrap();
            async move {
                let (client_io, server_io) = tokio::io::duplex(16384);
                tokio::spawn(async move {
                    srv.serve_conn(server_io, addr, false, false, None, None)
                        .await;
                });
                let (mut r, mut w) = tokio::io::split(client_io);
                w.write_all(b"GET /.env HTTP/1.1\r\nHost: geo.example.test\r\nUser-Agent: Mozilla/5.0 Chrome/126\r\nAccept: text/html\r\nSec-Fetch-Mode: navigate\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
                let mut buf = Vec::new();
                r.read_to_end(&mut buf).await.unwrap();
                String::from_utf8_lossy(&buf).into_owned()
            }
        };

        // 1. AU (1.1.1.1) -> geo_block (403)
        let r_au = send_browser(Arc::clone(&server), "1.1.1.1").await;
        assert!(
            r_au.starts_with("HTTP/1.1 403"),
            "expected AU 403, got: {r_au}"
        );

        // 2. US (8.8.8.8) -> geo_challenge (302 /cdn-cgi/)
        let r_us = send_browser(Arc::clone(&server), "8.8.8.8").await;
        assert!(
            r_us.starts_with("HTTP/1.1 302"),
            "expected US 302 challenge, got: {r_us}"
        );

        // 3. CH (9.9.9.9) -> geo_evilpot (200 decoy)
        let r_ch = send_browser(Arc::clone(&server), "9.9.9.9").await;
        assert!(
            r_ch.starts_with("HTTP/1.1 200"),
            "expected CH evilpot 200, got: {r_ch}"
        );

        // 4. CN (114.114.114.114) -> Allowed past GeoIP -> misses peer -> 502 with CN country logged
        let r_cn = send_browser(Arc::clone(&server), "114.114.114.114").await;
        assert!(
            r_cn.starts_with("HTTP/1.1 502"),
            "expected CN 502 past Geo, got: {r_cn}"
        );

        let (recs, _, fps) = logger.drain_for_maintainer().await;
        assert!(
            recs.iter()
                .any(|r| r.client_country.as_deref() == Some("AU")
                    && r.action.as_deref() == Some("geo_block"))
        );
        assert!(
            recs.iter()
                .any(|r| r.client_country.as_deref() == Some("US")
                    && r.action.as_deref() == Some("geo_challenge"))
        );
        assert!(
            recs.iter()
                .any(|r| r.client_country.as_deref() == Some("CH")
                    && r.action.as_deref() == Some("geo_evilpot"))
        );
        assert!(
            recs.iter()
                .any(|r| r.client_country.as_deref() == Some("CN"))
        );
        assert!(
            fps.iter().any(|f| f.geo_country.as_deref() == Some("AU")
                && f.geo_continent.as_deref() == Some("OC"))
        );
        assert!(
            fps.iter().any(|f| f.geo_country.as_deref() == Some("US")
                && f.geo_continent.as_deref() == Some("NA"))
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[tokio::test]
    async fn waf_block_is_not_5xx_or_pow_and_backend_5xx_logs_error_and_unified_ray_id() {
        use exposure_core::config::{
            AntibotMode, EgressConfig, EgressServiceConfig, GuardProfile, IngressRule,
            LoggerConfig, NodeRoles, RelayConfig, RuleMatch, SegmentConfig, TrustedOrigin,
            WafConfig,
        };
        use exposure_link::LinkManager;
        use http_body_util::Full;
        use hyper::service::service_fn;
        use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
        use std::collections::BTreeMap;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend_listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = backend_listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let svc = service_fn(|req: Request<Incoming>| async move {
                        if req.uri().path() == "/boom" {
                            return Ok::<_, hyper::Error>(
                                Response::builder()
                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                    .header(header::CONTENT_TYPE, "application/json")
                                    .header("x-exposure-upstream-error", "spoofed-by-origin")
                                    .body(Full::new(Bytes::from_static(
                                        br#"{"error":"database deadlock on orders"}"#,
                                    )))
                                    .unwrap(),
                            );
                        }
                        Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::from_static(b"ok")))
                                .unwrap(),
                        )
                    });
                    let _ = AutoServerBuilder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });

        let tmp_dir = std::env::temp_dir().join(format!("exp-ray-5xx-test-{}", Uuid::new_v4()));
        let logger = NodeLogger::new(
            "node-ray",
            LoggerConfig {
                hmac_key: generate_random_secret_hex(32),
                store_raw_ip: false,
                sample_rate: 1.0,
                hll_precision: 10,
                segment: SegmentConfig {
                    dir: tmp_dir.to_string_lossy().to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();

        let kp = NodeKeyPair::generate();
        let lm = LinkManager::new("node-ray", kp.clone(), false, vec![], Default::default());
        let mut services = BTreeMap::new();
        services.insert(
            "svc-pass".to_string(),
            EgressServiceConfig {
                backend: backend_addr.to_string(),
                protocol: Default::default(),
                tls: Some(false),
                ca_cert_path: None,
                insecure_skip_verify: Some(false),
                allow_from: vec!["node-ray".into()],
                allow_any_origin: Some(false),
                timeout_ms: 5000,
                intercept_errors: Some(false),
                local_health_check: None,
            },
        );
        services.insert(
            "svc-intercept".to_string(),
            EgressServiceConfig {
                backend: backend_addr.to_string(),
                protocol: Default::default(),
                tls: Some(false),
                ca_cert_path: None,
                insecure_skip_verify: Some(false),
                allow_from: vec!["node-ray".into()],
                allow_any_origin: Some(false),
                timeout_ms: 5000,
                intercept_errors: Some(true),
                local_health_check: None,
            },
        );
        let egress = crate::egress::EgressHandler::new(
            "node-ray",
            EgressConfig {
                services,
                ..Default::default()
            },
            vec![TrustedOrigin {
                node_tag: "node-ray".into(),
                public_key: kp.public_key_b64(),
            }],
            Arc::clone(&logger),
        );
        let (fwd, _rx) = Forwarder::new(
            "node-ray",
            NodeRoles {
                ingress: true,
                egress: true,
                relay: false,
                maintainer: false,
            },
            RelayConfig::default(),
            lm,
            egress,
            Arc::clone(&logger),
        );

        let mut guards = BTreeMap::new();
        guards.insert(
            "waf-blk".to_string(),
            GuardProfile {
                antibot: AntibotMode::Off,
                waf: Some(WafConfig {
                    mode: WafMode::Block,
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let cfg = IngressConfig {
            rules: vec![
                IngressRule {
                    name: Some("pass".into()),
                    r#match: RuleMatch {
                        host: Some("pass.example.test".into()),
                        ..Default::default()
                    },
                    service_tag: "svc-pass".into(),
                    next_peer: "node-ray".into(),
                    guard: Some("waf-blk".into()),
                    intercept_errors: Some(false),
                    js_fp_beacon: Some(false),
                    ..Default::default()
                },
                IngressRule {
                    name: Some("intercept".into()),
                    r#match: RuleMatch {
                        host: Some("intercept.example.test".into()),
                        ..Default::default()
                    },
                    service_tag: "svc-intercept".into(),
                    next_peer: "node-ray".into(),
                    guard: Some("waf-blk".into()),
                    intercept_errors: Some(true),
                    js_fp_beacon: Some(false),
                    ..Default::default()
                },
            ],
            guards,
            ..Default::default()
        };

        let server = IngressServer::new(
            "node-ray",
            kp,
            cfg,
            8,
            fwd,
            DynamicCertResolver::new(),
            Arc::clone(&logger),
        );

        let send_raw = |srv: Arc<IngressServer>, raw_req: String| async move {
            let (client_io, server_io) = tokio::io::duplex(16384);
            tokio::spawn(async move {
                srv.serve_conn(
                    server_io,
                    "198.51.100.77:43001".parse().unwrap(),
                    false,
                    false,
                    None,
                    None,
                )
                .await;
            });
            let (mut r, mut w) = tokio::io::split(client_io);
            w.write_all(raw_req.as_bytes()).await.unwrap();
            let mut buf = Vec::new();
            r.read_to_end(&mut buf).await.unwrap();
            String::from_utf8_lossy(&buf).into_owned()
        };
        let extract_header = |raw_resp: &str, name: &str| -> Option<String> {
            raw_resp
                .split("\r\n\r\n")
                .next()
                .unwrap_or("")
                .lines()
                .find_map(|line| {
                    let (k, v) = line.split_once(':')?;
                    if k.trim().eq_ignore_ascii_case(name) {
                        Some(v.trim().to_string())
                    } else {
                        None
                    }
                })
        };

        // 1. WAF block -> 403, NOT counted as 5xx or PoW challenge
        let waf_resp = send_raw(
            Arc::clone(&server),
            "GET /search?q=1%20UNION%20SELECT%201 HTTP/1.1\r\nHost: pass.example.test\r\nUser-Agent: curl/8.5.0\r\nConnection: close\r\n\r\n".into(),
        )
        .await;
        assert!(waf_resp.starts_with("HTTP/1.1 403"), "{waf_resp}");
        let waf_ray =
            extract_header(&waf_resp, "x-exposure-ray").expect("missing ray header on waf 403");

        let (waf_recs, waf_sums, _) = logger.drain_for_maintainer().await;
        assert!(
            waf_sums.iter().all(|s| s.errors == 0),
            "WAF 403 must never increment 5xx errors"
        );
        assert!(
            waf_sums.iter().all(|s| s.challenges_issued == 0),
            "WAF 403 must not increment PoW challenges_issued"
        );
        assert_eq!(
            waf_sums.iter().map(|s| s.blocked).sum::<u64>(),
            1,
            "WAF 403 must increment blocked"
        );
        let waf_rec = waf_recs
            .iter()
            .find(|r| r.ray_id.as_deref() == Some(waf_ray.as_str()))
            .expect("missing WAF log record by ray_id");
        assert_eq!(waf_rec.status, 403);
        assert_eq!(waf_rec.action.as_deref(), Some("waf_block"));
        assert!(!waf_rec.challenged);

        // 2. Backend 500 with intercept_errors = false -> raw body passed through, x-exposure-ray present, both ingress & egress log backend error + shared ray_id
        let pass_500 = send_raw(
            Arc::clone(&server),
            "GET /boom HTTP/1.1\r\nHost: pass.example.test\r\nUser-Agent: curl/8.5.0\r\nConnection: close\r\n\r\n".into(),
        )
        .await;
        assert!(pass_500.starts_with("HTTP/1.1 500"), "{pass_500}");
        assert!(
            pass_500.contains("database deadlock on orders"),
            "{pass_500}"
        );
        assert!(
            extract_header(&pass_500, "x-exposure-upstream-error").is_none(),
            "internal header leaked"
        );
        let pass_ray =
            extract_header(&pass_500, "x-exposure-ray").expect("missing x-exposure-ray on 500");

        let (pass_recs, _, _) = logger.drain_for_maintainer().await;
        let ing_pass = pass_recs
            .iter()
            .find(|r| r.role == "ingress" && r.ray_id.as_deref() == Some(pass_ray.as_str()))
            .expect("missing ingress 500 log for ray_id");
        let eg_pass = pass_recs
            .iter()
            .find(|r| r.role == "egress" && r.ray_id.as_deref() == Some(pass_ray.as_str()))
            .expect("missing egress 500 log for ray_id");
        assert_eq!(ing_pass.action.as_deref(), Some("upstream_error"));
        assert_eq!(eg_pass.action.as_deref(), Some("upstream_error"));
        assert!(
            ing_pass
                .error
                .as_deref()
                .unwrap_or("")
                .contains("database deadlock on orders"),
            "ingress error: {:?}",
            ing_pass.error
        );
        assert!(
            eg_pass
                .error
                .as_deref()
                .unwrap_or("")
                .contains("database deadlock on orders"),
            "egress error: {:?}",
            eg_pass.error
        );

        // 3. Backend 500 with intercept_errors = true -> client gets generic HTML error page with Ray ID (no backend error leak), logs STILL capture backend error
        let int_500 = send_raw(
            Arc::clone(&server),
            "GET /boom HTTP/1.1\r\nHost: intercept.example.test\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".into(),
        )
        .await;
        assert!(int_500.starts_with("HTTP/1.1 500"), "{int_500}");
        let int_ray = extract_header(&int_500, "x-exposure-ray")
            .expect("missing x-exposure-ray on intercepted 500");
        assert!(
            int_500.contains(&int_ray),
            "HTML error page must include ray_id: {int_500}"
        );
        assert!(
            !int_500.contains("database deadlock on orders"),
            "intercepted response must not leak backend error"
        );
        assert!(
            extract_header(&int_500, "x-exposure-upstream-error").is_none(),
            "internal header leaked"
        );

        let (int_recs, _, _) = logger.drain_for_maintainer().await;
        let ing_int = int_recs
            .iter()
            .find(|r| r.role == "ingress" && r.ray_id.as_deref() == Some(int_ray.as_str()))
            .expect("missing ingress intercepted 500 log for ray_id");
        let eg_int = int_recs
            .iter()
            .find(|r| r.role == "egress" && r.ray_id.as_deref() == Some(int_ray.as_str()))
            .expect("missing egress intercepted 500 log for ray_id");
        assert_eq!(ing_int.action.as_deref(), Some("upstream_error"));
        assert_eq!(eg_int.action.as_deref(), Some("upstream_error"));
        assert!(
            ing_int
                .error
                .as_deref()
                .unwrap_or("")
                .contains("database deadlock on orders"),
            "ingress intercepted error: {:?}",
            ing_int.error
        );
        assert!(
            eg_int
                .error
                .as_deref()
                .unwrap_or("")
                .contains("database deadlock on orders"),
            "egress intercepted error: {:?}",
            eg_int.error
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
