use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use exposure_core::assets::{WebApp, load_web_asset_negotiated};
use exposure_core::config::{
    ControlConfig, ControlRetentionConfig, ControlRole, DnsProviderAccountConfig,
    MaintainerRetentionConfig, NodeConfig, TopologySpec,
};
use exposure_core::crypto::{
    ct_eq_hashed, generate_random_secret_hex, hmac_ip, validate_identifier, verify_password,
};
use exposure_core::protocol::{DnsManageOp, MaintainerQuery};
use exposure_core::routing::{
    LinkHealthState, canonical_ip, is_public_routable_ip, parse_valid_host,
};
use exposure_core::telemetry::{
    AlertRecord, BanRecord, EvilpotEventInfo, EvilpotSessionInfo, FingerprintObservation,
    HyperLogLog, LatencyHistogram, MaintainerStorageStats, MinuteSummary, SessionSummary,
    is_cache_served_status, is_evilpot_action, is_mitigated_record, normalize_alert_severity,
};
use futures::stream::{FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use crate::client::ControlClient;

const SESSION_COOKIE_NAME: &str = "exposure_session";
const SESSION_TTL_SECS: i64 = 8 * 3600;
const MAX_SESSIONS: usize = 2048;
const MAX_YAML_BYTES: usize = 256 * 1024;
const REDACTED_SECRET: &str = "********";
const LOGIN_MAX_FAILURES: u32 = 5;
const LOGIN_LOCKOUT_SECS: u64 = 60;
const PANEL_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'";

#[derive(Clone)]
struct AdminSession {
    username: String,
    expires_at: i64,
}

#[derive(Default)]
struct LoginAttemptState {
    failures: u32,
    locked_until: Option<Instant>,
}

#[derive(Clone)]
pub struct ApiState {
    pub cfg: ControlConfig,
    pub client: Arc<ControlClient>,
    sessions: Arc<DashMap<String, AdminSession>>,
    login_limiter: Arc<DashMap<String, LoginAttemptState>>,
    auth_sem: Arc<Semaphore>,
    http_client: reqwest::Client,
}

impl ApiState {
    pub fn new(cfg: ControlConfig, client: Arc<ControlClient>) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .connect_timeout(Duration::from_secs(5))
            .user_agent("exposure-control/0.1")
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            cfg,
            client,
            sessions: Arc::new(DashMap::new()),
            login_limiter: Arc::new(DashMap::new()),
            auth_sem: Arc::new(Semaphore::new(4)),
            http_client,
        }
    }
}

fn hash_session_token(secret: &str, raw_token: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"exposure-admin-session-v2:");
    h.update(secret.as_bytes());
    h.update(b":");
    h.update(raw_token.as_bytes());
    hex::encode(h.finalize())
}

pub fn build_router(state: ApiState) -> Router {
    Router::new()
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/me", get(auth_me))
        .route("/api/overview", get(overview))
        .route("/api/nodes", get(list_nodes))
        .route("/api/nodes/{tag}/push", post(push_single_node))
        .route(
            "/api/topology",
            get(get_topology).post(save_topology).put(save_topology),
        )
        .route("/api/topology/validate", post(validate_topology))
        .route("/api/topology/preflight", post(preflight_topology))
        .route("/api/config-versions", get(list_config_versions))
        .route("/api/config-versions/{id}/rollback", post(rollback_version))
        .route("/api/config-releases", get(list_config_releases))
        .route(
            "/api/config-releases/{rev}/rollback",
            post(rollback_release),
        )
        .route(
            "/api/passphrases",
            get(list_passphrases).post(register_passphrase),
        )
        .route("/api/passphrases/{tag}/revoke", post(revoke_passphrase))
        .route("/api/discovery/run", post(run_discovery))
        .route("/api/dns/sync", post(sync_dns))
        .route("/api/dns/domains/{domain}/inspect", get(inspect_dns_domain))
        .route("/api/dns/domains/{domain}/records", post(create_dns_record))
        .route(
            "/api/dns/domains/{domain}/records/{record_id}",
            put(update_dns_record).delete(delete_dns_record),
        )
        .route(
            "/api/dns/domains/{domain}/records/{record_id}/status",
            post(set_dns_record_status),
        )
        .route("/api/telemetry", get(get_telemetry))
        .route("/api/telemetry/pull", post(pull_telemetry))
        .route("/api/evilpot", get(get_evilpot))
        .route("/api/bans", get(list_bans))
        .route("/api/alerts", get(list_alerts))
        .route("/api/waf/rules", get(get_waf_rules))
        .route("/api/waf/crs/sync", post(sync_waf_crs))
        .route("/api/security/abuseipdb/test", post(test_abuseipdb_key))
        .route("/api/security/unban", post(unban_security_target))
        .route("/api/security/geoip/status", get(get_geoip_status))
        .route("/api/security/geoip/sync", post(sync_geoip))
        .route("/api/security/geoip/lookup", get(lookup_geoip))
        .route("/api/fingerprints", get(list_fingerprints))
        .route("/api/logs", get(list_logs))
        .route("/api/audit", get(list_audit))
        .route(
            "/api/storage/retention",
            get(get_storage_retention).put(update_storage_retention),
        )
        .route("/api/storage/cleanup", post(run_storage_cleanup))
        .fallback(serve_web_panel)
        .layer(middleware::from_fn(csrf_origin_guard))
        .layer(middleware::from_fn(security_headers_middleware))
        .with_state(state)
}

async fn security_headers_middleware(req: axum::extract::Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    h.insert(
        header::HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(PANEL_CSP),
    );
    resp
}

fn default_port_for_scheme(scheme: &str) -> Option<u16> {
    match scheme {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    }
}

/// Lowercased host and optional explicit port from an authority (`example.com:8090`, `[::1]:8090`).
fn host_and_port_from_authority(v: &str) -> Option<(String, Option<u16>)> {
    let trimmed = v.trim();
    if trimmed.is_empty() {
        return None;
    }
    let uri: axum::http::Uri = format!("http://{trimmed}").parse().ok()?;
    let host = uri
        .host()
        .map(|h| h.trim_matches(['[', ']']).to_ascii_lowercase())?;
    if host.is_empty() {
        return None;
    }
    Some((host, uri.port_u16()))
}

/// Lowercased `(scheme, host, normalized_port)` from an absolute URI (`Origin`/`Referer`).
fn origin_tuple_from_uri(v: &str) -> Option<(String, String, Option<u16>)> {
    let uri: axum::http::Uri = v.trim().parse().ok()?;
    let scheme = uri.scheme_str()?.to_ascii_lowercase();
    let host = uri
        .host()
        .map(|h| h.trim_matches(['[', ']']).to_ascii_lowercase())?;
    if host.is_empty() {
        return None;
    }
    let port = uri.port_u16().or_else(|| default_port_for_scheme(&scheme));
    Some((scheme, host, port))
}

/// CSRF defense for state-changing requests.
///
/// `SameSite=Strict` alone does not protect against a same-site sibling subdomain
/// (`evil.example.com` -> `control.example.com`) because the cookie is still sent. For
/// browser-originated mutations we require any `Origin` (or `Referer`) `(scheme, host, port)` to
/// match the request's own authority/forwarded headers (preserving compatibility with proxies that
/// omit default/forwarded ports unless an explicit mismatched port is present).
async fn csrf_origin_guard(req: axum::extract::Request, next: Next) -> Response {
    let state_changing = matches!(req.method().as_str(), "POST" | "PUT" | "PATCH" | "DELETE");
    if state_changing {
        let headers = req.headers();
        let expected_scheme = if let Some(hv) = headers.get("x-forwarded-proto") {
            let Ok(s) = hv.to_str() else {
                return json_err(StatusCode::FORBIDDEN, "cross-origin request blocked");
            };
            s.split(',')
                .next()
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(|p| p.to_ascii_lowercase())
        } else {
            req.uri().scheme_str().map(str::to_ascii_lowercase)
        };

        let mut expected: Vec<(String, Option<u16>)> = Vec::new();
        if let Some(a) = req.uri().authority() {
            expected.push((
                a.host().trim_matches(['[', ']']).to_ascii_lowercase(),
                a.port_u16(),
            ));
        }
        for hv in headers.get_all(header::HOST) {
            let Ok(s) = hv.to_str() else {
                return json_err(StatusCode::FORBIDDEN, "cross-origin request blocked");
            };
            let Some(hp) = host_and_port_from_authority(s) else {
                return json_err(StatusCode::FORBIDDEN, "cross-origin request blocked");
            };
            expected.push(hp);
        }
        for hv in headers.get_all("x-forwarded-host") {
            let Ok(s) = hv.to_str() else {
                return json_err(StatusCode::FORBIDDEN, "cross-origin request blocked");
            };
            let first = s.split(',').next().map(str::trim).unwrap_or("");
            if !first.is_empty() {
                let Some(hp) = host_and_port_from_authority(first) else {
                    return json_err(StatusCode::FORBIDDEN, "cross-origin request blocked");
                };
                expected.push(hp);
            }
        }
        expected.sort();
        expected.dedup();

        let origin = match headers.get(header::ORIGIN) {
            Some(hv) => {
                let Ok(s) = hv.to_str() else {
                    return json_err(StatusCode::FORBIDDEN, "cross-origin request blocked");
                };
                let Some(parsed) = origin_tuple_from_uri(s) else {
                    return json_err(StatusCode::FORBIDDEN, "cross-origin request blocked");
                };
                Some(parsed)
            }
            None => None,
        };
        let referer = if origin.is_none() {
            match headers.get(header::REFERER) {
                Some(hv) => {
                    let Ok(s) = hv.to_str() else {
                        return json_err(StatusCode::FORBIDDEN, "cross-origin request blocked");
                    };
                    let Some(parsed) = origin_tuple_from_uri(s) else {
                        return json_err(StatusCode::FORBIDDEN, "cross-origin request blocked");
                    };
                    Some(parsed)
                }
                None => None,
            }
        } else {
            None
        };

        if let Some((src_scheme, src_host, src_port)) = origin.or(referer) {
            let scheme_ok = expected_scheme
                .as_deref()
                .map(|es| es == src_scheme)
                .unwrap_or(true);
            let target_ok = expected.iter().any(|(exp_host, exp_port)| {
                if exp_host != &src_host {
                    return false;
                }
                match *exp_port {
                    Some(ep) => src_port == Some(ep),
                    None => true,
                }
            });
            if !(scheme_ok && target_ok) {
                return json_err(StatusCode::FORBIDDEN, "cross-origin request blocked");
            }
        }
    }
    next.run(req).await
}

/// `Secure` cookie suffix when the panel is served over TLS, including TLS terminated at a
/// trusted reverse proxy (`X-Forwarded-Proto: https`).
fn cookie_secure_suffix(state: &ApiState, headers: &HeaderMap) -> &'static str {
    let tls = state.cfg.tls.is_some();
    let forwarded_https = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(',')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("https")
        })
        .unwrap_or(false);
    if tls || forwarded_https {
        "; Secure"
    } else {
        ""
    }
}

fn extract_raw_session_token(headers: &HeaderMap) -> Option<String> {
    if let Some(tok) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Some(tok.to_string());
    }
    for hv in headers.get_all(header::COOKIE) {
        if let Ok(s) = hv.to_str() {
            for pair in s.split(';') {
                if let Some((k, v)) = pair.trim().split_once('=') {
                    if k == SESSION_COOKIE_NAME && !v.trim().is_empty() {
                        return Some(v.trim().to_string());
                    }
                }
            }
        }
    }
    None
}

fn create_admin_session(state: &ApiState, username: &str) -> String {
    let now = Utc::now().timestamp();
    if state.sessions.len() >= MAX_SESSIONS {
        state.sessions.retain(|_, s| s.expires_at > now);
        if state.sessions.len() >= MAX_SESSIONS {
            state.sessions.clear();
        }
    }
    let raw_token = generate_random_secret_hex(32);
    let key = hash_session_token(&state.cfg.admin.token_secret, &raw_token);
    state.sessions.insert(
        key,
        AdminSession {
            username: username.to_string(),
            expires_at: now + SESSION_TTL_SECS,
        },
    );
    raw_token
}

fn verify_admin_auth(state: &ApiState, headers: &HeaderMap) -> Result<String, Box<Response>> {
    let raw_token = extract_raw_session_token(headers).ok_or_else(|| {
        Box::new(json_err(
            StatusCode::UNAUTHORIZED,
            "missing session authentication",
        ))
    })?;
    let key = hash_session_token(&state.cfg.admin.token_secret, &raw_token);
    let now = Utc::now().timestamp();
    let Some(entry) = state.sessions.get(&key) else {
        return Err(Box::new(json_err(
            StatusCode::UNAUTHORIZED,
            "invalid or revoked session",
        )));
    };
    if entry.expires_at < now || entry.username != state.cfg.admin.username {
        drop(entry);
        state.sessions.remove(&key);
        return Err(Box::new(json_err(
            StatusCode::UNAUTHORIZED,
            "session expired",
        )));
    }
    Ok(entry.username.clone())
}

fn require_active_role(state: &ApiState) -> Result<(), Box<Response>> {
    if state.cfg.role != ControlRole::Active {
        return Err(Box::new(json_err(
            StatusCode::CONFLICT,
            "control instance is in standby mode",
        )));
    }
    Ok(())
}

fn json_err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

fn redact_dns_provider_account(prov: &mut DnsProviderAccountConfig) {
    match prov {
        DnsProviderAccountConfig::Cloudflare { api_token } => {
            if !api_token.is_empty() {
                *api_token = REDACTED_SECRET.into();
            }
        }
        DnsProviderAccountConfig::Aliyun {
            access_key_secret, ..
        } => {
            if !access_key_secret.is_empty() {
                *access_key_secret = REDACTED_SECRET.into();
            }
        }
        DnsProviderAccountConfig::Webhook { auth_header, .. } => {
            if auth_header.is_some() {
                *auth_header = Some(REDACTED_SECRET.into());
            }
        }
        DnsProviderAccountConfig::Exec { .. } => {}
    }
}

fn restore_dns_provider_account(
    name: &str,
    new_p: &mut DnsProviderAccountConfig,
    old_p: Option<&DnsProviderAccountConfig>,
) -> Result<(), String> {
    if let Some(old_p) = old_p {
        match (new_p.clone(), old_p) {
            (
                DnsProviderAccountConfig::Cloudflare { api_token },
                DnsProviderAccountConfig::Cloudflare { api_token: old_tok },
            ) if api_token == REDACTED_SECRET => {
                if old_tok.is_empty() {
                    return Err(format!(
                        "DNS provider '{name}' cannot use redacted placeholder with no existing token"
                    ));
                }
                if let DnsProviderAccountConfig::Cloudflare { api_token } = new_p {
                    *api_token = old_tok.clone();
                }
                return Ok(());
            }
            (
                DnsProviderAccountConfig::Aliyun {
                    access_key_secret, ..
                },
                DnsProviderAccountConfig::Aliyun {
                    access_key_secret: old_secret,
                    ..
                },
            ) if access_key_secret == REDACTED_SECRET => {
                if old_secret.is_empty() {
                    return Err(format!(
                        "DNS provider '{name}' cannot use redacted placeholder with no existing secret"
                    ));
                }
                if let DnsProviderAccountConfig::Aliyun {
                    access_key_secret, ..
                } = new_p
                {
                    *access_key_secret = old_secret.clone();
                }
                return Ok(());
            }
            (
                DnsProviderAccountConfig::Webhook { auth_header, .. },
                DnsProviderAccountConfig::Webhook {
                    auth_header: old_auth,
                    ..
                },
            ) if auth_header.as_deref() == Some(REDACTED_SECRET) => {
                if old_auth.as_deref().map(str::is_empty).unwrap_or(true) {
                    return Err(format!(
                        "DNS provider '{name}' cannot use redacted placeholder with no existing auth header"
                    ));
                }
                if let DnsProviderAccountConfig::Webhook { auth_header, .. } = new_p {
                    *auth_header = old_auth.clone();
                }
                return Ok(());
            }
            _ => {}
        }
    }
    let has_redacted = match new_p {
        DnsProviderAccountConfig::Cloudflare { api_token } => api_token == REDACTED_SECRET,
        DnsProviderAccountConfig::Aliyun {
            access_key_secret, ..
        } => access_key_secret == REDACTED_SECRET,
        DnsProviderAccountConfig::Webhook { auth_header, .. } => {
            auth_header.as_deref() == Some(REDACTED_SECRET)
        }
        DnsProviderAccountConfig::Exec { .. } => false,
    };
    if has_redacted {
        return Err(format!(
            "DNS provider '{name}' contains redacted secret placeholder without a matching prior secret"
        ));
    }
    Ok(())
}

fn redact_api_bypass_headers(headers: &mut [String]) {
    for h in headers {
        if let Some((name, _)) = h.split_once(':') {
            *h = format!("{}: {REDACTED_SECRET}", name.trim());
        }
    }
}

fn restore_api_bypass_headers(
    new_headers: &mut [String],
    old_headers: &[String],
) -> Result<(), String> {
    let mut seen_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for h in new_headers {
        if let Some((name, val)) = h.split_once(':') {
            let key = name.trim().to_ascii_lowercase();
            let idx = {
                let c = seen_counts.entry(key.clone()).or_insert(0);
                let cur = *c;
                *c += 1;
                cur
            };
            if val.trim() == REDACTED_SECRET {
                let matched = old_headers
                    .iter()
                    .filter(|oh| {
                        oh.split_once(':')
                            .map(|(on, _)| on.trim().to_ascii_lowercase() == key)
                            .unwrap_or(false)
                    })
                    .nth(idx);
                if let Some(old_h) = matched {
                    *h = old_h.clone();
                } else {
                    return Err(format!(
                        "API bypass header '{}' uses redacted placeholder without a matching prior header",
                        name.trim()
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Redact all sensitive fields in `TopologySpec` before returning to API callers.
fn redact_topology_spec(mut spec: TopologySpec) -> TopologySpec {
    if !spec.defaults.ingress.clearance_secret.is_empty() {
        spec.defaults.ingress.clearance_secret = REDACTED_SECRET.into();
    }
    if !spec.defaults.ingress.abuseipdb.api_key.is_empty() {
        spec.defaults.ingress.abuseipdb.api_key = REDACTED_SECRET.into();
    }
    for g in spec.guard_templates.values_mut() {
        redact_api_bypass_headers(&mut g.api_bypass_headers);
    }
    for ab in spec.antibot_templates.values_mut() {
        redact_api_bypass_headers(&mut ab.api_bypass_headers);
    }
    if let Some(ref mut gl) = spec.global_logger {
        if !gl.hmac_key.is_empty() {
            gl.hmac_key = REDACTED_SECRET.into();
        }
    }
    for node in spec.nodes.values_mut() {
        if !node.ingress.clearance_secret.is_empty() {
            node.ingress.clearance_secret = REDACTED_SECRET.into();
        }
        if !node.ingress.abuseipdb.api_key.is_empty() {
            node.ingress.abuseipdb.api_key = REDACTED_SECRET.into();
        }
        for g in node.ingress.guards.values_mut() {
            redact_api_bypass_headers(&mut g.api_bypass_headers);
        }
        for ab in node.ingress.antibot_sets.values_mut() {
            redact_api_bypass_headers(&mut ab.api_bypass_headers);
        }
    }
    for prov in spec.dns_providers.values_mut() {
        redact_dns_provider_account(prov);
    }
    for maint in spec.maintainer_templates.values_mut() {
        if maint.cert_signing_secret_key.is_some() {
            maint.cert_signing_secret_key = Some(REDACTED_SECRET.into());
        }
        if !maint.logger.hmac_key.is_empty() {
            maint.logger.hmac_key = REDACTED_SECRET.into();
        }
        for prov in maint.dns_providers.values_mut() {
            redact_dns_provider_account(prov);
        }
    }
    spec
}

fn bad_redacted_secret(msg: impl Into<String>) -> Box<Response> {
    Box::new(json_err(StatusCode::BAD_REQUEST, msg))
}

/// Restore redacted sentinel (`"********"`) secrets from previously stored topology on save,
/// rejecting any sentinel that has no non-empty prior secret to restore from.
fn restore_redacted_secrets(
    mut incoming: TopologySpec,
    existing: &TopologySpec,
) -> Result<TopologySpec, Box<Response>> {
    if incoming.defaults.ingress.clearance_secret == REDACTED_SECRET {
        if existing.defaults.ingress.clearance_secret.is_empty() {
            return Err(bad_redacted_secret(
                "defaults.ingress.clearance_secret uses redacted placeholder with no existing secret",
            ));
        }
        incoming.defaults.ingress.clearance_secret =
            existing.defaults.ingress.clearance_secret.clone();
    }
    if incoming.defaults.ingress.abuseipdb.api_key == REDACTED_SECRET {
        if existing.defaults.ingress.abuseipdb.api_key.is_empty() {
            return Err(bad_redacted_secret(
                "defaults.ingress.abuseipdb.api_key uses redacted placeholder with no existing secret",
            ));
        }
        incoming.defaults.ingress.abuseipdb.api_key =
            existing.defaults.ingress.abuseipdb.api_key.clone();
    }
    for (g_name, new_g) in &mut incoming.guard_templates {
        let old = existing
            .guard_templates
            .get(g_name)
            .map(|g| g.api_bypass_headers.as_slice())
            .unwrap_or(&[]);
        restore_api_bypass_headers(&mut new_g.api_bypass_headers, old)
            .map_err(bad_redacted_secret)?;
    }
    for (ab_name, new_ab) in &mut incoming.antibot_templates {
        let old = existing
            .antibot_templates
            .get(ab_name)
            .map(|ab| ab.api_bypass_headers.as_slice())
            .unwrap_or(&[]);
        restore_api_bypass_headers(&mut new_ab.api_bypass_headers, old)
            .map_err(bad_redacted_secret)?;
    }
    if let Some(new_gl) = &mut incoming.global_logger {
        if new_gl.hmac_key == REDACTED_SECRET {
            let Some(old_gl) = &existing.global_logger else {
                return Err(bad_redacted_secret(
                    "global_logger.hmac_key uses redacted placeholder with no existing secret",
                ));
            };
            if old_gl.hmac_key.is_empty() {
                return Err(bad_redacted_secret(
                    "global_logger.hmac_key uses redacted placeholder with no existing secret",
                ));
            }
            new_gl.hmac_key = old_gl.hmac_key.clone();
        }
    }
    for (tag, new_node) in &mut incoming.nodes {
        let old_node = existing.nodes.get(tag);
        if new_node.ingress.clearance_secret == REDACTED_SECRET {
            let old_s = old_node
                .map(|n| n.ingress.clearance_secret.as_str())
                .unwrap_or("");
            if old_s.is_empty() {
                return Err(bad_redacted_secret(format!(
                    "nodes.{tag}.ingress.clearance_secret uses redacted placeholder with no existing secret"
                )));
            }
            new_node.ingress.clearance_secret = old_s.to_string();
        }
        if new_node.ingress.abuseipdb.api_key == REDACTED_SECRET {
            let old_k = old_node
                .map(|n| n.ingress.abuseipdb.api_key.as_str())
                .unwrap_or("");
            if old_k.is_empty() {
                return Err(bad_redacted_secret(format!(
                    "nodes.{tag}.ingress.abuseipdb.api_key uses redacted placeholder with no existing secret"
                )));
            }
            new_node.ingress.abuseipdb.api_key = old_k.to_string();
        }
        for (g_name, new_g) in &mut new_node.ingress.guards {
            let old = old_node
                .and_then(|n| n.ingress.guards.get(g_name))
                .map(|g| g.api_bypass_headers.as_slice())
                .unwrap_or(&[]);
            restore_api_bypass_headers(&mut new_g.api_bypass_headers, old)
                .map_err(bad_redacted_secret)?;
        }
        for (ab_name, new_ab) in &mut new_node.ingress.antibot_sets {
            let old = old_node
                .and_then(|n| n.ingress.antibot_sets.get(ab_name))
                .map(|ab| ab.api_bypass_headers.as_slice())
                .unwrap_or(&[]);
            restore_api_bypass_headers(&mut new_ab.api_bypass_headers, old)
                .map_err(bad_redacted_secret)?;
        }
    }
    for (p_name, new_p) in &mut incoming.dns_providers {
        restore_dns_provider_account(p_name, new_p, existing.dns_providers.get(p_name))
            .map_err(bad_redacted_secret)?;
    }
    for (tpl_name, new_m) in &mut incoming.maintainer_templates {
        let old_m = existing.maintainer_templates.get(tpl_name);
        if new_m.cert_signing_secret_key.as_deref() == Some(REDACTED_SECRET) {
            let old_ck = old_m.and_then(|m| m.cert_signing_secret_key.as_ref());
            let Some(old_ck) = old_ck.filter(|k| !k.is_empty()) else {
                return Err(bad_redacted_secret(format!(
                    "maintainer_templates.{tpl_name}.cert_signing_secret_key uses redacted placeholder with no existing secret"
                )));
            };
            new_m.cert_signing_secret_key = Some(old_ck.clone());
        }
        if new_m.logger.hmac_key == REDACTED_SECRET {
            let old_hk = old_m.map(|m| m.logger.hmac_key.as_str()).unwrap_or("");
            if old_hk.is_empty() {
                return Err(bad_redacted_secret(format!(
                    "maintainer_templates.{tpl_name}.logger.hmac_key uses redacted placeholder with no existing secret"
                )));
            }
            new_m.logger.hmac_key = old_hk.to_string();
        }
        for (p_name, new_p) in &mut new_m.dns_providers {
            let old_p = old_m.and_then(|m| m.dns_providers.get(p_name));
            restore_dns_provider_account(p_name, new_p, old_p).map_err(bad_redacted_secret)?;
        }
    }
    Ok(incoming)
}

/// Redact secret fields from serialized `NodeConfig` JSON returned by `/api/config-versions`.
fn redact_node_config_json(raw_json: &str) -> String {
    let Ok(mut cfg) = serde_json::from_str::<NodeConfig>(raw_json) else {
        return "{}".into();
    };
    if !cfg.identity_secret_key.is_empty() {
        cfg.identity_secret_key = REDACTED_SECRET.into();
    }
    if !cfg.ingress.clearance_secret.is_empty() {
        cfg.ingress.clearance_secret = REDACTED_SECRET.into();
    }
    if !cfg.ingress.abuseipdb.api_key.is_empty() {
        cfg.ingress.abuseipdb.api_key = REDACTED_SECRET.into();
    }
    for g in cfg.ingress.guards.values_mut() {
        redact_api_bypass_headers(&mut g.api_bypass_headers);
    }
    for ab in cfg.ingress.antibot_sets.values_mut() {
        redact_api_bypass_headers(&mut ab.api_bypass_headers);
    }
    if !cfg.logger.hmac_key.is_empty() {
        cfg.logger.hmac_key = REDACTED_SECRET.into();
    }
    if let Some(ref mut m) = cfg.maintainer {
        if m.cert_signing_secret_key.is_some() {
            m.cert_signing_secret_key = Some(REDACTED_SECRET.into());
        }
        if !m.logger.hmac_key.is_empty() {
            m.logger.hmac_key = REDACTED_SECRET.into();
        }
        for prov in m.dns_providers.values_mut() {
            redact_dns_provider_account(prov);
        }
    }
    serde_json::to_string(&cfg).unwrap_or_else(|_| "{}".into())
}

#[derive(Deserialize)]
struct LoginReq {
    username: String,
    password: String,
}

async fn login(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<LoginReq>,
) -> Response {
    // Reject immediately during lockout BEFORE touching Argon2, and cap concurrent
    // password-hashing tasks via `auth_sem` inside `spawn_blocking` to prevent CPU/reactor DoS.
    let now = Instant::now();
    let locked = state
        .login_limiter
        .get("global")
        .and_then(|st| st.locked_until)
        .map(|until| now < until)
        .unwrap_or(false);
    if locked {
        return json_err(
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed login attempts; please try again shortly",
        );
    }
    let Ok(_permit) = state.auth_sem.clone().try_acquire_owned() else {
        return json_err(
            StatusCode::TOO_MANY_REQUESTS,
            "too many concurrent login attempts; please try again shortly",
        );
    };

    let user_ok = ct_eq_hashed(req.username.as_bytes(), state.cfg.admin.username.as_bytes());
    let password = req.password.clone();
    let expected_hash = state.cfg.admin.password_hash.clone();
    let pass_ok = tokio::task::spawn_blocking(move || verify_password(&password, &expected_hash))
        .await
        .unwrap_or(false);
    if !user_ok || !pass_ok {
        let mut entry = state.login_limiter.entry("global".into()).or_default();
        if entry.locked_until.map(|u| now >= u).unwrap_or(false) {
            entry.failures = 0;
            entry.locked_until = None;
        }
        entry.failures += 1;
        let fails = entry.failures;
        if entry.failures >= LOGIN_MAX_FAILURES {
            entry.locked_until = Some(now + Duration::from_secs(LOGIN_LOCKOUT_SECS));
        }
        drop(entry);

        // Only audit first few failures per lockout window to prevent audit-log flood DoS
        if fails <= LOGIN_MAX_FAILURES {
            let safe_user: String = req.username.chars().take(64).collect();
            state
                .client
                .db()
                .append_audit(&safe_user, "login", "control", false, "bad credentials")
                .await;
        }
        return json_err(StatusCode::UNAUTHORIZED, "invalid username or password");
    }

    state.login_limiter.remove("global");
    let token = create_admin_session(&state, &state.cfg.admin.username);
    state
        .client
        .db()
        .append_audit(
            &state.cfg.admin.username,
            "login",
            "control",
            true,
            "admin login",
        )
        .await;

    let secure_flag = cookie_secure_suffix(&state, &headers);
    let cookie = format!(
        "{SESSION_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict{secure_flag}; Max-Age={SESSION_TTL_SECS}"
    );
    let mut resp = Json(serde_json::json!({
        "ok": true,
        "username": state.cfg.admin.username,
        "token": token,
    }))
    .into_response();
    if let Ok(hv) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    resp
}

async fn logout(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Some(raw_token) = extract_raw_session_token(&headers) {
        let key = hash_session_token(&state.cfg.admin.token_secret, &raw_token);
        if let Some((_, sess)) = state.sessions.remove(&key) {
            state
                .client
                .db()
                .append_audit(&sess.username, "logout", "control", true, "admin logout")
                .await;
        }
    }
    let secure_flag = cookie_secure_suffix(&state, &headers);
    let clear_cookie = format!(
        "{SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict{secure_flag}; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
    );
    let mut resp = Json(serde_json::json!({ "ok": true })).into_response();
    if let Ok(hv) = HeaderValue::from_str(&clear_cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    resp.headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    resp
}

async fn auth_me(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    let mut resp = match verify_admin_auth(&state, &headers) {
        Ok(username) => Json(serde_json::json!({
            "authenticated": true,
            "username": username,
        }))
        .into_response(),
        Err(r) => *r,
    };
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    resp
}

#[derive(Deserialize, Default, Clone)]
struct TimeRangeQuery {
    #[serde(default)]
    from_ms: Option<i64>,
    #[serde(default)]
    to_ms: Option<i64>,
    #[serde(default)]
    window_secs: Option<i64>,
}

fn resolve_time_window(
    from_ms: Option<i64>,
    to_ms: Option<i64>,
    window_secs: Option<i64>,
) -> (Option<i64>, Option<i64>) {
    if from_ms.is_some() || to_ms.is_some() {
        return (from_ms, to_ms);
    }
    match window_secs {
        Some(w) if w > 0 => {
            let now = Utc::now().timestamp_millis();
            (Some(now.saturating_sub(w.saturating_mul(1000))), Some(now))
        }
        _ => (None, None),
    }
}

fn normalize_alert_record(mut a: AlertRecord) -> AlertRecord {
    a.severity = normalize_alert_severity(&a.severity).to_string();
    if a.timestamp_ms <= 0 {
        a.timestamp_ms = DateTime::parse_from_rfc3339(a.timestamp.trim())
            .map(|dt| dt.timestamp_millis())
            .unwrap_or(0);
    }
    a
}

fn collect_normalized_cached_alerts(
    alerts: &[AlertRecord],
    from_ms: Option<i64>,
    to_ms: Option<i64>,
) -> Vec<AlertRecord> {
    let mut seen: HashSet<(i64, String, String, String)> = HashSet::new();
    let mut out = Vec::new();
    for raw in alerts {
        let a = normalize_alert_record(raw.clone());
        if let Some(f) = from_ms {
            if a.timestamp_ms > 0 && a.timestamp_ms < f {
                continue;
            }
        }
        if let Some(t) = to_ms {
            if a.timestamp_ms > 0 && a.timestamp_ms > t {
                continue;
            }
        }
        let key = (
            a.timestamp_ms,
            a.source.clone(),
            a.severity.clone(),
            a.message.clone(),
        );
        if seen.insert(key) {
            out.push(a);
        }
    }
    out.sort_by(|a, b| b.timestamp_ms.cmp(&a.timestamp_ms));
    out
}

struct AggregatedTraffic {
    traffic_json: serde_json::Value,
    timeseries: Vec<serde_json::Value>,
    service_breakdown: Vec<serde_json::Value>,
    node_breakdown: Vec<serde_json::Value>,
    device_counts: BTreeMap<String, u64>,
    browser_counts: BTreeMap<String, u64>,
    os_counts: BTreeMap<String, u64>,
    client_fp_verified: u64,
}

fn summary_bucket_metrics_json(s: &MinuteSummary) -> serde_json::Value {
    serde_json::json!({
        "requests": s.requests,
        "errors": s.errors,
        "rate_limited": s.rate_limited,
        "challenges_issued": s.challenges_issued,
        "challenges_passed": s.challenges_passed,
        "blocked": s.blocked,
        "evilpot_hits": s.evilpot_hits,
        "autoban_hits": s.autoban_hits,
        "bytes_in": s.bytes_in,
        "bytes_out": s.bytes_out,
        "cached_requests": s.cached_requests,
        "cached_bytes_out": s.cached_bytes_out,
        "uv_estimate": s.uv_estimate().round(),
        "p50_ms": s.p50_ms(),
        "p95_ms": s.p95_ms(),
        "p99_ms": s.p99_ms(),
    })
}

fn build_aggregated_traffic_from_maps(
    by_minute: BTreeMap<i64, MinuteSummary>,
    by_service: BTreeMap<String, MinuteSummary>,
    by_node: BTreeMap<String, MinuteSummary>,
) -> AggregatedTraffic {
    let mut total_requests: u64 = 0;
    let mut total_errors: u64 = 0;
    let mut total_rate_limited: u64 = 0;
    let mut total_challenges_issued: u64 = 0;
    let mut total_challenges_passed: u64 = 0;
    let mut total_blocked: u64 = 0;
    let mut total_evilpot_hits: u64 = 0;
    let mut total_autoban_hits: u64 = 0;
    let mut total_bytes_in: u64 = 0;
    let mut total_bytes_out: u64 = 0;
    let mut total_cached_requests: u64 = 0;
    let mut total_cached_bytes_out: u64 = 0;
    let mut client_fp_verified: u64 = 0;
    let mut merged_hll: Option<HyperLogLog> = None;
    let mut merged_hist: Option<LatencyHistogram> = None;
    let mut device_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut browser_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut os_counts: BTreeMap<String, u64> = BTreeMap::new();

    for s in by_minute.values() {
        total_requests = total_requests.saturating_add(s.requests);
        total_errors = total_errors.saturating_add(s.errors);
        total_rate_limited = total_rate_limited.saturating_add(s.rate_limited);
        total_challenges_issued = total_challenges_issued.saturating_add(s.challenges_issued);
        total_challenges_passed = total_challenges_passed.saturating_add(s.challenges_passed);
        total_blocked = total_blocked.saturating_add(s.blocked);
        total_evilpot_hits = total_evilpot_hits.saturating_add(s.evilpot_hits);
        total_autoban_hits = total_autoban_hits.saturating_add(s.autoban_hits);
        total_bytes_in = total_bytes_in.saturating_add(s.bytes_in);
        total_bytes_out = total_bytes_out.saturating_add(s.bytes_out);
        total_cached_requests = total_cached_requests.saturating_add(s.cached_requests);
        total_cached_bytes_out = total_cached_bytes_out.saturating_add(s.cached_bytes_out);
        client_fp_verified = client_fp_verified.saturating_add(s.client_fp_verified);
        for (k, v) in &s.device_counts {
            *device_counts.entry(k.clone()).or_insert(0) += *v;
        }
        for (k, v) in &s.browser_counts {
            *browser_counts.entry(k.clone()).or_insert(0) += *v;
        }
        for (k, v) in &s.os_counts {
            *os_counts.entry(k.clone()).or_insert(0) += *v;
        }
        match &mut merged_hll {
            Some(h) => h.merge(&s.uv_hll),
            None => merged_hll = Some(s.uv_hll.clone()),
        }
        match &mut merged_hist {
            Some(h) => h.merge(&s.latency_hist),
            None => merged_hist = Some(s.latency_hist.clone()),
        }
    }

    let timeseries: Vec<serde_json::Value> = by_minute
        .into_iter()
        .map(|(minute_epoch, s)| {
            let mut val = summary_bucket_metrics_json(&s);
            if let Some(obj) = val.as_object_mut() {
                obj.insert("minute_epoch".into(), serde_json::json!(minute_epoch));
            }
            val
        })
        .collect();

    let mut service_breakdown: Vec<serde_json::Value> = by_service
        .into_iter()
        .map(|(service_tag, s)| {
            let mut val = summary_bucket_metrics_json(&s);
            if let Some(obj) = val.as_object_mut() {
                obj.insert("service_tag".into(), serde_json::json!(service_tag));
            }
            val
        })
        .collect();
    service_breakdown.sort_by(|a, b| {
        b["requests"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&a["requests"].as_u64().unwrap_or(0))
    });

    let mut node_breakdown: Vec<serde_json::Value> = by_node
        .into_iter()
        .map(|(node_tag, s)| {
            let mut val = summary_bucket_metrics_json(&s);
            if let Some(obj) = val.as_object_mut() {
                obj.insert("node_tag".into(), serde_json::json!(node_tag));
                obj.insert("role".into(), serde_json::json!(s.role));
            }
            val
        })
        .collect();
    node_breakdown.sort_by(|a, b| {
        b["requests"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&a["requests"].as_u64().unwrap_or(0))
    });

    let uv_exact_or_hll = merged_hll.map(|h| h.estimate().round()).unwrap_or(0.0);
    let traffic_json = serde_json::json!({
        "total_requests": total_requests,
        "total_errors": total_errors,
        "total_rate_limited": total_rate_limited,
        "total_challenges_issued": total_challenges_issued,
        "total_challenges_passed": total_challenges_passed,
        "total_blocked": total_blocked,
        "total_evilpot_hits": total_evilpot_hits,
        "total_autoban_hits": total_autoban_hits,
        "total_bytes_in": total_bytes_in,
        "total_bytes_out": total_bytes_out,
        "total_cached_requests": total_cached_requests,
        "total_cached_bytes_out": total_cached_bytes_out,
        "uv_estimate": uv_exact_or_hll,
        "p50_ms": merged_hist.as_ref().map(|h| h.quantile(0.50)).unwrap_or(0.0),
        "p95_ms": merged_hist.as_ref().map(|h| h.quantile(0.95)).unwrap_or(0.0),
        "p99_ms": merged_hist.as_ref().map(|h| h.quantile(0.99)).unwrap_or(0.0),
        "client_fp_verified": client_fp_verified,
    });

    AggregatedTraffic {
        traffic_json,
        timeseries,
        service_breakdown,
        node_breakdown,
        device_counts,
        browser_counts,
        os_counts,
        client_fp_verified,
    }
}

/// Role-aware, true HLL-union & LatencyHistogram-merge aggregation over MinuteSummary records.
fn aggregate_summaries(
    summaries: &[MinuteSummary],
    node_filter: Option<&str>,
    service_filter: Option<&str>,
    from_ms: Option<i64>,
    to_ms: Option<i64>,
) -> AggregatedTraffic {
    let from_sec = from_ms.map(|ms| ms.div_euclid(1000));
    let to_sec = to_ms.map(|ms| ms.div_euclid(1000));

    let base: Vec<&MinuteSummary> = summaries
        .iter()
        .filter(|s| {
            if let Some(f) = from_sec {
                if s.minute_epoch + 60 <= f {
                    return false;
                }
            }
            if let Some(t) = to_sec {
                if s.minute_epoch > t {
                    return false;
                }
            }
            if let Some(nf) = node_filter {
                if s.node_tag != nf {
                    return false;
                }
            }
            if let Some(sf) = service_filter {
                if s.service_tag != sf {
                    return false;
                }
            }
            true
        })
        .collect();

    let has_ingress = base.iter().any(|s| s.role == "ingress");
    let primary: Vec<&MinuteSummary> = if has_ingress {
        base.iter()
            .copied()
            .filter(|s| s.role == "ingress" || s.role.is_empty())
            .collect()
    } else {
        base.clone()
    };

    let mut by_minute: BTreeMap<i64, MinuteSummary> = BTreeMap::new();
    let mut by_service: BTreeMap<String, MinuteSummary> = BTreeMap::new();
    let mut by_node: BTreeMap<String, MinuteSummary> = BTreeMap::new();

    for s in &primary {
        by_minute
            .entry(s.minute_epoch)
            .and_modify(|acc| acc.merge_from(s))
            .or_insert_with(|| (*s).clone());
        by_service
            .entry(s.service_tag.clone())
            .and_modify(|acc| acc.merge_from(s))
            .or_insert_with(|| (*s).clone());
    }

    let mut node_has_ingress: HashSet<&str> = HashSet::new();
    for s in &base {
        if s.role == "ingress" {
            node_has_ingress.insert(s.node_tag.as_str());
        }
    }
    for s in &base {
        if node_has_ingress.contains(s.node_tag.as_str()) && s.role == "egress" {
            continue;
        }
        by_node
            .entry(s.node_tag.clone())
            .and_modify(|acc| acc.merge_from(s))
            .or_insert_with(|| (*s).clone());
    }

    build_aggregated_traffic_from_maps(by_minute, by_service, by_node)
}

fn merge_maintainer_traffic_maps(
    replies: &[serde_json::Value],
) -> (
    BTreeMap<i64, MinuteSummary>,
    BTreeMap<String, MinuteSummary>,
    BTreeMap<String, MinuteSummary>,
) {
    let mut by_minute: BTreeMap<i64, MinuteSummary> = BTreeMap::new();
    let mut by_service: BTreeMap<String, MinuteSummary> = BTreeMap::new();
    let mut by_node: BTreeMap<String, MinuteSummary> = BTreeMap::new();
    for rep in replies {
        if let Some(arr) = rep.get("traffic_buckets").and_then(|v| v.as_array()) {
            for item in arr {
                if let Ok(mut s) = serde_json::from_value::<MinuteSummary>(item.clone()) {
                    by_minute
                        .entry(s.minute_epoch)
                        .and_modify(|acc| acc.merge_from(&s))
                        .or_insert_with(|| {
                            s.node_tag.clear();
                            s
                        });
                }
            }
        }
        if let Some(arr) = rep.get("service_summaries").and_then(|v| v.as_array()) {
            for item in arr {
                if let Ok(s) = serde_json::from_value::<MinuteSummary>(item.clone()) {
                    by_service
                        .entry(s.service_tag.clone())
                        .and_modify(|acc| acc.merge_from(&s))
                        .or_insert(s);
                }
            }
        }
        if let Some(arr) = rep.get("node_summaries").and_then(|v| v.as_array()) {
            for item in arr {
                if let Ok(s) = serde_json::from_value::<MinuteSummary>(item.clone()) {
                    by_node
                        .entry(s.node_tag.clone())
                        .and_modify(|acc| {
                            if s.requests > acc.requests {
                                *acc = s.clone();
                            }
                        })
                        .or_insert(s);
                }
            }
        }
    }
    (by_minute, by_service, by_node)
}

async fn overview(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<TimeRangeQuery>,
) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return *r;
    }
    let (from_ms, to_ms) = resolve_time_window(q.from_ms, q.to_ms, q.window_secs);
    let nodes = match state.client.db().list_nodes().await {
        Ok(n) => n,
        Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let latest_rel = state
        .client
        .db()
        .get_latest_config_release()
        .await
        .ok()
        .flatten();
    let seq = state
        .client
        .db()
        .latest_config_sequence()
        .await
        .unwrap_or(0);
    let tel = state.client.cached_telemetry().await;
    let boot = state.client.active_bootstrap_tag().await;
    let online_nodes = nodes.iter().filter(|n| n.online).count();
    let links_up = tel
        .links
        .iter()
        .filter(|l| l.state == LinkHealthState::Up)
        .count();
    let links_degraded = tel
        .links
        .iter()
        .filter(|l| l.state == LinkHealthState::Degraded)
        .count();
    let links_down = tel
        .links
        .iter()
        .filter(|l| l.state == LinkHealthState::Down)
        .count();

    let maint_replies: Vec<serde_json::Value> = state
        .client
        .query_maintainers(MaintainerQuery::Overview { from_ms, to_ms })
        .await
        .into_iter()
        .filter_map(|(_, r)| r.ok())
        .collect();

    let (agg, alerts, alerts_total) = if !maint_replies.is_empty() {
        let (by_m, by_s, by_n) = merge_maintainer_traffic_maps(&maint_replies);
        let agg = build_aggregated_traffic_from_maps(by_m, by_s, by_n);
        let mut all_alerts: Vec<AlertRecord> = Vec::new();
        let mut max_total: u64 = 0;
        for rep in &maint_replies {
            if let Some(arr) = rep.get("alerts").and_then(|v| v.as_array()) {
                for v in arr {
                    if let Ok(a) = serde_json::from_value::<AlertRecord>(v.clone()) {
                        all_alerts.push(a);
                    }
                }
            }
            max_total = max_total.max(
                rep.get("alerts_total")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            );
        }
        all_alerts.extend(tel.alerts.iter().cloned());
        let mut deduped = collect_normalized_cached_alerts(&all_alerts, from_ms, to_ms);
        let eff_total = max_total.max(deduped.len() as u64);
        deduped.truncate(20);
        (agg, deduped, eff_total)
    } else {
        let agg = aggregate_summaries(&tel.summaries, None, None, from_ms, to_ms);
        let mut deduped = collect_normalized_cached_alerts(&tel.alerts, from_ms, to_ms);
        let tot = deduped.len() as u64;
        deduped.truncate(20);
        (agg, deduped, tot)
    };

    let certs_valid = tel
        .certificates
        .iter()
        .filter(|c| c.status == "valid")
        .count();
    let certs_degraded = tel.certificates.len().saturating_sub(certs_valid);

    let yaml = state
        .client
        .db()
        .get_topology_yaml()
        .await
        .unwrap_or_default();
    let spec: TopologySpec = if yaml.trim().is_empty() {
        TopologySpec::default()
    } else {
        redact_topology_spec(serde_yaml::from_str(&yaml).unwrap_or_default())
    };

    Json(serde_json::json!({
        "control_id": state.cfg.control_id,
        "role": format!("{:?}", state.cfg.role).to_ascii_lowercase(),
        "bootstrap_node": boot,
        "last_pulled_at": tel.last_pulled_at,
        "node_count": nodes.len(),
        "online_nodes": online_nodes,
        "links_up": links_up,
        "links_degraded": links_degraded,
        "links_down": links_down,
        "latest_sequence": seq,
        "latest_revision": latest_rel.as_ref().map(|r| r.revision.as_str()).unwrap_or(""),
        "latest_revision_full": latest_rel.as_ref().map(|r| r.revision_full.as_str()).unwrap_or(""),
        "latest_release_seq": latest_rel.as_ref().map(|r| r.release_seq).unwrap_or(seq),
        "alerts": alerts,
        "alerts_total": alerts_total,
        "maintainers": tel.maintainers,
        "traffic": agg.traffic_json,
        "certificates_summary": {
            "total": tel.certificates.len(),
            "valid": certs_valid,
            "degraded": certs_degraded,
        },
        "timeseries": agg.timeseries,
        "service_breakdown": agg.service_breakdown,
        "node_breakdown": agg.node_breakdown,
        "nodes": nodes,
        "links": tel.links,
        "spec": spec,
    }))
    .into_response()
}

async fn list_nodes(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return *r;
    }
    let nodes = match state.client.db().list_nodes().await {
        Ok(n) => n,
        Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let tel = state.client.cached_telemetry().await;
    let boot = state.client.active_bootstrap_tag().await;
    let latest_release = state
        .client
        .db()
        .get_latest_config_release()
        .await
        .ok()
        .flatten();
    let enriched_nodes: Vec<serde_json::Value> = nodes
        .into_iter()
        .map(|n| {
            let uptime = tel.node_uptimes.get(&n.node_tag).copied();
            serde_json::json!({
                "node_tag": n.node_tag,
                "public_key": n.public_key,
                "pubkey_fingerprint": n.pubkey_fingerprint,
                "roles": n.roles,
                "config_seq": n.config_seq,
                "config_revision": n.config_revision,
                "last_reload_status": n.last_reload_status,
                "online": n.online,
                "uptime_secs": uptime,
            })
        })
        .collect();
    Json(serde_json::json!({
        "bootstrap_node": boot,
        "last_pulled_at": tel.last_pulled_at,
        "latest_revision": latest_release.as_ref().map(|r| r.revision.as_str()).unwrap_or(""),
        "latest_release_seq": latest_release.as_ref().map(|r| r.release_seq).unwrap_or(0),
        "nodes": enriched_nodes,
        "links": tel.links,
    }))
    .into_response()
}

async fn push_single_node(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(tag): Path<String>,
) -> Response {
    let actor = match verify_admin_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return *r,
    };
    if let Err(r) = require_active_role(&state) {
        return *r;
    }
    let yaml = match state.client.db().get_topology_yaml().await {
        Ok(y) => y,
        Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let (topo, report, compiled) = match state.client.compile_yaml_and_provision(&yaml).await {
        Ok(t) => t,
        Err(e) => return json_err(StatusCode::BAD_REQUEST, e.to_string()),
    };
    if !report.valid {
        return json_err(
            StatusCode::BAD_REQUEST,
            format!("topology invalid: {:?}", report.errors),
        );
    }
    let Some(cfg) = compiled.get(&tag).cloned() else {
        return json_err(
            StatusCode::NOT_FOUND,
            format!("node '{tag}' not in topology"),
        );
    };
    match state
        .client
        .push_single_node_latest(&actor, &topo, &yaml, &tag, cfg, false)
        .await
    {
        Ok((seq, rev)) => Json(serde_json::json!({
            "ok": true,
            "sequence": seq,
            "revision": rev,
        }))
        .into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
    }
}

async fn get_topology(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return *r;
    }
    let yaml = match state.client.db().get_topology_yaml().await {
        Ok(y) => y,
        Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let (spec, report) = if yaml.trim().is_empty() {
        (TopologySpec::default(), None)
    } else {
        match state.client.compile_yaml_readonly(&yaml).await {
            Ok((topo, rep, _)) => (topo, Some(rep)),
            Err(_) => (serde_yaml::from_str(&yaml).unwrap_or_default(), None),
        }
    };
    let redacted_spec = redact_topology_spec(spec);
    let redacted_yaml = serde_yaml::to_string(&redacted_spec).unwrap_or_default();
    let nodes = state.client.db().list_nodes().await.unwrap_or_default();
    let tel = state.client.cached_telemetry().await;
    Json(serde_json::json!({
        "yaml": redacted_yaml,
        "spec": redacted_spec,
        "paths": report.as_ref().map(|r| &r.paths),
        "errors": report.as_ref().map(|r| &r.errors),
        "warnings": report.as_ref().map(|r| &r.warnings),
        "live_nodes": nodes,
        "live_links": tel.links,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct TopoReq {
    #[serde(default)]
    yaml: Option<String>,
    #[serde(default)]
    spec: Option<TopologySpec>,
    #[serde(default)]
    push: bool,
    #[serde(default)]
    sync_dns: bool,
}

fn reject_yaml_bomb(yaml: &str) -> Result<(), Box<Response>> {
    if yaml.len() > MAX_YAML_BYTES {
        return Err(Box::new(json_err(
            StatusCode::PAYLOAD_TOO_LARGE,
            "topology YAML exceeds 256 KiB limit",
        )));
    }
    if yaml.lines().count() > 16_384 {
        return Err(Box::new(json_err(
            StatusCode::BAD_REQUEST,
            "topology YAML exceeds maximum line count",
        )));
    }
    // Scan outside single/double quotes and line comments for flow depth explosions,
    // YAML anchors/aliases (`&anchor`, `*alias`), and merge keys (`<<:`).
    let bytes = yaml.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut depth = 0usize;
    let mut sol = true;
    while i < len {
        let b = bytes[i];
        if in_double {
            if b == b'\\' && i + 1 < len {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_double = false;
            }
            sol = b == b'\n';
            i += 1;
            continue;
        }
        if in_single {
            if b == b'\'' {
                if i + 1 < len && bytes[i + 1] == b'\'' {
                    i += 2;
                    continue;
                }
                in_single = false;
            }
            sol = b == b'\n';
            i += 1;
            continue;
        }
        if b == b'\n' || b == b'\r' {
            sol = true;
            i += 1;
            continue;
        }
        if b == b'"' {
            in_double = true;
            sol = false;
            i += 1;
            continue;
        }
        if b == b'\'' {
            in_single = true;
            sol = false;
            i += 1;
            continue;
        }
        let prev_ws_or_sol = sol || matches!(bytes[i - 1], b' ' | b'\t');
        if b == b'#' && prev_ws_or_sol {
            while i < len && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b == b'{' || b == b'[' {
            depth += 1;
            if depth > 32 {
                return Err(Box::new(json_err(
                    StatusCode::BAD_REQUEST,
                    "YAML flow collection nesting exceeds 32 levels",
                )));
            }
        } else if b == b'}' || b == b']' {
            depth = depth.saturating_sub(1);
        }
        let at_indicator_pos = sol
            || matches!(
                bytes[i - 1],
                b' ' | b'\t' | b':' | b'-' | b'[' | b'{' | b',' | b'\n' | b'\r'
            );
        if at_indicator_pos {
            if b == b'<' && i + 2 < len && bytes[i + 1] == b'<' {
                let mut k = i + 2;
                while k < len && matches!(bytes[k], b' ' | b'\t') {
                    k += 1;
                }
                if k < len && bytes[k] == b':' {
                    return Err(Box::new(json_err(
                        StatusCode::BAD_REQUEST,
                        "YAML merge keys are not permitted",
                    )));
                }
            }
            if (b == b'&' || b == b'*') && i + 1 < len {
                let next = bytes[i + 1];
                if !matches!(next, b' ' | b'\t' | b'\n' | b'\r' | b',' | b']' | b'}') {
                    return Err(Box::new(json_err(
                        StatusCode::BAD_REQUEST,
                        "YAML anchors and aliases are not permitted",
                    )));
                }
            }
        }
        sol = false;
        i += 1;
    }
    Ok(())
}

async fn resolve_and_merge_topo_yaml(
    state: &ApiState,
    req: &TopoReq,
) -> Result<String, Box<Response>> {
    let existing_yaml = state
        .client
        .db()
        .get_topology_yaml()
        .await
        .unwrap_or_default();
    let existing_spec: TopologySpec = if existing_yaml.trim().is_empty() {
        TopologySpec::default()
    } else {
        serde_yaml::from_str(&existing_yaml).unwrap_or_default()
    };

    let parsed_spec: TopologySpec = if let Some(spec) = &req.spec {
        spec.clone()
    } else if let Some(yaml) = &req.yaml {
        reject_yaml_bomb(yaml)?;
        serde_yaml::from_str(yaml).map_err(|e| {
            Box::new(json_err(
                StatusCode::BAD_REQUEST,
                format!("parse topology yaml: {e}"),
            ))
        })?
    } else {
        return Err(Box::new(json_err(
            StatusCode::BAD_REQUEST,
            "either yaml or spec must be provided",
        )));
    };

    let merged = restore_redacted_secrets(parsed_spec, &existing_spec)?;
    let out_yaml = serde_yaml::to_string(&merged).map_err(|e| {
        Box::new(json_err(
            StatusCode::BAD_REQUEST,
            format!("serialize spec: {e}"),
        ))
    })?;
    if out_yaml.len() > MAX_YAML_BYTES {
        return Err(Box::new(json_err(
            StatusCode::PAYLOAD_TOO_LARGE,
            "serialized topology exceeds 256 KiB limit",
        )));
    }
    Ok(out_yaml)
}

async fn validate_topology(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<TopoReq>,
) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return *r;
    }
    let yaml = match resolve_and_merge_topo_yaml(&state, &req).await {
        Ok(y) => y,
        Err(r) => return *r,
    };
    match state.client.compile_yaml_readonly(&yaml).await {
        Ok((topo, report, _)) => {
            let redacted = redact_topology_spec(topo);
            let redacted_yaml = serde_yaml::to_string(&redacted).unwrap_or_default();
            Json(serde_json::json!({
                "valid": report.valid,
                "errors": report.errors,
                "warnings": report.warnings,
                "paths": report.paths,
                "yaml": redacted_yaml,
                "spec": redacted,
            }))
            .into_response()
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn preflight_topology(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<TopoReq>,
) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return *r;
    }
    if let Err(r) = require_active_role(&state) {
        return *r;
    }
    let yaml = match resolve_and_merge_topo_yaml(&state, &req).await {
        Ok(y) => y,
        Err(r) => return *r,
    };
    let (topo, report, compiled) = match state.client.compile_yaml_readonly(&yaml).await {
        Ok(t) => t,
        Err(e) => return json_err(StatusCode::BAD_REQUEST, e.to_string()),
    };
    if !report.valid {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "valid": false,
                "errors": report.errors,
                "warnings": report.warnings,
                "all_ok": false,
                "reports": [],
            })),
        )
            .into_response();
    }

    let mut reports = Vec::with_capacity(compiled.len());
    let sem = Arc::new(Semaphore::new(8));
    let mut futs = FuturesUnordered::new();
    for (tag, cfg) in compiled {
        let client = Arc::clone(&state.client);
        let topo_ref = &topo;
        let sem = Arc::clone(&sem);
        futs.push(async move {
            let _permit = sem.acquire_owned().await.ok();
            client.preflight_node_config(topo_ref, &tag, cfg).await
        });
    }
    while let Some(rep) = futs.next().await {
        reports.push(rep);
    }
    let all_ok = reports.iter().all(|r| r.ok);
    Json(serde_json::json!({
        "valid": true,
        "warnings": report.warnings,
        "all_ok": all_ok,
        "reports": reports,
    }))
    .into_response()
}

async fn save_topology(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<TopoReq>,
) -> Response {
    let actor = match verify_admin_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return *r,
    };
    if let Err(r) = require_active_role(&state) {
        return *r;
    }
    let yaml = match resolve_and_merge_topo_yaml(&state, &req).await {
        Ok(y) => y,
        Err(r) => return *r,
    };
    let (topo, report, compiled) = match state.client.compile_yaml_and_provision(&yaml).await {
        Ok(t) => t,
        Err(e) => return json_err(StatusCode::BAD_REQUEST, e.to_string()),
    };
    if !report.valid {
        return (StatusCode::BAD_REQUEST, Json(report)).into_response();
    }
    if let Err(e) = state.client.db().set_topology_yaml(&yaml).await {
        return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    state
        .client
        .db()
        .append_audit(
            &actor,
            "topology_save",
            "topology",
            true,
            "saved valid topology",
        )
        .await;

    let mut pushed_count = 0usize;
    let mut push_errors = Vec::new();
    let mut release_seq: Option<u64> = None;
    let mut revision: Option<String> = None;
    let mut revision_full: Option<String> = None;
    let mut push_results = Vec::new();
    if req.push {
        match state
            .client
            .deploy_topology_release(
                &actor,
                &yaml,
                &topo,
                compiled,
                "topology_push",
                "Deploy topology",
            )
            .await
        {
            Ok(dep) => {
                release_seq = Some(dep.release_seq);
                revision = Some(dep.revision);
                revision_full = Some(dep.revision_full);
                for item in &dep.results {
                    if item["ok"].as_bool().unwrap_or(false) {
                        pushed_count += 1;
                    } else {
                        let tag = item["node_tag"].as_str().unwrap_or("?");
                        let err = item["error"].as_str().unwrap_or("failed");
                        push_errors.push(format!("{tag}: {err}"));
                    }
                }
                push_results = dep.results;
            }
            Err(e) => push_errors.push(e.to_string()),
        }
    }

    let mut dns_sync_results = None;
    let mut dns_sync_error = None;
    if req.sync_dns {
        match state.client.sync_dns(&actor, None, None).await {
            Ok((_, res)) => dns_sync_results = Some(res),
            Err(e) => dns_sync_error = Some(e.to_string()),
        }
    }

    let redacted = redact_topology_spec(topo);
    let redacted_yaml = serde_yaml::to_string(&redacted).unwrap_or_default();
    Json(serde_json::json!({
        "valid": report.valid,
        "warnings": report.warnings,
        "paths": report.paths,
        "release_seq": release_seq,
        "revision": revision,
        "revision_full": revision_full,
        "pushed_count": pushed_count,
        "push_errors": push_errors,
        "push_results": push_results,
        "dns_sync_results": dns_sync_results,
        "dns_sync_error": dns_sync_error,
        "yaml": redacted_yaml,
        "spec": redacted,
    }))
    .into_response()
}

#[derive(Deserialize, Default)]
struct ReleasesQuery {
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    limit: Option<usize>,
}

async fn list_config_releases(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<ReleasesQuery>,
) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return *r;
    }
    let offset = q.offset.unwrap_or(0);
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let (items, total) = match state.client.db().list_config_releases(offset, limit).await {
        Ok(res) => res,
        Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let latest = state
        .client
        .db()
        .get_latest_config_release()
        .await
        .ok()
        .flatten();
    Json(serde_json::json!({
        "latest_revision": latest.as_ref().map(|r| r.revision.as_str()).unwrap_or(""),
        "latest_release_seq": latest.as_ref().map(|r| r.release_seq).unwrap_or(0),
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": offset.saturating_add(items.len()) < total,
        "releases": items,
    }))
    .into_response()
}

async fn rollback_release(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(rev): Path<String>,
) -> Response {
    let actor = match verify_admin_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return *r,
    };
    if let Err(r) = require_active_role(&state) {
        return *r;
    }
    match state.client.rollback_to_release(&actor, &rev).await {
        Ok(dep) => Json(serde_json::json!({
            "ok": true,
            "release_seq": dep.release_seq,
            "revision": dep.revision,
            "revision_full": dep.revision_full,
            "parent_revision": dep.parent_revision,
            "results": dep.results,
        }))
        .into_response(),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn list_config_versions(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return *r;
    }
    let versions = match state.client.db().list_config_versions(50).await {
        Ok(v) => v,
        Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let redacted: Vec<serde_json::Value> = versions
        .into_iter()
        .map(|v| {
            serde_json::json!({
                "id": v.id,
                "sequence": v.sequence,
                "node_tag": v.node_tag,
                "config_json": redact_node_config_json(&v.config_json),
                "status": v.status,
                "created_at": v.created_at,
            })
        })
        .collect();
    Json(serde_json::json!({ "versions": redacted })).into_response()
}

async fn rollback_version(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let actor = match verify_admin_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return *r,
    };
    if let Err(r) = require_active_role(&state) {
        return *r;
    }
    let rec = match state.client.db().get_config_version(id).await {
        Ok(Some(r)) => r,
        Ok(None) => return json_err(StatusCode::NOT_FOUND, "version not found"),
        Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let cfg: NodeConfig = match serde_json::from_str(&rec.config_json) {
        Ok(c) => c,
        Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let yaml = state
        .client
        .db()
        .get_topology_yaml()
        .await
        .unwrap_or_default();
    let topo = serde_yaml::from_str(&yaml).unwrap_or_default();
    match state
        .client
        .push_node_config(&actor, &topo, &rec.node_tag, cfg)
        .await
    {
        Ok(seq) => Json(serde_json::json!({ "ok": true, "new_sequence": seq })).into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
    }
}

async fn list_passphrases(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return *r;
    }
    let items = match state.client.db().list_passphrases().await {
        Ok(v) => v,
        Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    Json(serde_json::json!({ "items": items })).into_response()
}

#[derive(Deserialize)]
struct RegisterPassphraseReq {
    node_tag: String,
    passphrase: String,
    mode: String,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    via_hops: Vec<String>,
}

async fn validate_dial_address_async(addr: &str) -> Result<(), &'static str> {
    let trimmed = addr.trim();
    let Some((host, port_s)) = trimmed.rsplit_once(':') else {
        return Err("address must be host:port");
    };
    let port: u16 = port_s
        .parse()
        .ok()
        .filter(|&p| p > 0)
        .ok_or("invalid host or port in address")?;
    if host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
        return Err("invalid host or port in address");
    }
    let Some(clean) = parse_valid_host(host) else {
        return Err("invalid host or port in address");
    };
    if clean == "localhost" || clean.ends_with(".localhost") {
        return Err("loopback target address is not allowed");
    }
    if let Ok(ip) = clean.parse::<IpAddr>() {
        if !is_public_routable_ip(canonical_ip(ip)) {
            return Err("private/internal or non-routable IP address is not allowed");
        }
        return Ok(());
    }
    let resolved = tokio::net::lookup_host((clean.as_str(), port))
        .await
        .map_err(|_| "failed to resolve target address")?;
    let mut saw_any = false;
    for sock in resolved {
        saw_any = true;
        if !is_public_routable_ip(canonical_ip(sock.ip())) {
            return Err("target hostname resolves to non-public/internal IP address");
        }
    }
    if !saw_any {
        return Err("failed to resolve target address");
    }
    Ok(())
}

async fn register_passphrase(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<RegisterPassphraseReq>,
) -> Response {
    let actor = match verify_admin_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return *r,
    };
    if let Err(r) = require_active_role(&state) {
        return *r;
    }

    if let Err(e) = validate_identifier(&req.node_tag, "node_tag") {
        return json_err(StatusCode::BAD_REQUEST, e.to_string());
    }
    if req.passphrase.trim().len() < 16 {
        return json_err(
            StatusCode::BAD_REQUEST,
            "passphrase must be at least 16 characters",
        );
    }
    if !matches!(req.mode.as_str(), "active" | "listening") {
        return json_err(
            StatusCode::BAD_REQUEST,
            "mode must be 'active' or 'listening'",
        );
    }
    // Forbid silently re-enrolling / overwriting an already-pinned node
    if let Ok(Some(existing)) = state.client.db().get_node(&req.node_tag).await {
        if !existing.public_key.trim().is_empty() {
            return json_err(
                StatusCode::CONFLICT,
                format!(
                    "node '{}' is already enrolled with a pinned public key",
                    req.node_tag
                ),
            );
        }
    }
    if req.mode == "listening" {
        let Some(ref addr) = req.address else {
            return json_err(
                StatusCode::BAD_REQUEST,
                "listening mode requires target address (host:port)",
            );
        };
        if let Err(msg) = validate_dial_address_async(addr).await {
            return json_err(StatusCode::BAD_REQUEST, msg);
        }
    }

    if let Err(e) = state
        .client
        .db()
        .register_passphrase(
            &req.node_tag,
            req.passphrase.trim(),
            &req.mode,
            req.address.as_deref(),
            &req.via_hops,
            600,
        )
        .await
    {
        return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    state
        .client
        .db()
        .append_audit(
            &actor,
            "register_passphrase",
            &req.node_tag,
            true,
            &req.mode,
        )
        .await;

    if req.mode == "listening" {
        if let Some(ref addr) = req.address {
            if let Err(e) = state
                .client
                .trigger_listening_enroll(
                    &actor,
                    &req.node_tag,
                    addr,
                    req.passphrase.trim(),
                    &req.via_hops,
                )
                .await
            {
                // The enroll helper can fail before it reaches its own revoke paths (e.g. no
                // connected bootstrap node, or the RPC send fails). Revoke here so the
                // one-time passphrase can never remain usable after we report it as revoked.
                let _ = state.client.db().revoke_passphrase(&req.node_tag).await;
                return json_err(
                    StatusCode::BAD_GATEWAY,
                    format!("dial enroll failed (passphrase revoked): {e}"),
                );
            }
        }
    }

    Json(serde_json::json!({ "ok": true })).into_response()
}

async fn revoke_passphrase(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(tag): Path<String>,
) -> Response {
    let actor = match verify_admin_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return *r,
    };
    if let Err(r) = require_active_role(&state) {
        return *r;
    }
    if let Err(e) = state.client.db().revoke_passphrase(&tag).await {
        return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    state
        .client
        .db()
        .append_audit(&actor, "revoke_passphrase", &tag, true, "manual revoke")
        .await;
    Json(serde_json::json!({ "ok": true })).into_response()
}

async fn run_discovery(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    let actor = match verify_admin_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return *r,
    };
    if let Err(r) = require_active_role(&state) {
        return *r;
    }
    match state.client.run_discovery(&actor).await {
        Ok(n) => Json(serde_json::json!({ "discovered_nodes": n })).into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
    }
}

#[derive(Deserialize, Default)]
struct DnsSyncApiReq {
    #[serde(default)]
    domains: Option<Vec<String>>,
    #[serde(default)]
    maintainer_tag: Option<String>,
}

async fn sync_dns(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Option<Json<DnsSyncApiReq>>,
) -> Response {
    let actor = match verify_admin_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return *r,
    };
    if let Err(r) = require_active_role(&state) {
        return *r;
    }
    let req = body.map(|Json(b)| b).unwrap_or_default();
    match state
        .client
        .sync_dns(&actor, req.domains, req.maintainer_tag)
        .await
    {
        Ok((maintainer_tag, results)) => {
            let ok = results.iter().all(|r| r.ok);
            Json(serde_json::json!({
                "ok": ok,
                "maintainer_tag": maintainer_tag,
                "results": results,
            }))
            .into_response()
        }
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
    }
}

#[derive(Deserialize, Default)]
struct DnsInspectQuery {
    #[serde(default)]
    include_lines: Option<bool>,
    #[serde(default)]
    maintainer_tag: Option<String>,
}

#[derive(Deserialize, Default)]
struct DnsMaintainerQuery {
    #[serde(default)]
    maintainer_tag: Option<String>,
}

async fn inspect_dns_domain(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(domain): Path<String>,
    Query(q): Query<DnsInspectQuery>,
) -> Response {
    let actor = match verify_admin_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return *r,
    };
    let op = DnsManageOp::Inspect {
        domain: domain.clone(),
        include_lines: q.include_lines.unwrap_or(true),
    };
    match state.client.manage_dns(&actor, op, q.maintainer_tag).await {
        Ok((maintainer_tag, capabilities, lines, records, _)) => Json(serde_json::json!({
            "ok": true,
            "domain": domain,
            "maintainer_tag": maintainer_tag,
            "capabilities": capabilities,
            "lines": lines,
            "records": records,
        }))
        .into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
    }
}

#[derive(Deserialize)]
struct DnsRecordMutateReq {
    record_type: String,
    value: String,
    #[serde(default)]
    line: Option<String>,
    #[serde(default)]
    ttl: Option<u32>,
    #[serde(default)]
    proxied: Option<bool>,
    #[serde(default)]
    maintainer_tag: Option<String>,
}

async fn create_dns_record(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(domain): Path<String>,
    Json(req): Json<DnsRecordMutateReq>,
) -> Response {
    let actor = match verify_admin_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return *r,
    };
    if let Err(r) = require_active_role(&state) {
        return *r;
    }
    let op = DnsManageOp::Create {
        domain,
        record_type: req.record_type,
        value: req.value,
        line: req.line,
        ttl: req.ttl,
        proxied: req.proxied,
    };
    match state
        .client
        .manage_dns(&actor, op, req.maintainer_tag)
        .await
    {
        Ok((maintainer_tag, _, _, _, record_id)) => Json(serde_json::json!({
            "ok": true,
            "maintainer_tag": maintainer_tag,
            "record_id": record_id,
        }))
        .into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
    }
}

async fn update_dns_record(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path((domain, record_id)): Path<(String, String)>,
    Json(req): Json<DnsRecordMutateReq>,
) -> Response {
    let actor = match verify_admin_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return *r,
    };
    if let Err(r) = require_active_role(&state) {
        return *r;
    }
    let op = DnsManageOp::Update {
        domain,
        record_id,
        record_type: req.record_type,
        value: req.value,
        line: req.line,
        ttl: req.ttl,
        proxied: req.proxied,
    };
    match state
        .client
        .manage_dns(&actor, op, req.maintainer_tag)
        .await
    {
        Ok((maintainer_tag, _, _, _, rid)) => Json(serde_json::json!({
            "ok": true,
            "maintainer_tag": maintainer_tag,
            "record_id": rid,
        }))
        .into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
    }
}

#[derive(Deserialize)]
struct DnsRecordStatusReq {
    enabled: bool,
    #[serde(default)]
    maintainer_tag: Option<String>,
}

async fn set_dns_record_status(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path((domain, record_id)): Path<(String, String)>,
    Json(req): Json<DnsRecordStatusReq>,
) -> Response {
    let actor = match verify_admin_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return *r,
    };
    if let Err(r) = require_active_role(&state) {
        return *r;
    }
    let op = DnsManageOp::SetStatus {
        domain,
        record_id,
        enabled: req.enabled,
    };
    match state
        .client
        .manage_dns(&actor, op, req.maintainer_tag)
        .await
    {
        Ok((maintainer_tag, _, _, _, rid)) => Json(serde_json::json!({
            "ok": true,
            "maintainer_tag": maintainer_tag,
            "record_id": rid,
        }))
        .into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
    }
}

async fn delete_dns_record(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path((domain, record_id)): Path<(String, String)>,
    Query(q): Query<DnsMaintainerQuery>,
) -> Response {
    let actor = match verify_admin_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return *r,
    };
    if let Err(r) = require_active_role(&state) {
        return *r;
    }
    let op = DnsManageOp::Delete { domain, record_id };
    match state.client.manage_dns(&actor, op, q.maintainer_tag).await {
        Ok((maintainer_tag, _, _, _, rid)) => Json(serde_json::json!({
            "ok": true,
            "maintainer_tag": maintainer_tag,
            "record_id": rid,
        }))
        .into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
    }
}

#[derive(Serialize)]
struct SummaryDto {
    minute_epoch: i64,
    node_tag: String,
    role: String,
    service_tag: String,
    requests: u64,
    uv_estimate: f64,
    errors: u64,
    rate_limited: u64,
    challenges_issued: u64,
    challenges_passed: u64,
    blocked: u64,
    evilpot_hits: u64,
    autoban_hits: u64,
    bytes_in: u64,
    bytes_out: u64,
    cached_requests: u64,
    cached_bytes_out: u64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    device_counts: BTreeMap<String, u64>,
    browser_counts: BTreeMap<String, u64>,
    os_counts: BTreeMap<String, u64>,
    client_fp_verified: u64,
}

#[derive(Deserialize, Default)]
struct TelemetryQuery {
    #[serde(default)]
    node: Option<String>,
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    from_ms: Option<i64>,
    #[serde(default)]
    to_ms: Option<i64>,
    #[serde(default)]
    window_secs: Option<i64>,
    #[serde(default)]
    bucket_offset: Option<usize>,
    #[serde(default)]
    bucket_limit: Option<usize>,
}

fn evilpot_status_rank(s: &str) -> u8 {
    match s {
        "verified_exploit" => 3,
        "multi_step_exploitation" => 2,
        "probing" => 1,
        _ => 0,
    }
}

#[derive(Deserialize, Default)]
struct EvilpotQuery {
    #[serde(default)]
    from_ms: Option<i64>,
    #[serde(default)]
    to_ms: Option<i64>,
    #[serde(default)]
    window_secs: Option<i64>,
    #[serde(default)]
    node: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    sessions_offset: Option<usize>,
    #[serde(default)]
    sessions_limit: Option<usize>,
    #[serde(default)]
    events_offset: Option<usize>,
    #[serde(default)]
    events_limit: Option<usize>,
}

async fn get_evilpot(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<EvilpotQuery>,
) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return *r;
    }
    let tel = state.client.cached_telemetry().await;
    let (from_ms, to_ms) = resolve_time_window(q.from_ms, q.to_ms, q.window_secs);
    let sess_off = q.sessions_offset.unwrap_or(0);
    let sess_lim = q.sessions_limit.unwrap_or(50).clamp(1, 200);
    let ev_off = q.events_offset.unwrap_or(0);
    let ev_lim = q.events_limit.unwrap_or(50).clamp(1, 200);

    // Live node metrics (from StatusResp.evilpot) for in-flight tarpits / active bans
    let mut live_requests_handled = 0u64;
    let mut live_traps_triggered = 0u64;
    let mut live_canary_verifications = 0u64;
    let mut live_verified_sessions = 0u64;
    let mut live_tarpit_bytes = 0u64;
    let mut live_active_tarpit = 0usize;
    let mut live_active_ip_bans = 0usize;
    let mut live_active_fp_bans = 0usize;
    let mut live_total_auto_bans = 0u64;
    let mut live_total_ban_drops = 0u64;
    let mut live_nodes = Vec::new();
    let mut live_active_bans: Vec<serde_json::Value> = Vec::new();
    for rep in &tel.evilpot_reports {
        live_requests_handled = live_requests_handled.saturating_add(rep.requests_handled);
        live_traps_triggered = live_traps_triggered.saturating_add(rep.traps_triggered);
        live_canary_verifications =
            live_canary_verifications.saturating_add(rep.canary_verifications);
        live_verified_sessions =
            live_verified_sessions.saturating_add(rep.verified_attack_sessions);
        live_tarpit_bytes = live_tarpit_bytes.saturating_add(rep.tarpit_bytes_dripped);
        live_active_tarpit = live_active_tarpit.saturating_add(rep.active_tarpit_connections);
        live_active_ip_bans = live_active_ip_bans.saturating_add(rep.active_ip_bans);
        live_active_fp_bans = live_active_fp_bans.saturating_add(rep.active_fp_bans);
        live_total_auto_bans = live_total_auto_bans.saturating_add(rep.total_auto_bans);
        live_total_ban_drops = live_total_ban_drops.saturating_add(rep.total_ban_drops);
        live_nodes.push(serde_json::json!({
            "node_tag": rep.node_tag,
            "current_epoch": rep.current_epoch,
            "rotations_completed": rep.rotations_completed,
            "requests_handled": rep.requests_handled,
            "traps_triggered": rep.traps_triggered,
            "canary_verifications": rep.canary_verifications,
            "verified_attack_sessions": rep.verified_attack_sessions,
            "tarpit_bytes_dripped": rep.tarpit_bytes_dripped,
            "active_tarpit_connections": rep.active_tarpit_connections,
            "active_ip_bans": rep.active_ip_bans,
            "active_fp_bans": rep.active_fp_bans,
            "total_auto_bans": rep.total_auto_bans,
            "total_ban_drops": rep.total_ban_drops,
            "tracked_sessions": rep.sessions.len(),
        }));
        for b in &rep.active_bans {
            let mut v = serde_json::to_value(b).unwrap_or_default();
            if let Some(o) = v.as_object_mut() {
                o.insert(
                    "node_tag".into(),
                    serde_json::Value::String(rep.node_tag.clone()),
                );
            }
            live_active_bans.push(v);
        }
    }

    let maint_replies: Vec<serde_json::Value> = state
        .client
        .query_maintainers(MaintainerQuery::Evilpot {
            from_ms,
            to_ms,
            node: q.node.clone(),
            status: q.status.clone(),
            ip: q.ip.clone(),
            q: q.q.clone(),
            sessions_offset: if sess_off > 0 { 0 } else { sess_off },
            sessions_limit: (sess_off + sess_lim).min(200),
            events_offset: if ev_off > 0 { 0 } else { ev_off },
            events_limit: (ev_off + ev_lim).min(200),
        })
        .await
        .into_iter()
        .filter_map(|(_, r)| r.ok())
        .collect();

    if !maint_replies.is_empty() {
        let mut avail_nodes: BTreeSet<String> = tel
            .evilpot_reports
            .iter()
            .map(|r| r.node_tag.clone())
            .collect();
        let mut sess_map: HashMap<(String, String), EvilpotSessionInfo> = HashMap::new();
        let mut ev_map: HashMap<(String, u64, String, String, String), EvilpotEventInfo> =
            HashMap::new();
        let mut db_traps = 0u64;
        let mut db_canaries = 0u64;
        let mut db_tarpit = 0u64;
        let mut s_total_max = 0usize;
        let mut e_total_max = 0usize;

        for rep in &maint_replies {
            if let Some(arr) = rep.get("available_nodes").and_then(|v| v.as_array()) {
                for n in arr {
                    if let Some(ns) = n.as_str() {
                        avail_nodes.insert(ns.to_string());
                    }
                }
            }
            if let Some(arr) = rep.get("sessions").and_then(|v| v.as_array()) {
                for v in arr {
                    if let Ok(s) = serde_json::from_value::<EvilpotSessionInfo>(v.clone()) {
                        let k = (s.node_tag.clone(), s.client_ip.clone());
                        sess_map
                            .entry(k)
                            .and_modify(|cur| {
                                if evilpot_status_rank(&s.status)
                                    >= evilpot_status_rank(&cur.status)
                                    && s.last_seen_unix >= cur.last_seen_unix
                                {
                                    *cur = s.clone();
                                }
                            })
                            .or_insert(s);
                    }
                }
            }
            if let Some(arr) = rep.get("recent_events").and_then(|v| v.as_array()) {
                for v in arr {
                    if let Ok(ev) = serde_json::from_value::<EvilpotEventInfo>(v.clone()) {
                        let k = (
                            ev.node_tag.clone(),
                            ev.timestamp_unix,
                            ev.client_ip.clone(),
                            ev.trap_kind.clone(),
                            ev.detail.clone(),
                        );
                        ev_map.entry(k).or_insert(ev);
                    }
                }
            }
            db_traps += rep["summary"]["traps_triggered"].as_u64().unwrap_or(0);
            db_canaries += rep["summary"]["canary_verifications"].as_u64().unwrap_or(0);
            db_tarpit += rep["summary"]["tarpit_bytes_dripped"].as_u64().unwrap_or(0);
            s_total_max = s_total_max.max(rep["sessions_total"].as_u64().unwrap_or(0) as usize);
            e_total_max = e_total_max.max(rep["events_total"].as_u64().unwrap_or(0) as usize);
        }

        let mut sessions: Vec<EvilpotSessionInfo> = sess_map.into_values().collect();
        sessions.sort_by(|a, b| {
            evilpot_status_rank(&b.status)
                .cmp(&evilpot_status_rank(&a.status))
                .then_with(|| b.last_seen_unix.cmp(&a.last_seen_unix))
        });
        let verified_cnt = sessions
            .iter()
            .filter(|s| s.status == "verified_exploit")
            .count() as u64;
        let multi_cnt = sessions
            .iter()
            .filter(|s| s.status == "multi_step_exploitation")
            .count() as u64;
        let probing_cnt = sessions.iter().filter(|s| s.status == "probing").count() as u64;
        let sess_total = if maint_replies.len() == 1 {
            s_total_max.max(sessions.len())
        } else {
            sessions.len()
        };
        let sess_page: Vec<_> = sessions.into_iter().skip(sess_off).take(sess_lim).collect();

        let mut recent_events: Vec<EvilpotEventInfo> = ev_map.into_values().collect();
        recent_events.sort_by(|a, b| b.timestamp_unix.cmp(&a.timestamp_unix));
        let ev_total = if maint_replies.len() == 1 {
            e_total_max.max(recent_events.len())
        } else {
            recent_events.len()
        };
        let ev_page: Vec<_> = recent_events
            .into_iter()
            .skip(ev_off)
            .take(ev_lim)
            .collect();

        return Json(serde_json::json!({
            "last_pulled_at": tel.last_pulled_at,
            "summary": {
                "active_nodes": live_nodes.len(),
                "requests_handled": live_requests_handled,
                "traps_triggered": db_traps.max(live_traps_triggered),
                "canary_verifications": db_canaries.max(live_canary_verifications),
                "verified_attack_sessions": verified_cnt.max(live_verified_sessions),
                "multi_step_sessions": multi_cnt,
                "probing_sessions": probing_cnt,
                "tracked_sessions": sess_total,
                "tarpit_bytes_dripped": db_tarpit.max(live_tarpit_bytes),
                "active_tarpit_connections": live_active_tarpit,
                "active_ip_bans": live_active_ip_bans,
                "active_fp_bans": live_active_fp_bans,
                "total_auto_bans": live_total_auto_bans,
                "total_ban_drops": live_total_ban_drops,
                "total_events": ev_total,
            },
            "available_nodes": avail_nodes.into_iter().collect::<Vec<_>>(),
            "nodes": live_nodes,
            "sessions": sess_page,
            "sessions_total": sess_total,
            "sessions_offset": sess_off,
            "sessions_limit": sess_lim,
            "recent_events": ev_page,
            "events_total": ev_total,
            "events_offset": ev_off,
            "events_limit": ev_lim,
            "active_bans": live_active_bans,
        }))
        .into_response();
    }

    // Fallback: Cached live reports
    let mut sessions: Vec<serde_json::Value> = Vec::new();
    let mut recent_events: Vec<serde_json::Value> = Vec::new();
    let from_sec = from_ms.map(|ms| ms.div_euclid(1000).max(0) as u64);
    let to_sec = to_ms.map(|ms| ms.div_euclid(1000).max(0) as u64);
    for rep in &tel.evilpot_reports {
        for s in &rep.sessions {
            if let Some(f) = from_sec {
                if s.last_seen_unix < f {
                    continue;
                }
            }
            if let Some(t) = to_sec {
                if s.first_seen_unix > t {
                    continue;
                }
            }
            let mut val = serde_json::to_value(s).unwrap_or_default();
            if let Some(obj) = val.as_object_mut() {
                obj.insert(
                    "node_tag".into(),
                    serde_json::Value::String(rep.node_tag.clone()),
                );
            }
            sessions.push(val);
        }
        for ev in &rep.recent_events {
            if let Some(f) = from_sec {
                if ev.timestamp_unix < f {
                    continue;
                }
            }
            if let Some(t) = to_sec {
                if ev.timestamp_unix > t {
                    continue;
                }
            }
            let mut val = serde_json::to_value(ev).unwrap_or_default();
            if let Some(obj) = val.as_object_mut() {
                obj.insert(
                    "node_tag".into(),
                    serde_json::Value::String(rep.node_tag.clone()),
                );
            }
            recent_events.push(val);
        }
    }
    sessions.sort_by(|a, b| {
        let ra = evilpot_status_rank(a.get("status").and_then(|v| v.as_str()).unwrap_or(""));
        let rb = evilpot_status_rank(b.get("status").and_then(|v| v.as_str()).unwrap_or(""));
        let ta = a
            .get("last_seen_unix")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let tb = b
            .get("last_seen_unix")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        rb.cmp(&ra).then_with(|| tb.cmp(&ta))
    });
    let sess_total = sessions.len();
    let sess_page: Vec<_> = sessions.into_iter().skip(sess_off).take(sess_lim).collect();
    recent_events.sort_by(|a, b| {
        b.get("timestamp_unix")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            .cmp(
                &a.get("timestamp_unix")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            )
    });
    let ev_total = recent_events.len();
    let ev_page: Vec<_> = recent_events
        .into_iter()
        .skip(ev_off)
        .take(ev_lim)
        .collect();

    Json(serde_json::json!({
        "last_pulled_at": tel.last_pulled_at,
        "summary": {
            "active_nodes": live_nodes.len(),
            "requests_handled": live_requests_handled,
            "traps_triggered": live_traps_triggered,
            "canary_verifications": live_canary_verifications,
            "verified_attack_sessions": live_verified_sessions,
            "tracked_sessions": sess_total,
            "tarpit_bytes_dripped": live_tarpit_bytes,
            "active_tarpit_connections": live_active_tarpit,
            "active_ip_bans": live_active_ip_bans,
            "active_fp_bans": live_active_fp_bans,
            "total_auto_bans": live_total_auto_bans,
            "total_ban_drops": live_total_ban_drops,
            "total_events": ev_total,
        },
        "available_nodes": tel.evilpot_reports.iter().map(|r| r.node_tag.clone()).collect::<Vec<_>>(),
        "nodes": live_nodes,
        "sessions": sess_page,
        "sessions_total": sess_total,
        "sessions_offset": sess_off,
        "sessions_limit": sess_lim,
        "recent_events": ev_page,
        "events_total": ev_total,
        "events_offset": ev_off,
        "events_limit": ev_lim,
        "active_bans": live_active_bans,
    }))
    .into_response()
}

#[derive(Deserialize, Default)]
struct BansQuery {
    #[serde(default)]
    from_ms: Option<i64>,
    #[serde(default)]
    to_ms: Option<i64>,
    #[serde(default)]
    window_secs: Option<i64>,
    #[serde(default)]
    node: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    limit: Option<usize>,
}

async fn list_bans(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<BansQuery>,
) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return *r;
    }
    let tel = state.client.cached_telemetry().await;
    let (from_ms, to_ms) = resolve_time_window(q.from_ms, q.to_ms, q.window_secs);
    let offset = q.offset.unwrap_or(0);
    let limit = q.limit.unwrap_or(50).clamp(1, 200);

    let maint_replies: Vec<serde_json::Value> = state
        .client
        .query_maintainers(MaintainerQuery::Bans {
            from_ms,
            to_ms,
            node: q.node.clone(),
            status: q.status.clone(),
            kind: q.kind.clone(),
            target: q.target.clone(),
            q: q.q.clone(),
            offset: 0,
            limit: (offset + limit).min(200),
        })
        .await
        .into_iter()
        .filter_map(|(_, r)| r.ok())
        .collect();

    if !maint_replies.is_empty() {
        let mut avail_nodes: BTreeSet<String> = tel
            .evilpot_reports
            .iter()
            .map(|r| r.node_tag.clone())
            .collect();
        let mut ban_map: HashMap<(String, String, String, u64), BanRecord> = HashMap::new();
        let mut total_max = 0usize;
        for rep in &maint_replies {
            if let Some(arr) = rep.get("available_nodes").and_then(|v| v.as_array()) {
                for n in arr {
                    if let Some(ns) = n.as_str() {
                        avail_nodes.insert(ns.to_string());
                    }
                }
            }
            if let Some(arr) = rep.get("items").and_then(|v| v.as_array()) {
                for v in arr {
                    if let Ok(b) = serde_json::from_value::<BanRecord>(v.clone()) {
                        let k = (
                            b.node_tag.clone(),
                            b.kind.clone(),
                            b.target.clone(),
                            b.banned_at_unix,
                        );
                        ban_map
                            .entry(k)
                            .and_modify(|cur| {
                                cur.hits_blocked = cur.hits_blocked.max(b.hits_blocked);
                                if b.status == "unbanned" {
                                    cur.status = "unbanned".into();
                                    cur.unbanned_at_unix = b.unbanned_at_unix;
                                    cur.unbanned_by = b.unbanned_by.clone();
                                }
                            })
                            .or_insert(b);
                    }
                }
            }
            total_max = total_max.max(rep["total_matched"].as_u64().unwrap_or(0) as usize);
        }
        // Freshen hits_blocked from live active_bans snapshot (without resurrecting already-unbanned rows)
        for rep in &tel.evilpot_reports {
            for ab in &rep.active_bans {
                let k = (
                    rep.node_tag.clone(),
                    ab.kind.clone(),
                    ab.target.clone(),
                    ab.banned_at_unix,
                );
                if let Some(cur) = ban_map.get_mut(&k) {
                    cur.hits_blocked = cur.hits_blocked.max(ab.hits_blocked);
                }
            }
        }
        let mut items: Vec<BanRecord> = ban_map.into_values().collect();
        items.sort_by(|a, b| {
            let act_a = if a.status == "active" { 0 } else { 1 };
            let act_b = if b.status == "active" { 0 } else { 1 };
            act_a
                .cmp(&act_b)
                .then_with(|| b.banned_at_unix.cmp(&a.banned_at_unix))
                .then_with(|| b.id.cmp(&a.id))
        });

        let summary = if maint_replies.len() == 1 {
            maint_replies[0]["summary"].clone()
        } else {
            let active_ip = items
                .iter()
                .filter(|b| b.status == "active" && b.kind == "ip")
                .count();
            let active_fp = items
                .iter()
                .filter(|b| b.status == "active" && b.kind != "ip")
                .count();
            let expired = items.iter().filter(|b| b.status == "expired").count() as u64;
            let unbanned = items.iter().filter(|b| b.status == "unbanned").count() as u64;
            let hits: u64 = items.iter().map(|b| b.hits_blocked).sum();
            serde_json::json!({
                "total_bans": items.len() as u64,
                "active_ip_bans": active_ip,
                "active_fp_bans": active_fp,
                "expired_bans": expired,
                "unbanned_bans": unbanned,
                "total_hits_blocked": hits,
            })
        };
        let total_matched = if maint_replies.len() == 1 {
            total_max
        } else {
            items.len()
        };
        let page: Vec<_> = items.into_iter().skip(offset).take(limit).collect();
        let has_more = offset.saturating_add(page.len()) < total_matched;
        return Json(serde_json::json!({
            "last_pulled_at": tel.last_pulled_at,
            "total_matched": total_matched,
            "offset": offset,
            "limit": limit,
            "has_more": has_more,
            "summary": summary,
            "available_nodes": avail_nodes.into_iter().collect::<Vec<_>>(),
            "items": page,
        }))
        .into_response();
    }

    // Fallback: synthesize from live active_bans in CachedTelemetry
    let node_f = clean_filter_opt(q.node.as_deref());
    let status_f = clean_filter_opt(q.status.as_deref()).map(|s| s.to_ascii_lowercase());
    let kind_f = clean_filter_opt(q.kind.as_deref()).map(|s| s.to_ascii_lowercase());
    let target_f = clean_filter_opt(q.target.as_deref()).map(|s| s.to_ascii_lowercase());
    let q_f = clean_filter_opt(q.q.as_deref()).map(|s| s.to_ascii_lowercase());
    let avail_nodes: BTreeSet<String> = tel
        .evilpot_reports
        .iter()
        .map(|r| r.node_tag.clone())
        .collect();
    let mut rows: Vec<BanRecord> = Vec::new();
    for rep in &tel.evilpot_reports {
        if let Some(ref nf) = node_f {
            if &rep.node_tag != nf {
                continue;
            }
        }
        for b in &rep.active_bans {
            if status_f.as_deref().map(|s| s != "active").unwrap_or(false) {
                continue;
            }
            if let Some(ref kf) = kind_f {
                if &b.kind != kf {
                    continue;
                }
            }
            if let Some(ref tf) = target_f {
                if !b.target.to_ascii_lowercase().contains(tf) {
                    continue;
                }
            }
            if let Some(ref qf) = q_f {
                if !b.target.to_ascii_lowercase().contains(qf)
                    && !b.reason.to_ascii_lowercase().contains(qf)
                    && !rep.node_tag.to_ascii_lowercase().contains(qf)
                {
                    continue;
                }
            }
            rows.push(BanRecord {
                id: 0,
                node_tag: rep.node_tag.clone(),
                kind: b.kind.clone(),
                target: b.target.clone(),
                reason: b.reason.clone(),
                service_tag: None,
                host: None,
                offense_level: b.offense_level,
                banned_at_unix: b.banned_at_unix,
                expires_at_unix: b.expires_at_unix,
                unbanned_at_unix: None,
                unbanned_by: None,
                hits_blocked: b.hits_blocked,
                status: "active".into(),
            });
        }
    }
    let active_ip_bans = rows.iter().filter(|b| b.kind == "ip").count();
    let active_fp_bans = rows.iter().filter(|b| b.kind != "ip").count();
    let hits_blocked: u64 = rows.iter().map(|b| b.hits_blocked).sum();
    let (page, total_matched, off, lim, has_more) = paginate_items(rows, q.offset, q.limit);
    Json(serde_json::json!({
        "last_pulled_at": tel.last_pulled_at,
        "total_matched": total_matched,
        "offset": off,
        "limit": lim,
        "has_more": has_more,
        "summary": {
            "total_bans": total_matched,
            "active_ip_bans": active_ip_bans,
            "active_fp_bans": active_fp_bans,
            "expired_bans": 0,
            "unbanned_bans": 0,
            "total_hits_blocked": hits_blocked,
        },
        "available_nodes": avail_nodes.into_iter().collect::<Vec<_>>(),
        "items": page,
    }))
    .into_response()
}

#[derive(Deserialize, Default)]
struct AlertsQuery {
    #[serde(default)]
    from_ms: Option<i64>,
    #[serde(default)]
    to_ms: Option<i64>,
    #[serde(default)]
    window_secs: Option<i64>,
    #[serde(default)]
    node: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    limit: Option<usize>,
}

async fn list_alerts(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<AlertsQuery>,
) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return *r;
    }
    let tel = state.client.cached_telemetry().await;
    let (from_ms, to_ms) = resolve_time_window(q.from_ms, q.to_ms, q.window_secs);
    let offset = q.offset.unwrap_or(0);
    let limit = q.limit.unwrap_or(50).clamp(1, 200);

    let maint_replies: Vec<serde_json::Value> = state
        .client
        .query_maintainers(MaintainerQuery::Alerts {
            from_ms,
            to_ms,
            node: q.node.clone(),
            severity: q.severity.clone(),
            q: q.q.clone(),
            offset: 0,
            limit: (offset + limit).min(200),
        })
        .await
        .into_iter()
        .filter_map(|(_, r)| r.ok())
        .collect();

    if !maint_replies.is_empty() {
        let mut avail_sources: BTreeSet<String> = BTreeSet::new();
        let mut seen: HashSet<(i64, String, String, String)> = HashSet::new();
        let mut items: Vec<AlertRecord> = Vec::new();
        let mut total_max = 0usize;
        for rep in &maint_replies {
            if let Some(arr) = rep.get("available_sources").and_then(|v| v.as_array()) {
                for s in arr {
                    if let Some(ss) = s.as_str() {
                        avail_sources.insert(ss.to_string());
                    }
                }
            }
            if let Some(arr) = rep.get("items").and_then(|v| v.as_array()) {
                for v in arr {
                    if let Ok(a) = serde_json::from_value::<AlertRecord>(v.clone()) {
                        let a = normalize_alert_record(a);
                        let key = (
                            a.timestamp_ms,
                            a.source.clone(),
                            a.severity.clone(),
                            a.message.clone(),
                        );
                        if seen.insert(key) {
                            items.push(a);
                        }
                    }
                }
            }
            total_max = total_max.max(rep["total_matched"].as_u64().unwrap_or(0) as usize);
        }
        items.sort_by(|a, b| b.timestamp_ms.cmp(&a.timestamp_ms));
        let total_matched = if maint_replies.len() == 1 {
            total_max
        } else {
            items.len()
        };
        let sev_counts = if maint_replies.len() == 1 {
            maint_replies[0]["severity_counts"].clone()
        } else {
            let mut m: BTreeMap<String, u64> = BTreeMap::new();
            for a in &items {
                *m.entry(a.severity.clone()).or_insert(0) += 1;
            }
            serde_json::to_value(m).unwrap_or_default()
        };
        let page: Vec<_> = items.into_iter().skip(offset).take(limit).collect();
        let has_more = offset.saturating_add(page.len()) < total_matched;
        return Json(serde_json::json!({
            "last_pulled_at": tel.last_pulled_at,
            "total_matched": total_matched,
            "offset": offset,
            "limit": limit,
            "has_more": has_more,
            "severity_counts": sev_counts,
            "available_sources": avail_sources.into_iter().collect::<Vec<_>>(),
            "items": page,
        }))
        .into_response();
    }

    // Fallback to CachedTelemetry alerts
    let node_f = clean_filter_opt(q.node.as_deref());
    let sev_f =
        clean_filter_opt(q.severity.as_deref()).map(|s| normalize_alert_severity(&s).to_string());
    let q_f = clean_filter_opt(q.q.as_deref()).map(|s| s.to_ascii_lowercase());
    let all = collect_normalized_cached_alerts(&tel.alerts, from_ms, to_ms);
    let avail_sources: BTreeSet<String> = all.iter().map(|a| a.source.clone()).collect();
    let mut sev_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut matched = Vec::new();
    for a in all {
        if let Some(ref nf) = node_f {
            if &a.source != nf {
                continue;
            }
        }
        if let Some(ref qf) = q_f {
            if !a.message.to_ascii_lowercase().contains(qf)
                && !a.source.to_ascii_lowercase().contains(qf)
            {
                continue;
            }
        }
        *sev_counts.entry(a.severity.clone()).or_insert(0) += 1;
        if let Some(ref sv) = sev_f {
            if &a.severity != sv {
                continue;
            }
        }
        matched.push(a);
    }
    let (page, total_matched, off, lim, has_more) = paginate_items(matched, q.offset, q.limit);
    Json(serde_json::json!({
        "last_pulled_at": tel.last_pulled_at,
        "total_matched": total_matched,
        "offset": off,
        "limit": lim,
        "has_more": has_more,
        "severity_counts": sev_counts,
        "available_sources": avail_sources.into_iter().collect::<Vec<_>>(),
        "items": page,
    }))
    .into_response()
}

async fn get_telemetry(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<TelemetryQuery>,
) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return *r;
    }
    let tel = state.client.cached_telemetry().await;
    let (from_ms, to_ms) = resolve_time_window(q.from_ms, q.to_ms, q.window_secs);
    let node_f = clean_filter_opt(q.node.as_deref());
    let svc_f = clean_filter_opt(q.service.as_deref());
    let b_off = q.bucket_offset.unwrap_or(0);
    let b_lim = q.bucket_limit.unwrap_or(100).clamp(1, 200);

    let maint_replies: Vec<serde_json::Value> = state
        .client
        .query_maintainers(MaintainerQuery::Telemetry {
            from_ms,
            to_ms,
            node: node_f.clone(),
            service: svc_f.clone(),
            bucket_offset: if b_off > 0 { 0 } else { b_off },
            bucket_limit: (b_off + b_lim).min(200),
        })
        .await
        .into_iter()
        .filter_map(|(_, r)| r.ok())
        .collect();

    if !maint_replies.is_empty() {
        let mut avail_nodes: BTreeSet<String> = BTreeSet::new();
        let mut avail_svcs: BTreeSet<String> = BTreeSet::new();
        let (by_m, by_s, by_n) = merge_maintainer_traffic_maps(&maint_replies);
        let agg = build_aggregated_traffic_from_maps(by_m, by_s, by_n);
        let mut bucket_map: HashMap<(i64, String, String, String), serde_json::Value> =
            HashMap::new();
        let mut max_buckets_total = 0usize;
        for rep in &maint_replies {
            if let Some(arr) = rep.get("available_nodes").and_then(|v| v.as_array()) {
                for n in arr {
                    if let Some(s) = n.as_str() {
                        avail_nodes.insert(s.to_string());
                    }
                }
            }
            if let Some(arr) = rep.get("available_services").and_then(|v| v.as_array()) {
                for sv in arr {
                    if let Some(s) = sv.as_str() {
                        avail_svcs.insert(s.to_string());
                    }
                }
            }
            if let Some(arr) = rep.get("buckets").and_then(|v| v.as_array()) {
                for b in arr {
                    let ep = b["minute_epoch"].as_i64().unwrap_or(0);
                    let nt = b["node_tag"].as_str().unwrap_or("").to_string();
                    let rl = b["role"].as_str().unwrap_or("").to_string();
                    let st = b["service_tag"].as_str().unwrap_or("").to_string();
                    let k = (ep, nt, rl, st);
                    bucket_map
                        .entry(k)
                        .and_modify(|cur| {
                            if b["requests"].as_u64().unwrap_or(0)
                                > cur["requests"].as_u64().unwrap_or(0)
                            {
                                *cur = b.clone();
                            }
                        })
                        .or_insert_with(|| b.clone());
                }
            }
            max_buckets_total =
                max_buckets_total.max(rep["buckets_total"].as_u64().unwrap_or(0) as usize);
        }
        let mut buckets: Vec<serde_json::Value> = bucket_map.into_values().collect();
        buckets.sort_by(|a, b| {
            b["minute_epoch"]
                .as_i64()
                .unwrap_or(0)
                .cmp(&a["minute_epoch"].as_i64().unwrap_or(0))
                .then_with(|| a["node_tag"].as_str().cmp(&b["node_tag"].as_str()))
        });
        let buckets_total = if maint_replies.len() == 1 {
            max_buckets_total.max(buckets.len())
        } else {
            buckets.len()
        };
        let summaries_page: Vec<_> = buckets.into_iter().skip(b_off).take(b_lim).collect();
        return Json(serde_json::json!({
            "last_pulled_at": tel.last_pulled_at,
            "traffic": agg.traffic_json,
            "timeseries": agg.timeseries,
            "service_breakdown": agg.service_breakdown,
            "node_breakdown": agg.node_breakdown,
            "device_counts": agg.device_counts,
            "browser_counts": agg.browser_counts,
            "os_counts": agg.os_counts,
            "client_fp_verified": agg.client_fp_verified,
            "available_nodes": avail_nodes.into_iter().collect::<Vec<_>>(),
            "available_services": avail_svcs.into_iter().collect::<Vec<_>>(),
            "summaries": summaries_page,
            "buckets_total": buckets_total,
            "bucket_offset": b_off,
            "bucket_limit": b_lim,
            "certificates": tel.certificates,
            "maintainers": tel.maintainers,
            "links": tel.links,
            "alerts": collect_normalized_cached_alerts(&tel.alerts, from_ms, to_ms),
        }))
        .into_response();
    }

    let from_sec = from_ms.map(|ms| ms.div_euclid(1000));
    let to_sec = to_ms.map(|ms| ms.div_euclid(1000));
    let mut available_nodes: BTreeSet<String> = BTreeSet::new();
    let mut available_services: BTreeSet<String> = BTreeSet::new();
    for s in &tel.summaries {
        available_nodes.insert(s.node_tag.clone());
        available_services.insert(s.service_tag.clone());
    }

    let agg = aggregate_summaries(
        &tel.summaries,
        node_f.as_deref(),
        svc_f.as_deref(),
        from_ms,
        to_ms,
    );

    let mut summaries: Vec<SummaryDto> = tel
        .summaries
        .iter()
        .filter(|s| {
            from_sec.map(|f| s.minute_epoch + 60 > f).unwrap_or(true)
                && to_sec.map(|t| s.minute_epoch <= t).unwrap_or(true)
                && node_f.as_deref().map(|n| s.node_tag == n).unwrap_or(true)
                && svc_f
                    .as_deref()
                    .map(|sv| s.service_tag == sv)
                    .unwrap_or(true)
        })
        .map(|s| SummaryDto {
            minute_epoch: s.minute_epoch,
            node_tag: s.node_tag.clone(),
            role: s.role.clone(),
            service_tag: s.service_tag.clone(),
            requests: s.requests,
            uv_estimate: s.uv_estimate().round(),
            errors: s.errors,
            rate_limited: s.rate_limited,
            challenges_issued: s.challenges_issued,
            challenges_passed: s.challenges_passed,
            blocked: s.blocked,
            evilpot_hits: s.evilpot_hits,
            autoban_hits: s.autoban_hits,
            bytes_in: s.bytes_in,
            bytes_out: s.bytes_out,
            cached_requests: s.cached_requests,
            cached_bytes_out: s.cached_bytes_out,
            p50_ms: s.p50_ms(),
            p95_ms: s.p95_ms(),
            p99_ms: s.p99_ms(),
            device_counts: s.device_counts.clone(),
            browser_counts: s.browser_counts.clone(),
            os_counts: s.os_counts.clone(),
            client_fp_verified: s.client_fp_verified,
        })
        .collect();
    summaries.sort_by(|a, b| {
        b.minute_epoch
            .cmp(&a.minute_epoch)
            .then_with(|| a.node_tag.cmp(&b.node_tag))
            .then_with(|| a.service_tag.cmp(&b.service_tag))
    });
    let buckets_total = summaries.len();
    let summaries_page: Vec<_> = summaries.into_iter().skip(b_off).take(b_lim).collect();

    Json(serde_json::json!({
        "last_pulled_at": tel.last_pulled_at,
        "traffic": agg.traffic_json,
        "timeseries": agg.timeseries,
        "service_breakdown": agg.service_breakdown,
        "node_breakdown": agg.node_breakdown,
        "device_counts": agg.device_counts,
        "browser_counts": agg.browser_counts,
        "os_counts": agg.os_counts,
        "client_fp_verified": agg.client_fp_verified,
        "available_nodes": available_nodes.into_iter().collect::<Vec<_>>(),
        "available_services": available_services.into_iter().collect::<Vec<_>>(),
        "summaries": summaries_page,
        "buckets_total": buckets_total,
        "bucket_offset": b_off,
        "bucket_limit": b_lim,
        "certificates": tel.certificates,
        "maintainers": tel.maintainers,
        "links": tel.links,
        "alerts": collect_normalized_cached_alerts(&tel.alerts, from_ms, to_ms),
    }))
    .into_response()
}

fn paginate_items<T>(
    mut items: Vec<T>,
    offset: Option<usize>,
    limit: Option<usize>,
) -> (Vec<T>, usize, usize, usize, bool) {
    let total_matched = items.len();
    let limit = limit.unwrap_or(50).clamp(1, 200);
    let offset = offset.unwrap_or(0);
    let end = offset.saturating_add(limit).min(total_matched);
    let has_more = end < total_matched;
    let page = if offset >= total_matched {
        Vec::new()
    } else {
        items.drain(offset..end).collect()
    };
    (page, total_matched, offset, limit, has_more)
}

#[derive(Deserialize, Default)]
struct FingerprintQuery {
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    fp: Option<String>,
    #[serde(default)]
    node: Option<String>,
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    country: Option<String>,
    /// `"all" | "js" | "ua" | "beacon" | "pow"`
    #[serde(default)]
    verified: Option<String>,
    /// `"all" | "bot" | "headless" | "suspicious" | "clean"`
    #[serde(default)]
    risk: Option<String>,
    #[serde(default)]
    from_ms: Option<i64>,
    #[serde(default)]
    to_ms: Option<i64>,
    #[serde(default)]
    window_secs: Option<i64>,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    limit: Option<usize>,
}

fn compute_query_ip_hmac(hmac_key: Option<&str>, raw: Option<&str>) -> Option<String> {
    let parsed = raw?.parse::<IpAddr>().ok()?;
    let key = hmac_key?;
    Some(hmac_ip(key, &canonical_ip(parsed).to_string()))
}

async fn is_store_raw_ip_enabled(state: &ApiState) -> bool {
    state
        .client
        .db()
        .get_topology_yaml()
        .await
        .ok()
        .and_then(|y| serde_yaml::from_str::<TopologySpec>(&y).ok())
        .and_then(|t| t.global_logger)
        .map(|l| l.store_raw_ip)
        .unwrap_or(false)
}

fn contains_ascii_icase(haystack: &str, needle_lower: &str) -> bool {
    if needle_lower.is_empty() {
        return true;
    }
    if needle_lower.is_ascii() {
        let nb = needle_lower.as_bytes();
        let hb = haystack.as_bytes();
        return hb.len() >= nb.len() && hb.windows(nb.len()).any(|w| w.eq_ignore_ascii_case(nb));
    }
    haystack
        .to_lowercase()
        .contains(&needle_lower.to_lowercase())
}

async fn list_fingerprints(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<FingerprintQuery>,
) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return *r;
    }
    let tel = state.client.cached_telemetry().await;
    let hmac_key = state.client.effective_logger_hmac_key().await;
    let store_raw_ip_enabled = is_store_raw_ip_enabled(&state).await;
    let (from_ms, to_ms) = resolve_time_window(q.from_ms, q.to_ms, q.window_secs);
    let offset = q.offset.unwrap_or(0);
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let q_ip_hmac = compute_query_ip_hmac(
        hmac_key.as_deref(),
        q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()),
    );
    let ip_hmac = compute_query_ip_hmac(
        hmac_key.as_deref(),
        q.ip.as_deref().map(str::trim).filter(|s| !s.is_empty()),
    );

    let maint_replies: Vec<serde_json::Value> = state
        .client
        .query_maintainers(MaintainerQuery::Fingerprints {
            from_ms,
            to_ms,
            node: q.node.clone(),
            service: q.service.clone(),
            country: q.country.clone(),
            verified: q.verified.clone(),
            risk: q.risk.clone(),
            ip: q.ip.clone(),
            ip_hmac: ip_hmac.clone(),
            fp: q.fp.clone(),
            q: q.q.clone(),
            q_ip_hmac: q_ip_hmac.clone(),
            offset: 0,
            limit: (offset + limit).min(200),
        })
        .await
        .into_iter()
        .filter_map(|(_, r)| r.ok())
        .collect();

    if maint_replies.len() == 1 {
        let mut val = maint_replies[0].clone();
        if let Some(obj) = val.as_object_mut() {
            obj.insert(
                "last_pulled_at".into(),
                serde_json::json!(tel.last_pulled_at),
            );
            obj.insert(
                "store_raw_ip_enabled".into(),
                serde_json::json!(store_raw_ip_enabled),
            );
        }
        return Json(val).into_response();
    } else if maint_replies.len() > 1 {
        let mut avail_nodes: BTreeSet<String> = BTreeSet::new();
        let mut avail_svcs: BTreeSet<String> = BTreeSet::new();
        let mut avail_countries: BTreeSet<String> = BTreeSet::new();
        let mut fp_map: HashMap<String, FingerprintObservation> = HashMap::new();
        for rep in &maint_replies {
            for (k, set) in [
                ("available_nodes", &mut avail_nodes),
                ("available_services", &mut avail_svcs),
                ("available_countries", &mut avail_countries),
            ] {
                if let Some(arr) = rep.get(k).and_then(|v| v.as_array()) {
                    for x in arr {
                        if let Some(s) = x.as_str() {
                            set.insert(s.to_string());
                        }
                    }
                }
            }
            if let Some(arr) = rep.get("items").and_then(|v| v.as_array()) {
                for v in arr {
                    if let Ok(obs) = serde_json::from_value::<FingerprintObservation>(v.clone()) {
                        fp_map
                            .entry(obs.id.clone())
                            .and_modify(|acc| acc.merge_from(&obs))
                            .or_insert(obs);
                    }
                }
            }
        }
        let mut all_obs: Vec<FingerprintObservation> = fp_map.into_values().collect();
        all_obs.sort_by(|a, b| b.last_seen_ts.cmp(&a.last_seen_ts));
        let unique_ips: HashSet<&str> = all_obs.iter().map(|o| o.ip_hmac.as_str()).collect();
        let unique_fps: HashSet<&str> = all_obs.iter().map(|o| o.fp_hash.as_str()).collect();
        let js_verified = all_obs.iter().filter(|o| o.js_verified).count();
        let beacon_count = all_obs.iter().filter(|o| o.fp_source == "beacon").count();
        let pow_count = all_obs.iter().filter(|o| o.fp_source == "pow").count();
        let bots = all_obs.iter().filter(|o| o.is_bot).count();
        let headless = all_obs.iter().filter(|o| o.is_headless).count();
        let webrtc_leaks = all_obs
            .iter()
            .filter(|o| {
                o.js_fp
                    .as_ref()
                    .map(|j| j.webrtc_ip_mismatch)
                    .unwrap_or(false)
            })
            .count();
        let webrtc_lan_leaks = all_obs
            .iter()
            .filter(|o| {
                o.js_fp
                    .as_ref()
                    .map(|j| !j.webrtc_local_ips.is_empty())
                    .unwrap_or(false)
            })
            .count();
        let unique_ips_len = unique_ips.len();
        let unique_fps_len = unique_fps.len();
        let (mut dev_c, mut br_c, mut os_c) = (BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
        for o in &all_obs {
            if !o.device_type.is_empty() {
                *dev_c.entry(o.device_type.clone()).or_insert(0u64) += 1;
            }
            if !o.browser_family.is_empty() {
                *br_c.entry(o.browser_family.clone()).or_insert(0u64) += 1;
            }
            if !o.os_family.is_empty() {
                *os_c.entry(o.os_family.clone()).or_insert(0u64) += 1;
            }
        }
        let (page, total_matched, off, lim, has_more) = paginate_items(all_obs, q.offset, q.limit);
        return Json(serde_json::json!({
            "last_pulled_at": tel.last_pulled_at,
            "total_matched": total_matched,
            "offset": off,
            "limit": lim,
            "has_more": has_more,
            "store_raw_ip_enabled": store_raw_ip_enabled,
            "summary": {
                "total_visitors": total_matched,
                "unique_ips": unique_ips_len,
                "unique_fps": unique_fps_len,
                "js_verified": js_verified,
                "beacon_count": beacon_count,
                "pow_count": pow_count,
                "bots": bots,
                "headless": headless,
                "webrtc_leaks": webrtc_leaks,
                "webrtc_lan_leaks": webrtc_lan_leaks,
            },
            "device_counts": dev_c,
            "browser_counts": br_c,
            "os_counts": os_c,
            "available_nodes": avail_nodes.into_iter().collect::<Vec<_>>(),
            "available_services": avail_svcs.into_iter().collect::<Vec<_>>(),
            "available_countries": avail_countries.into_iter().collect::<Vec<_>>(),
            "items": page,
        }))
        .into_response();
    }

    let cutoff = from_ms.map(|ms| ms.div_euclid(1000)).unwrap_or(0);
    let to_sec = to_ms.map(|ms| ms.div_euclid(1000));
    let node_f = q
        .node
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "all");
    let svc_f = q
        .service
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "all");
    let country_f = clean_filter_opt(q.country.as_deref()).map(|s| s.to_ascii_uppercase());
    let verified_f = q
        .verified
        .as_deref()
        .map(str::trim)
        .unwrap_or("all")
        .to_ascii_lowercase();
    let risk_f = q
        .risk
        .as_deref()
        .map(str::trim)
        .unwrap_or("all")
        .to_ascii_lowercase();
    let q_str =
        q.q.as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_ascii_lowercase());
    let ip_str =
        q.ip.as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_ascii_lowercase());
    let fp_str =
        q.fp.as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_ascii_lowercase());

    // Auto-compute cluster IP HMAC when the search query or IP filter is a literal IP address,
    // allowing exact IP lookup even when `store_raw_ip: false`!
    let q_ip_hmac = compute_query_ip_hmac(hmac_key.as_deref(), q_str.as_deref());
    let ip_filter_hmac = compute_query_ip_hmac(hmac_key.as_deref(), ip_str.as_deref());

    let mut available_nodes: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut available_services: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    let mut available_countries: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    for obs in &tel.fingerprints {
        available_nodes.insert(obs.node_tag.clone());
        available_services.insert(obs.service_tag.clone());
        if let Some(cc) = obs
            .geo_country
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| {
                obs.abuse_country
                    .as_deref()
                    .filter(|s| !s.trim().is_empty())
            })
        {
            available_countries.insert(cc.to_ascii_uppercase());
        }
    }

    let mut matched = Vec::new();
    let mut unique_ips = std::collections::HashSet::new();
    let mut unique_fps = std::collections::HashSet::new();
    let mut js_verified_count: usize = 0;
    let mut beacon_count: usize = 0;
    let mut pow_count: usize = 0;
    let mut bot_count: usize = 0;
    let mut headless_count: usize = 0;
    let mut webrtc_leak_count: usize = 0;
    let mut webrtc_lan_leak_count: usize = 0;
    let mut device_counts: std::collections::BTreeMap<String, u64> =
        std::collections::BTreeMap::new();
    let mut browser_counts: std::collections::BTreeMap<String, u64> =
        std::collections::BTreeMap::new();
    let mut os_counts: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();

    for obs in &tel.fingerprints {
        if obs.last_seen_ts < cutoff {
            continue;
        }
        if let Some(t) = to_sec {
            if obs.last_seen_ts > t {
                continue;
            }
        }
        if let Some(nf) = node_f {
            if obs.node_tag != nf {
                continue;
            }
        }
        if let Some(sf) = svc_f {
            if obs.service_tag != sf {
                continue;
            }
        }
        if let Some(ref cf) = country_f {
            let obs_cc = obs
                .geo_country
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| {
                    obs.abuse_country
                        .as_deref()
                        .filter(|s| !s.trim().is_empty())
                })
                .unwrap_or("");
            if !obs_cc.eq_ignore_ascii_case(cf) {
                continue;
            }
        }
        match verified_f.as_str() {
            "js" if !obs.js_verified => continue,
            "ua" if obs.js_verified => continue,
            "beacon" if obs.fp_source != "beacon" => continue,
            "pow" if obs.fp_source != "pow" => continue,
            _ => {}
        }
        match risk_f.as_str() {
            "bot" if !obs.is_bot => continue,
            "headless" if !obs.is_headless => continue,
            "webrtc_leak"
                if !obs
                    .js_fp
                    .as_ref()
                    .map(|j| j.webrtc_ip_mismatch || !j.webrtc_local_ips.is_empty())
                    .unwrap_or(false) =>
            {
                continue;
            }
            "suspicious" if obs.suspicion_score < 40 && !obs.is_bot && !obs.is_headless => continue,
            "clean" if obs.is_bot || obs.is_headless || obs.suspicion_score >= 40 => continue,
            _ => {}
        }
        if let Some(ref ipq) = ip_str {
            let raw_match = obs
                .client_ip
                .as_deref()
                .map(|v| contains_ascii_icase(v, ipq))
                .unwrap_or(false);
            let prefix_match = contains_ascii_icase(&obs.ip_prefix, ipq);
            let hmac_sub_match = contains_ascii_icase(&obs.ip_hmac, ipq);
            let hmac_exact_match = ip_filter_hmac
                .as_deref()
                .map(|h| obs.ip_hmac.eq_ignore_ascii_case(h))
                .unwrap_or(false);
            let webrtc_match = obs
                .js_fp
                .as_ref()
                .map(|j| {
                    j.webrtc_public_ips
                        .iter()
                        .chain(j.webrtc_local_ips.iter())
                        .any(|w| contains_ascii_icase(w, ipq))
                })
                .unwrap_or(false);
            if !(raw_match || prefix_match || hmac_sub_match || hmac_exact_match || webrtc_match) {
                continue;
            }
        }
        if let Some(ref fpq) = fp_str {
            let hash_match = contains_ascii_icase(&obs.fp_hash, fpq)
                || obs
                    .tls_ja3
                    .as_deref()
                    .map(|j| contains_ascii_icase(j, fpq))
                    .unwrap_or(false);
            let canvas_match = obs
                .js_fp
                .as_ref()
                .map(|j| {
                    contains_ascii_icase(&j.canvas_hash, fpq)
                        || contains_ascii_icase(&j.webgl, fpq)
                        || contains_ascii_icase(&j.webgl_vendor, fpq)
                        || contains_ascii_icase(&j.audio_hash, fpq)
                        || contains_ascii_icase(&j.fonts_hash, fpq)
                        || contains_ascii_icase(&j.platform, fpq)
                        || contains_ascii_icase(&j.screen, fpq)
                })
                .unwrap_or(false);
            if !(hash_match || canvas_match) {
                continue;
            }
        }
        if let Some(ref qs) = q_str {
            let hmac_exact = q_ip_hmac
                .as_deref()
                .map(|h| obs.ip_hmac.eq_ignore_ascii_case(h))
                .unwrap_or(false);
            let hit = hmac_exact
                || obs
                    .client_ip
                    .as_deref()
                    .map(|v| contains_ascii_icase(v, qs))
                    .unwrap_or(false)
                || contains_ascii_icase(&obs.ip_prefix, qs)
                || contains_ascii_icase(&obs.ip_hmac, qs)
                || contains_ascii_icase(&obs.fp_hash, qs)
                || obs
                    .tls_ja3
                    .as_deref()
                    .map(|v| contains_ascii_icase(v, qs))
                    .unwrap_or(false)
                || obs
                    .abuse_country
                    .as_deref()
                    .map(|v| contains_ascii_icase(v, qs))
                    .unwrap_or(false)
                || obs
                    .geo_country
                    .as_deref()
                    .map(|v| contains_ascii_icase(v, qs))
                    .unwrap_or(false)
                || obs
                    .geo_continent
                    .as_deref()
                    .map(|v| contains_ascii_icase(v, qs))
                    .unwrap_or(false)
                || obs
                    .abuse_isp
                    .as_deref()
                    .map(|v| contains_ascii_icase(v, qs))
                    .unwrap_or(false)
                || contains_ascii_icase(&obs.user_agent, qs)
                || contains_ascii_icase(&obs.host, qs)
                || contains_ascii_icase(&obs.service_tag, qs)
                || contains_ascii_icase(&obs.node_tag, qs)
                || contains_ascii_icase(&obs.browser_family, qs)
                || contains_ascii_icase(&obs.os_family, qs)
                || contains_ascii_icase(&obs.device_type, qs)
                || obs
                    .js_fp
                    .as_ref()
                    .map(|j| {
                        contains_ascii_icase(&j.webgl, qs)
                            || contains_ascii_icase(&j.webgl_vendor, qs)
                            || contains_ascii_icase(&j.canvas_hash, qs)
                            || contains_ascii_icase(&j.audio_hash, qs)
                            || contains_ascii_icase(&j.fonts_hash, qs)
                            || contains_ascii_icase(&j.ua_brands, qs)
                            || contains_ascii_icase(&j.platform, qs)
                            || contains_ascii_icase(&j.tz, qs)
                            || contains_ascii_icase(&j.screen, qs)
                            || contains_ascii_icase(&j.webrtc_status, qs)
                            || j.webrtc_public_ips
                                .iter()
                                .chain(j.webrtc_local_ips.iter())
                                .any(|w| contains_ascii_icase(w, qs))
                    })
                    .unwrap_or(false);
            if !hit {
                continue;
            }
        }

        unique_ips.insert(obs.ip_hmac.clone());
        unique_fps.insert(obs.fp_hash.clone());
        if obs.js_verified {
            js_verified_count += 1;
        }
        if obs.fp_source == "beacon" {
            beacon_count += 1;
        } else if obs.fp_source == "pow" {
            pow_count += 1;
        }
        if obs.is_bot {
            bot_count += 1;
        }
        if obs.is_headless {
            headless_count += 1;
        }
        if let Some(ref js) = obs.js_fp {
            if js.webrtc_ip_mismatch {
                webrtc_leak_count += 1;
            }
            if !js.webrtc_local_ips.is_empty() {
                webrtc_lan_leak_count += 1;
            }
        }
        if !obs.device_type.is_empty() {
            *device_counts.entry(obs.device_type.clone()).or_insert(0) += 1;
        }
        if !obs.browser_family.is_empty() {
            *browser_counts
                .entry(obs.browser_family.clone())
                .or_insert(0) += 1;
        }
        if !obs.os_family.is_empty() {
            *os_counts.entry(obs.os_family.clone()).or_insert(0) += 1;
        }
        matched.push(obs);
    }

    let (matched, total_matched, offset, limit, has_more) =
        paginate_items(matched, q.offset, q.limit);

    let store_raw_ip_enabled = is_store_raw_ip_enabled(&state).await;

    Json(serde_json::json!({
        "last_pulled_at": tel.last_pulled_at,
        "total_matched": total_matched,
        "offset": offset,
        "limit": limit,
        "has_more": has_more,
        "store_raw_ip_enabled": store_raw_ip_enabled,
        "summary": {
            "total_visitors": total_matched,
            "unique_ips": unique_ips.len(),
            "unique_fps": unique_fps.len(),
            "js_verified": js_verified_count,
            "beacon_count": beacon_count,
            "pow_count": pow_count,
            "bots": bot_count,
            "headless": headless_count,
            "webrtc_leaks": webrtc_leak_count,
            "webrtc_lan_leaks": webrtc_lan_leak_count,
        },
        "device_counts": device_counts,
        "browser_counts": browser_counts,
        "os_counts": os_counts,
        "available_nodes": available_nodes.into_iter().collect::<Vec<_>>(),
        "available_services": available_services.into_iter().collect::<Vec<_>>(),
        "available_countries": available_countries.into_iter().collect::<Vec<_>>(),
        "items": matched,
    }))
    .into_response()
}

#[derive(Deserialize, Default)]
struct LogQuery {
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    ray_id: Option<String>,
    #[serde(default)]
    node: Option<String>,
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    action: Option<String>,
    /// Exact status (`"404"`), status class (`"2xx"`, `"3xx"`, `"4xx"`, `"5xx"`), or `"all"`.
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    from_ms: Option<i64>,
    #[serde(default)]
    to_ms: Option<i64>,
    #[serde(default)]
    window_secs: Option<i64>,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    limit: Option<usize>,
}

fn clean_filter_opt(v: Option<&str>) -> Option<String> {
    v.map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("all"))
        .map(str::to_string)
}

fn log_protection_totals(
    tel: &crate::client::CachedTelemetry,
) -> exposure_core::telemetry::LogProtectionStats {
    let mut prot_totals = exposure_core::telemetry::LogProtectionStats::default();
    for st in tel.log_stats.values() {
        prot_totals.dropped_records = prot_totals
            .dropped_records
            .saturating_add(st.dropped_records);
        prot_totals.folded_records = prot_totals.folded_records.saturating_add(st.folded_records);
        prot_totals.warn_suppressed = prot_totals
            .warn_suppressed
            .saturating_add(st.warn_suppressed);
    }
    prot_totals
}

async fn list_logs(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<LogQuery>,
) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return *r;
    }
    let tel = state.client.cached_telemetry().await;
    let hmac_key = state.client.effective_logger_hmac_key().await;
    let store_raw_ip_enabled = is_store_raw_ip_enabled(&state).await;
    let (from_ms, to_ms) = resolve_time_window(q.from_ms, q.to_ms, q.window_secs);
    let offset = q.offset.unwrap_or(0);
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let q_ip_hmac = compute_query_ip_hmac(
        hmac_key.as_deref(),
        clean_filter_opt(q.q.as_deref()).as_deref(),
    );
    let ip_hmac = compute_query_ip_hmac(
        hmac_key.as_deref(),
        clean_filter_opt(q.ip.as_deref()).as_deref(),
    );

    let maint_replies: Vec<serde_json::Value> = state
        .client
        .query_maintainers(MaintainerQuery::AccessLogs {
            from_ms,
            to_ms,
            node: q.node.clone(),
            service: q.service.clone(),
            role: q.role.clone(),
            method: q.method.clone(),
            action: q.action.clone(),
            status: q.status.clone(),
            host: q.host.clone(),
            ip: q.ip.clone(),
            ip_hmac,
            country: q.country.clone(),
            ray_id: q.ray_id.clone(),
            q: q.q.clone(),
            q_ip_hmac,
            offset: if offset > 0 { 0 } else { offset },
            limit: (offset + limit).min(200),
        })
        .await
        .into_iter()
        .filter_map(|(_, r)| r.ok())
        .collect();

    if maint_replies.len() == 1 {
        let mut val = maint_replies[0].clone();
        // The Maintainer was asked for rows [0, offset+limit) so a single request can serve
        // the current page; slice locally here (it returns the requested window only).
        let total = val["total_matched"].as_u64().unwrap_or(0) as usize;
        if offset > 0 {
            if let Some(items) = val.get_mut("items").and_then(|v| v.as_array_mut()) {
                let sliced: Vec<_> = std::mem::take(items)
                    .into_iter()
                    .skip(offset)
                    .take(limit)
                    .collect();
                *items = sliced;
            }
        }
        if let Some(obj) = val.as_object_mut() {
            obj.insert("offset".into(), serde_json::json!(offset));
            obj.insert("limit".into(), serde_json::json!(limit));
            obj.insert(
                "has_more".into(),
                serde_json::json!(offset.saturating_add(limit) < total),
            );
            obj.insert(
                "last_pulled_at".into(),
                serde_json::json!(tel.last_pulled_at),
            );
            obj.insert(
                "store_raw_ip_enabled".into(),
                serde_json::json!(store_raw_ip_enabled),
            );
            obj.insert(
                "log_protection".into(),
                serde_json::json!(log_protection_totals(&tel)),
            );
            obj.insert("node_log_stats".into(), serde_json::json!(tel.log_stats));
        }
        return Json(val).into_response();
    } else if maint_replies.len() > 1 {
        let mut rec_map: HashMap<(String, String, i64, String), SessionSummary> = HashMap::new();
        let mut avail_nodes = BTreeSet::new();
        let mut avail_svcs = BTreeSet::new();
        let mut avail_hosts = BTreeSet::new();
        let mut avail_actions = BTreeSet::new();
        let mut avail_countries = BTreeSet::new();
        for rep in &maint_replies {
            for (k, set) in [
                ("available_nodes", &mut avail_nodes),
                ("available_services", &mut avail_svcs),
                ("available_hosts", &mut avail_hosts),
                ("available_actions", &mut avail_actions),
                ("available_countries", &mut avail_countries),
            ] {
                if let Some(arr) = rep.get(k).and_then(|v| v.as_array()) {
                    for x in arr {
                        if let Some(s) = x.as_str() {
                            set.insert(s.to_string());
                        }
                    }
                }
            }
            if let Some(arr) = rep.get("items").and_then(|v| v.as_array()) {
                for v in arr {
                    if let Ok(r) = serde_json::from_value::<SessionSummary>(v.clone()) {
                        let k = (
                            r.node_tag.clone(),
                            r.role.clone(),
                            r.timestamp_ms,
                            r.ray_id.clone().unwrap_or_else(|| {
                                format!(
                                    "{}:{}:{}",
                                    r.ip_hmac,
                                    r.path.as_deref().unwrap_or(""),
                                    r.status
                                )
                            }),
                        );
                        rec_map
                            .entry(k)
                            .and_modify(|cur| {
                                cur.repeat_count = cur.repeat_count.max(r.repeat_count)
                            })
                            .or_insert(r);
                    }
                }
            }
        }
        let mut merged_tel = (*tel).clone();
        merged_tel.recent_logs = rec_map.into_values().collect();
        merged_tel
            .recent_logs
            .sort_by(|a, b| b.timestamp_ms.cmp(&a.timestamp_ms));
        let mut out =
            build_logs_response_json(&merged_tel, hmac_key.as_deref(), store_raw_ip_enabled, &q);
        if let Some(obj) = out.as_object_mut() {
            obj.insert(
                "available_nodes".into(),
                serde_json::json!(avail_nodes.into_iter().collect::<Vec<_>>()),
            );
            obj.insert(
                "available_services".into(),
                serde_json::json!(avail_svcs.into_iter().collect::<Vec<_>>()),
            );
            obj.insert(
                "available_hosts".into(),
                serde_json::json!(avail_hosts.into_iter().collect::<Vec<_>>()),
            );
            obj.insert(
                "available_actions".into(),
                serde_json::json!(avail_actions.into_iter().collect::<Vec<_>>()),
            );
            obj.insert(
                "available_countries".into(),
                serde_json::json!(avail_countries.into_iter().collect::<Vec<_>>()),
            );
        }
        return Json(out).into_response();
    }

    Json(build_logs_response_json(
        &tel,
        hmac_key.as_deref(),
        store_raw_ip_enabled,
        &q,
    ))
    .into_response()
}

fn build_logs_response_json(
    tel: &crate::client::CachedTelemetry,
    hmac_key: Option<&str>,
    store_raw_ip_enabled: bool,
    q: &LogQuery,
) -> serde_json::Value {
    let (from_ms, to_ms) = resolve_time_window(q.from_ms, q.to_ms, q.window_secs);
    let cutoff_ms = from_ms.unwrap_or(0);
    let node_f = clean_filter_opt(q.node.as_deref());
    let svc_f = clean_filter_opt(q.service.as_deref());
    let role_f = clean_filter_opt(q.role.as_deref());
    let method_f = clean_filter_opt(q.method.as_deref()).map(|s| s.to_ascii_uppercase());
    let action_f = clean_filter_opt(q.action.as_deref()).map(|s| s.to_ascii_lowercase());
    let status_f = clean_filter_opt(q.status.as_deref()).map(|s| s.to_ascii_lowercase());
    let host_f = clean_filter_opt(q.host.as_deref()).map(|s| s.to_ascii_lowercase());
    let ip_str = clean_filter_opt(q.ip.as_deref()).map(|s| s.to_ascii_lowercase());
    let country_f = clean_filter_opt(q.country.as_deref()).map(|s| s.to_ascii_uppercase());
    let ray_id_f = clean_filter_opt(q.ray_id.as_deref()).map(|s| s.to_ascii_lowercase());
    let q_str = clean_filter_opt(q.q.as_deref()).map(|s| s.to_ascii_lowercase());

    let q_ip_hmac = compute_query_ip_hmac(hmac_key, q_str.as_deref());
    let ip_filter_hmac = compute_query_ip_hmac(hmac_key, ip_str.as_deref());

    let mut available_nodes: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut available_services: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    let mut available_hosts: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut available_actions: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    let mut available_countries: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    for rec in &tel.recent_logs {
        available_nodes.insert(rec.node_tag.clone());
        available_services.insert(rec.service_tag.clone());
        if let Some(ref h) = rec.host {
            if !h.is_empty() {
                available_hosts.insert(h.clone());
            }
        }
        if let Some(ref a) = rec.action {
            if !a.is_empty() {
                available_actions.insert(a.clone());
            }
        }
        if let Some(ref cc) = rec.client_country {
            if !cc.is_empty() {
                available_countries.insert(cc.to_ascii_uppercase());
            }
        }
    }

    // Raw (possibly multi-hop) rows that passed the filters; collapsed per Ray ID below.
    let mut matched: Vec<exposure_core::telemetry::SessionSummary> = Vec::new();
    let mut total_requests: u64 = 0;
    let mut blocked_requests: u64 = 0;
    let mut error_5xx_requests: u64 = 0;
    let mut cache_hits: u64 = 0;
    let mut folded_requests: u64 = 0;
    let mut unique_ips = std::collections::HashSet::new();
    let mut unique_paths = std::collections::HashSet::new();
    let mut action_counts: std::collections::BTreeMap<String, u64> =
        std::collections::BTreeMap::new();
    let mut status_class_counts: std::collections::BTreeMap<String, u64> =
        std::collections::BTreeMap::new();
    // (host, path) -> (total_hits, blocked_hits, error_5xx)
    let mut path_stats: std::collections::HashMap<(String, String), (u64, u64, u64)> =
        std::collections::HashMap::new();

    for rec in &tel.recent_logs {
        if rec.timestamp_ms < cutoff_ms {
            continue;
        }
        if let Some(t_ms) = to_ms {
            if rec.timestamp_ms > t_ms {
                continue;
            }
        }
        if let Some(ref nf) = node_f {
            if &rec.node_tag != nf {
                continue;
            }
        }
        if let Some(ref sf) = svc_f {
            if &rec.service_tag != sf {
                continue;
            }
        }
        if let Some(ref cf) = country_f {
            if !rec
                .client_country
                .as_deref()
                .map(|c| c.eq_ignore_ascii_case(cf))
                .unwrap_or(false)
            {
                continue;
            }
        }
        if let Some(ref rf) = role_f {
            if !rec.role.eq_ignore_ascii_case(rf) {
                continue;
            }
        }
        if let Some(ref mf) = method_f {
            if !rec
                .method
                .as_deref()
                .map(|m| m.eq_ignore_ascii_case(mf))
                .unwrap_or(false)
            {
                continue;
            }
        }
        let is_blocked_rec = is_mitigated_record(rec);
        if let Some(ref af) = action_f {
            if af == "blocked" {
                if !is_blocked_rec {
                    continue;
                }
            } else if af == "allow" {
                let allowed_rec = rec
                    .action
                    .as_deref()
                    .map(|a| a.eq_ignore_ascii_case("allow"))
                    .unwrap_or(!is_blocked_rec);
                if !allowed_rec {
                    continue;
                }
            } else if !rec
                .action
                .as_deref()
                .map(|a| a.eq_ignore_ascii_case(af))
                .unwrap_or(false)
            {
                continue;
            }
        }
        if let Some(ref sf) = status_f {
            let ok = match sf.as_str() {
                "2xx" => (200..300).contains(&rec.status),
                "3xx" => (300..400).contains(&rec.status),
                "4xx" => (400..500).contains(&rec.status),
                "5xx" => (500..600).contains(&rec.status),
                exact => exact
                    .parse::<u16>()
                    .map(|code| rec.status == code)
                    .unwrap_or(false),
            };
            if !ok {
                continue;
            }
        }
        if let Some(ref hf) = host_f {
            if !rec
                .host
                .as_deref()
                .map(|h| contains_ascii_icase(h, hf))
                .unwrap_or(false)
            {
                continue;
            }
        }
        if let Some(ref ipq) = ip_str {
            let raw_match = rec
                .raw_ip
                .as_deref()
                .map(|v| contains_ascii_icase(v, ipq))
                .unwrap_or(false);
            let hmac_sub = contains_ascii_icase(&rec.ip_hmac, ipq);
            let hmac_exact = ip_filter_hmac
                .as_deref()
                .map(|h| rec.ip_hmac.eq_ignore_ascii_case(h))
                .unwrap_or(false);
            if !(raw_match || hmac_sub || hmac_exact) {
                continue;
            }
        }
        if let Some(ref rf) = ray_id_f {
            if !rec
                .ray_id
                .as_deref()
                .map(|v| contains_ascii_icase(v, rf))
                .unwrap_or(false)
            {
                continue;
            }
        }
        if let Some(ref qs) = q_str {
            let hmac_exact = q_ip_hmac
                .as_deref()
                .map(|h| rec.ip_hmac.eq_ignore_ascii_case(h))
                .unwrap_or(false);
            let hit = hmac_exact
                || rec
                    .path
                    .as_deref()
                    .map(|v| contains_ascii_icase(v, qs))
                    .unwrap_or(false)
                || rec
                    .query
                    .as_deref()
                    .map(|v| contains_ascii_icase(v, qs))
                    .unwrap_or(false)
                || rec
                    .host
                    .as_deref()
                    .map(|v| contains_ascii_icase(v, qs))
                    .unwrap_or(false)
                || rec
                    .ray_id
                    .as_deref()
                    .map(|v| contains_ascii_icase(v, qs))
                    .unwrap_or(false)
                || rec
                    .user_agent
                    .as_deref()
                    .map(|v| contains_ascii_icase(v, qs))
                    .unwrap_or(false)
                || rec
                    .referer
                    .as_deref()
                    .map(|v| contains_ascii_icase(v, qs))
                    .unwrap_or(false)
                || rec
                    .error
                    .as_deref()
                    .map(|v| contains_ascii_icase(v, qs))
                    .unwrap_or(false)
                || rec
                    .waf_category
                    .as_deref()
                    .map(|v| contains_ascii_icase(v, qs))
                    .unwrap_or(false)
                || rec
                    .waf_rule_id
                    .map(|id| id.to_string().contains(qs))
                    .unwrap_or(false)
                || rec
                    .action
                    .as_deref()
                    .map(|v| contains_ascii_icase(v, qs))
                    .unwrap_or(false)
                || rec
                    .raw_ip
                    .as_deref()
                    .map(|v| contains_ascii_icase(v, qs))
                    .unwrap_or(false)
                || rec
                    .client_country
                    .as_deref()
                    .map(|v| contains_ascii_icase(v, qs))
                    .unwrap_or(false)
                || contains_ascii_icase(&rec.ip_hmac, qs)
                || contains_ascii_icase(&rec.service_tag, qs)
                || contains_ascii_icase(&rec.node_tag, qs);
            if !hit {
                continue;
            }
        }

        matched.push(rec.clone());
    }

    // Collapse the ingress + egress rows that share a Ray ID into one logical request.
    let mut groups: Vec<Vec<exposure_core::telemetry::SessionSummary>> = Vec::new();
    let mut group_index: HashMap<String, usize> = HashMap::new();
    for rec in matched {
        let key = rec
            .ray_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| format!("ray:{s}"))
            .unwrap_or_else(|| {
                format!(
                    "row:{}:{}:{}:{}",
                    rec.node_tag, rec.role, rec.timestamp_ms, rec.ip_hmac
                )
            });
        let slot = *group_index.entry(key).or_insert_with(|| {
            groups.push(Vec::new());
            groups.len() - 1
        });
        groups[slot].push(rec);
    }

    struct LogicalRequest {
        primary: exposure_core::telemetry::SessionSummary,
        hops: u32,
        entered_ms: i64,
        egress: Option<serde_json::Value>,
    }

    let mut logical: Vec<LogicalRequest> = Vec::with_capacity(groups.len());
    for mut hops in groups {
        // Primary = ingress hop (fallback: earliest hop) so status/protocol describe the
        // client-facing leg.
        hops.sort_by(|a, b| {
            let ai = u8::from(!a.role.eq_ignore_ascii_case("ingress"));
            let bi = u8::from(!b.role.eq_ignore_ascii_case("ingress"));
            ai.cmp(&bi)
                .then_with(|| a.timestamp_ms.cmp(&b.timestamp_ms))
        });
        let hop_count = hops.len() as u32;
        let entered_ms = hops
            .iter()
            .find(|r| r.role.eq_ignore_ascii_case("ingress"))
            .map(|r| r.timestamp_ms)
            .or_else(|| hops.iter().map(|r| r.timestamp_ms).min())
            .unwrap_or(0);
        let egress = hops
            .iter()
            .find(|r| r.role.eq_ignore_ascii_case("egress"))
            .map(|e| {
                serde_json::json!({
                    "node_tag": e.node_tag,
                    "status": e.status,
                    "latency_ms": e.latency_ms,
                    "protocol": e.protocol,
                })
            });
        let primary = hops.remove(0);
        logical.push(LogicalRequest {
            primary,
            hops: hop_count,
            entered_ms,
            egress,
        });
    }
    // Newest client entry first; requests that never reached egress still sort by ingress time.
    logical.sort_by(|a, b| b.entered_ms.cmp(&a.entered_ms));

    let mut items: Vec<serde_json::Value> = Vec::with_capacity(logical.len());
    for l in &logical {
        let rec = &l.primary;
        let is_blocked_rec = is_mitigated_record(rec);
        let weight = u64::from(rec.repeat_count.max(1));
        total_requests = total_requests.saturating_add(weight);
        folded_requests =
            folded_requests.saturating_add(u64::from(rec.repeat_count.saturating_sub(1)));
        if is_blocked_rec {
            blocked_requests = blocked_requests.saturating_add(weight);
        }
        // Evilpot decoy responses mimic origin failures; count them as blocked, not 5xx.
        if rec.status >= 500 && !is_evilpot_action(rec.action.as_deref()) {
            error_5xx_requests = error_5xx_requests.saturating_add(weight);
        }
        if is_cache_served_status(rec.cache_status.as_deref()) {
            cache_hits = cache_hits.saturating_add(weight);
        }
        unique_ips.insert(rec.ip_hmac.clone());
        let act_key = rec.action.clone().unwrap_or_else(|| "allow".into());
        *action_counts.entry(act_key).or_insert(0) += weight;
        let sc_key = format!("{}xx", rec.status / 100);
        *status_class_counts.entry(sc_key).or_insert(0) += weight;
        if let Some(ref p) = rec.path {
            if !p.is_empty() {
                let h = rec.host.clone().unwrap_or_default();
                unique_paths.insert((h.clone(), p.clone()));
                let entry = path_stats.entry((h, p.clone())).or_insert((0, 0, 0));
                entry.0 = entry.0.saturating_add(weight);
                if is_blocked_rec {
                    entry.1 = entry.1.saturating_add(weight);
                }
                if rec.status >= 500 && !is_evilpot_action(rec.action.as_deref()) {
                    entry.2 = entry.2.saturating_add(weight);
                }
            }
        }

        let mut val = serde_json::to_value(rec).unwrap_or_default();
        if let Some(o) = val.as_object_mut() {
            o.insert("hops".into(), serde_json::json!(l.hops));
            o.insert("ray_entered_ms".into(), serde_json::json!(l.entered_ms));
            if let Some(ref e) = l.egress {
                o.insert("egress".into(), e.clone());
            }
        }
        items.push(val);
    }

    let mut top_paths: Vec<_> = path_stats
        .into_iter()
        .map(|((host, path), (hits, blocked, errors_5xx))| {
            serde_json::json!({
                "host": host,
                "path": path,
                "hits": hits,
                "blocked": blocked,
                "errors_5xx": errors_5xx,
            })
        })
        .collect();
    top_paths.sort_by(|a, b| {
        b["hits"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&a["hits"].as_u64().unwrap_or(0))
    });
    top_paths.truncate(12);

    let mut prot_totals = exposure_core::telemetry::LogProtectionStats::default();
    for st in tel.log_stats.values() {
        prot_totals.dropped_records = prot_totals
            .dropped_records
            .saturating_add(st.dropped_records);
        prot_totals.folded_records = prot_totals.folded_records.saturating_add(st.folded_records);
        prot_totals.warn_suppressed = prot_totals
            .warn_suppressed
            .saturating_add(st.warn_suppressed);
    }

    let (items, total_matched, offset, limit, has_more) = paginate_items(items, q.offset, q.limit);

    serde_json::json!({
        "last_pulled_at": tel.last_pulled_at,
        "total_matched": total_matched,
        "offset": offset,
        "limit": limit,
        "has_more": has_more,
        "store_raw_ip_enabled": store_raw_ip_enabled,
        "summary": {
            "total_events": total_matched,
            "total_requests": total_requests,
            "blocked_requests": blocked_requests,
            "error_5xx_requests": error_5xx_requests,
            "cache_hits": cache_hits,
            "folded_requests": folded_requests,
            "unique_ips": unique_ips.len(),
            "unique_paths": unique_paths.len(),
        },
        "top_paths": top_paths,
        "action_counts": action_counts,
        "status_class_counts": status_class_counts,
        "log_protection": prot_totals,
        "node_log_stats": tel.log_stats,
        "available_nodes": available_nodes.into_iter().collect::<Vec<_>>(),
        "available_services": available_services.into_iter().collect::<Vec<_>>(),
        "available_hosts": available_hosts.into_iter().collect::<Vec<_>>(),
        "available_actions": available_actions.into_iter().collect::<Vec<_>>(),
        "available_countries": available_countries.into_iter().collect::<Vec<_>>(),
        "items": items,
    })
}

async fn pull_telemetry(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return *r;
    }
    if let Err(r) = require_active_role(&state) {
        return *r;
    }
    match state.client.pull_all_telemetry().await {
        Ok(n) => Json(serde_json::json!({ "pulled_sources": n })).into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
    }
}

#[derive(Deserialize, Default)]
struct AuditQuery {
    #[serde(default)]
    from_ms: Option<i64>,
    #[serde(default)]
    to_ms: Option<i64>,
    #[serde(default)]
    window_secs: Option<i64>,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    limit: Option<usize>,
}

async fn list_audit(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<AuditQuery>,
) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return *r;
    }
    let (from_ms, to_ms) = resolve_time_window(q.from_ms, q.to_ms, q.window_secs);
    let offset = q.offset.unwrap_or(0);
    let limit = q.limit.unwrap_or(100).clamp(1, 200);
    match state
        .client
        .db()
        .query_audit_logs(
            from_ms, to_ms, q.actor, q.action, q.target, q.q, offset, limit,
        )
        .await
    {
        Ok(mut res) => {
            if let Some(obj) = res.as_object_mut() {
                if let Some(items) = obj.get("items").cloned() {
                    obj.insert("logs".into(), items);
                }
            }
            Json(res).into_response()
        }
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn get_storage_retention(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return *r;
    }
    let control_retention = state
        .client
        .db()
        .get_control_retention_config()
        .await
        .unwrap_or_default();
    let control_stats = state.client.db().storage_stats().await.unwrap_or_default();
    let yaml = state
        .client
        .db()
        .get_topology_yaml()
        .await
        .unwrap_or_default();
    let topo: TopologySpec = serde_yaml::from_str(&yaml).unwrap_or_default();
    let maintainer_retention = topo
        .global_logger
        .as_ref()
        .map(|l| l.retention.clone())
        .unwrap_or_default();

    let live_stats: Vec<MaintainerStorageStats> = state
        .client
        .query_maintainers(MaintainerQuery::StorageStats)
        .await
        .into_iter()
        .filter_map(|(_, r)| r.ok())
        .filter_map(|v| serde_json::from_value::<MaintainerStorageStats>(v).ok())
        .collect();
    let maintainer_stats = if !live_stats.is_empty() {
        live_stats
    } else {
        let tel = state.client.cached_telemetry().await;
        tel.maintainers
            .iter()
            .filter_map(|m| m.storage_stats.clone())
            .collect()
    };

    Json(serde_json::json!({
        "control_retention": control_retention,
        "maintainer_retention": maintainer_retention,
        "control_stats": control_stats,
        "maintainer_stats": maintainer_stats,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct UpdateStorageRetentionReq {
    #[serde(default)]
    control_retention: Option<ControlRetentionConfig>,
    #[serde(default)]
    maintainer_retention: Option<MaintainerRetentionConfig>,
    #[serde(default = "default_true_retention_push")]
    push: bool,
}

fn default_true_retention_push() -> bool {
    true
}

async fn update_storage_retention(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<UpdateStorageRetentionReq>,
) -> Response {
    let actor = match verify_admin_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return *r,
    };
    if let Err(r) = require_active_role(&state) {
        return *r;
    }

    if let Some(ref c_ret) = req.control_retention {
        if let Err(e) = state.client.db().set_control_retention_config(c_ret).await {
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
        }
    }

    let mut release_info: Option<serde_json::Value> = None;
    let mut push_errors: Vec<String> = Vec::new();
    if let Some(ref m_ret) = req.maintainer_retention {
        let yaml = state
            .client
            .db()
            .get_topology_yaml()
            .await
            .unwrap_or_default();
        if !yaml.trim().is_empty() {
            let mut topo: TopologySpec = match serde_yaml::from_str(&yaml) {
                Ok(t) => t,
                Err(e) => {
                    return json_err(
                        StatusCode::BAD_REQUEST,
                        format!("parse saved topology: {e}"),
                    );
                }
            };
            let gl = topo.global_logger.get_or_insert_with(Default::default);
            gl.retention = m_ret.clone();
            for mc in topo.maintainer_templates.values_mut() {
                mc.logger.retention = m_ret.clone();
            }
            let new_yaml = match serde_yaml::to_string(&topo) {
                Ok(y) => y,
                Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            };
            let (compiled_topo, report, compiled) =
                match state.client.compile_yaml_and_provision(&new_yaml).await {
                    Ok(t) => t,
                    Err(e) => return json_err(StatusCode::BAD_REQUEST, e.to_string()),
                };
            if !report.valid {
                return json_err(
                    StatusCode::BAD_REQUEST,
                    format!("compiled topology invalid: {:?}", report.errors),
                );
            }
            if let Err(e) = state.client.db().set_topology_yaml(&new_yaml).await {
                return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
            }
            if req.push {
                match state
                    .client
                    .deploy_topology_release(
                        &actor,
                        &new_yaml,
                        &compiled_topo,
                        compiled,
                        "retention_update",
                        "Update storage & retention policy",
                    )
                    .await
                {
                    Ok(dep) => {
                        for item in &dep.results {
                            if !item["ok"].as_bool().unwrap_or(false) {
                                push_errors.push(format!(
                                    "{}: {}",
                                    item["node_tag"].as_str().unwrap_or("?"),
                                    item["error"].as_str().unwrap_or("failed")
                                ));
                            }
                        }
                        release_info = Some(serde_json::json!({
                            "release_seq": dep.release_seq,
                            "revision": dep.revision,
                            "results": dep.results,
                        }));
                    }
                    Err(e) => push_errors.push(e.to_string()),
                }
            }
        }
    }

    state
        .client
        .db()
        .append_audit(
            &actor,
            "storage.retention_update",
            "storage",
            push_errors.is_empty(),
            "updated retention policy",
        )
        .await;

    let control_retention = state
        .client
        .db()
        .get_control_retention_config()
        .await
        .unwrap_or_default();
    let yaml = state
        .client
        .db()
        .get_topology_yaml()
        .await
        .unwrap_or_default();
    let maintainer_retention = serde_yaml::from_str::<TopologySpec>(&yaml)
        .ok()
        .and_then(|t| t.global_logger.map(|l| l.retention))
        .unwrap_or_default();

    Json(serde_json::json!({
        "ok": push_errors.is_empty(),
        "control_retention": control_retention,
        "maintainer_retention": maintainer_retention,
        "release": release_info,
        "push_errors": push_errors,
    }))
    .into_response()
}

async fn run_storage_cleanup(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    let actor = match verify_admin_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return *r,
    };
    if let Err(r) = require_active_role(&state) {
        return *r;
    }
    let c_ret = state
        .client
        .db()
        .get_control_retention_config()
        .await
        .unwrap_or_default();
    let control_cleanup = match state.client.db().prune_old_records(&c_ret).await {
        Ok(rep) => rep,
        Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let maint_replies = state
        .client
        .query_maintainers(MaintainerQuery::RunCleanup)
        .await;
    let maintainer_cleanups: Vec<serde_json::Value> = maint_replies
        .into_iter()
        .map(|(tag, res)| match res {
            Ok(data) => serde_json::json!({
                "maintainer_tag": tag,
                "ok": true,
                "report": data,
            }),
            Err(e) => serde_json::json!({
                "maintainer_tag": tag,
                "ok": false,
                "error": e.to_string(),
            }),
        })
        .collect();

    state
        .client
        .db()
        .append_audit(
            &actor,
            "storage.cleanup",
            "storage",
            true,
            "triggered manual storage cleanup",
        )
        .await;

    Json(serde_json::json!({
        "ok": true,
        "control_cleanup": control_cleanup,
        "maintainer_cleanups": maintainer_cleanups,
    }))
    .into_response()
}

/// `GET /api/waf/rules`: return active OWASP CRS ruleset metadata, rules, and cluster CRS configuration.
async fn get_waf_rules(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return *r;
    }
    let crs_snap = state.client.active_crs_snapshot().await;
    let builtin_rules: Vec<exposure_core::crs::WafRuleDescriptor> = Vec::new();
    let crs_cfg = state
        .client
        .db()
        .get_topology_yaml()
        .await
        .ok()
        .and_then(|y| serde_yaml::from_str::<TopologySpec>(&y).ok())
        .map(|t| t.defaults.ingress.crs)
        .unwrap_or_default();

    Json(serde_json::json!({
        "crs_meta": {
            "version": crs_snap.version,
            "source_url": crs_snap.source_url,
            "updated_at": crs_snap.updated_at,
            "total_parsed": crs_snap.total_parsed,
            "skipped_pcre": crs_snap.skipped_pcre,
            "active_count": crs_snap.rules.len(),
        },
        "crs_config": crs_cfg,
        "builtin_rules": builtin_rules,
        "crs_rules": crs_snap.rules,
        "rules": crs_snap.rules,
    }))
    .into_response()
}

/// `POST /api/waf/crs/sync`: download & compile the latest OWASP CRS ruleset from `coreruleset.org`.
async fn sync_waf_crs(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    let actor = match verify_admin_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return *r,
    };
    if let Err(r) = require_active_role(&state) {
        return *r;
    }
    match state.client.sync_owasp_crs(&actor).await {
        Ok(snap) => Json(serde_json::json!({
            "ok": true,
            "version": snap.version,
            "source_url": snap.source_url,
            "updated_at": snap.updated_at,
            "rules_count": snap.rules.len(),
            "total_parsed": snap.total_parsed,
            "skipped_pcre": snap.skipped_pcre,
        }))
        .into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
    }
}

#[derive(Deserialize)]
struct TestAbuseIpDbReq {
    #[serde(default)]
    api_key: String,
    #[serde(default)]
    ip: String,
    #[serde(default)]
    max_age_days: Option<u16>,
}

/// `POST /api/security/abuseipdb/test`: verify an operator's AbuseIPDB v2 API key against a
/// hardcoded `https://api.abuseipdb.com/api/v2/check` endpoint (SSRF-safe).
async fn test_abuseipdb_key(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<TestAbuseIpDbReq>,
) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return *r;
    }
    let mut api_key = req.api_key.trim().to_string();
    if api_key.is_empty() || api_key == REDACTED_SECRET {
        api_key = state
            .client
            .db()
            .get_topology_yaml()
            .await
            .ok()
            .and_then(|y| serde_yaml::from_str::<TopologySpec>(&y).ok())
            .map(|t| t.defaults.ingress.abuseipdb.api_key.trim().to_string())
            .unwrap_or_default();
    }
    if api_key.is_empty() {
        return json_err(StatusCode::BAD_REQUEST, "AbuseIPDB API key is empty");
    }
    if api_key.len() > 256 || !api_key.bytes().all(|b| b.is_ascii_graphic()) {
        return json_err(StatusCode::BAD_REQUEST, "invalid AbuseIPDB API key format");
    }

    let target_ip_str = if req.ip.trim().is_empty() {
        "118.25.6.39".to_string()
    } else {
        req.ip.trim().to_string()
    };
    let parsed_ip: IpAddr = match target_ip_str.parse() {
        Ok(ip) => canonical_ip(ip),
        Err(_) => return json_err(StatusCode::BAD_REQUEST, "invalid test IP address"),
    };
    if !is_public_routable_ip(parsed_ip) {
        return json_err(
            StatusCode::BAD_REQUEST,
            "test IP must be a public routable IP address",
        );
    }

    let max_age = req.max_age_days.unwrap_or(90).clamp(1, 365);
    let resp = match state
        .http_client
        .get("https://api.abuseipdb.com/api/v2/check")
        .header("Key", &api_key)
        .header("Accept", "application/json")
        .query(&[
            ("ipAddress", parsed_ip.to_string()),
            ("maxAgeInDays", max_age.to_string()),
        ])
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return json_err(
                StatusCode::BAD_GATEWAY,
                format!("AbuseIPDB request failed: {e}"),
            );
        }
    };

    let status = resp.status();
    let body_text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        let msg = serde_json::from_str::<serde_json::Value>(&body_text)
            .ok()
            .and_then(|v| v["errors"][0]["detail"].as_str().map(str::to_string))
            .unwrap_or_else(|| format!("AbuseIPDB API returned HTTP {status}"));
        return json_err(StatusCode::BAD_GATEWAY, msg);
    }

    let parsed: serde_json::Value = match serde_json::from_str(&body_text) {
        Ok(v) => v,
        Err(e) => {
            return json_err(
                StatusCode::BAD_GATEWAY,
                format!("parse AbuseIPDB JSON failed: {e}"),
            );
        }
    };
    let d = &parsed["data"];
    Json(serde_json::json!({
        "ok": true,
        "ip_address": d["ipAddress"].as_str().unwrap_or(&parsed_ip.to_string()),
        "abuse_confidence_score": d["abuseConfidenceScore"].as_u64().unwrap_or(0),
        "country_code": d["countryCode"].as_str(),
        "isp": d["isp"].as_str(),
        "usage_type": d["usageType"].as_str(),
        "is_tor": d["isTor"].as_bool().unwrap_or(false),
        "total_reports": d["totalReports"].as_u64().unwrap_or(0),
    }))
    .into_response()
}

#[derive(Deserialize)]
struct UnbanTargetReq {
    #[serde(alias = "ban_kind")]
    kind: String,
    target: String,
    #[serde(default)]
    node_tag: Option<String>,
}

/// `POST /api/security/unban`: remove an active ban on one or all ingress nodes and update cached telemetry.
async fn unban_security_target(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<UnbanTargetReq>,
) -> Response {
    let actor = match verify_admin_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return *r,
    };
    if let Err(r) = require_active_role(&state) {
        return *r;
    }
    let kind = req.kind.trim();
    let target = req.target.trim();
    let node_tag = req
        .node_tag
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("all"));
    match state
        .client
        .unban_target(&actor, kind, target, node_tag)
        .await
    {
        Ok(val) => Json(val).into_response(),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

/// `GET /api/security/geoip/status`: return per-ingress GeoIP database status and defaults.
async fn get_geoip_status(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return *r;
    }
    let status = state.client.geoip_status().await;
    Json(status).into_response()
}

#[derive(Deserialize, Default)]
struct SyncGeoIpReq {
    #[serde(default)]
    node_tag: Option<String>,
    #[serde(default)]
    force: bool,
}

/// `POST /api/security/geoip/sync`: ask one or all ingress nodes to pull/refresh their local GeoIP DB.
async fn sync_geoip(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Option<Json<SyncGeoIpReq>>,
) -> Response {
    let actor = match verify_admin_auth(&state, &headers) {
        Ok(u) => u,
        Err(r) => return *r,
    };
    if let Err(r) = require_active_role(&state) {
        return *r;
    }
    let req = body.map(|Json(b)| b).unwrap_or_default();
    let node_tag = req
        .node_tag
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("all"));
    match state
        .client
        .sync_geoip_nodes(&actor, node_tag, req.force)
        .await
    {
        Ok(val) => Json(val).into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
    }
}

#[derive(Deserialize)]
struct LookupGeoIpQuery {
    ip: String,
    #[serde(default, alias = "node_tag")]
    node: Option<String>,
}

/// `GET /api/security/geoip/lookup`: query an ingress node's local GeoIP database for an IP.
async fn lookup_geoip(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<LookupGeoIpQuery>,
) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return *r;
    }
    let ip = q.ip.trim();
    if ip.is_empty() {
        return json_err(StatusCode::BAD_REQUEST, "ip query parameter is required");
    }
    let node = q
        .node
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("all"));
    match state.client.lookup_geoip_on_node(ip, node).await {
        Ok(val) => Json(val).into_response(),
        Err(e) => json_err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

/// Serve Control Web Panel static files (returning JSON 404 for unknown `/api/*` paths).
async fn serve_web_panel(headers: HeaderMap, uri: Uri) -> Response {
    let path = uri.path();
    if path.starts_with("/api/") || path == "/api" {
        return json_err(StatusCode::NOT_FOUND, "api endpoint not found");
    }
    let accept_enc = headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let asset = load_web_asset_negotiated(WebApp::Control, path, accept_enc)
        .or_else(|| load_web_asset_negotiated(WebApp::Control, "index.html", accept_enc));

    match asset {
        Some(asset) => {
            let mut resp_headers = HeaderMap::new();
            resp_headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(asset.mime));
            resp_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
            resp_headers.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
            if let Some(encoding) = asset.encoding {
                resp_headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static(encoding));
            }
            (StatusCode::OK, resp_headers, asset.bytes.into_owned()).into_response()
        }
        None => (StatusCode::NOT_FOUND, "Control web asset not found").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exposure_core::telemetry::SessionSummary;

    #[test]
    fn logs_fallback_collapses_ingress_and_egress_hops_by_ray_id() {
        let mk = |role: &'static str, ts: i64, ray: &str, status: u16, latency: f64| {
            let mut r = SessionSummary {
                timestamp_ms: ts,
                node_tag: if role == "ingress" { "ing-1" } else { "egr-1" }.into(),
                role: role.into(),
                service_tag: "svc".into(),
                status,
                latency_ms: latency,
                ip_hmac: "ip1".into(),
                ray_id: Some(ray.into()),
                action: Some("allow".into()),
                ..Default::default()
            };
            r.sanitize();
            r
        };
        let tel = crate::client::CachedTelemetry {
            recent_logs: vec![
                mk("ingress", 1_700_000_030_000, "r1", 200, 12.0),
                mk("egress", 1_700_000_029_000, "r1", 200, 6.0),
                // upstream failure: ingress only, must still be sortable by entry time
                mk("ingress", 1_700_000_020_000, "r2", 502, 40.0),
                // ingress record lost: egress only
                mk("egress", 1_700_000_010_000, "r3", 200, 5.0),
            ],
            ..Default::default()
        };

        let res = build_logs_response_json(&tel, None, false, &LogQuery::default());
        assert_eq!(res["total_matched"], 3, "one row per Ray ID, not per hop");
        assert_eq!(
            res["summary"]["total_requests"], 3,
            "ingress+egress hops must not be double counted"
        );
        let items = res["items"].as_array().unwrap();
        assert_eq!(items.len(), 3);
        let rays: Vec<&str> = items.iter().filter_map(|i| i["ray_id"].as_str()).collect();
        assert_eq!(rays, vec!["r1", "r2", "r3"]);

        assert_eq!(items[0]["hops"], 2);
        assert_eq!(items[0]["role"], "ingress");
        assert_eq!(items[0]["node_tag"], "ing-1");
        assert_eq!(items[0]["latency_ms"].as_f64().unwrap(), 12.0);
        assert_eq!(items[0]["egress"]["node_tag"], "egr-1");
        assert_eq!(items[0]["egress"]["latency_ms"].as_f64().unwrap(), 6.0);

        assert_eq!(items[1]["hops"], 1);
        assert!(items[1].get("egress").is_none());
    }

    #[test]
    fn logs_query_finds_full_ray_id_and_separates_waf_from_5xx() {
        let uuid_ray = "550e8400-e29b-41d4-a716-446655440000";
        let waf_ray = "a1b2c3d4e5f60708";
        let mut r_500 = SessionSummary {
            timestamp_ms: 1_700_000_000_000,
            node_tag: "n1".into(),
            role: "ingress".into(),
            service_tag: "svc".into(),
            status: 500,
            ip_hmac: "ip1".into(),
            ray_id: Some(uuid_ray.into()),
            error: Some("backend 500: db deadlock".into()),
            action: Some("upstream_error".into()),
            ..Default::default()
        };
        r_500.sanitize();
        let mut r_waf = SessionSummary {
            timestamp_ms: 1_700_000_001_000,
            node_tag: "n1".into(),
            role: "ingress".into(),
            service_tag: "svc".into(),
            status: 403,
            ip_hmac: "ip2".into(),
            ray_id: Some(waf_ray.into()),
            error: Some("waf:crs:942100:sql-injection:query".into()),
            action: Some("waf_block".into()),
            ..Default::default()
        };
        r_waf.sanitize();
        let mut r_origin_403 = SessionSummary {
            timestamp_ms: 1_700_000_002_000,
            node_tag: "n1".into(),
            role: "ingress".into(),
            service_tag: "svc".into(),
            status: 403,
            ip_hmac: "ip3".into(),
            ray_id: Some("origin403ray".into()),
            action: Some("allow".into()),
            ..Default::default()
        };
        r_origin_403.sanitize();
        let mut r_canary = SessionSummary {
            timestamp_ms: 1_700_000_003_000,
            node_tag: "n1".into(),
            role: "ingress".into(),
            service_tag: "svc".into(),
            status: 200,
            ip_hmac: "ip4".into(),
            ray_id: Some("canaryray1".into()),
            action: Some("evilpot_canary".into()),
            ..Default::default()
        };
        r_canary.sanitize();
        let mut r_monitor = SessionSummary {
            timestamp_ms: 1_700_000_004_000,
            node_tag: "n1".into(),
            role: "ingress".into(),
            service_tag: "svc".into(),
            status: 200,
            ip_hmac: "ip5".into(),
            ray_id: Some("monitorray1".into()),
            action: Some("waf_monitor".into()),
            waf_rule_id: Some(941100),
            waf_category: Some("xss".into()),
            ..Default::default()
        };
        r_monitor.sanitize();

        let tel = crate::client::CachedTelemetry {
            recent_logs: vec![r_500, r_waf, r_origin_403, r_canary, r_monitor],
            ..Default::default()
        };

        let all = build_logs_response_json(&tel, None, false, &LogQuery::default());
        assert_eq!(all["summary"]["blocked_requests"], 2); // waf_block + evilpot_canary (NOT origin 403)
        assert_eq!(all["summary"]["error_5xx_requests"], 1);

        let by_q = build_logs_response_json(
            &tel,
            None,
            false,
            &LogQuery {
                q: Some(uuid_ray.into()),
                ..Default::default()
            },
        );
        assert_eq!(by_q["total_matched"], 1);
        assert_eq!(by_q["items"][0]["ray_id"], uuid_ray);
        assert_eq!(by_q["items"][0]["error"], "backend 500: db deadlock");

        let by_rule = build_logs_response_json(
            &tel,
            None,
            false,
            &LogQuery {
                q: Some("941100".into()),
                ..Default::default()
            },
        );
        assert_eq!(by_rule["total_matched"], 1);
        assert_eq!(by_rule["items"][0]["action"], "waf_monitor");

        let by_ray = build_logs_response_json(
            &tel,
            None,
            false,
            &LogQuery {
                ray_id: Some(waf_ray.into()),
                ..Default::default()
            },
        );
        assert_eq!(by_ray["total_matched"], 1);
        assert_eq!(by_ray["items"][0]["action"], "waf_block");
        assert_eq!(by_ray["summary"]["error_5xx_requests"], 0);
        assert_eq!(by_ray["summary"]["blocked_requests"], 1);
    }
}
