use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use dashmap::DashMap;
use exposure_core::assets::{load_web_asset, WebApp};
use exposure_core::config::{
    ControlConfig, ControlRole, Dns01ProviderConfig, NodeConfig, TopologySpec,
};
use exposure_core::crypto::{
    ct_eq_hashed, generate_random_secret_hex, validate_identifier, verify_password,
};
use exposure_core::routing::{canonical_ip, LinkHealthState};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::client::ControlClient;

const SESSION_COOKIE_NAME: &str = "exposure_session";
const SESSION_TTL_SECS: i64 = 8 * 3600;
const MAX_SESSIONS: usize = 2048;
const MAX_YAML_BYTES: usize = 256 * 1024;
const REDACTED_SECRET: &str = "********";
const LOGIN_MAX_FAILURES: u32 = 5;
const LOGIN_LOCKOUT_SECS: u64 = 60;
const PANEL_CSP: &str =
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'";

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
}

impl ApiState {
    pub fn new(cfg: ControlConfig, client: Arc<ControlClient>) -> Self {
        Self {
            cfg,
            client,
            sessions: Arc::new(DashMap::new()),
            login_limiter: Arc::new(DashMap::new()),
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
        .route("/api/topology", get(get_topology).post(save_topology))
        .route("/api/topology/validate", post(validate_topology))
        .route("/api/topology/preflight", post(preflight_topology))
        .route("/api/config-versions", get(list_config_versions))
        .route("/api/config-versions/{id}/rollback", post(rollback_version))
        .route("/api/passphrases", get(list_passphrases).post(register_passphrase))
        .route("/api/passphrases/{tag}/revoke", post(revoke_passphrase))
        .route("/api/discovery/run", post(run_discovery))
        .route("/api/telemetry", get(get_telemetry))
        .route("/api/telemetry/pull", post(pull_telemetry))
        .route("/api/audit", get(list_audit))
        .fallback(serve_web_panel)
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

fn verify_admin_auth(state: &ApiState, headers: &HeaderMap) -> Result<String, Response> {
    let raw_token = extract_raw_session_token(headers)
        .ok_or_else(|| json_err(StatusCode::UNAUTHORIZED, "missing session authentication"))?;
    let key = hash_session_token(&state.cfg.admin.token_secret, &raw_token);
    let now = Utc::now().timestamp();
    let Some(entry) = state.sessions.get(&key) else {
        return Err(json_err(StatusCode::UNAUTHORIZED, "invalid or revoked session"));
    };
    if entry.expires_at < now || entry.username != state.cfg.admin.username {
        drop(entry);
        state.sessions.remove(&key);
        return Err(json_err(StatusCode::UNAUTHORIZED, "session expired"));
    }
    Ok(entry.username.clone())
}

fn require_active_role(state: &ApiState) -> Result<(), Response> {
    if state.cfg.role != ControlRole::Active {
        return Err(json_err(
            StatusCode::CONFLICT,
            "control instance is in standby mode",
        ));
    }
    Ok(())
}

fn json_err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

/// Redact all sensitive fields in `TopologySpec` before returning to API callers.
fn redact_topology_spec(mut spec: TopologySpec) -> TopologySpec {
    if let Some(ref mut gl) = spec.global_logger {
        if !gl.hmac_key.is_empty() {
            gl.hmac_key = REDACTED_SECRET.into();
        }
    }
    for node in spec.nodes.values_mut() {
        if !node.ingress.clearance_secret.is_empty() {
            node.ingress.clearance_secret = REDACTED_SECRET.into();
        }
        for g in node.ingress.guards.values_mut() {
            for h in &mut g.api_bypass_headers {
                if let Some((name, _)) = h.split_once(':') {
                    *h = format!("{}: {REDACTED_SECRET}", name.trim());
                }
            }
        }
    }
    for maint in spec.maintainer_templates.values_mut() {
        if maint.cert_signing_secret_key.is_some() {
            maint.cert_signing_secret_key = Some(REDACTED_SECRET.into());
        }
        if !maint.logger.hmac_key.is_empty() {
            maint.logger.hmac_key = REDACTED_SECRET.into();
        }
        for prov in maint.acme.providers.values_mut() {
            match prov {
                Dns01ProviderConfig::Cloudflare { api_token, .. } => {
                    if !api_token.is_empty() {
                        *api_token = REDACTED_SECRET.into();
                    }
                }
                Dns01ProviderConfig::Webhook { auth_header, .. } => {
                    if auth_header.is_some() {
                        *auth_header = Some(REDACTED_SECRET.into());
                    }
                }
                Dns01ProviderConfig::Exec { .. } => {}
            }
        }
    }
    spec
}

/// Restore redacted sentinel (`"********"`) secrets from previously stored topology on save.
fn restore_redacted_secrets(mut incoming: TopologySpec, existing: &TopologySpec) -> TopologySpec {
    if let (Some(ref mut new_gl), Some(ref old_gl)) =
        (&mut incoming.global_logger, &existing.global_logger)
    {
        if new_gl.hmac_key == REDACTED_SECRET {
            new_gl.hmac_key = old_gl.hmac_key.clone();
        }
    }
    for (tag, new_node) in &mut incoming.nodes {
        if let Some(old_node) = existing.nodes.get(tag) {
            if new_node.ingress.clearance_secret == REDACTED_SECRET {
                new_node.ingress.clearance_secret = old_node.ingress.clearance_secret.clone();
            }
            for (g_name, new_g) in &mut new_node.ingress.guards {
                if let Some(old_g) = old_node.ingress.guards.get(g_name) {
                    for h in &mut new_g.api_bypass_headers {
                        if let Some((name, val)) = h.split_once(':') {
                            if val.trim() == REDACTED_SECRET {
                                if let Some(old_h) = old_g.api_bypass_headers.iter().find(|oh| {
                                    oh.split_once(':')
                                        .map(|(on, _)| on.trim().eq_ignore_ascii_case(name.trim()))
                                        .unwrap_or(false)
                                }) {
                                    *h = old_h.clone();
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    for (tpl_name, new_m) in &mut incoming.maintainer_templates {
        if let Some(old_m) = existing.maintainer_templates.get(tpl_name) {
            if new_m.cert_signing_secret_key.as_deref() == Some(REDACTED_SECRET) {
                new_m.cert_signing_secret_key = old_m.cert_signing_secret_key.clone();
            }
            if new_m.logger.hmac_key == REDACTED_SECRET {
                new_m.logger.hmac_key = old_m.logger.hmac_key.clone();
            }
            for (p_name, new_p) in &mut new_m.acme.providers {
                if let Some(old_p) = old_m.acme.providers.get(p_name) {
                    match (new_p, old_p) {
                        (
                            Dns01ProviderConfig::Cloudflare { api_token, .. },
                            Dns01ProviderConfig::Cloudflare {
                                api_token: old_tok, ..
                            },
                        ) if api_token == REDACTED_SECRET => {
                            *api_token = old_tok.clone();
                        }
                        (
                            Dns01ProviderConfig::Webhook { auth_header, .. },
                            Dns01ProviderConfig::Webhook {
                                auth_header: old_auth,
                                ..
                            },
                        ) if auth_header.as_deref() == Some(REDACTED_SECRET) => {
                            *auth_header = old_auth.clone();
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    incoming
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
        for prov in m.acme.providers.values_mut() {
            match prov {
                Dns01ProviderConfig::Cloudflare { api_token, .. } => {
                    *api_token = REDACTED_SECRET.into();
                }
                Dns01ProviderConfig::Webhook { auth_header, .. } => {
                    if auth_header.is_some() {
                        *auth_header = Some(REDACTED_SECRET.into());
                    }
                }
                Dns01ProviderConfig::Exec { .. } => {}
            }
        }
    }
    serde_json::to_string(&cfg).unwrap_or_else(|_| "{}".into())
}

#[derive(Deserialize)]
struct LoginReq {
    username: String,
    password: String,
}

async fn login(State(state): State<ApiState>, Json(req): Json<LoginReq>) -> Response {
    // Global brute-force throttle for admin login
    let now = Instant::now();
    {
        if let Some(st) = state.login_limiter.get("global") {
            if let Some(until) = st.locked_until {
                if now < until {
                    return json_err(
                        StatusCode::TOO_MANY_REQUESTS,
                        "too many failed login attempts; please try again shortly",
                    );
                }
            }
        }
    }

    let user_ok = ct_eq_hashed(req.username.as_bytes(), state.cfg.admin.username.as_bytes());
    let pass_ok = verify_password(&req.password, &state.cfg.admin.password_hash);
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
        .append_audit(&state.cfg.admin.username, "login", "control", true, "admin login")
        .await;

    let secure_flag = if state.cfg.tls.is_some() { "; Secure" } else { "" };
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
    let secure_flag = if state.cfg.tls.is_some() { "; Secure" } else { "" };
    let clear_cookie = format!(
        "{SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict{secure_flag}; Max-Age=0"
    );
    let mut resp = Json(serde_json::json!({ "ok": true })).into_response();
    if let Ok(hv) = HeaderValue::from_str(&clear_cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

async fn auth_me(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    match verify_admin_auth(&state, &headers) {
        Ok(username) => Json(serde_json::json!({
            "authenticated": true,
            "username": username,
        }))
        .into_response(),
        Err(r) => r,
    }
}

#[derive(Deserialize, Default)]
struct OverviewQuery {
    #[serde(default)]
    window_secs: Option<i64>,
}

async fn overview(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(q): Query<OverviewQuery>,
) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return r;
    }
    let cutoff = q
        .window_secs
        .filter(|&w| w > 0)
        .map(|w| Utc::now().timestamp().saturating_sub(w))
        .unwrap_or(0);
    let nodes = match state.client.db().list_nodes().await {
        Ok(n) => n,
        Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
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

    let mut total_requests: u64 = 0;
    let mut total_errors: u64 = 0;
    let mut total_rate_limited: u64 = 0;
    let mut total_challenges_issued: u64 = 0;
    let mut total_challenges_passed: u64 = 0;
    let mut total_bytes_in: u64 = 0;
    let mut total_bytes_out: u64 = 0;
    let mut merged_hll: Option<exposure_core::telemetry::HyperLogLog> = None;
    let mut merged_hist: Option<exposure_core::telemetry::LatencyHistogram> = None;

    let mut by_minute: std::collections::BTreeMap<i64, exposure_core::telemetry::MinuteSummary> =
        std::collections::BTreeMap::new();
    let mut by_service: std::collections::BTreeMap<String, exposure_core::telemetry::MinuteSummary> =
        std::collections::BTreeMap::new();
    let mut by_node: std::collections::BTreeMap<String, exposure_core::telemetry::MinuteSummary> =
        std::collections::BTreeMap::new();

    for s in tel.summaries.iter().filter(|s| s.minute_epoch >= cutoff) {
        total_requests = total_requests.saturating_add(s.requests);
        total_errors = total_errors.saturating_add(s.errors);
        total_rate_limited = total_rate_limited.saturating_add(s.rate_limited);
        total_challenges_issued = total_challenges_issued.saturating_add(s.challenges_issued);
        total_challenges_passed = total_challenges_passed.saturating_add(s.challenges_passed);
        total_bytes_in = total_bytes_in.saturating_add(s.bytes_in);
        total_bytes_out = total_bytes_out.saturating_add(s.bytes_out);

        match &mut merged_hll {
            Some(h) => h.merge(&s.uv_hll),
            None => merged_hll = Some(s.uv_hll.clone()),
        }
        match &mut merged_hist {
            Some(h) => h.merge(&s.latency_hist),
            None => merged_hist = Some(s.latency_hist.clone()),
        }

        by_minute
            .entry(s.minute_epoch)
            .and_modify(|acc| acc.merge_from(s))
            .or_insert_with(|| s.clone());

        by_service
            .entry(s.service_tag.clone())
            .and_modify(|acc| acc.merge_from(s))
            .or_insert_with(|| s.clone());

        by_node
            .entry(s.node_tag.clone())
            .and_modify(|acc| acc.merge_from(s))
            .or_insert_with(|| s.clone());
    }

    let timeseries: Vec<serde_json::Value> = by_minute
        .into_iter()
        .map(|(minute_epoch, s)| {
            serde_json::json!({
                "minute_epoch": minute_epoch,
                "requests": s.requests,
                "errors": s.errors,
                "rate_limited": s.rate_limited,
                "challenges_issued": s.challenges_issued,
                "challenges_passed": s.challenges_passed,
                "bytes_in": s.bytes_in,
                "bytes_out": s.bytes_out,
                "uv_estimate": s.uv_estimate(),
                "p50_ms": s.p50_ms(),
                "p95_ms": s.p95_ms(),
                "p99_ms": s.p99_ms(),
            })
        })
        .collect();

    let mut service_breakdown: Vec<serde_json::Value> = by_service
        .into_iter()
        .map(|(service_tag, s)| {
            serde_json::json!({
                "service_tag": service_tag,
                "requests": s.requests,
                "errors": s.errors,
                "rate_limited": s.rate_limited,
                "uv_estimate": s.uv_estimate(),
                "p50_ms": s.p50_ms(),
                "p95_ms": s.p95_ms(),
                "p99_ms": s.p99_ms(),
            })
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
            serde_json::json!({
                "node_tag": node_tag,
                "requests": s.requests,
                "errors": s.errors,
                "rate_limited": s.rate_limited,
                "uv_estimate": s.uv_estimate(),
                "p50_ms": s.p50_ms(),
                "p95_ms": s.p95_ms(),
                "p99_ms": s.p99_ms(),
            })
        })
        .collect();
    node_breakdown.sort_by(|a, b| {
        b["requests"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&a["requests"].as_u64().unwrap_or(0))
    });

    let certs_valid = tel.certificates.iter().filter(|c| c.status == "valid").count();
    let certs_degraded = tel.certificates.len().saturating_sub(certs_valid);

    let yaml = state.client.db().get_topology_yaml().await.unwrap_or_default();
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
        "alerts": tel.alerts,
        "maintainers": tel.maintainers,
        "traffic": {
            "total_requests": total_requests,
            "total_errors": total_errors,
            "total_rate_limited": total_rate_limited,
            "total_challenges_issued": total_challenges_issued,
            "total_challenges_passed": total_challenges_passed,
            "total_bytes_in": total_bytes_in,
            "total_bytes_out": total_bytes_out,
            "uv_estimate": merged_hll.map(|h| h.estimate()).unwrap_or(0.0),
            "p50_ms": merged_hist.as_ref().map(|h| h.quantile(0.50)).unwrap_or(0.0),
            "p95_ms": merged_hist.as_ref().map(|h| h.quantile(0.95)).unwrap_or(0.0),
            "p99_ms": merged_hist.as_ref().map(|h| h.quantile(0.99)).unwrap_or(0.0),
        },
        "certificates_summary": {
            "total": tel.certificates.len(),
            "valid": certs_valid,
            "degraded": certs_degraded,
        },
        "timeseries": timeseries,
        "service_breakdown": service_breakdown,
        "node_breakdown": node_breakdown,
        "nodes": nodes,
        "links": tel.links,
        "spec": spec,
    }))
    .into_response()
}

async fn list_nodes(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return r;
    }
    let nodes = match state.client.db().list_nodes().await {
        Ok(n) => n,
        Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let tel = state.client.cached_telemetry().await;
    let boot = state.client.active_bootstrap_tag().await;
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
                "last_reload_status": n.last_reload_status,
                "online": n.online,
                "uptime_secs": uptime,
            })
        })
        .collect();
    Json(serde_json::json!({
        "bootstrap_node": boot,
        "last_pulled_at": tel.last_pulled_at,
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
        Err(r) => return r,
    };
    if let Err(r) = require_active_role(&state) {
        return r;
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
        return json_err(StatusCode::NOT_FOUND, format!("node '{tag}' not in topology"));
    };
    match state.client.push_node_config(&actor, &topo, &tag, cfg).await {
        Ok(seq) => Json(serde_json::json!({ "ok": true, "sequence": seq })).into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
    }
}

async fn get_topology(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return r;
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
}

fn reject_yaml_bomb(yaml: &str) -> Result<(), Response> {
    if yaml.len() > MAX_YAML_BYTES {
        return Err(json_err(
            StatusCode::PAYLOAD_TOO_LARGE,
            "topology YAML exceeds 256 KiB limit",
        ));
    }
    // Reject YAML anchors/aliases to prevent billion-laughs memory expansion in serde_yaml
    for line in yaml.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        if trimmed.contains(" *") || trimmed.contains(": *") || trimmed.contains(" &") || trimmed.contains(": &") {
            return Err(json_err(
                StatusCode::BAD_REQUEST,
                "YAML anchors and aliases are not permitted",
            ));
        }
    }
    Ok(())
}

async fn resolve_and_merge_topo_yaml(
    state: &ApiState,
    req: &TopoReq,
) -> Result<String, Response> {
    let existing_yaml = state.client.db().get_topology_yaml().await.unwrap_or_default();
    let existing_spec: TopologySpec = if existing_yaml.trim().is_empty() {
        TopologySpec::default()
    } else {
        serde_yaml::from_str(&existing_yaml).unwrap_or_default()
    };

    let parsed_spec: TopologySpec = if let Some(spec) = &req.spec {
        spec.clone()
    } else if let Some(yaml) = &req.yaml {
        reject_yaml_bomb(yaml)?;
        serde_yaml::from_str(yaml)
            .map_err(|e| json_err(StatusCode::BAD_REQUEST, format!("parse topology yaml: {e}")))?
    } else {
        return Err(json_err(
            StatusCode::BAD_REQUEST,
            "either yaml or spec must be provided",
        ));
    };

    let merged = restore_redacted_secrets(parsed_spec, &existing_spec);
    let out_yaml = serde_yaml::to_string(&merged)
        .map_err(|e| json_err(StatusCode::BAD_REQUEST, format!("serialize spec: {e}")))?;
    if out_yaml.len() > MAX_YAML_BYTES {
        return Err(json_err(
            StatusCode::PAYLOAD_TOO_LARGE,
            "serialized topology exceeds 256 KiB limit",
        ));
    }
    Ok(out_yaml)
}

async fn validate_topology(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<TopoReq>,
) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return r;
    }
    let yaml = match resolve_and_merge_topo_yaml(&state, &req).await {
        Ok(y) => y,
        Err(r) => return r,
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
        return r;
    }
    if let Err(r) = require_active_role(&state) {
        return r;
    }
    let yaml = match resolve_and_merge_topo_yaml(&state, &req).await {
        Ok(y) => y,
        Err(r) => return r,
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

    let mut reports = Vec::new();
    for (tag, cfg) in compiled {
        reports.push(state.client.preflight_node_config(&topo, &tag, cfg).await);
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
        Err(r) => return r,
    };
    if let Err(r) = require_active_role(&state) {
        return r;
    }
    let yaml = match resolve_and_merge_topo_yaml(&state, &req).await {
        Ok(y) => y,
        Err(r) => return r,
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
        .append_audit(&actor, "topology_save", "topology", true, "saved valid topology")
        .await;

    let mut pushed_count = 0usize;
    let mut push_errors = Vec::new();
    if req.push {
        for (tag, cfg) in compiled {
            match state.client.push_node_config(&actor, &topo, &tag, cfg).await {
                Ok(_) => pushed_count += 1,
                Err(e) => push_errors.push(format!("{tag}: {e}")),
            }
        }
    }

    let redacted = redact_topology_spec(topo);
    let redacted_yaml = serde_yaml::to_string(&redacted).unwrap_or_default();
    Json(serde_json::json!({
        "valid": report.valid,
        "warnings": report.warnings,
        "paths": report.paths,
        "pushed_count": pushed_count,
        "push_errors": push_errors,
        "yaml": redacted_yaml,
        "spec": redacted,
    }))
    .into_response()
}

async fn list_config_versions(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return r;
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
        Err(r) => return r,
    };
    if let Err(r) = require_active_role(&state) {
        return r;
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
    let yaml = state.client.db().get_topology_yaml().await.unwrap_or_default();
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
        return r;
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

fn validate_dial_address(addr: &str) -> Result<(), &'static str> {
    let trimmed = addr.trim();
    let Some((host, port_s)) = trimmed.rsplit_once(':') else {
        return Err("address must be host:port");
    };
    if host.is_empty() || !port_s.parse::<u16>().map(|p| p > 0).unwrap_or(false) {
        return Err("invalid host or port in address");
    }
    let clean = host
        .trim_matches(|c| c == '[' || c == ']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if clean == "localhost" || clean.ends_with(".localhost") {
        return Err("loopback target address is not allowed");
    }
    if let Ok(ip) = clean.parse::<IpAddr>() {
        let c = canonical_ip(ip);
        if c.is_loopback() || c.is_unspecified() {
            return Err("loopback or unspecified IP address is not allowed");
        }
        if let IpAddr::V4(v4) = c {
            if v4.is_link_local() {
                return Err("link-local metadata IP address is not allowed");
            }
        }
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
        Err(r) => return r,
    };
    if let Err(r) = require_active_role(&state) {
        return r;
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
                format!("node '{}' is already enrolled with a pinned public key", req.node_tag),
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
        if let Err(msg) = validate_dial_address(addr) {
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
        .append_audit(&actor, "register_passphrase", &req.node_tag, true, &req.mode)
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
        Err(r) => return r,
    };
    if let Err(r) = require_active_role(&state) {
        return r;
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
        Err(r) => return r,
    };
    if let Err(r) = require_active_role(&state) {
        return r;
    }
    match state.client.run_discovery(&actor).await {
        Ok(n) => Json(serde_json::json!({ "discovered_nodes": n })).into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
    }
}

#[derive(Serialize)]
struct SummaryDto {
    minute_epoch: i64,
    node_tag: String,
    service_tag: String,
    requests: u64,
    uv_estimate: f64,
    errors: u64,
    rate_limited: u64,
    challenges_issued: u64,
    challenges_passed: u64,
    bytes_in: u64,
    bytes_out: u64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    device_counts: std::collections::BTreeMap<String, u64>,
    browser_counts: std::collections::BTreeMap<String, u64>,
    os_counts: std::collections::BTreeMap<String, u64>,
    client_fp_verified: u64,
}

async fn get_telemetry(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return r;
    }
    let tel = state.client.cached_telemetry().await;
    let mut summaries: Vec<SummaryDto> = tel
        .summaries
        .iter()
        .map(|s| SummaryDto {
            minute_epoch: s.minute_epoch,
            node_tag: s.node_tag.clone(),
            service_tag: s.service_tag.clone(),
            requests: s.requests,
            uv_estimate: s.uv_estimate(),
            errors: s.errors,
            rate_limited: s.rate_limited,
            challenges_issued: s.challenges_issued,
            challenges_passed: s.challenges_passed,
            bytes_in: s.bytes_in,
            bytes_out: s.bytes_out,
            p50_ms: s.p50_ms(),
            p95_ms: s.p95_ms(),
            p99_ms: s.p99_ms(),
            device_counts: s.device_counts.clone(),
            browser_counts: s.browser_counts.clone(),
            os_counts: s.os_counts.clone(),
            client_fp_verified: s.client_fp_verified,
        })
        .collect();
    summaries.sort_by_key(|s| (s.minute_epoch, s.node_tag.clone(), s.service_tag.clone()));
    Json(serde_json::json!({
        "last_pulled_at": tel.last_pulled_at,
        "summaries": summaries,
        "certificates": tel.certificates,
        "maintainers": tel.maintainers,
        "links": tel.links,
        "alerts": tel.alerts,
    }))
    .into_response()
}

async fn pull_telemetry(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return r;
    }
    if let Err(r) = require_active_role(&state) {
        return r;
    }
    match state.client.pull_all_telemetry().await {
        Ok(n) => Json(serde_json::json!({ "pulled_sources": n })).into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
    }
}

async fn list_audit(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return r;
    }
    let logs = match state.client.db().list_audit_logs(100).await {
        Ok(l) => l,
        Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    Json(serde_json::json!({ "logs": logs })).into_response()
}

/// Serve Control Web Panel static files (returning JSON 404 for unknown `/api/*` paths).
async fn serve_web_panel(uri: Uri) -> Response {
    let path = uri.path();
    if path.starts_with("/api/") || path == "/api" {
        return json_err(StatusCode::NOT_FOUND, "api endpoint not found");
    }
    let asset = load_web_asset(WebApp::Control, path)
        .or_else(|| load_web_asset(WebApp::Control, "index.html"));

    match asset {
        Some((bytes, mime)) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, mime),
                (header::CACHE_CONTROL, "no-cache"),
            ],
            bytes,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "Control web asset not found").into_response(),
    }
}
