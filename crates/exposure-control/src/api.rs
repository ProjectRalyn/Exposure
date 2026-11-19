use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use exposure_core::assets::{load_web_asset, WebApp};
use exposure_core::config::{ControlConfig, ControlRole, NodeConfig, TopologySpec};
use exposure_core::routing::LinkHealthState;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::client::ControlClient;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct ApiState {
    pub cfg: ControlConfig,
    pub client: Arc<ControlClient>,
}

pub fn build_router(state: ApiState) -> Router {
    Router::new()
        .route("/api/auth/login", post(login))
        .route("/api/overview", get(overview))
        .route("/api/nodes", get(list_nodes))
        .route("/api/nodes/{tag}/push", post(push_single_node))
        .route("/api/topology", get(get_topology))
        .route("/api/topology", put(save_topology))
        .route("/api/topology/validate", post(validate_topology))
        .route("/api/topology/preflight", post(preflight_topology))
        .route("/api/config-versions", get(list_config_versions))
        .route("/api/config-versions/{id}/rollback", post(rollback_version))
        .route("/api/passphrases", get(list_passphrases))
        .route("/api/passphrases", post(register_passphrase))
        .route("/api/passphrases/{tag}/revoke", post(revoke_passphrase))
        .route("/api/discovery/run", post(run_discovery))
        .route("/api/telemetry", get(get_telemetry))
        .route("/api/telemetry/pull", post(pull_telemetry))
        .route("/api/audit", get(list_audit))
        .fallback(serve_web_panel)
        .with_state(state)
}

fn sign_admin_token(secret: &str, username: &str) -> String {
    let exp = Utc::now().timestamp() + 86_400;
    let payload = format!("{username}:{exp}");
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(payload_b64.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{payload_b64}.{sig_b64}")
}

fn verify_admin_auth(state: &ApiState, headers: &HeaderMap) -> Result<String, Response> {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| json_err(StatusCode::UNAUTHORIZED, "missing bearer token"))?;

    let (payload_b64, sig_b64) = auth
        .split_once('.')
        .ok_or_else(|| json_err(StatusCode::UNAUTHORIZED, "malformed token"))?;

    let mut mac = HmacSha256::new_from_slice(state.cfg.admin.token_secret.as_bytes()).unwrap();
    mac.update(payload_b64.as_bytes());
    let expected = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    let ok: bool = expected.as_bytes().ct_eq(sig_b64.as_bytes()).into();
    if !ok {
        return Err(json_err(StatusCode::UNAUTHORIZED, "invalid token"));
    }

    let raw = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| json_err(StatusCode::UNAUTHORIZED, "invalid token payload"))?;
    let s = String::from_utf8(raw)
        .map_err(|_| json_err(StatusCode::UNAUTHORIZED, "invalid token utf8"))?;
    let (user, exp_s) = s
        .split_once(':')
        .ok_or_else(|| json_err(StatusCode::UNAUTHORIZED, "invalid token claims"))?;
    let exp: i64 = exp_s
        .parse()
        .map_err(|_| json_err(StatusCode::UNAUTHORIZED, "invalid token expiry"))?;
    if Utc::now().timestamp() > exp {
        return Err(json_err(StatusCode::UNAUTHORIZED, "token expired"));
    }
    Ok(user.to_string())
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

#[derive(Deserialize)]
struct LoginReq {
    username: String,
    password: String,
}

async fn login(State(state): State<ApiState>, Json(req): Json<LoginReq>) -> Response {
    let user_ok: bool = req
        .username
        .as_bytes()
        .ct_eq(state.cfg.admin.username.as_bytes())
        .into();
    let pass_ok: bool = req
        .password
        .as_bytes()
        .ct_eq(state.cfg.admin.password.as_bytes())
        .into();
    if !user_ok || !pass_ok {
        state
            .client
            .db()
            .append_audit(&req.username, "login", "control", false, "bad credentials")
            .await;
        return json_err(StatusCode::UNAUTHORIZED, "invalid username or password");
    }
    let token = sign_admin_token(&state.cfg.admin.token_secret, &req.username);
    state
        .client
        .db()
        .append_audit(&req.username, "login", "control", true, "admin login")
        .await;
    Json(serde_json::json!({ "token": token })).into_response()
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
        .map(|w| Utc::now().timestamp() - w)
        .unwrap_or(0);
    let nodes = state.client.db().list_nodes().await.unwrap_or_default();
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

    // Aggregate traffic KPIs & time-series across all pulled MinuteSummaries
    let mut total_requests: u64 = 0;
    let mut total_errors: u64 = 0;
    let mut total_rate_limited: u64 = 0;
    let mut total_challenges_issued: u64 = 0;
    let mut total_challenges_passed: u64 = 0;
    let mut total_bytes_in: u64 = 0;
    let mut total_bytes_out: u64 = 0;
    let mut merged_hll: Option<exposure_core::telemetry::HyperLogLog> = None;
    let mut merged_hist: Option<exposure_core::telemetry::LatencyHistogram> = None;

    // Per-minute, per-service, and per-node buckets for instant overview visualization
    let mut by_minute: std::collections::BTreeMap<i64, exposure_core::telemetry::MinuteSummary> =
        std::collections::BTreeMap::new();
    let mut by_service: std::collections::BTreeMap<String, exposure_core::telemetry::MinuteSummary> =
        std::collections::BTreeMap::new();
    let mut by_node: std::collections::BTreeMap<String, exposure_core::telemetry::MinuteSummary> =
        std::collections::BTreeMap::new();

    for s in tel.summaries.iter().filter(|s| s.minute_epoch >= cutoff) {
        total_requests += s.requests;
        total_errors += s.errors;
        total_rate_limited += s.rate_limited;
        total_challenges_issued += s.challenges_issued;
        total_challenges_passed += s.challenges_passed;
        total_bytes_in += s.bytes_in;
        total_bytes_out += s.bytes_out;

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
        serde_yaml::from_str(&yaml).unwrap_or_default()
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
    let nodes = state.client.db().list_nodes().await.unwrap_or_default();
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
    let (topo, report, compiled) = match state.client.compile_yaml(&yaml).await {
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
    let yaml = state.client.db().get_topology_yaml().await.unwrap_or_default();
    let (spec, report) = if yaml.trim().is_empty() {
        (TopologySpec::default(), None)
    } else {
        match state.client.compile_yaml(&yaml).await {
            Ok((topo, rep, _)) => (topo, Some(rep)),
            Err(_) => (serde_yaml::from_str(&yaml).unwrap_or_default(), None),
        }
    };
    let nodes = state.client.db().list_nodes().await.unwrap_or_default();
    let tel = state.client.cached_telemetry().await;
    Json(serde_json::json!({
        "yaml": yaml,
        "spec": spec,
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

fn resolve_topo_yaml(req: &TopoReq) -> std::result::Result<String, Response> {
    if let Some(spec) = &req.spec {
        return serde_yaml::to_string(spec)
            .map_err(|e| json_err(StatusCode::BAD_REQUEST, format!("serialize spec: {e}")));
    }
    if let Some(yaml) = &req.yaml {
        return Ok(yaml.clone());
    }
    Err(json_err(StatusCode::BAD_REQUEST, "either yaml or spec must be provided"))
}

async fn validate_topology(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<TopoReq>,
) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return r;
    }
    let yaml = match resolve_topo_yaml(&req) {
        Ok(y) => y,
        Err(r) => return r,
    };
    match state.client.compile_yaml(&yaml).await {
        Ok((topo, report, _)) => Json(serde_json::json!({
            "valid": report.valid,
            "errors": report.errors,
            "warnings": report.warnings,
            "paths": report.paths,
            "yaml": yaml,
            "spec": topo,
        }))
        .into_response(),
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
    let yaml = match resolve_topo_yaml(&req) {
        Ok(y) => y,
        Err(r) => return r,
    };
    let (topo, report, compiled) = match state.client.compile_yaml(&yaml).await {
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
    let yaml = match resolve_topo_yaml(&req) {
        Ok(y) => y,
        Err(r) => return r,
    };
    let (topo, report, compiled) = match state.client.compile_yaml(&yaml).await {
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

    Json(serde_json::json!({
        "valid": report.valid,
        "warnings": report.warnings,
        "paths": report.paths,
        "pushed_count": pushed_count,
        "push_errors": push_errors,
        "yaml": yaml,
        "spec": topo,
    }))
    .into_response()
}

async fn list_config_versions(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return r;
    }
    let versions = state
        .client
        .db()
        .list_config_versions(50)
        .await
        .unwrap_or_default();
    Json(serde_json::json!({ "versions": versions })).into_response()
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
    let items = state
        .client
        .db()
        .list_passphrases()
        .await
        .unwrap_or_default();
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
    if let Err(e) = state
        .client
        .db()
        .register_passphrase(
            &req.node_tag,
            &req.passphrase,
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

    // If listening mode with address provided, immediately trigger remote dial enrollment
    if req.mode == "listening" {
        if let Some(ref addr) = req.address {
            if let Err(e) = state
                .client
                .trigger_listening_enroll(&req.node_tag, addr, &req.passphrase, &req.via_hops)
                .await
            {
                return json_err(StatusCode::BAD_GATEWAY, format!("registered, but dial enroll failed: {e}"));
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
    let _ = state.client.db().revoke_passphrase(&tag).await;
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
    match state.client.pull_all_telemetry().await {
        Ok(n) => Json(serde_json::json!({ "pulled_sources": n })).into_response(),
        Err(e) => json_err(StatusCode::BAD_GATEWAY, e.to_string()),
    }
}

async fn list_audit(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if let Err(r) = verify_admin_auth(&state, &headers) {
        return r;
    }
    let logs = state
        .client
        .db()
        .list_audit_logs(100)
        .await
        .unwrap_or_default();
    Json(serde_json::json!({ "logs": logs })).into_response()
}

/// Serve Control Web Panel static files (vanilla HTML5/CSS/JS):
/// - Debug build: directly serves live source files from `web/control/`
/// - Release build: serves Vite-minified embedded assets
async fn serve_web_panel(uri: Uri) -> Response {
    let path = uri.path();
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
