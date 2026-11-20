use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::Utc;
use dashmap::DashMap;
use exposure_core::assets::{load_web_asset, WebApp};
use exposure_core::config::{AntibotMode, GuardProfile, RateLimitBucket};
use exposure_core::crypto::{
    ct_eq_hashed, short_sha256_hex, sign_challenge_token, sign_clearance_cookie, sign_fp_cookie,
    sign_fp_token, verify_challenge_token, verify_clearance_cookie, verify_fp_cookie,
    verify_fp_token, verify_pow_solution, ClearanceClaims, FpCookieClaims,
};
use exposure_core::routing::{canonical_ip, ip_matches_cidrs, normalize_host};
use exposure_core::telemetry::ClientJsFingerprint;
use http::{header, HeaderMap, Method, StatusCode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::tls::ClientHelloSignal;

pub const CLEARANCE_COOKIE_NAME: &str = "exposure_clearance";
pub const FP_COOKIE_NAME: &str = "exposure_fp";
const MAX_RATE_LIMIT_BUCKETS: usize = 100_000;
const BUCKET_IDLE_TTL: Duration = Duration::from_secs(600);
const MAX_SPENT_CHALLENGES: usize = 50_000;
const MAX_SPENT_FP_TOKENS: usize = 50_000;
const MAX_FP_COOLDOWNS: usize = 50_000;
const CHALLENGE_TTL_SECS: i64 = 300;
const FP_TOKEN_TTL_SECS: i64 = 60;
const FP_INJECT_COOLDOWN: Duration = Duration::from_secs(15);
const CHALLENGE_CSP: &str =
    "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'self'";

#[derive(Debug, Clone)]
pub struct VerifiedFpSubmission {
    pub service_tag: Option<String>,
    pub fp_hash: String,
    pub fp_source: &'static str, // "pow" | "beacon"
    pub is_headless: bool,
    pub js_fp: ClientJsFingerprint,
}

struct TokenBucketState {
    tokens: f64,
    last_refill: Instant,
}

pub enum GuardDecision {
    Allow,
    RateLimited { retry_after_secs: u64 },
    Reject { status: StatusCode, reason: String },
    ChallengeRedirect { location: String },
}

pub struct GuardHttpResponse {
    pub status: StatusCode,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub extra_headers: Vec<(String, String)>,
}

/// Ingress Entry Guard Engine (DESIGN.md §11):
/// - CIDR allow/deny (canonicalized IPv4/IPv6)
/// - Bounded named token-bucket rate limiting (429 + Retry-After)
/// - TLS + HTTP browser fingerprint scoring
/// - Built-in `/cdn-cgi/` single-use host/IP-bound PoW challenge & signed clearance cookies
/// - Adaptive passive JS fingerprint beacon (`/cdn-cgi/fp.js` + `/cdn-cgi/fp-report`)
pub struct GuardEngine {
    buckets: DashMap<(String, String), TokenBucketState>,
    /// Single-use spent PoW challenge tokens mapped to their expiration timestamp.
    spent_challenges: DashMap<String, i64>,
    /// Single-use spent passive FP report tokens mapped to their expiration timestamp.
    spent_fp_tokens: DashMap<String, i64>,
    /// Dedicated per-IP rate limiter for `/cdn-cgi/fp-report` (prevents telemetry/CPU flooding).
    fp_report_limiter: DashMap<String, TokenBucketState>,
    /// Per-(ip_prefix, host) injection cooldown so parallel HTML fetches don't re-inject beacons.
    fp_inject_cooldown: DashMap<(String, String), Instant>,
}

impl Default for GuardEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl GuardEngine {
    pub fn new() -> Self {
        Self {
            buckets: DashMap::new(),
            spent_challenges: DashMap::new(),
            spent_fp_tokens: DashMap::new(),
            fp_report_limiter: DashMap::new(),
            fp_inject_cooldown: DashMap::new(),
        }
    }

    /// Evaluate ONLY CIDR + Rate Limit checks (used on `/cdn-cgi/*` before PoW handling).
    pub fn evaluate_access_and_rate_limit(
        &self,
        profile: &GuardProfile,
        bucket_defs: &BTreeMap<String, RateLimitBucket>,
        client_ip: IpAddr,
    ) -> GuardDecision {
        let client_ip = canonical_ip(client_ip);
        if !profile.deny_cidrs.is_empty() && ip_matches_cidrs(client_ip, &profile.deny_cidrs) {
            return GuardDecision::Reject {
                status: StatusCode::FORBIDDEN,
                reason: "source CIDR denied".into(),
            };
        }
        if !profile.allow_cidrs.is_empty() && !ip_matches_cidrs(client_ip, &profile.allow_cidrs) {
            return GuardDecision::Reject {
                status: StatusCode::FORBIDDEN,
                reason: "source CIDR not in allowlist".into(),
            };
        }
        if let Some(ref bucket_name) = profile.rate_limit_bucket {
            if let Some(def) = bucket_defs.get(bucket_name) {
                if let Err(retry_after) = self.consume_token(bucket_name, def, client_ip) {
                    return GuardDecision::RateLimited {
                        retry_after_secs: retry_after,
                    };
                }
            }
        }
        GuardDecision::Allow
    }

    #[allow(clippy::too_many_arguments)]
    pub fn evaluate(
        &self,
        profile: &GuardProfile,
        bucket_defs: &BTreeMap<String, RateLimitBucket>,
        clearance_secret: &str,
        client_ip: IpAddr,
        host: &str,
        path_and_query: &str,
        headers: &HeaderMap,
        tls_signal: Option<&ClientHelloSignal>,
    ) -> GuardDecision {
        let client_ip = canonical_ip(client_ip);

        // 1 & 2. Source CIDR restrictions + Named token bucket rate limiting
        match self.evaluate_access_and_rate_limit(profile, bucket_defs, client_ip) {
            GuardDecision::Allow => {}
            other => return other,
        }

        // 3. `antibot: off` completely skips challenge/fingerprint logic
        if profile.antibot == AntibotMode::Off
            && !profile.effective_block_bots()
            && !profile.effective_require_client_fp()
        {
            return GuardDecision::Allow;
        }

        // 4. Authenticated API bypass headers (`Header-Name: secret-value`, constant-time compare)
        for bypass_rule in &profile.api_bypass_headers {
            if let Some((h_name, expected_val)) = bypass_rule.split_once(':') {
                let h_name = h_name.trim();
                let expected_val = expected_val.trim();
                if !h_name.is_empty() && !expected_val.is_empty() {
                    for hv in headers.get_all(h_name) {
                        if let Ok(actual) = hv.to_str() {
                            if ct_eq_hashed(actual.trim().as_bytes(), expected_val.as_bytes()) {
                                return GuardDecision::Allow;
                            }
                        }
                    }
                }
            }
        }

        // 4b. Block known bot/scraper UAs if enabled
        let client_fp = classify_client(headers);
        if profile.effective_block_bots() && client_fp.is_bot {
            return GuardDecision::Reject {
                status: StatusCode::FORBIDDEN,
                reason: "bot User-Agent blocked".into(),
            };
        }

        // 4c. Block headless browsers previously caught by passive FP cookie if block_headless is enabled
        if profile.effective_block_headless() {
            if let Some(fp_claims) = self.valid_fp_cookie(clearance_secret, host, client_ip, headers) {
                if fp_claims.is_headless {
                    return GuardDecision::Reject {
                        status: StatusCode::FORBIDDEN,
                        reason: "headless browser fingerprint blocked".into(),
                    };
                }
            }
        }

        // 5. Check existing clearance cookie (and client FP binding if required)
        if let Some(claims) =
            self.valid_clearance_claims(profile, clearance_secret, host, client_ip, headers)
        {
            if !profile.effective_require_client_fp() || claims.fp_hash.is_some() {
                return GuardDecision::Allow;
            }
        }

        // 5b. `antibot: always` or `require_client_fp`: challenge every client without valid FP clearance
        if profile.antibot == AntibotMode::Always || profile.effective_require_client_fp() {
            let encoded = url_encode(path_and_query);
            return GuardDecision::ChallengeRedirect {
                location: format!("/cdn-cgi/?redirect={encoded}"),
            };
        }

        if profile.antibot == AntibotMode::Off {
            return GuardDecision::Allow;
        }

        // 6. Browser fingerprint suspicion scoring (0..=100)
        let score = compute_suspicion_score(headers, tls_signal);

        if profile.reject_threshold > 0 && score >= profile.reject_threshold {
            return GuardDecision::Reject {
                status: StatusCode::FORBIDDEN,
                reason: format!("bot fingerprint score {score}"),
            };
        }

        if score >= profile.challenge_threshold {
            match profile.antibot {
                AntibotMode::Silent => {
                    return GuardDecision::Reject {
                        status: StatusCode::SERVICE_UNAVAILABLE,
                        reason: format!("silent guard blocked (score {score})"),
                    };
                }
                AntibotMode::Challenge | AntibotMode::Always => {
                    let encoded = url_encode(path_and_query);
                    return GuardDecision::ChallengeRedirect {
                        location: format!("/cdn-cgi/?redirect={encoded}"),
                    };
                }
                AntibotMode::Off => {}
            }
        }

        GuardDecision::Allow
    }

    fn consume_token(
        &self,
        bucket_name: &str,
        def: &RateLimitBucket,
        client_ip: IpAddr,
    ) -> Result<(), u64> {
        let now = Instant::now();
        if self.buckets.len() >= MAX_RATE_LIMIT_BUCKETS {
            self.buckets
                .retain(|_, v| now.duration_since(v.last_refill) < BUCKET_IDLE_TTL);
            if self.buckets.len() >= MAX_RATE_LIMIT_BUCKETS {
                // Shed oldest/idle state rather than OOMing
                self.buckets.clear();
            }
        }

        let key = (
            bucket_name.to_string(),
            if def.effective_per_ip() {
                canonical_ip(client_ip).to_string()
            } else {
                "*".to_string()
            },
        );
        let mut entry = self.buckets.entry(key).or_insert_with(|| TokenBucketState {
            tokens: def.capacity,
            last_refill: now,
        });
        let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
        entry.tokens = (entry.tokens + elapsed * def.refill_per_sec).min(def.capacity);
        entry.last_refill = now;

        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            Ok(())
        } else {
            let needed = 1.0 - entry.tokens;
            let wait = if def.refill_per_sec > 0.0 {
                (needed / def.refill_per_sec).ceil().max(1.0) as u64
            } else {
                60
            };
            Err(wait)
        }
    }

    fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
        headers.get_all(header::COOKIE).iter().find_map(|hv| {
            let s = hv.to_str().ok()?;
            s.split(';').find_map(|pair| {
                let (k, v) = pair.trim().split_once('=')?;
                if k == name && !v.trim().is_empty() {
                    Some(v.trim().to_string())
                } else {
                    None
                }
            })
        })
    }

    pub fn valid_fp_cookie(
        &self,
        secret: &str,
        host: &str,
        client_ip: IpAddr,
        headers: &HeaderMap,
    ) -> Option<FpCookieClaims> {
        let token = Self::extract_cookie(headers, FP_COOKIE_NAME)?;
        let claims = verify_fp_cookie(secret, &token).ok()?;
        let now = Utc::now().timestamp();
        if claims.expires_at < now {
            return None;
        }
        if normalize_host(&claims.host) != normalize_host(host) {
            return None;
        }
        let ua = headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if claims.ua_hash != short_sha256_hex(ua) {
            return None;
        }
        if claims.ip_prefix != ip_prefix(client_ip) {
            return None;
        }
        Some(claims)
    }

    /// Return verified JS fingerprint hash & source (`"pow"` or `"beacon"`) if client carries either
    /// a valid PoW clearance cookie with `fp_hash` or a valid passive `exposure_fp` cookie.
    pub fn verified_fp_info(
        &self,
        profile: Option<&GuardProfile>,
        secret: &str,
        host: &str,
        client_ip: IpAddr,
        headers: &HeaderMap,
    ) -> Option<(String, &'static str, bool)> {
        let fallback = GuardProfile::default();
        let eff = profile.unwrap_or(&fallback);
        let canon = canonical_ip(client_ip);
        if let Some(claims) = self.valid_clearance_claims(eff, secret, host, canon, headers) {
            if let Some(fp_hash) = claims.fp_hash {
                return Some((fp_hash, "pow", false));
            }
        }
        if let Some(fp_claims) = self.valid_fp_cookie(secret, host, canon, headers) {
            return Some((fp_claims.fp_hash, "beacon", fp_claims.is_headless));
        }
        None
    }

    pub fn has_valid_fp_clearance(
        &self,
        profile: Option<&GuardProfile>,
        secret: &str,
        host: &str,
        client_ip: IpAddr,
        headers: &HeaderMap,
    ) -> bool {
        self.verified_fp_info(profile, secret, host, client_ip, headers)
            .is_some()
    }

    /// Adaptive passive JS fingerprint injection policy:
    /// Injects ONLY on `GET` HTML document navigations from browsers without a valid JS FP cookie,
    /// subject to a per-(ip_prefix, host) 15s cooldown to avoid flooding parallel tabs or cookie-less clients.
    #[allow(clippy::too_many_arguments)]
    pub fn should_inject_fp_beacon(
        &self,
        method: &Method,
        is_upgrade: bool,
        client_ip: IpAddr,
        host: &str,
        headers: &HeaderMap,
        secret: &str,
        profile: Option<&GuardProfile>,
        node_beacon_default: bool,
        rule_beacon_override: Option<bool>,
    ) -> bool {
        let enabled = rule_beacon_override
            .or_else(|| profile.and_then(|p| p.js_fp_beacon))
            .unwrap_or(node_beacon_default);
        if !enabled || method != Method::GET || is_upgrade {
            return false;
        }
        // Only target browser HTML document navigations (never API JSON/XHR/subresources)
        let accept = headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !accept.to_ascii_lowercase().contains("text/html") {
            return false;
        }
        if let Some(dest) = headers.get("sec-fetch-dest").and_then(|v| v.to_str().ok()) {
            if !dest.eq_ignore_ascii_case("document") {
                return false;
            }
        }
        // Already have a valid unexpired JS fingerprint (via PoW clearance or passive FP cookie)? Skip!
        if self.has_valid_fp_clearance(profile, secret, host, client_ip, headers) {
            return false;
        }
        // Enforce short cooldown per (ip_prefix, host) to balance report frequency vs effectiveness
        let now = Instant::now();
        if self.fp_inject_cooldown.len() >= MAX_FP_COOLDOWNS {
            self.fp_inject_cooldown
                .retain(|_, ts| now.duration_since(*ts) < FP_INJECT_COOLDOWN);
            if self.fp_inject_cooldown.len() >= MAX_FP_COOLDOWNS {
                self.fp_inject_cooldown.clear();
            }
        }
        let cd_key = (ip_prefix(client_ip), normalize_host(host));
        if let Some(last) = self.fp_inject_cooldown.get(&cd_key) {
            if now.duration_since(*last) < FP_INJECT_COOLDOWN {
                return false;
            }
        }
        self.fp_inject_cooldown.insert(cd_key, now);
        true
    }

    /// Mint a short-lived (60s), single-use, host+ip_prefix+UA+service-bound token for `/cdn-cgi/fp.js`.
    pub fn mint_fp_token(
        &self,
        secret: &str,
        host: &str,
        client_ip: IpAddr,
        headers: &HeaderMap,
        service_tag: &str,
    ) -> String {
        let host_clean = normalize_host(host);
        let ip_key = ip_prefix(client_ip);
        let ua = headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let ua_hash = short_sha256_hex(ua);
        let token_id = Uuid::new_v4().simple().to_string();
        let expires_at = Utc::now().timestamp() + FP_TOKEN_TTL_SECS;
        let svc_b64 = URL_SAFE_NO_PAD.encode(service_tag.as_bytes());
        let sig = sign_fp_token(
            secret,
            &host_clean,
            &ip_key,
            &ua_hash,
            service_tag,
            &token_id,
            expires_at,
        );
        format!("{token_id}.{expires_at}.{svc_b64}.{sig}")
    }

    fn consume_fp_report_rate_limit(&self, client_ip: IpAddr) -> bool {
        let now = Instant::now();
        if self.fp_report_limiter.len() >= MAX_SPENT_FP_TOKENS {
            self.fp_report_limiter
                .retain(|_, v| now.duration_since(v.last_refill) < BUCKET_IDLE_TTL);
            if self.fp_report_limiter.len() >= MAX_SPENT_FP_TOKENS {
                self.fp_report_limiter.clear();
            }
        }
        let key = canonical_ip(client_ip).to_string();
        let mut entry = self
            .fp_report_limiter
            .entry(key)
            .or_insert_with(|| TokenBucketState {
                tokens: 12.0,
                last_refill: now,
            });
        let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
        entry.tokens = (entry.tokens + elapsed * 0.2).min(12.0); // 12 burst, 12/min sustained
        entry.last_refill = now;
        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn consume_fp_token(&self, token_id: &str, expires_at: i64, now: i64) -> bool {
        if self.spent_fp_tokens.len() >= MAX_SPENT_FP_TOKENS {
            self.spent_fp_tokens.retain(|_, exp| *exp >= now);
            if self.spent_fp_tokens.len() >= MAX_SPENT_FP_TOKENS {
                self.spent_fp_tokens.clear();
            }
        }
        let mut inserted = false;
        self.spent_fp_tokens
            .entry(token_id.to_string())
            .or_insert_with(|| {
                inserted = true;
                expires_at
            });
        inserted
    }

    fn valid_clearance_claims(
        &self,
        profile: &GuardProfile,
        secret: &str,
        host: &str,
        client_ip: IpAddr,
        headers: &HeaderMap,
    ) -> Option<ClearanceClaims> {
        let token = Self::extract_cookie(headers, CLEARANCE_COOKIE_NAME)?;
        let claims = verify_clearance_cookie(secret, &token).ok()?;
        let now = Utc::now().timestamp();
        if claims.expires_at < now {
            return None;
        }
        let host_clean = normalize_host(host);
        if normalize_host(&claims.host) != host_clean {
            return None;
        }
        if profile.effective_bind_ua() {
            let ua = headers
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if claims.ua_hash.as_deref() != Some(&short_sha256_hex(ua)) {
                return None;
            }
        }
        if profile.effective_bind_ip_prefix() {
            if claims.ip_prefix.as_deref() != Some(&ip_prefix(client_ip)) {
                return None;
            }
        }
        Some(claims)
    }

    fn consume_challenge_token(&self, token: &str, expires_at: i64, now: i64) -> bool {
        if self.spent_challenges.len() >= MAX_SPENT_CHALLENGES {
            self.spent_challenges.retain(|_, exp| *exp >= now);
            if self.spent_challenges.len() >= MAX_SPENT_CHALLENGES {
                self.spent_challenges.clear();
            }
        }
        let mut inserted = false;
        self.spent_challenges
            .entry(token.to_string())
            .or_insert_with(|| {
                inserted = true;
                expires_at
            });
        inserted
    }

    /// Handle built-in `/cdn-cgi/*` challenge, passive FP beacon report, and static asset endpoints.
    #[allow(clippy::too_many_arguments)]
    pub fn handle_cdn_cgi(
        &self,
        method: &Method,
        path: &str,
        body: &[u8],
        headers: &HeaderMap,
        host: &str,
        client_ip: IpAddr,
        is_tls: bool,
        profile: Option<&GuardProfile>,
        clearance_secret: &str,
        fp_ttl_secs: u64,
    ) -> (GuardHttpResponse, Option<VerifiedFpSubmission>) {
        let client_ip = canonical_ip(client_ip);
        let host_clean = normalize_host(host);
        let ip_key = ip_prefix(client_ip);
        let sub = path.strip_prefix("/cdn-cgi").unwrap_or("");

        let sec_headers = || -> Vec<(String, String)> {
            vec![
                ("X-Content-Type-Options".into(), "nosniff".into()),
                ("X-Frame-Options".into(), "SAMEORIGIN".into()),
                ("Content-Security-Policy".into(), CHALLENGE_CSP.into()),
            ]
        };

        if method == Method::GET && sub == "/challenge" {
            let difficulty = profile.map(|p| p.pow_difficulty).unwrap_or(16).clamp(1, 28);
            let token = Uuid::new_v4().to_string();
            let expires_at = Utc::now().timestamp() + CHALLENGE_TTL_SECS;
            let signature = sign_challenge_token(
                clearance_secret,
                &host_clean,
                &ip_key,
                &token,
                expires_at,
                difficulty,
            );
            let payload = serde_json::json!({
                "token": token,
                "difficulty": difficulty,
                "expires_at": expires_at,
                "signature": signature,
            });
            let mut extra = sec_headers();
            extra.push(("Cache-Control".into(), "no-store".into()));
            return (
                GuardHttpResponse {
                    status: StatusCode::OK,
                    content_type: "application/json; charset=utf-8",
                    body: serde_json::to_vec(&payload).unwrap_or_default(),
                    extra_headers: extra,
                },
                None,
            );
        }

        // Passive JS fingerprint beacon ingestion endpoint (authenticated via short-lived single-use HMAC nonce)
        if method == Method::POST && sub == "/fp-report" {
            if !self.consume_fp_report_rate_limit(client_ip) {
                return (
                    GuardHttpResponse {
                        status: StatusCode::TOO_MANY_REQUESTS,
                        content_type: "text/plain; charset=utf-8",
                        body: b"fp report rate limited".to_vec(),
                        extra_headers: sec_headers(),
                    },
                    None,
                );
            }
            if body.len() > 4096 {
                return (
                    GuardHttpResponse {
                        status: StatusCode::PAYLOAD_TOO_LARGE,
                        content_type: "text/plain; charset=utf-8",
                        body: b"fp report payload too large".to_vec(),
                        extra_headers: sec_headers(),
                    },
                    None,
                );
            }
            if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
                if !site.eq_ignore_ascii_case("same-origin") {
                    return (
                        GuardHttpResponse {
                            status: StatusCode::FORBIDDEN,
                            content_type: "text/plain; charset=utf-8",
                            body: b"cross-site fp report rejected".to_vec(),
                            extra_headers: sec_headers(),
                        },
                        None,
                    );
                }
            }
            if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
                let origin_host = origin
                    .parse::<http::Uri>()
                    .ok()
                    .and_then(|u| u.authority().map(|a| normalize_host(a.as_str())));
                if origin_host.as_deref() != Some(host_clean.as_str()) {
                    return (
                        GuardHttpResponse {
                            status: StatusCode::FORBIDDEN,
                            content_type: "text/plain; charset=utf-8",
                            body: b"origin mismatch".to_vec(),
                            extra_headers: sec_headers(),
                        },
                        None,
                    );
                }
            }
            let ct = headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !ct.to_ascii_lowercase().starts_with("application/json") {
                return (
                    GuardHttpResponse {
                        status: StatusCode::UNSUPPORTED_MEDIA_TYPE,
                        content_type: "text/plain; charset=utf-8",
                        body: b"expected application/json".to_vec(),
                        extra_headers: sec_headers(),
                    },
                    None,
                );
            }

            #[derive(Deserialize)]
            struct FpReportReq {
                token: String,
                fp: ClientJsFingerprint,
            }

            let mut req: FpReportReq = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(_) => {
                    return (
                        GuardHttpResponse {
                            status: StatusCode::BAD_REQUEST,
                            content_type: "text/plain; charset=utf-8",
                            body: b"invalid fp report payload".to_vec(),
                            extra_headers: sec_headers(),
                        },
                        None,
                    );
                }
            };

            let parts: Vec<&str> = req.token.split('.').collect();
            if parts.len() != 4 {
                return (
                    GuardHttpResponse {
                        status: StatusCode::FORBIDDEN,
                        content_type: "text/plain; charset=utf-8",
                        body: b"malformed fp token".to_vec(),
                        extra_headers: sec_headers(),
                    },
                    None,
                );
            }
            let (token_id, exp_s, svc_b64, sig) = (parts[0], parts[1], parts[2], parts[3]);
            let Ok(expires_at) = exp_s.parse::<i64>() else {
                return (
                    GuardHttpResponse {
                        status: StatusCode::FORBIDDEN,
                        content_type: "text/plain; charset=utf-8",
                        body: b"invalid fp token expiry".to_vec(),
                        extra_headers: sec_headers(),
                    },
                    None,
                );
            };
            let service_tag = match URL_SAFE_NO_PAD
                .decode(svc_b64)
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
            {
                Some(s) if !s.is_empty() && s.len() <= 128 => s,
                _ => {
                    return (
                        GuardHttpResponse {
                            status: StatusCode::FORBIDDEN,
                            content_type: "text/plain; charset=utf-8",
                            body: b"invalid fp token service".to_vec(),
                            extra_headers: sec_headers(),
                        },
                        None,
                    );
                }
            };

            let now = Utc::now().timestamp();
            let ua = headers
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let ua_hash = short_sha256_hex(ua);

            if expires_at < now
                || expires_at > now + FP_TOKEN_TTL_SECS + 15
                || !verify_fp_token(
                    clearance_secret,
                    &host_clean,
                    &ip_key,
                    &ua_hash,
                    &service_tag,
                    token_id,
                    expires_at,
                    sig,
                )
            {
                return (
                    GuardHttpResponse {
                        status: StatusCode::FORBIDDEN,
                        content_type: "text/plain; charset=utf-8",
                        body: b"fp token expired or invalid".to_vec(),
                        extra_headers: sec_headers(),
                    },
                    None,
                );
            }

            if !self.consume_fp_token(token_id, expires_at, now) {
                return (
                    GuardHttpResponse {
                        status: StatusCode::FORBIDDEN,
                        content_type: "text/plain; charset=utf-8",
                        body: b"fp token already consumed".to_vec(),
                        extra_headers: sec_headers(),
                    },
                    None,
                );
            }

            req.fp.sanitize();
            let is_headless = req.fp.detect_headless(ua);
            let fp_hash = req.fp.canonical_hash();
            let ttl = profile
                .and_then(|p| p.js_fp_ttl_secs)
                .unwrap_or(fp_ttl_secs)
                .max(60);

            let claims = FpCookieClaims {
                host: host_clean,
                expires_at: now.saturating_add(ttl as i64),
                ua_hash,
                ip_prefix: ip_key,
                fp_hash: fp_hash.clone(),
                is_headless,
            };
            let cookie_val = match sign_fp_cookie(clearance_secret, &claims) {
                Ok(v) => v,
                Err(_) => {
                    return (
                        GuardHttpResponse {
                            status: StatusCode::INTERNAL_SERVER_ERROR,
                            content_type: "text/plain; charset=utf-8",
                            body: b"failed to sign fp cookie".to_vec(),
                            extra_headers: sec_headers(),
                        },
                        None,
                    );
                }
            };

            let secure_attr = if is_tls { "; Secure" } else { "" };
            let cookie = format!(
                "{FP_COOKIE_NAME}={cookie_val}; Path=/; HttpOnly; SameSite=Lax{secure_attr}; Max-Age={ttl}"
            );
            let mut extra = sec_headers();
            extra.push(("Set-Cookie".into(), cookie));
            extra.push(("Cache-Control".into(), "no-store".into()));
            return (
                GuardHttpResponse {
                    status: StatusCode::NO_CONTENT,
                    content_type: "text/plain; charset=utf-8",
                    body: Vec::new(),
                    extra_headers: extra,
                },
                Some(VerifiedFpSubmission {
                    service_tag: Some(service_tag),
                    fp_hash,
                    fp_source: "beacon",
                    is_headless,
                    js_fp: req.fp,
                }),
            );
        }

        if method == Method::POST && sub == "/verify" {
            if body.len() > 4096 {
                return (
                    GuardHttpResponse {
                        status: StatusCode::PAYLOAD_TOO_LARGE,
                        content_type: "text/plain; charset=utf-8",
                        body: b"verify payload too large".to_vec(),
                        extra_headers: sec_headers(),
                    },
                    None,
                );
            }
            #[derive(Deserialize)]
            struct VerifyReq {
                token: String,
                nonce: u64,
                signature: String,
                expires_at: i64,
                difficulty: u8,
                #[serde(default)]
                redirect: Option<String>,
                #[serde(default)]
                client_fp: Option<ClientJsFingerprint>,
            }
            #[derive(Serialize)]
            struct VerifyResp {
                ok: bool,
                redirect: String,
            }

            let mut req: VerifyReq = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(_) => {
                    return (
                        GuardHttpResponse {
                            status: StatusCode::BAD_REQUEST,
                            content_type: "text/plain; charset=utf-8",
                            body: b"invalid verify payload".to_vec(),
                            extra_headers: sec_headers(),
                        },
                        None,
                    );
                }
            };

            let required_difficulty = profile.map(|p| p.pow_difficulty).unwrap_or(16).clamp(1, 28);
            let now = Utc::now().timestamp();
            if req.difficulty < required_difficulty
                || req.expires_at < now
                || req.expires_at > now + CHALLENGE_TTL_SECS + 60
                || !verify_challenge_token(
                    clearance_secret,
                    &host_clean,
                    &ip_key,
                    &req.token,
                    req.expires_at,
                    req.difficulty,
                    &req.signature,
                )
            {
                return (
                    GuardHttpResponse {
                        status: StatusCode::FORBIDDEN,
                        content_type: "text/plain; charset=utf-8",
                        body: b"challenge expired, downgraded, or invalid signature".to_vec(),
                        extra_headers: sec_headers(),
                    },
                    None,
                );
            }

            if !verify_pow_solution(&req.token, req.nonce, req.difficulty) {
                return (
                    GuardHttpResponse {
                        status: StatusCode::FORBIDDEN,
                        content_type: "text/plain; charset=utf-8",
                        body: b"invalid proof-of-work solution".to_vec(),
                        extra_headers: sec_headers(),
                    },
                    None,
                );
            }

            if !self.consume_challenge_token(&req.token, req.expires_at, now) {
                return (
                    GuardHttpResponse {
                        status: StatusCode::FORBIDDEN,
                        content_type: "text/plain; charset=utf-8",
                        body: b"challenge token already used".to_vec(),
                        extra_headers: sec_headers(),
                    },
                    None,
                );
            }

            let ttl = profile.map(|p| p.clearance_ttl_secs).unwrap_or(1800);
            let bind_ua = profile.map(|p| p.effective_bind_ua()).unwrap_or(true);
            let bind_ip = profile
                .map(|p| p.effective_bind_ip_prefix())
                .unwrap_or(false);
            let ua = headers
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let block_headless = profile
                .map(|p| p.effective_block_headless())
                .unwrap_or(false);

            let mut verified_fp_sub: Option<VerifiedFpSubmission> = None;
            let fp_hash = if let Some(ref mut cfp) = req.client_fp {
                cfp.sanitize();
                let is_headless = cfp.detect_headless(ua);
                if block_headless && is_headless {
                    return (
                        GuardHttpResponse {
                            status: StatusCode::FORBIDDEN,
                            content_type: "text/plain; charset=utf-8",
                            body: b"headless or tampered browser fingerprint rejected".to_vec(),
                            extra_headers: sec_headers(),
                        },
                        None,
                    );
                }
                let h = cfp.canonical_hash();
                verified_fp_sub = Some(VerifiedFpSubmission {
                    service_tag: None,
                    fp_hash: h.clone(),
                    fp_source: "pow",
                    is_headless,
                    js_fp: cfp.clone(),
                });
                Some(h)
            } else {
                None
            };

            let claims = ClearanceClaims {
                host: host_clean,
                expires_at: now.saturating_add(ttl as i64),
                ua_hash: if bind_ua {
                    Some(short_sha256_hex(ua))
                } else {
                    None
                },
                ip_prefix: if bind_ip { Some(ip_key) } else { None },
                fp_hash,
            };

            let cookie_val = match sign_clearance_cookie(clearance_secret, &claims) {
                Ok(v) => v,
                Err(_) => {
                    return (
                        GuardHttpResponse {
                            status: StatusCode::INTERNAL_SERVER_ERROR,
                            content_type: "text/plain",
                            body: b"failed to sign clearance".to_vec(),
                            extra_headers: sec_headers(),
                        },
                        None,
                    );
                }
            };

            let redirect = sanitize_redirect(req.redirect.as_deref().unwrap_or("/"));
            let secure_attr = if is_tls { "; Secure" } else { "" };
            let cookie = format!(
                "{CLEARANCE_COOKIE_NAME}={cookie_val}; Path=/; HttpOnly; SameSite=Lax{secure_attr}; Max-Age={ttl}"
            );
            let mut extra = sec_headers();
            extra.push(("Set-Cookie".into(), cookie));
            extra.push(("Cache-Control".into(), "no-store".into()));
            return (
                GuardHttpResponse {
                    status: StatusCode::OK,
                    content_type: "application/json; charset=utf-8",
                    body: serde_json::to_vec(&VerifyResp { ok: true, redirect })
                        .unwrap_or_default(),
                    extra_headers: extra,
                },
                verified_fp_sub,
            );
        }

        let asset_path = sub.trim_start_matches('/');
        if let Some((bytes, mime)) = load_web_asset(WebApp::Challenge, asset_path) {
            let mut extra = sec_headers();
            let cc = if asset_path == "fp.js" {
                "public, max-age=300"
            } else {
                "no-cache"
            };
            extra.push(("Cache-Control".into(), cc.into()));
            return (
                GuardHttpResponse {
                    status: StatusCode::OK,
                    content_type: mime,
                    body: bytes,
                    extra_headers: extra,
                },
                None,
            );
        }

        (
            GuardHttpResponse {
                status: StatusCode::NOT_FOUND,
                content_type: "text/plain; charset=utf-8",
                body: b"not found".to_vec(),
                extra_headers: sec_headers(),
            },
            None,
        )
    }
}

/// Heuristic browser fingerprint suspicion score (0 = clean browser, 100 = clearly automated bot).
pub fn compute_suspicion_score(headers: &HeaderMap, tls: Option<&ClientHelloSignal>) -> u8 {
    let mut score: u32 = 0;

    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let ua_l = ua.to_ascii_lowercase();

    if ua.is_empty() {
        score += 45;
    } else if ua_l.contains("curl")
        || ua_l.contains("wget")
        || ua_l.contains("python")
        || ua_l.contains("scrapy")
        || ua_l.contains("go-http-client")
        || ua_l.contains("headless")
        || ua_l.contains("bot")
    {
        score += 55;
    }

    if !headers.contains_key(header::ACCEPT) {
        score += 15;
    }
    if !headers.contains_key(header::ACCEPT_LANGUAGE) {
        score += 20;
    }
    if ua_l.contains("mozilla/") && !headers.contains_key("sec-fetch-mode") {
        score += 15;
    }

    if let Some(sig) = tls {
        if sig.cipher_count > 0 && sig.cipher_count < 4 {
            score += 20;
        }
        if !sig.has_alpn {
            score += 15;
        }
    }

    score.min(100) as u8
}

fn ip_prefix(ip: IpAddr) -> String {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}", s[0], s[1], s[2])
        }
    }
}

/// Strict same-origin relative redirect sanitizer (blocks `//`, `/\`, backslashes, control chars, scheme URIs).
pub fn sanitize_redirect(raw: &str) -> String {
    if !raw.starts_with('/') {
        return "/".to_string();
    }
    if raw.len() >= 2 && matches!(raw.as_bytes()[1], b'/' | b'\\') {
        return "/".to_string();
    }
    if raw.bytes().any(|b| b == b'\\' || b < 0x20 || b == 0x7f) {
        return "/".to_string();
    }
    match raw.parse::<http::Uri>() {
        Ok(uri) if uri.scheme().is_none() && uri.authority().is_none() => raw.to_string(),
        _ => "/".to_string(),
    }
}

#[derive(Debug, Clone)]
pub struct ClientFingerprint {
    pub device_type: &'static str,
    pub browser_family: &'static str,
    pub os_family: &'static str,
    pub is_bot: bool,
}

/// Classify client device, browser family, OS, and bot status from HTTP headers (server-side).
pub fn classify_client(headers: &HeaderMap) -> ClientFingerprint {
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let ua_l = ua.to_ascii_lowercase();
    let ch_mobile = headers
        .get("sec-ch-ua-mobile")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let ch_plat = headers
        .get("sec-ch-ua-platform")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    let is_bot = ua.is_empty()
        || ua_l.contains("bot")
        || ua_l.contains("spider")
        || ua_l.contains("crawler")
        || ua_l.contains("scrapy")
        || ua_l.contains("curl")
        || ua_l.contains("wget")
        || ua_l.contains("python-requests")
        || ua_l.contains("go-http-client")
        || ua_l.contains("headless");

    let device_type = if is_bot {
        if ua_l.contains("curl") || ua_l.contains("wget") || ua_l.contains("python") || ua_l.contains("go-http") {
            "API/CLI"
        } else {
            "Bot"
        }
    } else if ch_mobile == "?1" || ua_l.contains("iphone") || (ua_l.contains("android") && ua_l.contains("mobile")) {
        "Mobile"
    } else if ua_l.contains("ipad") || ua_l.contains("tablet") {
        "Tablet"
    } else {
        "Desktop"
    };

    let browser_family = if ua_l.contains("edg/") || ua_l.contains("edge/") {
        "Edge"
    } else if ua_l.contains("opr/") || ua_l.contains("opera") {
        "Opera"
    } else if ua_l.contains("firefox/") {
        "Firefox"
    } else if ua_l.contains("chrome/") || ua_l.contains("crios/") {
        "Chrome"
    } else if ua_l.contains("safari/") {
        "Safari"
    } else if ua_l.contains("curl") || ua_l.contains("wget") || ua_l.contains("python") {
        "CLI/Script"
    } else if is_bot {
        "Bot"
    } else {
        "Other"
    };

    let os_family = if ch_plat.contains("windows") || ua_l.contains("windows") {
        "Windows"
    } else if ch_plat.contains("android") || ua_l.contains("android") {
        "Android"
    } else if ua_l.contains("iphone") || ua_l.contains("ipad") || ch_plat.contains("ios") {
        "iOS"
    } else if ch_plat.contains("mac") || ua_l.contains("mac os x") || ua_l.contains("macintosh") {
        "macOS"
    } else if ch_plat.contains("linux") || ua_l.contains("linux") {
        "Linux"
    } else {
        "Other"
    };

    ClientFingerprint {
        device_type,
        browser_family,
        os_family,
        is_bot,
    }
}

fn url_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_rate_limit_and_antibot_modes() {
        let engine = GuardEngine::new();
        let mut buckets = BTreeMap::new();
        buckets.insert(
            "api".into(),
            RateLimitBucket {
                capacity: 2.0,
                refill_per_sec: 0.1,
                per_ip: Some(true),
            },
        );
        let profile = GuardProfile {
            antibot: AntibotMode::Off,
            rate_limit_bucket: Some("api".into()),
            ..Default::default()
        };
        let ip: IpAddr = "203.0.113.10".parse().unwrap();
        let headers = HeaderMap::new();
        assert!(matches!(
            engine.evaluate(&profile, &buckets, "sec", ip, "example.com", "/", &headers, None),
            GuardDecision::Allow
        ));
        assert!(matches!(
            engine.evaluate(&profile, &buckets, "sec", ip, "example.com", "/", &headers, None),
            GuardDecision::Allow
        ));
        assert!(matches!(
            engine.evaluate(&profile, &buckets, "sec", ip, "example.com", "/", &headers, None),
            GuardDecision::RateLimited { .. }
        ));
    }

    #[test]
    fn guard_pow_challenge_clearance_replay_and_redirect_sanitization() {
        assert_eq!(sanitize_redirect("/\\evil.example"), "/");
        assert_eq!(sanitize_redirect("//evil.example"), "/");
        assert_eq!(sanitize_redirect("/ok?a=1"), "/ok?a=1");

        let engine = GuardEngine::new();
        let profile = GuardProfile {
            antibot: AntibotMode::Challenge,
            challenge_threshold: 40,
            reject_threshold: 95,
            pow_difficulty: 8,
            clearance_ttl_secs: 600,
            bind_ua: Some(true),
            bind_ip_prefix: Some(false),
            ..Default::default()
        };
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::USER_AGENT, "curl/8.0".parse().unwrap());

        let dec = engine.evaluate(
            &profile,
            &BTreeMap::new(),
            "my-secret-key-for-testing-123456",
            ip,
            "example.com",
            "/hello",
            &headers,
            None,
        );
        assert!(matches!(dec, GuardDecision::ChallengeRedirect { .. }));

        let (ch, _) = engine.handle_cdn_cgi(
            &Method::GET,
            "/cdn-cgi/challenge",
            &[],
            &headers,
            "example.com",
            ip,
            true,
            Some(&profile),
            "my-secret-key-for-testing-123456",
            3600,
        );
        assert_eq!(ch.status, StatusCode::OK);
        let val: serde_json::Value = serde_json::from_slice(&ch.body).unwrap();
        let token = val["token"].as_str().unwrap().to_string();
        let diff = val["difficulty"].as_u64().unwrap() as u8;
        let mut nonce = 0u64;
        while !verify_pow_solution(&token, nonce, diff) {
            nonce += 1;
        }
        let verify_body = serde_json::to_vec(&serde_json::json!({
            "token": token,
            "nonce": nonce,
            "signature": val["signature"],
            "expires_at": val["expires_at"],
            "difficulty": diff,
            "redirect": "/hello"
        }))
        .unwrap();

        // Cross-host submission must fail
        let (cross_host, _) = engine.handle_cdn_cgi(
            &Method::POST,
            "/cdn-cgi/verify",
            &verify_body,
            &headers,
            "other.example.com",
            ip,
            true,
            Some(&profile),
            "my-secret-key-for-testing-123456",
            3600,
        );
        assert_eq!(cross_host.status, StatusCode::FORBIDDEN);

        // Legitimate submission succeeds and sets Secure flag on TLS
        let (ver, _) = engine.handle_cdn_cgi(
            &Method::POST,
            "/cdn-cgi/verify",
            &verify_body,
            &headers,
            "example.com",
            ip,
            true,
            Some(&profile),
            "my-secret-key-for-testing-123456",
            3600,
        );
        assert_eq!(ver.status, StatusCode::OK);
        let set_cookie = ver
            .extra_headers
            .iter()
            .find(|(k, _)| k == "Set-Cookie")
            .unwrap()
            .1
            .clone();
        assert!(set_cookie.contains("; Secure"));

        // Replaying the same solved challenge token must fail!
        let (replay, _) = engine.handle_cdn_cgi(
            &Method::POST,
            "/cdn-cgi/verify",
            &verify_body,
            &headers,
            "example.com",
            ip,
            true,
            Some(&profile),
            "my-secret-key-for-testing-123456",
            3600,
        );
        assert_eq!(replay.status, StatusCode::FORBIDDEN);

        // Passive JS FP beacon token mint, report, cookie verification, and replay rejection
        let mut browser_hdrs = HeaderMap::new();
        browser_hdrs.insert(header::USER_AGENT, "Mozilla/5.0 Chrome/130".parse().unwrap());
        browser_hdrs.insert(header::ACCEPT, "text/html".parse().unwrap());
        browser_hdrs.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        browser_hdrs.insert("sec-fetch-site", "same-origin".parse().unwrap());
        browser_hdrs.insert("sec-fetch-dest", "document".parse().unwrap());
        assert!(engine.should_inject_fp_beacon(
            &Method::GET,
            false,
            ip,
            "example.com",
            &browser_hdrs,
            "my-secret-key-for-testing-123456",
            Some(&profile),
            true,
            None,
        ));
        let fp_tok = engine.mint_fp_token(
            "my-secret-key-for-testing-123456",
            "example.com",
            ip,
            &browser_hdrs,
            "web@default",
        );
        let fp_body = serde_json::to_vec(&serde_json::json!({
            "token": fp_tok,
            "fp": {
                "webdriver": false,
                "webgl": "ANGLE (Apple M2)",
                "platform": "MacIntel",
                "screen": "1440x900x24",
                "tz": "Asia/Shanghai",
                "lang": "zh-CN",
                "cores": 8,
                "mem": 8,
                "touch": 0,
                "canvas_hash": "deadbeef"
            }
        }))
        .unwrap();
        let (fp_resp, fp_sub) = engine.handle_cdn_cgi(
            &Method::POST,
            "/cdn-cgi/fp-report",
            &fp_body,
            &browser_hdrs,
            "example.com",
            ip,
            true,
            Some(&profile),
            "my-secret-key-for-testing-123456",
            3600,
        );
        assert_eq!(fp_resp.status, StatusCode::NO_CONTENT);
        assert!(fp_sub.is_some());
        // Replay must be rejected
        let (fp_replay, _) = engine.handle_cdn_cgi(
            &Method::POST,
            "/cdn-cgi/fp-report",
            &fp_body,
            &browser_hdrs,
            "example.com",
            ip,
            true,
            Some(&profile),
            "my-secret-key-for-testing-123456",
            3600,
        );
        assert_eq!(fp_replay.status, StatusCode::FORBIDDEN);

        let cookie_pair = set_cookie.split(';').next().unwrap();
        // Also test HTTP/2 multi-Cookie header support
        headers.append(header::COOKIE, "other=1".parse().unwrap());
        headers.append(header::COOKIE, cookie_pair.parse().unwrap());

        let dec2 = engine.evaluate(
            &profile,
            &BTreeMap::new(),
            "my-secret-key-for-testing-123456",
            ip,
            "example.com",
            "/hello",
            &headers,
            None,
        );
        assert!(matches!(dec2, GuardDecision::Allow));
    }

    #[test]
    fn guard_always_mode_challenges_normal_browser() {
        let engine = GuardEngine::new();
        let profile = GuardProfile {
            antibot: AntibotMode::Always,
            challenge_threshold: 50,
            reject_threshold: 85,
            pow_difficulty: 8,
            ..Default::default()
        };
        let ip: IpAddr = "198.51.100.9".parse().unwrap();
        let mut browser_headers = HeaderMap::new();
        browser_headers.insert(
            header::USER_AGENT,
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36"
                .parse()
                .unwrap(),
        );
        browser_headers.insert(header::ACCEPT, "text/html".parse().unwrap());
        browser_headers.insert(header::ACCEPT_LANGUAGE, "en-US,en;q=0.9".parse().unwrap());
        browser_headers.insert("sec-fetch-mode", "navigate".parse().unwrap());

        assert_eq!(compute_suspicion_score(&browser_headers, None), 0);
        let dec = engine.evaluate(
            &profile,
            &BTreeMap::new(),
            "my-secret",
            ip,
            "example.com",
            "/app",
            &browser_headers,
            None,
        );
        assert!(matches!(dec, GuardDecision::ChallengeRedirect { .. }));
    }
}
