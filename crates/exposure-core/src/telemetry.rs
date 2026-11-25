use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::routing::LinkHealthState;

/// Up to this many unique visitors per sketch are tracked with 100% exact cardinality;
/// beyond this threshold the sketch seamlessly switches to HyperLogLog registers.
pub const EXACT_UV_THRESHOLD: usize = 512;

/// Deterministic HyperLogLog++ hybrid sketch (exact set up to 512 items, HLL above).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperLogLog {
    pub precision: u8,
    pub seed: u64,
    pub registers: Vec<u8>,
    #[serde(default)]
    pub exact_set: BTreeSet<String>,
    #[serde(default)]
    pub exact_overflow: bool,
}

impl HyperLogLog {
    pub fn new(precision: u8, seed: u64) -> Self {
        let p = precision.clamp(4, 16);
        let m = 1usize << p;
        Self {
            precision: p,
            seed,
            registers: vec![0u8; m],
            exact_set: BTreeSet::new(),
            exact_overflow: false,
        }
    }

    pub fn is_valid(&self) -> bool {
        (4..=16).contains(&self.precision) && self.registers.len() == (1usize << self.precision)
    }

    fn hash64(&self, item: &str) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(self.seed.to_be_bytes());
        hasher.update(item.as_bytes());
        let digest = hasher.finalize();
        u64::from_be_bytes(digest[..8].try_into().unwrap())
    }

    pub fn insert(&mut self, item: &str) {
        if !self.is_valid() || item.is_empty() {
            return;
        }
        let h = self.hash64(item);
        let idx = (h >> (64 - self.precision)) as usize;
        let w = (h << self.precision) | (1u64 << (self.precision - 1));
        let rho = (w.leading_zeros() as u8) + 1;
        if let Some(slot) = self.registers.get_mut(idx) {
            if rho > *slot {
                *slot = rho;
            }
        }
        if !self.exact_overflow {
            // Compact 16-hex-char hashed key inside exact_set to bound memory
            let compact = format!("{h:016x}");
            self.exact_set.insert(compact);
            if self.exact_set.len() > EXACT_UV_THRESHOLD {
                self.exact_set.clear();
                self.exact_overflow = true;
            }
        }
    }

    pub fn merge(&mut self, other: &HyperLogLog) {
        if !self.is_valid() || !other.is_valid() {
            return;
        }
        if self.precision != other.precision || self.seed != other.seed {
            return;
        }
        let self_has_nonzero_regs = self.registers.iter().any(|&r| r > 0);
        let other_has_nonzero_regs = other.registers.iter().any(|&r| r > 0);
        // Handle legacy sketches serialized without exact_set populated
        let self_legacy = !self.exact_overflow && self.exact_set.is_empty() && self_has_nonzero_regs;
        let other_legacy = !other.exact_overflow && other.exact_set.is_empty() && other_has_nonzero_regs;

        for (a, &b) in self.registers.iter_mut().zip(other.registers.iter()) {
            if b > *a {
                *a = b;
            }
        }

        if self.exact_overflow || other.exact_overflow || self_legacy || other_legacy {
            self.exact_set.clear();
            self.exact_overflow = true;
        } else {
            for k in &other.exact_set {
                self.exact_set.insert(k.clone());
                if self.exact_set.len() > EXACT_UV_THRESHOLD {
                    self.exact_set.clear();
                    self.exact_overflow = true;
                    break;
                }
            }
        }
    }

    pub fn estimate(&self) -> f64 {
        if !self.is_valid() || self.registers.is_empty() {
            return 0.0;
        }
        if !self.exact_overflow {
            let has_regs = self.registers.iter().any(|&r| r > 0);
            if !self.exact_set.is_empty() || !has_regs {
                return self.exact_set.len() as f64;
            }
        }
        let m = self.registers.len() as f64;
        let alpha = match self.registers.len() {
            16 => 0.673,
            32 => 0.697,
            64 => 0.709,
            _ => 0.7213 / (1.0 + 1.079 / m),
        };
        let sum: f64 = self
            .registers
            .iter()
            .map(|&r| 2.0_f64.powi(-(r.min(64) as i32)))
            .sum();
        if sum <= 0.0 || !sum.is_finite() {
            return 0.0;
        }
        let raw = alpha * m * m / sum;

        if raw <= 2.5 * m {
            let zeros = self.registers.iter().filter(|&&r| r == 0).count() as f64;
            if zeros > 0.0 {
                return m * (m / zeros).ln();
            }
        }
        raw
    }
}

/// Fixed-boundary latency histogram supporting merge and quantile computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyHistogram {
    pub boundaries_ms: Vec<f64>,
    /// Length is `boundaries_ms.len() + 1` (last bucket is +Inf overflow).
    pub counts: Vec<u64>,
}

impl LatencyHistogram {
    pub fn new(boundaries_ms: Vec<f64>) -> Self {
        let len = boundaries_ms.len() + 1;
        Self {
            boundaries_ms,
            counts: vec![0u64; len],
        }
    }

    pub fn observe(&mut self, latency_ms: f64) {
        if !latency_ms.is_finite() || latency_ms < 0.0 {
            return;
        }
        let mut idx = self.boundaries_ms.len();
        for (i, &b) in self.boundaries_ms.iter().enumerate() {
            if latency_ms <= b {
                idx = i;
                break;
            }
        }
        if let Some(c) = self.counts.get_mut(idx) {
            *c = c.saturating_add(1);
        }
    }

    pub fn merge(&mut self, other: &LatencyHistogram) {
        if self.boundaries_ms != other.boundaries_ms || self.counts.len() != other.counts.len() {
            return;
        }
        for (a, &b) in self.counts.iter_mut().zip(other.counts.iter()) {
            *a = a.saturating_add(b);
        }
    }

    pub fn total(&self) -> u64 {
        self.counts.iter().copied().fold(0u64, u64::saturating_add)
    }

    pub fn quantile(&self, q: f64) -> f64 {
        let total = self.total();
        if total == 0 {
            return 0.0;
        }
        let target = (q.clamp(0.0, 1.0) * total as f64).ceil().max(1.0) as u64;
        let mut acc = 0u64;
        for (i, &c) in self.counts.iter().enumerate() {
            let prev_acc = acc;
            acc = acc.saturating_add(c);
            if acc >= target {
                if i < self.boundaries_ms.len() {
                    let lower = if i == 0 { 0.0 } else { self.boundaries_ms[i - 1] };
                    let upper = self.boundaries_ms[i];
                    let frac = if c > 0 {
                        (target.saturating_sub(prev_acc)) as f64 / c as f64
                    } else {
                        1.0
                    };
                    return lower + (upper - lower) * frac;
                } else {
                    return self.boundaries_ms.last().copied().unwrap_or(0.0);
                }
            }
        }
        self.boundaries_ms.last().copied().unwrap_or(0.0)
    }
}

fn default_repeat_one() -> u32 {
    1
}

fn is_repeat_one(v: &u32) -> bool {
    *v <= 1
}

const SENSITIVE_QUERY_KEYS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "token",
    "secret",
    "api_key",
    "apikey",
    "key",
    "auth",
    "session",
    "sid",
    "jwt",
    "sig",
    "signature",
    "cookie",
    "credential",
    "code",
    "access_key",
    "private",
];

/// Strip control characters (preventing log/CRLF injection), trim, and safely truncate to `max_chars`.
pub fn sanitize_log_text(raw: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .collect();
    let trimmed = cleaned.trim();
    let count = trimmed.chars().count();
    if count <= max_chars {
        return trimmed.to_string();
    }
    if max_chars > 3 {
        let mut out: String = trimmed.chars().take(max_chars - 1).collect();
        out.push('…');
        out
    } else {
        trimmed.chars().take(max_chars).collect()
    }
}

pub fn sanitize_url_path(raw: &str) -> String {
    sanitize_log_text(raw, 256)
}

/// Sanitize a URL query string (stripping leading `?`, control chars, capping at 64 pairs / 256 chars)
/// and redacting sensitive parameter values such as tokens, passwords, secrets, and API keys.
pub fn sanitize_and_redact_query(raw: &str) -> String {
    let trimmed = raw.trim().trim_start_matches('?');
    if trimmed.is_empty() {
        return String::new();
    }
    let mut parts = Vec::new();
    for pair in trimmed.split('&').take(64) {
        if pair.is_empty() {
            continue;
        }
        let clean_pair: String = pair
            .chars()
            .filter(|c| !c.is_control() || *c == ' ')
            .collect();
        if let Some((k, v)) = clean_pair.split_once('=') {
            let kl = k.trim().to_ascii_lowercase();
            let sensitive = SENSITIVE_QUERY_KEYS.iter().any(|s| kl.contains(s));
            if sensitive {
                parts.push(format!("{}=[REDACTED]", k.trim()));
            } else {
                parts.push(format!("{}={}", k.trim(), v.trim()));
            }
        } else {
            parts.push(clean_pair.trim().to_string());
        }
    }
    let joined = parts.join("&");
    sanitize_log_text(&joined, 256)
}

/// Sanitize HTTP `Referer` header by stripping query/fragment components and capping to 192 chars.
pub fn sanitize_referer(raw: &str) -> String {
    let no_frag = raw.split('#').next().unwrap_or(raw);
    let no_query = no_frag.split('?').next().unwrap_or(no_frag);
    sanitize_log_text(no_query, 192)
}

fn sanitize_opt(opt: &mut Option<String>, max_chars: usize) {
    if let Some(val) = opt.as_mut() {
        let cleaned = sanitize_log_text(val, max_chars);
        if cleaned.is_empty() {
            *opt = None;
        } else {
            *val = cleaned;
        }
    }
}

/// GeoIP database sync status snapshot reported by Ingress nodes.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoIpStatusSnapshot {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub loaded: bool,
    #[serde(default)]
    pub ipv4_ranges: usize,
    #[serde(default)]
    pub ipv6_ranges: usize,
    #[serde(default)]
    pub updated_at: i64,
    #[serde(default)]
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Individual session / HTTP access log record written to segment files (production layer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub timestamp_ms: i64,
    pub node_tag: String,
    pub role: String,
    pub service_tag: String,
    pub status: u16,
    pub latency_ms: f64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub ip_hmac: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_ip: Option<String>,
    /// Locally resolved ISO-3166-1 alpha-2 country code from Node GeoIP DB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_country: Option<String>,
    #[serde(default)]
    pub rate_limited: bool,
    #[serde(default)]
    pub challenged: bool,
    #[serde(default)]
    pub challenge_passed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_family: Option<String>,
    #[serde(default)]
    pub client_fp_verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ray_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ja3: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waf_rule_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waf_category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspicion_score: Option<u8>,
    #[serde(default = "default_repeat_one", skip_serializing_if = "is_repeat_one")]
    pub repeat_count: u32,
}

impl Default for SessionSummary {
    fn default() -> Self {
        Self {
            timestamp_ms: 0,
            node_tag: String::new(),
            role: String::new(),
            service_tag: String::new(),
            status: 0,
            latency_ms: 0.0,
            bytes_in: 0,
            bytes_out: 0,
            ip_hmac: String::new(),
            raw_ip: None,
            client_country: None,
            rate_limited: false,
            challenged: false,
            challenge_passed: false,
            error: None,
            device_type: None,
            browser_family: None,
            os_family: None,
            client_fp_verified: false,
            ray_id: None,
            method: None,
            host: None,
            path: None,
            query: None,
            protocol: None,
            scheme: None,
            user_agent: None,
            referer: None,
            action: None,
            cache_status: None,
            tls_ja3: None,
            waf_rule_id: None,
            waf_category: None,
            suspicion_score: None,
            repeat_count: 1,
        }
    }
}

impl SessionSummary {
    /// Enforce strict control-character stripping, query redaction, and length bounds
    /// so untrusted HTTP inputs can never cause log injection or storage amplification.
    pub fn sanitize(&mut self) {
        self.node_tag = sanitize_log_text(&self.node_tag, 64);
        self.role = sanitize_log_text(&self.role, 32);
        self.service_tag = sanitize_log_text(&self.service_tag, 128);
        self.ip_hmac = sanitize_log_text(&self.ip_hmac, 64);
        sanitize_opt(&mut self.raw_ip, 64);
        sanitize_opt(&mut self.client_country, 8);
        sanitize_opt(&mut self.error, 256);
        sanitize_opt(&mut self.device_type, 32);
        sanitize_opt(&mut self.browser_family, 32);
        sanitize_opt(&mut self.os_family, 32);
        sanitize_opt(&mut self.ray_id, 64);
        sanitize_opt(&mut self.method, 16);
        sanitize_opt(&mut self.host, 128);
        if let Some(ref mut p) = self.path {
            let cleaned = sanitize_url_path(p);
            if cleaned.is_empty() {
                self.path = None;
            } else {
                *p = cleaned;
            }
        }
        if let Some(ref mut q) = self.query {
            let cleaned = sanitize_and_redact_query(q);
            if cleaned.is_empty() {
                self.query = None;
            } else {
                *q = cleaned;
            }
        }
        sanitize_opt(&mut self.protocol, 16);
        sanitize_opt(&mut self.scheme, 8);
        sanitize_opt(&mut self.user_agent, 192);
        if let Some(ref mut rf) = self.referer {
            let cleaned = sanitize_referer(rf);
            if cleaned.is_empty() {
                self.referer = None;
            } else {
                *rf = cleaned;
            }
        }
        sanitize_opt(&mut self.action, 32);
        sanitize_opt(&mut self.cache_status, 16);
        sanitize_opt(&mut self.tls_ja3, 32);
        sanitize_opt(&mut self.waf_category, 48);
        if self.repeat_count == 0 {
            self.repeat_count = 1;
        }
    }
}

/// Anti-DoS log protection counters reported per node.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LogProtectionStats {
    #[serde(default)]
    pub dropped_records: u64,
    #[serde(default)]
    pub folded_records: u64,
    #[serde(default)]
    pub warn_suppressed: u64,
}

/// Whether an access log `action` represents a hard security block or honeypot diversion
/// (distinct from PoW challenges, rate limits, and 5xx errors).
pub fn is_security_block_action(action: Option<&str>) -> bool {
    matches!(
        action,
        Some(
            "autoban"
                | "waf_block"
                | "evilpot"
                | "evilpot_canary"
                | "guard_reject"
                | "abuseipdb"
                | "geo_block"
                | "geo_evilpot"
        )
    )
}

/// Whether an access log record represents a security/edge mitigation (rate-limit, challenge,
/// WAF/Guard/Geo/AutoBan/AbuseIPDB block, or Evilpot diversion), without misclassifying
/// origin-returned 403/429 responses (`action = Some("allow")`).
pub fn is_mitigated_record(rec: &SessionSummary) -> bool {
    if rec.rate_limited || rec.challenged {
        return true;
    }
    match rec.action.as_deref() {
        Some(a) => {
            is_security_block_action(Some(a))
                || matches!(a, "rate_limit" | "challenge" | "geo_challenge")
        }
        // Legacy pre-`action` segment logs fallback
        None => rec.status == 403 || rec.status == 429,
    }
}

/// Whether a response `cache_status` represents serving content from the edge cache.
pub fn is_cache_served_status(cache_status: Option<&str>) -> bool {
    matches!(cache_status, Some("HIT" | "STALE" | "REVALIDATED"))
}

/// Aggregated summary per `(node_tag, role, minute_epoch, service_tag)` pushed to Maintainer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinuteSummary {
    pub minute_epoch: i64,
    pub node_tag: String,
    /// Node role that recorded this summary (`"ingress"` or `"egress"`).
    #[serde(default)]
    pub role: String,
    pub service_tag: String,
    pub requests: u64,
    pub errors: u64,
    pub rate_limited: u64,
    pub challenges_issued: u64,
    pub challenges_passed: u64,
    #[serde(default)]
    pub blocked: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub uv_hll: HyperLogLog,
    pub latency_hist: LatencyHistogram,
    #[serde(default)]
    pub device_counts: std::collections::BTreeMap<String, u64>,
    #[serde(default)]
    pub browser_counts: std::collections::BTreeMap<String, u64>,
    #[serde(default)]
    pub os_counts: std::collections::BTreeMap<String, u64>,
    #[serde(default)]
    pub client_fp_verified: u64,
    #[serde(default)]
    pub cached_requests: u64,
    #[serde(default)]
    pub cached_bytes_out: u64,
}

impl MinuteSummary {
    pub fn new(
        minute_epoch: i64,
        node_tag: impl Into<String>,
        role: impl Into<String>,
        service_tag: impl Into<String>,
        hll_precision: u8,
        hll_seed: u64,
        buckets_ms: Vec<f64>,
    ) -> Self {
        Self {
            minute_epoch,
            node_tag: node_tag.into(),
            role: role.into(),
            service_tag: service_tag.into(),
            requests: 0,
            errors: 0,
            rate_limited: 0,
            challenges_issued: 0,
            challenges_passed: 0,
            blocked: 0,
            bytes_in: 0,
            bytes_out: 0,
            uv_hll: HyperLogLog::new(hll_precision, hll_seed),
            latency_hist: LatencyHistogram::new(buckets_ms),
            device_counts: std::collections::BTreeMap::new(),
            browser_counts: std::collections::BTreeMap::new(),
            os_counts: std::collections::BTreeMap::new(),
            client_fp_verified: 0,
            cached_requests: 0,
            cached_bytes_out: 0,
        }
    }

    pub fn record(&mut self, rec: &SessionSummary) {
        self.requests = self.requests.saturating_add(1);
        if rec.status >= 500 {
            self.errors = self.errors.saturating_add(1);
        }
        if rec.rate_limited {
            self.rate_limited = self.rate_limited.saturating_add(1);
        }
        if rec.challenged {
            self.challenges_issued = self.challenges_issued.saturating_add(1);
        } else if !rec.rate_limited
            && rec.status < 500
            && is_security_block_action(rec.action.as_deref())
        {
            self.blocked = self.blocked.saturating_add(1);
        }
        if rec.challenge_passed {
            self.challenges_passed = self.challenges_passed.saturating_add(1);
        }
        if rec.client_fp_verified {
            self.client_fp_verified = self.client_fp_verified.saturating_add(1);
        }
        if let Some(ref d) = rec.device_type {
            let e = self.device_counts.entry(d.clone()).or_insert(0);
            *e = e.saturating_add(1);
        }
        if let Some(ref b) = rec.browser_family {
            let e = self.browser_counts.entry(b.clone()).or_insert(0);
            *e = e.saturating_add(1);
        }
        if let Some(ref o) = rec.os_family {
            let e = self.os_counts.entry(o.clone()).or_insert(0);
            *e = e.saturating_add(1);
        }
        self.bytes_in = self.bytes_in.saturating_add(rec.bytes_in);
        self.bytes_out = self.bytes_out.saturating_add(rec.bytes_out);
        if is_cache_served_status(rec.cache_status.as_deref()) {
            self.cached_requests = self.cached_requests.saturating_add(1);
            self.cached_bytes_out = self.cached_bytes_out.saturating_add(rec.bytes_out);
        }
        self.uv_hll.insert(&rec.ip_hmac);
        self.latency_hist.observe(rec.latency_ms);
    }

    pub fn merge_from(&mut self, other: &MinuteSummary) {
        self.requests = self.requests.saturating_add(other.requests);
        self.errors = self.errors.saturating_add(other.errors);
        self.rate_limited = self.rate_limited.saturating_add(other.rate_limited);
        self.challenges_issued = self.challenges_issued.saturating_add(other.challenges_issued);
        self.challenges_passed = self.challenges_passed.saturating_add(other.challenges_passed);
        self.blocked = self.blocked.saturating_add(other.blocked);
        self.client_fp_verified = self.client_fp_verified.saturating_add(other.client_fp_verified);
        for (k, v) in &other.device_counts {
            if self.device_counts.len() < 64 || self.device_counts.contains_key(k) {
                let e = self.device_counts.entry(k.clone()).or_insert(0);
                *e = e.saturating_add(*v);
            }
        }
        for (k, v) in &other.browser_counts {
            if self.browser_counts.len() < 64 || self.browser_counts.contains_key(k) {
                let e = self.browser_counts.entry(k.clone()).or_insert(0);
                *e = e.saturating_add(*v);
            }
        }
        for (k, v) in &other.os_counts {
            if self.os_counts.len() < 64 || self.os_counts.contains_key(k) {
                let e = self.os_counts.entry(k.clone()).or_insert(0);
                *e = e.saturating_add(*v);
            }
        }
        self.bytes_in = self.bytes_in.saturating_add(other.bytes_in);
        self.bytes_out = self.bytes_out.saturating_add(other.bytes_out);
        self.cached_requests = self.cached_requests.saturating_add(other.cached_requests);
        self.cached_bytes_out = self.cached_bytes_out.saturating_add(other.cached_bytes_out);
        self.uv_hll.merge(&other.uv_hll);
        self.latency_hist.merge(&other.latency_hist);
    }

    pub fn uv_estimate(&self) -> f64 {
        self.uv_hll.estimate()
    }

    pub fn p50_ms(&self) -> f64 {
        self.latency_hist.quantile(0.50)
    }

    pub fn p95_ms(&self) -> f64 {
        self.latency_hist.quantile(0.95)
    }

    pub fn p99_ms(&self) -> f64 {
        self.latency_hist.quantile(0.99)
    }
}

fn deser_u16_lenient<'de, D>(deserializer: D) -> std::result::Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = f64::deserialize(deserializer)?;
    if !v.is_finite() || v < 0.0 {
        return Ok(0);
    }
    Ok(v.round().min(u16::MAX as f64) as u16)
}

fn deser_u8_lenient<'de, D>(deserializer: D) -> std::result::Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = f64::deserialize(deserializer)?;
    if !v.is_finite() || v < 0.0 {
        return Ok(0);
    }
    Ok(v.round().min(u8::MAX as f64) as u8)
}

fn deser_i16_lenient<'de, D>(deserializer: D) -> std::result::Result<i16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = f64::deserialize(deserializer)?;
    if !v.is_finite() {
        return Ok(0);
    }
    Ok(v.round().clamp(i16::MIN as f64, i16::MAX as f64) as i16)
}

fn deser_u32_lenient<'de, D>(deserializer: D) -> std::result::Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = f64::deserialize(deserializer)?;
    if !v.is_finite() || v < 0.0 {
        return Ok(0);
    }
    Ok(v.round().min(u32::MAX as f64) as u32)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientJsFingerprint {
    #[serde(default)]
    pub webdriver: bool,
    #[serde(default)]
    pub webgl: String,
    #[serde(default)]
    pub webgl_vendor: String,
    #[serde(default)]
    pub webgl_ext_hash: String,
    #[serde(default, deserialize_with = "deser_u32_lenient")]
    pub webgl_max_tex: u32,
    #[serde(default)]
    pub platform: String,
    #[serde(default)]
    pub screen: String,
    #[serde(default)]
    pub avail_screen: String,
    #[serde(default)]
    pub tz: String,
    #[serde(default, deserialize_with = "deser_i16_lenient")]
    pub tz_offset: i16,
    #[serde(default)]
    pub intl_locale: String,
    #[serde(default)]
    pub lang: String,
    #[serde(default)]
    pub languages: String,
    #[serde(default)]
    pub ua_brands: String,
    #[serde(default, deserialize_with = "deser_u16_lenient")]
    pub cores: u16,
    #[serde(default, deserialize_with = "deser_u16_lenient")]
    pub mem: u16,
    #[serde(default, deserialize_with = "deser_u8_lenient")]
    pub touch: u8,
    #[serde(default)]
    pub canvas_hash: String,
    #[serde(default)]
    pub audio_hash: String,
    #[serde(default)]
    pub fonts_hash: String,
    #[serde(default, deserialize_with = "deser_u16_lenient")]
    pub fonts_count: u16,
    #[serde(default)]
    pub dpr: String,
    #[serde(default)]
    pub media_prefs: String,
    #[serde(default)]
    pub storage_flags: String,
    #[serde(default, deserialize_with = "deser_u16_lenient")]
    pub plugins_count: u16,
    #[serde(default, deserialize_with = "deser_u16_lenient")]
    pub speech_voices: u16,
    #[serde(default)]
    pub tamper_flags: Vec<String>,
    /// WebRTC ICE leak status: `"" | "unsupported" | "blocked" | "no_candidates" | "mdns_only" | "leaked"`.
    #[serde(default)]
    pub webrtc_status: String,
    /// Public IPv4/IPv6 addresses (or masked `/24` `/48` subnets when `store_raw_ip: false`) discovered via WebRTC ICE.
    #[serde(default)]
    pub webrtc_public_ips: Vec<String>,
    /// Private/LAN IP addresses exposed via WebRTC host ICE candidates.
    #[serde(default)]
    pub webrtc_local_ips: Vec<String>,
    /// Whether mDNS `.local` host candidates were observed instead of raw LAN IPs.
    #[serde(default)]
    pub webrtc_mdns: bool,
    /// Server-authoritative verdict: `true` iff public WebRTC ICE IP(s) do not match the observed client IP.
    #[serde(default)]
    pub webrtc_ip_mismatch: bool,
}

fn clean_fp_str(raw: &str, max_len: usize) -> String {
    raw.chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .take(max_len)
        .collect::<String>()
        .trim()
        .to_string()
}

fn format_public_ip_cidr(ip: std::net::IpAddr) -> String {
    match crate::routing::canonical_ip(ip) {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
    }
}

fn normalize_webrtc_public_entry(raw: &str) -> Option<String> {
    let s = raw.trim();
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        let canon = crate::routing::canonical_ip(ip);
        return crate::routing::is_public_routable_ip(canon).then(|| canon.to_string());
    }
    if let Some((addr_s, pref_s)) = s.split_once('/') {
        let ip = addr_s.trim().parse::<std::net::IpAddr>().ok()?;
        let canon = crate::routing::canonical_ip(ip);
        if !crate::routing::is_public_routable_ip(canon) {
            return None;
        }
        let valid_prefix = (canon.is_ipv4() && pref_s.trim() == "24")
            || (canon.is_ipv6() && pref_s.trim() == "48");
        if valid_prefix {
            return Some(format_public_ip_cidr(canon));
        }
    }
    None
}

fn push_unique_bounded(list: &mut Vec<String>, val: String, max_len: usize) {
    if list.len() < max_len && !list.iter().any(|x| x == &val) {
        list.push(val);
    }
}

impl ClientJsFingerprint {
    pub fn sanitize(&mut self) {
        self.webgl = clean_fp_str(&self.webgl, 96);
        self.webgl_vendor = clean_fp_str(&self.webgl_vendor, 64);
        self.webgl_ext_hash = clean_fp_str(&self.webgl_ext_hash, 32);
        self.platform = clean_fp_str(&self.platform, 32);
        self.screen = clean_fp_str(&self.screen, 32);
        self.avail_screen = clean_fp_str(&self.avail_screen, 32);
        self.tz = clean_fp_str(&self.tz, 48);
        self.intl_locale = clean_fp_str(&self.intl_locale, 48);
        self.lang = clean_fp_str(&self.lang, 24);
        self.languages = clean_fp_str(&self.languages, 96);
        self.ua_brands = clean_fp_str(&self.ua_brands, 96);
        self.canvas_hash = clean_fp_str(&self.canvas_hash, 32);
        self.audio_hash = clean_fp_str(&self.audio_hash, 32);
        self.fonts_hash = clean_fp_str(&self.fonts_hash, 32);
        self.dpr = clean_fp_str(&self.dpr, 16);
        self.media_prefs = clean_fp_str(&self.media_prefs, 64);
        self.storage_flags = clean_fp_str(&self.storage_flags, 64);
        self.tamper_flags = self
            .tamper_flags
            .iter()
            .take(12)
            .map(|f| clean_fp_str(f, 32))
            .filter(|f| !f.is_empty())
            .collect();
        self.webrtc_status = match self.webrtc_status.trim() {
            "unsupported" | "blocked" | "no_candidates" | "mdns_only" | "leaked" => {
                self.webrtc_status.trim().to_string()
            }
            _ => String::new(),
        };
        let mut clean_pubs = Vec::new();
        for raw in &self.webrtc_public_ips {
            if let Some(norm) = normalize_webrtc_public_entry(raw) {
                push_unique_bounded(&mut clean_pubs, norm, 4);
            }
        }
        self.webrtc_public_ips = clean_pubs;
        let mut clean_locals = Vec::new();
        for raw in &self.webrtc_local_ips {
            if let Ok(ip) = raw.trim().parse::<std::net::IpAddr>() {
                let canon = crate::routing::canonical_ip(ip);
                if !crate::routing::is_public_routable_ip(canon) {
                    push_unique_bounded(&mut clean_locals, canon.to_string(), 4);
                }
            }
        }
        self.webrtc_local_ips = clean_locals;
    }

    /// Recomputes `webrtc_ip_mismatch` server-side from validated `webrtc_public_ips` against
    /// the real TCP peer IP and records `webrtc_ip_leak` / `webrtc_lan_leak` advisory flags.
    pub fn evaluate_webrtc_against_client_ip(&mut self, observed_ip: std::net::IpAddr) {
        self.webrtc_ip_mismatch = false;
        let canon_obs = crate::routing::canonical_ip(observed_ip);
        if crate::routing::is_public_routable_ip(canon_obs) && !self.webrtc_public_ips.is_empty() {
            let raw_pubs: Vec<std::net::IpAddr> = self
                .webrtc_public_ips
                .iter()
                .filter_map(|s| s.parse::<std::net::IpAddr>().ok().map(crate::routing::canonical_ip))
                .collect();
            if !raw_pubs.is_empty() && !raw_pubs.contains(&canon_obs) {
                self.webrtc_ip_mismatch = true;
                push_unique_bounded(&mut self.tamper_flags, "webrtc_ip_leak".into(), 12);
            }
        }
        if !self.webrtc_local_ips.is_empty() {
            push_unique_bounded(&mut self.tamper_flags, "webrtc_lan_leak".into(), 12);
        }
    }

    /// Masks raw public IPv4/IPv6 strings in `webrtc_public_ips` into `/24` / `/48` prefixes
    /// when `store_raw_ip` is disabled.
    pub fn mask_raw_ips(&mut self) {
        let mut masked = Vec::new();
        for entry in &self.webrtc_public_ips {
            if let Some(norm) = normalize_webrtc_public_entry(entry) {
                let cidr = norm
                    .parse::<std::net::IpAddr>()
                    .map(format_public_ip_cidr)
                    .unwrap_or(norm);
                push_unique_bounded(&mut masked, cidr, 4);
            }
        }
        self.webrtc_public_ips = masked;
    }

    pub fn canonical_hash(&self) -> String {
        let canonical = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.screen,
            self.tz,
            self.lang,
            self.platform,
            self.cores,
            self.mem,
            self.touch,
            self.webgl,
            self.webgl_ext_hash,
            self.canvas_hash,
            self.audio_hash,
            self.fonts_hash,
            self.dpr,
            self.media_prefs,
        );
        crate::crypto::short_sha256_hex(&canonical)
    }

    /// Auxiliary client-side headless & tamper detector.
    /// NOTE: Client JS signals are UNTRUSTED and may only flag anomalies/headless tampering;
    /// they must NEVER reduce server-side suspicion scores or grant trust by themselves.
    pub fn detect_headless(&self, ua: &str) -> bool {
        let webgl_l = self.webgl.to_ascii_lowercase();
        let plat_l = self.platform.to_ascii_lowercase();
        let ua_l = ua.to_ascii_lowercase();

        // 1. Direct automation / headless / tamper signals
        let is_sw_renderer = webgl_l.contains("swiftshader")
            || webgl_l.contains("llvmpipe")
            || webgl_l.contains("mesa offscreen");
        if self.webdriver
            || webgl_l.contains("headless")
            || (is_sw_renderer && self.plugins_count == 0)
            || self.tamper_flags.iter().any(|f| {
                matches!(
                    f.as_str(),
                    "playwright"
                        | "puppeteer"
                        | "selenium"
                        | "phantom"
                        | "zero_outer_dims"
                        | "native_fn_tampered"
                )
            })
        {
            return true;
        }

        // 2. Cross-field OS vs navigator.platform consistency checks
        if !plat_l.is_empty() {
            if ua_l.contains("windows nt") && (plat_l.contains("linux") || plat_l.contains("mac")) {
                return true;
            }
            if (ua_l.contains("macintosh") || ua_l.contains("mac os x"))
                && !ua_l.contains("iphone")
                && !ua_l.contains("ipad")
                && (plat_l.contains("win") || plat_l.contains("linux"))
            {
                return true;
            }
            if ua_l.contains("linux")
                && !ua_l.contains("android")
                && (plat_l.contains("win") || plat_l.contains("mac"))
            {
                return true;
            }
            if ua_l.contains("iphone")
                && (plat_l.contains("win") || plat_l.contains("linux") || plat_l.contains("macintel"))
            {
                return true;
            }
            if ua_l.contains("ipad") && (plat_l.contains("win") || plat_l.contains("linux")) {
                return true;
            }
            if ua_l.contains("android") && (plat_l.contains("win") || plat_l.contains("mac")) {
                return true;
            }
        }

        // 3. Malformed / fabricated canvas_hash or screen dimensions
        if !self.canvas_hash.is_empty()
            && (self.canvas_hash.len() < 6
                || !self.canvas_hash.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return true;
        }
        if !self.screen.is_empty() {
            let parts: Vec<&str> = self.screen.split('x').collect();
            let valid_dims = parts.len() >= 2
                && parts[0].parse::<u32>().map(|w| w > 0).unwrap_or(false)
                && parts[1].parse::<u32>().map(|h| h > 0).unwrap_or(false);
            if !valid_dims {
                return true;
            }
        }

        // 4. Completely empty fingerprint claiming to be a standard browser
        if ua_l.contains("mozilla/")
            && self.cores == 0
            && self.platform.is_empty()
            && self.tz.is_empty()
            && self.canvas_hash.is_empty()
            && self.screen.is_empty()
        {
            return true;
        }

        false
    }
}

/// Rich visitor & browser fingerprint observation aggregated across Node -> Maintainer -> Control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintObservation {
    /// Composite key: `<ip_hmac>:<fp_hash>` (deduplicates same visitor + browser FP).
    pub id: String,
    pub ip_hmac: String,
    /// Raw client IP (populated only when `store_raw_ip: true`).
    #[serde(default)]
    pub client_ip: Option<String>,
    /// Masked IP subnet prefix (e.g. `203.0.113.0/24` or `2001:db8:1::/48`).
    #[serde(default)]
    pub ip_prefix: String,
    /// Browser JS fingerprint hash (when JS-verified) or server-side UA/header hash.
    pub fp_hash: String,
    #[serde(default)]
    pub js_verified: bool,
    /// `"none" | "beacon" | "pow"`
    #[serde(default)]
    pub fp_source: String,
    pub node_tag: String,
    pub service_tag: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub user_agent: String,
    #[serde(default)]
    pub accept_language: String,
    #[serde(default)]
    pub device_type: String,
    #[serde(default)]
    pub browser_family: String,
    #[serde(default)]
    pub os_family: String,
    #[serde(default)]
    pub is_bot: bool,
    #[serde(default)]
    pub is_headless: bool,
    #[serde(default)]
    pub suspicion_score: u8,
    #[serde(default)]
    pub tls_cipher_count: u16,
    #[serde(default)]
    pub tls_alpn: bool,
    /// Unforgeable server-observed TLS ClientHello fingerprint (JA3-like hash).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ja3: Option<String>,
    /// Whether TLS ClientHello included RFC 8701 GREASE values (present in modern browsers, rare in bots).
    #[serde(default)]
    pub tls_grease: bool,
    /// Server-side AbuseIPDB confidence score (0..=100, higher = more abusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abuse_score: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abuse_country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abuse_isp: Option<String>,
    #[serde(default)]
    pub abuse_is_tor: bool,
    /// Locally resolved ISO-3166-1 alpha-2 country code from Node GeoIP DB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geo_country: Option<String>,
    /// Locally resolved continent code (`AS|EU|NA|SA|AF|OC|AN`) from Node GeoIP DB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geo_continent: Option<String>,
    #[serde(default)]
    pub js_fp: Option<ClientJsFingerprint>,
    pub first_seen_ts: i64,
    pub last_seen_ts: i64,
    pub request_count: u64,
    #[serde(default)]
    pub challenge_count: u64,
    #[serde(default)]
    pub rate_limited_count: u64,
}

impl FingerprintObservation {
    pub fn sanitize(&mut self) {
        self.id = clean_fp_str(&self.id, 64);
        self.ip_hmac = clean_fp_str(&self.ip_hmac, 32);
        if let Some(ref mut ip) = self.client_ip {
            *ip = clean_fp_str(ip, 64);
        }
        self.ip_prefix = clean_fp_str(&self.ip_prefix, 64);
        self.fp_hash = clean_fp_str(&self.fp_hash, 32);
        self.fp_source = clean_fp_str(&self.fp_source, 16);
        self.host = clean_fp_str(&self.host, 128);
        self.user_agent = clean_fp_str(&self.user_agent, 320);
        self.accept_language = clean_fp_str(&self.accept_language, 64);
        self.device_type = clean_fp_str(&self.device_type, 32);
        self.browser_family = clean_fp_str(&self.browser_family, 32);
        self.os_family = clean_fp_str(&self.os_family, 32);
        if let Some(ref mut ja3) = self.tls_ja3 {
            *ja3 = clean_fp_str(ja3, 40);
        }
        if let Some(ref mut cc) = self.abuse_country {
            *cc = clean_fp_str(cc, 8);
        }
        if let Some(ref mut isp) = self.abuse_isp {
            *isp = clean_fp_str(isp, 96);
        }
        if let Some(ref mut gc) = self.geo_country {
            *gc = clean_fp_str(gc, 8);
        }
        if let Some(ref mut gct) = self.geo_continent {
            *gct = clean_fp_str(gct, 8);
        }
        if let Some(ref mut js) = self.js_fp {
            js.sanitize();
        }
    }

    pub fn merge_from(&mut self, other: &FingerprintObservation) {
        if other.first_seen_ts > 0 && (self.first_seen_ts == 0 || other.first_seen_ts < self.first_seen_ts) {
            self.first_seen_ts = other.first_seen_ts;
        }
        if other.last_seen_ts >= self.last_seen_ts {
            self.last_seen_ts = other.last_seen_ts;
            if !other.node_tag.is_empty() {
                self.node_tag = other.node_tag.clone();
            }
            if !other.service_tag.is_empty() {
                self.service_tag = other.service_tag.clone();
            }
            if !other.host.is_empty() {
                self.host = other.host.clone();
            }
            if !other.user_agent.is_empty() {
                self.user_agent = other.user_agent.clone();
            }
            if !other.accept_language.is_empty() {
                self.accept_language = other.accept_language.clone();
            }
        }
        if self.client_ip.is_none() && other.client_ip.is_some() {
            self.client_ip = other.client_ip.clone();
        }
        if self.ip_prefix.is_empty() && !other.ip_prefix.is_empty() {
            self.ip_prefix = other.ip_prefix.clone();
        }
        self.request_count = self.request_count.saturating_add(other.request_count);
        self.challenge_count = self.challenge_count.saturating_add(other.challenge_count);
        self.rate_limited_count = self
            .rate_limited_count
            .saturating_add(other.rate_limited_count);
        self.suspicion_score = self.suspicion_score.max(other.suspicion_score);
        self.is_bot |= other.is_bot;
        self.is_headless |= other.is_headless;
        if other.tls_cipher_count > 0 {
            self.tls_cipher_count = other.tls_cipher_count;
            self.tls_alpn = other.tls_alpn;
            self.tls_grease |= other.tls_grease;
            if other.tls_ja3.is_some() {
                self.tls_ja3 = other.tls_ja3.clone();
            }
        }
        if let Some(sc) = other.abuse_score {
            self.abuse_score = Some(self.abuse_score.map_or(sc, |old| old.max(sc)));
        }
        if other.abuse_country.is_some() {
            self.abuse_country = other.abuse_country.clone();
        }
        if other.abuse_isp.is_some() {
            self.abuse_isp = other.abuse_isp.clone();
        }
        self.abuse_is_tor |= other.abuse_is_tor;
        if other.geo_country.is_some() {
            self.geo_country = other.geo_country.clone();
        }
        if other.geo_continent.is_some() {
            self.geo_continent = other.geo_continent.clone();
        }
        if other.js_verified {
            self.js_verified = true;
            if other.fp_source == "pow" || self.fp_source.is_empty() || self.fp_source == "none" {
                self.fp_source = other.fp_source.clone();
            }
            if other.js_fp.is_some() {
                self.js_fp = other.js_fp.clone();
            }
        } else if self.js_fp.is_none() && other.js_fp.is_some() {
            self.js_fp = other.js_fp.clone();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkStatusSnapshot {
    pub node_tag: String,
    pub peer_tag: String,
    pub endpoint: String,
    pub state: LinkHealthState,
    pub rtt_ms: Option<u64>,
    pub loss_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertStatusInfo {
    pub domain: String,
    pub targets: Vec<String>,
    pub expires_at: Option<String>,
    pub last_renewed: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRecord {
    pub timestamp: String,
    pub source: String,
    pub severity: String,
    pub message: String,
}

/// Attacker deception & exploit-verification session report collected by `evilpot` on an Ingress node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvilpotSessionInfo {
    pub client_ip: String,
    pub epoch_id: u64,
    pub persona_hostname: String,
    pub first_seen_unix: u64,
    pub last_seen_unix: u64,
    pub total_trapped_requests: u64,
    /// `"probing"` | `"multi_step_exploitation"` | `"verified_exploit"`
    pub status: String,
    pub canary_triggers: u32,
    pub sqli_probes: u32,
    pub sqli_distinct_positions: usize,
    #[serde(default)]
    pub rce_commands_executed: Vec<String>,
    #[serde(default)]
    pub captured_iocs: Vec<String>,
    #[serde(default)]
    pub distinct_paths: Vec<String>,
    pub tarpit_bytes_consumed: u64,
    pub tarpit_max_duration_ms: u64,
    #[serde(default)]
    pub evidence: Vec<String>,
}

/// Individual deception / exploit-verification threat event recorded by `evilpot`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvilpotEventInfo {
    pub timestamp_unix: u64,
    pub epoch_id: u64,
    pub persona_hostname: String,
    pub client_ip: String,
    pub verification_status: String,
    pub trap_kind: String,
    pub detail: String,
    #[serde(default)]
    pub evidence: Vec<String>,
}

/// Active auto-ban entry for a confirmed attacker IP or fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveBanInfo {
    /// `"ip"` | `"js_fp"` | `"composite_fp"`
    pub kind: String,
    pub target: String,
    pub reason: String,
    pub banned_at_unix: u64,
    pub expires_at_unix: u64,
    pub offense_level: u8,
    pub hits_blocked: u64,
}

/// Per-node `evilpot` honeypot metrics, tracked attacker sessions, recent deception events,
/// and active auto-ban state for confirmed attacker IPs & fingerprints.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvilpotNodeReport {
    pub node_tag: String,
    pub current_epoch: u64,
    pub rotations_completed: u64,
    pub requests_handled: u64,
    pub traps_triggered: u64,
    pub canary_verifications: u64,
    pub verified_attack_sessions: u64,
    pub tarpit_bytes_dripped: u64,
    pub active_tarpit_connections: usize,
    #[serde(default)]
    pub active_ip_bans: usize,
    #[serde(default)]
    pub active_fp_bans: usize,
    #[serde(default)]
    pub total_auto_bans: u64,
    #[serde(default)]
    pub total_ban_drops: u64,
    #[serde(default)]
    pub sessions: Vec<EvilpotSessionInfo>,
    #[serde(default)]
    pub recent_events: Vec<EvilpotEventInfo>,
    #[serde(default)]
    pub active_bans: Vec<ActiveBanInfo>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hll_union_and_histogram_merge() {
        let mut a = HyperLogLog::new(10, 42);
        let mut b = HyperLogLog::new(10, 42);
        for i in 0..500 {
            a.insert(&format!("ip-{i}"));
        }
        for i in 250..750 {
            b.insert(&format!("ip-{i}"));
        }
        a.merge(&b);
        let est = a.estimate();
        assert!(est > 600.0 && est < 900.0, "unexpected HLL estimate: {est}");

        // Exact cardinality for small sets (<= 512)
        let mut small_a = HyperLogLog::new(12, 42);
        let mut small_b = HyperLogLog::new(12, 42);
        for i in 0..10 {
            small_a.insert(&format!("user-{i}"));
        }
        for i in 5..15 {
            small_b.insert(&format!("user-{i}"));
        }
        assert_eq!(small_a.estimate(), 10.0);
        small_a.merge(&small_b);
        assert_eq!(small_a.estimate(), 15.0);

        // Malformed deserialized HLL must not panic or return NaN
        let mut bad = HyperLogLog {
            precision: 0,
            seed: 1,
            registers: vec![],
            exact_set: BTreeSet::new(),
            exact_overflow: false,
        };
        bad.insert("test");
        assert_eq!(bad.estimate(), 0.0);

        let buckets = vec![10.0, 50.0, 100.0, 500.0];
        let mut h1 = LatencyHistogram::new(buckets.clone());
        let mut h2 = LatencyHistogram::new(buckets);
        for _ in 0..50 {
            h1.observe(8.0);
        }
        for _ in 0..50 {
            h2.observe(90.0);
        }
        h1.merge(&h2);
        assert_eq!(h1.total(), 100);
        assert!(h1.quantile(0.50) <= 10.0);
        assert!(h1.quantile(0.95) > 50.0 && h1.quantile(0.95) <= 100.0);
    }

    #[test]
    fn url_query_referer_sanitization_redacts_secrets_and_bounds_lengths() {
        let long_path = format!("/api/v1/{}?bad\r\ninject", "a".repeat(300));
        let clean_path = sanitize_url_path(&long_path);
        assert!(clean_path.chars().count() <= 256);
        assert!(!clean_path.contains('\r') && !clean_path.contains('\n'));
        assert!(clean_path.ends_with('…'));

        let raw_q = "page=2&q=hello&token=supersecret123&api_key=abc&password=pw1&auth=xyz&secret=s1&sort=desc";
        let redacted = sanitize_and_redact_query(raw_q);
        assert!(redacted.contains("page=2"));
        assert!(redacted.contains("q=hello"));
        assert!(redacted.contains("sort=desc"));
        assert!(redacted.contains("token=[REDACTED]"));
        assert!(redacted.contains("api_key=[REDACTED]"));
        assert!(redacted.contains("password=[REDACTED]"));
        assert!(redacted.contains("auth=[REDACTED]"));
        assert!(redacted.contains("secret=[REDACTED]"));
        assert!(!redacted.contains("supersecret123"));
        assert!(!redacted.contains("pw1"));

        let long_q = (0..100)
            .map(|i| format!("k{i}={}", "x".repeat(20)))
            .collect::<Vec<_>>()
            .join("&");
        assert!(sanitize_and_redact_query(&long_q).chars().count() <= 256);

        let rf = sanitize_referer("https://app.example.com/login?token=leak#frag\r\n");
        assert_eq!(rf, "https://app.example.com/login");

        let mut rec = SessionSummary {
            node_tag: "n1\n".into(),
            role: "ingress".into(),
            service_tag: "svc".into(),
            path: Some(format!("/{}", "p".repeat(300))),
            query: Some("token=secret999&page=1".into()),
            referer: Some("https://ref.example.com/p?code=123#hash".into()),
            repeat_count: 0,
            ..Default::default()
        };
        rec.sanitize();
        assert_eq!(rec.node_tag, "n1");
        assert_eq!(rec.path.as_deref().unwrap().chars().count(), 256);
        assert_eq!(rec.query.as_deref(), Some("token=[REDACTED]&page=1"));
        assert_eq!(rec.referer.as_deref(), Some("https://ref.example.com/p"));
        assert_eq!(rec.repeat_count, 1);

        // Legacy SessionSummary without new fields must deserialize cleanly
        let legacy_json = r#"{"timestamp_ms":1700000000000,"node_tag":"n","role":"ingress","service_tag":"s","status":200,"latency_ms":1.0,"bytes_in":1,"bytes_out":2,"ip_hmac":"abcd"}"#;
        let parsed: SessionSummary = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(parsed.repeat_count, 1);
        assert!(parsed.path.is_none());
    }

    #[test]
    fn webrtc_leak_detection_validates_ips_detects_mismatch_and_respects_privacy() {
        let mut fp = ClientJsFingerprint {
            webgl: "ANGLE (NVIDIA)".into(),
            canvas_hash: "a1b2c3d4".into(),
            screen: "1920x1080x24".into(),
            webrtc_status: "leaked".into(),
            webrtc_public_ips: vec![
                "9.9.9.9".into(),
                "127.0.0.1".into(), // private/loopback rejected from public list
                "not-an-ip".into(), // junk rejected
                "9.9.9.9".into(),   // duplicate collapsed
            ],
            webrtc_local_ips: vec![
                "192.168.1.42".into(),
                "8.8.8.8".into(), // public IP rejected from local list
            ],
            webrtc_ip_mismatch: true, // client-spoofed value must NOT be blindly trusted
            ..Default::default()
        };

        fp.sanitize();
        assert_eq!(fp.webrtc_public_ips, vec!["9.9.9.9"]);
        assert_eq!(fp.webrtc_local_ips, vec!["192.168.1.42"]);

        // Same public IP as HTTP peer -> spoofed webrtc_ip_mismatch is cleared
        let base_hash = fp.canonical_hash();
        fp.evaluate_webrtc_against_client_ip("9.9.9.9".parse().unwrap());
        assert!(!fp.webrtc_ip_mismatch);
        assert!(!fp.tamper_flags.iter().any(|f| f == "webrtc_ip_leak"));
        assert!(fp.tamper_flags.iter().any(|f| f == "webrtc_lan_leak"));
        // VPN/network leak never triggers false headless rejection
        assert!(!fp.detect_headless("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0"));
        // Canonical fingerprint hash stays invariant across network IPs
        assert_eq!(fp.canonical_hash(), base_hash);

        // HTTP peer differs from WebRTC public IP -> server marks webrtc_ip_mismatch
        fp.evaluate_webrtc_against_client_ip("1.1.1.1".parse().unwrap());
        assert!(fp.webrtc_ip_mismatch);
        assert!(fp.tamper_flags.iter().any(|f| f == "webrtc_ip_leak"));

        // Privacy masking for store_raw_ip = false preserves mismatch flag & masked /24 CIDR across re-sanitize
        fp.mask_raw_ips();
        assert_eq!(fp.webrtc_public_ips, vec!["9.9.9.0/24"]);
        fp.sanitize();
        assert_eq!(fp.webrtc_public_ips, vec!["9.9.9.0/24"]);
        assert!(fp.webrtc_ip_mismatch);
    }

    #[test]
    fn session_summary_sanitize_preserves_full_uuid_ray_id() {
        let full_uuid = "550e8400-e29b-41d4-a716-446655440000";
        let mut rec = SessionSummary {
            ray_id: Some(full_uuid.to_string()),
            ..Default::default()
        };
        rec.sanitize();
        assert_eq!(rec.ray_id.as_deref(), Some(full_uuid));
    }

    #[test]
    fn minute_summary_and_mitigation_helpers_classify_blocks_cache_and_origin_403_accurately() {
        let mut sum = MinuteSummary::new(1_700_000_040, "n1", "ingress", "svc", 10, 1, vec![10.0]);

        let waf_blk = SessionSummary {
            status: 403,
            action: Some("waf_block".into()),
            ip_hmac: "ip-waf".into(),
            ..Default::default()
        };
        let origin_403 = SessionSummary {
            status: 403,
            action: Some("allow".into()),
            ip_hmac: "ip-origin".into(),
            ..Default::default()
        };
        let canary = SessionSummary {
            status: 200,
            action: Some("evilpot_canary".into()),
            ip_hmac: "ip-canary".into(),
            ..Default::default()
        };
        let cached = SessionSummary {
            status: 200,
            bytes_out: 512,
            action: Some("cache_hit".into()),
            cache_status: Some("HIT".into()),
            ip_hmac: "ip-cache".into(),
            ..Default::default()
        };
        let stale = SessionSummary {
            status: 200,
            bytes_out: 256,
            action: Some("cache_stale".into()),
            cache_status: Some("STALE".into()),
            ip_hmac: "ip-stale".into(),
            ..Default::default()
        };

        sum.record(&waf_blk);
        sum.record(&origin_403);
        sum.record(&canary);
        sum.record(&cached);
        sum.record(&stale);

        assert_eq!(sum.requests, 5);
        assert_eq!(sum.errors, 0);
        assert_eq!(sum.challenges_issued, 0);
        assert_eq!(sum.blocked, 2); // waf_block + evilpot_canary (NOT origin_403)
        assert_eq!(sum.cached_requests, 2); // HIT + STALE
        assert_eq!(sum.cached_bytes_out, 768);

        assert!(is_mitigated_record(&waf_blk));
        assert!(!is_mitigated_record(&origin_403));
        assert!(is_mitigated_record(&canary));
        assert!(!is_mitigated_record(&cached));
    }
}
