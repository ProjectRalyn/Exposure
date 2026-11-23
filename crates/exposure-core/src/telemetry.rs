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

/// Individual session log record written to segment files (production layer).
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
    #[serde(default)]
    pub raw_ip: Option<String>,
    #[serde(default)]
    pub rate_limited: bool,
    #[serde(default)]
    pub challenged: bool,
    #[serde(default)]
    pub challenge_passed: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub device_type: Option<String>,
    #[serde(default)]
    pub browser_family: Option<String>,
    #[serde(default)]
    pub os_family: Option<String>,
    #[serde(default)]
    pub client_fp_verified: bool,
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
            bytes_in: 0,
            bytes_out: 0,
            uv_hll: HyperLogLog::new(hll_precision, hll_seed),
            latency_hist: LatencyHistogram::new(buckets_ms),
            device_counts: std::collections::BTreeMap::new(),
            browser_counts: std::collections::BTreeMap::new(),
            os_counts: std::collections::BTreeMap::new(),
            client_fp_verified: 0,
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
        self.uv_hll.insert(&rec.ip_hmac);
        self.latency_hist.observe(rec.latency_ms);
    }

    pub fn merge_from(&mut self, other: &MinuteSummary) {
        self.requests = self.requests.saturating_add(other.requests);
        self.errors = self.errors.saturating_add(other.errors);
        self.rate_limited = self.rate_limited.saturating_add(other.rate_limited);
        self.challenges_issued = self.challenges_issued.saturating_add(other.challenges_issued);
        self.challenges_passed = self.challenges_passed.saturating_add(other.challenges_passed);
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientJsFingerprint {
    #[serde(default)]
    pub webdriver: bool,
    #[serde(default)]
    pub webgl: String,
    #[serde(default)]
    pub platform: String,
    #[serde(default)]
    pub screen: String,
    #[serde(default)]
    pub tz: String,
    #[serde(default)]
    pub lang: String,
    #[serde(default, deserialize_with = "deser_u16_lenient")]
    pub cores: u16,
    #[serde(default, deserialize_with = "deser_u16_lenient")]
    pub mem: u16,
    #[serde(default, deserialize_with = "deser_u8_lenient")]
    pub touch: u8,
    #[serde(default)]
    pub canvas_hash: String,
    #[serde(default)]
    pub dpr: String,
    #[serde(default, deserialize_with = "deser_u16_lenient")]
    pub plugins_count: u16,
}

fn clean_fp_str(raw: &str, max_len: usize) -> String {
    raw.chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .take(max_len)
        .collect::<String>()
        .trim()
        .to_string()
}

impl ClientJsFingerprint {
    pub fn sanitize(&mut self) {
        self.webgl = clean_fp_str(&self.webgl, 96);
        self.platform = clean_fp_str(&self.platform, 32);
        self.screen = clean_fp_str(&self.screen, 32);
        self.tz = clean_fp_str(&self.tz, 48);
        self.lang = clean_fp_str(&self.lang, 24);
        self.canvas_hash = clean_fp_str(&self.canvas_hash, 32);
        self.dpr = clean_fp_str(&self.dpr, 16);
    }

    pub fn canonical_hash(&self) -> String {
        let canonical = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.screen,
            self.tz,
            self.lang,
            self.platform,
            self.cores,
            self.mem,
            self.touch,
            self.webgl,
            self.canvas_hash,
            self.dpr,
        );
        crate::crypto::short_sha256_hex(&canonical)
    }

    pub fn detect_headless(&self, ua: &str) -> bool {
        let webgl_l = self.webgl.to_ascii_lowercase();
        let plat_l = self.platform.to_ascii_lowercase();
        let ua_l = ua.to_ascii_lowercase();

        // 1. Direct automation / headless signals (only flag SwiftShader/llvmpipe when plugins_count == 0
        //    so genuine desktop browsers with GPU acceleration disabled or in VMs aren't false-positived)
        let is_sw_renderer = webgl_l.contains("swiftshader")
            || webgl_l.contains("llvmpipe")
            || webgl_l.contains("mesa offscreen");
        if self.webdriver
            || webgl_l.contains("headless")
            || (is_sw_renderer && self.plugins_count == 0)
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

/// Per-node `evilpot` honeypot metrics, tracked attacker sessions, and recent deception events.
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
    pub sessions: Vec<EvilpotSessionInfo>,
    #[serde(default)]
    pub recent_events: Vec<EvilpotEventInfo>,
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
}
