use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::routing::LinkHealthState;

/// Deterministic HyperLogLog sketch with fixed precision and hash seed (DESIGN.md §4 & §12).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HyperLogLog {
    pub precision: u8,
    pub seed: u64,
    pub registers: Vec<u8>,
}

impl HyperLogLog {
    pub fn new(precision: u8, seed: u64) -> Self {
        let p = precision.clamp(4, 16);
        let m = 1usize << p;
        Self {
            precision: p,
            seed,
            registers: vec![0u8; m],
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
        if !self.is_valid() {
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
    }

    pub fn merge(&mut self, other: &HyperLogLog) {
        if !self.is_valid() || !other.is_valid() {
            return;
        }
        if self.precision != other.precision || self.seed != other.seed {
            return;
        }
        for (a, &b) in self.registers.iter_mut().zip(other.registers.iter()) {
            if b > *a {
                *a = b;
            }
        }
    }

    pub fn estimate(&self) -> f64 {
        if !self.is_valid() || self.registers.is_empty() {
            return 0.0;
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

/// Aggregated summary per `(node_tag, minute_epoch, service_tag)` pushed to Maintainer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinuteSummary {
    pub minute_epoch: i64,
    pub node_tag: String,
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
        service_tag: impl Into<String>,
        hll_precision: u8,
        hll_seed: u64,
        buckets_ms: Vec<f64>,
    ) -> Self {
        Self {
            minute_epoch,
            node_tag: node_tag.into(),
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

        // Malformed deserialized HLL must not panic or return NaN
        let mut bad = HyperLogLog {
            precision: 0,
            seed: 1,
            registers: vec![],
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
