use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

fn default_ttl() -> u8 {
    16
}
fn default_true() -> bool {
    true
}
fn default_weight() -> u32 {
    100
}
fn default_priority() -> u32 {
    10
}
fn default_probe_interval_ms() -> u64 {
    5000
}
fn default_probe_timeout_ms() -> u64 {
    2000
}
fn default_degraded_rtt_ms() -> u64 {
    250
}
fn default_degraded_loss_rate() -> f64 {
    0.05
}
fn default_down_failures() -> u32 {
    3
}
fn default_recover_successes() -> u32 {
    2
}
fn default_pow_difficulty() -> u8 {
    16
}
fn default_clearance_ttl_secs() -> u64 {
    600
}
fn default_hll_precision() -> u8 {
    12
}
fn default_hll_seed() -> u64 {
    0x517c_c1b7_2722_0a95
}
fn default_histogram_buckets() -> Vec<f64> {
    vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0]
}
fn default_sample_rate() -> f64 {
    1.0
}
fn default_flush_interval_secs() -> u64 {
    10
}
fn default_max_batch_records() -> usize {
    512
}
fn default_max_segment_bytes() -> u64 {
    16 * 1024 * 1024
}
fn default_max_disk_bytes() -> u64 {
    256 * 1024 * 1024
}
fn default_retention_hours() -> u64 {
    72
}
fn default_renew_before_days() -> u32 {
    30
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeRoles {
    #[serde(default)]
    pub ingress: bool,
    #[serde(default)]
    pub egress: bool,
    #[serde(default)]
    pub relay: bool,
    #[serde(default)]
    pub maintainer: bool,
}

impl NodeRoles {
    pub fn names(&self) -> Vec<String> {
        let mut v = Vec::new();
        if self.ingress {
            v.push("ingress".into());
        }
        if self.egress {
            v.push("egress".into());
        }
        if self.relay {
            v.push("relay".into());
        }
        if self.maintainer {
            v.push("maintainer".into());
        }
        v
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LinkMode {
    OnDemand,
    Tunnel,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TunnelDirection {
    Outbound,
    Inbound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEndpoint {
    pub address: String,
    #[serde(default = "default_priority")]
    pub priority: u32,
    #[serde(default = "default_weight")]
    pub weight: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    /// Logical peer tag used in local rules (defaults to node_tag when omitted by compiler).
    pub peer_tag: String,
    /// Target peer's unique Node Tag (used for Hop Table routing).
    pub node_tag: String,
    /// Expected ed25519 public key (base64) or SHA-256 fingerprint hex.
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub pubkey_fingerprint: Option<String>,
    pub mode: LinkMode,
    #[serde(default)]
    pub tunnel_direction: Option<TunnelDirection>,
    /// Optional auxiliary expected client IP/CIDR for inbound tunnels (mismatch logs WARN, keeps conn).
    #[serde(default)]
    pub expected_client_addr: Option<String>,
    #[serde(default)]
    pub endpoints: Vec<PeerEndpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeConfig {
    #[serde(default = "default_probe_interval_ms")]
    pub interval_ms: u64,
    #[serde(default = "default_probe_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_degraded_rtt_ms")]
    pub degraded_rtt_ms: u64,
    #[serde(default = "default_degraded_loss_rate")]
    pub degraded_loss_rate: f64,
    #[serde(default = "default_down_failures")]
    pub down_failures: u32,
    #[serde(default = "default_recover_successes")]
    pub recover_successes: u32,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            interval_ms: default_probe_interval_ms(),
            timeout_ms: default_probe_timeout_ms(),
            degraded_rtt_ms: default_degraded_rtt_ms(),
            degraded_loss_rate: default_degraded_loss_rate(),
            down_failures: default_down_failures(),
            recover_successes: default_recover_successes(),
        }
    }
}

fn default_js_fp_ttl_secs() -> u64 {
    3600
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkListenConfig {
    pub listen_addr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_on_demand: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_tunnel: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_bootstrap: Option<bool>,
}

impl LinkListenConfig {
    pub fn effective_allow_on_demand(&self) -> bool {
        self.allow_on_demand.unwrap_or(true)
    }
    pub fn effective_allow_tunnel(&self) -> bool {
        self.allow_tunnel.unwrap_or(true)
    }
    pub fn effective_allow_bootstrap(&self) -> bool {
        self.allow_bootstrap.unwrap_or(false)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum AntibotMode {
    #[default]
    Off,
    Silent,
    Challenge,
    /// Always require PoW clearance cookie regardless of browser fingerprint score (Under Attack mode).
    Always,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitBucket {
    pub capacity: f64,
    pub refill_per_sec: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_ip: Option<bool>,
}

impl RateLimitBucket {
    pub fn effective_per_ip(&self) -> bool {
        self.per_ip.unwrap_or(true)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardProfile {
    #[serde(default)]
    pub antibot: AntibotMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_bucket: Option<String>,
    #[serde(default)]
    pub allow_cidrs: Vec<String>,
    #[serde(default)]
    pub deny_cidrs: Vec<String>,
    /// Minimum suspicion score (0..100) to trigger PoW challenge or silent reject.
    #[serde(default = "default_challenge_threshold")]
    pub challenge_threshold: u8,
    /// Minimum suspicion score (0..100) to reject immediately (403).
    #[serde(default = "default_reject_threshold")]
    pub reject_threshold: u8,
    #[serde(default = "default_pow_difficulty")]
    pub pow_difficulty: u8,
    #[serde(default = "default_clearance_ttl_secs")]
    pub clearance_ttl_secs: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_ua: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_ip_prefix: Option<bool>,
    /// Authenticated API bypass rules formatted as `"Header-Name: expected-secret-value"`.
    #[serde(default)]
    pub api_bypass_headers: Vec<String>,
    /// Block known bot/scraper User-Agents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_bots: Option<bool>,
    /// Reject headless/automated browsers detected via JS WebGL/webdriver/platform cross-check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_headless: Option<bool>,
    /// Require a verified browser JS fingerprint bound to the clearance cookie.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_client_fp: Option<bool>,
    /// Inject passive JS fingerprint beacon into unverified HTML document responses (tri-state: Default/On/Off).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub js_fp_beacon: Option<bool>,
    /// Cooldown TTL in seconds before re-collecting passive JS fingerprint from the same browser.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub js_fp_ttl_secs: Option<u64>,
}

impl GuardProfile {
    pub fn effective_bind_ua(&self) -> bool {
        self.bind_ua.unwrap_or(true)
    }
    pub fn effective_bind_ip_prefix(&self) -> bool {
        self.bind_ip_prefix.unwrap_or(true)
    }
    pub fn effective_block_bots(&self) -> bool {
        self.block_bots.unwrap_or(false)
    }
    pub fn effective_block_headless(&self) -> bool {
        self.block_headless.unwrap_or(true)
    }
    pub fn effective_require_client_fp(&self) -> bool {
        self.require_client_fp.unwrap_or(false)
    }
    pub fn effective_js_fp_beacon(&self) -> bool {
        self.js_fp_beacon.unwrap_or(true)
    }
    pub fn effective_js_fp_ttl_secs(&self) -> u64 {
        self.js_fp_ttl_secs.unwrap_or_else(default_js_fp_ttl_secs).max(60)
    }
}

impl Default for GuardProfile {
    fn default() -> Self {
        Self {
            antibot: AntibotMode::Off,
            rate_limit_bucket: None,
            allow_cidrs: Vec::new(),
            deny_cidrs: Vec::new(),
            challenge_threshold: default_challenge_threshold(),
            reject_threshold: default_reject_threshold(),
            pow_difficulty: default_pow_difficulty(),
            clearance_ttl_secs: default_clearance_ttl_secs(),
            bind_ua: None,
            bind_ip_prefix: None,
            api_bypass_headers: Vec::new(),
            block_bots: None,
            block_headless: None,
            require_client_fp: None,
            js_fp_beacon: None,
            js_fp_ttl_secs: None,
        }
    }
}

fn default_challenge_threshold() -> u8 {
    50
}
fn default_reject_threshold() -> u8 {
    85
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleMatch {
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub url_prefix: Option<String>,
    #[serde(default)]
    pub source_cidrs: Vec<String>,
    #[serde(default)]
    pub sni: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressRule {
    #[serde(default)]
    pub name: Option<String>,
    pub r#match: RuleMatch,
    pub service_tag: String,
    /// Next hop Peer Tag, or this node's own `node_tag` / `"local"` for co-located egress.
    pub next_peer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intercept_errors: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub js_fp_beacon: Option<bool>,
}

impl IngressRule {
    pub fn effective_intercept_errors(&self) -> bool {
        self.intercept_errors.unwrap_or(false)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCertEntry {
    pub domain: String,
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressListener {
    pub listen_addr: String,
    #[serde(default)]
    pub tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressConfig {
    #[serde(default)]
    pub listeners: Vec<IngressListener>,
    #[serde(default)]
    pub rules: Vec<IngressRule>,
    #[serde(default)]
    pub guards: BTreeMap<String, GuardProfile>,
    #[serde(default)]
    pub rate_limit_buckets: BTreeMap<String, RateLimitBucket>,
    #[serde(default)]
    pub tls_certs: Vec<TlsCertEntry>,
    /// HMAC signing secret for Entry Guard challenges & clearance cookies (must be high-entropy random).
    #[serde(default)]
    pub clearance_secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_store_dir: Option<String>,
    #[serde(default = "default_server_header")]
    pub server_header: String,
    /// Node-level default for passive HTML JS fingerprint beacon injection (tri-state: Default/On/Off).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub js_fp_beacon: Option<bool>,
    /// Cooldown TTL in seconds before re-injecting passive JS fingerprint beacon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub js_fp_ttl_secs: Option<u64>,
}

impl IngressConfig {
    pub fn effective_js_fp_beacon(&self) -> bool {
        self.js_fp_beacon.unwrap_or(true)
    }
    pub fn effective_js_fp_ttl_secs(&self) -> u64 {
        self.js_fp_ttl_secs.unwrap_or_else(default_js_fp_ttl_secs).max(60)
    }
}

impl Default for IngressConfig {
    fn default() -> Self {
        Self {
            listeners: Vec::new(),
            rules: Vec::new(),
            guards: BTreeMap::new(),
            rate_limit_buckets: BTreeMap::new(),
            tls_certs: Vec::new(),
            clearance_secret: String::new(),
            cert_store_dir: None,
            server_header: default_server_header(),
            js_fp_beacon: None,
            js_fp_ttl_secs: None,
        }
    }
}

fn default_server_header() -> String {
    "nginx".into()
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum BackendProtocol {
    #[default]
    Http1,
    H2,
    Auto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalHealthCheckConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_hc_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_hc_timeout")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub http_path: Option<String>,
}

fn default_hc_interval() -> u64 {
    10
}
fn default_hc_timeout() -> u64 {
    2000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressServiceConfig {
    pub backend: String,
    #[serde(default)]
    pub protocol: BackendProtocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<bool>,
    /// Optional path to custom PEM root CA certificate bundle for verifying `tls: true` backends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_cert_path: Option<String>,
    /// Explicitly skip backend server certificate chain verification (still verifies TLS handshake signatures).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insecure_skip_verify: Option<bool>,
    /// Allowed origin ingress Node Tags. Empty => deny unless `allow_any_origin: true`.
    #[serde(default)]
    pub allow_from: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_any_origin: Option<bool>,
    #[serde(default = "default_backend_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intercept_errors: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_health_check: Option<LocalHealthCheckConfig>,
}

impl EgressServiceConfig {
    pub fn effective_tls(&self) -> bool {
        self.tls.unwrap_or(false)
    }
    pub fn effective_insecure_skip_verify(&self) -> bool {
        self.insecure_skip_verify.unwrap_or(false)
    }
    pub fn effective_allow_any_origin(&self) -> bool {
        self.allow_any_origin.unwrap_or(false)
    }
    pub fn effective_intercept_errors(&self) -> bool {
        self.intercept_errors.unwrap_or(false)
    }
}

fn default_backend_timeout_ms() -> u64 {
    30_000
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EgressConfig {
    #[serde(default)]
    pub services: BTreeMap<String, EgressServiceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayRule {
    pub service_tag: String,
    pub next_peer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelayConfig {
    #[serde(default)]
    pub rules: Vec<RelayRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentConfig {
    #[serde(default = "default_segment_dir")]
    pub dir: String,
    #[serde(default = "default_flush_interval_secs")]
    pub flush_interval_secs: u64,
    #[serde(default = "default_max_batch_records")]
    pub max_batch_records: usize,
    #[serde(default = "default_max_segment_bytes")]
    pub max_segment_bytes: u64,
    #[serde(default = "default_max_disk_bytes")]
    pub max_disk_bytes: u64,
    #[serde(default = "default_retention_hours")]
    pub retention_hours: u64,
}

fn default_segment_dir() -> String {
    "./data/segments".into()
}

impl Default for SegmentConfig {
    fn default() -> Self {
        Self {
            dir: default_segment_dir(),
            flush_interval_secs: default_flush_interval_secs(),
            max_batch_records: default_max_batch_records(),
            max_segment_bytes: default_max_segment_bytes(),
            max_disk_bytes: default_max_disk_bytes(),
            retention_hours: default_retention_hours(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggerConfig {
    /// HMAC key for pseudonymizing client IPs (auto-generated randomly if left empty on standalone nodes).
    #[serde(default)]
    pub hmac_key: String,
    #[serde(default)]
    pub store_raw_ip: bool,
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,
    #[serde(default = "default_hll_precision")]
    pub hll_precision: u8,
    #[serde(default = "default_hll_seed")]
    pub hll_seed: u64,
    #[serde(default = "default_histogram_buckets")]
    pub histogram_buckets_ms: Vec<f64>,
    #[serde(default)]
    pub segment: SegmentConfig,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            hmac_key: String::new(),
            store_raw_ip: false,
            sample_rate: default_sample_rate(),
            hll_precision: default_hll_precision(),
            hll_seed: default_hll_seed(),
            histogram_buckets_ms: default_histogram_buckets(),
            segment: SegmentConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum DnsProviderAccountConfig {
    Cloudflare {
        api_token: String,
    },
    #[serde(alias = "alidns")]
    Aliyun {
        access_key_id: String,
        access_key_secret: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        region_id: Option<String>,
    },
    Webhook {
        present_url: String,
        cleanup_url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sync_url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth_header: Option<String>,
    },
    Exec {
        command: String,
        #[serde(default)]
        args: Vec<String>,
    },
}

fn default_dns_ttl() -> u32 {
    600
}

/// Binding between a domain (apex, subdomain, or wildcard) and a named DNS provider account,
/// optionally carrying zone metadata and target nodes for declarative A/AAAA DNS sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainBindingConfig {
    /// Named account key in `dns_providers`.
    pub provider: String,
    /// Optional Cloudflare Zone ID (auto-queried via Cloudflare API when omitted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<String>,
    /// Optional hosted root/apex domain name (auto-detected when omitted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_domain: Option<String>,
    /// Target node tags whose configured `external_ips` are synced as A/AAAA records for this domain.
    #[serde(default)]
    pub target_nodes: Vec<String>,
    /// DNS record TTL in seconds (default 600).
    #[serde(default = "default_dns_ttl")]
    pub ttl: u32,
    /// Cloudflare proxy flag (ignored by non-Cloudflare providers).
    #[serde(default)]
    pub proxied: bool,
}

impl Default for DomainBindingConfig {
    fn default() -> Self {
        Self {
            provider: String::new(),
            zone_id: None,
            root_domain: None,
            target_nodes: Vec::new(),
            ttl: default_dns_ttl(),
            proxied: false,
        }
    }
}

/// Resolve a domain (e.g. `*.api.sub.example.com` or `api.sub.example.com`) against
/// `domains` using exact match first, then longest-suffix parent domain match.
pub fn resolve_domain_binding<'a>(
    domains: &'a BTreeMap<String, DomainBindingConfig>,
    target_domain: &str,
) -> Option<(&'a str, &'a DomainBindingConfig)> {
    let raw = target_domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if raw.is_empty() {
        return None;
    }
    let norm = raw.strip_prefix("*.").unwrap_or(&raw).to_string();

    // 1. Exact key match (including wildcard key if explicitly configured)
    for (k, v) in domains {
        let k_raw = k.trim().trim_end_matches('.').to_ascii_lowercase();
        if k_raw == raw {
            return Some((k.as_str(), v));
        }
    }

    // 2. Exact match after stripping `*.` on target_domain (against non-wildcard key)
    for (k, v) in domains {
        let k_raw = k.trim().trim_end_matches('.').to_ascii_lowercase();
        if !k_raw.starts_with("*.") && k_raw == norm {
            return Some((k.as_str(), v));
        }
    }

    // 3. Longest-suffix parent domain match (e.g. `a.b.example.com` -> `b.example.com` -> `example.com`)
    let mut best: Option<(&'a str, &'a DomainBindingConfig, usize)> = None;
    for (k, v) in domains {
        let k_raw = k.trim().trim_end_matches('.').to_ascii_lowercase();
        if k_raw.starts_with("*.") || k_raw.is_empty() {
            continue;
        }
        if norm.ends_with(&format!(".{k_raw}")) {
            let len = k_raw.len();
            if best.map(|(_, _, blen)| len > blen).unwrap_or(true) {
                best = Some((k.as_str(), v, len));
            }
        }
    }
    best.map(|(k, v, _)| (k, v))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertOrderConfig {
    pub domain: String,
    /// Optional DNS provider account override; when omitted, resolved via `domains` binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default)]
    pub target_nodes: Vec<String>,
    /// Explicit Hop Table from Maintainer to each target node (keyed by target node_tag).
    #[serde(default)]
    pub target_hops: BTreeMap<String, Vec<String>>,
    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AcmeConfig {
    #[serde(default)]
    pub directory_url: String,
    #[serde(default)]
    pub contact_email: String,
    #[serde(default)]
    pub orders: Vec<CertOrderConfig>,
    #[serde(default = "default_cert_dir")]
    pub storage_dir: String,
}

fn default_cert_dir() -> String {
    "./data/certs".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MaintainerConfig {
    /// Ed25519 private key (base64) generated and provisioned by Control for signing cert bundles.
    #[serde(default)]
    pub cert_signing_secret_key: Option<String>,
    #[serde(default)]
    pub is_primary_cert_manager: bool,
    #[serde(default)]
    pub logger: LoggerConfig,
    #[serde(default)]
    pub acme: AcmeConfig,
    /// Separated DNS provider credentials (multiple accounts per provider supported).
    #[serde(default)]
    pub dns_providers: BTreeMap<String, DnsProviderAccountConfig>,
    /// Separated domain bindings (used by DNS-01 cert orders and Control-authorized DNS sync).
    #[serde(default)]
    pub domains: BTreeMap<String, DomainBindingConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedMaintainer {
    pub node_tag: String,
    pub public_key: String,
}

/// Alias for trusted origin Ingress public keys provisioned onto Egress nodes for multi-hop ACL verification.
pub type TrustedOrigin = TrustedMaintainer;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub node_tag: String,
    /// Ed25519 link identity secret key (base64).
    pub identity_secret_key: String,
    /// Control's Ed25519 config-signing public key (installed during onboarding or pre-configured).
    #[serde(default)]
    pub control_public_key: Option<String>,
    /// Control's Ed25519 link-authentication public key (falls back to `control_public_key` when omitted).
    #[serde(default)]
    pub control_link_public_key: Option<String>,
    #[serde(default)]
    pub roles: NodeRoles,
    #[serde(default)]
    pub link_listener: Option<LinkListenConfig>,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    #[serde(default)]
    pub probe: ProbeConfig,
    #[serde(default = "default_ttl")]
    pub default_ttl: u8,
    /// Explicit Hop Table from this node to Maintainer for log & telemetry delivery.
    #[serde(default)]
    pub maintainer_hops: Vec<String>,
    #[serde(default)]
    pub trusted_maintainers: Vec<TrustedMaintainer>,
    /// Trusted origin Ingress public keys for verifying multi-hop `ServiceStreamHeader` signatures on Egress.
    #[serde(default)]
    pub trusted_origins: Vec<TrustedOrigin>,
    #[serde(default)]
    pub logger: LoggerConfig,
    #[serde(default)]
    pub ingress: IngressConfig,
    #[serde(default)]
    pub egress: EgressConfig,
    #[serde(default)]
    pub relay: RelayConfig,
    #[serde(default)]
    pub maintainer: Option<MaintainerConfig>,
    /// Bootstrap node address for initial active onboarding (cleared once enrolled).
    #[serde(default)]
    pub bootstrap_tunnel_addr: Option<String>,
    /// Config sequence currently applied (monotonic anti-rollback).
    #[serde(default)]
    pub config_sequence: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigBundlePurpose {
    #[default]
    Apply,
    Preflight,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedConfigBundle {
    #[serde(default)]
    pub purpose: ConfigBundlePurpose,
    pub node_tag: String,
    pub sequence: u64,
    pub min_sequence: u64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub config: NodeConfig,
    pub signature: String,
}

impl SignedConfigBundle {
    pub fn canonical_bytes(&self) -> crate::Result<Vec<u8>> {
        #[derive(Serialize)]
        struct SigningPayload<'a> {
            purpose: ConfigBundlePurpose,
            node_tag: &'a str,
            sequence: u64,
            min_sequence: u64,
            issued_at: i64,
            expires_at: i64,
            config: &'a NodeConfig,
        }
        let prefix: &[u8] = match self.purpose {
            ConfigBundlePurpose::Apply => b"exposure-config-apply-v2:",
            ConfigBundlePurpose::Preflight => b"exposure-config-preflight-v2:",
        };
        let body = serde_json::to_vec(&SigningPayload {
            purpose: self.purpose,
            node_tag: &self.node_tag,
            sequence: self.sequence,
            min_sequence: self.min_sequence,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            config: &self.config,
        })
        .map_err(|e| crate::ExposureError::Config(format!("canonical config encode: {e}")))?;
        let mut out = Vec::with_capacity(prefix.len() + body.len());
        out.extend_from_slice(prefix);
        out.extend_from_slice(&body);
        Ok(out)
    }

    pub fn verify(
        &self,
        control_pubkey_b64: &str,
        expected_node_tag: &str,
        expected_purpose: ConfigBundlePurpose,
        current_seq: u64,
        now_ts: i64,
    ) -> crate::Result<()> {
        if self.purpose != expected_purpose {
            return Err(crate::ExposureError::Auth(format!(
                "config bundle purpose mismatch: got {:?}, expected {:?}",
                self.purpose, expected_purpose
            )));
        }
        if self.node_tag != expected_node_tag || self.config.node_tag != expected_node_tag {
            return Err(crate::ExposureError::Auth(format!(
                "config bundle target mismatch: bundle={} config={} expected={}",
                self.node_tag, self.config.node_tag, expected_node_tag
            )));
        }
        if self.sequence <= current_seq {
            return Err(crate::ExposureError::Auth(format!(
                "config rollback rejected: incoming seq {} <= current {}",
                self.sequence, current_seq
            )));
        }
        if self.sequence < self.min_sequence {
            return Err(crate::ExposureError::Auth(format!(
                "config seq {} below min_sequence {}",
                self.sequence, self.min_sequence
            )));
        }
        if now_ts > self.expires_at {
            return Err(crate::ExposureError::Auth(format!(
                "config bundle expired at {} (now {})",
                self.expires_at, now_ts
            )));
        }
        if self.issued_at > now_ts + 300 {
            return Err(crate::ExposureError::Auth(format!(
                "config bundle issued_at {} is too far in the future",
                self.issued_at
            )));
        }
        let payload = self.canonical_bytes()?;
        crate::crypto::verify_signature_b64(control_pubkey_b64, &payload, &self.signature)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ControlRole {
    #[default]
    Active,
    Standby,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAuthConfig {
    pub username: String,
    /// PHC Argon2id password hash (`$argon2id$...`).
    pub password_hash: String,
    /// High-entropy session signing/derivation secret (>= 32 chars, no weak default).
    pub token_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlTlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapNodeTarget {
    pub node_tag: String,
    pub address: String,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub passphrase: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlConfig {
    pub control_id: String,
    #[serde(default)]
    pub role: ControlRole,
    pub panel_listen_addr: String,
    /// Optional TLS configuration for the Control Admin Panel & API.
    #[serde(default)]
    pub tls: Option<ControlTlsConfig>,
    pub sqlite_path: String,
    /// Ed25519 config-signing secret key (base64).
    pub signing_secret_key: String,
    /// Ed25519 link client secret key (base64).
    pub link_secret_key: String,
    pub admin: AdminAuthConfig,
    /// Bootstrap tunnel-listening nodes (supports primary + backups).
    #[serde(default)]
    pub bootstrap_nodes: Vec<BootstrapNodeTarget>,
    #[serde(default = "default_pull_interval")]
    pub telemetry_pull_interval_secs: u64,
    #[serde(default)]
    pub initial_topology_path: Option<String>,
}

fn default_pull_interval() -> u64 {
    30
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressDefaults {
    #[serde(default = "default_server_header")]
    pub server_header: String,
    #[serde(default)]
    pub clearance_secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_store_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_guard: Option<String>,
    #[serde(default)]
    pub intercept_errors: bool,
    #[serde(default = "default_true")]
    pub js_fp_beacon: bool,
    #[serde(default = "default_js_fp_ttl_secs")]
    pub js_fp_ttl_secs: u64,
}

impl Default for IngressDefaults {
    fn default() -> Self {
        Self {
            server_header: default_server_header(),
            clearance_secret: String::new(),
            cert_store_dir: None,
            default_guard: None,
            intercept_errors: false,
            js_fp_beacon: true,
            js_fp_ttl_secs: default_js_fp_ttl_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardDefaults {
    #[serde(default)]
    pub antibot: AntibotMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_bucket: Option<String>,
    #[serde(default = "default_challenge_threshold")]
    pub challenge_threshold: u8,
    #[serde(default = "default_reject_threshold")]
    pub reject_threshold: u8,
    #[serde(default = "default_pow_difficulty")]
    pub pow_difficulty: u8,
    #[serde(default = "default_clearance_ttl_secs")]
    pub clearance_ttl_secs: u64,
    #[serde(default = "default_true")]
    pub bind_ua: bool,
    #[serde(default = "default_true")]
    pub bind_ip_prefix: bool,
    #[serde(default)]
    pub block_bots: bool,
    #[serde(default = "default_true")]
    pub block_headless: bool,
    #[serde(default)]
    pub require_client_fp: bool,
    #[serde(default = "default_true")]
    pub js_fp_beacon: bool,
    #[serde(default = "default_js_fp_ttl_secs")]
    pub js_fp_ttl_secs: u64,
}

impl Default for GuardDefaults {
    fn default() -> Self {
        Self {
            antibot: AntibotMode::Challenge,
            rate_limit_bucket: None,
            challenge_threshold: default_challenge_threshold(),
            reject_threshold: default_reject_threshold(),
            pow_difficulty: default_pow_difficulty(),
            clearance_ttl_secs: default_clearance_ttl_secs(),
            bind_ua: true,
            bind_ip_prefix: true,
            block_bots: false,
            block_headless: true,
            require_client_fp: false,
            js_fp_beacon: true,
            js_fp_ttl_secs: default_js_fp_ttl_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressDefaults {
    #[serde(default)]
    pub protocol: BackendProtocol,
    #[serde(default = "default_backend_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub tls: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_cert_path: Option<String>,
    #[serde(default)]
    pub insecure_skip_verify: bool,
    #[serde(default)]
    pub allow_any_origin: bool,
    #[serde(default)]
    pub intercept_errors: bool,
}

impl Default for EgressDefaults {
    fn default() -> Self {
        Self {
            protocol: BackendProtocol::Auto,
            timeout_ms: default_backend_timeout_ms(),
            tls: false,
            ca_cert_path: None,
            insecure_skip_verify: false,
            allow_any_origin: false,
            intercept_errors: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkListenerDefaults {
    #[serde(default = "default_true")]
    pub allow_on_demand: bool,
    #[serde(default = "default_true")]
    pub allow_tunnel: bool,
    #[serde(default)]
    pub allow_bootstrap: bool,
}

impl Default for LinkListenerDefaults {
    fn default() -> Self {
        Self {
            allow_on_demand: true,
            allow_tunnel: true,
            allow_bootstrap: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TopologyDefaults {
    #[serde(default)]
    pub ingress: IngressDefaults,
    #[serde(default)]
    pub guard: GuardDefaults,
    #[serde(default)]
    pub egress: EgressDefaults,
    #[serde(default)]
    pub link_listener: LinkListenerDefaults,
}

/// High-level topology table edited in Control and compiled into per-node configs.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TopologySpec {
    #[serde(default)]
    pub defaults: TopologyDefaults,
    /// Globally reusable Guard profile templates selectable on any Ingress node/rule.
    #[serde(default)]
    pub guard_templates: BTreeMap<String, GuardProfile>,
    /// Globally reusable Rate-Limit bucket templates selectable by any Guard template or Ingress node.
    #[serde(default)]
    pub bucket_templates: BTreeMap<String, RateLimitBucket>,
    /// Separated DNS provider credentials (supports multiple accounts per provider).
    #[serde(default)]
    pub dns_providers: BTreeMap<String, DnsProviderAccountConfig>,
    /// Separated domain bindings (1st/multi-level domains -> DNS provider account, zone metadata, & target nodes).
    #[serde(default)]
    pub domains: BTreeMap<String, DomainBindingConfig>,
    #[serde(default)]
    pub nodes: BTreeMap<String, TopologyNodeSpec>,
    #[serde(default)]
    pub links: Vec<TopologyLinkSpec>,
    #[serde(default)]
    pub maintainer_templates: BTreeMap<String, MaintainerConfig>,
    #[serde(default)]
    pub global_logger: Option<LoggerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TopologyNodeSpec {
    #[serde(default)]
    pub roles: NodeRoles,
    /// Public/external IPv4 or IPv6 addresses advertised by this node for automatic DNS A/AAAA sync.
    #[serde(default)]
    pub external_ips: Vec<String>,
    #[serde(default)]
    pub link_listener: Option<LinkListenConfig>,
    #[serde(default)]
    pub ingress: IngressConfig,
    #[serde(default)]
    pub egress: EgressConfig,
    #[serde(default)]
    pub relay: RelayConfig,
    #[serde(default)]
    pub maintainer_template: Option<String>,
    #[serde(default)]
    pub maintainer_hops: Vec<String>,
    #[serde(default)]
    pub probe: Option<ProbeConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyLinkSpec {
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub peer_tag: Option<String>,
    pub mode: LinkMode,
    #[serde(default)]
    pub tunnel_direction: Option<TunnelDirection>,
    /// For `on-demand` links: defaults to `true` (bidirectional single-line link).
    #[serde(default = "default_true")]
    pub bidirectional: bool,
    #[serde(default)]
    pub endpoints: Vec<PeerEndpoint>,
    /// Optional reverse endpoints (`to -> from`) when `bidirectional: true` on `on-demand` links.
    #[serde(default)]
    pub reverse_endpoints: Vec<PeerEndpoint>,
    #[serde(default)]
    pub expected_client_addr: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        resolve_domain_binding, CertOrderConfig, DnsProviderAccountConfig, DomainBindingConfig,
    };

    #[test]
    fn aliyun_dns_provider_account_serde_yaml_and_alias() {
        let yaml = r#"
type: aliyun
access_key_id: LTAI5tExampleKeyId
access_key_secret: ExampleSecretValue
region_id: cn-hangzhou
"#;
        let parsed: DnsProviderAccountConfig =
            serde_yaml::from_str(yaml).expect("parse aliyun yaml");
        match &parsed {
            DnsProviderAccountConfig::Aliyun {
                access_key_id,
                access_key_secret,
                region_id,
            } => {
                assert_eq!(access_key_id, "LTAI5tExampleKeyId");
                assert_eq!(access_key_secret, "ExampleSecretValue");
                assert_eq!(region_id.as_deref(), Some("cn-hangzhou"));
            }
            other => panic!("unexpected variant: {other:?}"),
        }

        let alias_yaml = r#"
type: alidns
access_key_id: LTAI5tAliasKey
access_key_secret: AliasSecret
"#;
        let alias_parsed: DnsProviderAccountConfig =
            serde_yaml::from_str(alias_yaml).expect("parse alidns alias yaml");
        match alias_parsed {
            DnsProviderAccountConfig::Aliyun {
                access_key_id,
                access_key_secret,
                region_id,
            } => {
                assert_eq!(access_key_id, "LTAI5tAliasKey");
                assert_eq!(access_key_secret, "AliasSecret");
                assert!(region_id.is_none());
            }
            other => panic!("unexpected variant: {other:?}"),
        }

        let json_val = serde_json::to_value(&parsed).expect("serialize aliyun json");
        assert_eq!(json_val["type"], "aliyun");
    }

    #[test]
    fn domain_binding_longest_suffix_and_cert_order_optional_provider() {
        let mut domains = BTreeMap::new();
        domains.insert(
            "example.com".to_string(),
            DomainBindingConfig {
                provider: "aliyun-main".to_string(),
                ..Default::default()
            },
        );
        domains.insert(
            "sub.example.com".to_string(),
            DomainBindingConfig {
                provider: "cf-sub".to_string(),
                zone_id: Some("zone-sub".to_string()),
                ..Default::default()
            },
        );

        let (k1, b1) = resolve_domain_binding(&domains, "example.com").unwrap();
        assert_eq!(k1, "example.com");
        assert_eq!(b1.provider, "aliyun-main");

        let (k2, b2) = resolve_domain_binding(&domains, "*.api.example.com").unwrap();
        assert_eq!(k2, "example.com");
        assert_eq!(b2.provider, "aliyun-main");

        let (k3, b3) = resolve_domain_binding(&domains, "*.v2.sub.example.com").unwrap();
        assert_eq!(k3, "sub.example.com");
        assert_eq!(b3.provider, "cf-sub");
        assert_eq!(b3.zone_id.as_deref(), Some("zone-sub"));

        assert!(resolve_domain_binding(&domains, "other.org").is_none());

        let order_yaml = r#"
domain: "*.v2.sub.example.com"
target_nodes: ["ingress-hk"]
"#;
        let order: CertOrderConfig = serde_yaml::from_str(order_yaml).unwrap();
        assert!(order.provider.is_none());
        assert_eq!(order.renew_before_days, 30);
    }
}
