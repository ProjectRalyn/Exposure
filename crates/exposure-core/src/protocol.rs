use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::{NodeRoles, SignedConfigBundle};
use crate::crypto::push_len_prefixed;
use crate::error::{ExposureError, Result};
use crate::telemetry::{
    AlertRecord, CertStatusInfo, EvilpotNodeReport, FingerprintObservation, LinkStatusSnapshot,
    MinuteSummary, SessionSummary,
};

pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_HANDSHAKE_FRAME_BYTES: usize = 16 * 1024;
pub const MAX_HEADER_FRAME_BYTES: usize = 32 * 1024;
pub const MAX_SPECIAL_HOPS: usize = 32;
pub const MAX_TTL: u8 = 32;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamKind {
    Service = 1,
    Special = 2,
    Probe = 3,
    Bootstrap = 4,
}

impl StreamKind {
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            1 => Ok(Self::Service),
            2 => Ok(Self::Special),
            3 => Ok(Self::Probe),
            4 => Ok(Self::Bootstrap),
            _ => Err(ExposureError::Protocol(format!("unknown stream kind: {b}"))),
        }
    }
}

/// First frame sent after Noise transport establishment to bind Ed25519 identity to the Noise channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloFrame {
    pub node_tag: String,
    pub public_key: String,
    pub nonce: Vec<u8>,
    pub timestamp: i64,
    pub signature: String,
    #[serde(default)]
    pub is_control: bool,
    /// Optional HMAC passphrase proof used during initial onboarding.
    #[serde(default)]
    pub bootstrap_proof: Option<String>,
}

impl HelloFrame {
    /// Protocol v2 channel-bound signing bytes (binds Noise handshake hash `h` + length-prefixed fields).
    pub fn signing_bytes(
        noise_handshake_hash: &[u8],
        node_tag: &str,
        public_key: &str,
        nonce: &[u8],
        timestamp: i64,
        is_control: bool,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(192);
        out.extend_from_slice(b"exposure-hello-c2s-v2:");
        push_len_prefixed(&mut out, noise_handshake_hash);
        push_len_prefixed(&mut out, node_tag.as_bytes());
        push_len_prefixed(&mut out, public_key.as_bytes());
        push_len_prefixed(&mut out, nonce);
        out.extend_from_slice(&timestamp.to_be_bytes());
        out.push(if is_control { 1 } else { 0 });
        out
    }
}

/// Signed responder acknowledgement binding responder Ed25519 identity to the same Noise session & client nonce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloAck {
    pub accepted: bool,
    pub authenticated: bool,
    pub bootstrap_pending: bool,
    pub node_tag: String,
    pub public_key: String,
    pub nonce: Vec<u8>,
    pub timestamp: i64,
    pub signature: String,
    #[serde(default)]
    pub warning: Option<String>,
}

impl HelloAck {
    #[allow(clippy::too_many_arguments)]
    pub fn signing_bytes(
        noise_handshake_hash: &[u8],
        client_nonce: &[u8],
        server_nonce: &[u8],
        timestamp: i64,
        node_tag: &str,
        public_key: &str,
        accepted: bool,
        authenticated: bool,
        bootstrap_pending: bool,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(224);
        out.extend_from_slice(b"exposure-hello-s2c-v2:");
        push_len_prefixed(&mut out, noise_handshake_hash);
        push_len_prefixed(&mut out, client_nonce);
        push_len_prefixed(&mut out, server_nonce);
        out.extend_from_slice(&timestamp.to_be_bytes());
        push_len_prefixed(&mut out, node_tag.as_bytes());
        push_len_prefixed(&mut out, public_key.as_bytes());
        out.push(if accepted { 1 } else { 0 });
        out.push(if authenticated { 1 } else { 0 });
        out.push(if bootstrap_pending { 1 } else { 0 });
        out
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceStreamProtocol {
    #[default]
    Http1,
    H2,
    RawTcp,
}

/// Header placed at the start of every normal service stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStreamHeader {
    pub service_tag: String,
    pub origin_node_tag: String,
    pub ttl: u8,
    pub hop_count: u8,
    pub request_id: String,
    #[serde(default)]
    pub client_ip: Option<String>,
    #[serde(default)]
    pub is_tls: bool,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub protocol: ServiceStreamProtocol,
    /// Nodes already traversed to guarantee loop prevention across relays.
    #[serde(default)]
    pub visited: Vec<String>,
    /// Unix timestamp (seconds) when origin created this stream header.
    #[serde(default)]
    pub timestamp: i64,
    /// Ed25519 signature by `origin_node_tag` authenticating origin identity to Egress ACLs.
    #[serde(default)]
    pub origin_signature: Option<String>,
}

impl ServiceStreamHeader {
    pub fn origin_signing_bytes(
        service_tag: &str,
        origin_node_tag: &str,
        request_id: &str,
        timestamp: i64,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(b"exposure-svc-origin-v2:");
        push_len_prefixed(&mut out, service_tag.as_bytes());
        push_len_prefixed(&mut out, origin_node_tag.as_bytes());
        push_len_prefixed(&mut out, request_id.as_bytes());
        out.extend_from_slice(&timestamp.to_be_bytes());
        out
    }
}

/// Special data frame routed explicitly along a Node Tag Hop Table.
/// Replies reverse `hops` and traverse back along the symmetric path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecialFrame {
    pub id: String,
    pub hops: Vec<String>,
    pub hop_index: usize,
    pub ttl: u8,
    pub payload: SpecialPayload,
}

impl SpecialFrame {
    pub fn new(id: impl Into<String>, hops: Vec<String>, ttl: u8, payload: SpecialPayload) -> Self {
        Self {
            id: id.into(),
            hops,
            hop_index: 0,
            ttl: ttl.min(MAX_TTL),
            payload,
        }
    }

    pub fn current_target(&self) -> Option<&str> {
        self.hops.get(self.hop_index).map(|s| s.as_str())
    }

    pub fn prev_hop(&self) -> Option<&str> {
        self.hop_index
            .checked_sub(1)
            .and_then(|i| self.hops.get(i))
            .map(|s| s.as_str())
    }

    pub fn next_hop(&self) -> Option<&str> {
        self.hop_index
            .checked_add(1)
            .and_then(|i| self.hops.get(i))
            .map(|s| s.as_str())
    }

    pub fn is_final_hop(&self, self_tag: &str) -> bool {
        if self.hop_index >= self.hops.len() {
            return false;
        }
        let next_idx = match self.hop_index.checked_add(1) {
            Some(v) => v,
            None => return false,
        };
        next_idx == self.hops.len()
            && self
                .hops
                .get(self.hop_index)
                .map(|t| t == self_tag)
                .unwrap_or(false)
    }

    pub fn validate_hops(&self) -> Result<()> {
        if self.hops.is_empty() || self.hops.len() > MAX_SPECIAL_HOPS {
            return Err(ExposureError::Routing(format!(
                "invalid special frame hops len: {}",
                self.hops.len()
            )));
        }
        if self.hop_index >= self.hops.len() {
            return Err(ExposureError::Routing("special frame hop_index out of bounds".into()));
        }
        if self.ttl > MAX_TTL {
            return Err(ExposureError::Routing("special frame ttl exceeds maximum".into()));
        }
        let mut seen = std::collections::HashSet::with_capacity(self.hops.len());
        for h in &self.hops {
            if !seen.insert(h.as_str()) {
                return Err(ExposureError::Routing(format!(
                    "special frame contains duplicate hop '{h}'"
                )));
            }
        }
        Ok(())
    }

    pub fn advance(&mut self) -> Result<()> {
        if self.ttl == 0 {
            return Err(ExposureError::Routing("special frame TTL exhausted".into()));
        }
        let next = self
            .hop_index
            .checked_add(1)
            .ok_or_else(|| ExposureError::Routing("special frame hop_index overflow".into()))?;
        if next >= self.hops.len() {
            return Err(ExposureError::Routing("special frame has no next hop".into()));
        }
        self.ttl -= 1;
        self.hop_index = next;
        Ok(())
    }

    /// Build a symmetric reply frame by reversing the Hop Table.
    pub fn reverse_for_reply(&self, payload: SpecialPayload) -> Self {
        let mut rev = self.hops.clone();
        rev.reverse();
        Self {
            id: self.id.clone(),
            hops: rev,
            hop_index: 0,
            // Size the reply TTL to the reversed hop count so long (≤ MAX_SPECIAL_HOPS) paths
            // are not guaranteed to exhaust a hard-coded TTL of 16 before returning.
            ttl: (self.hops.len().min(MAX_TTL as usize) as u8).max(1),
            payload,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryNeighbor {
    pub peer_tag: String,
    pub node_tag: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatusSnapshot {
    pub node_tag: String,
    pub roles: NodeRoles,
    pub config_sequence: u64,
    pub last_reload_ok: bool,
    #[serde(default)]
    pub last_reload_error: Option<String>,
    pub uptime_secs: u64,
    pub links: Vec<LinkStatusSnapshot>,
    #[serde(default)]
    pub alerts: Vec<AlertRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evilpot: Option<EvilpotNodeReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MaintainerTelemetrySnapshot {
    pub maintainer_tag: String,
    pub summaries: Vec<MinuteSummary>,
    #[serde(default)]
    pub fingerprints: Vec<FingerprintObservation>,
    pub certificates: Vec<CertStatusInfo>,
    pub segment_backlog: usize,
    pub merge_latency_ms: f64,
    pub alerts: Vec<AlertRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightCheckItem {
    pub target: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightReport {
    pub node_tag: String,
    pub ok: bool,
    pub checks: Vec<PreflightCheckItem>,
}

fn default_dns_sync_line() -> String {
    "default".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsLineSyncEntry {
    #[serde(default = "default_dns_sync_line")]
    pub line: String,
    #[serde(default)]
    pub ipv4s: Vec<String>,
    #[serde(default)]
    pub ipv6s: Vec<String>,
    #[serde(default)]
    pub cnames: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxied: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSyncRecordSpec {
    pub domain: String,
    #[serde(default)]
    pub ipv4s: Vec<String>,
    #[serde(default)]
    pub ipv6s: Vec<String>,
    /// Optional per-line split-horizon sync entries (when non-empty, supersedes flat `ipv4s`/`ipv6s`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub line_entries: Vec<DnsLineSyncEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxied: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSyncDomainResult {
    pub domain: String,
    pub ok: bool,
    #[serde(default)]
    pub created: usize,
    #[serde(default)]
    pub updated: usize,
    #[serde(default)]
    pub deleted: usize,
    #[serde(default)]
    pub unchanged: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSupportLine {
    pub code: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRemoteRecord {
    pub record_id: String,
    pub rr: String,
    pub fqdn: String,
    /// Strictly Exposure-managed types: "A" | "AAAA" | "CNAME"
    pub record_type: String,
    pub value: String,
    pub line: String,
    pub ttl: u32,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxied: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsProviderCapabilities {
    pub supports_lines: bool,
    pub supports_proxied: bool,
    pub supports_status_toggle: bool,
    pub supports_remote_edit: bool,
}

/// Control-authorized remote DNS management operation scoped strictly to Exposure-managed records (A / AAAA / CNAME).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum DnsManageOp {
    Inspect {
        domain: String,
        #[serde(default)]
        include_lines: bool,
    },
    Create {
        domain: String,
        record_type: String,
        value: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        line: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ttl: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        proxied: Option<bool>,
    },
    Update {
        domain: String,
        record_id: String,
        record_type: String,
        value: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        line: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ttl: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        proxied: Option<bool>,
    },
    SetStatus {
        domain: String,
        record_id: String,
        enabled: bool,
    },
    Delete {
        domain: String,
        record_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SpecialPayload {
    ConfigPush(Box<SignedConfigBundle>),
    PreflightReq(Box<SignedConfigBundle>),
    PreflightResp(PreflightReport),
    ConfigAck {
        node_tag: String,
        sequence: u64,
        applied: bool,
        #[serde(default)]
        error: Option<String>,
    },
    DiscoveryReq {
        request_id: String,
        initiator: String,
    },
    DiscoveryResp {
        request_id: String,
        node_tag: String,
        roles: NodeRoles,
        public_key: String,
        config_sequence: u64,
        neighbors: Vec<DiscoveryNeighbor>,
        signature: String,
    },
    LogBatch {
        from_node: String,
        records: Vec<SessionSummary>,
        minute_summaries: Vec<MinuteSummary>,
        #[serde(default)]
        fingerprints: Vec<FingerprintObservation>,
    },
    LogAck {
        accepted: usize,
    },
    CertBundle {
        domain: String,
        target_node_tag: String,
        cert_pem: String,
        key_pem: String,
        issued_at: i64,
        expires_at: i64,
        maintainer_tag: String,
        signature: String,
    },
    CertAck {
        node_tag: String,
        domain: String,
        applied: bool,
        #[serde(default)]
        error: Option<String>,
    },
    StatusReq,
    StatusResp(NodeStatusSnapshot),
    PullTelemetryReq {
        #[serde(default)]
        since_minute: Option<i64>,
    },
    PullTelemetryResp(MaintainerTelemetrySnapshot),
    BootstrapForward {
        node_tag: String,
        public_key: String,
        nonce: Vec<u8>,
        proof: String,
        via_node: String,
    },
    BootstrapReply {
        accepted: bool,
        #[serde(default)]
        control_public_key: Option<String>,
        #[serde(default)]
        control_link_public_key: Option<String>,
        /// Passphrase-keyed HMAC proving responder knows the onboarding passphrase.
        #[serde(default)]
        reply_proof: Option<String>,
        /// Nonce used to compute `reply_proof`.
        #[serde(default)]
        nonce: Vec<u8>,
        #[serde(default)]
        error: Option<String>,
    },
    DialEnrollReq {
        request_id: String,
        issued_at: i64,
        expires_at: i64,
        target_node_tag: String,
        target_addr: String,
        passphrase: String,
        control_public_key: String,
        control_link_public_key: String,
        /// Ed25519 signature by Control's config-signing key authorizing this relay dial.
        control_signature: String,
    },
    DialEnrollResp {
        success: bool,
        #[serde(default)]
        node_public_key: Option<String>,
        #[serde(default)]
        error: Option<String>,
    },
    /// Control-signed command instructing a Maintainer node to declaratively sync DNS A/AAAA records.
    /// Maintainer MUST refuse DNS sync without a valid, non-expired, non-replayed Control signature.
    DnsSyncReq {
        request_id: String,
        issued_at: i64,
        expires_at: i64,
        maintainer_tag: String,
        records: Vec<DnsSyncRecordSpec>,
        control_signature: String,
    },
    DnsSyncResp {
        request_id: String,
        maintainer_tag: String,
        ok: bool,
        results: Vec<DnsSyncDomainResult>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// Control-signed remote DNS inspection / single-record mutation scoped to Exposure's A/AAAA/CNAME records.
    DnsManageReq {
        request_id: String,
        issued_at: i64,
        expires_at: i64,
        maintainer_tag: String,
        op: DnsManageOp,
        control_signature: String,
    },
    DnsManageResp {
        request_id: String,
        maintainer_tag: String,
        ok: bool,
        #[serde(default)]
        capabilities: DnsProviderCapabilities,
        #[serde(default)]
        lines: Vec<DnsSupportLine>,
        #[serde(default)]
        records: Vec<DnsRemoteRecord>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        record_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    ErrorReply {
        message: String,
    },
}

pub fn cert_bundle_signing_bytes(
    domain: &str,
    target_node_tag: &str,
    cert_pem: &str,
    key_pem: &str,
    issued_at: i64,
    expires_at: i64,
    maintainer_tag: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"exposure-cert-v2:");
    push_len_prefixed(&mut out, maintainer_tag.as_bytes());
    push_len_prefixed(&mut out, target_node_tag.as_bytes());
    push_len_prefixed(&mut out, domain.as_bytes());
    out.extend_from_slice(&issued_at.to_be_bytes());
    out.extend_from_slice(&expires_at.to_be_bytes());
    push_len_prefixed(&mut out, cert_pem.as_bytes());
    push_len_prefixed(&mut out, key_pem.as_bytes());
    out
}

pub fn discovery_resp_signing_bytes(
    request_id: &str,
    node_tag: &str,
    roles: &NodeRoles,
    public_key: &str,
    config_sequence: u64,
    neighbors: &[DiscoveryNeighbor],
) -> Vec<u8> {
    let r_json = serde_json::to_vec(roles).unwrap_or_default();
    let n_json = serde_json::to_vec(neighbors).unwrap_or_default();
    let mut out = Vec::new();
    out.extend_from_slice(b"exposure-discovery-v2:");
    push_len_prefixed(&mut out, request_id.as_bytes());
    push_len_prefixed(&mut out, node_tag.as_bytes());
    push_len_prefixed(&mut out, &r_json);
    push_len_prefixed(&mut out, public_key.as_bytes());
    out.extend_from_slice(&config_sequence.to_be_bytes());
    push_len_prefixed(&mut out, &n_json);
    out
}

#[allow(clippy::too_many_arguments)]
pub fn dial_enroll_req_signing_bytes(
    request_id: &str,
    issued_at: i64,
    expires_at: i64,
    relay_node_tag: &str,
    target_node_tag: &str,
    target_addr: &str,
    passphrase: &str,
    control_public_key: &str,
    control_link_public_key: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(b"exposure-dial-enroll-v2:");
    push_len_prefixed(&mut out, request_id.as_bytes());
    out.extend_from_slice(&issued_at.to_be_bytes());
    out.extend_from_slice(&expires_at.to_be_bytes());
    push_len_prefixed(&mut out, relay_node_tag.as_bytes());
    push_len_prefixed(&mut out, target_node_tag.as_bytes());
    push_len_prefixed(&mut out, target_addr.as_bytes());
    push_len_prefixed(&mut out, passphrase.as_bytes());
    push_len_prefixed(&mut out, control_public_key.as_bytes());
    push_len_prefixed(&mut out, control_link_public_key.as_bytes());
    out
}

pub fn dns_sync_req_signing_bytes(
    request_id: &str,
    issued_at: i64,
    expires_at: i64,
    maintainer_tag: &str,
    records: &[DnsSyncRecordSpec],
) -> Vec<u8> {
    let rec_json = serde_json::to_vec(records).unwrap_or_default();
    let mut out = Vec::with_capacity(192 + rec_json.len());
    out.extend_from_slice(b"exposure-dns-sync-v1:");
    push_len_prefixed(&mut out, request_id.as_bytes());
    out.extend_from_slice(&issued_at.to_be_bytes());
    out.extend_from_slice(&expires_at.to_be_bytes());
    push_len_prefixed(&mut out, maintainer_tag.as_bytes());
    push_len_prefixed(&mut out, &rec_json);
    out
}

pub fn dns_manage_req_signing_bytes(
    request_id: &str,
    issued_at: i64,
    expires_at: i64,
    maintainer_tag: &str,
    op: &DnsManageOp,
) -> Vec<u8> {
    let op_json = serde_json::to_vec(op).unwrap_or_default();
    let mut out = Vec::with_capacity(192 + op_json.len());
    out.extend_from_slice(b"exposure-dns-manage-v1:");
    push_len_prefixed(&mut out, request_id.as_bytes());
    out.extend_from_slice(&issued_at.to_be_bytes());
    out.extend_from_slice(&expires_at.to_be_bytes());
    push_len_prefixed(&mut out, maintainer_tag.as_bytes());
    push_len_prefixed(&mut out, &op_json);
    out
}

/// Write a length-prefixed JSON frame (`[u32 BE len][json bytes]`).
pub async fn write_json_frame<W, T>(writer: &mut W, msg: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let data = serde_json::to_vec(msg)
        .map_err(|e| ExposureError::Protocol(format!("serialize frame: {e}")))?;
    if data.len() > MAX_FRAME_BYTES {
        return Err(ExposureError::Protocol(format!(
            "frame too large: {} bytes",
            data.len()
        )));
    }
    writer.write_u32(data.len() as u32).await?;
    writer.write_all(&data).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a length-prefixed JSON frame with an explicit maximum byte limit.
pub async fn read_json_frame_bounded<R, T>(reader: &mut R, max_bytes: usize) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let len = reader.read_u32().await? as usize;
    let cap = max_bytes.min(MAX_FRAME_BYTES);
    if len == 0 || len > cap {
        return Err(ExposureError::Protocol(format!(
            "incoming frame length {len} outside allowed 1..={cap}"
        )));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf)
        .map_err(|e| ExposureError::Protocol(format!("deserialize frame: {e}")))
}

/// Read a length-prefixed JSON frame (up to `MAX_FRAME_BYTES`).
pub async fn read_json_frame<R, T>(reader: &mut R) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    read_json_frame_bounded(reader, MAX_FRAME_BYTES).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_table_reverse_symmetry_and_overflow_safety() {
        let req = SpecialFrame::new(
            "req-1",
            vec!["control-1".into(), "boot".into(), "relay-a".into(), "egress-1".into()],
            16,
            SpecialPayload::StatusReq,
        );
        assert_eq!(req.current_target(), Some("control-1"));
        assert_eq!(req.next_hop(), Some("boot"));
        assert!(req.validate_hops().is_ok());

        let rep = req.reverse_for_reply(SpecialPayload::ErrorReply {
            message: "ok".into(),
        });
        assert_eq!(
            rep.hops,
            vec!["egress-1", "relay-a", "boot", "control-1"]
        );
        assert_eq!(rep.hop_index, 0);

        let bad = SpecialFrame {
            id: "bad".into(),
            hops: vec!["a".into(), "b".into()],
            hop_index: usize::MAX,
            ttl: 8,
            payload: SpecialPayload::StatusReq,
        };
        assert!(!bad.is_final_hop("a"));
        assert_eq!(bad.next_hop(), None);
        assert!(bad.validate_hops().is_err());
    }
}
