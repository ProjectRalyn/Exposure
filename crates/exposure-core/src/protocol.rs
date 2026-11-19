use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::{NodeRoles, SignedConfigBundle};
use crate::error::{ExposureError, Result};
use crate::telemetry::{AlertRecord, CertStatusInfo, LinkStatusSnapshot, MinuteSummary, SessionSummary};

pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

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

/// First frame sent after Noise transport establishment to bind Ed25519 identity.
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
    pub fn signing_bytes(
        node_tag: &str,
        public_key: &str,
        nonce: &[u8],
        timestamp: i64,
        is_control: bool,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(b"exposure-hello-v1:");
        out.extend_from_slice(node_tag.as_bytes());
        out.push(b':');
        out.extend_from_slice(public_key.as_bytes());
        out.push(b':');
        out.extend_from_slice(nonce);
        out.push(b':');
        out.extend_from_slice(&timestamp.to_be_bytes());
        out.push(if is_control { 1 } else { 0 });
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloAck {
    pub accepted: bool,
    pub authenticated: bool,
    pub bootstrap_pending: bool,
    pub node_tag: String,
    pub public_key: String,
    #[serde(default)]
    pub warning: Option<String>,
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
            ttl,
            payload,
        }
    }

    pub fn current_target(&self) -> Option<&str> {
        self.hops.get(self.hop_index).map(|s| s.as_str())
    }

    pub fn next_hop(&self) -> Option<&str> {
        self.hops.get(self.hop_index + 1).map(|s| s.as_str())
    }

    pub fn is_final_hop(&self, self_tag: &str) -> bool {
        self.hop_index + 1 >= self.hops.len()
            && self
                .hops
                .get(self.hop_index)
                .map(|t| t == self_tag)
                .unwrap_or(false)
    }

    pub fn advance(&mut self) -> Result<()> {
        if self.ttl == 0 {
            return Err(ExposureError::Routing("special frame TTL exhausted".into()));
        }
        self.ttl -= 1;
        self.hop_index += 1;
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
            ttl: 16,
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
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MaintainerTelemetrySnapshot {
    pub maintainer_tag: String,
    pub summaries: Vec<MinuteSummary>,
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
    },
    LogAck {
        accepted: usize,
    },
    CertBundle {
        domain: String,
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
        error: Option<String>,
    },
    DialEnrollReq {
        target_node_tag: String,
        target_addr: String,
        passphrase: String,
        control_public_key: String,
    },
    DialEnrollResp {
        success: bool,
        #[serde(default)]
        node_public_key: Option<String>,
        #[serde(default)]
        error: Option<String>,
    },
    ErrorReply {
        message: String,
    },
}

pub fn cert_bundle_signing_bytes(
    domain: &str,
    cert_pem: &str,
    key_pem: &str,
    issued_at: i64,
    expires_at: i64,
    maintainer_tag: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"exposure-cert-v1:");
    out.extend_from_slice(maintainer_tag.as_bytes());
    out.push(b':');
    out.extend_from_slice(domain.as_bytes());
    out.push(b':');
    out.extend_from_slice(&issued_at.to_be_bytes());
    out.extend_from_slice(&expires_at.to_be_bytes());
    out.extend_from_slice(cert_pem.as_bytes());
    out.extend_from_slice(key_pem.as_bytes());
    out
}

pub fn discovery_resp_signing_bytes(
    request_id: &str,
    node_tag: &str,
    public_key: &str,
    config_sequence: u64,
    neighbors: &[DiscoveryNeighbor],
) -> Vec<u8> {
    let n_json = serde_json::to_vec(neighbors).unwrap_or_default();
    let mut out = Vec::new();
    out.extend_from_slice(b"exposure-discovery-v1:");
    out.extend_from_slice(request_id.as_bytes());
    out.push(b':');
    out.extend_from_slice(node_tag.as_bytes());
    out.push(b':');
    out.extend_from_slice(public_key.as_bytes());
    out.extend_from_slice(&config_sequence.to_be_bytes());
    out.extend_from_slice(&n_json);
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

/// Read a length-prefixed JSON frame.
pub async fn read_json_frame<R, T>(reader: &mut R) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let len = reader.read_u32().await? as usize;
    if len > MAX_FRAME_BYTES {
        return Err(ExposureError::Protocol(format!(
            "incoming frame exceeds limit: {len} bytes"
        )));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf)
        .map_err(|e| ExposureError::Protocol(format!("deserialize frame: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_table_reverse_symmetry() {
        let req = SpecialFrame::new(
            "req-1",
            vec!["control-1".into(), "boot".into(), "relay-a".into(), "egress-1".into()],
            16,
            SpecialPayload::StatusReq,
        );
        assert_eq!(req.current_target(), Some("control-1"));
        assert_eq!(req.next_hop(), Some("boot"));

        let rep = req.reverse_for_reply(SpecialPayload::ErrorReply {
            message: "ok".into(),
        });
        assert_eq!(
            rep.hops,
            vec!["egress-1", "relay-a", "boot", "control-1"]
        );
        assert_eq!(rep.hop_index, 0);
    }
}
