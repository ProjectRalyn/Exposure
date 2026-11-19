use std::net::SocketAddr;

use chrono::Utc;
use exposure_core::config::PeerConfig;
use exposure_core::crypto::{
    pubkey_fingerprint_b64, verify_signature_b64, NodeKeyPair,
};
use exposure_core::protocol::{read_json_frame, write_json_frame, HelloAck, HelloFrame};
use exposure_core::routing::ip_matches_cidrs;
use exposure_core::{ExposureError, Result};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::warn;

const HELLO_MAX_SKEW_SECS: i64 = 300;

#[derive(Debug, Clone)]
pub struct HandshakeOutcome {
    pub remote_node_tag: String,
    pub remote_public_key: String,
    pub authenticated: bool,
    pub bootstrap_pending: bool,
    pub is_control: bool,
    pub bootstrap_nonce: Vec<u8>,
    pub bootstrap_proof: Option<String>,
    pub warning: Option<String>,
}

/// Client/Initiator side of Ed25519 Hello identity binding over Noise.
pub async fn client_hello<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    local_tag: &str,
    keypair: &NodeKeyPair,
    is_control: bool,
    bootstrap_proof: Option<(Vec<u8>, String)>,
    expected_remote_pubkey: Option<&str>,
    expected_remote_fp: Option<&str>,
) -> Result<HandshakeOutcome> {
    let (nonce, proof) = match bootstrap_proof {
        Some((n, p)) => (n, Some(p)),
        None => {
            let mut n = vec![0u8; 24];
            rand::thread_rng().fill_bytes(&mut n);
            (n, None)
        }
    };
    let timestamp = Utc::now().timestamp();
    let pk = keypair.public_key_b64();
    let signing = HelloFrame::signing_bytes(local_tag, &pk, &nonce, timestamp, is_control);
    let signature = keypair.sign_b64(&signing);

    let hello = HelloFrame {
        node_tag: local_tag.to_string(),
        public_key: pk,
        nonce: nonce.clone(),
        timestamp,
        signature,
        is_control,
        bootstrap_proof: proof.clone(),
    };
    write_json_frame(stream, &hello).await?;

    let ack: HelloAck = read_json_frame(stream).await?;
    if !ack.accepted {
        return Err(ExposureError::Auth(
            ack.warning
                .unwrap_or_else(|| "remote rejected hello handshake".into()),
        ));
    }

    if let Some(exp_pk) = expected_remote_pubkey {
        if ack.public_key.trim() != exp_pk.trim() {
            return Err(ExposureError::Auth(format!(
                "remote public key mismatch for {}",
                ack.node_tag
            )));
        }
    }
    if let Some(exp_fp) = expected_remote_fp {
        let actual_fp = pubkey_fingerprint_b64(&ack.public_key)?;
        if actual_fp != exp_fp.trim() {
            return Err(ExposureError::Auth(format!(
                "remote pubkey fingerprint mismatch for {}",
                ack.node_tag
            )));
        }
    }

    if let Some(ref w) = ack.warning {
        warn!(remote = %ack.node_tag, warning = %w, "link hello warning from remote");
    }

    Ok(HandshakeOutcome {
        remote_node_tag: ack.node_tag,
        remote_public_key: ack.public_key,
        authenticated: ack.authenticated,
        bootstrap_pending: ack.bootstrap_pending,
        is_control: false,
        bootstrap_nonce: nonce,
        bootstrap_proof: proof,
        warning: ack.warning,
    })
}

/// Server/Responder side of Ed25519 Hello identity binding over Noise.
/// Per DESIGN.md §6.1 & user confirmation:
/// - Signature validation is always checked;
/// - Auxiliary client_addr mismatch or unconfigured peer logs WARN and keeps the connection
///   (marking `authenticated = false` so normal user traffic is not permitted on unauthenticated links).
pub async fn server_hello<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    remote_addr: SocketAddr,
    local_tag: &str,
    keypair: &NodeKeyPair,
    peers: &[PeerConfig],
    trusted_control_pubkeys: &[String],
    local_bootstrap_passphrase: Option<&str>,
) -> Result<HandshakeOutcome> {
    let hello: HelloFrame = read_json_frame(stream).await?;

    let now = Utc::now().timestamp();
    if (now - hello.timestamp).abs() > HELLO_MAX_SKEW_SECS {
        let ack = HelloAck {
            accepted: false,
            authenticated: false,
            bootstrap_pending: false,
            node_tag: local_tag.to_string(),
            public_key: keypair.public_key_b64(),
            warning: Some("hello timestamp skew exceeded".into()),
        };
        let _ = write_json_frame(stream, &ack).await;
        return Err(ExposureError::Auth("hello timestamp skew exceeded".into()));
    }

    let signing = HelloFrame::signing_bytes(
        &hello.node_tag,
        &hello.public_key,
        &hello.nonce,
        hello.timestamp,
        hello.is_control,
    );
    if let Err(e) = verify_signature_b64(&hello.public_key, &signing, &hello.signature) {
        let ack = HelloAck {
            accepted: false,
            authenticated: false,
            bootstrap_pending: false,
            node_tag: local_tag.to_string(),
            public_key: keypair.public_key_b64(),
            warning: Some(format!("invalid hello signature: {e}")),
        };
        let _ = write_json_frame(stream, &ack).await;
        return Err(e);
    }

    let mut authenticated = false;
    let mut bootstrap_pending = false;
    let mut warning: Option<String> = None;

    if hello.is_control {
        // Control connecting to tunnel listener: either already known Control pubkey or passphrase proof!
        if trusted_control_pubkeys
            .iter()
            .any(|pk| pk.trim() == hello.public_key.trim())
        {
            authenticated = true;
        } else if let (Some(pass), Some(ref proof)) =
            (local_bootstrap_passphrase, &hello.bootstrap_proof)
        {
            if exposure_core::crypto::verify_passphrase_proof(
                pass,
                &hello.node_tag,
                &hello.public_key,
                &hello.nonce,
                proof,
            ) {
                authenticated = true;
                bootstrap_pending = true;
            } else {
                let msg = format!(
                    "control {} from {} presented invalid passphrase proof",
                    hello.node_tag, remote_addr
                );
                warn!("{msg}");
                warning = Some(msg);
            }
        } else {
            let msg = format!(
                "unregistered control {} connected from {} (keeping link in unauthenticated mode)",
                hello.node_tag, remote_addr
            );
            warn!("{msg}");
            warning = Some(msg);
            bootstrap_pending = hello.bootstrap_proof.is_some();
        }
    } else if let Some(peer) = peers.iter().find(|p| p.node_tag == hello.node_tag) {
        let mut pk_ok = true;
        if let Some(ref exp_pk) = peer.public_key {
            if exp_pk.trim() != hello.public_key.trim() {
                pk_ok = false;
            }
        }
        if let Some(ref exp_fp) = peer.pubkey_fingerprint {
            let actual = pubkey_fingerprint_b64(&hello.public_key)?;
            if actual != exp_fp.trim() {
                pk_ok = false;
            }
        }
        if pk_ok {
            authenticated = true;
            if let Some(ref expected_addr) = peer.expected_client_addr {
                if !ip_matches_cidrs(remote_addr.ip(), std::slice::from_ref(expected_addr)) {
                    let msg = format!(
                        "tunnel peer {} connected from unexpected client addr {} (expected {}), keeping connection",
                        hello.node_tag, remote_addr, expected_addr
                    );
                    warn!("{msg}");
                    warning = Some(msg);
                }
            }
        } else {
            let msg = format!(
                "peer {} pubkey mismatch from {} (keeping link unauthenticated)",
                hello.node_tag, remote_addr
            );
            warn!("{msg}");
            warning = Some(msg);
        }
    } else {
        // Unknown node (e.g., active onboarding node connecting to bootstrap tunnel)
        let msg = format!(
            "unregistered node {} connected from {} (bootstrap_proof={})",
            hello.node_tag,
            remote_addr,
            hello.bootstrap_proof.is_some()
        );
        warn!("{msg}");
        warning = Some(msg);
        if hello.bootstrap_proof.is_some() {
            bootstrap_pending = true;
        }
    }

    let ack = HelloAck {
        accepted: true,
        authenticated,
        bootstrap_pending,
        node_tag: local_tag.to_string(),
        public_key: keypair.public_key_b64(),
        warning: warning.clone(),
    };
    write_json_frame(stream, &ack).await?;

    Ok(HandshakeOutcome {
        remote_node_tag: hello.node_tag,
        remote_public_key: hello.public_key,
        authenticated,
        bootstrap_pending,
        is_control: hello.is_control,
        bootstrap_nonce: hello.nonce,
        bootstrap_proof: hello.bootstrap_proof,
        warning,
    })
}
