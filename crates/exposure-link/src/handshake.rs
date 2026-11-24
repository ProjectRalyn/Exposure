use std::net::SocketAddr;
use std::time::{Duration, Instant};

use chrono::Utc;
use dashmap::DashMap;
use exposure_core::config::{LinkListenConfig, LinkMode, PeerConfig, TunnelDirection};
use exposure_core::crypto::{
    pubkey_fingerprint_b64, verify_passphrase_proof, verify_signature_b64, NodeKeyPair,
};
use exposure_core::protocol::{
    read_json_frame_bounded, write_json_frame, HelloAck, HelloFrame, MAX_HANDSHAKE_FRAME_BYTES,
};
use exposure_core::routing::ip_matches_cidrs;
use exposure_core::{ExposureError, Result};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tracing::warn;

const HELLO_MAX_SKEW_SECS: u64 = 60;
const MIN_NONCE_LEN: usize = 16;
const MAX_NONCE_LEN: usize = 64;
const MAX_NONCE_CACHE: usize = 16_384;
const MAX_BOOTSTRAP_FAILURES: u32 = 5;
/// After `MAX_BOOTSTRAP_FAILURES`, temporarily reject attempts for this window instead of
/// destroying the passphrase (avoids a remote-triggerable onboarding DoS).
const BOOTSTRAP_LOCKOUT_SECS: u64 = 60;

/// Bounded TTL replay cache for Hello nonces.
#[derive(Default)]
pub struct NonceReplayCache {
    seen: DashMap<Vec<u8>, i64>,
}

impl NonceReplayCache {
    pub fn new() -> Self {
        Self {
            seen: DashMap::new(),
        }
    }

    pub fn check_and_insert(&self, nonce: &[u8], now: i64) -> bool {
        if self.seen.len() >= MAX_NONCE_CACHE {
            let cutoff = now.saturating_sub(HELLO_MAX_SKEW_SECS as i64 * 2);
            self.seen.retain(|_, ts| *ts >= cutoff);
            if self.seen.len() >= MAX_NONCE_CACHE {
                // Evict ~half instead of wiping the whole replay cache (which would disable
                // replay protection precisely under a nonce flood).
                let to_remove = self.seen.len() / 2;
                let mut removed = 0usize;
                self.seen.retain(|_, _| {
                    if removed < to_remove {
                        removed += 1;
                        false
                    } else {
                        true
                    }
                });
            }
        }
        let mut fresh = false;
        self.seen.entry(nonce.to_vec()).or_insert_with(|| {
            fresh = true;
            now
        });
        fresh
    }
}

struct BootstrapPassphraseEntry {
    phrase: String,
    failed_attempts: u32,
    locked_until: Option<Instant>,
}

/// Atomic single-use bootstrap passphrase verifier with brute-force lockout.
#[derive(Default)]
pub struct BootstrapAuthState {
    inner: Mutex<Option<BootstrapPassphraseEntry>>,
}

impl BootstrapAuthState {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    pub async fn set(&self, phrase: Option<String>) {
        let mut guard = self.inner.lock().await;
        *guard = phrase.filter(|p| !p.trim().is_empty()).map(|p| {
            BootstrapPassphraseEntry {
                phrase: p,
                locked_until: None,
                failed_attempts: 0,
            }
        });
    }

    pub async fn has_active(&self) -> bool {
        self.inner.lock().await.is_some()
    }

    /// Atomically verify a passphrase proof; consumes the passphrase on success,
    /// or locks out (clears) it after `MAX_BOOTSTRAP_FAILURES` failed attempts.
    pub async fn verify_and_consume(
        &self,
        node_tag: &str,
        pubkey_b64: &str,
        nonce: &[u8],
        proof_hex: &str,
    ) -> std::result::Result<bool, &'static str> {
        let now = Instant::now();
        let mut guard = self.inner.lock().await;
        let Some(ref mut entry) = *guard else {
            return Ok(false);
        };
        // Enforce a temporary lockout window without destroying the passphrase.
        if let Some(until) = entry.locked_until {
            if now < until {
                return Err("bootstrap passphrase temporarily locked out after repeated failures");
            }
            entry.locked_until = None;
            entry.failed_attempts = 0;
        }
        if verify_passphrase_proof(&entry.phrase, node_tag, pubkey_b64, nonce, proof_hex) {
            *guard = None; // One-time atomic consumption!
            return Ok(true);
        }
        entry.failed_attempts += 1;
        if entry.failed_attempts >= MAX_BOOTSTRAP_FAILURES {
            // Keep the passphrase alive; just throttle for a window. Destroying it here would let
            // any reachable unauthenticated client DoS a freshly generated onboarding passphrase.
            entry.failed_attempts = 0;
            entry.locked_until = Some(now + Duration::from_secs(BOOTSTRAP_LOCKOUT_SECS));
            return Err("bootstrap passphrase temporarily locked out after repeated failures");
        }
        Err("invalid bootstrap passphrase proof")
    }
}

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

#[allow(clippy::too_many_arguments)]
fn build_signed_ack(
    keypair: &NodeKeyPair,
    noise_handshake_hash: &[u8],
    client_nonce: &[u8],
    local_tag: &str,
    accepted: bool,
    authenticated: bool,
    bootstrap_pending: bool,
    warning: Option<String>,
) -> HelloAck {
    let mut server_nonce = vec![0u8; 24];
    rand::thread_rng().fill_bytes(&mut server_nonce);
    let timestamp = Utc::now().timestamp();
    let pk = keypair.public_key_b64();
    let signing = HelloAck::signing_bytes(
        noise_handshake_hash,
        client_nonce,
        &server_nonce,
        timestamp,
        local_tag,
        &pk,
        accepted,
        authenticated,
        bootstrap_pending,
    );
    let signature = keypair.sign_b64(&signing);
    HelloAck {
        accepted,
        authenticated,
        bootstrap_pending,
        node_tag: local_tag.to_string(),
        public_key: pk,
        nonce: server_nonce,
        timestamp,
        signature,
        warning,
    }
}

/// Client/Initiator side of Protocol v2 channel-bound mutual Ed25519 Hello over Noise.
#[allow(clippy::too_many_arguments)]
pub async fn client_hello<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    noise_handshake_hash: &[u8],
    local_tag: &str,
    keypair: &NodeKeyPair,
    is_control: bool,
    bootstrap_proof: Option<(Vec<u8>, String)>,
    expected_remote_node_tag: Option<&str>,
    expected_remote_pubkey: Option<&str>,
    expected_remote_fp: Option<&str>,
    allow_unauthenticated: bool,
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
    let signing = HelloFrame::signing_bytes(
        noise_handshake_hash,
        local_tag,
        &pk,
        &nonce,
        timestamp,
        is_control,
    );
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

    let ack: HelloAck = read_json_frame_bounded(stream, MAX_HANDSHAKE_FRAME_BYTES).await?;
    if !ack.accepted {
        return Err(ExposureError::Auth(
            ack.warning
                .unwrap_or_else(|| "remote rejected hello handshake".into()),
        ));
    }

    // Verify responder's HelloAck Ed25519 signature bound to the exact Noise handshake hash & client nonce!
    let now = Utc::now().timestamp();
    if ack.nonce.len() < MIN_NONCE_LEN || ack.nonce.len() > MAX_NONCE_LEN {
        return Err(ExposureError::Auth("invalid server hello ack nonce length".into()));
    }
    if now.abs_diff(ack.timestamp) > HELLO_MAX_SKEW_SECS {
        return Err(ExposureError::Auth("server hello ack timestamp skew exceeded".into()));
    }
    let ack_signing = HelloAck::signing_bytes(
        noise_handshake_hash,
        &nonce,
        &ack.nonce,
        ack.timestamp,
        &ack.node_tag,
        &ack.public_key,
        ack.accepted,
        ack.authenticated,
        ack.bootstrap_pending,
    );
    verify_signature_b64(&ack.public_key, &ack_signing, &ack.signature)?;

    if let Some(exp_tag) = expected_remote_node_tag {
        if ack.node_tag != exp_tag {
            return Err(ExposureError::Auth(format!(
                "remote node_tag mismatch: got '{}', expected '{exp_tag}'",
                ack.node_tag
            )));
        }
    }

    if let Some(exp_pk) = expected_remote_pubkey.map(str::trim).filter(|s| !s.is_empty()) {
        if ack.public_key.trim() != exp_pk {
            return Err(ExposureError::Auth(format!(
                "remote public key mismatch for {}",
                ack.node_tag
            )));
        }
    }
    if let Some(exp_fp) = expected_remote_fp.map(str::trim).filter(|s| !s.is_empty()) {
        let actual_fp = pubkey_fingerprint_b64(&ack.public_key)?;
        if !actual_fp.eq_ignore_ascii_case(exp_fp) {
            return Err(ExposureError::Auth(format!(
                "remote pubkey fingerprint mismatch for {}",
                ack.node_tag
            )));
        }
    }

    if !allow_unauthenticated && !ack.authenticated {
        return Err(ExposureError::Auth(format!(
            "remote {} did not authenticate us (warning: {:?})",
            ack.node_tag, ack.warning
        )));
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

/// Server/Responder side of Protocol v2 channel-bound mutual Ed25519 Hello over Noise.
#[allow(clippy::too_many_arguments)]
pub async fn server_hello<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    noise_handshake_hash: &[u8],
    remote_addr: SocketAddr,
    local_tag: &str,
    keypair: &NodeKeyPair,
    listen_policy: &LinkListenConfig,
    peers: &[PeerConfig],
    trusted_control_pubkeys: &[String],
    bootstrap_state: &BootstrapAuthState,
    nonce_cache: &NonceReplayCache,
) -> Result<HandshakeOutcome> {
    let hello: HelloFrame = read_json_frame_bounded(stream, MAX_HANDSHAKE_FRAME_BYTES).await?;

    let now = Utc::now().timestamp();
    if now.abs_diff(hello.timestamp) > HELLO_MAX_SKEW_SECS {
        let ack = build_signed_ack(
            keypair,
            noise_handshake_hash,
            &hello.nonce,
            local_tag,
            false,
            false,
            false,
            Some("hello timestamp skew exceeded".into()),
        );
        let _ = write_json_frame(stream, &ack).await;
        return Err(ExposureError::Auth("hello timestamp skew exceeded".into()));
    }

    if hello.nonce.len() < MIN_NONCE_LEN || hello.nonce.len() > MAX_NONCE_LEN {
        let ack = build_signed_ack(
            keypair,
            noise_handshake_hash,
            &hello.nonce,
            local_tag,
            false,
            false,
            false,
            Some("invalid hello nonce length".into()),
        );
        let _ = write_json_frame(stream, &ack).await;
        return Err(ExposureError::Auth("invalid hello nonce length".into()));
    }

    let signing = HelloFrame::signing_bytes(
        noise_handshake_hash,
        &hello.node_tag,
        &hello.public_key,
        &hello.nonce,
        hello.timestamp,
        hello.is_control,
    );
    if let Err(e) = verify_signature_b64(&hello.public_key, &signing, &hello.signature) {
        let ack = build_signed_ack(
            keypair,
            noise_handshake_hash,
            &hello.nonce,
            local_tag,
            false,
            false,
            false,
            Some(format!("invalid hello signature: {e}")),
        );
        let _ = write_json_frame(stream, &ack).await;
        return Err(e);
    }

    // Only consume a replay-cache slot AFTER the peer proves possession of its key, so an
    // unauthenticated client cannot pollute the bounded nonce cache.
    if !nonce_cache.check_and_insert(&hello.nonce, now) {
        let ack = build_signed_ack(
            keypair,
            noise_handshake_hash,
            &hello.nonce,
            local_tag,
            false,
            false,
            false,
            Some("hello nonce replay detected".into()),
        );
        let _ = write_json_frame(stream, &ack).await;
        return Err(ExposureError::Auth("hello nonce replay detected".into()));
    }

    let mut authenticated = false;
    let mut bootstrap_pending = false;
    let mut warning: Option<String> = None;

    if hello.is_control {
        if trusted_control_pubkeys
            .iter()
            .any(|pk| !pk.trim().is_empty() && pk.trim() == hello.public_key.trim())
        {
            authenticated = true;
        } else if listen_policy.effective_allow_bootstrap() {
            if let Some(ref proof) = hello.bootstrap_proof {
                match bootstrap_state
                    .verify_and_consume(&hello.node_tag, &hello.public_key, &hello.nonce, proof)
                    .await
                {
                    Ok(true) => {
                        authenticated = true;
                        bootstrap_pending = true;
                    }
                    Ok(false) => {
                        let msg = format!(
                            "control {} rejected: no active local bootstrap passphrase",
                            hello.node_tag
                        );
                        warn!("{msg}");
                        let ack = build_signed_ack(
                            keypair,
                            noise_handshake_hash,
                            &hello.nonce,
                            local_tag,
                            false,
                            false,
                            false,
                            Some(msg.clone()),
                        );
                        let _ = write_json_frame(stream, &ack).await;
                        return Err(ExposureError::Auth(msg));
                    }
                    Err(reason) => {
                        let msg = format!("control {} from {} {reason}", hello.node_tag, remote_addr);
                        warn!("{msg}");
                        let ack = build_signed_ack(
                            keypair,
                            noise_handshake_hash,
                            &hello.nonce,
                            local_tag,
                            false,
                            false,
                            false,
                            Some(msg.clone()),
                        );
                        let _ = write_json_frame(stream, &ack).await;
                        return Err(ExposureError::Auth(msg));
                    }
                }
            } else {
                let msg = format!("unregistered control {} rejected", hello.node_tag);
                warn!("{msg}");
                let ack = build_signed_ack(
                    keypair,
                    noise_handshake_hash,
                    &hello.nonce,
                    local_tag,
                    false,
                    false,
                    false,
                    Some(msg.clone()),
                );
                let _ = write_json_frame(stream, &ack).await;
                return Err(ExposureError::Auth(msg));
            }
        } else {
            let msg = format!("bootstrap disabled on listener; rejected control {}", hello.node_tag);
            warn!("{msg}");
            let ack = build_signed_ack(
                keypair,
                noise_handshake_hash,
                &hello.nonce,
                local_tag,
                false,
                false,
                false,
                Some(msg.clone()),
            );
            let _ = write_json_frame(stream, &ack).await;
            return Err(ExposureError::Auth(msg));
        }
    } else if let Some(peer) = peers.iter().find(|p| p.node_tag == hello.node_tag) {
        // Enforce LinkListenConfig policy flags
        let is_inbound_tunnel =
            peer.mode == LinkMode::Tunnel && peer.tunnel_direction == Some(TunnelDirection::Inbound);
        if is_inbound_tunnel && !listen_policy.effective_allow_tunnel() {
            let msg = format!("inbound tunnel peer {} rejected by listener policy", hello.node_tag);
            warn!("{msg}");
            let ack = build_signed_ack(
                keypair,
                noise_handshake_hash,
                &hello.nonce,
                local_tag,
                false,
                false,
                false,
                Some(msg.clone()),
            );
            let _ = write_json_frame(stream, &ack).await;
            return Err(ExposureError::Auth(msg));
        }
        if !is_inbound_tunnel && !listen_policy.effective_allow_on_demand() {
            let msg = format!("on-demand peer {} rejected by listener policy", hello.node_tag);
            warn!("{msg}");
            let ack = build_signed_ack(
                keypair,
                noise_handshake_hash,
                &hello.nonce,
                local_tag,
                false,
                false,
                false,
                Some(msg.clone()),
            );
            let _ = write_json_frame(stream, &ack).await;
            return Err(ExposureError::Auth(msg));
        }

        // Fail-closed: require at least one non-empty public key or fingerprint pin!
        let has_pk = peer
            .public_key
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty());
        let has_fp = peer
            .pubkey_fingerprint
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty());
        let mut pk_ok = has_pk || has_fp;

        if let Some(exp_pk) = peer.public_key.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            if exp_pk != hello.public_key.trim() {
                pk_ok = false;
            }
        }
        if let Some(exp_fp) = peer
            .pubkey_fingerprint
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let actual = pubkey_fingerprint_b64(&hello.public_key)?;
            if !actual.eq_ignore_ascii_case(exp_fp) {
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
                "peer {} failed pubkey pin verification from {}",
                hello.node_tag, remote_addr
            );
            warn!("{msg}");
            let ack = build_signed_ack(
                keypair,
                noise_handshake_hash,
                &hello.nonce,
                local_tag,
                false,
                false,
                false,
                Some(msg.clone()),
            );
            let _ = write_json_frame(stream, &ack).await;
            return Err(ExposureError::Auth(msg));
        }
    } else if listen_policy.effective_allow_bootstrap() {
        if let Some(ref proof) = hello.bootstrap_proof {
            if bootstrap_state.has_active().await {
                // Listening node being dialed via DialEnrollReq by a relay node with local passphrase proof
                match bootstrap_state
                    .verify_and_consume(&hello.node_tag, &hello.public_key, &hello.nonce, proof)
                    .await
                {
                    Ok(true) => {
                        authenticated = true;
                        bootstrap_pending = true;
                    }
                    Ok(false) => {
                        bootstrap_pending = true;
                    }
                    Err(reason) => {
                        let msg = format!(
                            "bootstrap peer {} from {} rejected: {reason}",
                            hello.node_tag, remote_addr
                        );
                        warn!("{msg}");
                        let ack = build_signed_ack(
                            keypair,
                            noise_handshake_hash,
                            &hello.nonce,
                            local_tag,
                            false,
                            false,
                            false,
                            Some(msg.clone()),
                        );
                        let _ = write_json_frame(stream, &ack).await;
                        return Err(ExposureError::Auth(msg));
                    }
                }
            } else {
                // Active onboarding node connecting to an enrolled bootstrap node to send BootstrapForward
                bootstrap_pending = true;
                let msg = format!(
                    "unregistered node {} connected from {} for bootstrap forwarding",
                    hello.node_tag, remote_addr
                );
                warn!("{msg}");
                warning = Some(msg);
            }
        } else {
            let msg = format!(
                "unregistered node {} without bootstrap proof rejected from {}",
                hello.node_tag, remote_addr
            );
            warn!("{msg}");
            let ack = build_signed_ack(
                keypair,
                noise_handshake_hash,
                &hello.nonce,
                local_tag,
                false,
                false,
                false,
                Some(msg.clone()),
            );
            let _ = write_json_frame(stream, &ack).await;
            return Err(ExposureError::Auth(msg));
        }
    } else {
        let msg = format!(
            "unregistered node {} rejected from {} (bootstrap disabled)",
            hello.node_tag, remote_addr
        );
        warn!("{msg}");
        let ack = build_signed_ack(
            keypair,
            noise_handshake_hash,
            &hello.nonce,
            local_tag,
            false,
            false,
            false,
            Some(msg.clone()),
        );
        let _ = write_json_frame(stream, &ack).await;
        return Err(ExposureError::Auth(msg));
    }

    let ack = build_signed_ack(
        keypair,
        noise_handshake_hash,
        &hello.nonce,
        local_tag,
        true,
        authenticated,
        bootstrap_pending,
        warning.clone(),
    );
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
