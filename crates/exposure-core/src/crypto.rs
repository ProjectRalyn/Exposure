use std::io::Write;
use std::path::Path;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::{ExposureError, Result};

type HmacSha256 = Hmac<Sha256>;

/// Compact 128-word NATO/tech-inspired list for onboarding passphrases.
const WORDLIST: &[&str] = &[
    "amber", "anchor", "apex", "atlas", "aurora", "badge", "basalt", "beacon",
    "birch", "blaze", "bolt", "breeze", "bridge", "brook", "canyon", "carbon",
    "cedar", "cipher", "citadel", "cliff", "cloud", "cobalt", "comet", "compass",
    "copper", "coral", "crest", "crown", "crystal", "current", "dawn", "delta",
    "drift", "dune", "echo", "eclipse", "ember", "falcon", "fjord", "flame",
    "flint", "forest", "forge", "frost", "galaxy", "glacier", "granite", "grove",
    "harbor", "haven", "hawk", "hazel", "horizon", "indigo", "iron", "island",
    "ivory", "jade", "jasper", "kelp", "kestrel", "lagoon", "lantern", "larch",
    "laurel", "ledge", "lotus", "lunar", "maple", "marble", "meadow", "mercury",
    "meteor", "mist", "monolith", "moss", "nebula", "nectar", "nimbus", "north",
    "oak", "oasis", "obsidian", "ocean", "olive", "onyx", "opal", "orbit",
    "orchid", "osprey", "otter", "pearl", "pebble", "phoenix", "pine", "plume",
    "polar", "prism", "pulse", "quartz", "raven", "reef", "ridge", "river",
    "robin", "ruby", "saffron", "sage", "sapphire", "sequoia", "shadow", "shield",
    "sierra", "silver", "slate", "solar", "spruce", "star", "steel", "stone",
    "storm", "summit", "timber", "titan", "topaz", "vector", "velvet", "zenith",
];

/// Append a length-prefixed (`u32 BE`) byte slice to a transcript to eliminate delimiter ambiguity.
pub fn push_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Update an HMAC with a length-prefixed (`u32 BE`) byte slice.
fn mac_update_lp(mac: &mut HmacSha256, data: &[u8]) {
    mac.update(&(data.len() as u32).to_be_bytes());
    mac.update(data);
}

/// Generate a cryptographically random hex string of `num_bytes` bytes (2 * num_bytes hex chars).
pub fn generate_random_secret_hex(num_bytes: usize) -> String {
    let mut buf = vec![0u8; num_bytes];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Hash a plaintext password using Argon2id with a random salt.
pub fn hash_password(plaintext: &str) -> Result<String> {
    if plaintext.is_empty() {
        return Err(ExposureError::Crypto("password cannot be empty".into()));
    }
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(plaintext.as_bytes(), &salt)
        .map_err(|e| ExposureError::Crypto(format!("argon2 hash failed: {e}")))?;
    Ok(hash.to_string())
}

/// Verify a plaintext password against a stored PHC Argon2id hash.
pub fn verify_password(plaintext: &str, stored_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored_hash.trim()) else {
        return false;
    };
    Argon2::default()
        .verify_password(plaintext.as_bytes(), &parsed)
        .is_ok()
}

pub fn is_valid_argon2_hash(stored_hash: &str) -> bool {
    let trimmed = stored_hash.trim();
    trimmed.starts_with("$argon2") && PasswordHash::new(trimmed).is_ok()
}

/// Returns true if a secret is empty, too short, or matches a known hardcoded weak placeholder.
pub fn is_weak_secret(secret: &str) -> bool {
    let s = secret.trim();
    if s.len() < 16 {
        return true;
    }
    matches!(
        s,
        "exposure-default-clearance-secret-change-me"
            | "exposure-default-hmac-key"
            | "exposure-control-session-secret"
            | "exposure-admin"
            | "change-this-in-production"
            | "change-me-now"
            | "replace-me"
    )
}

/// Validate a node/peer/service tag identifier (no path traversal, control chars, or colons).
pub fn validate_identifier(tag: &str, kind: &str) -> Result<()> {
    let t = tag.trim();
    if t.is_empty() || t.len() > 128 {
        return Err(ExposureError::Config(format!(
            "invalid {kind}: must be 1..=128 chars"
        )));
    }
    if t.contains("..")
        || !t
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'))
    {
        return Err(ExposureError::Config(format!(
            "invalid {kind} '{tag}': only [A-Za-z0-9._@-] without '..' allowed"
        )));
    }
    Ok(())
}

/// Validate a DNS domain (optionally leading `*.` wildcard) against path traversal & injection.
pub fn validate_dns_domain(domain: &str) -> Result<()> {
    let d = domain.trim();
    if d.is_empty() || d.len() > 253 {
        return Err(ExposureError::Config(format!(
            "invalid domain '{domain}': length must be 1..=253"
        )));
    }
    if d == "*" {
        return Ok(());
    }
    let check = d.strip_prefix("*.").unwrap_or(d);
    if check.is_empty() || check.starts_with('.') || check.ends_with('.') || check.contains("..") {
        return Err(ExposureError::Config(format!(
            "invalid domain '{domain}'"
        )));
    }
    for label in check.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ExposureError::Config(format!(
                "invalid domain label in '{domain}'"
            )));
        }
        if label.starts_with('-')
            || label.ends_with('-')
            || !label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(ExposureError::Config(format!(
                "invalid character in domain '{domain}'"
            )));
        }
    }
    Ok(())
}

/// Atomically write sensitive file contents with `0o600` permissions on Unix (`create_new` -> `sync_all` -> `rename`).
pub fn write_secret_file_atomic(path: &Path, content: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("secret");
    let rand_suffix = generate_random_secret_hex(8);
    let tmp_path = parent.join(format!(".{file_name}.{rand_suffix}.tmp"));

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let write_res = (|| -> std::io::Result<()> {
        let mut f = opts.open(&tmp_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(content)?;
        f.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_res {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e.into());
    }

    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e.into());
    }
    Ok(())
}

/// Enforce restrictive `0o600` permissions on an existing file (Unix).
pub fn restrict_file_permissions_0600(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    let _ = path;
    Ok(())
}

/// Enforce restrictive `0o700` permissions on a directory (Unix).
pub fn restrict_dir_permissions_0700(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    let _ = path;
    Ok(())
}

#[derive(Clone)]
pub struct NodeKeyPair {
    signing: SigningKey,
}

impl std::fmt::Debug for NodeKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeKeyPair")
            .field("public_key", &self.public_key_b64())
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}

impl NodeKeyPair {
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        Self { signing }
    }

    pub fn from_secret_b64(b64: &str) -> Result<Self> {
        let raw = STANDARD
            .decode(b64.trim())
            .map_err(|e| ExposureError::Crypto(format!("invalid secret key base64: {e}")))?;
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| ExposureError::Crypto("ed25519 secret key must be 32 bytes".into()))?;
        Ok(Self {
            signing: SigningKey::from_bytes(&bytes),
        })
    }

    pub fn secret_key_b64(&self) -> String {
        STANDARD.encode(self.signing.to_bytes())
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn public_key_b64(&self) -> String {
        STANDARD.encode(self.public_key_bytes())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub fn fingerprint(&self) -> String {
        pubkey_fingerprint(&self.public_key_bytes())
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing.sign(message).to_bytes().to_vec()
    }

    pub fn sign_b64(&self, message: &[u8]) -> String {
        STANDARD.encode(self.sign(message))
    }
}

pub fn parse_verifying_key_b64(b64: &str) -> Result<VerifyingKey> {
    let raw = STANDARD
        .decode(b64.trim())
        .map_err(|e| ExposureError::Crypto(format!("invalid public key base64: {e}")))?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| ExposureError::Crypto("ed25519 public key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|e| ExposureError::Crypto(format!("invalid ed25519 public key: {e}")))
}

pub fn verify_signature_b64(pubkey_b64: &str, message: &[u8], sig_b64: &str) -> Result<()> {
    let vk = parse_verifying_key_b64(pubkey_b64)?;
    let sig_raw = STANDARD
        .decode(sig_b64.trim())
        .map_err(|e| ExposureError::Crypto(format!("invalid signature base64: {e}")))?;
    let sig_bytes: [u8; 64] = sig_raw
        .try_into()
        .map_err(|_| ExposureError::Crypto("ed25519 signature must be 64 bytes".into()))?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(message, &sig)
        .map_err(|_| ExposureError::Auth("ed25519 signature verification failed".into()))
}

pub fn pubkey_fingerprint(pubkey_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pubkey_bytes);
    hex::encode(hasher.finalize())
}

pub fn pubkey_fingerprint_b64(pubkey_b64: &str) -> Result<String> {
    let vk = parse_verifying_key_b64(pubkey_b64)?;
    Ok(pubkey_fingerprint(&vk.to_bytes()))
}

/// Generate a high-entropy one-time onboarding passphrase (5 words + 64-bit random hex = 99 bits entropy).
pub fn generate_five_word_passphrase() -> String {
    let mut rng = OsRng;
    let mut parts: Vec<String> = (0..5)
        .map(|_| WORDLIST[rng.gen_range(0..WORDLIST.len())].to_string())
        .collect();
    parts.push(generate_random_secret_hex(8));
    parts.join("-")
}

/// Compute length-prefixed HMAC-SHA256 proof binding passphrase, node_tag, pubkey, and handshake nonce.
pub fn compute_passphrase_proof(
    passphrase: &str,
    node_tag: &str,
    pubkey_b64: &str,
    nonce: &[u8],
) -> String {
    let mut mac = HmacSha256::new_from_slice(passphrase.trim().as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(b"exposure-bootstrap-v2:");
    mac_update_lp(&mut mac, node_tag.as_bytes());
    mac_update_lp(&mut mac, pubkey_b64.as_bytes());
    mac_update_lp(&mut mac, nonce);
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_passphrase_proof(
    passphrase: &str,
    node_tag: &str,
    pubkey_b64: &str,
    nonce: &[u8],
    proof_hex: &str,
) -> bool {
    let trimmed = passphrase.trim();
    if trimmed.is_empty() || nonce.len() < 16 {
        return false;
    }
    let expected = compute_passphrase_proof(trimmed, node_tag, pubkey_b64, nonce);
    let candidate = proof_hex.trim();
    expected.len() == candidate.len() && bool::from(expected.as_bytes().ct_eq(candidate.as_bytes()))
}

/// Compute mutual-auth HMAC proof for `BootstrapReply`, proving the responder knows the onboarding passphrase
/// and binding `control_signing_pubkey`, `control_link_pubkey`, `target_node_tag`, and `nonce`.
pub fn compute_bootstrap_reply_proof(
    passphrase: &str,
    control_signing_pubkey: &str,
    control_link_pubkey: &str,
    target_node_tag: &str,
    nonce: &[u8],
) -> String {
    let mut mac = HmacSha256::new_from_slice(passphrase.trim().as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(b"exposure-bootstrap-reply-v2:");
    mac_update_lp(&mut mac, control_signing_pubkey.as_bytes());
    mac_update_lp(&mut mac, control_link_pubkey.as_bytes());
    mac_update_lp(&mut mac, target_node_tag.as_bytes());
    mac_update_lp(&mut mac, nonce);
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_bootstrap_reply_proof(
    passphrase: &str,
    control_signing_pubkey: &str,
    control_link_pubkey: &str,
    target_node_tag: &str,
    nonce: &[u8],
    proof_hex: &str,
) -> bool {
    let trimmed = passphrase.trim();
    if trimmed.is_empty() || nonce.len() < 16 {
        return false;
    }
    let expected = compute_bootstrap_reply_proof(
        trimmed,
        control_signing_pubkey,
        control_link_pubkey,
        target_node_tag,
        nonce,
    );
    let candidate = proof_hex.trim();
    expected.len() == candidate.len() && bool::from(expected.as_bytes().ct_eq(candidate.as_bytes()))
}

/// Anonymize client IP using HMAC-SHA256 truncated to 16 hex chars (64-bit pseudonymous tag).
pub fn hmac_ip(secret: &str, ip: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(b"exposure-ip-v1:");
    mac.update(ip.as_bytes());
    let out = mac.finalize().into_bytes();
    hex::encode(&out[..8])
}

/// Verify SHA-256 PoW solution: `SHA256("{token}:{nonce}")` has `difficulty` leading zero bits.
pub fn verify_pow_solution(token: &str, nonce: u64, difficulty: u8) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(format!("{token}:{nonce}").as_bytes());
    let digest = hasher.finalize();
    has_leading_zero_bits(&digest, difficulty)
}

pub fn has_leading_zero_bits(bytes: &[u8], bits: u8) -> bool {
    let mut remaining = bits as usize;
    for &b in bytes {
        if remaining == 0 {
            return true;
        }
        if remaining >= 8 {
            if b != 0 {
                return false;
            }
            remaining -= 8;
        } else {
            let mask = 0xffu8 << (8 - remaining);
            return (b & mask) == 0;
        }
    }
    remaining == 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearanceClaims {
    pub host: String,
    pub expires_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default)]
    pub ua_hash: Option<String>,
    #[serde(default)]
    pub ip_prefix: Option<String>,
    #[serde(default)]
    pub fp_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_hash: Option<String>,
}

pub fn sign_clearance_cookie(secret: &str, claims: &ClearanceClaims) -> Result<String> {
    let payload = serde_json::to_vec(claims)
        .map_err(|e| ExposureError::Crypto(format!("serialize clearance claims: {e}")))?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(b"exposure-clearance-v1:");
    mac.update(payload_b64.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    Ok(format!("{payload_b64}.{sig_b64}"))
}

pub fn verify_clearance_cookie(secret: &str, cookie_val: &str) -> Result<ClearanceClaims> {
    let (payload_b64, sig_b64) = cookie_val
        .split_once('.')
        .ok_or_else(|| ExposureError::Auth("malformed clearance cookie".into()))?;
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(b"exposure-clearance-v1:");
    mac.update(payload_b64.as_bytes());
    let expected_b64 = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    let eq: bool = expected_b64.len() == sig_b64.len()
        && bool::from(expected_b64.as_bytes().ct_eq(sig_b64.as_bytes()));
    if !eq {
        return Err(ExposureError::Auth("invalid clearance cookie signature".into()));
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| ExposureError::Auth(format!("invalid clearance payload: {e}")))?;
    let claims: ClearanceClaims = serde_json::from_slice(&payload)
        .map_err(|e| ExposureError::Auth(format!("invalid clearance JSON: {e}")))?;
    Ok(claims)
}

/// Sign a PoW challenge token bound to `(host, client_ip_key, token, expires_at, difficulty)`.
pub fn sign_challenge_token(
    secret: &str,
    host: &str,
    client_ip_key: &str,
    token: &str,
    expires_at: i64,
    difficulty: u8,
) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(b"exposure-pow-v2:");
    mac_update_lp(&mut mac, host.as_bytes());
    mac_update_lp(&mut mac, client_ip_key.as_bytes());
    mac_update_lp(&mut mac, token.as_bytes());
    mac.update(&expires_at.to_be_bytes());
    mac.update(&[difficulty]);
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

pub fn verify_challenge_token(
    secret: &str,
    host: &str,
    client_ip_key: &str,
    token: &str,
    expires_at: i64,
    difficulty: u8,
    sig: &str,
) -> bool {
    let expected = sign_challenge_token(secret, host, client_ip_key, token, expires_at, difficulty);
    expected.len() == sig.len() && bool::from(expected.as_bytes().ct_eq(sig.as_bytes()))
}

/// Signed passive JS fingerprint cookie claims (avoids re-injecting FP beacon until TTL expires).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FpCookieClaims {
    pub host: String,
    pub expires_at: i64,
    pub ua_hash: String,
    pub ip_prefix: String,
    pub fp_hash: String,
    #[serde(default)]
    pub is_headless: bool,
}

pub fn sign_fp_cookie(secret: &str, claims: &FpCookieClaims) -> Result<String> {
    let payload = serde_json::to_vec(claims)
        .map_err(|e| ExposureError::Crypto(format!("serialize fp cookie claims: {e}")))?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(b"exposure-fp-cookie-v1:");
    mac.update(payload_b64.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    Ok(format!("{payload_b64}.{sig_b64}"))
}

pub fn verify_fp_cookie(secret: &str, cookie_val: &str) -> Result<FpCookieClaims> {
    let (payload_b64, sig_b64) = cookie_val
        .split_once('.')
        .ok_or_else(|| ExposureError::Auth("malformed fp cookie".into()))?;
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(b"exposure-fp-cookie-v1:");
    mac.update(payload_b64.as_bytes());
    let expected_b64 = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    let eq: bool = expected_b64.len() == sig_b64.len()
        && bool::from(expected_b64.as_bytes().ct_eq(sig_b64.as_bytes()));
    if !eq {
        return Err(ExposureError::Auth("invalid fp cookie signature".into()));
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| ExposureError::Auth(format!("invalid fp cookie payload: {e}")))?;
    let claims: FpCookieClaims = serde_json::from_slice(&payload)
        .map_err(|e| ExposureError::Auth(format!("invalid fp cookie JSON: {e}")))?;
    Ok(claims)
}

/// Sign a short-lived single-use passive JS fingerprint report token bound to
/// `(host, client_ip_prefix, ua_hash, service_tag, token_id, expires_at)`.
pub fn sign_fp_token(
    secret: &str,
    host: &str,
    ip_prefix: &str,
    ua_hash: &str,
    service_tag: &str,
    token_id: &str,
    expires_at: i64,
) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(b"exposure-fp-report-v1:");
    mac_update_lp(&mut mac, host.as_bytes());
    mac_update_lp(&mut mac, ip_prefix.as_bytes());
    mac_update_lp(&mut mac, ua_hash.as_bytes());
    mac_update_lp(&mut mac, service_tag.as_bytes());
    mac_update_lp(&mut mac, token_id.as_bytes());
    mac.update(&expires_at.to_be_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

#[allow(clippy::too_many_arguments)]
pub fn verify_fp_token(
    secret: &str,
    host: &str,
    ip_prefix: &str,
    ua_hash: &str,
    service_tag: &str,
    token_id: &str,
    expires_at: i64,
    sig: &str,
) -> bool {
    let expected = sign_fp_token(
        secret,
        host,
        ip_prefix,
        ua_hash,
        service_tag,
        token_id,
        expires_at,
    );
    expected.len() == sig.len() && bool::from(expected.as_bytes().ct_eq(sig.as_bytes()))
}

pub fn short_sha256_hex(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    hex::encode(&h.finalize()[..8])
}

/// Keyed 64-bit HMAC-SHA256 hex digest (16 hex chars) for binding UA/attributes in cookies
/// without exposing offline-computable unkeyed hashes.
pub fn keyed_short_hmac_hex(secret: &str, domain: &str, input: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(domain.as_bytes());
    mac.update(b":");
    mac.update(input.as_bytes());
    hex::encode(&mac.finalize().into_bytes()[..8])
}

/// Constant-time comparison of two arbitrary-length byte slices using fixed-length SHA-256 digests
/// so slice length is not leaked via timing.
pub fn ct_eq_hashed(a: &[u8], b: &[u8]) -> bool {
    let da = Sha256::digest(a);
    let db = Sha256::digest(b);
    bool::from(da.ct_eq(&db))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let kp = NodeKeyPair::generate();
        let msg = b"exposure-config-v1";
        let sig = kp.sign_b64(msg);
        assert!(verify_signature_b64(&kp.public_key_b64(), msg, &sig).is_ok());
        assert!(verify_signature_b64(&kp.public_key_b64(), b"tampered", &sig).is_err());
    }

    #[test]
    fn passphrase_and_proof() {
        let pass = generate_five_word_passphrase();
        assert_eq!(pass.split('-').count(), 6);
        let nonce = b"random-nonce-1234567890";
        let proof = compute_passphrase_proof(&pass, "node-a", "pk-abc", nonce);
        assert!(verify_passphrase_proof(&pass, "node-a", "pk-abc", nonce, &proof));
        assert!(!verify_passphrase_proof("wrong-pass-here-now-no-0000", "node-a", "pk-abc", nonce, &proof));

        let reply_proof = compute_bootstrap_reply_proof(&pass, "ctrl-sig", "ctrl-link", "node-a", nonce);
        assert!(verify_bootstrap_reply_proof(&pass, "ctrl-sig", "ctrl-link", "node-a", nonce, &reply_proof));
        assert!(!verify_bootstrap_reply_proof(&pass, "other-sig", "ctrl-link", "node-a", nonce, &reply_proof));
    }

    #[test]
    fn argon2_password_roundtrip() {
        let h = hash_password("s3cr3t-passphrase!").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password("s3cr3t-passphrase!", &h));
        assert!(!verify_password("wrong", &h));
    }

    #[test]
    fn pow_and_clearance_cookie() {
        let token = "test-challenge-token";
        let mut nonce = 0u64;
        while !verify_pow_solution(token, nonce, 10) {
            nonce += 1;
        }
        assert!(verify_pow_solution(token, nonce, 10));

        let sig = sign_challenge_token("secret-key", "example.com", "203.0.113", token, 4_000_000_000, 10);
        assert!(verify_challenge_token("secret-key", "example.com", "203.0.113", token, 4_000_000_000, 10, &sig));
        assert!(!verify_challenge_token("secret-key", "other.com", "203.0.113", token, 4_000_000_000, 10, &sig));

        let claims = ClearanceClaims {
            host: "example.com".into(),
            expires_at: 4_000_000_000,
            jti: Some("sess0123456789ab".into()),
            ua_hash: Some(keyed_short_hmac_hex("secret-key", "exposure-ua", "Mozilla/5.0")),
            ip_prefix: Some("203.0.113.10".into()),
            fp_hash: None,
            profile_hash: None,
        };
        let cookie = sign_clearance_cookie("secret-key", &claims).unwrap();
        let decoded = verify_clearance_cookie("secret-key", &cookie).unwrap();
        assert_eq!(decoded.host, "example.com");
        assert!(verify_clearance_cookie("other-key", &cookie).is_err());
    }

    #[test]
    fn domain_validation_blocks_traversal() {
        assert!(validate_dns_domain("example.com").is_ok());
        assert!(validate_dns_domain("*.sub.example.com").is_ok());
        assert!(validate_dns_domain("../etc/passwd").is_err());
        assert!(validate_dns_domain("/etc/passwd").is_err());
        assert!(validate_dns_domain("a\\b.com").is_err());
        assert!(validate_dns_domain("a;rm -rf /").is_err());
    }
}
