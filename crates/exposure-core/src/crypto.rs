use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::{ExposureError, Result};

type HmacSha256 = Hmac<Sha256>;

/// Compact 128-word NATO/tech-inspired list for 5-word one-time onboarding passphrases.
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

/// Generate a 5-word one-time onboarding passphrase (valid for 10 minutes).
pub fn generate_five_word_passphrase() -> String {
    let mut rng = OsRng;
    let words: Vec<&str> = (0..5)
        .map(|_| WORDLIST[rng.gen_range(0..WORDLIST.len())])
        .collect();
    words.join("-")
}

/// Compute HMAC-SHA256 proof binding passphrase, node_tag, pubkey, and handshake nonce.
pub fn compute_passphrase_proof(
    passphrase: &str,
    node_tag: &str,
    pubkey_b64: &str,
    nonce: &[u8],
) -> String {
    let mut mac = HmacSha256::new_from_slice(passphrase.trim().as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(b"exposure-bootstrap-v1:");
    mac.update(node_tag.as_bytes());
    mac.update(b":");
    mac.update(pubkey_b64.as_bytes());
    mac.update(b":");
    mac.update(nonce);
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_passphrase_proof(
    passphrase: &str,
    node_tag: &str,
    pubkey_b64: &str,
    nonce: &[u8],
    proof_hex: &str,
) -> bool {
    let expected = compute_passphrase_proof(passphrase, node_tag, pubkey_b64, nonce);
    expected.as_bytes().ct_eq(proof_hex.trim().as_bytes()).into()
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
    #[serde(default)]
    pub ua_hash: Option<String>,
    #[serde(default)]
    pub ip_prefix: Option<String>,
    #[serde(default)]
    pub fp_hash: Option<String>,
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
    let eq: bool = expected_b64.as_bytes().ct_eq(sig_b64.as_bytes()).into();
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

pub fn sign_challenge_token(secret: &str, token: &str, expires_at: i64, difficulty: u8) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(format!("exposure-pow-v1:{token}:{expires_at}:{difficulty}").as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

pub fn verify_challenge_token(
    secret: &str,
    token: &str,
    expires_at: i64,
    difficulty: u8,
    sig: &str,
) -> bool {
    let expected = sign_challenge_token(secret, token, expires_at, difficulty);
    expected.as_bytes().ct_eq(sig.as_bytes()).into()
}

pub fn short_sha256_hex(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    hex::encode(&h.finalize()[..8])
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
        assert_eq!(pass.split('-').count(), 5);
        let nonce = b"random-nonce-123";
        let proof = compute_passphrase_proof(&pass, "node-a", "pk-abc", nonce);
        assert!(verify_passphrase_proof(&pass, "node-a", "pk-abc", nonce, &proof));
        assert!(!verify_passphrase_proof("wrong-pass-here-now-no", "node-a", "pk-abc", nonce, &proof));
    }

    #[test]
    fn pow_and_clearance_cookie() {
        let token = "test-challenge-token";
        let mut nonce = 0u64;
        while !verify_pow_solution(token, nonce, 10) {
            nonce += 1;
        }
        assert!(verify_pow_solution(token, nonce, 10));

        let claims = ClearanceClaims {
            host: "example.com".into(),
            expires_at: 4_000_000_000,
            ua_hash: Some(short_sha256_hex("Mozilla/5.0")),
            ip_prefix: Some("203.0.113".into()),
        };
        let cookie = sign_clearance_cookie("secret-key", &claims).unwrap();
        let decoded = verify_clearance_cookie("secret-key", &cookie).unwrap();
        assert_eq!(decoded.host, "example.com");
        assert!(verify_clearance_cookie("other-key", &cookie).is_err());
    }
}
