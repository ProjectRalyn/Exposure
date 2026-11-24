use std::future::Future;
use std::path::Path;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use exposure_core::error::{ExposureError, Result};
use exposure_core::crypto::write_secret_file_atomic;
use reqwest::Client;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracing::{debug, info};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcmeDirectory {
    new_nonce: String,
    new_account: String,
    new_order: String,
}

#[derive(Debug, Deserialize)]
struct AcmeOrder {
    status: String,
    #[serde(default)]
    authorizations: Vec<String>,
    finalize: String,
    #[serde(default)]
    certificate: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AcmeAuthz {
    status: String,
    #[serde(default)]
    challenges: Vec<AcmeChallenge>,
}

#[derive(Debug, Deserialize)]
struct AcmeChallenge {
    #[serde(rename = "type")]
    kind: String,
    url: String,
    token: String,
}

struct AcmeClient {
    http: Client,
    rng: SystemRandom,
    key: EcdsaKeyPair,
    jwk: Value,
    jwk_thumbprint: String,
    dir: AcmeDirectory,
    nonce: String,
    kid: Option<String>,
}

fn b64u(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn load_or_create_account_key(storage_dir: &str, rng: &SystemRandom) -> Result<EcdsaKeyPair> {
    if !storage_dir.is_empty() {
        let dir = Path::new(storage_dir);
        std::fs::create_dir_all(dir)?;
        let key_path = dir.join("acme_account.p256.pk8");
        if key_path.exists() {
            let bytes = std::fs::read(&key_path)?;
            return EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &bytes, rng)
                .map_err(|e| ExposureError::Crypto(format!("load ACME account key: {e}")));
        }
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, rng)
            .map_err(|e| ExposureError::Crypto(format!("generate ACME account key: {e}")))?;
        write_secret_file_atomic(&key_path, doc.as_ref())?;
        return EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, doc.as_ref(), rng)
            .map_err(|e| ExposureError::Crypto(format!("parse ACME account key: {e}")));
    }
    let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, rng)
        .map_err(|e| ExposureError::Crypto(format!("generate ACME account key: {e}")))?;
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, doc.as_ref(), rng)
        .map_err(|e| ExposureError::Crypto(format!("parse ACME account key: {e}")))
}

impl AcmeClient {
    async fn connect(http: Client, directory_url: &str, storage_dir: &str) -> Result<Self> {
        let storage_owned = storage_dir.to_string();
        let key = tokio::task::spawn_blocking(move || {
            let rng = SystemRandom::new();
            load_or_create_account_key(&storage_owned, &rng)
        })
        .await
        .map_err(|e| ExposureError::Crypto(format!("ACME key task join: {e}")))??;
        let rng = SystemRandom::new();

        let pub_bytes = key.public_key().as_ref();
        if pub_bytes.len() != 65 || pub_bytes[0] != 0x04 {
            return Err(ExposureError::Crypto("unexpected P-256 public key format".into()));
        }
        let x = b64u(&pub_bytes[1..33]);
        let y = b64u(&pub_bytes[33..65]);
        // Canonical key order per RFC 7638: crv, kty, x, y
        let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
        let jwk_thumbprint = b64u(&Sha256::digest(canonical.as_bytes()));
        let jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
        });

        let dir: AcmeDirectory = http
            .get(directory_url)
            .send()
            .await
            .map_err(|e| ExposureError::Link(format!("ACME directory GET: {e}")))?
            .error_for_status()
            .map_err(|e| ExposureError::Link(format!("ACME directory status: {e}")))?
            .json()
            .await
            .map_err(|e| ExposureError::Protocol(format!("ACME directory json: {e}")))?;

        let mut client = Self {
            http,
            rng,
            key,
            jwk,
            jwk_thumbprint,
            dir,
            nonce: String::new(),
            kid: None,
        };
        client.refresh_nonce().await?;
        Ok(client)
    }

    async fn refresh_nonce(&mut self) -> Result<()> {
        let resp = self
            .http
            .head(&self.dir.new_nonce)
            .send()
            .await
            .map_err(|e| ExposureError::Link(format!("ACME newNonce: {e}")))?;
        self.nonce = resp
            .headers()
            .get("replay-nonce")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| ExposureError::Protocol("ACME newNonce missing Replay-Nonce".into()))?
            .to_string();
        Ok(())
    }

    async fn jws_post(&mut self, url: &str, payload: Option<&Value>) -> Result<(reqwest::header::HeaderMap, String)> {
        for attempt in 0..3 {
            let protected = match &self.kid {
                Some(kid) => json!({
                    "alg": "ES256",
                    "kid": kid,
                    "nonce": self.nonce,
                    "url": url,
                }),
                None => json!({
                    "alg": "ES256",
                    "jwk": self.jwk,
                    "nonce": self.nonce,
                    "url": url,
                }),
            };
            let protected_b64 = b64u(protected.to_string().as_bytes());
            let payload_b64 = match payload {
                Some(v) => b64u(v.to_string().as_bytes()),
                None => String::new(),
            };
            let signing_input = format!("{protected_b64}.{payload_b64}");
            let sig = self
                .key
                .sign(&self.rng, signing_input.as_bytes())
                .map_err(|e| ExposureError::Crypto(format!("ACME JWS sign: {e}")))?;
            let body = json!({
                "protected": protected_b64,
                "payload": payload_b64,
                "signature": b64u(sig.as_ref()),
            });

            let resp = self
                .http
                .post(url)
                .header("Content-Type", "application/jose+json")
                .json(&body)
                .send()
                .await
                .map_err(|e| ExposureError::Link(format!("ACME POST {url}: {e}")))?;

            let mut got_fresh_nonce = false;
            if let Some(next_nonce) = resp.headers().get("replay-nonce").and_then(|v| v.to_str().ok()) {
                self.nonce = next_nonce.to_string();
                got_fresh_nonce = true;
            }

            let status = resp.status();
            let headers = resp.headers().clone();
            let text = resp
                .text()
                .await
                .map_err(|e| ExposureError::Protocol(format!("ACME response body: {e}")))?;

            if status.is_success() {
                return Ok((headers, text));
            }
            if attempt < 2 && text.contains("badNonce") {
                debug!("ACME badNonce received; refreshing nonce and retrying");
                if !got_fresh_nonce || attempt > 0 {
                    self.refresh_nonce().await?;
                }
                continue;
            }
            return Err(ExposureError::Link(format!("ACME {url} failed ({status}): {text}")));
        }
        Err(ExposureError::Link(format!("ACME {url} failed after nonce retry")))
    }

    async fn register_account(&mut self, contact_email: &str) -> Result<()> {
        let mut payload = json!({ "termsOfServiceAgreed": true });
        if !contact_email.trim().is_empty() {
            payload["contact"] = json!([format!("mailto:{}", contact_email.trim())]);
        }
        let (headers, _) = self.jws_post(&self.dir.new_account.clone(), Some(&payload)).await?;
        let kid = headers
            .get("location")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| ExposureError::Protocol("ACME newAccount missing Location header".into()))?
            .to_string();
        self.kid = Some(kid);
        Ok(())
    }
}

pub async fn issue_acme_dns01_cert<FP, FutP, FC, FutC>(
    http: Client,
    directory_url: &str,
    contact_email: &str,
    storage_dir: &str,
    domain: &str,
    present_fn: FP,
    cleanup_fn: FC,
) -> Result<(String, String)>
where
    FP: Fn(String) -> FutP,
    FutP: Future<Output = Result<Option<String>>>,
    FC: Fn(String, Option<String>) -> FutC,
    FutC: Future<Output = ()>,
{
    let mut client = AcmeClient::connect(http, directory_url, storage_dir).await?;
    client.register_account(contact_email).await?;

    let order_payload = json!({
        "identifiers": [{ "type": "dns", "value": domain }]
    });
    let (order_headers, order_body) = client
        .jws_post(&client.dir.new_order.clone(), Some(&order_payload))
        .await?;
    let order_url = order_headers
        .get("location")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ExposureError::Protocol("ACME newOrder missing Location".into()))?
        .to_string();
    let order: AcmeOrder = serde_json::from_str(&order_body)
        .map_err(|e| ExposureError::Protocol(format!("ACME order json: {e}")))?;

    for authz_url in &order.authorizations {
        let (_, authz_body) = client.jws_post(authz_url, None).await?;
        let authz: AcmeAuthz = serde_json::from_str(&authz_body)
            .map_err(|e| ExposureError::Protocol(format!("ACME authz json: {e}")))?;
        if authz.status == "valid" {
            continue;
        }
        let chall = authz
            .challenges
            .iter()
            .find(|c| c.kind == "dns-01")
            .ok_or_else(|| ExposureError::Protocol("ACME authz missing dns-01 challenge".into()))?;

        let key_auth = format!("{}.{}", chall.token, client.jwk_thumbprint);
        let txt_val = b64u(&Sha256::digest(key_auth.as_bytes()));

        let rec_id = present_fn(txt_val.clone()).await?;
        info!(domain = %domain, "ACME DNS-01 TXT record published; waiting for DNS propagation");
        tokio::time::sleep(Duration::from_secs(10)).await;

        let res = async {
            client.jws_post(&chall.url, Some(&json!({}))).await?;
            for _ in 0..25 {
                tokio::time::sleep(Duration::from_secs(3)).await;
                let (_, poll_body) = client.jws_post(authz_url, None).await?;
                let polled: AcmeAuthz = serde_json::from_str(&poll_body)
                    .map_err(|e| ExposureError::Protocol(format!("ACME authz poll json: {e}")))?;
                if polled.status == "valid" {
                    return Ok(());
                }
                if polled.status == "invalid" {
                    return Err(ExposureError::Link(format!(
                        "ACME dns-01 authorization invalid for {domain}: {poll_body}"
                    )));
                }
            }
            Err(ExposureError::Link(format!(
                "ACME dns-01 authorization timed out for {domain}"
            )))
        }
        .await;

        cleanup_fn(txt_val, rec_id).await;
        res?;
    }

    let domain_kp = rcgen::KeyPair::generate()
        .map_err(|e| ExposureError::Crypto(format!("generate domain keypair: {e}")))?;
    let mut params = rcgen::CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| ExposureError::Crypto(format!("CSR params: {e}")))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    if domain.len() <= 64 {
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, domain);
    }
    let csr = params
        .serialize_request(&domain_kp)
        .map_err(|e| ExposureError::Crypto(format!("serialize CSR: {e}")))?;

    client
        .jws_post(&order.finalize, Some(&json!({ "csr": b64u(csr.der()) })))
        .await?;

    let cert_url = {
        let mut found = None;
        for _ in 0..20 {
            let (_, poll_body) = client.jws_post(&order_url, None).await?;
            let polled: AcmeOrder = serde_json::from_str(&poll_body)
                .map_err(|e| ExposureError::Protocol(format!("ACME order poll json: {e}")))?;
            if polled.status == "valid" {
                if let Some(url) = polled.certificate {
                    found = Some(url);
                    break;
                }
            }
            if polled.status == "invalid" {
                return Err(ExposureError::Link(format!(
                    "ACME order invalid for {domain}: {poll_body}"
                )));
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        found.ok_or_else(|| ExposureError::Link(format!("ACME order finalize timed out for {domain}")))?
    };

    let (_, cert_pem) = client.jws_post(&cert_url, None).await?;
    let key_pem = domain_kp.serialize_pem();
    info!(domain = %domain, "ACME DNS-01 certificate issued successfully");
    Ok((cert_pem, key_pem))
}
