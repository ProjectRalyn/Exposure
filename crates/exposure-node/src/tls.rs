use std::collections::HashSet;
use std::io::BufReader;
use std::sync::Arc;

use dashmap::DashMap;
use exposure_core::config::TlsCertEntry;
use exposure_core::routing::normalize_host;
use exposure_core::{ExposureError, Result};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tracing::{info, warn};

/// Dynamic SNI certificate resolver supporting exact & wildcard domain hot-reloading,
/// keeping ACME/pushed certs (`dynamic_certs`) isolated from config file certs (`file_certs`).
#[derive(Debug, Default)]
pub struct DynamicCertResolver {
    dynamic_certs: DashMap<String, Arc<CertifiedKey>>,
    file_certs: DashMap<String, Arc<CertifiedKey>>,
}

fn parse_certified_key_pem(domain: &str, cert_pem: &str, key_pem: &str) -> Result<Arc<CertifiedKey>> {
    let mut cert_reader = BufReader::new(cert_pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| ExposureError::Crypto(format!("parse cert PEM for {domain}: {e}")))?;
    if certs.is_empty() {
        return Err(ExposureError::Crypto(format!(
            "no certificates found in PEM for {domain}"
        )));
    }

    let mut key_reader = BufReader::new(key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| ExposureError::Crypto(format!("parse private key PEM for {domain}: {e}")))?
        .ok_or_else(|| ExposureError::Crypto(format!("no private key found for {domain}")))?;

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| ExposureError::Crypto(format!("unsupported private key for {domain}: {e}")))?;

    let ck = CertifiedKey::new(certs, signing_key);
    ck.keys_match().map_err(|e| {
        ExposureError::Crypto(format!("certificate and private key mismatch for {domain}: {e}"))
    })?;
    Ok(Arc::new(ck))
}

impl DynamicCertResolver {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            dynamic_certs: DashMap::new(),
            file_certs: DashMap::new(),
        })
    }

    pub fn load_from_pem(&self, domain: &str, cert_pem: &str, key_pem: &str) -> Result<()> {
        let ck = parse_certified_key_pem(domain, cert_pem, key_pem)?;
        let key_domain = normalize_host(domain);
        self.dynamic_certs.insert(key_domain, ck);
        info!(domain = %domain, "loaded TLS certificate into dynamic resolver");
        Ok(())
    }

    /// Replace file-based certificates atomically (validating all files before updating, and pruning removed ones)
    /// without touching ACME/pushed certificates in `dynamic_certs`.
    pub fn load_from_files(&self, entries: &[TlsCertEntry]) -> Result<()> {
        let mut parsed: Vec<(String, Arc<CertifiedKey>)> = Vec::with_capacity(entries.len());
        for entry in entries {
            let cert_pem = std::fs::read_to_string(&entry.cert_path).map_err(|e| {
                ExposureError::Config(format!("read cert file {}: {e}", entry.cert_path))
            })?;
            let key_pem = std::fs::read_to_string(&entry.key_path).map_err(|e| {
                ExposureError::Config(format!("read key file {}: {e}", entry.key_path))
            })?;
            let ck = parse_certified_key_pem(&entry.domain, &cert_pem, &key_pem)?;
            parsed.push((normalize_host(&entry.domain), ck));
        }

        let new_set: HashSet<&str> = parsed.iter().map(|(d, _)| d.as_str()).collect();
        let old_domains: Vec<String> = self.file_certs.iter().map(|e| e.key().clone()).collect();
        for old in old_domains {
            if !new_set.contains(old.as_str()) {
                self.file_certs.remove(&old);
            }
        }
        for (domain, ck) in parsed {
            self.file_certs.insert(domain, ck);
        }
        Ok(())
    }

    pub fn build_server_config(self: &Arc<Self>) -> Result<Arc<ServerConfig>> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let resolver: Arc<dyn ResolvesServerCert> = self.clone();
        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Arc::new(cfg))
    }

    pub fn cert_count(&self) -> usize {
        let mut domains: HashSet<String> =
            HashSet::with_capacity(self.dynamic_certs.len() + self.file_certs.len());
        for entry in self.dynamic_certs.iter() {
            domains.insert(entry.key().clone());
        }
        for entry in self.file_certs.iter() {
            domains.insert(entry.key().clone());
        }
        domains.len()
    }

    fn resolve_exact_or_wildcard(&self, key: &str) -> Option<Arc<CertifiedKey>> {
        if let Some(c) = self.dynamic_certs.get(key) {
            return Some(Arc::clone(&c));
        }
        self.file_certs.get(key).map(|c| Arc::clone(&c))
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(sni) = client_hello.server_name() {
            let lower = normalize_host(sni);
            if let Some(exact) = self.resolve_exact_or_wildcard(&lower) {
                return Some(exact);
            }
            if let Some((_, rest)) = lower.split_once('.') {
                let wildcard = format!("*.{rest}");
                if let Some(wc) = self.resolve_exact_or_wildcard(&wildcard) {
                    return Some(wc);
                }
            }
        }
        // Only serve explicit wildcard default "*" certificate; never leak another tenant's certificate
        self.resolve_exact_or_wildcard("*")
    }
}

/// Extracted pre-TLS ClientHello metadata for unforgeable server-side JA3/GREASE/ALPN scoring.
#[derive(Debug, Clone, Default)]
pub struct ClientHelloSignal {
    pub sni: Option<String>,
    pub tls_version: u16,
    pub cipher_count: usize,
    pub extension_count: usize,
    pub has_alpn: bool,
    pub alpn_h2: bool,
    pub has_grease: bool,
    pub supported_groups_count: usize,
    pub fingerprint: Option<String>,
}

/// Check RFC 8701 GREASE codepoint: both bytes identical and `(byte & 0x0f) == 0x0a`.
#[inline]
fn is_grease_value(val: u16) -> bool {
    (val & 0x0f0f) == 0x0a0a && (val >> 8) == (val & 0xff)
}

/// Non-destructively peek at the TCP stream's TLS ClientHello before rustls consumes it.
pub async fn peek_client_hello(stream: &TcpStream) -> ClientHelloSignal {
    let mut buf = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(250);
    let mut last_n = 0usize;
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        match tokio::time::timeout(deadline - now, stream.peek(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                last_n = n;
                if buf[0] != 0x16 {
                    return ClientHelloSignal::default();
                }
                if n >= 5 {
                    let rec_len = 5usize + u16::from_be_bytes([buf[3], buf[4]]) as usize;
                    if n >= rec_len.min(buf.len()) {
                        break;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            _ => break,
        }
    }
    if last_n < 43 {
        return ClientHelloSignal::default();
    }
    parse_client_hello_bytes(&buf[..last_n]).unwrap_or_default()
}

pub fn parse_client_hello_bytes(data: &[u8]) -> Option<ClientHelloSignal> {
    if data.len() < 9 || data[0] != 0x16 {
        return None;
    }
    if data[5] != 0x01 {
        return None;
    }
    let mut pos = 9;
    if pos + 2 + 32 + 1 > data.len() {
        return None;
    }
    let tls_version = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2 + 32;

    let sid_len = data[pos] as usize;
    pos += 1 + sid_len;
    if pos + 2 > data.len() {
        return None;
    }

    let cs_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if pos + cs_len > data.len() {
        return None;
    }
    let mut ciphers = Vec::new();
    let mut has_grease = false;
    for chunk in data[pos..pos + cs_len].chunks_exact(2) {
        let c = u16::from_be_bytes([chunk[0], chunk[1]]);
        if is_grease_value(c) {
            has_grease = true;
        } else {
            ciphers.push(c);
        }
    }
    pos += cs_len;

    if pos + 1 > data.len() {
        return None;
    }
    let comp_len = data[pos] as usize;
    pos += 1 + comp_len;

    let mut extensions = Vec::new();
    let mut supported_groups = Vec::new();
    let mut ec_point_formats = Vec::new();
    let mut sni = None;
    let mut has_alpn = false;
    let mut alpn_h2 = false;

    if pos + 2 <= data.len() {
        let ext_total = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let ext_end = (pos + ext_total).min(data.len());
        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;
            if pos + ext_len > ext_end {
                break;
            }
            let ext_data = &data[pos..pos + ext_len];
            if is_grease_value(ext_type) {
                has_grease = true;
            } else {
                extensions.push(ext_type);
            }
            if ext_type == 0x0000 && ext_data.len() >= 5 {
                let name_type = ext_data[2];
                let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
                if name_type == 0 && 5 + name_len <= ext_data.len() {
                    if let Ok(host) = std::str::from_utf8(&ext_data[5..5 + name_len]) {
                        sni = Some(normalize_host(host));
                    }
                }
            } else if ext_type == 0x0010 && ext_data.len() >= 2 {
                has_alpn = true;
                let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                let mut ap = 2;
                let ap_end = (2 + list_len).min(ext_data.len());
                while ap < ap_end {
                    let plen = ext_data[ap] as usize;
                    ap += 1;
                    if ap + plen > ap_end {
                        break;
                    }
                    if &ext_data[ap..ap + plen] == b"h2" {
                        alpn_h2 = true;
                    }
                    ap += plen;
                }
            } else if ext_type == 0x000a && ext_data.len() >= 2 {
                // supported_groups (elliptic curves)
                let g_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                let g_end = (2 + g_len).min(ext_data.len());
                for chunk in ext_data[2..g_end].chunks_exact(2) {
                    let g = u16::from_be_bytes([chunk[0], chunk[1]]);
                    if is_grease_value(g) {
                        has_grease = true;
                    } else {
                        supported_groups.push(g);
                    }
                }
            } else if ext_type == 0x000b && !ext_data.is_empty() {
                // ec_point_formats
                let f_len = ext_data[0] as usize;
                let f_end = (1 + f_len).min(ext_data.len());
                ec_point_formats.extend_from_slice(&ext_data[1..f_end]);
            }
            pos += ext_len;
        }
    }

    let raw_fp = format!(
        "{},{},{},{},{}",
        tls_version,
        ciphers
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-"),
        extensions
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-"),
        supported_groups
            .iter()
            .map(|g| g.to_string())
            .collect::<Vec<_>>()
            .join("-"),
        ec_point_formats
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join("-")
    );
    let mut hasher = Sha256::new();
    hasher.update(raw_fp.as_bytes());
    let fp = hex::encode(&hasher.finalize()[..12]);

    Some(ClientHelloSignal {
        sni,
        tls_version,
        cipher_count: ciphers.len(),
        extension_count: extensions.len(),
        has_alpn,
        alpn_h2,
        has_grease,
        supported_groups_count: supported_groups.len(),
        fingerprint: Some(fp),
    })
}

/// Generate a self-signed certificate for local testing / dev mode.
pub fn generate_self_signed_pem(domain: &str) -> Result<(String, String)> {
    let cert = rcgen::generate_simple_self_signed(vec![domain.to_string()])
        .map_err(|e| ExposureError::Crypto(format!("rcgen self-signed cert: {e}")))?;
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    warn!(domain = %domain, "generated self-signed certificate");
    Ok((cert_pem, key_pem))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_mask_matches_rfc8701_only() {
        assert!(is_grease_value(0x0a0a));
        assert!(is_grease_value(0xfafa));
        assert!(!is_grease_value(0x0a1a));
        assert!(!is_grease_value(0x1301));
    }

    #[test]
    fn file_reload_does_not_overwrite_dynamic_certs() {
        let store = DynamicCertResolver::new();
        let (cert_a, key_a) = generate_self_signed_pem("dyn.example.com").unwrap();
        let (cert_b, key_b) = generate_self_signed_pem("file.example.com").unwrap();
        store.load_from_pem("dyn.example.com", &cert_a, &key_a).unwrap();
        let tmp = std::env::temp_dir().join(format!("exp-tls-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let cp = tmp.join("f.crt");
        let kp = tmp.join("f.key");
        std::fs::write(&cp, &cert_b).unwrap();
        std::fs::write(&kp, &key_b).unwrap();
        store
            .load_from_files(&[TlsCertEntry {
                domain: "file.example.com".into(),
                cert_path: cp.to_string_lossy().into_owned(),
                key_path: kp.to_string_lossy().into_owned(),
            }])
            .unwrap();
        assert_eq!(store.cert_count(), 2);
        // Empty file reload prunes file_certs but keeps dynamic_certs intact.
        store.load_from_files(&[]).unwrap();
        assert_eq!(store.cert_count(), 1);
        assert!(store.resolve_exact_or_wildcard("dyn.example.com").is_some());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
