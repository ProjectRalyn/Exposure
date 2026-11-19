use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use dashmap::DashMap;
use exposure_core::config::TlsCertEntry;
use exposure_core::{ExposureError, Result};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tracing::{info, warn};

/// Dynamic SNI certificate resolver supporting exact & wildcard domain hot-reloading.
#[derive(Debug, Default)]
pub struct DynamicCertResolver {
    certs: DashMap<String, Arc<CertifiedKey>>,
}

impl DynamicCertResolver {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            certs: DashMap::new(),
        })
    }

    pub fn load_from_pem(&self, domain: &str, cert_pem: &str, key_pem: &str) -> Result<()> {
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

        let ck = Arc::new(CertifiedKey::new(certs, signing_key));
        self.certs.insert(domain.trim().to_ascii_lowercase(), ck);
        info!(domain = %domain, "loaded TLS certificate into dynamic resolver");
        Ok(())
    }

    pub fn load_from_files(&self, entries: &[TlsCertEntry]) -> Result<()> {
        for entry in entries {
            let cert_pem = std::fs::read_to_string(&entry.cert_path).map_err(|e| {
                ExposureError::Config(format!("read cert file {}: {e}", entry.cert_path))
            })?;
            let key_pem = std::fs::read_to_string(&entry.key_path).map_err(|e| {
                ExposureError::Config(format!("read key file {}: {e}", entry.key_path))
            })?;
            self.load_from_pem(&entry.domain, &cert_pem, &key_pem)?;
        }
        Ok(())
    }

    pub fn load_pem_file_pair(&self, domain: &str, cert_path: &Path, key_path: &Path) -> Result<()> {
        let mut cert_reader = BufReader::new(File::open(cert_path)?);
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| ExposureError::Crypto(format!("parse cert file: {e}")))?;
        let mut key_reader = BufReader::new(File::open(key_path)?);
        let key = rustls_pemfile::private_key(&mut key_reader)
            .map_err(|e| ExposureError::Crypto(format!("parse key file: {e}")))?
            .ok_or_else(|| ExposureError::Crypto("no private key in file".into()))?;
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
            .map_err(|e| ExposureError::Crypto(format!("unsupported key: {e}")))?;
        self.certs.insert(
            domain.trim().to_ascii_lowercase(),
            Arc::new(CertifiedKey::new(certs, signing_key)),
        );
        Ok(())
    }

    pub fn build_server_config(self: &Arc<Self>) -> Result<Arc<ServerConfig>> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let resolver: Arc<dyn ResolvesServerCert> = self.clone();
        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        // Support HTTP/2 and HTTP/1.1 via ALPN
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Arc::new(cfg))
    }

    pub fn cert_count(&self) -> usize {
        self.certs.len()
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(sni) = client_hello.server_name() {
            let lower = sni.to_ascii_lowercase();
            if let Some(exact) = self.certs.get(&lower) {
                return Some(Arc::clone(&exact));
            }
            // Wildcard match: a.b.example.com -> *.b.example.com
            if let Some((_, rest)) = lower.split_once('.') {
                let wildcard = format!("*.{rest}");
                if let Some(wc) = self.certs.get(&wildcard) {
                    return Some(Arc::clone(&wc));
                }
            }
        }
        if let Some(default) = self.certs.get("*") {
            return Some(Arc::clone(&default));
        }
        // Fallback to first loaded certificate if SNI omitted
        self.certs.iter().next().map(|e| Arc::clone(e.value()))
    }
}

/// Extracted pre-TLS ClientHello metadata for SNI routing and JA3-like bot scoring.
#[derive(Debug, Clone, Default)]
pub struct ClientHelloSignal {
    pub sni: Option<String>,
    pub tls_version: u16,
    pub cipher_count: usize,
    pub extension_count: usize,
    pub has_alpn: bool,
    pub fingerprint: Option<String>,
}

/// Non-destructively peek at the TCP stream's TLS ClientHello before rustls consumes it.
pub async fn peek_client_hello(stream: &TcpStream) -> ClientHelloSignal {
    let mut buf = [0u8; 2048];
    let n = match tokio::time::timeout(
        std::time::Duration::from_millis(250),
        stream.peek(&mut buf),
    )
    .await
    {
        Ok(Ok(n)) if n >= 43 => n,
        _ => return ClientHelloSignal::default(),
    };
    parse_client_hello_bytes(&buf[..n]).unwrap_or_default()
}

pub fn parse_client_hello_bytes(data: &[u8]) -> Option<ClientHelloSignal> {
    // TLS record header: type=0x16 (Handshake), version(2), length(2)
    if data.len() < 9 || data[0] != 0x16 {
        return None;
    }
    // Handshake header: type=0x01 (ClientHello), len(3)
    if data[5] != 0x01 {
        return None;
    }
    let mut pos = 9;
    if pos + 2 + 32 + 1 > data.len() {
        return None;
    }
    let tls_version = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2 + 32; // version + random

    // Session ID
    let sid_len = data[pos] as usize;
    pos += 1 + sid_len;
    if pos + 2 > data.len() {
        return None;
    }

    // Cipher suites
    let cs_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if pos + cs_len > data.len() {
        return None;
    }
    let mut ciphers = Vec::new();
    for chunk in data[pos..pos + cs_len].chunks_exact(2) {
        let c = u16::from_be_bytes([chunk[0], chunk[1]]);
        // Ignore GREASE values
        if (c & 0x0f0f) != 0x0a0a {
            ciphers.push(c);
        }
    }
    pos += cs_len;

    // Compression methods
    if pos + 1 > data.len() {
        return None;
    }
    let comp_len = data[pos] as usize;
    pos += 1 + comp_len;

    // Extensions
    let mut extensions = Vec::new();
    let mut sni = None;
    let mut has_alpn = false;

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
            if (ext_type & 0x0f0f) != 0x0a0a {
                extensions.push(ext_type);
            }
            if ext_type == 0x0000 && ext_data.len() >= 5 {
                // server_name extension
                let name_type = ext_data[2];
                let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
                if name_type == 0 && 5 + name_len <= ext_data.len() {
                    if let Ok(host) = std::str::from_utf8(&ext_data[5..5 + name_len]) {
                        sni = Some(host.to_string());
                    }
                }
            } else if ext_type == 0x0010 {
                has_alpn = true;
            }
            pos += ext_len;
        }
    }

    let raw_fp = format!(
        "{},{},{}",
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
