use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use exposure_core::config::{ControlConfig, ControlRole, ControlTlsConfig};
use exposure_core::crypto::{is_valid_argon2_hash, is_weak_secret};
use exposure_core::{ExposureError, Result};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use crate::api::{build_router, ApiState};
use crate::client::ControlClient;
use crate::db::ControlDb;

pub struct ControlRuntime {
    cfg: ControlConfig,
    client: Arc<ControlClient>,
    shutdown_tx: watch::Sender<bool>,
}

fn build_control_tls_acceptor(tls: &ControlTlsConfig) -> Result<TlsAcceptor> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert_bytes = std::fs::read(&tls.cert_path)
        .map_err(|e| ExposureError::Config(format!("read control TLS cert {}: {e}", tls.cert_path)))?;
    let key_bytes = std::fs::read(&tls.key_path)
        .map_err(|e| ExposureError::Config(format!("read control TLS key {}: {e}", tls.key_path)))?;

    let mut cert_reader = BufReader::new(&cert_bytes[..]);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| ExposureError::Crypto(format!("parse control TLS cert: {e}")))?;
    if certs.is_empty() {
        return Err(ExposureError::Crypto("no certificates in control TLS cert file".into()));
    }
    let mut key_reader = BufReader::new(&key_bytes[..]);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| ExposureError::Crypto(format!("parse control TLS key: {e}")))?
        .ok_or_else(|| ExposureError::Crypto("no private key in control TLS key file".into()))?;

    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ExposureError::Crypto(format!("control TLS config: {e}")))?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

impl ControlRuntime {
    pub async fn new(cfg: ControlConfig) -> Result<Arc<Self>> {
        // Refuse to start with weak/default token_secret or missing Argon2id password hash
        if is_weak_secret(&cfg.admin.token_secret) || cfg.admin.token_secret.trim().len() < 32 {
            return Err(ExposureError::Config(
                "admin.token_secret must be a high-entropy random secret (>= 32 chars)".into(),
            ));
        }
        if !is_valid_argon2_hash(&cfg.admin.password_hash) {
            return Err(ExposureError::Config(
                "admin.password_hash must be a valid Argon2id PHC hash ($argon2id$...)".into(),
            ));
        }
        if cfg.admin.username.trim().is_empty() || cfg.admin.username.contains(':') {
            return Err(ExposureError::Config(
                "admin.username must be non-empty and must not contain ':'".into(),
            ));
        }

        let db = ControlDb::open(&cfg.sqlite_path)?;
        if let Some(ref topo_path) = cfg.initial_topology_path {
            let existing = db.get_topology_yaml().await?;
            if existing.trim().is_empty() && tokio::fs::try_exists(topo_path).await.unwrap_or(false) {
                let yaml = tokio::fs::read_to_string(topo_path).await?;
                // Validate YAML parses cleanly before persisting
                let _: exposure_core::config::TopologySpec = serde_yaml::from_str(&yaml)
                    .map_err(|e| ExposureError::Config(format!("invalid initial_topology_path YAML: {e}")))?;
                db.set_topology_yaml(&yaml).await?;
            }
        }
        let client = ControlClient::new(cfg.clone(), db)?;
        client.restore_telemetry_cache().await;
        let (shutdown_tx, _) = watch::channel(false);
        Ok(Arc::new(Self {
            cfg,
            client,
            shutdown_tx,
        }))
    }

    pub fn client(&self) -> &Arc<ControlClient> {
        &self.client
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Connect to bootstrap tunnel node(s), spawn keepalive + telemetry pull + DB pruning loops, and start Web Panel.
    pub async fn start(self: &Arc<Self>) -> Result<SocketAddr> {
        if !self.cfg.bootstrap_nodes.is_empty() {
            if let Err(e) = self.client.connect_bootstrap().await {
                warn!(error = %e, "initial bootstrap tunnel connect failed; background reconnect active");
            }
        }

        // Dedicated bootstrap reconnect loop (never stalled by slow telemetry pulls!)
        {
            let this = Arc::clone(self);
            let mut rx = self.shutdown_tx.subscribe();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = rx.changed() => {
                            if *rx.borrow() {
                                return;
                            }
                        }
                        _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                    }
                    if !this.client.is_bootstrap_connected().await
                        && !this.cfg.bootstrap_nodes.is_empty()
                    {
                        if let Err(e) = this.client.connect_bootstrap().await {
                            warn!(error = %e, "background bootstrap reconnect failed");
                        }
                    }
                }
            });
        }

        // Dedicated active telemetry pull + periodic SQLite retention pruning loop
        {
            let this = Arc::clone(self);
            let mut rx = self.shutdown_tx.subscribe();
            tokio::spawn(async move {
                let interval = Duration::from_secs(this.cfg.telemetry_pull_interval_secs.max(5));
                let mut last_cleanup = std::time::Instant::now();
                loop {
                    tokio::select! {
                        _ = rx.changed() => {
                            if *rx.borrow() {
                                return;
                            }
                        }
                        _ = tokio::time::sleep(interval) => {}
                    }
                    if this.cfg.role == ControlRole::Active {
                        if let Err(e) = this.client.pull_all_telemetry().await {
                            warn!(error = %e, "periodic telemetry pull failed");
                        }
                    }
                    let ret = this
                        .client
                        .db()
                        .get_control_retention_config()
                        .await
                        .unwrap_or_default();
                    let cleanup_every =
                        Duration::from_secs(u64::from(ret.control_cleanup_interval_mins.max(5)) * 60);
                    if last_cleanup.elapsed() >= cleanup_every {
                        last_cleanup = std::time::Instant::now();
                        if let Err(e) = this.client.db().prune_old_records(&ret).await {
                            warn!(error = %e, "periodic sqlite pruning failed");
                        }
                    }
                }
            });
        }

        // Background OWASP CRS auto-updater loop (active Control only)
        if self.cfg.role == ControlRole::Active {
            let this = Arc::clone(self);
            let mut rx = self.shutdown_tx.subscribe();
            tokio::spawn(async move {
                // Short startup grace delay before first check so bootstrap & panel bind finish cleanly
                let mut first_wait = Duration::from_secs(30);
                loop {
                    tokio::select! {
                        _ = rx.changed() => {
                            if *rx.borrow() {
                                return;
                            }
                        }
                        _ = tokio::time::sleep(first_wait) => {}
                    }
                    first_wait = Duration::from_secs(30 * 60);

                    let crs_cfg = match this.client.db().get_topology_yaml().await {
                        Ok(yaml) if !yaml.trim().is_empty() => {
                            serde_yaml::from_str::<exposure_core::config::TopologySpec>(&yaml)
                                .map(|t| t.defaults.ingress.crs)
                                .unwrap_or_default()
                        }
                        _ => exposure_core::config::CrsUpdateConfig::default(),
                    };
                    if !crs_cfg.auto_update {
                        continue;
                    }
                    let interval_secs = (crs_cfg.update_interval_hours.clamp(1, 720) as i64) * 3600;
                    let needs_sync = match this
                        .client
                        .db()
                        .get_kv_json::<exposure_core::crs::CrsRulesetSnapshot>(
                            crate::client::KV_CRS_RULESET,
                        )
                        .await
                    {
                        Ok(Some(snap)) => {
                            if snap.rules.is_empty() {
                                true
                            } else {
                                chrono::DateTime::parse_from_rfc3339(&snap.updated_at)
                                    .map(|dt| {
                                        chrono::Utc::now().timestamp() - dt.timestamp()
                                            >= interval_secs
                                    })
                                    .unwrap_or(true)
                            }
                        }
                        _ => true,
                    };
                    if needs_sync {
                        match this.client.sync_owasp_crs("crs-auto-updater").await {
                            Ok(snap) => {
                                info!(
                                    version = %snap.version,
                                    rules = snap.rules.len(),
                                    "auto-updated OWASP CRS ruleset"
                                );
                            }
                            Err(e) => {
                                warn!(error = %e, "background OWASP CRS auto-update failed (will retry)");
                            }
                        }
                    }
                }
            });
        }

        let listener = TcpListener::bind(&self.cfg.panel_listen_addr).await?;
        let bound = listener.local_addr()?;

        let tls_acceptor = if let Some(ref tls_cfg) = self.cfg.tls {
            Some(build_control_tls_acceptor(tls_cfg)?)
        } else {
            if !bound.ip().is_loopback() {
                warn!(
                    addr = %bound,
                    "Control web panel is bound to a non-loopback address without TLS; configure `tls:` or place behind a TLS reverse proxy"
                );
            }
            None
        };

        info!(
            control = %self.cfg.control_id,
            role = ?self.cfg.role,
            addr = %bound,
            tls = tls_acceptor.is_some(),
            "Control web panel started"
        );

        let router = build_router(ApiState::new(self.cfg.clone(), Arc::clone(&self.client)));
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let conn_sem = Arc::new(Semaphore::new(512));

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    accept_res = listener.accept() => {
                        let Ok((tcp, _)) = accept_res else {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        };
                        let Ok(permit) = Arc::clone(&conn_sem).try_acquire_owned() else {
                            warn!("control panel connection dropped: concurrent limit reached");
                            continue;
                        };
                        let acc_opt = tls_acceptor.clone();
                        let svc = TowerToHyperService::new(router.clone());
                        tokio::spawn(async move {
                            let _permit = permit;
                            let mut builder = AutoServerBuilder::new(TokioExecutor::new());
                            builder
                                .http1()
                                .timer(TokioTimer::new())
                                .header_read_timeout(Duration::from_secs(10))
                                .max_headers(100);
                            builder
                                .http2()
                                .timer(TokioTimer::new())
                                .keep_alive_interval(Duration::from_secs(30))
                                .keep_alive_timeout(Duration::from_secs(15));
                            if let Some(acc) = acc_opt {
                                if let Ok(Ok(tls_stream)) = tokio::time::timeout(
                                    Duration::from_secs(10),
                                    acc.accept(tcp),
                                ).await {
                                    let _ = builder
                                        .serve_connection(TokioIo::new(tls_stream), svc)
                                        .await;
                                }
                            } else {
                                let _ = builder
                                    .serve_connection(TokioIo::new(tcp), svc)
                                    .await;
                            }
                        });
                    }
                }
            }
        });

        Ok(bound)
    }
}
