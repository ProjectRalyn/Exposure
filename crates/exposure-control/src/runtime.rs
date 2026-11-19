use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use exposure_core::config::{ControlConfig, ControlRole};
use exposure_core::Result;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::api::{build_router, ApiState};
use crate::client::ControlClient;
use crate::db::ControlDb;

pub struct ControlRuntime {
    cfg: ControlConfig,
    client: Arc<ControlClient>,
}

impl ControlRuntime {
    pub async fn new(cfg: ControlConfig) -> Result<Arc<Self>> {
        let db = ControlDb::open(&cfg.sqlite_path)?;
        if let Some(ref topo_path) = cfg.initial_topology_path {
            let existing = db.get_topology_yaml().await?;
            if existing.trim().is_empty() && std::path::Path::new(topo_path).exists() {
                let yaml = std::fs::read_to_string(topo_path)?;
                db.set_topology_yaml(&yaml).await?;
            }
        }
        let client = ControlClient::new(cfg.clone(), db)?;
        Ok(Arc::new(Self { cfg, client }))
    }

    pub fn client(&self) -> &Arc<ControlClient> {
        &self.client
    }

    /// Connect to bootstrap tunnel node(s), spawn active pull scheduler, and start Web Panel HTTP server.
    pub async fn start(self: &Arc<Self>) -> Result<SocketAddr> {
        if !self.cfg.bootstrap_nodes.is_empty() {
            if let Err(e) = self.client.connect_bootstrap().await {
                warn!(error = %e, "initial bootstrap tunnel connect failed; background reconnect active");
            }
        }

        // Background bootstrap keepalive + active telemetry pull scheduler
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let interval = Duration::from_secs(this.cfg.telemetry_pull_interval_secs.max(5));
            loop {
                if !this.client.is_bootstrap_connected().await
                    && !this.cfg.bootstrap_nodes.is_empty()
                {
                    let _ = this.client.connect_bootstrap().await;
                }
                if this.cfg.role == ControlRole::Active {
                    let _ = this.client.pull_all_telemetry().await;
                }
                tokio::time::sleep(interval).await;
            }
        });

        let listener = TcpListener::bind(&self.cfg.panel_listen_addr).await?;
        let bound = listener.local_addr()?;
        info!(
            control = %self.cfg.control_id,
            role = ?self.cfg.role,
            addr = %bound,
            "Control web panel started"
        );

        let router = build_router(ApiState {
            cfg: self.cfg.clone(),
            client: Arc::clone(&self.client),
        });
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, router).await {
                warn!(error = %e, "control web panel server exited");
            }
        });

        Ok(bound)
    }
}
