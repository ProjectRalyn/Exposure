use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use exposure_control::compiler::compile_topology;
use exposure_control::ControlRuntime;
use exposure_core::config::{
    AdminAuthConfig, BootstrapNodeTarget, ControlConfig, ControlRole, LinkListenConfig,
    MaintainerConfig, NodeConfig, NodeRoles, TopologySpec,
};
use exposure_core::crypto::{generate_five_word_passphrase, NodeKeyPair};
use exposure_node::NodeRuntime;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "exposure", version, about = "Exposure reverse proxy, mesh, guard & telemetry platform")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new Node bootstrap config and emit a one-time 5-word onboarding passphrase.
    InitNode {
        #[arg(long)]
        tag: String,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        listen: Option<String>,
        #[arg(long)]
        bootstrap: Option<String>,
        #[arg(long)]
        ingress: bool,
        #[arg(long)]
        egress: bool,
        #[arg(long)]
        relay: bool,
        #[arg(long)]
        maintainer: bool,
    },
    /// Initialize a Control plane config with fresh Ed25519 keys.
    InitControl {
        #[arg(long, default_value = "control-1")]
        id: String,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8090")]
        panel: String,
        #[arg(long, default_value = "./data/control.db")]
        sqlite: String,
        #[arg(long, default_value = "admin")]
        admin_user: String,
        #[arg(long, default_value = "exposure-admin")]
        admin_password: String,
        #[arg(long)]
        bootstrap_tag: Option<String>,
        #[arg(long)]
        bootstrap_addr: Option<String>,
        #[arg(long)]
        bootstrap_passphrase: Option<String>,
    },
    /// Run an Exposure Node (ingress / egress / relay / maintainer).
    Node {
        #[arg(short, long)]
        config: PathBuf,
        /// Optional one-time 5-word passphrase for initial onboarding (valid 10 minutes).
        #[arg(long)]
        passphrase: Option<String>,
        /// Generate and print a fresh one-time 5-word passphrase on startup.
        #[arg(long)]
        reset_passphrase: bool,
    },
    /// Run the Exposure Control plane & Web Admin Panel.
    Control {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Generate a standalone Ed25519 keypair and fingerprint.
    Keygen,
    /// Validate a Topology YAML file using the Control compiler (loop, ACL, reachability checks).
    ValidateTopology {
        #[arg(short, long)]
        file: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::InitNode {
            tag,
            output,
            listen,
            bootstrap,
            ingress,
            egress,
            relay,
            maintainer,
        } => {
            let kp = NodeKeyPair::generate();
            let passphrase = generate_five_word_passphrase();
            let cfg = NodeConfig {
                node_tag: tag.clone(),
                identity_secret_key: kp.secret_key_b64(),
                control_public_key: None,
                roles: NodeRoles {
                    ingress,
                    egress,
                    relay,
                    maintainer,
                },
                link_listener: listen.map(|addr| LinkListenConfig {
                    listen_addr: addr,
                    allow_on_demand: true,
                    allow_tunnel: true,
                    allow_bootstrap: true,
                }),
                peers: vec![],
                probe: Default::default(),
                default_ttl: 16,
                maintainer_hops: vec![],
                trusted_maintainers: vec![],
                logger: Default::default(),
                ingress: Default::default(),
                egress: Default::default(),
                relay: Default::default(),
                maintainer: if maintainer {
                    Some(MaintainerConfig::default())
                } else {
                    None
                },
                bootstrap_tunnel_addr: bootstrap,
                config_sequence: 0,
            };
            if let Some(parent) = output.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            let yaml = serde_yaml::to_string(&cfg)?;
            std::fs::write(&output, yaml)?;

            println!("Node initialized: {}", output.display());
            println!("Node Tag:         {}", tag);
            println!("Public Key:       {}", kp.public_key_b64());
            println!("Fingerprint:      {}", kp.fingerprint());
            println!("One-time Passphrase (valid 10m, shown once — start node with --passphrase):");
            println!("  {}", passphrase);
        }
        Commands::InitControl {
            id,
            output,
            panel,
            sqlite,
            admin_user,
            admin_password,
            bootstrap_tag,
            bootstrap_addr,
            bootstrap_passphrase,
        } => {
            let sign_kp = NodeKeyPair::generate();
            let bootstrap_nodes = match (bootstrap_tag, bootstrap_addr) {
                (Some(node_tag), Some(address)) => vec![BootstrapNodeTarget {
                    node_tag,
                    address,
                    public_key: None,
                    passphrase: bootstrap_passphrase,
                }],
                _ => vec![],
            };
            let cfg = ControlConfig {
                control_id: id.clone(),
                role: ControlRole::Active,
                panel_listen_addr: panel,
                sqlite_path: sqlite,
                signing_secret_key: sign_kp.secret_key_b64(),
                link_secret_key: sign_kp.secret_key_b64(),
                admin: AdminAuthConfig {
                    username: admin_user,
                    password: admin_password,
                    token_secret: NodeKeyPair::generate().fingerprint(),
                },
                bootstrap_nodes,
                telemetry_pull_interval_secs: 30,
                initial_topology_path: None,
            };
            if let Some(parent) = output.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            std::fs::write(&output, serde_yaml::to_string(&cfg)?)?;
            println!("Control initialized: {}", output.display());
            println!("Control ID:          {}", id);
            println!("Signing Public Key:  {}", sign_kp.public_key_b64());
            println!("Fingerprint:         {}", sign_kp.fingerprint());
        }
        Commands::Node {
            config,
            passphrase,
            reset_passphrase,
        } => {
            let raw = std::fs::read_to_string(&config)
                .with_context(|| format!("read node config {}", config.display()))?;
            let cfg: NodeConfig = serde_yaml::from_str(&raw)?;
            let phrase = if reset_passphrase || (passphrase.is_none() && cfg.control_public_key.is_none()) {
                let p = passphrase.unwrap_or_else(generate_five_word_passphrase);
                println!("========================================================");
                println!("ONE-TIME ONBOARDING PASSPHRASE (valid 10m, shown once):");
                println!("  {p}");
                println!("========================================================");
                Some(p)
            } else {
                passphrase
            };

            let runtime = NodeRuntime::new(cfg, Some(config), phrase).await?;
            let (link_addr, ingress_addrs) = runtime.start().await?;
            info!(
                node = %runtime.node_tag(),
                link_addr = ?link_addr,
                ingress_addrs = ?ingress_addrs,
                "Exposure Node running"
            );

            wait_for_shutdown_signal().await;
            runtime.shutdown().await;
        }
        Commands::Control { config } => {
            let raw = std::fs::read_to_string(&config)
                .with_context(|| format!("read control config {}", config.display()))?;
            let cfg: ControlConfig = serde_yaml::from_str(&raw)?;
            let runtime = ControlRuntime::new(cfg).await?;
            let bound = runtime.start().await?;
            info!(panel = %bound, "Exposure Control running");

            wait_for_shutdown_signal().await;
        }
        Commands::Keygen => {
            let kp = NodeKeyPair::generate();
            println!("secret_key:  {}", kp.secret_key_b64());
            println!("public_key:  {}", kp.public_key_b64());
            println!("fingerprint: {}", kp.fingerprint());
        }
        Commands::ValidateTopology { file } => {
            let raw = std::fs::read_to_string(&file)?;
            let topo: TopologySpec = serde_yaml::from_str(&raw)?;
            let (report, _) = compile_topology(&topo, "preview-key", &HashMap::new(), &HashMap::new());
            println!("{}", serde_yaml::to_string(&report)?);
            if !report.valid {
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
