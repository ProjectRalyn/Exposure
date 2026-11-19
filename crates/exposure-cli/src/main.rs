use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use exposure_control::compiler::compile_topology_with_options;
use exposure_control::ControlRuntime;
use exposure_core::config::{
    AdminAuthConfig, BootstrapNodeTarget, ControlConfig, ControlRole, LinkListenConfig,
    MaintainerConfig, NodeConfig, NodeRoles, TopologySpec,
};
use exposure_core::crypto::{
    generate_five_word_passphrase, generate_random_secret_hex, hash_password, validate_identifier,
    write_secret_file_atomic, NodeKeyPair,
};
use exposure_node::NodeRuntime;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "exposure",
    version,
    about = "Exposure reverse proxy, mesh, guard & telemetry platform"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new Node bootstrap config (mode 0600, separate random secrets).
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
        /// Overwrite existing config file if present.
        #[arg(long)]
        force: bool,
    },
    /// Initialize a Control plane config with separate signing/link Ed25519 keys and Argon2id admin password hash.
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
        /// Optional admin password (or env EXPOSURE_ADMIN_PASSWORD); randomly generated if omitted.
        #[arg(long)]
        admin_password: Option<String>,
        /// Read admin password from a file (avoids process-list exposure).
        #[arg(long)]
        admin_password_file: Option<PathBuf>,
        #[arg(long)]
        bootstrap_tag: Option<String>,
        #[arg(long)]
        bootstrap_addr: Option<String>,
        /// Optional bootstrap passphrase (or env EXPOSURE_BOOTSTRAP_PASSPHRASE).
        #[arg(long)]
        bootstrap_passphrase: Option<String>,
        /// Read bootstrap passphrase from a file (avoids process-list exposure).
        #[arg(long)]
        bootstrap_passphrase_file: Option<PathBuf>,
        /// Overwrite existing config file if present.
        #[arg(long)]
        force: bool,
    },
    /// Run an Exposure Node (ingress / egress / relay / maintainer).
    Node {
        #[arg(short, long)]
        config: PathBuf,
        /// Optional one-time onboarding passphrase (prefer --passphrase-file or EXPOSURE_PASSPHRASE env).
        #[arg(long)]
        passphrase: Option<String>,
        /// Read one-time onboarding passphrase from a file (avoids /proc/cmdline exposure).
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// Generate and print a fresh one-time onboarding passphrase on startup (ignores --passphrase).
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
    /// Validate a Topology YAML file using the Control compiler (offline dry-run: warns on unpinned keys).
    ValidateTopology {
        #[arg(short, long)]
        file: PathBuf,
    },
}

fn read_secret_file(path: &PathBuf) -> Result<String> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read secret file {}", path.display()))?;
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        bail!("secret file {} is empty", path.display());
    }
    Ok(trimmed)
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
            force,
        } => {
            validate_identifier(&tag, "node_tag")?;
            if output.exists() && !force {
                bail!(
                    "refusing to overwrite existing node config {} (pass --force to overwrite)",
                    output.display()
                );
            }
            if let Some(ref addr) = listen {
                addr.parse::<SocketAddr>()
                    .with_context(|| format!("invalid --listen socket address '{addr}'"))?;
            }

            let kp = NodeKeyPair::generate();
            let mut ingress_cfg = exposure_core::config::IngressConfig::default();
            if ingress {
                ingress_cfg.clearance_secret = generate_random_secret_hex(32);
            }
            let mut logger_cfg = exposure_core::config::LoggerConfig::default();
            logger_cfg.hmac_key = generate_random_secret_hex(32);

            let cfg = NodeConfig {
                node_tag: tag.clone(),
                identity_secret_key: kp.secret_key_b64(),
                control_public_key: None,
                control_link_public_key: None,
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
                trusted_origins: vec![],
                logger: logger_cfg,
                ingress: ingress_cfg,
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

            let yaml = serde_yaml::to_string(&cfg)?;
            write_secret_file_atomic(&output, yaml.as_bytes())?;

            println!("Node initialized (mode 0600): {}", output.display());
            println!("Node Tag:         {}", tag);
            println!("Public Key:       {}", kp.public_key_b64());
            println!("Fingerprint:      {}", kp.fingerprint());
            println!("Note: A fresh one-time onboarding passphrase will be generated when `exposure node` starts before enrollment.");
        }
        Commands::InitControl {
            id,
            output,
            panel,
            sqlite,
            admin_user,
            admin_password,
            admin_password_file,
            bootstrap_tag,
            bootstrap_addr,
            bootstrap_passphrase,
            bootstrap_passphrase_file,
            force,
        } => {
            validate_identifier(&id, "control_id")?;
            if admin_user.trim().is_empty() || admin_user.contains(':') {
                bail!("--admin-user must be non-empty and must not contain ':'");
            }
            panel
                .parse::<SocketAddr>()
                .with_context(|| format!("invalid --panel socket address '{panel}'"))?;
            if output.exists() && !force {
                bail!(
                    "refusing to overwrite existing control config {} (pass --force to overwrite)",
                    output.display()
                );
            }

            let boot_pass = match (bootstrap_passphrase_file, bootstrap_passphrase) {
                (Some(p), _) => Some(read_secret_file(&p)?),
                (None, Some(v)) => Some(v),
                (None, None) => std::env::var("EXPOSURE_BOOTSTRAP_PASSPHRASE")
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
            };
            let bootstrap_nodes = match (bootstrap_tag, bootstrap_addr) {
                (Some(node_tag), Some(address)) => {
                    validate_identifier(&node_tag, "bootstrap_tag")?;
                    vec![BootstrapNodeTarget {
                        node_tag,
                        address,
                        public_key: None,
                        passphrase: boot_pass,
                    }]
                }
                (None, None) => {
                    if boot_pass.is_some() {
                        bail!("--bootstrap-passphrase requires both --bootstrap-tag and --bootstrap-addr");
                    }
                    vec![]
                }
                _ => {
                    bail!("--bootstrap-tag and --bootstrap-addr must both be provided together");
                }
            };

            let admin_pw_opt = admin_password.or_else(|| {
                std::env::var("EXPOSURE_ADMIN_PASSWORD")
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            });
            let (plain_pass, generated_pass) = match (admin_password_file, admin_pw_opt) {
                (Some(p), _) => (read_secret_file(&p)?, false),
                (None, Some(pw)) => {
                    if pw.trim().len() < 8 {
                        bail!("--admin-password must be at least 8 characters");
                    }
                    (pw, false)
                }
                (None, None) => (generate_random_secret_hex(16), true),
            };
            let password_hash = hash_password(&plain_pass)?;

            // Generate TWO independent Ed25519 keypairs (key separation between config signing and link identity!)
            let sign_kp = NodeKeyPair::generate();
            let link_kp = NodeKeyPair::generate();

            let cfg = ControlConfig {
                control_id: id.clone(),
                role: ControlRole::Active,
                panel_listen_addr: panel,
                tls: None,
                sqlite_path: sqlite,
                signing_secret_key: sign_kp.secret_key_b64(),
                link_secret_key: link_kp.secret_key_b64(),
                admin: AdminAuthConfig {
                    username: admin_user.clone(),
                    password_hash,
                    token_secret: generate_random_secret_hex(32),
                },
                bootstrap_nodes,
                telemetry_pull_interval_secs: 30,
                initial_topology_path: None,
            };

            let yaml = serde_yaml::to_string(&cfg)?;
            write_secret_file_atomic(&output, yaml.as_bytes())?;

            println!("Control initialized (mode 0600): {}", output.display());
            println!("Control ID:          {}", id);
            println!("Signing Public Key:  {}", sign_kp.public_key_b64());
            println!("Signing Fingerprint: {}", sign_kp.fingerprint());
            println!("Link Public Key:     {}", link_kp.public_key_b64());
            println!("Admin Username:      {}", admin_user);
            if generated_pass {
                println!("Generated Admin Password (shown once, stored as Argon2id hash):");
                println!("  {}", plain_pass);
            }
        }
        Commands::Node {
            config,
            passphrase,
            passphrase_file,
            reset_passphrase,
        } => {
            let raw = std::fs::read_to_string(&config)
                .with_context(|| format!("read node config {}", config.display()))?;
            let cfg: NodeConfig = serde_yaml::from_str(&raw)?;
            let supplied = match (passphrase_file, passphrase) {
                (Some(p), _) => Some(read_secret_file(&p)?),
                (None, Some(v)) => Some(v),
                (None, None) => std::env::var("EXPOSURE_PASSPHRASE")
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
            };
            let phrase = if reset_passphrase {
                let p = generate_five_word_passphrase();
                println!("========================================================");
                println!("ONE-TIME ONBOARDING PASSPHRASE (valid 10m, shown once):");
                println!("  {p}");
                println!("========================================================");
                Some(p)
            } else if supplied.is_none() && cfg.control_public_key.is_none() {
                let p = generate_five_word_passphrase();
                println!("========================================================");
                println!("ONE-TIME ONBOARDING PASSPHRASE (valid 10m, shown once):");
                println!("  {p}");
                println!("========================================================");
                Some(p)
            } else {
                supplied
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
            runtime.shutdown();
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
            let (report, _) = compile_topology_with_options(
                &topo,
                "preview-signing-key",
                "preview-link-key",
                &HashMap::new(),
                &HashMap::new(),
                false, // offline CLI dry-run warns rather than errors on unenrolled keys
            );
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
