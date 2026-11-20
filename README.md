<p align="center">
  <img src="assets/banner.svg" alt="Exposure" width="100%" />
</p>

**English** | [简体中文](README.zh-CN.md)

**A zero-trust, multi-hop reverse proxy, encrypted service mesh, edge guard, and telemetry platform written in Rust.**

Exposure lets you securely publish internal or NAT-bound services across untrusted networks through composable **Ingress**, **Relay**, **Egress**, and **Maintainer** nodes—coordinated by a centralized **Control** plane with a built-in Web Admin Panel.

---

## Quick Start

### 1. One-Line Install (Linux systemd, Recommended)

Run the installer to automatically download the latest release binary (with `SHA256SUMS.txt` verification), interactively configure `node` or `control` initialization settings, register the hardened `systemd` service, and print the **Onboarding** details (including the one-time 5-word passphrase and node public key):

```bash
curl -fsSL https://raw.githubusercontent.com/ProjectRalyn/Exposure/main/install.sh | sudo bash
```

Non-interactive examples:

```bash
# Install and start an Ingress + Relay node
curl -fsSL https://raw.githubusercontent.com/ProjectRalyn/Exposure/main/install.sh | sudo bash -s -- \
  --role node -y --tag ingress-hk --listen 0.0.0.0:10802 --ingress --relay

# Install and start the Control plane
curl -fsSL https://raw.githubusercontent.com/ProjectRalyn/Exposure/main/install.sh | sudo bash -s -- \
  --role control -y --panel 127.0.0.1:8090

# Uninstall (add --purge to also remove /etc/exposure and /var/lib/exposure)
sudo ./install.sh --uninstall
```

> Pass `--bin /path/to/exposure` to install a locally compiled binary instead of downloading from GitHub Releases, or `--version <tag>` to pin a specific release.

### 2. Build from Source (Manual)

Prerequisites:
- Rust toolchain (`rustc` / `cargo`, 2021 edition)
- Node.js & `pnpm` (only needed if rebuilding the embedded web UI in `web/`)

```bash
# Optional: rebuild embedded web UI assets (Control Panel & PoW Challenge UI)
cd web && pnpm install --frozen-lockfile && pnpm build && cd ..

# Build the release binary
cargo build --release --bin exposure
```

The compiled binary will be at `target/release/exposure`.

### 3. Initialize a Control Plane & First Node

Generate a node configuration (which emits a one-time 5-word onboarding passphrase valid for 10 minutes on first start):

```bash
./target/release/exposure init-node \
  --tag edge-1 \
  --output ./node.yaml \
  --listen 0.0.0.0:10802 \
  --ingress --egress
```

Initialize the Control plane configuration:

```bash
./target/release/exposure init-control \
  --id control-1 \
  --output ./control.yaml \
  --panel 127.0.0.1:8090 \
  --admin-user admin \
  --admin-password "change-me-now" \
  --bootstrap-tag edge-1 \
  --bootstrap-addr 127.0.0.1:10802 \
  --bootstrap-passphrase "<five-word-passphrase>"
```

Start the Node and Control plane in separate terminals:

```bash
./target/release/exposure node --config ./node.yaml
./target/release/exposure control --config ./control.yaml
```

Open `http://127.0.0.1:8090` in your browser to access the Control Web Admin Panel.

### 4. Validate a Topology File

Before applying a declarative topology (see [`examples/topology.yaml`](examples/topology.yaml)), validate it with the Control compiler:

```bash
./target/release/exposure validate-topology --file examples/topology.yaml
```

---

## Features

- **Encrypted & Multiplexed Mesh Links (`exposure-link`)**
  - All node-to-node links are encrypted end-to-end with **Noise (`Noise_XX_25519_ChaChaPoly_BLAKE2s`)** and multiplexed over **Yamux**.
  - Mutual **Ed25519** identity authentication with signed `HelloFrame` nonces and timestamps.
  - Supports **on-demand** connections, persistent **outbound/inbound tunnels** (for NAT traversal), and **bootstrap** onboarding links.
- **Composable Node Roles (`exposure-node`)**
  - **Ingress**: Terminates HTTP/HTTPS (with SNI & dynamic TLS certs), enforces Entry Guard policies, and forwards matched traffic by `ServiceTag`.
  - **Relay**: Forwards streams across multi-hop paths with loop prevention (`TTL` & hop tracking) and health-aware peer selection.
  - **Egress**: Enforces `allow_from` origin ACLs (default deny), proxies HTTP/1.1, HTTP/2 (`h2`/`h2c`), and WebSockets to local backends, and runs local backend health checks.
  - **Maintainer**: Manages **ACME DNS-01** certificate issuance/renewal (Cloudflare, Webhook, Exec Hook, or self-signed), aggregates node telemetry, and distributes signed config/cert bundles.
- **Edge Entry Guard & Anti-Bot Protection**
  - CIDR allow/deny filtering and named **token-bucket rate limiting** (`429 Too Many Requests` + `Retry-After`).
  - TLS ClientHello + HTTP header fingerprint scoring with configurable `off`, `silent`, and `challenge` modes.
  - Built-in `/cdn-cgi/` **SHA-256 Proof-of-Work (PoW)** challenge page and HMAC-signed `exposure_clearance` cookies.
- **Centralized Control Plane & Web UI (`exposure-control` + `web/`)**
  - Compiles declarative `Topology` YAML into per-node signed bundles (`Ed25519`), validating against routing loops, missing ACLs, and unreachable nodes.
  - SQLite-backed state (`rusqlite`), versioned configs with one-click rollback, audit logs, active/standby role support, and an embedded Web Admin Panel.
- **Privacy-Aware Telemetry**
  - Sampled session logging with HMAC-hashed client IPs by default (`store_raw_ip: false`), atomic disk segments, and periodic per-minute service summaries.

---

## Architecture Overview

```text
  Client (HTTP/HTTPS/WS)
         │
         ▼
  ┌─────────────┐   Noise XX + Yamux   ┌─────────────┐   Noise XX + Yamux   ┌─────────────┐
  │   Ingress   │ ───────────────────► │    Relay    │ ◄─────────────────── │   Egress    │
  │ (Guard+TLS) │                      │  (Forward)  │   (Outbound Tunnel)  │ (ACL+Proxy) │
  └─────────────┘                      └─────────────┘                      └──────┬──────┘
         ▲                                    ▲                                    │
         │         SpecialFrame / Hop Table   │                                    ▼
         └──────────────────┬─────────────────┘                             Local Backend
                            │
                     ┌──────┴──────┐        Config Push & Pull       ┌─────────────┐
                     │ Maintainer  │ ◄─────────────────────────────► │   Control   │
                     │ (ACME+Logs) │     (Noise + Ed25519 Bundles)   │ (SQLite+UI) │
                     └─────────────┘                                 └─────────────┘
```

For a deep dive into the protocol, security model, routing, and subsystem internals, see [DESIGN.md](DESIGN.md).

---

## Workspace Layout

| Crate / Directory | Responsibility |
| :--- | :--- |
| [`crates/exposure-core`](crates/exposure-core) | Shared config schemas, Ed25519/HMAC/PoW crypto, wire protocol frames, routing helpers, segmented storage, telemetry types, and embedded web assets. |
| [`crates/exposure-link`](crates/exposure-link) | Noise XX transport encryption, Yamux stream multiplexing, `HelloFrame` identity handshake, link lifecycle manager, and active link probing. |
| [`crates/exposure-node`](crates/exposure-node) | Node runtime implementing Ingress, Relay, Egress, Maintainer (ACME DNS-01 + telemetry), Entry Guard, TLS termination, and local logging. |
| [`crates/exposure-control`](crates/exposure-control) | Control plane runtime, Topology YAML compiler, SQLite persistence, signed bundle distribution, and Axum HTTP API + Web UI server. |
| [`crates/exposure-cli`](crates/exposure-cli) | `exposure` CLI binary (`init-node`, `init-control`, `node`, `control`, `keygen`, `validate-topology`) and end-to-end mesh integration tests. |
| [`web`](web) | Frontend assets for the Control Admin Panel (`web/control`) and `/cdn-cgi/` PoW Challenge page (`web/challenge`). |
| [`examples`](examples) | Sample multi-node [`topology.yaml`](examples/topology.yaml) configuration. |

---

## Testing

Run the full unit and end-to-end mesh test suite:

```bash
cargo test --workspace
```

---

## License

**MIT**
