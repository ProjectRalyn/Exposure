# Exposure Architecture & Design

**English** | [简体中文](DESIGN.zh-CN.md)

This document describes the architecture, wire protocols, security model, and subsystem design of **Exposure**.

---

## 1. Design Goals

Exposure is built to publish internal and NAT-bound services across untrusted networks without requiring public IPs on origin servers, while keeping configuration declarative and verifiable:

1. **Zero-Trust Mesh Links**: Every inter-node connection is encrypted (`Noise_XX_25519_ChaChaPoly_BLAKE2s`) and mutually authenticated via Ed25519 identities.
2. **Composable Node Roles**: A single `exposure` binary can act as any combination of **Ingress**, **Relay**, **Egress**, and **Maintainer** nodes.
3. **NAT-Friendly Connectivity**: Nodes behind NAT or firewalls can establish persistent outbound tunnels to public Relays, while public nodes can connect on demand.
4. **Declarative, Verified Topology**: A centralized **Control** plane compiles a single `TopologySpec` into per-node signed configuration bundles, catching routing loops, unreachable nodes, and missing ACLs before deployment.
5. **Defense at the Edge**: Ingress nodes include an integrated Entry Guard with CIDR filtering, token-bucket rate limiting, TLS/HTTP fingerprint scoring, and SHA-256 Proof-of-Work (`/cdn-cgi/`) challenges.
6. **Privacy-Preserving Telemetry**: Session logs hash client IPs via HMAC by default and persist in atomic disk segments.

---

## 2. System Topology & Roles

Exposure separates the **Data Plane** (Nodes) from the **Control Plane** (Control), with **Maintainer** nodes bridging certificate lifecycle and telemetry collection across the mesh.

```text
                        ┌───────────────────────────────┐
                        │         Control Plane         │
                        │  • Topology Compiler          │
                        │  • Ed25519 Bundle Signing     │
                        │  • SQLite Store & Versioning  │
                        │  • Axum API & Web Admin UI    │
                        └───────────────┬───────────────┘
                                        │ Noise XX + Signed Bundles
          ┌─────────────────────────────┼─────────────────────────────┐
          ▼                             ▼                             ▼
  ┌───────────────┐             ┌───────────────┐             ┌───────────────┐
  │ Ingress Node  │ ──(Mesh)──► │  Relay Node   │ ◄──(Tunnel)─│  Egress Node  │
  │ • TLS & SNI   │             │ • Multi-hop   │             │ • allow_from  │
  │ • Entry Guard │             │ • Loop/TTL    │             │ • HTTP/WS     │
  │ • Host Match  │             │ • Link Probe  │             │ • Health Chk  │
  └───────▲───────┘             └───────▲───────┘             └───────┬───────┘
          │                             │                             │
          │         SpecialFrame (Explicit Hop Table)                 ▼
          └─────────────────────────────┴────────────────────── Local Backend
                                        │
                                ┌───────┴───────┐
                                │  Maintainer   │
                                │ • ACME DNS-01 │
                                │ • Telemetry   │
                                └───────────────┘
```

### Node Roles

| Role | Responsibility |
| :--- | :--- |
| **Ingress** | Listens for external HTTP/HTTPS traffic, terminates TLS (using certs synced from Maintainer), runs the Entry Guard pipeline, matches rules (`host`, `source_cidrs`), and opens a `Service` stream toward `next_peer` tagged with `ServiceTag`. |
| **Relay** | Forwards `Service` streams across hops according to `ServiceTag -> next_peer` rules and relays `SpecialFrame` control/telemetry messages along explicit hop tables. |
| **Egress** | Terminates `Service` streams, enforces `allow_from` ACLs against `origin_node_tag` (default deny unless `allow_any_origin` is set), proxies HTTP/1.1, HTTP/2 (`h2`/`h2c`), and WebSocket upgrades to local backends, and runs optional local backend health checks. |
| **Maintainer** | Manages ACME DNS-01 certificate orders and renewals (Cloudflare, Aliyun DNS, Webhook, Exec Hook, or `self-signed`), distributes signed certificate bundles, and aggregates node telemetry summaries/alerts. |

---

## 3. Link Layer (`exposure-link`)

All node-to-node and control-to-node communication runs over `exposure-link`, which stacks three layers over TCP (`TcpTransport`):

1. **Encrypted Transport (`noise.rs`)**:
   - Pattern: `Noise_XX_25519_ChaChaPoly_BLAKE2s` (via `snow`).
   - Provides forward secrecy, confidentiality, integrity, and monotonic-nonce replay protection, framed in length-prefixed chunks up to 65,535 bytes (`MAX_NOISE_PAYLOAD = 65000`).
2. **Identity Handshake (`handshake.rs`, `protocol.rs`)**:
   - Immediately after Noise handshake completion, both sides exchange a `HelloFrame` containing `node_tag`, Ed25519 `public_key`, random `nonce`, `timestamp`, `is_control` flag, optional `bootstrap_proof`, and an Ed25519 signature over `"exposure-hello-v1:{node_tag}:{public_key}:{nonce}:{timestamp}:{is_control}"`.
   - The peer responds with `HelloAck` (`accepted`, `authenticated`, `bootstrap_pending`).
3. **Stream Multiplexing (`mux.rs`)**:
   - Runs **Yamux** (`yamux::Connection`) over the encrypted `NoiseStream`.
   - Each opened Yamux stream begins with a 1-byte `StreamKind` discriminator:
     - `1` (`Service`): Data-plane proxied traffic prefixed with `ServiceStreamHeader`.
     - `2` (`Special`): Hop-routed control, config push, certificate sync, and telemetry messages (`SpecialFrame`).
     - `3` (`Probe`): Active link health/latency probes (`probe.rs`).
     - `4` (`Bootstrap`): Initial node onboarding over one-time passphrase links.

### Link Modes & Health

`LinkManager` (`manager.rs`) supports three link modes configured per peer:
- **`on-demand`**: Dials peer endpoints when streams are needed; supports multi-endpoint `priority` and `weight` selection.
- **`tunnel`**: Maintains persistent outbound (or accepts inbound) connections so NAT-bound Egress or Edge nodes remain reachable by Relays.
- **`bootstrap`**: Temporary link mode used during initial onboarding before the node receives its full signed topology.

---

## 4. Routing & Hop-Table Forwarding

Exposure uses two distinct routing mechanisms:

### Data Plane: `ServiceTag` Routing
- Ingress rules map incoming requests (`host`, `source_cidrs`) to a `service_tag` (e.g., `web@region-a`) and a `next_peer`.
- `ServiceStreamHeader` carries `service_tag`, `origin_node_tag`, `ttl` (default `16`), `hop_count`, `request_id`, `client_ip`, `is_tls`, `sni`, and `protocol` (`http1`, `h2`, `raw-tcp`).
- Each Relay inspects `service_tag`, decrements `ttl`, increments `hop_count`, and forwards to its configured `next_peer` until reaching the Egress node.
- Egress checks `allow_from` against `origin_node_tag` (the original Ingress node), ensuring intermediate Relays cannot spoof origin identity.

### Control & Maintenance Plane: `SpecialFrame` Hop Tables
- `SpecialFrame` carries an explicit `hops: Vec<String>`, `hop_index`, `ttl`, and `SpecialPayload` (e.g., config pushes, telemetry pulls, cert sync, discovery).
- Each node forwards to `hops[hop_index + 1]`. Replies simply reverse `hops` and traverse back along the symmetric path, allowing Control or Maintainer nodes to reach NAT-bound nodes through Relays without direct IP reachability.

---

## 5. Security & Entry Guard

### Cryptographic Identity & Onboarding
- **Node & Control Keys**: Ed25519 keypairs (`ed25519-dalek`) identify every Node and Control instance.
- **5-Word Onboarding Passphrase**: `exposure init-node` generates a one-time 5-word passphrase (valid for 10 minutes). Control uses an HMAC `bootstrap_proof` derived from this passphrase to authenticate on first contact and deliver the signed `NodeConfig` + Control public key.
- **Signed Config Bundles**: Control signs `SignedConfigBundle` payloads with its Ed25519 private key and embeds a monotonically increasing `config_sequence` to prevent downgrade or unauthorized config injection.

### Ingress Entry Guard (`guard.rs`)
Every incoming HTTP(S) request on Ingress passes through `GuardEngine`:
1. **CIDR Filtering**: Evaluates source IP against rule/guard allow/deny CIDRs.
2. **Token-Bucket Rate Limiting**: Named `rate_limit_buckets` (`capacity`, `refill_per_sec`, `per_ip`) return `429 Too Many Requests` with `Retry-After` when exhausted.
3. **Fingerprint Scoring**: Combines TLS `ClientHelloSignal` and HTTP header heuristics into a suspicion score (`0..100`) compared against `challenge_threshold` and `reject_threshold`.
4. **Anti-Bot Modes (`antibot`)**:
   - `off`: Guard scoring disabled.
   - `silent`: Rejects requests exceeding `reject_threshold`.
   - `challenge`: Redirects suspicious clients to `/cdn-cgi/` to solve a **SHA-256 Proof-of-Work** puzzle (`pow_difficulty` leading zero bits on `SHA256("{token}:{nonce}")`).
5. **Clearance Cookies**: Upon solving the PoW, Ingress issues an HMAC-SHA256 signed `exposure_clearance` cookie (`clearance_ttl_secs`, optionally bound to User-Agent via `bind_ua`).

---

## 6. Certificate Lifecycle & DNS Management (Maintainer)

`Maintainer` (`maintainer.rs`) centralizes TLS certificate management and DNS record execution:
- Separates **DNS Provider Accounts** (`dns_providers`, supporting multiple accounts per provider) from **Domain Bindings** (`domains`, supporting apex and multi-level subdomains with longest-suffix inheritance):
  - **Cloudflare** DNS API (automatic `zone_id` lookup when omitted)
  - **Aliyun DNS** (Alidns OpenAPI V3)
  - **Generic Webhook**
  - **Exec Hook** (external script/binary)
  - **`self-signed`** mode (via `rcgen`) for local testing and private meshes
- **Declarative DNS A/AAAA Sync (`DnsSyncReq` / `DnsSyncResp`)**: Control computes desired IPv4/IPv6 sets from `domains[*].target_nodes` and `nodes[*].external_ips` and sends an Ed25519-signed, replay-protected `DnsSyncReq` (`POST /api/dns/sync`) to the primary Maintainer. Maintainer executes DNS changes solely with its own credentials and strictly refuses DNS record sync without a valid Control-signed command.
- Stores certificates in `acme.storage_dir` and pushes updated certificate bundles to Ingress nodes over `SpecialFrame` streams.

---

## 7. Control Plane & Topology Compiler (`exposure-control`)

The Control plane (`runtime.rs`, `api.rs`, `db.rs`, `compiler.rs`) provides:

- **Topology Compiler (`compiler.rs`)**:
  - Parses `TopologySpec` YAML (`nodes`, `links`, `maintainer_templates`).
  - Validates graph reachability, detects forwarding loops, verifies `allow_from` ACL references, and expands `links` and `maintainer_hops` into per-node `NodeConfig`s.
- **SQLite Persistence (`db.rs`)**:
  - Stores node registrations, onboarding passphrases, topology drafts, versioned config snapshots (supporting rollback via `/api/config-versions/{id}/rollback`), telemetry summaries, and admin audit logs.
- **Axum HTTP API & Embedded Web UI (`api.rs`, `web/`)**:
  - Authenticates administrators with HMAC-SHA256 Bearer tokens (`/api/auth/login`).
  - Serves the embedded single-page Web Admin Panel (`exposure-core::assets`) and exposes REST endpoints for `/api/overview`, `/api/nodes`, `/api/topology`, `/api/config-versions`, `/api/passphrases`, `/api/discovery/run`, `/api/telemetry`, and `/api/audit`.
  - Supports `active` and `standby` `ControlRole` modes so standby instances reject mutating API calls (`409 Conflict`).

---

## 8. Telemetry & Segmented Logging (`logger.rs`, `segment.rs`)

- **Sampling & IP Privacy**: `NodeLogger` applies `sample_rate` and hashes client IPs with HMAC by default (`store_raw_ip: false`).
- **Atomic Disk Segments**: `SegmentWriter<SessionSummary>` flushes session batches to disk segments on batch full, timer tick, or `SIGINT`/`SIGTERM`.
- **Minute Summaries & Alerts**: Aggregates per-`(node, minute, service)` `MinuteSummary` metrics and `AlertRecord` events for periodic reporting to Maintainer and Control.
