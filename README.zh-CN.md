# Exposure

[English](README.md) | **简体中文**

**基于 Rust 构建的零信任多跳反向代理、加密服务网格、边缘防护与遥测平台。**

Exposure 支持通过可组合的 **Ingress**、**Relay**、**Egress** 和 **Maintainer** 节点，在不可信网络中安全地暴露内网或 NAT 后的服务，并由内置 Web 管理面板的集中式 **Control** 控制面统一编排与下发配置。

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#许可证)
[![Rust](https://img.shields.io/badge/rust-2021%20edition-orange.svg)](https://www.rust-lang.org/)

---

## 核心特性

- **加密多路复用网格链路（`exposure-link`）**
  - 所有节点间通信均采用 **Noise（`Noise_XX_25519_ChaChaPoly_BLAKE2s`）** 端到端加密，并基于 **Yamux** 进行多路复用。
  - 通过带随机数与时间戳签名的 `HelloFrame` 实现双向 **Ed25519** 身份认证。
  - 支持 **按需连接（on-demand）**、持久化 **出站/入站隧道（tunnel）**（用于 NAT 穿透）以及 **引导接入（bootstrap）** 链路。
- **可组合的节点角色（`exposure-node`）**
  - **Ingress**：终结 HTTP/HTTPS 流量（支持 SNI 与动态 TLS 证书），执行 Entry Guard 安全策略，并按 `ServiceTag` 转发流量。
  - **Relay**：按多跳路径转发数据流，内置防环路机制（`TTL` 与跳数追踪）及基于健康度的节点选择。
  - **Egress**：基于 `origin_node_tag` 强制校验 `allow_from` 访问控制（默认拒绝），向本地后端代理 HTTP/1.1、HTTP/2（`h2`/`h2c`）和 WebSocket，并支持本地后端健康检查。
  - **Maintainer**：负责 **ACME DNS-01** 证书签发与续期（支持 Cloudflare、通用 Webhook、Exec Hook 或自签名模式），聚合节点遥测数据，并分发签名配置/证书包。
- **边缘 Entry Guard 与人机校验**
  - 支持 CIDR 黑白名单过滤与命名 **令牌桶限流（token-bucket）**（触发时返回 `429 Too Many Requests` 及 `Retry-After`）。
  - 结合 TLS ClientHello 与 HTTP 请求头进行浏览器指纹评分，支持 `off`、`silent` 和 `challenge` 三种模式。
  - 内置 `/cdn-cgi/` **SHA-256 工作量证明（PoW）** 挑战页面及基于 HMAC 签名的 `exposure_clearance` 通行 Cookie。
- **集中式控制面与 Web 管理面板（`exposure-control` + `web/`）**
  - 将声明式 `Topology` YAML 编译为各节点的 Ed25519 签名配置包，并在编译期校验路由环路、缺失的 ACL 及不可达节点。
  - 基于 SQLite（`rusqlite`）持久化状态，支持配置版本管理与一键回滚、审计日志、Active/Standby 角色控制，以及内嵌的 Web 管理面板。
- **隐私友好的遥测系统**
  - 支持采样会话日志，默认对客户端 IP 进行 HMAC 哈希脱敏（`store_raw_ip: false`），通过原子磁盘分段写入，并定期向上游汇报分钟级服务摘要。

---

## 架构概览

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

关于协议细节、安全模型、路由机制与子系统设计的完整说明，请参阅 [DESIGN.zh-CN.md](DESIGN.zh-CN.md)。

---

## 快速开始

### 1. 从源码构建

前置依赖：
- Rust 工具链（`rustc` / `cargo`，2021 edition）
- Node.js 与 `pnpm`（仅在需要重新构建 `web/` 内的前端资源时使用）

```bash
# 可选：重新构建内嵌前端资源（Control 管理面板与 PoW 挑战页）
cd web && pnpm install --frozen-lockfile && pnpm build && cd ..

# 构建 Release 二进制文件
cargo build --release --bin exposure
```

编译产物位于 `target/release/exposure`。

### 2. 初始化控制面与首个节点

生成节点配置（将输出一个有效期为 10 分钟的一次性 5 词引导口令）：

```bash
./target/release/exposure init-node \
  --tag edge-1 \
  --output ./node.yaml \
  --listen 0.0.0.0:9443 \
  --ingress --egress
```

初始化 Control 控制面配置：

```bash
./target/release/exposure init-control \
  --id control-1 \
  --output ./control.yaml \
  --panel 127.0.0.1:8090 \
  --admin-user admin \
  --admin-password "change-me-now" \
  --bootstrap-tag edge-1 \
  --bootstrap-addr 127.0.0.1:9443 \
  --bootstrap-passphrase "<five-word-passphrase>"
```

在不同终端中分别启动 Node 与 Control：

```bash
./target/release/exposure node --config ./node.yaml
./target/release/exposure control --config ./control.yaml
```

在浏览器中打开 `http://127.0.0.1:8090` 即可访问 Control Web 管理面板。

### 3. 校验拓扑文件

在应用声明式拓扑配置（参考 [`examples/topology.yaml`](examples/topology.yaml)）前，可使用 Control 编译器进行校验：

```bash
./target/release/exposure validate-topology --file examples/topology.yaml
```

---

## Linux 部署脚本（`install.sh`）

针对基于 systemd 的 Linux 环境，`install.sh` 提供二进制安装、配置初始化及 systemd 服务注册的一键能力：

```bash
# 安装二进制并配置 Ingress + Relay 节点
sudo ./install.sh --role node --bin ./target/release/exposure \
  --tag ingress-hk --listen 0.0.0.0:9443 --ingress --relay

# 安装二进制并配置 Control 控制面
sudo ./install.sh --role control --bin ./target/release/exposure \
  --panel 127.0.0.1:8090

# 卸载（附加 --purge 将同时清理 /etc/exposure 与 /var/lib/exposure）
sudo ./install.sh --uninstall
```

---

## Workspace 结构

| Crate / 目录 | 职责 |
| :--- | :--- |
| [`crates/exposure-core`](crates/exposure-core) | 共享配置结构、Ed25519/HMAC/PoW 密码学原语、线协议帧定义、路由辅助逻辑、分段存储、遥测类型及内嵌前端资源。 |
| [`crates/exposure-link`](crates/exposure-link) | Noise XX 传输加密、Yamux 流多路复用、`HelloFrame` 身份握手、链路生命周期管理及主动链路探测。 |
| [`crates/exposure-node`](crates/exposure-node) | 节点运行时，实现 Ingress、Relay、Egress、Maintainer（ACME DNS-01 与遥测）、Entry Guard、TLS 终结与本地日志。 |
| [`crates/exposure-control`](crates/exposure-control) | 控制面运行时、Topology YAML 编译器、SQLite 持久化、签名配置包分发及 Axum HTTP API / Web UI 服务。 |
| [`crates/exposure-cli`](crates/exposure-cli) | `exposure` CLI 二进制（`init-node`、`init-control`、`node`、`control`、`keygen`、`validate-topology`）及端到端网格集成测试。 |
| [`web`](web) | Control 管理面板（`web/control`）与 `/cdn-cgi/` PoW 挑战页（`web/challenge`）前端源码。 |
| [`examples`](examples) | 多节点拓扑配置示例 [`topology.yaml`](examples/topology.yaml)。 |

---

## 运行测试

执行全量单元测试与端到端网格测试：

```bash
cargo test --workspace
```

---

## 许可证

本项目采用双许可证授权，可任选其一：

- **MIT License**
- **Apache License, Version 2.0**
