# Exposure 架构与设计文档

[English](DESIGN.md) | **简体中文**

本文档介绍 **Exposure** 的系统架构、通信协议、安全模型与核心子系统设计。

---

## 1. 设计目标

Exposure 旨在无需源站具备公网 IP 的前提下，在不可信网络中安全地发布内网或 NAT 后的服务，同时保持配置声明式且可验证：

1. **零信任网格链路**：所有节点间连接均通过 `Noise_XX_25519_ChaChaPoly_BLAKE2s` 加密，并基于 Ed25519 身份进行双向认证。
2. **可组合节点角色**：单一 `exposure` 二进制文件可按需启用 **Ingress**、**Relay**、**Egress** 和 **Maintainer** 中的任意角色组合。
3. **NAT 友好连接**：位于 NAT 或防火墙后的节点可主动向公网 Relay 建立持久化出站隧道，公网节点之间则可按需建立连接。
4. **声明式且可校验的拓扑**：集中式 **Control** 控制面将单一 `TopologySpec` 编译为各节点的签名配置包，在部署前捕获路由环路、不可达节点与缺失的 ACL。
5. **边缘侧安全防护**：Ingress 节点内置 Entry Guard，提供 CIDR 过滤、令牌桶限流、TLS/HTTP 指纹评分以及 `/cdn-cgi/` SHA-256 工作量证明（PoW）挑战。
6. **隐私优先的遥测**：会话日志默认使用 HMAC 对客户端 IP 脱敏，并以原子分段文件持久化落盘。

---

## 2. 系统拓扑与节点角色

Exposure 将**数据面（Nodes）**与**控制面（Control）**分离，并通过 **Maintainer** 节点串联证书生命周期管理与全网遥测聚合。

```text
                        ┌───────────────────────────────┐
                        │         Control 控制面        │
                        │  • 拓扑编译器                 │
                        │  • Ed25519 配置包签名         │
                        │  • SQLite 存储与版本回滚      │
                        │  • Axum API 与 Web 管理面板   │
                        └───────────────┬───────────────┘
                                        │ Noise XX + 签名配置包
          ┌─────────────────────────────┼─────────────────────────────┐
          ▼                             ▼                             ▼
  ┌───────────────┐             ┌───────────────┐             ┌───────────────┐
  │ Ingress 节点  │ ──(Mesh)──► │  Relay 节点   │ ◄──(Tunnel)─│  Egress 节点  │
  │ • TLS 与 SNI  │             │ • 多跳转发    │             │ • allow_from  │
  │ • Entry Guard │             │ • 环路/TTL    │             │ • HTTP/WS     │
  │ • Host 匹配   │             │ • 链路探测    │             │ • 健康检查    │
  └───────▲───────┘             └───────▲───────┘             └───────┬───────┘
          │                             │                             │
          │         SpecialFrame（显式跳表路由）                      ▼
          └─────────────────────────────┴──────────────────────── 本地后端服务
                                        │
                                ┌───────┴───────┐
                                │  Maintainer   │
                                │ • ACME DNS-01 │
                                │ • 遥测聚合    │
                                └───────────────┘
```

### 节点角色职责

| 角色 | 职责说明 |
| :--- | :--- |
| **Ingress** | 监听外部 HTTP/HTTPS 流量，终结 TLS（使用从 Maintainer 同步的证书），执行 Entry Guard 流水线，匹配规则（`host`、`source_cidrs`），并向 `next_peer` 打开携带 `ServiceTag` 的 `Service` 流。 |
| **Relay** | 依据 `ServiceTag -> next_peer` 规则在多跳间转发 `Service` 流，并沿显式跳表转发 `SpecialFrame` 控制/遥测消息。 |
| **Egress** | 终结 `Service` 流，基于 `origin_node_tag` 校验 `allow_from` ACL（除非设置 `allow_any_origin`，否则默认拒绝），向本地后端代理 HTTP/1.1、HTTP/2（`h2`/`h2c`）与 WebSocket 升级请求，并支持本地后端主动健康检查。 |
| **Maintainer** | 管理 ACME DNS-01 证书申请与续期（支持 Cloudflare、通用 Webhook、Exec Hook 或 `self-signed`），分发签名证书包，并聚合各节点的遥测摘要与告警。 |

---

## 3. 链路层（`exposure-link`）

所有节点间及控制面与节点间的通信均运行在 `exposure-link` 之上，在 TCP（`TcpTransport`）上叠加三层协议：

1. **加密传输层（`noise.rs`）**：
   - 采用 `Noise_XX_25519_ChaChaPoly_BLAKE2s` 模式（基于 `snow`）。
   - 提供前向安全性、机密性、完整性及单调递增 Nonce 防重放保护，单帧最大载荷 `MAX_NOISE_PAYLOAD = 65000` 字节（帧上限 65,535 字节）。
2. **身份握手层（`handshake.rs`、`protocol.rs`）**：
   - Noise 握手完成后，双方立即交换 `HelloFrame`，包含 `node_tag`、Ed25519 `public_key`、随机 `nonce`、`timestamp`、`is_control` 标志、可选 `bootstrap_proof`，以及对 `"exposure-hello-v1:{node_tag}:{public_key}:{nonce}:{timestamp}:{is_control}"` 的 Ed25519 签名。
   - 对端校验后回复 `HelloAck`（`accepted`、`authenticated`、`bootstrap_pending`）。
3. **流多路复用层（`mux.rs`）**：
   - 在加密 `NoiseStream` 之上运行 **Yamux**（`yamux::Connection`）。
   - 每条新建 Yamux 流的起始 1 字节为 `StreamKind` 类型标识：
     - `1`（`Service`）：数据面代理流量，前缀为 `ServiceStreamHeader`。
     - `2`（`Special`）：基于跳表路由的控制、配置下发、证书同步与遥测消息（`SpecialFrame`）。
     - `3`（`Probe`）：主动链路健康与延迟探测（`probe.rs`）。
     - `4`（`Bootstrap`）：基于一次性口令的初始节点引导接入。

### 链路模式与健康状态

`LinkManager`（`manager.rs`）为每个对端支持三种连接模式：
- **`on-demand`**：按需拨号，支持多端点 `priority` 与 `weight` 加权选择。
- **`tunnel`**：维护持久化出站（或接受入站）连接，使位于 NAT 后的 Egress 或边缘节点可被 Relay 反向触达。
- **`bootstrap`**：节点尚未获取完整签名拓扑前用于首次引导接入的临时链路模式。

---

## 4. 路由与跳表转发

Exposure 采用两套相互独立的路由机制：

### 数据面：`ServiceTag` 路由
- Ingress 规则将入站请求（`host`、`source_cidrs`）映射为 `service_tag`（如 `web@region-a`）与 `next_peer`。
- `ServiceStreamHeader` 携带 `service_tag`、`origin_node_tag`、`ttl`（默认 `16`）、`hop_count`、`request_id`、`client_ip`、`is_tls`、`sni` 及 `protocol`（`http1`、`h2`、`raw-tcp`）。
- 沿途每个 Relay 节点查询 `service_tag`，递减 `ttl`、递增 `hop_count` 并转发至 `next_peer`，直至抵达 Egress 节点。
- Egress 依据 `origin_node_tag`（原始 Ingress 节点）校验 `allow_from`，确保中间 Relay 无法伪造来源身份。

### 控制与维护面：`SpecialFrame` 跳表路由
- `SpecialFrame` 携带显式跳表 `hops: Vec<String>`、`hop_index`、`ttl` 以及 `SpecialPayload`（配置推送、遥测拉取、证书同步、节点发现等）。
- 每个节点将帧转发至 `hops[hop_index + 1]`；响应帧只需反转 `hops` 即可沿对称路径原路返回，从而使 Control 或 Maintainer 无需直连 IP 即可穿过 Relay 触达 NAT 后的节点。

---

## 5. 安全模型与 Entry Guard

### 密码学身份与引导接入
- **节点与控制面密钥**：所有 Node 与 Control 实例均由 Ed25519 密钥对（`ed25519-dalek`）唯一标识。
- **5 词引导口令**：`exposure init-node` 会生成有效期为 10 分钟的一次性 5 词引导口令。Control 在首次接入时使用由该口令派生的 HMAC `bootstrap_proof` 完成认证，并下发签名后的 `NodeConfig` 与 Control 公钥。
- **签名配置包**：Control 使用 Ed25519 私钥签名 `SignedConfigBundle`，并附带单调递增的 `config_sequence` 以防止降级或未授权的配置注入。

### Ingress Entry Guard（`guard.rs`）
Ingress 上的每个入站 HTTP(S) 请求都会经过 `GuardEngine` 处理：
1. **CIDR 过滤**：依据规则/防护配置中的允许或拒绝 CIDR 列表校验源 IP。
2. **令牌桶限流**：基于命名 `rate_limit_buckets`（`capacity`、`refill_per_sec`、`per_ip`），超限时返回 `429 Too Many Requests` 与 `Retry-After`。
3. **指纹评分**：综合 TLS `ClientHelloSignal` 与 HTTP 请求头特征计算可疑度评分（`0..100`），并与 `challenge_threshold` 和 `reject_threshold` 比较。
4. **人机校验模式（`antibot`）**：
   - `off`：关闭 Guard 评分。
   - `silent`：直接拒绝超过 `reject_threshold` 的请求。
   - `challenge`：将可疑请求重定向至 `/cdn-cgi/`，要求客户端完成 **SHA-256 工作量证明**（`SHA256("{token}:{nonce}")` 满足 `pow_difficulty` 个前导零比特）。
5. **通行 Cookie**：PoW 验证通过后，Ingress 签发 HMAC-SHA256 保护的 `exposure_clearance` Cookie（有效期 `clearance_ttl_secs`，可选通过 `bind_ua` 绑定 User-Agent）。

---

## 6. 证书生命周期（Maintainer）

`Maintainer`（`maintainer.rs`）集中管理 TLS 证书生命周期：
- 支持通过以下提供方执行 ACME **DNS-01** 验证：
  - **Cloudflare** DNS API
  - **通用 Webhook**
  - **Exec Hook**（外部脚本或二进制程序）
  - **`self-signed`** 模式（基于 `rcgen`），适用于本地测试与私有网格
- 证书持久化保存在 `acme.storage_dir`，并通过 `SpecialFrame` 流推送至 Ingress 节点。

---

## 7. 控制面与拓扑编译器（`exposure-control`）

Control 控制面（`runtime.rs`、`api.rs`、`db.rs`、`compiler.rs`）提供以下能力：

- **拓扑编译器（`compiler.rs`）**：
  - 解析 `TopologySpec` YAML（`nodes`、`links`、`maintainer_templates`）。
  - 校验图连通性、检测转发环路、验证 `allow_from` ACL 引用有效性，并将 `links` 与 `maintainer_hops` 展开为各节点的 `NodeConfig`。
- **SQLite 持久化（`db.rs`）**：
  - 存储节点注册信息、引导口令、拓扑草稿、历史配置版本快照（支持通过 `/api/config-versions/{id}/rollback` 回滚）、遥测摘要及管理员审计日志。
- **Axum HTTP API 与内嵌 Web UI（`api.rs`、`web/`）**：
  - 使用 HMAC-SHA256 Bearer Token 进行管理员认证（`/api/auth/login`）。
  - 托管内嵌单页 Web 管理面板（`exposure-core::assets`），并提供 `/api/overview`、`/api/nodes`、`/api/topology`、`/api/config-versions`、`/api/passphrases`、`/api/discovery/run`、`/api/telemetry` 与 `/api/audit` 接口。
  - 支持 `active` 与 `standby` 两种 `ControlRole` 模式，备节点会拒绝变更类 API 请求（返回 `409 Conflict`）。

---

## 8. 遥测与分段日志（`logger.rs`、`segment.rs`）

- **采样与 IP 脱敏**：`NodeLogger` 按 `sample_rate` 采样，默认通过 HMAC 对客户端 IP 哈希脱敏（`store_raw_ip: false`）。
- **原子分段写入**：`SegmentWriter<SessionSummary>` 在批次满、定时器触发或收到 `SIGINT`/`SIGTERM` 时原子刷新到磁盘分段文件。
- **分钟级摘要与告警**：按 `(node, minute, service)` 维度聚合 `MinuteSummary` 与 `AlertRecord`，定期上报至 Maintainer 与 Control。
