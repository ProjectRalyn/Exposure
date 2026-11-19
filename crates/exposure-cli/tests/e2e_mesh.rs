use std::collections::BTreeMap;
use std::time::Duration;

use bytes::Bytes;
use exposure_control::ControlRuntime;
use exposure_core::config::*;
use exposure_core::crypto::{
    generate_five_word_passphrase, generate_random_secret_hex, hash_password, verify_pow_solution,
    NodeKeyPair,
};
use exposure_core::protocol::{SpecialFrame, SpecialPayload};
use exposure_node::NodeRuntime;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use tokio::net::TcpListener;

async fn spawn_echo_backend() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let body = format!(
                        "echo:ver={:?}:path={}",
                        req.version(),
                        req.uri().path()
                    );
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from(body)))
                            .unwrap(),
                    )
                });
                let _ = AutoServerBuilder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    addr
}

fn temp_seg_cfg(name: &str) -> LoggerConfig {
    let dir = std::env::temp_dir().join(format!("exposure-e2e-{name}-{}", uuid::Uuid::new_v4()));
    LoggerConfig {
        hmac_key: generate_random_secret_hex(32),
        segment: SegmentConfig {
            dir: dir.to_string_lossy().to_string(),
            flush_interval_secs: 60,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Full end-to-end mesh & security verification test:
/// - 3-node mesh: `ingress-a` --(tunnel)--> `relay-1` <--(outbound tunnel)-- `egress-1` --> backend
/// - Tests channel-bound Noise_XX + signed HelloAck + signed multi-hop origin ACLs (HTTP/1.1 & HTTP/2)
/// - Tests co-located ingress+egress via self `node_tag`
/// - Tests Entry Guard rate limiting (429 + Retry-After) & single-use `/cdn-cgi/` PoW + replay rejection
/// - Tests Control onboarding via mutual-auth passphrase, separate signing/link keys, Discovery,
///   Signed Config Hot Reload, rollback rejection, Preflight cross-protocol replay rejection,
///   secret redaction on API, HttpOnly session cookie + server-side logout revocation,
///   and Maintainer per-target CertBundle signing/distribution.
#[tokio::test]
async fn e2e_mesh_h2_guard_control_and_maintainer() {
    let backend_addr = spawn_echo_backend().await;

    let kp_ingress = NodeKeyPair::generate();
    let kp_relay = NodeKeyPair::generate();
    let kp_egress = NodeKeyPair::generate();
    let kp_maint = NodeKeyPair::generate();
    let kp_maint_cert = NodeKeyPair::generate();
    let kp_ctrl_sign = NodeKeyPair::generate();
    let kp_ctrl_link = NodeKeyPair::generate();

    // 1. Start Maintainer Node
    let maint_cfg = NodeConfig {
        node_tag: "maintainer-1".into(),
        identity_secret_key: kp_maint.secret_key_b64(),
        control_public_key: Some(kp_ctrl_sign.public_key_b64()),
        control_link_public_key: Some(kp_ctrl_link.public_key_b64()),
        roles: NodeRoles {
            maintainer: true,
            ..Default::default()
        },
        link_listener: Some(LinkListenConfig {
            listen_addr: "127.0.0.1:0".into(),
            allow_on_demand: true,
            allow_tunnel: true,
            allow_bootstrap: false,
        }),
        peers: vec![],
        probe: ProbeConfig::default(),
        default_ttl: 16,
        maintainer_hops: vec![],
        trusted_maintainers: vec![],
        trusted_origins: vec![],
        logger: temp_seg_cfg("maint"),
        ingress: Default::default(),
        egress: Default::default(),
        relay: Default::default(),
        maintainer: Some(MaintainerConfig {
            cert_signing_secret_key: Some(kp_maint_cert.secret_key_b64()),
            is_primary_cert_manager: true,
            logger: temp_seg_cfg("maint-agg"),
            acme: AcmeConfig {
                directory_url: "self-signed".into(),
                storage_dir: std::env::temp_dir()
                    .join(format!("exposure-mcerts-{}", uuid::Uuid::new_v4()))
                    .to_string_lossy()
                    .to_string(),
                ..Default::default()
            },
        }),
        bootstrap_tunnel_addr: None,
        config_sequence: 0,
    };
    let maint_rt = NodeRuntime::new(maint_cfg, None, None).await.unwrap();
    let (maint_link_addr, _) = maint_rt.start().await.unwrap();
    let maint_link_addr = maint_link_addr.unwrap();

    // 2. Start Relay Node (also listens for inbound tunnel from egress-1 and ingress-a)
    let relay_cfg = NodeConfig {
        node_tag: "relay-1".into(),
        identity_secret_key: kp_relay.secret_key_b64(),
        control_public_key: Some(kp_ctrl_sign.public_key_b64()),
        control_link_public_key: Some(kp_ctrl_link.public_key_b64()),
        roles: NodeRoles {
            relay: true,
            ..Default::default()
        },
        link_listener: Some(LinkListenConfig {
            listen_addr: "127.0.0.1:0".into(),
            allow_on_demand: true,
            allow_tunnel: true,
            allow_bootstrap: false,
        }),
        peers: vec![
            PeerConfig {
                peer_tag: "egress-1".into(),
                node_tag: "egress-1".into(),
                public_key: Some(kp_egress.public_key_b64()),
                pubkey_fingerprint: None,
                mode: LinkMode::Tunnel,
                tunnel_direction: Some(TunnelDirection::Inbound),
                expected_client_addr: None,
                endpoints: vec![],
            },
            PeerConfig {
                peer_tag: "maintainer-1".into(),
                node_tag: "maintainer-1".into(),
                public_key: Some(kp_maint.public_key_b64()),
                pubkey_fingerprint: None,
                mode: LinkMode::OnDemand,
                tunnel_direction: None,
                expected_client_addr: None,
                endpoints: vec![PeerEndpoint {
                    address: maint_link_addr.to_string(),
                    priority: 10,
                    weight: 100,
                }],
            },
            PeerConfig {
                peer_tag: "ingress-a".into(),
                node_tag: "ingress-a".into(),
                public_key: Some(kp_ingress.public_key_b64()),
                pubkey_fingerprint: None,
                mode: LinkMode::Tunnel,
                tunnel_direction: Some(TunnelDirection::Inbound),
                expected_client_addr: None,
                endpoints: vec![],
            },
        ],
        probe: ProbeConfig::default(),
        default_ttl: 16,
        maintainer_hops: vec!["relay-1".into(), "maintainer-1".into()],
        trusted_maintainers: vec![],
        trusted_origins: vec![],
        logger: temp_seg_cfg("relay"),
        ingress: Default::default(),
        egress: Default::default(),
        relay: RelayConfig {
            rules: vec![RelayRule {
                service_tag: "web@remote".into(),
                next_peer: "egress-1".into(),
            }],
        },
        maintainer: None,
        bootstrap_tunnel_addr: None,
        config_sequence: 0,
    };
    let relay_rt = NodeRuntime::new(relay_cfg, None, None).await.unwrap();
    let (relay_link_addr, _) = relay_rt.start().await.unwrap();
    let relay_link_addr = relay_link_addr.unwrap();

    // Give Maintainer a peer back to relay-1 AND let Maintainer accept relay-1 on-demand!
    maint_rt
        .link_manager()
        .update_peers(
            vec![PeerConfig {
                peer_tag: "relay-1".into(),
                node_tag: "relay-1".into(),
                public_key: Some(kp_relay.public_key_b64()),
                pubkey_fingerprint: None,
                mode: LinkMode::OnDemand,
                tunnel_direction: None,
                expected_client_addr: None,
                endpoints: vec![PeerEndpoint {
                    address: relay_link_addr.to_string(),
                    priority: 10,
                    weight: 100,
                }],
            }],
            ProbeConfig::default(),
        )
        .await;

    // 3. Start Egress Node (outbound tunnel to relay-1, trusts ingress-a origin pubkey!)
    let mut egress_services = BTreeMap::new();
    egress_services.insert(
        "web@remote".into(),
        EgressServiceConfig {
            backend: backend_addr.to_string(),
            protocol: BackendProtocol::Auto,
            tls: false,
            ca_cert_path: None,
            insecure_skip_verify: false,
            allow_from: vec!["ingress-a".into()],
            allow_any_origin: false,
            timeout_ms: 5000,
            intercept_errors: false,
            local_health_check: None,
        },
    );
    let egress_cfg = NodeConfig {
        node_tag: "egress-1".into(),
        identity_secret_key: kp_egress.secret_key_b64(),
        control_public_key: Some(kp_ctrl_sign.public_key_b64()),
        control_link_public_key: Some(kp_ctrl_link.public_key_b64()),
        roles: NodeRoles {
            egress: true,
            ..Default::default()
        },
        link_listener: None,
        peers: vec![PeerConfig {
            peer_tag: "relay-1".into(),
            node_tag: "relay-1".into(),
            public_key: Some(kp_relay.public_key_b64()),
            pubkey_fingerprint: None,
            mode: LinkMode::Tunnel,
            tunnel_direction: Some(TunnelDirection::Outbound),
            expected_client_addr: None,
            endpoints: vec![PeerEndpoint {
                address: relay_link_addr.to_string(),
                priority: 10,
                weight: 100,
            }],
        }],
        probe: ProbeConfig::default(),
        default_ttl: 16,
        maintainer_hops: vec!["egress-1".into(), "relay-1".into(), "maintainer-1".into()],
        trusted_maintainers: vec![],
        trusted_origins: vec![TrustedOrigin {
            node_tag: "ingress-a".into(),
            public_key: kp_ingress.public_key_b64(),
        }],
        logger: temp_seg_cfg("egress"),
        ingress: Default::default(),
        egress: EgressConfig {
            services: egress_services,
        },
        relay: Default::default(),
        maintainer: None,
        bootstrap_tunnel_addr: None,
        config_sequence: 0,
    };
    let egress_rt = NodeRuntime::new(egress_cfg, None, None).await.unwrap();
    egress_rt.start().await.unwrap();

    // 4. Start Ingress Node (co-located egress for `web@local` + Bootstrap tunnel listener for Control)
    let mut guards = BTreeMap::new();
    guards.insert(
        "rl".into(),
        GuardProfile {
            antibot: AntibotMode::Off,
            rate_limit_bucket: Some("tight".into()),
            ..Default::default()
        },
    );
    guards.insert(
        "pow".into(),
        GuardProfile {
            antibot: AntibotMode::Challenge,
            challenge_threshold: 40,
            reject_threshold: 95,
            pow_difficulty: 8,
            clearance_ttl_secs: 600,
            bind_ua: true,
            bind_ip_prefix: false,
            ..Default::default()
        },
    );
    let mut buckets = BTreeMap::new();
    buckets.insert(
        "tight".into(),
        RateLimitBucket {
            capacity: 2.0,
            refill_per_sec: 0.01,
            per_ip: true,
        },
    );
    let mut local_services = BTreeMap::new();
    local_services.insert(
        "web@local".into(),
        EgressServiceConfig {
            backend: backend_addr.to_string(),
            protocol: BackendProtocol::Auto,
            tls: false,
            ca_cert_path: None,
            insecure_skip_verify: false,
            allow_from: vec!["ingress-a".into()],
            allow_any_origin: false,
            timeout_ms: 5000,
            intercept_errors: false,
            local_health_check: Some(LocalHealthCheckConfig {
                enabled: true,
                interval_secs: 10,
                timeout_ms: 1000,
                http_path: None,
            }),
        },
    );

    let boot_passphrase = generate_five_word_passphrase();
    let ingress_cfg = NodeConfig {
        node_tag: "ingress-a".into(),
        identity_secret_key: kp_ingress.secret_key_b64(),
        control_public_key: None,
        control_link_public_key: None,
        roles: NodeRoles {
            ingress: true,
            egress: true,
            ..Default::default()
        },
        link_listener: Some(LinkListenConfig {
            listen_addr: "127.0.0.1:0".into(),
            allow_on_demand: true,
            allow_tunnel: true,
            allow_bootstrap: true,
        }),
        peers: vec![PeerConfig {
            peer_tag: "relay-1".into(),
            node_tag: "relay-1".into(),
            public_key: Some(kp_relay.public_key_b64()),
            pubkey_fingerprint: None,
            mode: LinkMode::Tunnel,
            tunnel_direction: Some(TunnelDirection::Outbound),
            expected_client_addr: None,
            endpoints: vec![PeerEndpoint {
                address: relay_link_addr.to_string(),
                priority: 10,
                weight: 100,
            }],
        }],
        probe: ProbeConfig::default(),
        default_ttl: 16,
        maintainer_hops: vec!["ingress-a".into(), "relay-1".into(), "maintainer-1".into()],
        trusted_maintainers: vec![TrustedMaintainer {
            node_tag: "maintainer-1".into(),
            public_key: kp_maint_cert.public_key_b64(),
        }],
        trusted_origins: vec![],
        logger: temp_seg_cfg("ingress"),
        ingress: IngressConfig {
            listeners: vec![IngressListener {
                listen_addr: "127.0.0.1:0".into(),
                tls: false,
            }],
            rules: vec![
                IngressRule {
                    name: Some("remote".into()),
                    r#match: RuleMatch {
                        host: Some("remote.test".into()),
                        ..Default::default()
                    },
                    service_tag: "web@remote".into(),
                    next_peer: "relay-1".into(),
                    guard: None,
                    intercept_errors: false,
                },
                IngressRule {
                    name: Some("local-self-tag".into()),
                    r#match: RuleMatch {
                        host: Some("local.test".into()),
                        ..Default::default()
                    },
                    service_tag: "web@local".into(),
                    next_peer: "ingress-a".into(),
                    guard: None,
                    intercept_errors: false,
                },
                IngressRule {
                    name: Some("rate-limited".into()),
                    r#match: RuleMatch {
                        host: Some("rl.test".into()),
                        ..Default::default()
                    },
                    service_tag: "web@local".into(),
                    next_peer: "ingress-a".into(),
                    guard: Some("rl".into()),
                    intercept_errors: false,
                },
                IngressRule {
                    name: Some("pow-protected".into()),
                    r#match: RuleMatch {
                        host: Some("pow.test".into()),
                        ..Default::default()
                    },
                    service_tag: "web@local".into(),
                    next_peer: "ingress-a".into(),
                    guard: Some("pow".into()),
                    intercept_errors: false,
                },
            ],
            guards,
            rate_limit_buckets: buckets,
            tls_certs: vec![],
            clearance_secret: generate_random_secret_hex(32),
            cert_store_dir: None,
            server_header: "nginx".into(),
        },
        egress: EgressConfig {
            services: local_services,
        },
        relay: Default::default(),
        maintainer: None,
        bootstrap_tunnel_addr: None,
        config_sequence: 0,
    };
    let ingress_rt = NodeRuntime::new(ingress_cfg, None, Some(boot_passphrase.clone()))
        .await
        .unwrap();
    let (ingress_link_addr, ingress_http_addrs) = ingress_rt.start().await.unwrap();
    let ingress_link_addr = ingress_link_addr.unwrap();
    let ingress_http = ingress_http_addrs[0];

    // Wait briefly for outbound tunnels (ingress-a -> relay-1 and egress-1 -> relay-1) to establish
    tokio::time::sleep(Duration::from_millis(600)).await;

    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // --- TEST A: Multi-hop HTTP/1.1 with signed origin ACL ---
    let resp = http_client
        .get(format!("http://{ingress_http}/mesh-v1"))
        .header("Host", "remote.test")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("path=/mesh-v1"), "unexpected body: {body}");

    // --- TEST B: Multi-hop HTTP/2 (h2c) with signed origin ACL ---
    let tcp = tokio::net::TcpStream::connect(ingress_http).await.unwrap();
    let (mut h2_send, h2_conn) = hyper::client::conn::http2::handshake(
        TokioExecutor::new(),
        TokioIo::new(tcp),
    )
    .await
    .unwrap();
    tokio::spawn(async move {
        let _ = h2_conn.await;
    });
    let h2_req = Request::builder()
        .uri("http://remote.test/mesh-h2")
        .header("host", "remote.test")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let h2_resp = h2_send.send_request(h2_req).await.unwrap();
    assert_eq!(h2_resp.status(), StatusCode::OK);
    let h2_body = String::from_utf8(
        h2_resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
    )
    .unwrap();
    assert!(
        h2_body.contains("HTTP/2.0") && h2_body.contains("path=/mesh-h2"),
        "unexpected h2 body: {h2_body}"
    );

    // --- TEST C: Co-located ingress+egress via self node_tag ("ingress-a") ---
    let local_resp = http_client
        .get(format!("http://{ingress_http}/local-direct"))
        .header("Host", "local.test")
        .send()
        .await
        .unwrap();
    assert_eq!(local_resp.status(), 200);
    assert!(local_resp.text().await.unwrap().contains("path=/local-direct"));

    // --- TEST D: Guard Token Bucket Rate Limiting (429 + Retry-After) ---
    for _ in 0..2 {
        let r = http_client
            .get(format!("http://{ingress_http}/ok"))
            .header("Host", "rl.test")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
    }
    let rl_resp = http_client
        .get(format!("http://{ingress_http}/blocked"))
        .header("Host", "rl.test")
        .send()
        .await
        .unwrap();
    assert_eq!(rl_resp.status(), 429);
    assert!(rl_resp.headers().contains_key("retry-after"));

    // --- TEST E: Guard PoW Challenge under /cdn-cgi/, Replay Rejection & Clearance Cookie ---
    let bot_resp = http_client
        .get(format!("http://{ingress_http}/protected"))
        .header("Host", "pow.test")
        .header("User-Agent", "curl/8.5")
        .send()
        .await
        .unwrap();
    assert_eq!(bot_resp.status(), 302);
    assert!(bot_resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("/cdn-cgi/?redirect="));

    let html_resp = http_client
        .get(format!("http://{ingress_http}/cdn-cgi/"))
        .header("Host", "pow.test")
        .send()
        .await
        .unwrap();
    assert_eq!(html_resp.status(), 200);
    assert!(html_resp.headers().contains_key("content-security-policy"));

    let ch_json: serde_json::Value = http_client
        .get(format!("http://{ingress_http}/cdn-cgi/challenge"))
        .header("Host", "pow.test")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = ch_json["token"].as_str().unwrap();
    let diff = ch_json["difficulty"].as_u64().unwrap() as u8;
    let mut nonce = 0u64;
    while !verify_pow_solution(token, nonce, diff) {
        nonce += 1;
    }
    let verify_payload = serde_json::json!({
        "token": token,
        "nonce": nonce,
        "signature": ch_json["signature"],
        "expires_at": ch_json["expires_at"],
        "difficulty": diff,
        "redirect": "/protected"
    });
    let verify_resp = http_client
        .post(format!("http://{ingress_http}/cdn-cgi/verify"))
        .header("Host", "pow.test")
        .header("User-Agent", "curl/8.5")
        .json(&verify_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(verify_resp.status(), 200);
    let cookie_hdr = verify_resp
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();

    // Replaying the same PoW solution MUST be rejected!
    let replay_resp = http_client
        .post(format!("http://{ingress_http}/cdn-cgi/verify"))
        .header("Host", "pow.test")
        .header("User-Agent", "curl/8.5")
        .json(&verify_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(replay_resp.status(), 403);

    let cleared_resp = http_client
        .get(format!("http://{ingress_http}/protected"))
        .header("Host", "pow.test")
        .header("User-Agent", "curl/8.5")
        .header("Cookie", &cookie_hdr)
        .send()
        .await
        .unwrap();
    assert_eq!(cleared_resp.status(), 200);

    // --- TEST F: Maintainer Per-Target Cert Signing & Hop-Table Distribution -> Ingress Hot Reload ---
    let maint_svc = maint_rt.maintainer().await.unwrap();
    let order = CertOrderConfig {
        domain: "secure.test".into(),
        provider: "none".into(),
        target_nodes: vec!["ingress-a".into()],
        target_hops: BTreeMap::from([(
            "ingress-a".into(),
            vec!["maintainer-1".into(), "relay-1".into(), "ingress-a".into()],
        )]),
        renew_before_days: 30,
    };
    maint_svc
        .issue_and_distribute_order(&order, maint_rt.forwarder())
        .await
        .unwrap();
    assert_eq!(ingress_rt.cert_resolver().cert_count(), 1);

    // Push ingress logs along Hop Table to Maintainer
    let (recs, sums) = ingress_rt.logger().drain_for_maintainer().await;
    assert!(!sums.is_empty());
    let log_frame = SpecialFrame::new(
        uuid::Uuid::new_v4().to_string(),
        vec!["ingress-a".into(), "relay-1".into(), "maintainer-1".into()],
        16,
        SpecialPayload::LogBatch {
            from_node: "ingress-a".into(),
            records: recs,
            minute_summaries: sums,
        },
    );
    let log_ack = ingress_rt
        .forwarder()
        .send_special_rpc(log_frame, Duration::from_secs(5))
        .await
        .unwrap();
    assert!(matches!(log_ack.payload, SpecialPayload::LogAck { accepted } if accepted > 0));

    // --- TEST G: Control Bootstrap (separate signing/link keys!), Discovery, Telemetry Pull & Auth ---
    let ctrl_cfg = ControlConfig {
        control_id: "control-1".into(),
        role: ControlRole::Active,
        panel_listen_addr: "127.0.0.1:0".into(),
        tls: None,
        sqlite_path: ":memory:".into(),
        signing_secret_key: kp_ctrl_sign.secret_key_b64(),
        link_secret_key: kp_ctrl_link.secret_key_b64(),
        admin: AdminAuthConfig {
            username: "admin".into(),
            password_hash: hash_password("strong-e2e-password").unwrap(),
            token_secret: generate_random_secret_hex(32),
        },
        bootstrap_nodes: vec![BootstrapNodeTarget {
            node_tag: "ingress-a".into(),
            address: ingress_link_addr.to_string(),
            public_key: None,
            passphrase: Some(boot_passphrase),
        }],
        telemetry_pull_interval_secs: 60,
        initial_topology_path: None,
    };
    let ctrl_rt = ControlRuntime::new(ctrl_cfg).await.unwrap();
    let panel_addr = ctrl_rt.start().await.unwrap();

    // Give Control a brief moment to install BOTH signing & link pubkeys on ingress-a
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(ctrl_rt.client().is_bootstrap_connected().await);
    assert_eq!(
        ingress_rt.config_snapshot().await.control_public_key.as_deref(),
        Some(kp_ctrl_sign.public_key_b64().as_str())
    );
    assert_eq!(
        ingress_rt.config_snapshot().await.control_link_public_key.as_deref(),
        Some(kp_ctrl_link.public_key_b64().as_str())
    );

    // Run Discovery across mesh: control-1 -> ingress-a -> relay-1 -> (egress-1, maintainer-1)
    let discovered = ctrl_rt.client().run_discovery("test").await.unwrap();
    assert!(discovered >= 3, "expected >= 3 discovered nodes, got {discovered}");

    // Test Control Admin Panel HTML, security headers, Argon2 login, HttpOnly cookie & logout revocation
    let panel_resp = http_client
        .get(format!("http://{panel_addr}/"))
        .send()
        .await
        .unwrap();
    assert!(panel_resp.headers().contains_key("content-security-policy"));
    assert_eq!(
        panel_resp.headers().get("x-frame-options").unwrap(),
        "DENY"
    );
    let panel_html = panel_resp.text().await.unwrap();
    assert!(panel_html.contains("EXPOSURE CONTROL"));

    // Unknown /api/* route MUST return 404 JSON (not SPA index.html)
    let not_found_api = http_client
        .get(format!("http://{panel_addr}/api/nonexistent"))
        .send()
        .await
        .unwrap();
    assert_eq!(not_found_api.status(), 404);

    let login_resp = http_client
        .post(format!("http://{panel_addr}/api/auth/login"))
        .json(&serde_json::json!({ "username": "admin", "password": "strong-e2e-password" }))
        .send()
        .await
        .unwrap();
    assert_eq!(login_resp.status(), 200);
    let session_cookie = login_resp
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(session_cookie.contains("HttpOnly"));
    assert!(session_cookie.contains("SameSite=Strict"));
    let login_json: serde_json::Value = login_resp.json().await.unwrap();
    let bearer = login_json["token"].as_str().unwrap().to_string();

    // Pull telemetry actively via Maintainer Hop Table
    let pull_frame = SpecialFrame::new(
        uuid::Uuid::new_v4().to_string(),
        vec![
            "control-1".into(),
            "ingress-a".into(),
            "relay-1".into(),
            "maintainer-1".into(),
        ],
        16,
        SpecialPayload::PullTelemetryReq { since_minute: None },
    );
    let pulled = ctrl_rt
        .client()
        .send_special_rpc(pull_frame, Duration::from_secs(5))
        .await
        .unwrap();
    match pulled.payload {
        SpecialPayload::PullTelemetryResp(snap) => {
            assert!(!snap.summaries.is_empty());
            assert_eq!(snap.certificates.len(), 1);
            assert_eq!(snap.certificates[0].domain, "secure.test");
            assert_eq!(snap.certificates[0].status, "valid");
        }
        other => panic!("unexpected pull telemetry reply: {other:?}"),
    }

    // Verify Preflight bundle CANNOT be replayed as ConfigPush (domain separation!)
    let mut updated_cfg = ingress_rt.config_snapshot().await;
    updated_cfg.default_ttl = 12;
    let preflight_bundle = ctrl_rt
        .client()
        .sign_config_bundle_with_purpose(
            "ingress-a",
            2,
            updated_cfg.clone(),
            ConfigBundlePurpose::Preflight,
            30,
        )
        .unwrap();
    assert!(
        ingress_rt.apply_signed_config(preflight_bundle).await.is_err(),
        "Preflight bundle must NEVER be accepted by apply_signed_config"
    );

    // Verify signed Apply config push + rollback rejection on ingress-a
    let bundle_v2 = ctrl_rt
        .client()
        .sign_config_bundle("ingress-a", 2, updated_cfg.clone())
        .unwrap();
    ingress_rt.apply_signed_config(bundle_v2).await.unwrap();
    assert_eq!(ingress_rt.config_snapshot().await.config_sequence, 2);
    assert_eq!(ingress_rt.config_snapshot().await.default_ttl, 12);

    // Attempt rollback with seq=1 -> must be rejected and seq remains 2
    let bundle_rollback = ctrl_rt
        .client()
        .sign_config_bundle("ingress-a", 1, updated_cfg)
        .unwrap();
    assert!(ingress_rt.apply_signed_config(bundle_rollback).await.is_err());
    assert_eq!(ingress_rt.config_snapshot().await.config_sequence, 2);

    // Verify authenticated /api/nodes and /api/overview (ensuring no private key field leaked!)
    let overview_json: serde_json::Value = http_client
        .get(format!("http://{panel_addr}/api/overview"))
        .header("Authorization", format!("Bearer {bearer}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    for node_obj in overview_json["nodes"].as_array().unwrap() {
        assert!(
            node_obj.get("maintainer_signing_secret").is_none(),
            "maintainer_signing_secret must never be serialized to API"
        );
    }

    // Verify server-side logout revokes the token immediately!
    let logout_resp = http_client
        .post(format!("http://{panel_addr}/api/auth/logout"))
        .header("Authorization", format!("Bearer {bearer}"))
        .send()
        .await
        .unwrap();
    assert_eq!(logout_resp.status(), 200);

    let after_logout = http_client
        .get(format!("http://{panel_addr}/api/nodes"))
        .header("Authorization", format!("Bearer {bearer}"))
        .send()
        .await
        .unwrap();
    assert_eq!(after_logout.status(), 401);
}
