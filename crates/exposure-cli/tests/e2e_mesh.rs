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
                    if req.uri().path() == "/page.html" {
                        return Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "text/html; charset=utf-8")
                                .body(Full::new(Bytes::from(
                                    "<!doctype html><html><body><h1>Hello Exposure</h1></body></html>",
                                )))
                                .unwrap(),
                        );
                    }
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

fn temp_seg_cfg(name: &str, shared_hmac: &str) -> LoggerConfig {
    let dir = std::env::temp_dir().join(format!("exposure-e2e-{name}-{}", uuid::Uuid::new_v4()));
    LoggerConfig {
        hmac_key: shared_hmac.to_string(),
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
    let shared_hmac = generate_random_secret_hex(32);

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
            allow_on_demand: Some(true),
            allow_tunnel: Some(true),
            allow_bootstrap: Some(false),
        }),
        peers: vec![],
        probe: ProbeConfig::default(),
        default_ttl: 16,
        maintainer_hops: vec![],
        trusted_maintainers: vec![],
        trusted_origins: vec![],
        logger: temp_seg_cfg("maint", &shared_hmac),
        ingress: Default::default(),
        egress: Default::default(),
        relay: Default::default(),
        maintainer: Some(MaintainerConfig {
            cert_signing_secret_key: Some(kp_maint_cert.secret_key_b64()),
            is_primary_cert_manager: true,
            logger: temp_seg_cfg("maint-agg", &shared_hmac),
            acme: AcmeConfig {
                directory_url: "self-signed".into(),
                storage_dir: std::env::temp_dir()
                    .join(format!("exposure-mcerts-{}", uuid::Uuid::new_v4()))
                    .to_string_lossy()
                    .to_string(),
                ..Default::default()
            },
            ..Default::default()
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
            allow_on_demand: Some(true),
            allow_tunnel: Some(true),
            allow_bootstrap: Some(false),
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
        logger: temp_seg_cfg("relay", &shared_hmac),
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
            tls: Some(false),
            ca_cert_path: None,
            insecure_skip_verify: Some(false),
            allow_from: vec!["ingress-a".into()],
            allow_any_origin: Some(false),
            timeout_ms: 5000,
            intercept_errors: Some(false),
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
        logger: temp_seg_cfg("egress", &shared_hmac),
        ingress: Default::default(),
        egress: EgressConfig {
            services: egress_services,
            ..Default::default()
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
            bind_ua: Some(true),
            bind_ip_prefix: Some(false),
            ..Default::default()
        },
    );
    let mut buckets = BTreeMap::new();
    buckets.insert(
        "tight".into(),
        RateLimitBucket {
            capacity: 2.0,
            refill_per_sec: 0.01,
            per_ip: Some(true),
        },
    );
    let mut local_services = BTreeMap::new();
    local_services.insert(
        "web@local".into(),
        EgressServiceConfig {
            backend: backend_addr.to_string(),
            protocol: BackendProtocol::Auto,
            tls: Some(false),
            ca_cert_path: None,
            insecure_skip_verify: Some(false),
            allow_from: vec!["ingress-a".into()],
            allow_any_origin: Some(false),
            timeout_ms: 5000,
            intercept_errors: Some(false),
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
            allow_on_demand: Some(true),
            allow_tunnel: Some(true),
            allow_bootstrap: Some(true),
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
        logger: temp_seg_cfg("ingress", &shared_hmac),
        ingress: IngressConfig {
            listeners: vec![IngressListener {
                listen_addr: "127.0.0.1:0".into(),
                tls: false,
                redirect_https: false,
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
                    intercept_errors: Some(false),
                    js_fp_beacon: Some(true),
                    cache: None,
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
                    intercept_errors: Some(false),
                    js_fp_beacon: Some(true),
                    cache: None,
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
                    intercept_errors: Some(true),
                    js_fp_beacon: Some(false),
                    cache: None,
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
                    intercept_errors: Some(false),
                    js_fp_beacon: Some(true),
                    cache: None,
                },
            ],
            guards,
            rate_limit_buckets: buckets,
            tls_certs: vec![],
            clearance_secret: generate_random_secret_hex(32),
            cert_store_dir: None,
            server_header: "nginx".into(),
            js_fp_beacon: Some(true),
            js_fp_ttl_secs: Some(3600),
            pages: Default::default(),
            cache: Default::default(),
            evilpot: Default::default(),
        },
        egress: EgressConfig {
            services: local_services,
            pages: Default::default(),
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

    // --- TEST C2: Adaptive Passive JS Fingerprint Beacon Injection + Secure /cdn-cgi/fp-report ---
    let browser_ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36";
    let html_resp = http_client
        .get(format!("http://{ingress_http}/page.html"))
        .header("Host", "remote.test")
        .header("User-Agent", browser_ua)
        .header("Accept", "text/html,application/xhtml+xml")
        .header("Sec-Fetch-Dest", "document")
        .send()
        .await
        .unwrap();
    assert_eq!(html_resp.status(), 200);
    assert_eq!(
        html_resp.headers().get("cache-control").and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "injected HTML must set Cache-Control: no-store to prevent 304 token replay"
    );
    assert!(
        html_resp.headers().get("last-modified").is_none()
            && html_resp.headers().get("etag").is_none(),
        "injected HTML must strip Last-Modified and ETag validators"
    );
    let html_body = html_resp.text().await.unwrap();
    assert!(
        html_body.contains(r#"<script defer src="/cdn-cgi/fp.js" data-t=""#),
        "expected passive FP beacon script in HTML: {html_body}"
    );
    let marker = r#"data-t=""#;
    let tok_start = html_body.find(marker).unwrap() + marker.len();
    let tok_end = html_body[tok_start..].find('"').unwrap() + tok_start;
    let fp_token = html_body[tok_start..tok_end].to_string();

    // Cross-site FP report MUST be rejected
    let bad_fp_resp = http_client
        .post(format!("http://{ingress_http}/cdn-cgi/fp-report"))
        .header("Host", "remote.test")
        .header("User-Agent", browser_ua)
        .header("Sec-Fetch-Site", "cross-site")
        .json(&serde_json::json!({ "token": fp_token, "fp": { "canvas_hash": "abc12345" } }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_fp_resp.status(), 403);

    // Legitimate same-origin FP report succeeds, sets signed exposure_fp cookie, and rejects replay
    let fp_report_payload = serde_json::json!({
        "token": fp_token,
        "fp": {
            "webdriver": false,
            "webgl": "ANGLE (NVIDIA RTX 4090)",
            "platform": "Linux x86_64",
            "screen": "2560x1440x24",
            "tz": "Asia/Shanghai",
            "lang": "zh-CN",
            "cores": 16,
            "mem": 32,
            "touch": 0,
            "canvas_hash": "cafebabe99",
            "dpr": "2",
            "plugins_count": 5
        }
    });
    let ok_fp_resp = http_client
        .post(format!("http://{ingress_http}/cdn-cgi/fp-report"))
        .header("Host", "remote.test")
        .header("User-Agent", browser_ua)
        .header("Sec-Fetch-Site", "same-origin")
        .json(&fp_report_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(ok_fp_resp.status(), 204);
    let fp_cookie = ok_fp_resp
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert!(fp_cookie.starts_with("exposure_fp="));

    // Replaying the same single-use FP token MUST fail!
    let replay_fp_resp = http_client
        .post(format!("http://{ingress_http}/cdn-cgi/fp-report"))
        .header("Host", "remote.test")
        .header("User-Agent", browser_ua)
        .header("Sec-Fetch-Site", "same-origin")
        .json(&fp_report_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(replay_fp_resp.status(), 403);

    // Subsequent HTML request carrying valid exposure_fp cookie must NOT re-inject beacon!
    let html_resp2 = http_client
        .get(format!("http://{ingress_http}/page.html"))
        .header("Host", "remote.test")
        .header("User-Agent", browser_ua)
        .header("Accept", "text/html")
        .header("Sec-Fetch-Dest", "document")
        .header("Cookie", &fp_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(html_resp2.status(), 200);
    let html_body2 = html_resp2.text().await.unwrap();
    assert!(
        !html_body2.contains("/cdn-cgi/fp.js"),
        "should not re-inject beacon when valid exposure_fp cookie is present"
    );

    // --- TEST C3: Oversized single HTTP header (64 KiB) MUST be rejected with 431 (F5) ---
    let big_hdr = "A".repeat(64 * 1024);
    let big_hdr_resp = http_client
        .get(format!("http://{ingress_http}/mesh-v1"))
        .header("Host", "remote.test")
        .header("X-Oversized", big_hdr)
        .send()
        .await
        .unwrap();
    assert_eq!(
        big_hdr_resp.status(),
        431,
        "oversized 64 KiB single header should be rejected with 431"
    );

    // --- TEST C4: Unknown Host MUST be rejected with 421 Misdirected Request (F7) ---
    let unknown_host_resp = http_client
        .get(format!("http://{ingress_http}/index.html"))
        .header("Host", "unconfigured-vhost.invalid")
        .send()
        .await
        .unwrap();
    assert_eq!(
        unknown_host_resp.status(),
        421,
        "unknown Host header must be rejected with 421 Misdirected Request"
    );

    // --- TEST D: Guard Token Bucket Rate Limiting ---
    // Un-degraded hits (1..=3) return HTML error page and do NOT block /cdn-cgi/ PoW;
    // once degraded (4+), both normal routes AND /cdn-cgi/ PoW return ultra-short "429".
    for _ in 0..2 {
        let r = http_client
            .get(format!("http://{ingress_http}/ok"))
            .header("Host", "rl.test")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
    }
    // Hit 1: normal route -> 429 HTML page
    let rl_resp1 = http_client
        .get(format!("http://{ingress_http}/blocked"))
        .header("Host", "rl.test")
        .send()
        .await
        .unwrap();
    assert_eq!(rl_resp1.status(), 429);
    assert!(rl_resp1.headers().contains_key("retry-after"));
    let rl_body1 = rl_resp1.text().await.unwrap();
    assert!(rl_body1.contains("<!DOCTYPE html>"), "first hit should serve error page");

    // Before degradation, /cdn-cgi/ PoW page must remain unaffected
    let pre_deg_pow = http_client
        .get(format!("http://{ingress_http}/cdn-cgi/"))
        .header("Host", "rl.test")
        .send()
        .await
        .unwrap();
    assert_eq!(pre_deg_pow.status(), 200);

    // Hit 2 & 3: normal route -> still 429 HTML page
    for hit in [2, 3] {
        let rl_resp = http_client
            .get(format!("http://{ingress_http}/blocked"))
            .header("Host", "rl.test")
            .send()
            .await
            .unwrap();
        assert_eq!(rl_resp.status(), 429);
        let body = rl_resp.text().await.unwrap();
        assert!(body.contains("<!DOCTYPE html>"), "hit {hit} should serve error page");
    }

    // Hit 4+: bucket is degraded -> normal route AND /cdn-cgi/ PoW endpoints return ultra-short "429"
    for path in ["/blocked", "/cdn-cgi/", "/cdn-cgi/challenge"] {
        let rl_short = http_client
            .get(format!("http://{ingress_http}{path}"))
            .header("Host", "rl.test")
            .send()
            .await
            .unwrap();
        assert_eq!(rl_short.status(), 429);
        assert!(rl_short.headers().contains_key("retry-after"));
        assert_eq!(rl_short.text().await.unwrap(), "429");
    }

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
        provider: Some("none".into()),
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

    // Push ingress logs & fingerprint observations along Hop Table to Maintainer
    let (recs, sums, fps) = ingress_rt.logger().drain_for_maintainer().await;
    assert!(!sums.is_empty());
    assert!(!fps.is_empty(), "expected collected fingerprint observations");
    let log_frame = SpecialFrame::new(
        uuid::Uuid::new_v4().to_string(),
        vec!["ingress-a".into(), "relay-1".into(), "maintainer-1".into()],
        16,
        SpecialPayload::LogBatch {
            from_node: "ingress-a".into(),
            records: recs,
            minute_summaries: sums,
            fingerprints: fps,
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
            assert!(
                snap.fingerprints.iter().any(|f| f.js_verified && f.fp_source == "beacon"),
                "expected JS-verified beacon fingerprint in Maintainer snapshot"
            );
            assert_eq!(snap.certificates.len(), 1);
            assert_eq!(snap.certificates[0].domain, "secure.test");
            assert_eq!(snap.certificates[0].status, "valid");
        }
        other => panic!("unexpected pull telemetry reply: {other:?}"),
    }

    // Trigger Control telemetry pull via HTTP API (populates CachedTelemetry for /api/overview, /api/telemetry, /api/fingerprints)
    // First store a minimal topology YAML with shared_hmac so Control can resolve IP HMAC search + Maintainer hops
    let min_topo_yaml = format!(
        "global_logger:\n  hmac_key: \"{shared_hmac}\"\nnodes:\n  ingress-a:\n    roles:\n      ingress: true\n  relay-1:\n    roles:\n      relay: true\n  maintainer-1:\n    roles:\n      maintainer: true\nlinks:\n  - from: ingress-a\n    to: relay-1\n    mode: tunnel\n    tunnel_direction: outbound\n    endpoints:\n      - address: \"198.51.100.1:9443\"\n  - from: relay-1\n    to: maintainer-1\n    mode: on-demand\n    bidirectional: false\n    endpoints:\n      - address: \"198.51.100.2:9443\"\n"
    );
    ctrl_rt.client().db().set_topology_yaml(&min_topo_yaml).await.unwrap();
    let pull_api_resp = http_client
        .post(format!("http://{panel_addr}/api/telemetry/pull"))
        .header("Authorization", format!("Bearer {bearer}"))
        .send()
        .await
        .unwrap();
    assert_eq!(pull_api_resp.status(), 200);

    // Verify exact UV == 1 (single 127.0.0.1 visitor across multiple requests/services/roles, never double-counted!)
    let tel_json: serde_json::Value = http_client
        .get(format!("http://{panel_addr}/api/telemetry?window_secs=3600"))
        .header("Authorization", format!("Bearer {bearer}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        tel_json["traffic"]["uv_estimate"].as_f64(),
        Some(1.0),
        "exact UV for single 127.0.0.1 visitor must be 1.0: {tel_json}"
    );

    // Verify /api/fingerprints search by IP (auto-HMAC matched!) AND by browser FP (canvas_hash / webgl)
    let fp_by_ip: serde_json::Value = http_client
        .get(format!("http://{panel_addr}/api/fingerprints?ip=127.0.0.1&verified=js"))
        .header("Authorization", format!("Bearer {bearer}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        fp_by_ip["items"].as_array().map(|a| !a.is_empty()).unwrap_or(false),
        "IP search must match via HMAC even when store_raw_ip is false: {fp_by_ip}"
    );
    let fp_by_canvas: serde_json::Value = http_client
        .get(format!("http://{panel_addr}/api/fingerprints?fp=cafebabe99"))
        .header("Authorization", format!("Bearer {bearer}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        fp_by_canvas["items"].as_array().map(|a| a.len()),
        Some(1),
        "FP search by canvas_hash must find exact browser observation: {fp_by_canvas}"
    );

    // Verify Preflight bundle CANNOT be replayed as ConfigPush (domain separation!)
    let mut updated_cfg = ingress_rt.config_snapshot().await;
    updated_cfg.default_ttl = 12;
    updated_cfg.ingress.pages = exposure_core::config::CustomPagesConfig {
        error_html: Some("<html>custom-err-{{status}}</html>".into()),
        challenge_html: Some("<html><body>Custom PoW Page</body></html>".into()),
        challenge_css: Some("body{background:#010203}".into()),
    };
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

    // Verify custom Control-distributed PoW HTML & CSS are served immediately from memory
    let custom_pow_html = http_client
        .get(format!("http://{ingress_http}/cdn-cgi/"))
        .header("Host", "pow.test")
        .send()
        .await
        .unwrap();
    assert_eq!(custom_pow_html.status(), 200);
    assert_eq!(
        custom_pow_html.text().await.unwrap(),
        "<html><body>Custom PoW Page</body></html>"
    );
    let custom_pow_css = http_client
        .get(format!("http://{ingress_http}/cdn-cgi/styles.css"))
        .header("Host", "pow.test")
        .send()
        .await
        .unwrap();
    assert_eq!(custom_pow_css.status(), 200);
    assert_eq!(custom_pow_css.text().await.unwrap(), "body{background:#010203}");

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

    // Verify forged DnsSyncReq is rejected by Maintainer (no unauthorized DNS changes allowed!)
    let forged_sync = SpecialFrame::new(
        uuid::Uuid::new_v4().to_string(),
        vec![
            "control-1".into(),
            "ingress-a".into(),
            "relay-1".into(),
            "maintainer-1".into(),
        ],
        16,
        SpecialPayload::DnsSyncReq {
            request_id: "forged-sync-1".into(),
            issued_at: chrono::Utc::now().timestamp(),
            expires_at: chrono::Utc::now().timestamp() + 60,
            maintainer_tag: "maintainer-1".into(),
            records: vec![exposure_core::protocol::DnsSyncRecordSpec {
                domain: "app.example.com".into(),
                ipv4s: vec!["203.0.113.10".into()],
                ipv6s: vec![],
                line_entries: vec![],
                provider: Some("missing-prov".into()),
                zone_id: None,
                root_domain: None,
                ttl: Some(600),
                proxied: Some(false),
            }],
            control_signature: "invalid-signature".into(),
        },
    );
    let forged_reply = ctrl_rt
        .client()
        .send_special_rpc(forged_sync, Duration::from_secs(5))
        .await
        .unwrap();
    match forged_reply.payload {
        SpecialPayload::DnsSyncResp { ok, error, .. } => {
            assert!(!ok);
            assert!(
                error.as_deref().unwrap_or("").contains("signature invalid"),
                "expected signature rejection, got: {error:?}"
            );
        }
        other => panic!("unexpected forged DnsSync reply: {other:?}"),
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
