use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chrono::Utc;
use dashmap::DashMap;
use exposure_core::Result;
use exposure_core::config::AutoBanConfig;
use exposure_core::crypto::short_sha256_hex;
use exposure_core::routing::canonical_ip;
use exposure_core::segment::{read_json_snapshot, write_json_snapshot_atomic};
use exposure_core::telemetry::{ActiveBanInfo, BanRecord};
use serde::{Deserialize, Serialize};

const MAX_BANNED_IPS: usize = 65_536;
const MAX_BANNED_FPS: usize = 32_768;
const MAX_OFFENSE_ENTRIES: usize = 32_768;
const MAX_BENIGN_FPS: usize = 32_768;
const MAX_REPORT_BANS: usize = 64;
const OFFENSE_WINDOW: Duration = Duration::from_secs(300);
const ESCALATION_MEMORY: Duration = Duration::from_secs(86_400);
const BENIGN_FP_IDLE_TTL: Duration = Duration::from_secs(3600);
const MAX_REASON_CHARS: usize = 128;

pub(crate) fn evict_half<K, V>(map: &DashMap<K, V>)
where
    K: Eq + std::hash::Hash,
{
    let to_remove = map.len() / 2;
    if to_remove == 0 {
        return;
    }
    let mut removed = 0usize;
    map.retain(|_, _| {
        if removed < to_remove {
            removed += 1;
            false
        } else {
            true
        }
    });
}

fn evict_oldest_benign_half(map: &DashMap<String, BenignFpEntry>) {
    let cur = map.len();
    if cur < 2 {
        return;
    }
    let mut entries: Vec<(bool, Instant)> = map
        .iter()
        .map(|e| (e.value().distinct_ips.len() >= 2, e.value().last_seen))
        .collect();
    let mid = entries.len() / 2;
    let (_, mid_val, _) = entries.select_nth_unstable(mid);
    let (cutoff_multi, cutoff_ts) = *mid_val;
    let mut budget = cur / 2;
    map.retain(|_, v| {
        if budget == 0 {
            return true;
        }
        let multi = v.distinct_ips.len() >= 2;
        if (multi, v.last_seen) <= (cutoff_multi, cutoff_ts) {
            budget -= 1;
            false
        } else {
            true
        }
    });
}

fn clean_reason(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .take(MAX_REASON_CHARS)
        .collect()
}

fn now_unix_secs() -> u64 {
    Utc::now().timestamp().max(0) as u64
}

/// Build an unforgeable composite server-side client fingerprint combining TLS ClientHello JA3
/// with the client's User-Agent hash. Returns `None` when TLS JA3 is unavailable (plain HTTP)
/// so bare User-Agent strings are never mistakenly banned across unrelated clients.
pub fn build_composite_fp(tls_ja3: Option<&str>, ua: &str) -> Option<String> {
    let ja3 = tls_ja3.map(str::trim).filter(|s| !s.is_empty())?;
    let ua_h = short_sha256_hex(ua.trim());
    Some(format!("{ja3}:{ua_h}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanKind {
    Ip,
    JsFingerprint,
    CompositeFingerprint,
}

impl BanKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::JsFingerprint => "js_fp",
            Self::CompositeFingerprint => "composite_fp",
        }
    }
}

#[derive(Debug, Clone)]
pub struct BanMatch {
    pub kind: BanKind,
    pub target: String,
    pub reason: String,
    pub remaining_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffenseKind {
    /// Confirmed exploit behavior (Evilpot canary replay, RCE command/IOC, sustained tarpit read).
    VerifiedExploit,
    /// Multi-step exploitation observed by Evilpot (e.g. SQLi extraction, multi-path recon).
    MultiStepExploitation { trapped_requests: u64 },
    /// Attacker exhausted Evilpot per-IP admission quota / concurrency cap while attacking.
    EvilpotFlood,
    /// Unambiguous offensive vulnerability scanner UA (`sqlmap`, `nikto`, `nuclei`, etc.).
    AttackScannerProbe,
    /// Single WAF/CRS/Evilpot probing hit (requires repeated hits to confirm & ban).
    WafAttackProbe,
    /// Repeated PoW verification failures or tampered headless browser rejection.
    HeadlessOrVerifyAbuse,
}

#[derive(Debug, Clone)]
pub struct OffenseContext<'a> {
    pub client_ip: IpAddr,
    pub tls_ja3: Option<&'a str>,
    pub user_agent: &'a str,
    pub js_fp_hash: Option<&'a str>,
    pub service_tag: Option<&'a str>,
    pub host: Option<&'a str>,
    pub kind: OffenseKind,
    pub reason: &'a str,
}

#[derive(Debug, Clone, Default)]
pub struct OffenseOutcome {
    pub newly_banned_ip: bool,
    pub newly_banned_js_fp: bool,
    pub newly_banned_composite_fp: bool,
    pub ban_ttl_secs: u64,
    pub offense_level: u8,
    pub created_bans: Vec<BanRecord>,
}

impl OffenseOutcome {
    pub fn any_banned(&self) -> bool {
        self.newly_banned_ip || self.newly_banned_js_fp || self.newly_banned_composite_fp
    }
}

struct BanEntry {
    reason: String,
    service_tag: Option<String>,
    host: Option<String>,
    banned_at_unix: u64,
    expires_at: Instant,
    expires_at_unix: u64,
    offense_level: u8,
    hits_blocked: AtomicU64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedBanState {
    #[serde(default)]
    total_auto_bans: u64,
    #[serde(default)]
    total_ban_drops: u64,
    #[serde(default)]
    bans: Vec<BanRecord>,
}

fn clean_opt_meta(v: Option<&str>, max_chars: usize) -> Option<String> {
    v.map(str::trim).filter(|s| !s.is_empty()).map(|s| {
        s.chars()
            .filter(|c| !c.is_control())
            .take(max_chars)
            .collect()
    })
}

fn ban_entry_to_record(node_tag: &str, kind: BanKind, target: String, e: &BanEntry) -> BanRecord {
    BanRecord {
        id: 0,
        node_tag: node_tag.to_string(),
        kind: kind.as_str().to_string(),
        target,
        reason: e.reason.clone(),
        service_tag: e.service_tag.clone(),
        host: e.host.clone(),
        offense_level: e.offense_level,
        banned_at_unix: e.banned_at_unix,
        expires_at_unix: e.expires_at_unix,
        unbanned_at_unix: None,
        unbanned_by: None,
        hits_blocked: e.hits_blocked.load(Ordering::Relaxed),
        status: "active".to_string(),
    }
}

struct OffenseTrackerEntry {
    window_start: Instant,
    points: u32,
}

struct BenignFpEntry {
    last_seen: Instant,
    hits: u64,
    distinct_ips: Vec<IpAddr>,
}

#[derive(Debug, Clone, Default)]
pub struct AutoBanSnapshot {
    pub active_ip_bans: usize,
    pub active_fp_bans: usize,
    pub total_auto_bans: u64,
    pub total_ban_drops: u64,
    pub active_bans: Vec<ActiveBanInfo>,
}

/// Lock-free, strictly memory-bounded automatic IP and fingerprint ban engine.
///
/// Design goals:
/// 1. Only ban AFTER attack behavior is confirmed (avoiding false-positive lockouts on a single probe).
/// 2. Drop banned IPs at TCP accept (O(1) DashMap lookup, zero TLS handshake / WAF / AbuseIPDB cost).
/// 3. Ban attacker fingerprints (verified JS FP + attacker-exclusive composite TLS+UA FP) while
///    explicitly protecting fingerprints seen on legitimate benign traffic so shared browsers / SDKs
///    are never collateral-damaged.
pub struct AutoBanManager {
    enabled: AtomicBool,
    ban_fingerprints: AtomicBool,
    drop_at_tcp: AtomicBool,
    ban_ttl_secs: AtomicU64,
    max_ban_ttl_secs: AtomicU64,
    confirm_hits: AtomicU32,

    banned_ips: DashMap<IpAddr, BanEntry>,
    banned_js_fps: DashMap<String, BanEntry>,
    banned_composite_fps: DashMap<String, BanEntry>,

    offenses: DashMap<IpAddr, OffenseTrackerEntry>,
    escalation_history: DashMap<IpAddr, (Instant, u8)>,
    benign_composite_fps: DashMap<String, BenignFpEntry>,
    benign_js_fps: DashMap<String, BenignFpEntry>,

    total_auto_bans: AtomicU64,
    total_ban_drops: AtomicU64,
}

impl AutoBanManager {
    pub fn new(cfg: &AutoBanConfig) -> Self {
        let mgr = Self {
            enabled: AtomicBool::new(cfg.enabled),
            ban_fingerprints: AtomicBool::new(cfg.ban_fingerprints),
            drop_at_tcp: AtomicBool::new(cfg.drop_at_tcp),
            ban_ttl_secs: AtomicU64::new(cfg.ban_ttl_secs.clamp(60, 86_400)),
            max_ban_ttl_secs: AtomicU64::new(
                cfg.max_ban_ttl_secs
                    .max(cfg.ban_ttl_secs)
                    .clamp(60, 7 * 86_400),
            ),
            confirm_hits: AtomicU32::new(cfg.confirm_hits.clamp(1, 50)),
            banned_ips: DashMap::new(),
            banned_js_fps: DashMap::new(),
            banned_composite_fps: DashMap::new(),
            offenses: DashMap::new(),
            escalation_history: DashMap::new(),
            benign_composite_fps: DashMap::new(),
            benign_js_fps: DashMap::new(),
            total_auto_bans: AtomicU64::new(0),
            total_ban_drops: AtomicU64::new(0),
        };
        mgr
    }

    pub fn reconfigure(&self, cfg: &AutoBanConfig) {
        self.enabled.store(cfg.enabled, Ordering::Relaxed);
        self.ban_fingerprints
            .store(cfg.ban_fingerprints, Ordering::Relaxed);
        self.drop_at_tcp.store(cfg.drop_at_tcp, Ordering::Relaxed);
        let base_ttl = cfg.ban_ttl_secs.clamp(60, 86_400);
        let max_ttl = cfg.max_ban_ttl_secs.max(base_ttl).clamp(60, 7 * 86_400);
        self.ban_ttl_secs.store(base_ttl, Ordering::Relaxed);
        self.max_ban_ttl_secs.store(max_ttl, Ordering::Relaxed);
        self.confirm_hits
            .store(cfg.confirm_hits.clamp(1, 50), Ordering::Relaxed);
        if !cfg.enabled {
            self.banned_ips.clear();
            self.banned_js_fps.clear();
            self.banned_composite_fps.clear();
            self.offenses.clear();
        }
    }

    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Ultra-fast O(1) check called at TCP `accept()` before TLS handshake or task spawn.
    #[inline]
    pub fn is_ip_banned_for_tcp(&self, ip: IpAddr) -> bool {
        if !self.enabled.load(Ordering::Relaxed) || !self.drop_at_tcp.load(Ordering::Relaxed) {
            return false;
        }
        let canon = canonical_ip(ip);
        let now = Instant::now();
        let expired = match self.banned_ips.get(&canon) {
            Some(entry) => {
                if now < entry.expires_at {
                    entry.hits_blocked.fetch_add(1, Ordering::Relaxed);
                    self.total_ban_drops.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
                true
            }
            None => false,
        };
        if expired {
            self.banned_ips
                .remove_if(&canon, |_, e| now >= e.expires_at);
        }
        false
    }

    /// Check whether a request matches an active IP, verified JS FP, or composite TLS+UA FP ban.
    pub fn check_request(
        &self,
        ip: IpAddr,
        tls_ja3: Option<&str>,
        ua: &str,
        js_fp_hash: Option<&str>,
    ) -> Option<BanMatch> {
        if !self.enabled.load(Ordering::Relaxed) {
            return None;
        }
        let canon = canonical_ip(ip);
        let now = Instant::now();

        // 1. Exact IP ban
        if let Some(m) = self.check_map_ip(&canon, now) {
            return Some(m);
        }

        if !self.ban_fingerprints.load(Ordering::Relaxed) {
            return None;
        }

        // 2. Verified JS fingerprint ban (high-entropy device hash; catches rotating IPs)
        if let Some(js_h) = js_fp_hash.filter(|s| !s.is_empty()) {
            if let Some(m) =
                self.check_map_str(&self.banned_js_fps, BanKind::JsFingerprint, js_h, now)
            {
                return Some(m);
            }
        }

        // 3. Attacker-exclusive composite TLS+UA fingerprint ban (catches rotating botnet/tool IPs)
        if let Some(comp) = build_composite_fp(tls_ja3, ua) {
            if let Some(m) = self.check_map_str(
                &self.banned_composite_fps,
                BanKind::CompositeFingerprint,
                &comp,
                now,
            ) {
                return Some(m);
            }
        }

        None
    }

    fn check_map_ip(&self, ip: &IpAddr, now: Instant) -> Option<BanMatch> {
        let mut expired = false;
        let hit = if let Some(entry) = self.banned_ips.get(ip) {
            if now < entry.expires_at {
                entry.hits_blocked.fetch_add(1, Ordering::Relaxed);
                self.total_ban_drops.fetch_add(1, Ordering::Relaxed);
                Some(BanMatch {
                    kind: BanKind::Ip,
                    target: ip.to_string(),
                    reason: entry.reason.clone(),
                    remaining_secs: entry.expires_at.saturating_duration_since(now).as_secs(),
                })
            } else {
                expired = true;
                None
            }
        } else {
            None
        };
        if expired {
            self.banned_ips.remove_if(ip, |_, e| now >= e.expires_at);
        }
        hit
    }

    fn check_map_str(
        &self,
        map: &DashMap<String, BanEntry>,
        kind: BanKind,
        key: &str,
        now: Instant,
    ) -> Option<BanMatch> {
        let mut expired = false;
        let hit = if let Some(entry) = map.get(key) {
            if now < entry.expires_at {
                entry.hits_blocked.fetch_add(1, Ordering::Relaxed);
                self.total_ban_drops.fetch_add(1, Ordering::Relaxed);
                Some(BanMatch {
                    kind,
                    target: key.to_string(),
                    reason: entry.reason.clone(),
                    remaining_secs: entry.expires_at.saturating_duration_since(now).as_secs(),
                })
            } else {
                expired = true;
                None
            }
        } else {
            None
        };
        if expired {
            map.remove_if(key, |_, e| now >= e.expires_at);
        }
        hit
    }

    fn record_benign_fp_entry(
        map: &DashMap<String, BenignFpEntry>,
        key: String,
        canon_ip: IpAddr,
        now: Instant,
    ) {
        if map.len() >= MAX_BENIGN_FPS && !map.contains_key(&key) {
            map.retain(|_, v| now.duration_since(v.last_seen) < BENIGN_FP_IDLE_TTL);
            if map.len() >= MAX_BENIGN_FPS {
                evict_oldest_benign_half(map);
            }
        }
        let mut entry = map.entry(key).or_insert_with(|| BenignFpEntry {
            last_seen: now,
            hits: 0,
            distinct_ips: Vec::new(),
        });
        entry.last_seen = now;
        entry.hits = entry.hits.saturating_add(1);
        if entry.distinct_ips.len() < 8 && !entry.distinct_ips.contains(&canon_ip) {
            entry.distinct_ips.push(canon_ip);
        }
    }

    fn is_fp_shared_benign(
        map: &DashMap<String, BenignFpEntry>,
        key: &str,
        attacker_ip: IpAddr,
        min_other_ips: usize,
    ) -> bool {
        let Some(entry) = map.get(key) else {
            return false;
        };
        if Instant::now().duration_since(entry.last_seen) >= BENIGN_FP_IDLE_TTL {
            return false;
        }
        // Require at least `min_other_ips` distinct benign IPs (different from the attacker)
        // so a single attacker IP can NEVER self-seed benign immunity for its own fingerprint.
        let other_ips = entry
            .distinct_ips
            .iter()
            .filter(|ip| **ip != attacker_ip)
            .count();
        other_ips >= min_other_ips
    }

    /// Record a clean, legitimate request so popular shared browser/SDK TLS+UA and JS fingerprints
    /// are protected from ever being auto-banned globally.
    pub fn record_benign_request_with_js_fp(
        &self,
        ip: IpAddr,
        tls_ja3: Option<&str>,
        ua: &str,
        js_fp_hash: Option<&str>,
    ) {
        if !self.enabled.load(Ordering::Relaxed) || !self.ban_fingerprints.load(Ordering::Relaxed) {
            return;
        }
        let canon = canonical_ip(ip);
        let now = Instant::now();
        if let Some(comp) = build_composite_fp(tls_ja3, ua) {
            Self::record_benign_fp_entry(&self.benign_composite_fps, comp, canon, now);
        }
        if let Some(js_h) = js_fp_hash.map(str::trim).filter(|s| !s.is_empty()) {
            Self::record_benign_fp_entry(&self.benign_js_fps, js_h.to_string(), canon, now);
        }
    }

    pub fn record_benign_request(&self, ip: IpAddr, tls_ja3: Option<&str>, ua: &str) {
        self.record_benign_request_with_js_fp(ip, tls_ja3, ua, None);
    }

    fn is_composite_fp_shared_benign(&self, comp: &str, attacker_ip: IpAddr) -> bool {
        Self::is_fp_shared_benign(&self.benign_composite_fps, comp, attacker_ip, 1)
    }

    fn is_js_fp_shared_benign(&self, js_h: &str, attacker_ip: IpAddr) -> bool {
        Self::is_fp_shared_benign(&self.benign_js_fps, js_h, attacker_ip, 2)
    }

    /// Record an observed attack/abuse offense and auto-ban IP + safe fingerprints once confirmed.
    pub fn record_offense(&self, ctx: OffenseContext<'_>) -> OffenseOutcome {
        let mut outcome = OffenseOutcome::default();
        if !self.enabled.load(Ordering::Relaxed) {
            return outcome;
        }

        let ip = canonical_ip(ctx.client_ip);
        let now = Instant::now();
        let confirm_threshold = self.confirm_hits.load(Ordering::Relaxed).max(1);

        let confirmed = match ctx.kind {
            OffenseKind::VerifiedExploit | OffenseKind::EvilpotFlood => true,
            OffenseKind::MultiStepExploitation { trapped_requests } => {
                // Confirm after at least 2 multi-step interactions (or earlier if threshold is 1)
                trapped_requests >= 2.min(confirm_threshold as u64)
            }
            OffenseKind::AttackScannerProbe => {
                self.add_offense_points(ip, 2, now) >= confirm_threshold
            }
            OffenseKind::WafAttackProbe | OffenseKind::HeadlessOrVerifyAbuse => {
                self.add_offense_points(ip, 1, now) >= confirm_threshold
            }
        };

        if !confirmed {
            return outcome;
        }

        // Compute escalating ban TTL for repeat offenders
        let level = self.next_escalation_level(ip, now);
        let base_ttl = self.ban_ttl_secs.load(Ordering::Relaxed).max(60);
        let max_ttl = self.max_ban_ttl_secs.load(Ordering::Relaxed).max(base_ttl);
        let shift = (level.saturating_sub(1)).min(6) as u32;
        let ttl_secs = base_ttl.saturating_mul(1u64 << shift).min(max_ttl);

        let now_unix = now_unix_secs();
        let expires_at = now + Duration::from_secs(ttl_secs);
        let expires_at_unix = now_unix.saturating_add(ttl_secs);
        let reason = clean_reason(ctx.reason);
        let service_tag = clean_opt_meta(ctx.service_tag, 64);
        let host = clean_opt_meta(ctx.host, 128);

        // 1. Ban exact attacker IP
        self.prune_if_needed(&self.banned_ips, MAX_BANNED_IPS, now);
        let ip_already_banned = self
            .banned_ips
            .get(&ip)
            .map(|e| now < e.expires_at)
            .unwrap_or(false);
        let ip_entry = BanEntry {
            reason: reason.clone(),
            service_tag: service_tag.clone(),
            host: host.clone(),
            banned_at_unix: now_unix,
            expires_at,
            expires_at_unix,
            offense_level: level,
            hits_blocked: AtomicU64::new(0),
        };
        outcome.created_bans.push(ban_entry_to_record(
            "",
            BanKind::Ip,
            ip.to_string(),
            &ip_entry,
        ));
        self.banned_ips.insert(ip, ip_entry);
        self.offenses.remove(&ip);
        if !ip_already_banned {
            outcome.newly_banned_ip = true;
            self.total_auto_bans.fetch_add(1, Ordering::Relaxed);
        }
        outcome.ban_ttl_secs = ttl_secs;
        outcome.offense_level = level;

        // 2. Ban attacker fingerprints (strictly safeguarding benign shared fingerprints)
        if self.ban_fingerprints.load(Ordering::Relaxed) {
            if let Some(js_h) = ctx.js_fp_hash.filter(|s| !s.is_empty()) {
                if !self.is_js_fp_shared_benign(js_h, ip) {
                    self.prune_if_needed(&self.banned_js_fps, MAX_BANNED_FPS, now);
                    let already = self
                        .banned_js_fps
                        .get(js_h)
                        .map(|e| now < e.expires_at)
                        .unwrap_or(false);
                    let js_entry = BanEntry {
                        reason: reason.clone(),
                        service_tag: service_tag.clone(),
                        host: host.clone(),
                        banned_at_unix: now_unix,
                        expires_at,
                        expires_at_unix,
                        offense_level: level,
                        hits_blocked: AtomicU64::new(0),
                    };
                    outcome.created_bans.push(ban_entry_to_record(
                        "",
                        BanKind::JsFingerprint,
                        js_h.to_string(),
                        &js_entry,
                    ));
                    self.banned_js_fps.insert(js_h.to_string(), js_entry);
                    if !already {
                        outcome.newly_banned_js_fp = true;
                        self.total_auto_bans.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }

            if let Some(comp) = build_composite_fp(ctx.tls_ja3, ctx.user_agent) {
                if !self.is_composite_fp_shared_benign(&comp, ip) {
                    self.prune_if_needed(&self.banned_composite_fps, MAX_BANNED_FPS, now);
                    let already = self
                        .banned_composite_fps
                        .get(&comp)
                        .map(|e| now < e.expires_at)
                        .unwrap_or(false);
                    let comp_entry = BanEntry {
                        reason,
                        service_tag,
                        host,
                        banned_at_unix: now_unix,
                        expires_at,
                        expires_at_unix,
                        offense_level: level,
                        hits_blocked: AtomicU64::new(0),
                    };
                    outcome.created_bans.push(ban_entry_to_record(
                        "",
                        BanKind::CompositeFingerprint,
                        comp.clone(),
                        &comp_entry,
                    ));
                    self.banned_composite_fps.insert(comp, comp_entry);
                    if !already {
                        outcome.newly_banned_composite_fp = true;
                        self.total_auto_bans.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }

        outcome
    }

    fn add_offense_points(&self, ip: IpAddr, delta: u32, now: Instant) -> u32 {
        if self.offenses.len() >= MAX_OFFENSE_ENTRIES && !self.offenses.contains_key(&ip) {
            self.offenses
                .retain(|_, v| now.duration_since(v.window_start) < OFFENSE_WINDOW);
            if self.offenses.len() >= MAX_OFFENSE_ENTRIES {
                evict_half(&self.offenses);
            }
        }
        let mut entry = self.offenses.entry(ip).or_insert(OffenseTrackerEntry {
            window_start: now,
            points: 0,
        });
        if now.duration_since(entry.window_start) >= OFFENSE_WINDOW {
            entry.window_start = now;
            entry.points = delta;
        } else {
            entry.points = entry.points.saturating_add(delta);
        }
        entry.points
    }

    fn next_escalation_level(&self, ip: IpAddr, now: Instant) -> u8 {
        if self.escalation_history.len() >= MAX_OFFENSE_ENTRIES
            && !self.escalation_history.contains_key(&ip)
        {
            self.escalation_history
                .retain(|_, (ts, _)| now.duration_since(*ts) < ESCALATION_MEMORY);
            if self.escalation_history.len() >= MAX_OFFENSE_ENTRIES {
                evict_half(&self.escalation_history);
            }
        }
        let mut entry = self.escalation_history.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) >= ESCALATION_MEMORY {
            *entry = (now, 1);
            1
        } else {
            entry.0 = now;
            entry.1 = entry.1.saturating_add(1).min(8);
            entry.1
        }
    }

    fn prune_if_needed<K>(&self, map: &DashMap<K, BanEntry>, max_entries: usize, now: Instant)
    where
        K: Eq + std::hash::Hash,
    {
        if map.len() >= max_entries {
            map.retain(|_, e| now < e.expires_at);
            if map.len() >= max_entries {
                evict_half(map);
            }
        }
    }

    /// Manually unban an IP, JS fingerprint, composite TLS+UA fingerprint, or `"all"`.
    /// Also resets accumulated offense points & escalation history for an unbanned IP so a
    /// cleared legitimate user does not immediately inherit escalated TTLs.
    pub fn unban(&self, kind: &str, target: &str) -> bool {
        let t = target.trim();
        match kind.trim().to_ascii_lowercase().as_str() {
            "ip" => {
                let Ok(ip) = t.parse::<IpAddr>() else {
                    return false;
                };
                let canon = canonical_ip(ip);
                let removed_ban = self.banned_ips.remove(&canon).is_some();
                let removed_off = self.offenses.remove(&canon).is_some();
                self.escalation_history.remove(&canon);
                removed_ban || removed_off
            }
            "js_fp" => !t.is_empty() && self.banned_js_fps.remove(t).is_some(),
            "composite_fp" => !t.is_empty() && self.banned_composite_fps.remove(t).is_some(),
            "all" => {
                let had_any = !self.banned_ips.is_empty()
                    || !self.banned_js_fps.is_empty()
                    || !self.banned_composite_fps.is_empty()
                    || !self.offenses.is_empty();
                self.banned_ips.clear();
                self.banned_js_fps.clear();
                self.banned_composite_fps.clear();
                self.offenses.clear();
                self.escalation_history.clear();
                had_any
            }
            _ => false,
        }
    }

    pub fn snapshot(&self) -> AutoBanSnapshot {
        let now = Instant::now();
        self.banned_ips.retain(|_, e| now < e.expires_at);
        self.banned_js_fps.retain(|_, e| now < e.expires_at);
        self.banned_composite_fps.retain(|_, e| now < e.expires_at);

        let active_ip_bans = self.banned_ips.len();
        let active_fp_bans = self.banned_js_fps.len() + self.banned_composite_fps.len();

        let mut list: Vec<ActiveBanInfo> = Vec::new();
        for e in self.banned_ips.iter() {
            list.push(ActiveBanInfo {
                kind: BanKind::Ip.as_str().to_string(),
                target: e.key().to_string(),
                reason: e.value().reason.clone(),
                banned_at_unix: e.value().banned_at_unix,
                expires_at_unix: e.value().expires_at_unix,
                offense_level: e.value().offense_level,
                hits_blocked: e.value().hits_blocked.load(Ordering::Relaxed),
            });
        }
        for e in self.banned_js_fps.iter() {
            list.push(ActiveBanInfo {
                kind: BanKind::JsFingerprint.as_str().to_string(),
                target: e.key().clone(),
                reason: e.value().reason.clone(),
                banned_at_unix: e.value().banned_at_unix,
                expires_at_unix: e.value().expires_at_unix,
                offense_level: e.value().offense_level,
                hits_blocked: e.value().hits_blocked.load(Ordering::Relaxed),
            });
        }
        for e in self.banned_composite_fps.iter() {
            list.push(ActiveBanInfo {
                kind: BanKind::CompositeFingerprint.as_str().to_string(),
                target: e.key().clone(),
                reason: e.value().reason.clone(),
                banned_at_unix: e.value().banned_at_unix,
                expires_at_unix: e.value().expires_at_unix,
                offense_level: e.value().offense_level,
                hits_blocked: e.value().hits_blocked.load(Ordering::Relaxed),
            });
        }
        list.sort_by(|a, b| {
            b.hits_blocked
                .cmp(&a.hits_blocked)
                .then_with(|| b.banned_at_unix.cmp(&a.banned_at_unix))
        });
        list.truncate(MAX_REPORT_BANS);

        AutoBanSnapshot {
            active_ip_bans,
            active_fp_bans,
            total_auto_bans: self.total_auto_bans.load(Ordering::Relaxed),
            total_ban_drops: self.total_ban_drops.load(Ordering::Relaxed),
            active_bans: list,
        }
    }

    pub fn active_ban_records(&self, node_tag: &str) -> Vec<BanRecord> {
        let now = Instant::now();
        self.banned_ips.retain(|_, e| now < e.expires_at);
        self.banned_js_fps.retain(|_, e| now < e.expires_at);
        self.banned_composite_fps.retain(|_, e| now < e.expires_at);

        let mut out = Vec::with_capacity(
            self.banned_ips.len() + self.banned_js_fps.len() + self.banned_composite_fps.len(),
        );
        for e in self.banned_ips.iter() {
            out.push(ban_entry_to_record(
                node_tag,
                BanKind::Ip,
                e.key().to_string(),
                e.value(),
            ));
        }
        for e in self.banned_js_fps.iter() {
            out.push(ban_entry_to_record(
                node_tag,
                BanKind::JsFingerprint,
                e.key().clone(),
                e.value(),
            ));
        }
        for e in self.banned_composite_fps.iter() {
            out.push(ban_entry_to_record(
                node_tag,
                BanKind::CompositeFingerprint,
                e.key().clone(),
                e.value(),
            ));
        }
        out
    }

    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let state = PersistedBanState {
            total_auto_bans: self.total_auto_bans.load(Ordering::Relaxed),
            total_ban_drops: self.total_ban_drops.load(Ordering::Relaxed),
            bans: self.active_ban_records(""),
        };
        write_json_snapshot_atomic(path, &state)
    }

    pub fn load_from_file(&self, path: &Path) -> Result<usize> {
        let Some(state) = read_json_snapshot::<PersistedBanState>(path)? else {
            return Ok(0);
        };
        if state.total_auto_bans > 0 {
            self.total_auto_bans
                .fetch_max(state.total_auto_bans, Ordering::Relaxed);
        }
        if state.total_ban_drops > 0 {
            self.total_ban_drops
                .fetch_max(state.total_ban_drops, Ordering::Relaxed);
        }
        let now = Instant::now();
        let now_unix = now_unix_secs();
        let mut loaded = 0usize;
        for b in state.bans {
            if b.expires_at_unix <= now_unix {
                continue;
            }
            let remaining_secs = (b.expires_at_unix - now_unix).min(7 * 86_400);
            let entry = BanEntry {
                reason: clean_reason(&b.reason),
                service_tag: b.service_tag,
                host: b.host,
                banned_at_unix: b.banned_at_unix,
                expires_at: now + Duration::from_secs(remaining_secs),
                expires_at_unix: b.expires_at_unix,
                offense_level: b.offense_level.max(1),
                hits_blocked: AtomicU64::new(b.hits_blocked),
            };
            match b.kind.as_str() {
                "ip" => {
                    if let Ok(ip) = b.target.parse::<IpAddr>() {
                        self.banned_ips.insert(canonical_ip(ip), entry);
                        loaded += 1;
                    }
                }
                "js_fp" if !b.target.is_empty() => {
                    self.banned_js_fps.insert(b.target, entry);
                    loaded += 1;
                }
                "composite_fp" if !b.target.is_empty() => {
                    self.banned_composite_fps.insert(b.target, entry);
                    loaded += 1;
                }
                _ => {}
            }
        }
        Ok(loaded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirms_before_banning_and_protects_benign_shared_fingerprints() {
        let mgr = AutoBanManager::new(&AutoBanConfig {
            enabled: true,
            ban_ttl_secs: 600,
            max_ban_ttl_secs: 7200,
            confirm_hits: 3,
            ban_fingerprints: true,
            drop_at_tcp: true,
        });

        let normal_ip: IpAddr = "198.51.100.10".parse().unwrap();
        let attacker_ip: IpAddr = "198.51.100.99".parse().unwrap();
        let rotated_ip: IpAddr = "203.0.113.50".parse().unwrap();
        let chrome_ja3 = "aabbccddeeff001122334455";
        let chrome_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0.0.0 Safari/537.36";

        // 1. Legitimate Chrome user establishes benign composite fingerprint
        mgr.record_benign_request(normal_ip, Some(chrome_ja3), chrome_ua);

        // 2. Single WAF probe does NOT ban immediately (lets Evilpot waste attacker's time first)
        let o1 = mgr.record_offense(OffenseContext {
            client_ip: attacker_ip,
            tls_ja3: Some(chrome_ja3),
            user_agent: chrome_ua,
            js_fp_hash: Some("jsfp-attacker-1"),
            service_tag: None,
            host: None,
            kind: OffenseKind::WafAttackProbe,
            reason: "waf:sqli",
        });
        assert!(!o1.any_banned());
        assert!(!mgr.is_ip_banned_for_tcp(attacker_ip));

        // 3. VerifiedExploit (e.g. canary replay) immediately bans IP + JS FP,
        //    but MUST NOT ban the shared Chrome TLS+UA composite fingerprint!
        let o2 = mgr.record_offense(OffenseContext {
            client_ip: attacker_ip,
            tls_ja3: Some(chrome_ja3),
            user_agent: chrome_ua,
            js_fp_hash: Some("jsfp-attacker-1"),
            service_tag: None,
            host: None,
            kind: OffenseKind::VerifiedExploit,
            reason: "evilpot:verified_exploit:canary",
        });
        assert!(o2.newly_banned_ip);
        assert!(o2.newly_banned_js_fp);
        assert!(
            !o2.newly_banned_composite_fp,
            "shared benign Chrome TLS+UA must not be globally banned"
        );

        // Attacker IP is now dropped at TCP & HTTP
        assert!(mgr.is_ip_banned_for_tcp(attacker_ip));
        assert!(
            mgr.check_request(attacker_ip, Some(chrome_ja3), chrome_ua, None)
                .is_some()
        );

        // Normal Chrome user is 100% unaffected!
        assert!(!mgr.is_ip_banned_for_tcp(normal_ip));
        assert!(
            mgr.check_request(
                normal_ip,
                Some(chrome_ja3),
                chrome_ua,
                Some("jsfp-normal-user")
            )
            .is_none()
        );

        // Attacker rotating to a new IP with same JS FP is STILL blocked!
        let js_hit = mgr
            .check_request(
                rotated_ip,
                Some(chrome_ja3),
                chrome_ua,
                Some("jsfp-attacker-1"),
            )
            .expect("banned JS fingerprint must catch rotated IP");
        assert_eq!(js_hit.kind, BanKind::JsFingerprint);

        // 4. Custom exploit tool (never seen cleanly) rotating IPs IS banned by composite TLS+UA FP!
        let bot_ip1: IpAddr = "203.0.113.71".parse().unwrap();
        let bot_ip2: IpAddr = "203.0.113.72".parse().unwrap();
        let bot_ja3 = "deadbeefcafebabe00112233";
        let bot_ua = "CustomExploitBot/2.1";
        let ob = mgr.record_offense(OffenseContext {
            client_ip: bot_ip1,
            tls_ja3: Some(bot_ja3),
            user_agent: bot_ua,
            js_fp_hash: None,
            service_tag: None,
            host: None,
            kind: OffenseKind::VerifiedExploit,
            reason: "evilpot:verified_exploit:rce",
        });
        assert!(ob.newly_banned_ip);
        assert!(ob.newly_banned_composite_fp);

        let comp_hit = mgr
            .check_request(bot_ip2, Some(bot_ja3), bot_ua, None)
            .expect("attacker-exclusive composite TLS+UA FP must catch rotating bot IP");
        assert_eq!(comp_hit.kind, BanKind::CompositeFingerprint);

        let snap = mgr.snapshot();
        assert_eq!(snap.active_ip_bans, 2);
        assert_eq!(snap.active_fp_bans, 2);
        assert!(snap.total_ban_drops >= 3);
    }

    #[test]
    fn escalating_ttl_grows_for_repeat_offenders() {
        let mgr = AutoBanManager::new(&AutoBanConfig {
            enabled: true,
            ban_ttl_secs: 300,
            max_ban_ttl_secs: 2400,
            confirm_hits: 2,
            ban_fingerprints: false,
            drop_at_tcp: true,
        });
        let ip: IpAddr = "198.51.100.22".parse().unwrap();
        let o1 = mgr.record_offense(OffenseContext {
            client_ip: ip,
            tls_ja3: None,
            user_agent: "scanner",
            js_fp_hash: None,
            service_tag: None,
            host: None,
            kind: OffenseKind::VerifiedExploit,
            reason: "rce",
        });
        assert_eq!(o1.offense_level, 1);
        assert_eq!(o1.ban_ttl_secs, 300);

        let o2 = mgr.record_offense(OffenseContext {
            client_ip: ip,
            tls_ja3: None,
            user_agent: "scanner",
            js_fp_hash: None,
            service_tag: None,
            host: None,
            kind: OffenseKind::VerifiedExploit,
            reason: "rce-again",
        });
        assert_eq!(o2.offense_level, 2);
        assert_eq!(o2.ban_ttl_secs, 600);
    }

    #[test]
    fn unban_removes_ip_js_fp_composite_and_resets_escalation() {
        let mgr = AutoBanManager::new(&AutoBanConfig {
            enabled: true,
            ban_ttl_secs: 300,
            max_ban_ttl_secs: 2400,
            confirm_hits: 2,
            ban_fingerprints: true,
            drop_at_tcp: true,
        });
        let ip: IpAddr = "198.51.100.44".parse().unwrap();
        let o1 = mgr.record_offense(OffenseContext {
            client_ip: ip,
            tls_ja3: Some("ja3bad"),
            user_agent: "BadBot/1.0",
            js_fp_hash: Some("jsfpdeadbeef"),
            service_tag: None,
            host: None,
            kind: OffenseKind::VerifiedExploit,
            reason: "rce",
        });
        assert!(o1.newly_banned_ip);
        assert!(o1.newly_banned_js_fp);
        assert!(o1.newly_banned_composite_fp);
        assert!(mgr.is_ip_banned_for_tcp(ip));
        assert!(mgr.unban("ip", "::ffff:198.51.100.44"));
        assert!(!mgr.is_ip_banned_for_tcp(ip));

        // Next offense starts back at level 1 (escalation history was reset)
        let o2 = mgr.record_offense(OffenseContext {
            client_ip: ip,
            tls_ja3: None,
            user_agent: "BadBot/1.0",
            js_fp_hash: None,
            service_tag: None,
            host: None,
            kind: OffenseKind::VerifiedExploit,
            reason: "rce-2",
        });
        assert_eq!(o2.offense_level, 1);

        assert!(mgr.unban("js_fp", "jsfpdeadbeef"));
        assert!(
            mgr.check_request(
                "198.51.100.99".parse().unwrap(),
                None,
                "Mozilla",
                Some("jsfpdeadbeef")
            )
            .is_none()
        );

        let snap = mgr.snapshot();
        let comp_target = snap
            .active_bans
            .iter()
            .find(|b| b.kind == "composite_fp")
            .map(|b| b.target.clone())
            .expect("composite ban present");
        assert!(mgr.unban("composite_fp", &comp_target));
        assert!(mgr.unban("all", "*"));
        assert_eq!(mgr.snapshot().active_bans.len(), 0);
    }

    #[test]
    fn single_attacker_cannot_self_seed_immunity_and_shared_js_fp_is_protected() {
        let mgr = AutoBanManager::new(&AutoBanConfig {
            enabled: true,
            ban_ttl_secs: 600,
            max_ban_ttl_secs: 3600,
            confirm_hits: 2,
            ban_fingerprints: true,
            drop_at_tcp: true,
        });
        let attacker: IpAddr = "198.51.100.200".parse().unwrap();
        let ja3 = "cafebabe00112233";
        let ua = "CustomAttackerUA/1.0";

        // Same IP sends 10 benign hits first — must NOT immunize its composite FP against itself
        for _ in 0..10 {
            mgr.record_benign_request(attacker, Some(ja3), ua);
        }
        let o1 = mgr.record_offense(OffenseContext {
            client_ip: attacker,
            tls_ja3: Some(ja3),
            user_agent: ua,
            js_fp_hash: None,
            service_tag: None,
            host: None,
            kind: OffenseKind::VerifiedExploit,
            reason: "rce",
        });
        assert!(o1.newly_banned_ip);
        assert!(o1.newly_banned_composite_fp);

        // Popular shared JS FP across >= 2 distinct legitimate IPs is protected from global FP ban
        let benign_a: IpAddr = "203.0.113.10".parse().unwrap();
        let benign_b: IpAddr = "203.0.113.11".parse().unwrap();
        mgr.record_benign_request_with_js_fp(benign_a, None, "Chrome", Some("shared-js-fp"));
        mgr.record_benign_request_with_js_fp(benign_b, None, "Chrome", Some("shared-js-fp"));
        let o2 = mgr.record_offense(OffenseContext {
            client_ip: "198.51.100.201".parse().unwrap(),
            tls_ja3: None,
            user_agent: "Chrome",
            js_fp_hash: Some("shared-js-fp"),
            service_tag: None,
            host: None,
            kind: OffenseKind::VerifiedExploit,
            reason: "rce",
        });
        assert!(o2.newly_banned_ip);
        assert!(!o2.newly_banned_js_fp);
    }

    #[test]
    fn persists_active_bans_to_disk_and_reloads_across_restart() {
        let dir = std::env::temp_dir().join(format!("exp-ban-persist-{}", uuid::Uuid::new_v4()));
        let path = dir.join("node-bans-edge1.json");
        let cfg = AutoBanConfig {
            enabled: true,
            ban_ttl_secs: 900,
            max_ban_ttl_secs: 3600,
            confirm_hits: 2,
            ban_fingerprints: true,
            drop_at_tcp: true,
        };
        let mgr1 = AutoBanManager::new(&cfg);
        let attacker: IpAddr = "64.227.75.77".parse().unwrap();
        let out = mgr1.record_offense(OffenseContext {
            client_ip: attacker,
            tls_ja3: Some("deadbeef1234"),
            user_agent: "BadScanner/1.0",
            js_fp_hash: Some("js-evil-1"),
            service_tag: Some("www-static"),
            host: Some("jincaituanwei.com"),
            kind: OffenseKind::VerifiedExploit,
            reason: "evilpot:verified_exploit:rce",
        });
        assert_eq!(out.created_bans.len(), 3);
        assert_eq!(
            out.created_bans[0].service_tag.as_deref(),
            Some("www-static")
        );
        mgr1.save_to_file(&path).unwrap();

        let mgr2 = AutoBanManager::new(&cfg);
        let loaded = mgr2.load_from_file(&path).unwrap();
        assert_eq!(loaded, 3);
        assert!(mgr2.is_ip_banned_for_tcp(attacker));
        let active = mgr2.active_ban_records("edge-1");
        assert_eq!(active.len(), 3);
        assert!(
            active
                .iter()
                .all(|b| b.node_tag == "edge-1" && b.service_tag.as_deref() == Some("www-static"))
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
