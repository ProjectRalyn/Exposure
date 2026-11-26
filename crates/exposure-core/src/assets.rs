#[cfg(debug_assertions)]
use std::path::PathBuf;
use std::path::{Component, Path};
use std::borrow::Cow;

include!(concat!(env!("OUT_DIR"), "/embedded_web.rs"));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebApp {
    Control,
    Challenge,
    /// Built-in intercept (403 / 429 / 5xx) page. Assembled as a single self-contained document
    /// by the web build and embedded at compile time.
    Error,
}

impl WebApp {
    pub fn name(self) -> &'static str {
        match self {
            WebApp::Control => "control",
            WebApp::Challenge => "challenge",
            WebApp::Error => "error",
        }
    }
}

pub fn content_type_for_path(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("");
    match ext {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

fn sanitize_rel_path(req_path: &str) -> Option<String> {
    let trimmed = req_path.trim_start_matches('/');
    let rel = if trimmed.is_empty() {
        "index.html"
    } else {
        trimmed
    };
    let p = Path::new(rel);
    for comp in p.components() {
        match comp {
            Component::Normal(_) => {}
            _ => return None,
        }
    }
    Some(rel.to_string())
}

#[cfg(debug_assertions)]
fn resolve_dev_web_dir(app: WebApp) -> PathBuf {
    if let Ok(custom) = std::env::var("EXPOSURE_WEB_DIR") {
        return PathBuf::from(custom).join(app.name());
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|root| root.join("web").join(app.name()))
        .unwrap_or_else(|| PathBuf::from("web").join(app.name()))
}

/// CSP source hash (`sha256-<base64>`) of the script inlined into the built-in page for `app`,
/// when the web build inlined one (release builds). Serving nodes must allow it in `script-src`.
pub fn embedded_page_script_hash(app: &str) -> Option<&'static str> {
    embedded_script_hash(app)
}

/// A static web asset together with the content-coding it is stored in.
///
/// Release builds stage a pre-compressed (`br`/`gzip`) copy of every text asset at build time, so
/// negotiating one is a lookup plus a `memcpy` — no per-request compression work.
pub struct WebAsset {
    pub bytes: Cow<'static, [u8]>,
    pub mime: &'static str,
    /// `Some("br" | "gzip")` when `bytes` is already compressed; the caller must emit
    /// `Content-Encoding` (and `Vary: Accept-Encoding`).
    pub encoding: Option<&'static str>,
}

/// Quality (0..=1) the client assigned to `br` and `gzip`, honouring `q=0` and `*`.
fn coding_quality(accept_encoding: &str) -> (f32, f32) {
    let (mut br, mut gzip, mut star): (Option<f32>, Option<f32>, Option<f32>) = (None, None, None);
    for part in accept_encoding.split(',') {
        let mut params = part.split(';');
        let coding = params.next().unwrap_or("").trim();
        if coding.is_empty() {
            continue;
        }
        let mut q = 1.0f32;
        for p in params {
            if let Some(v) = p.trim().strip_prefix("q=") {
                q = v.trim().parse::<f32>().unwrap_or(0.0);
            }
        }
        if coding.eq_ignore_ascii_case("br") {
            br = Some(q);
        } else if coding.eq_ignore_ascii_case("gzip") || coding.eq_ignore_ascii_case("x-gzip") {
            gzip = Some(q);
        } else if coding == "*" {
            star = Some(q);
        }
    }
    let pick = |explicit: Option<f32>| explicit.or(star).unwrap_or(0.0).max(0.0);
    (pick(br), pick(gzip))
}

/// Best content-coding we can serve for this client: brotli if it beats gzip, else gzip, else none.
pub fn negotiate_encoding(accept_encoding: &str) -> Option<&'static str> {
    let (br, gzip) = coding_quality(accept_encoding);
    if br > 0.0 && br >= gzip {
        Some("br")
    } else if gzip > 0.0 {
        Some("gzip")
    } else {
        None
    }
}

/// Serve a web asset with the best content-coding the client accepts:
/// - In debug mode: reads live source files directly from `web/{control,challenge}/` on disk
///   (always identity — dev traffic is local and nothing is staged at build time).
/// - In release mode: returns the compile-time embedded Vite-minified asset bytes, preferring the
///   pre-compressed `br`/`gzip` variant staged by `build.rs`.
///
/// Returns `None` for unknown paths; path traversal attempts are rejected by `sanitize_rel_path`.
pub fn load_web_asset_negotiated(
    app: WebApp,
    req_path: &str,
    accept_encoding: &str,
) -> Option<WebAsset> {
    let rel = sanitize_rel_path(req_path)?;
    let mime = content_type_for_path(&rel);

    #[cfg(debug_assertions)]
    {
        let _ = accept_encoding;
        let full = resolve_dev_web_dir(app).join(&rel);
        let mut bytes = std::fs::read(&full).ok()?;
        // Page stylesheets import the shared layout skeleton; inline it so the served CSS is
        // already self-contained (see `inline_css_imports`).
        if mime.starts_with("text/css") {
            if let Ok(css) = std::str::from_utf8(&bytes) {
                let resolved = inline_css_imports(css, full.parent().unwrap_or(&full));
                bytes = resolved.into_bytes();
            }
        }
        Some(WebAsset {
            bytes: Cow::Owned(bytes),
            mime,
            encoding: None,
        })
    }

    #[cfg(not(debug_assertions))]
    {
        // Same alias fallbacks as `load_web_asset` (legacy `/cdn-cgi/pow.js` + `styles.css`).
        let served_rel: &str = if get_embedded(app.name(), &rel).is_some() {
            rel.as_str()
        } else if app == WebApp::Challenge {
            match rel.as_str() {
                "pow.js" => "assets/app.min.js",
                "styles.css" => "assets/styles.min.css",
                _ => return None,
            }
        } else {
            return None;
        };
        if let Some(encoding) = negotiate_encoding(accept_encoding) {
            if let Some(bytes) = get_embedded_encoded(app.name(), served_rel, encoding) {
                return Some(WebAsset {
                    bytes: Cow::Borrowed(bytes),
                    mime,
                    encoding: Some(encoding),
                });
            }
        }
        let bytes = get_embedded(app.name(), served_rel)?;
        Some(WebAsset {
            bytes: Cow::Borrowed(bytes),
            mime,
            encoding: None,
        })
    }
}

/// Resolve `@import "relative.css";` inside a stylesheet for debug builds.
///
/// Release builds let Vite (or the esbuild fallback with `--bundle`) inline imports at build
/// time. Debug builds instead splice the raw source CSS into a `<style>` block that is served
/// from an arbitrary Host and path, where a relative `@import` would resolve against the *page*
/// URL — fetching nothing in the best case, or hitting the customer's own backend in the worst.
#[cfg(debug_assertions)]
fn inline_css_imports(css: &str, base_dir: &Path) -> String {
    fn walk(css: &str, dir: &Path, depth: u8, out: &mut String) {
        // Depth cap: `@import` cycles are a config error, not a reason to hang a request.
        if depth > 4 {
            return;
        }
        let mut rest = css;
        while let Some(pos) = rest.find("@import") {
            out.push_str(&rest[..pos]);
            let after = &rest[pos + "@import".len()..];
            let Some(semi) = after.find(';') else {
                out.push_str(&rest[pos..]);
                return;
            };
            let spec = after[..semi].trim();
            let path = spec
                .strip_prefix("url(")
                .map(|s| s.strip_suffix(')').unwrap_or(s))
                .unwrap_or(spec)
                .trim()
                .trim_matches(|c| c == '"' || c == '\'');
            if path.is_empty() || path.contains("://") {
                // Remote imports are never used by the built-in pages; leave them untouched.
                out.push_str(&rest[pos..pos + "@import".len() + semi + 1]);
            } else if let Ok(inner) = std::fs::read_to_string(dir.join(path)) {
                let inner_dir = dir.join(path);
                walk(
                    &inner,
                    inner_dir.parent().unwrap_or(dir),
                    depth + 1,
                    out,
                );
            }
            // A missing target is dropped rather than emitted as a dead request.
            rest = &after[semi + 1..];
        }
        out.push_str(rest);
    }

    let mut out = String::with_capacity(css.len());
    walk(css, base_dir, 0, &mut out);
    out
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Single-pass `{{key}}` substitution that never re-scans substituted values, so user-controlled
/// content cannot inject placeholders that a later replacement would expand into raw markup.
fn fill_template(tpl: &str, pairs: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(tpl.len());
    let mut rest = tpl;
    while let Some(pos) = rest.find("{{") {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 2..];
        let Some(end) = after.find("}}") else {
            out.push_str(&rest[pos..]);
            return out;
        };
        let key = &after[..end];
        if let Some((_, val)) = pairs.iter().find(|(k, _)| *k == key) {
            out.push_str(val);
        } else {
            out.push_str(&rest[pos..pos + 2 + end + 2]);
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

/// Last-resort page used only when the embedded/dev built-in page cannot be read; never reached in
/// a valid release build (the web build embeds `error/index.html`).
const FALLBACK_ERROR_PAGE: &str = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"/><title>{{status}} {{title}}</title></head><body><h1>{{status}} {{title}}</h1><p>{{detail}}</p><p>Ray {{ray_id}}</p></body></html>";

/// Built-in intercept page: one complete document, built from `web/error` by the web toolchain
/// (stylesheet inlined) and embedded at compile time. Debug builds assemble the same document
/// from the live source tree so the page stays editable during development.
fn builtin_error_page() -> Cow<'static, str> {
    #[cfg(not(debug_assertions))]
    {
        if let Some(bytes) = get_embedded("error", "index.html") {
            if let Ok(page) = std::str::from_utf8(bytes) {
                return Cow::Borrowed(page);
            }
        }
    }

    #[cfg(debug_assertions)]
    {
        static DEV_PAGE: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
        if let Some(page) = DEV_PAGE.get_or_init(load_dev_error_page) {
            return Cow::Owned(page.clone());
        }
    }

    Cow::Borrowed(FALLBACK_ERROR_PAGE)
}

/// Dev-mode equivalent of the build-time single-file assembly: `web/error/index.html` with
/// `styles.css` inlined (the page is rendered into responses at arbitrary paths, so a relative
/// stylesheet reference would not resolve).
#[cfg(debug_assertions)]
fn load_dev_error_page() -> Option<String> {
    let dir = resolve_dev_web_dir(WebApp::Error);
    let html = std::fs::read_to_string(dir.join("index.html")).ok()?;
    match std::fs::read_to_string(dir.join("styles.css")) {
        Ok(css) if !css.contains("</style") => {
            let css = inline_css_imports(&css, &dir);
            Some(splice_stylesheet(&html, &css))
        }
        _ => Some(html),
    }
}

/// Replace the `<link rel="stylesheet">` tag with an inline `<style>` block.
#[cfg(debug_assertions)]
fn splice_stylesheet(html: &str, css: &str) -> String {
    let Some(at) = html.find("rel=\"stylesheet\"") else {
        return html.to_string();
    };
    let Some(start) = html[..at].rfind('<') else {
        return html.to_string();
    };
    let Some(close) = html[at..].find('>') else {
        return html.to_string();
    };
    let mut out = String::with_capacity(html.len() + css.len());
    out.push_str(&html[..start]);
    out.push_str("<style>");
    out.push_str(css);
    out.push_str("</style>");
    out.push_str(&html[at + close + 1..]);
    out
}

/// Status tone class for the built-in page: rate limiting (429) is amber, every other client
/// error is crimson, server-side failures are oxblood — so the three families read apart at a
/// glance without a second template.
fn status_tone(status: u16) -> &'static str {
    match status {
        429 => "is-429",
        400..=499 => "is-4xx",
        _ => "is-5xx",
    }
}

/// Light-mode accent hex for a status code; also what custom templates receive in `{{accent}}`.
fn status_accent(status: u16) -> &'static str {
    match status {
        429 => "#9A6A00",
        400..=499 => "#C40233",
        _ => "#7E0C1A",
    }
}

/// Render an error page for 429 / 5xx responses, using a Control-provisioned custom HTML
/// template when configured (with HTML-escaped placeholders) or falling back to the built-in page.
pub fn render_exposure_error_html_with_template(
    template: Option<&str>,
    status: u16,
    title: &str,
    detail: &str,
    ray_id: &str,
    retry_after_secs: Option<u64>,
) -> String {
    let accent = status_accent(status);
    let tone = status_tone(status);
    let retry_note = match retry_after_secs {
        Some(secs) => format!(
            r#"<dl class="meta">
<div><dt>Status</dt><dd>{status}</dd></div>
<div><dt>Retry after</dt><dd>{secs}s</dd></div>
</dl>
<div class="retry"><span>Auto-retry</span><i style="--d:{ms}ms"></i></div>
<script>setTimeout(function(){{location.reload()}},{ms});</script>"#,
            status = status,
            secs = secs,
            ms = secs.saturating_mul(1000).min(60_000)
        ),
        None => format!(
            r#"<dl class="meta">
<div><dt>Status</dt><dd>{status}</dd></div>
<div><dt>Cache</dt><dd>no-store</dd></div>
</dl>"#,
            status = status,
        ),
    };

    // A configured custom page replaces the built-in document wholesale; both are complete
    // single-file documents, and both get the same placeholder substitution.
    let tpl: Cow<'_, str> = match template.map(str::trim).filter(|s| !s.is_empty()) {
        Some(tpl) => Cow::Borrowed(tpl),
        None => builtin_error_page(),
    };
    let status_str = status.to_string();
    let retry_str = retry_after_secs.map(|s| s.to_string()).unwrap_or_default();
    let escaped_title = escape_html(title);
    let escaped_detail = escape_html(detail);
    let escaped_ray = escape_html(ray_id);
    fill_template(
        &tpl,
        &[
            ("status", status_str.as_str()),
            ("title", escaped_title.as_str()),
            ("detail", escaped_detail.as_str()),
            ("ray_id", escaped_ray.as_str()),
            ("retry_after", retry_str.as_str()),
            ("accent", accent),
            ("tone", tone),
            ("retry_note", retry_note.as_str()),
        ],
    )
}

/// Render a generic, zero-leakage error page (with Ray ID) for 429 / 5xx responses when `intercept_errors` is enabled.
pub fn render_exposure_error_html(
    status: u16,
    title: &str,
    detail: &str,
    ray_id: &str,
    retry_after_secs: Option<u64>,
) -> String {
    render_exposure_error_html_with_template(None, status, title, detail, ray_id, retry_after_secs)
}

/// Bodies below this size gain nothing from gzip once the trailer/header overhead is counted.
const COMPRESS_MIN_LEN: usize = 1024;

/// `true` when the client explicitly accepts `gzip` (or `x-gzip`/`*`) and did not set `q=0` on it.
fn accepts_gzip(accept_encoding: &str) -> bool {
    let mut wildcard = false;
    for part in accept_encoding.split(',') {
        let mut params = part.split(';');
        let coding = params.next().unwrap_or("").trim();
        if coding.is_empty() {
            continue;
        }
        // A `q=` parameter of zero means "not acceptable"; anything else keeps it acceptable.
        let mut rejected = false;
        for p in params {
            if let Some(q) = p.trim().strip_prefix("q=") {
                rejected = q.trim().parse::<f32>().map(|v| v <= 0.0).unwrap_or(false);
            }
        }
        if coding.eq_ignore_ascii_case("gzip") || coding.eq_ignore_ascii_case("x-gzip") {
            return !rejected;
        }
        if coding == "*" && !rejected {
            wildcard = true;
        }
    }
    wildcard
}

/// Gzip a locally generated body when the client accepts it.
///
/// The built-in intercept page inlines the SVG illustration (~64 KiB of path data), so this is
/// the biggest egress win on the 429/5xx path (~2.7x). The fastest compressor level is used on
/// purpose: the payload is dominated by highly repetitive path coordinates, which gzip shrinks
/// very close to level 9 even at level 1, while costing a fraction of the CPU — error pages can
/// sit on the hot path during a flood, so this must stay cheap.
///
/// Returns the (possibly compressed) body and the coding that was applied, if any. The caller is
/// responsible for emitting `Content-Encoding` and `Vary: Accept-Encoding` when it is `Some`.
pub fn maybe_gzip_body(body: Vec<u8>, accept_encoding: &str) -> (Vec<u8>, Option<&'static str>) {
    if body.len() < COMPRESS_MIN_LEN || !accepts_gzip(accept_encoding) {
        return (body, None);
    }
    let mut out = Vec::with_capacity(body.len() / 3 + 64);
    {
        let mut encoder = flate2::write::GzEncoder::new(&mut out, flate2::Compression::fast());
        if std::io::Write::write_all(&mut encoder, &body).is_err() || encoder.finish().is_err() {
            // Compression failure must never turn into a failed response: fall back to identity.
            return (body, None);
        }
    }
    if out.len() + 64 >= body.len() {
        return (body, None);
    }
    (out, Some("gzip"))
}

#[cfg(test)]
mod tests {
    use super::render_exposure_error_html_with_template;

    #[test]
    fn builtin_error_page_is_a_complete_single_file_document() {
        let html = super::render_exposure_error_html(429, "Too Many Requests", "slow down", "ray-1", Some(3));
        assert!(html.starts_with("<!DOCTYPE html>"), "not a full document: {html:.80}");
        assert!(html.contains("<style>"), "stylesheet was not inlined");
        assert!(html.contains("class=\"page is-429\""), "tone class missing");
        assert!(
            !html.contains("<link rel=\"stylesheet\""),
            "external stylesheet reference left in the inline page"
        );
        assert!(!html.contains("{{"), "unsubstituted placeholder left: {html:.200}");
        assert!(html.contains("exp") || html.contains("ray-1"));
        // Placeholders are HTML-escaped, and the retry note carries the auto-reload script.
        assert!(html.contains("setTimeout"));
    }

    /// The page stylesheets pull the layout skeleton in through `@import "../shared/page.css"`.
    /// Debug builds splice raw source CSS into the document, so the loader must resolve that
    /// import itself — a leftover `@import` would be fetched relative to the intercepted site.
    #[cfg(debug_assertions)]
    #[test]
    fn dev_builtin_page_inlines_the_shared_stylesheet_import() {
        let html = super::render_exposure_error_html(403, "Forbidden", "nope", "ray-2", None);
        assert!(
            html.contains("grid-template-columns"),
            "shared layout skeleton was not pulled in from web/shared/page.css"
        );
        assert!(
            !html.contains("@import"),
            "unresolved @import would be fetched from the intercepted site's origin"
        );
    }

    #[test]
    fn negotiate_encoding_prefers_brotli_and_honours_q_values() {
        assert_eq!(super::negotiate_encoding("gzip, deflate, br"), Some("br"));
        assert_eq!(super::negotiate_encoding("gzip"), Some("gzip"));
        assert_eq!(super::negotiate_encoding("identity"), None);
        assert_eq!(super::negotiate_encoding(""), None);
        assert_eq!(super::negotiate_encoding("br;q=0, gzip"), Some("gzip"));
        assert_eq!(super::negotiate_encoding("br;q=0.5, gzip;q=0.9"), Some("gzip"));
        assert_eq!(super::negotiate_encoding("*"), Some("br"));
        assert_eq!(super::negotiate_encoding("*;q=0"), None);
    }

    #[test]
    fn asset_lookup_rejects_path_traversal() {
        for p in ["/../Cargo.toml", "/assets/../../secret", "/.."] {
            assert!(
                super::load_web_asset_negotiated(super::WebApp::Challenge, p, "gzip").is_none(),
                "{p} must not resolve"
            );
        }
    }

    #[test]
    fn gzip_body_honours_accept_encoding() {
        let html = format!("<html>{}</html>", "x".repeat(4096));

        let (plain, enc) = super::maybe_gzip_body(html.clone().into_bytes(), "");
        assert!(
            enc.is_none(),
            "identity clients must get uncompressed bytes"
        );
        assert_eq!(plain.len(), html.len());

        let (gz, enc) = super::maybe_gzip_body(html.clone().into_bytes(), "deflate, gzip;q=0.8");
        assert_eq!(enc, Some("gzip"));
        let mut decoded = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&gz[..]), &mut decoded)
            .unwrap();
        assert_eq!(decoded, html.as_bytes());

        let (_, enc) = super::maybe_gzip_body(html.clone().into_bytes(), "gzip;q=0");
        assert!(enc.is_none(), "q=0 must be honoured");

        // Tiny bodies stay identity even when gzip is accepted.
        let (small, enc) = super::maybe_gzip_body(b"ok".to_vec(), "gzip");
        assert!(enc.is_none());
        assert_eq!(small, b"ok");
    }

    #[test]
    fn custom_error_template_substitutes_and_escapes_fields() {
        let tpl = "<html><body><h1>{{status}} {{title}}</h1><p>{{detail}}</p><span>{{ray_id}}</span><div>{{retry_after}}</div></body></html>";
        let rendered = render_exposure_error_html_with_template(
            Some(tpl),
            429,
            "Slow <Down>",
            "Wait & retry",
            "ray<1>",
            Some(12),
        );
        assert!(rendered.contains("<h1>429 Slow &lt;Down&gt;</h1>"));
        assert!(rendered.contains("<p>Wait &amp; retry</p>"));
        assert!(rendered.contains("<span>ray&lt;1&gt;</span>"));
        assert!(rendered.contains("<div>12</div>"));
    }
}
