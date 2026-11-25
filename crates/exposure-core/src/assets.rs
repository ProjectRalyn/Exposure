#[cfg(debug_assertions)]
use std::path::PathBuf;
use std::path::{Component, Path};
use std::borrow::Cow;

include!(concat!(env!("OUT_DIR"), "/embedded_web.rs"));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebApp {
    Control,
    Challenge,
}

impl WebApp {
    pub fn name(self) -> &'static str {
        match self {
            WebApp::Control => "control",
            WebApp::Challenge => "challenge",
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
        let bytes = std::fs::read(&full).ok()?;
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

/// Inline illustration for the built-in intercept page (line art, colours driven by the
/// `--art-*` custom properties so it follows the light/dark palette without a second asset).
const ERROR_PAGE_ART: &str = include_str!("../assets/error-art.svg");

/// Palette + layout for the built-in intercept page: monospace type, one hairline rule, no card
/// border or shadow — the semi-immersive language of the school portal / SSO pages.
const ERROR_PAGE_CSS: &str = r#"
:root{color-scheme:light dark;--bg:#ffffff;--text:#1a1a1a;--line:#1a1a1a;--muted:#6a6a6a;--soft:#f2f2f2;
--accent:#C40233;--accent-ink:#ffffff;--track:#e4e4e4;--art-ink:#141414;--art-paper:#ffffff;--art-red:#a6222c}
@media (prefers-color-scheme:dark){:root{--bg:#121212;--text:#ededed;--line:#5a5a5a;--muted:#8c8c8c;
--soft:#1e1e1e;--track:#2b2b2b;--art-ink:#ededed;--art-paper:#121212;--art-red:#c8444e}}
/* Status tone: rate limiting is amber, other client errors crimson, server errors oxblood. */
.page.is-429{--accent:#9A6A00;--accent-ink:#ffffff}
.page.is-4xx{--accent:#C40233;--accent-ink:#ffffff}
.page.is-5xx{--accent:#7E0C1A;--accent-ink:#ffffff}
@media (prefers-color-scheme:dark){
.page.is-429{--accent:#DCA93F;--accent-ink:#121212}
.page.is-4xx{--accent:#E4595F;--accent-ink:#121212}
.page.is-5xx{--accent:#B0505A;--accent-ink:#ffffff}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);overflow-x:hidden;
font-family:ui-monospace,"Sarasa Mono SC","Sarasa Term SC","Cascadia Code",Menlo,Consolas,monospace;font-size:14px;line-height:1.5}
.page{position:relative;min-height:100vh;display:flex;align-items:center;padding:64px min(9vw,120px)}
.col{position:relative;z-index:1;width:min(520px,100%)}
.tag{display:inline-block;padding:4px 9px;background:var(--accent);color:var(--accent-ink);
font-size:10px;font-weight:900;letter-spacing:.2em;text-transform:uppercase}
h1{margin:12px 0 0;font-size:clamp(26px,4.6vw,44px);line-height:1.05;font-weight:900;text-transform:uppercase;letter-spacing:.01em}
.rule{height:1px;margin:22px 0 0;background:var(--line);opacity:.5}
.detail{margin:20px 0 0;max-width:42ch;color:var(--muted);font-size:15px;line-height:1.7}
.meta{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px 28px;margin:32px 0 0;padding:0}
.meta div{display:flex;flex-direction:column;gap:3px}
.meta dt{margin:0;font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
.meta dd{margin:0;font-size:13px;font-weight:900;font-variant-numeric:tabular-nums}
.retry{display:flex;align-items:center;gap:14px;margin:26px 0 0}
.retry span{font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);white-space:nowrap}
.retry i{position:relative;flex:1;height:6px;background:var(--track);overflow:hidden}
.retry i::after{content:"";position:absolute;top:0;bottom:0;left:0;background:var(--accent);animation:load var(--d,12s) linear forwards}
@keyframes load{from{width:0}to{width:100%}}
.foot{display:flex;justify-content:space-between;gap:16px;margin:52px 0 0;font-size:10px;letter-spacing:.14em;
text-transform:uppercase;color:var(--muted);opacity:.75}
.art{position:absolute;right:-2vw;bottom:-1%;width:min(44vw,620px);pointer-events:none;user-select:none}
.art svg{display:block;width:100%;height:auto}
@media (max-width:980px){.page{align-items:flex-start;padding:52px 24px 0}.foot{margin-top:36px}
.art{right:-10%;bottom:-4%;width:68vw;opacity:.1}}
@media (prefers-reduced-motion:reduce){.retry i::after{animation:none;width:100%}}
"#;

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

    if let Some(tpl) = template.map(str::trim).filter(|s| !s.is_empty()) {
        let status_str = status.to_string();
        let retry_str = retry_after_secs.map(|s| s.to_string()).unwrap_or_default();
        let escaped_title = escape_html(title);
        let escaped_detail = escape_html(detail);
        let escaped_ray = escape_html(ray_id);
        return fill_template(
            tpl,
            &[
                ("status", status_str.as_str()),
                ("title", escaped_title.as_str()),
                ("detail", escaped_detail.as_str()),
                ("ray_id", escaped_ray.as_str()),
                ("retry_after", retry_str.as_str()),
                ("accent", accent),
                ("retry_note", retry_note.as_str()),
            ],
        );
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="color-scheme" content="light dark"/>
<title>{status} {title}</title>
<style>{css}</style></head>
<body><main class="page {tone}">
<section class="col">
<div class="tag">HTTP {status}</div>
<h1>{title}</h1>
<div class="rule"></div>
<p class="detail">{detail}</p>
{retry_note}
<div class="foot"><span>Exposure Edge</span><span>Ray {ray}</span></div>
</section>
<div class="art">{art}</div>
</main></body></html>"#,
        status = status,
        title = escape_html(title),
        detail = escape_html(detail),
        css = ERROR_PAGE_CSS,
        art = ERROR_PAGE_ART,
        tone = tone,
        retry_note = retry_note,
        ray = escape_html(ray_id),
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
