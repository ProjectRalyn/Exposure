use std::path::{Component, Path};
#[cfg(debug_assertions)]
use std::path::PathBuf;

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

/// Serve a web asset:
/// - In debug mode: reads live source files directly from `web/{control,challenge}/` on disk.
/// - In release mode: returns the compile-time embedded Vite-minified asset bytes.
pub fn load_web_asset(app: WebApp, req_path: &str) -> Option<(Vec<u8>, &'static str)> {
    let rel = sanitize_rel_path(req_path)?;
    let mime = content_type_for_path(&rel);

    #[cfg(debug_assertions)]
    {
        let full = resolve_dev_web_dir(app).join(&rel);
        let bytes = std::fs::read(&full).ok()?;
        Some((bytes, mime))
    }

    #[cfg(not(debug_assertions))]
    {
        let bytes = get_embedded(app.name(), &rel)?;
        Some((bytes.to_vec(), mime))
    }
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Render a generic, zero-leakage error page (with Ray ID) for 429 / 5xx responses when `intercept_errors` is enabled.
pub fn render_exposure_error_html(
    status: u16,
    title: &str,
    detail: &str,
    ray_id: &str,
    retry_after_secs: Option<u64>,
) -> String {
    let accent = if status == 429 { "#FAC800" } else { "#C40233" };
    let retry_note = match retry_after_secs {
        Some(secs) => format!(
            r#"<div class="meta"><span>Retry-After: {secs}s</span><span>Ray ID: {ray}</span></div>
               <script>setTimeout(()=>location.reload(), {ms});</script>"#,
            secs = secs,
            ray = escape_html(ray_id),
            ms = secs.saturating_mul(1000).min(60_000)
        ),
        None => format!(
            r#"<div class="meta"><span>Status: {status}</span><span>Ray ID: {ray}</span></div>"#,
            status = status,
            ray = escape_html(ray_id),
        ),
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{status} {title}</title>
<style>
*{{box-sizing:border-box}}
body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#020617;color:#e2e8f0;font-family:system-ui,-apple-system,sans-serif}}
.card{{width:min(480px,92vw);background:#0f172a;border:1px solid #1e293b;border-top:3px solid {accent};padding:28px}}
.tag{{font-size:11px;letter-spacing:.14em;color:{accent};font-weight:700;text-transform:uppercase;margin-bottom:10px}}
h1{{margin:0 0 8px;font-size:22px;font-weight:700}}
p{{margin:0 0 18px;color:#94a3b8;font-size:14px;line-height:1.55}}
.meta{{display:flex;justify-content:space-between;border-top:1px solid #1e293b;padding-top:12px;font-family:ui-monospace,monospace;font-size:12px;color:#94a3b8}}
</style></head>
<body><main class="card">
<div class="tag">HTTP {status}</div>
<h1>{title}</h1>
<p>{detail}</p>
{retry_note}
</main></body></html>"#,
        status = status,
        title = escape_html(title),
        detail = escape_html(detail),
        accent = accent,
        retry_note = retry_note,
    )
}
