use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn collect_files(base: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) {
    if !dir.exists() {
        return;
    }
    let mut entries: Vec<_> = fs::read_dir(dir)
        .expect("read web dist dir")
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.path());
    for entry in entries {
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            collect_files(base, &path, out);
        } else if meta.is_file() {
            let rel = path
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            out.push((rel, path));
        }
    }
}

fn watch_dir(dir: &Path) {
    if !dir.exists() {
        return;
    }
    println!("cargo:rerun-if-changed={}", dir.display());
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            let Ok(meta) = fs::symlink_metadata(&p) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                if p.file_name().and_then(|n| n.to_str()) == Some("node_modules") {
                    continue;
                }
                watch_dir(&p);
            } else {
                println!("cargo:rerun-if-changed={}", p.display());
            }
        }
    }
}

fn host_esbuild_pkg_dir() -> Option<&'static str> {
    match (env::consts::OS, env::consts::ARCH) {
        ("linux", "x86_64") => Some("linux-x64"),
        ("linux", "aarch64") => Some("linux-arm64"),
        ("macos", "x86_64") => Some("darwin-x64"),
        ("macos", "aarch64") => Some("darwin-arm64"),
        ("windows", "x86_64") => Some("win32-x64"),
        _ => None,
    }
}

fn find_native_esbuild(node_modules: &Path) -> Option<PathBuf> {
    let target_pkg = host_esbuild_pkg_dir()?;
    let bin_name = if env::consts::OS == "windows" {
        "esbuild.exe"
    } else {
        "esbuild"
    };
    let direct_pkg = node_modules.join("@esbuild").join(target_pkg);
    for candidate in [
        direct_pkg.join("bin").join(bin_name),
        direct_pkg.join(bin_name),
    ] {
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    // pnpm store layout: node_modules/.pnpm/@esbuild+<target>@.../node_modules/@esbuild/<target>/{bin/,}esbuild
    let pnpm_dir = node_modules.join(".pnpm");
    let prefix = format!("@esbuild+{target_pkg}@");
    if let Ok(entries) = fs::read_dir(&pnpm_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(&prefix) {
                let pkg_dir = entry
                    .path()
                    .join("node_modules")
                    .join("@esbuild")
                    .join(target_pkg);
                for candidate in [pkg_dir.join("bin").join(bin_name), pkg_dir.join(bin_name)] {
                    if candidate.is_file() {
                        return Some(candidate);
                    }
                }
            }
        }
    }
    None
}

/// Fallback minifier using the host-matched native `esbuild` binary into OUT_DIR staging.
fn build_with_native_esbuild(web_dir: &Path, stage_dir: &Path) -> bool {
    let Some(esbuild) = find_native_esbuild(&web_dir.join("node_modules")) else {
        return false;
    };

    let apps = [
        ("control", "app.js", "/"),
        ("challenge", "pow.js", "/cdn-cgi/"),
    ];

    for (app, entry_js, base) in apps {
        let src = web_dir.join(app);
        let dst = stage_dir.join(app);
        let assets = dst.join("assets");
        let _ = fs::remove_dir_all(&dst);
        if fs::create_dir_all(&assets).is_err() {
            return false;
        }

        let js_ok = Command::new(&esbuild)
            .arg(src.join(entry_js))
            .arg("--bundle")
            .arg("--format=esm")
            .arg("--minify")
            .arg(format!("--outfile={}", assets.join("app.min.js").display()))
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        let css_ok = Command::new(&esbuild)
            .arg(src.join("styles.css"))
            .arg("--minify")
            .arg(format!(
                "--outfile={}",
                assets.join("styles.min.css").display()
            ))
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if !js_ok || !css_ok {
            return false;
        }

        let Ok(html) = fs::read_to_string(src.join("index.html")) else {
            return false;
        };
        let patched = html
            .replace("./styles.css", &format!("{base}assets/styles.min.css"))
            .replace(
                &format!("./{entry_js}"),
                &format!("{base}assets/app.min.js"),
            )
            .replace(
                "/cdn-cgi/styles.css",
                &format!("{base}assets/styles.min.css"),
            )
            .replace(
                &format!("/cdn-cgi/{entry_js}"),
                &format!("{base}assets/app.min.js"),
            );
        if fs::write(dst.join("index.html"), patched).is_err() {
            return false;
        }

        // Also bundle standalone passive fingerprint beacon `/cdn-cgi/fp.js` into challenge dist
        if app == "challenge" && src.join("fp.js").exists() {
            let fp_ok = Command::new(&esbuild)
                .arg(src.join("fp.js"))
                .arg("--bundle")
                .arg("--format=iife")
                .arg("--minify")
                .arg(format!("--outfile={}", dst.join("fp.js").display()))
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !fp_ok {
                return false;
            }
        }
    }
    true
}

fn run_pnpm_build(web_dir: &Path, stage_dir: &Path) -> bool {
    let candidates: &[&str] = if cfg!(windows) {
        &["pnpm.cmd", "pnpm.exe", "pnpm"]
    } else {
        &["pnpm"]
    };
    for bin in candidates {
        if let Ok(status) = Command::new(bin)
            .arg("--dir")
            .arg(web_dir)
            .arg("build")
            .env("EXPOSURE_WEB_OUT_DIR", stage_dir)
            .status()
        {
            if status.success() {
                return true;
            }
        }
    }
    false
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let web_dir = workspace_root.join("web");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let dest = out_dir.join("embedded_web.rs");

    watch_dir(&web_dir.join("control"));
    watch_dir(&web_dir.join("challenge"));
    println!(
        "cargo:rerun-if-changed={}",
        web_dir.join("build.mjs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        web_dir.join("package.json").display()
    );
    println!("cargo:rerun-if-env-changed=EXPOSURE_USE_PREBUILT_WEB");

    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    if profile != "release" {
        fs::write(
            &dest,
            "pub fn get_embedded(_app: &str, _path: &str) -> Option<&'static [u8]> { None }\n\
             pub fn get_embedded_encoded(_app: &str, _path: &str, _encoding: &str) -> Option<&'static [u8]> { None }\n",
        )
        .unwrap();
        return;
    }

    let stage_dir = out_dir.join("web_dist");
    let vite_ok = run_pnpm_build(&web_dir, &stage_dir);

    let effective_dist = if (vite_ok
        && stage_dir.join("control").exists()
        && stage_dir.join("challenge").exists())
        || build_with_native_esbuild(&web_dir, &stage_dir)
    {
        stage_dir
    } else if env::var("EXPOSURE_USE_PREBUILT_WEB").ok().as_deref() == Some("1")
        && web_dir.join("dist").join("control").exists()
        && web_dir.join("dist").join("challenge").exists()
    {
        println!(
            "cargo:warning=Using prebuilt web/dist assets because EXPOSURE_USE_PREBUILT_WEB=1"
        );
        web_dir.join("dist")
    } else {
        panic!(
            "Release build failed to compile web assets via pnpm/esbuild (set EXPOSURE_USE_PREBUILT_WEB=1 to explicitly opt into prebuilt web/dist)"
        );
    };

    let dist_control = effective_dist.join("control");
    let dist_challenge = effective_dist.join("challenge");

    let mut control_files = Vec::new();
    let mut challenge_files = Vec::new();
    collect_files(&dist_control, &dist_control, &mut control_files);
    collect_files(&dist_challenge, &dist_challenge, &mut challenge_files);

    // The built-in PoW page ships as ONE self-contained document: the dist `index.html` with its
    // CSS and JS inlined. The separate `assets/app.min.js` / `assets/styles.min.css` stay embedded
    // too, so operator-provisioned pages may still reference those stable paths.
    let single_pow_page = build_single_file_page(&dist_challenge, &out_dir.join("web_single"));

    let compressed_root = out_dir.join("web_compressed");
    let mut code = String::from(
        "pub fn get_embedded(app: &str, path: &str) -> Option<&'static [u8]> {\n    match (app, path) {\n",
    );
    let mut encoded = String::from(
        "pub fn get_embedded_encoded(app: &str, path: &str, encoding: &str) -> Option<&'static [u8]> {\n    match (app, path, encoding) {\n",
    );
    for (app_name, files) in [("control", control_files), ("challenge", challenge_files)] {
        for (rel, full) in files {
            let abs = fs::canonicalize(&full).unwrap();
            let served = match (&single_pow_page, app_name, rel.as_str()) {
                (Some(page), "challenge", "index.html") => page.clone(),
                _ => abs,
            };
            code.push_str(&format!(
                "        ({:?}, {:?}) => Some(include_bytes!({:?})),\n",
                app_name,
                rel,
                served.to_string_lossy()
            ));
            for (coding, staged) in
                stage_compressed_variants(&compressed_root, app_name, &rel, &served)
            {
                encoded.push_str(&format!(
                    "        ({:?}, {:?}, {:?}) => Some(include_bytes!({:?})),\n",
                    app_name,
                    rel,
                    coding,
                    staged.to_string_lossy()
                ));
            }
        }
    }
    code.push_str("        _ => None,\n    }\n}\n");
    code.push_str(&encoded);
    code.push_str("        _ => None,\n    }\n}\n");
    fs::write(&dest, code).unwrap();
}

/// Replace the HTML tag that references `needle` with `replacement`, leaving the document
/// untouched when the tag cannot be located.
fn splice_tag(html: &str, needle: &str, replacement: &str) -> String {
    let Some(at) = html.find(needle) else {
        return html.to_string();
    };
    let Some(start) = html[..at].rfind('<') else {
        return html.to_string();
    };
    let Some(close) = html[at..].find('>') else {
        return html.to_string();
    };
    let mut out = String::with_capacity(html.len() + replacement.len());
    out.push_str(&html[..start]);
    out.push_str(replacement);
    out.push_str(&html[at + close + 1..]);
    out
}

/// Assemble the built-in PoW page as a single self-contained document (CSS + JS inlined).
///
/// The inline `<script>`/`<style>` bodies must not contain their own closing sequence; if the
/// minified bundle ever does, that asset is left as an external reference instead of producing a
/// broken inline page.
fn build_single_file_page(dist: &Path, out_dir: &Path) -> Option<PathBuf> {
    let mut html = fs::read_to_string(dist.join("index.html")).ok()?;
    let css = fs::read_to_string(dist.join("assets").join("styles.min.css")).unwrap_or_default();
    let js = fs::read_to_string(dist.join("assets").join("app.min.js")).unwrap_or_default();

    if !css.is_empty() && !css.contains("</style") {
        html = splice_tag(&html, "styles.min.css", &format!("<style>{css}</style>"));
    }
    if !js.is_empty() && !js.contains("</script") {
        html = splice_tag(
            &html,
            "app.min.js",
            &format!("<script type=\"module\">{js}</script>"),
        );
    }

    fs::create_dir_all(out_dir).ok()?;
    let dst = out_dir.join("challenge-index.html");
    fs::write(&dst, html).ok()?;
    fs::canonicalize(&dst).ok()
}

/// Payloads below this size are dominated by the coding's own framing overhead.
const MIN_COMPRESS_LEN: usize = 512;

/// Asset types that genuinely shrink under gzip/brotli. Already-compressed binaries
/// (png/jpg/ico/woff2) are skipped so we never ship a "compressed" variant that is larger.
fn is_compressible(rel: &str) -> bool {
    matches!(
        rel.rsplit('.').next().unwrap_or("").to_ascii_lowercase().as_str(),
        "html" | "htm" | "js" | "mjs" | "css" | "json" | "svg" | "txt" | "map" | "wasm"
    )
}

fn gzip_bytes(data: &[u8]) -> Option<Vec<u8>> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    std::io::Write::write_all(&mut enc, data).ok()?;
    enc.finish().ok()
}

fn brotli_bytes(data: &[u8]) -> Option<Vec<u8>> {
    let params = brotli::enc::BrotliEncoderParams {
        quality: 9,
        lgwin: 22,
        ..Default::default()
    };
    let mut out = Vec::new();
    brotli::BrotliCompress(&mut std::io::Cursor::new(data), &mut out, &params).ok()?;
    Some(out)
}

/// Pre-compress one embedded asset and return the staged `(coding, path)` pairs that are
/// strictly smaller than the identity payload. Compression happens once, at build time, so
/// serving a compressed asset costs the node nothing beyond a memcpy.
fn stage_compressed_variants(
    root: &Path,
    app: &str,
    rel: &str,
    file: &Path,
) -> Vec<(&'static str, PathBuf)> {
    if !is_compressible(rel) {
        return Vec::new();
    }
    let Ok(data) = fs::read(file) else {
        return Vec::new();
    };
    if data.len() < MIN_COMPRESS_LEN {
        return Vec::new();
    }
    let mut staged = Vec::new();
    for (coding, compressed) in [("br", brotli_bytes(&data)), ("gzip", gzip_bytes(&data))] {
        let Some(compressed) = compressed else { continue };
        if compressed.len() + 32 >= data.len() {
            continue;
        }
        let dst = root.join(app).join(coding).join(rel);
        let Some(parent) = dst.parent() else { continue };
        if fs::create_dir_all(parent).is_err() || fs::write(&dst, &compressed).is_err() {
            continue;
        }
        let Ok(abs) = fs::canonicalize(&dst) else {
            continue;
        };
        staged.push((coding, abs));
    }
    staged
}
