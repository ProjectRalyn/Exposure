//! Embed the web build output into the binary.
//!
//! Everything that shapes a byte of HTML/CSS/JS happens in `web/build.mjs` (Vite): page assembly,
//! `<!-- @inline -->` splicing, minification, and the single-file packaging of the built-in pages,
//! including the CSP hash of any script it inlined. This script only (a) asks the frontend build
//! to run, (b) pre-compresses text assets, and (c) emits `include_bytes!` tables. It must never
//! parse or rewrite a web asset.

use std::collections::BTreeMap;
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
            // Dot-files are build metadata the frontend build writes for us (`.script-hash`); they
            // are neither served nor embedded.
            if rel.rsplit('/').next().is_some_and(|n| n.starts_with('.')) {
                continue;
            }
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

/// Run the frontend build (Vite, through `pnpm build`). Bundling, page assembly and minification
/// all happen there; this is only the invocation.
fn run_pnpm_build(web_dir: &Path, stage_dir: &Path) -> bool {
    let candidates: &[&str] = if cfg!(windows) {
        &["pnpm.cmd", "pnpm.exe", "pnpm"]
    } else {
        &["pnpm"]
    };
    for bin in candidates {
        if Command::new(bin)
            .arg("--dir")
            .arg(web_dir)
            .arg("build")
            .env("EXPOSURE_WEB_OUT_DIR", stage_dir)
            .status()
            .is_ok_and(|status| status.success())
        {
            return true;
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
    watch_dir(&web_dir.join("error"));
    watch_dir(&web_dir.join("shared"));
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
             pub fn get_embedded_encoded(_app: &str, _path: &str, _encoding: &str) -> Option<&'static [u8]> { None }\n\
             pub fn embedded_script_hash(_app: &str) -> Option<&'static str> { None }\n",
        )
        .unwrap();
        return;
    }

    let stage_dir = out_dir.join("web_dist");
    let built = run_pnpm_build(&web_dir, &stage_dir)
        && stage_dir.join("control").exists()
        && stage_dir.join("challenge").exists()
        && stage_dir.join("error").exists();

    let effective_dist = if built {
        stage_dir
    } else if env::var("EXPOSURE_USE_PREBUILT_WEB").ok().as_deref() == Some("1")
        && web_dir.join("dist").join("control").exists()
        && web_dir.join("dist").join("challenge").exists()
        && web_dir.join("dist").join("error").exists()
    {
        println!(
            "cargo:warning=Using prebuilt web/dist assets because EXPOSURE_USE_PREBUILT_WEB=1"
        );
        web_dir.join("dist")
    } else {
        panic!(
            "failed to run the web build (`pnpm --dir web build`); fix the frontend toolchain, or \
             set EXPOSURE_USE_PREBUILT_WEB=1 to explicitly opt into an existing web/dist"
        );
    };

    let dist_control = effective_dist.join("control");
    let dist_challenge = effective_dist.join("challenge");
    let dist_error = effective_dist.join("error");

    let mut control_files = Vec::new();
    let mut challenge_files = Vec::new();
    let mut error_files = Vec::new();
    collect_files(&dist_control, &dist_control, &mut control_files);
    collect_files(&dist_challenge, &dist_challenge, &mut challenge_files);
    collect_files(&dist_error, &dist_error, &mut error_files);

    // CSP source hash of the script the frontend build inlined into the built-in page, recorded
    // next to that page. Only the PoW page inlines a script.
    let mut script_hashes: BTreeMap<&'static str, String> = BTreeMap::new();
    for (app, dist) in [("challenge", &dist_challenge), ("error", &dist_error)] {
        let Ok(raw) = fs::read_to_string(dist.join(".script-hash")) else {
            continue;
        };
        let hash = raw.trim();
        if !hash.is_empty() {
            script_hashes.insert(app, hash.to_string());
        }
    }

    let compressed_root = out_dir.join("web_compressed");
    let mut code = String::from(
        "pub fn get_embedded(app: &str, path: &str) -> Option<&'static [u8]> {\n    match (app, path) {\n",
    );
    let mut encoded = String::from(
        "pub fn get_embedded_encoded(app: &str, path: &str, encoding: &str) -> Option<&'static [u8]> {\n    match (app, path, encoding) {\n",
    );
    for (app_name, files) in [
        ("control", control_files),
        ("challenge", challenge_files),
        ("error", error_files),
    ] {
        for (rel, full) in files {
            // `error/assets/*` is unreachable at runtime: the intercept page is only ever served
            // as the inlined single-file document, and nothing maps a URL onto this app's assets.
            if app_name == "error" && rel.starts_with("assets/") {
                continue;
            }
            let abs = fs::canonicalize(&full).unwrap();
            code.push_str(&format!(
                "        ({:?}, {:?}) => Some(include_bytes!({:?})),\n",
                app_name,
                rel,
                abs.to_string_lossy()
            ));
            for (coding, staged) in
                stage_compressed_variants(&compressed_root, app_name, &rel, &abs)
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
    code.push_str("pub fn embedded_script_hash(app: &str) -> Option<&'static str> {\n    match app {\n");
    for (app, hash) in &script_hashes {
        code.push_str(&format!("        {:?} => Some({:?}),\n", app, hash));
    }
    code.push_str("        _ => None,\n    }\n}\n");
    fs::write(&dest, code).unwrap();
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
