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
    for candidate in [direct_pkg.join("bin").join(bin_name), direct_pkg.join(bin_name)] {
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
            .arg(format!("--outfile={}", assets.join("styles.min.css").display()))
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
            .replace(&format!("./{entry_js}"), &format!("{base}assets/app.min.js"))
            .replace("/cdn-cgi/styles.css", &format!("{base}assets/styles.min.css"))
            .replace(&format!("/cdn-cgi/{entry_js}"), &format!("{base}assets/app.min.js"));
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
    println!("cargo:rerun-if-changed={}", web_dir.join("build.mjs").display());
    println!("cargo:rerun-if-changed={}", web_dir.join("package.json").display());
    println!("cargo:rerun-if-env-changed=EXPOSURE_USE_PREBUILT_WEB");

    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    if profile != "release" {
        fs::write(
            &dest,
            "pub fn get_embedded(_app: &str, _path: &str) -> Option<&'static [u8]> { None }\n",
        )
        .unwrap();
        return;
    }

    let stage_dir = out_dir.join("web_dist");
    let vite_ok = run_pnpm_build(&web_dir, &stage_dir);

    let effective_dist = if (vite_ok && stage_dir.join("control").exists() && stage_dir.join("challenge").exists())
        || build_with_native_esbuild(&web_dir, &stage_dir)
    {
        stage_dir
    } else if env::var("EXPOSURE_USE_PREBUILT_WEB").ok().as_deref() == Some("1")
        && web_dir.join("dist").join("control").exists()
        && web_dir.join("dist").join("challenge").exists()
    {
        println!("cargo:warning=Using prebuilt web/dist assets because EXPOSURE_USE_PREBUILT_WEB=1");
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

    let mut code = String::from(
        "pub fn get_embedded(app: &str, path: &str) -> Option<&'static [u8]> {\n    match (app, path) {\n",
    );
    for (rel, full) in control_files {
        let abs = fs::canonicalize(&full).unwrap();
        code.push_str(&format!(
            "        (\"control\", {:?}) => Some(include_bytes!({:?})),\n",
            rel,
            abs.to_string_lossy()
        ));
    }
    for (rel, full) in challenge_files {
        let abs = fs::canonicalize(&full).unwrap();
        code.push_str(&format!(
            "        (\"challenge\", {:?}) => Some(include_bytes!({:?})),\n",
            rel,
            abs.to_string_lossy()
        ));
    }
    code.push_str("        _ => None,\n    }\n}\n");
    fs::write(&dest, code).unwrap();
}
