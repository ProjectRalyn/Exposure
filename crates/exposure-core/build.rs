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
        if path.is_dir() {
            collect_files(base, &path, out);
        } else if path.is_file() {
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
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
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

fn find_native_esbuild(dir: &Path) -> Option<PathBuf> {
    if !dir.exists() {
        return None;
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(cur) = stack.pop() {
        if let Ok(entries) = fs::read_dir(&cur) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.file_name().and_then(|n| n.to_str()) == Some("esbuild") {
                    if let Ok(meta) = fs::metadata(&p) {
                        if meta.is_file() && meta.len() > 1_000_000 {
                            return Some(p);
                        }
                    }
                }
            }
        }
    }
    None
}

/// Fallback minifier using the standalone native `esbuild` binary when `node`/Vite cannot run.
fn build_with_native_esbuild(web_dir: &Path) -> bool {
    let Some(esbuild) = find_native_esbuild(&web_dir.join("node_modules")) else {
        return false;
    };

    let apps = [
        ("control", "app.js", "/"),
        ("challenge", "pow.js", "/cdn-cgi/"),
    ];

    for (app, entry_js, base) in apps {
        let src = web_dir.join(app);
        let dst = web_dir.join("dist").join(app);
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
            .replace(&format!("./{entry_js}"), &format!("{base}assets/app.min.js"));
        if fs::write(dst.join("index.html"), patched).is_err() {
            return false;
        }
    }
    true
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

    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    if profile != "release" {
        fs::write(
            &dest,
            "pub fn get_embedded(_app: &str, _path: &str) -> Option<&'static [u8]> { None }\n",
        )
        .unwrap();
        return;
    }

    let dist_control = web_dir.join("dist").join("control");
    let dist_challenge = web_dir.join("dist").join("challenge");

    let vite_ok = Command::new("pnpm")
        .arg("--dir")
        .arg(&web_dir)
        .arg("build")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !vite_ok {
        let esbuild_ok = build_with_native_esbuild(&web_dir);
        if !esbuild_ok && (!dist_control.exists() || !dist_challenge.exists()) {
            panic!(
                "Release build requires minified assets in {} (run `pnpm --dir web install && pnpm --dir web build`)",
                web_dir.join("dist").display()
            );
        }
    }

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
