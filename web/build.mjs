import { build } from "vite";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const baseOutDir = process.env.EXPOSURE_WEB_OUT_DIR
  ? resolve(process.env.EXPOSURE_WEB_OUT_DIR)
  : resolve(__dirname, "dist");

const apps = [
  { name: "control", root: resolve(__dirname, "control"), outDir: resolve(baseOutDir, "control") },
  { name: "challenge", root: resolve(__dirname, "challenge"), outDir: resolve(baseOutDir, "challenge") },
];

for (const app of apps) {
  console.log(`[exposure-web] Building ${app.name} -> ${app.outDir}`);
  // The challenge app is served behind `/cdn-cgi/`, where the Node intercepts fixed asset paths
  // (`assets/app.min.js`, `assets/styles.min.css`) to honour Control-provisioned custom page
  // HTML/CSS — keep those names stable instead of hashing them.
  const stableNames = app.name === "challenge";
  await build({
    root: app.root,
    base: app.name === "challenge" ? "/cdn-cgi/" : "/",
    build: {
      outDir: app.outDir,
      emptyOutDir: true,
      minify: "esbuild",
      cssMinify: true,
      assetsInlineLimit: 0,
      rollupOptions: {
        input: resolve(app.root, "index.html"),
        output: stableNames
          ? {
              entryFileNames: "assets/app.min.js",
              chunkFileNames: "assets/[name]-[hash].js",
              assetFileNames: (info) => {
                const name = info.names?.[0] ?? info.name ?? "";
                return name.endsWith(".css")
                  ? "assets/styles.min.css"
                  : "assets/[name]-[hash][extname]";
              },
            }
          : undefined,
      },
    },
    logLevel: "warn",
  });
  if (app.name === "challenge") {
    await build({
      root: app.root,
      build: {
        outDir: app.outDir,
        emptyOutDir: false,
        minify: "esbuild",
        lib: {
          entry: resolve(app.root, "fp.js"),
          formats: ["iife"],
          name: "ExposureFpBeacon",
          fileName: () => "fp.js",
        },
      },
      logLevel: "warn",
    });
  }
}

console.log("[exposure-web] All vanilla H5/JS apps built and minified.");
