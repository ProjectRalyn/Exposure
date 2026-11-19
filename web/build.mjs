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
      },
    },
    logLevel: "warn",
  });
}

console.log("[exposure-web] All vanilla H5/JS apps built and minified.");
