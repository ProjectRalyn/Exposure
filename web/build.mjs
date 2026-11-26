import { build } from "vite";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const baseOutDir = process.env.EXPOSURE_WEB_OUT_DIR
  ? resolve(process.env.EXPOSURE_WEB_OUT_DIR)
  : resolve(__dirname, "dist");

/**
 * Assemble the built-in pages into ONE self-contained document.
 *
 * Both pages are served by the edge in a position where a second request is never acceptable: the
 * PoW page must not stall behind an extra round trip, and the intercept page is rendered into
 * responses at arbitrary host/path combinations, so any relative URL would resolve against the
 * intercepted site instead of the edge. The stylesheet (and, for the PoW page, the script) is
 * therefore inlined here, at build time.
 *
 * `.script-hash` records the CSP `sha256-<base64>` of the exact inlined script: the Node allows it
 * by hash rather than `'unsafe-inline'`. Empty when the page has no script.
 */
function assembleSingleFile(outDir) {
  const page = resolve(outDir, "index.html");
  let html = readFileSync(page, "utf8");

  const readOptional = (p) => (existsSync(p) ? readFileSync(p, "utf8") : "");
  const css = readOptional(resolve(outDir, "assets/styles.min.css"));
  if (css && !css.includes("</style")) {
    html = html.replace(
      /<link\b[^>]*rel="stylesheet"[^>]*>/,
      () => `<style>${css}</style>`,
    );
  }

  let scriptHash = "";
  const js = readOptional(resolve(outDir, "assets/app.min.js"));
  if (js && !js.includes("</script")) {
    html = html.replace(
      /<script\b[^>]*\bsrc="[^"]*app\.min\.js"[^>]*><\/script>/,
      () => `<script type="module">${js}</script>`,
    );
    scriptHash = `sha256-${createHash("sha256").update(js, "utf8").digest("base64")}`;
  }

  writeFileSync(page, html);
  // `build.rs` embeds this next to the page; it is build metadata, never served.
  writeFileSync(resolve(outDir, ".script-hash"), `${scriptHash}\n`);
}

/**
 * Splice `<!-- @inline path -->` directives (today: the page illustrations) into the page HTML.
 *
 * The artwork stays in a standalone `.svg` file so it can be opened and edited as SVG, yet must
 * end up inline in the document: it is painted with the page's CSS custom properties
 * (`var(--art-ink)`, `var(--art-red)`), which do not reach an external `<img>`/`<object>`, and the
 * intercept page is served as ONE self-contained file so it can never issue a second request.
 *
 * `order: "pre"` runs before Vite rewrites the stylesheet/script tags. Applies to `vite build` and
 * to `vite <app>`, so the dev server shows the same page. A missing file fails the build.
 *
 * The committed artwork is deliberately coarse: coordinates live on a 1/4 unit grid of the
 * original drawing, which is sub-pixel at the only sizes the pages ever render it (400px / 620px)
 * and cuts the payload by ~28% / ~41%. Redraw at full resolution only if that stops being true.
 */
function inlineDirectives(root) {
  return {
    name: "exposure-inline-directives",
    transformIndexHtml: {
      order: "pre",
      handler(html) {
        return html.replace(
          /^([ \t]*)<!--\s*@inline\s+(\S+)\s*-->[ \t]*$/gm,
          (_match, indent, rel) => {
            const body = readFileSync(resolve(root, rel), "utf8")
              .replace(/\r/g, "")
              .replace(/\n+$/, "");
            return body
              .split("\n")
              .map((line) => (line.trim() ? indent + line : line))
              .join("\n");
          },
        );
      },
    },
  };
}

const apps = [
  { name: "control", root: resolve(__dirname, "control"), outDir: resolve(baseOutDir, "control") },
  { name: "challenge", root: resolve(__dirname, "challenge"), outDir: resolve(baseOutDir, "challenge") },
  { name: "error", root: resolve(__dirname, "error"), outDir: resolve(baseOutDir, "error") },
];

for (const app of apps) {
  console.log(`[exposure-web] Building ${app.name} -> ${app.outDir}`);
  // The challenge app is served behind `/cdn-cgi/`, where the Node intercepts fixed asset paths
  // (`assets/app.min.js`, `assets/styles.min.css`) to honour Control-provisioned custom page
  // HTML/CSS — keep those names stable instead of hashing them. The error page is inlined into
  // one document at build time, so its stable names only have to be predictable.
  const stableNames = app.name !== "control";
  await build({
    root: app.root,
    base: app.name === "challenge" ? "/cdn-cgi/" : "/",
    plugins: [inlineDirectives(app.root)],
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
  if (app.name !== "control") assembleSingleFile(app.outDir);
}

console.log("[exposure-web] All vanilla H5/JS apps built and minified.");
