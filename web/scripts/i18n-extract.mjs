#!/usr/bin/env node
// Sync locale files with the English source strings used by the Control UI.
//
//   pnpm i18n:extract           # add missing keys (empty translation) and report unused
//   pnpm i18n:extract --prune   # also delete entries no longer present in the UI
//
// Existing translations are never overwritten. Unused entries are reported as `stale`
// (they usually mean the English copy changed and needs re-translation).
import {
  collectSources,
  listLocales,
  readLocale,
  writeLocale,
  normalize,
} from "./i18n-lib.mjs";

const prune = process.argv.includes("--prune");
const sources = collectSources();
const locales = listLocales();

if (!locales.length) {
  console.error("No locale files found under control/i18n/locales/");
  process.exit(1);
}

console.log(`== i18n extract ==\n  source strings: ${sources.size}\n  locales: ${locales.join(", ")}\n`);

let missingTotal = 0;
let unusedTotal = 0;

for (const code of locales) {
  const { meta, entries } = readLocale(code);
  const next = { ...entries };
  const missing = [];
  const unused = [];

  for (const text of sources.keys()) {
    if (!(text in next)) {
      missing.push(text);
      next[text] = "";
    } else if (typeof next[text] !== "string") {
      next[text] = "";
    }
  }
  for (const key of Object.keys(next)) {
    if (!sources.has(key)) unused.push(key);
  }

  if (prune) for (const key of unused) delete next[key];

  if (missing.length) writeLocale(code, meta, next);
  missingTotal += missing.length;
  unusedTotal += unused.length;

  console.log(`[${code}] missing=${missing.length} unused=${unused.length}${prune ? " (pruned)" : ""}`);
  for (const text of missing.slice(0, 20)) console.log(`   + ${JSON.stringify(text)}`);
  if (missing.length > 20) console.log(`   … ${missing.length - 20} more`);
  for (const text of unused.slice(0, 20)) console.log(`   - ${JSON.stringify(text)}`);
  if (unused.length > 20) console.log(`   … ${unused.length - 20} more`);
}

// Detect duplicate translations of the same English source across the catalogue.
const dupes = new Map();
for (const [text] of sources) {
  const norm = normalize(text);
  if (dupes.has(norm) && dupes.get(norm) !== text) {
    console.warn(`!! duplicate source after normalization: ${JSON.stringify(dupes.get(norm))} / ${JSON.stringify(text)}`);
  }
  dupes.set(norm, text);
}

console.log(`\nDone. added ${missingTotal}, unused ${unusedTotal}.`);
if (missingTotal) console.log("Fill the empty strings in the locale files to translate them.");
