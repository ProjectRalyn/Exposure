#!/usr/bin/env node
// CI gate: verify every locale file covers the English source strings used by the UI.
//
//   pnpm i18n:check          # exit 1 when translations are missing (also lists stale keys)
//   pnpm i18n:check --warn   # never fail, only report
import { collectSources, listLocales, readLocale } from "./i18n-lib.mjs";

const warnOnly = process.argv.includes("--warn");
const sources = collectSources();
const locales = listLocales();

if (!locales.length) {
  console.error("No locale files found under control/i18n/locales/");
  process.exit(1);
}

let failed = false;
console.log(`== i18n check ==\n  source strings: ${sources.size}`);

for (const code of locales) {
  const { entries } = readLocale(code);
  const missing = [];
  for (const text of sources.keys()) {
    if (!(text in entries) || !String(entries[text] || "").trim()) missing.push(text);
  }
  const stale = Object.keys(entries).filter((key) => !sources.has(key));

  const status = missing.length ? "FAIL" : "ok";
  if (missing.length) failed = true;
  console.log(`  [${code}] ${status} · missing=${missing.length} · stale=${stale.length}`);
  for (const text of missing.slice(0, 15)) console.log(`     missing: ${JSON.stringify(text)}`);
  if (missing.length > 15) console.log(`     … ${missing.length - 15} more`);
  for (const text of stale.slice(0, 10)) console.log(`     stale  : ${JSON.stringify(text)}`);
  if (stale.length > 10) console.log(`     … ${stale.length - 10} more`);
}

if (failed) {
  console.log("\nRun `pnpm i18n:extract` to add the missing keys, then fill in the translations.");
  process.exit(warnOnly ? 0 : 1);
}
console.log("\nAll locales are in sync.");
