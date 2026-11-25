// Shared helpers for the English-source i18n tooling.
//
// Source strings are plain English: `t("English text")` in JS and any static text in
// markup. Locale files under control/i18n/locales/<code>.json map that English text to
// the translated text; there are no short keys and no data-i18n attributes.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const webDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const controlDir = path.resolve(webDir, "control");
export const localeDir = path.resolve(controlDir, "i18n", "locales");

/**
 * Reject strings that are clearly data rather than UI copy. Dynamic/API values are
 * additionally excluded at runtime by `applyI18n`'s skip rules.
 */
export function isTranslatable(text) {
  const t = normalize(text);
  if (t.length < 2) return false;
  if (!/[A-Za-z\u4e00-\u9fff]/.test(t)) return false;
  if (/:\/\/|^\//.test(t)) return false;
  if (/^[\s\d.,:;%+\-–—_/()[\]]+$/.test(t)) return false;
  if (t.includes("${")) return false;
  return true;
}

export function normalize(text) {
  return String(text ?? "").replace(/\s+/g, " ").trim();
}

function decodeEntities(text) {
  return text
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#0?39;/g, "'");
}

function listFiles(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (["node_modules", "dist", "i18n"].includes(entry.name)) continue;
      listFiles(p, out);
    } else if (entry.name.endsWith(".js")) {
      out.push(p);
    } else if (entry.name.endsWith(".html")) {
      out.push(p);
    }
  }
  return out;
}

const T_CALL =
  /\bt\(\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\$]|\\.)*`)/g;
const ATTRS = /\b(?:placeholder|title|aria-label|alt)\s*=\s*"([^"]*)"/g;
// Plain text between tags inside JS template literals (markup rendered via innerHTML).
const MARKUP_TEXT = />([^<>]+)</g;
// Fragments that look like code instead of UI copy.
const CODEISH = /[{}`$=]|&&|\|\||=>|==|!=|\/\//;

function addCandidate(map, raw, origin) {
  const text = normalize(raw);
  if (!isTranslatable(text)) return;
  const entry = map.get(text) || { text, origins: new Set() };
  entry.origins.add(origin);
  map.set(text, entry);
}

function collectFromJs(file, map) {
  const src = fs.readFileSync(file, "utf8");
  const rel = path.relative(controlDir, file);
  for (const m of src.matchAll(T_CALL)) {
    const literal = m[1];
    let value;
    try {
      // String literal only (backticks without ${} are allowed and checked above).
      // eslint-disable-next-line no-new-func
      value = new Function(`return (${literal});`)();
    } catch {
      continue;
    }
    addCandidate(map, value, rel);
  }
  // Static copy written directly in markup templates; translated at runtime by applyI18n().
  for (const m of src.matchAll(MARKUP_TEXT)) {
    const text = normalize(decodeEntities(m[1]));
    if (CODEISH.test(text)) continue;
    if (!isMarkupCopy(text)) continue;
    addCandidate(map, text, rel);
  }
}

/**
 * Conservative filter for markup text: keeps visible UI copy ("Access Logs", "2 hops")
 * and drops template fragments ("req ·", "i: 1 ms", "&laquo;") and code.
 */
function isMarkupCopy(text) {
  const t = normalize(text);
  if (t.length < 2 || t.length > 160) return false;
  if (!/^[A-Z\u4e00-\u9fff]/.test(t)) return false;
  if (/&[a-zA-Z]+;/.test(t)) return false;
  if (/[:·,;/-]$/.test(t)) return false;
  if (/(^|\s)(req|ms|B|KB|MB|GB|KiB|MiB)$/.test(t)) return false;
  return true;
}

function collectFromHtml(file, map) {
  const rel = path.relative(controlDir, file);
  let html = fs.readFileSync(file, "utf8");
  html = html.replace(/<!--[\s\S]*?-->/g, " ");
  html = html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ");
  html = html.replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ");
  for (const m of html.matchAll(ATTRS)) addCandidate(map, decodeEntities(m[1]), rel);
  const textOnly = html.replace(/<[^>]*>/g, "\n");
  for (const line of textOnly.split("\n")) addCandidate(map, decodeEntities(line), rel);
}

/** Collect every translatable English source string used by the UI. */
export function collectSources() {
  const map = new Map();
  const runtimeModule = path.join(controlDir, "i18n.js");
  for (const file of listFiles(controlDir)) {
    if (file === runtimeModule) continue; // doc-comment examples are not UI copy
    if (file.endsWith(".js")) collectFromJs(file, map);
    else collectFromHtml(file, map);
  }
  return map;
}

export function listLocales() {
  if (!fs.existsSync(localeDir)) return [];
  return fs
    .readdirSync(localeDir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => f.replace(/\.json$/, ""))
    .sort();
}

export function readLocale(code) {
  const file = path.join(localeDir, `${code}.json`);
  const raw = JSON.parse(fs.readFileSync(file, "utf8"));
  const { __meta, ...entries } = raw;
  return { meta: __meta || { name: code, dir: "ltr" }, entries };
}

export function writeLocale(code, meta, entries) {
  const sorted = {};
  for (const key of Object.keys(entries).sort((a, b) => a.localeCompare(b))) {
    sorted[key] = entries[key];
  }
  fs.mkdirSync(localeDir, { recursive: true });
  fs.writeFileSync(
    path.join(localeDir, `${code}.json`),
    `${JSON.stringify({ __meta: meta, ...sorted }, null, 2)}\n`
  );
}
