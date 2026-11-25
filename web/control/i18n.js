// English-source i18n engine for Exposure Control.
//
// Authoring rule
// --------------
// Write plain English. Static markup needs no attributes: `applyI18n()` translates DOM
// text nodes plus the placeholder/title/aria-label/alt attributes at runtime by exact
// matching against the active locale dictionary (English text -> translation).
// Inside JS strings use `t("English text")`; `{name}` placeholders are supported.
//
// Locale files live in ./i18n/locales/<code>.json shaped as { "English source": "译文" }
// and are synced by `pnpm i18n:extract` / validated by `pnpm i18n:check`.
//
// API-driven values are exempt from translation: the walker skips code/pre/textarea/SVG,
// table bodies and any subtree marked with `data-i18n-skip`.

const LANG_STORAGE_KEY = "exposure_panel_lang";
const SOURCE_LANG = "en";

const LOCALE_MODULES = import.meta.glob("./i18n/locales/*.json", { eager: true });

/** Collapse whitespace so markup indentation never affects lookups. */
function normalize(text) {
  return String(text ?? "").replace(/\s+/g, " ").trim();
}

function buildLocales() {
  const out = new Map();
  // The source language needs no dictionary: the UI already is English.
  out.set(SOURCE_LANG, { code: SOURCE_LANG, name: "English", dir: "ltr", dict: new Map() });
  for (const [file, mod] of Object.entries(LOCALE_MODULES || {})) {
    const code = (file.match(/([^/]+)\.json$/) || [])[1];
    if (!code) continue;
    const data = (mod && mod.default) || {};
    const dict = new Map();
    for (const [source, translated] of Object.entries(data)) {
      if (source === "__meta") continue;
      if (typeof translated !== "string" || !translated.trim()) continue;
      dict.set(normalize(source), translated);
    }
    out.set(code, {
      code,
      name: data.__meta?.name || code,
      dir: data.__meta?.dir || "ltr",
      dict,
    });
  }
  return out;
}

const LOCALES = buildLocales();
const listeners = new Set();

function detectInitialLang() {
  try {
    const saved = localStorage.getItem(LANG_STORAGE_KEY);
    if (saved && LOCALES.has(saved)) return saved;
  } catch {}
  let navLang = "";
  try {
    navLang = (navigator.language || "").toLowerCase();
  } catch {}
  if (navLang) {
    for (const code of LOCALES.keys()) {
      if (code === SOURCE_LANG) continue;
      const base = code.toLowerCase().split("-")[0];
      if (navLang.startsWith(base)) return code;
    }
  }
  return SOURCE_LANG;
}

let currentLang = detectInitialLang();

export function getLang() {
  return currentLang;
}

/** All registered languages, source language first. */
export function getAvailableLangs() {
  return [...LOCALES.values()].map(({ code, name, dir }) => ({ code, name, dir }));
}

export function setLang(lang) {
  if (!LOCALES.has(lang) || lang === currentLang) return;
  currentLang = lang;
  try {
    localStorage.setItem(LANG_STORAGE_KEY, lang);
  } catch {}
  const meta = LOCALES.get(lang);
  document.documentElement.lang = lang;
  document.documentElement.dir = meta?.dir || "ltr";
  applyI18n(document);
  for (const fn of listeners) fn(lang);
}

export function onLangChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/**
 * Translate an English source string. Missing translations fall back to the English
 * source, so a partially translated locale still renders a usable UI.
 */
export function t(source, vars = null) {
  const locale = LOCALES.get(currentLang) || LOCALES.get(SOURCE_LANG);
  const key = normalize(source);
  let msg = locale.dict.get(key) ?? key;
  if (vars && typeof vars === "object") {
    for (const [k, v] of Object.entries(vars)) {
      msg = msg.replaceAll(`{${k}}`, String(v ?? ""));
    }
  }
  return msg;
}

/* ==================== DOM translation (no data-i18n required) ==================== */

// Never touch: executable/embedded content, values that come from API payloads, and
// elements explicitly opted out with `data-i18n-skip`.
const SKIP_TAGS = new Set([
  "SCRIPT",
  "STYLE",
  "PRE",
  "CODE",
  "TEXTAREA",
  "SVG",
  "CANVAS",
  "IFRAME",
  "NOSCRIPT",
]);
const SKIP_SELECTOR = [
  "tbody", // table bodies are rendered from API data
  ".fp-kv-val", // detail drawers show API values
  ".fp-ua-box",
  ".output-box",
  ".code-editor",
  ".chart-box",
  ".chart-svg-wrap",
  "[data-i18n-skip]",
].join(",");
const ATTRS = ["placeholder", "title", "aria-label", "alt"];

const originalText = new WeakMap();
const originalAttrs = new WeakMap();

function isSkipped(el) {
  if (SKIP_TAGS.has(el.tagName)) return true;
  if (el.isContentEditable) return true;
  return el.matches(SKIP_SELECTOR);
}

function walkTree(root, handler) {
  const visit = (node) => {
    if (node.nodeType === Node.TEXT_NODE) {
      handler.text(node);
      return;
    }
    if (node.nodeType !== Node.ELEMENT_NODE) return;
    if (isSkipped(node)) return;
    handler.element(node);
    for (let child = node.firstChild; child; child = child.nextSibling) visit(child);
  };
  if (!root) return;
  for (let child = root.firstChild; child; child = child.nextSibling) visit(child);
}

function translateTextNode(node, dict) {
  const raw = node.nodeValue;
  if (!raw) return;
  const key = normalize(raw);
  if (key.length < 2) return;
  const translated = dict.get(key);
  if (!translated || translated === key) return;
  if (!originalText.has(node)) originalText.set(node, raw);
  const m = raw.match(/^(\s*)([\s\S]*?)(\s*)$/);
  node.nodeValue = `${m[1]}${translated}${m[3]}`;
}

function restoreTree(root) {
  walkTree(root, {
    text(node) {
      const original = originalText.get(node);
      if (original != null) node.nodeValue = original;
    },
    element(el) {
      const attrs = originalAttrs.get(el);
      if (!attrs) return;
      for (const [name, value] of attrs) {
        if (el.getAttribute(name) !== value) el.setAttribute(name, value);
      }
    },
  });
}

/**
 * Translate (or restore, when the active language is English) static UI text under `root`.
 * Call after every view render; safe to call repeatedly.
 */
export function applyI18n(root = document) {
  if (currentLang === SOURCE_LANG) {
    restoreTree(root);
    return;
  }
  const dict = LOCALES.get(currentLang)?.dict;
  if (!dict || dict.size === 0) return;
  walkTree(root, {
    text(node) {
      translateTextNode(node, dict);
    },
    element(el) {
      for (const name of ATTRS) {
        const value = el.getAttribute(name);
        if (!value) continue;
        const key = normalize(value);
        const translated = dict.get(key);
        if (!translated || translated === key) continue;
        let attrs = originalAttrs.get(el);
        if (!attrs) {
          attrs = new Map();
          originalAttrs.set(el, attrs);
        }
        if (!attrs.has(name)) attrs.set(name, value);
        el.setAttribute(name, translated);
      }
    },
  });
}

/** Backwards-compatible alias for the previous attribute-based API. */
export const applyStaticI18n = applyI18n;

// Common Aliyun DNS line display names fallback when DescribeSupportLines hasn't been fetched yet
export const COMMON_ALIYUN_LINES = [
  { code: "default", en: "Default", zh: "默认 (Default)" },
  { code: "telecom", en: "China Telecom", zh: "中国电信" },
  { code: "unicom", en: "China Unicom", zh: "中国联通" },
  { code: "mobile", en: "China Mobile", zh: "中国移动" },
  { code: "edu", en: "CERNET (EDU)", zh: "中国教育网" },
  { code: "oversea", en: "Overseas", zh: "境外" },
  { code: "drpeng", en: "Dr.Peng", zh: "鹏博士" },
  { code: "btvn", en: "China Broadcast", zh: "中国广电" },
  { code: "search", en: "Search Engine", zh: "搜索引擎" },
];

export function formatLineLabel(code, fetchedLines = []) {
  const c = String(code || "default").trim();
  const hit = (fetchedLines || []).find((l) => l.code === c);
  if (hit) return `${hit.name} (${hit.code})`;
  const fb = COMMON_ALIYUN_LINES.find((l) => l.code === c);
  if (fb) return currentLang === "zh-CN" ? `${fb.zh} (${fb.code})` : `${fb.en} (${fb.code})`;
  return c;
}
