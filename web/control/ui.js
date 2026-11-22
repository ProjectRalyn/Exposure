// Reusable DOM, Drawer, Modal, Slider & Formatting UI Helpers
import { t } from "./i18n.js";

export const el = (id) => document.getElementById(id);

export function esc(v) {
  return String(v ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function parseNum(raw, fallback, min = -Infinity, max = Infinity) {
  if (raw === "" || raw == null) return fallback;
  const n = Number(raw);
  if (Number.isNaN(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

export function shellQuote(v) {
  return `'${String(v ?? "").replace(/'/g, `'\\''`)}'`;
}

export function generateRandomSecretHex(bytes = 32) {
  const buf = new Uint8Array(bytes);
  if (globalThis.crypto?.getRandomValues) {
    globalThis.crypto.getRandomValues(buf);
  } else {
    for (let i = 0; i < bytes; i++) buf[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
}

export async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    showToast(t("common.copied"));
    return true;
  } catch {
    showToast("Clipboard unavailable", true);
    return false;
  }
}

export function showToast(msg, isError = false) {
  const stack = el("toast-stack");
  if (!stack) return;
  const item = document.createElement("div");
  const err = isError === true || isError === "error";
  item.className = `toast-item ${err ? "error" : ""}`;
  item.textContent = msg;
  stack.appendChild(item);
  setTimeout(() => {
    item.style.opacity = "0";
    item.style.transition = "opacity 0.2s";
    setTimeout(() => item.remove(), 220);
  }, 4200);
}

/* ==================== MODAL ==================== */

export function openModal({ title, bodyHtml, actions = [] }) {
  el("modal-title").textContent = title;
  el("modal-body").innerHTML = bodyHtml;
  const foot = el("modal-footer");
  foot.innerHTML = "";
  for (const act of actions) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = `btn ${act.cls || ""}`;
    btn.textContent = act.label;
    btn.addEventListener("click", () => {
      if (act.onClick) act.onClick();
      if (act.close !== false) closeModal();
    });
    foot.appendChild(btn);
  }
  el("modal-backdrop").classList.remove("hidden");
}

export function closeModal() {
  el("modal-backdrop")?.classList.add("hidden");
}

/* ==================== SLIDE-OVER DRAWER ==================== */

let drawerOnClose = null;

export function openDrawer({ title, subtitle = "", bodyHtml = "", footerHtml = "", wide = false, onClose = null }) {
  const backdrop = el("drawer-backdrop");
  const panel = el("drawer-panel");
  if (!backdrop || !panel) return;
  drawerOnClose = onClose;
  panel.classList.toggle("wide", Boolean(wide));
  el("drawer-title").textContent = title;
  const subEl = el("drawer-subtitle");
  if (subEl) {
    subEl.textContent = subtitle;
    subEl.classList.toggle("hidden", !subtitle);
  }
  el("drawer-body").innerHTML = bodyHtml;
  const foot = el("drawer-footer");
  if (foot) {
    foot.innerHTML = footerHtml;
    foot.classList.toggle("hidden", !footerHtml);
  }
  backdrop.classList.remove("hidden");
  return {
    body: el("drawer-body"),
    footer: foot,
    close: closeDrawer,
  };
}

export function closeDrawer() {
  const backdrop = el("drawer-backdrop");
  if (backdrop) backdrop.classList.add("hidden");
  const cb = drawerOnClose;
  drawerOnClose = null;
  if (cb) cb();
}

export function initOverlayControls() {
  el("btn-modal-close")?.addEventListener("click", closeModal);
  el("modal-backdrop")?.addEventListener("click", (ev) => {
    if (ev.target === el("modal-backdrop")) closeModal();
  });
  el("btn-drawer-close")?.addEventListener("click", closeDrawer);
  el("drawer-backdrop")?.addEventListener("click", (ev) => {
    if (ev.target === el("drawer-backdrop")) closeDrawer();
  });
  window.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") {
      if (!el("modal-backdrop")?.classList.contains("hidden")) {
        closeModal();
      } else if (!el("drawer-backdrop")?.classList.contains("hidden")) {
        closeDrawer();
      }
    }
  });
}

/* ==================== TRI-STATE & BINARY SLIDERS ==================== */

export function renderTriSlider({ attrName, attrVal, label, sub = "", val = null, inherited = false }) {
  const cur = val === true ? "on" : val === false ? "off" : "default";
  const inhText = inherited ? t("common.on") : t("common.off");
  const defText = `${t("common.default")} (${inhText})`;
  return `
    <div class="tri-row">
      <div class="tri-label-wrap">
        <span class="tri-label">${esc(label)}</span>
        ${sub ? `<span class="tri-sub">${esc(sub)}</span>` : ""}
      </div>
      <div class="tri-slider" role="radiogroup" aria-label="${esc(label)}" ${attrName}="${esc(attrVal)}">
        <button type="button" class="tri-opt ${cur === "default" ? "active" : ""}" data-tri-val="default">${esc(defText)}</button>
        <button type="button" class="tri-opt ${cur === "off" ? "active" : ""}" data-tri-val="off">${esc(t("common.off"))}</button>
        <button type="button" class="tri-opt ${cur === "on" ? "active" : ""}" data-tri-val="on">${esc(t("common.on"))}</button>
      </div>
    </div>`;
}

export function renderBinSlider({ attrName, attrVal, label, sub = "", val = false }) {
  const on = Boolean(val);
  return `
    <div class="tri-row">
      <div class="tri-label-wrap">
        <span class="tri-label">${esc(label)}</span>
        ${sub ? `<span class="tri-sub">${esc(sub)}</span>` : ""}
      </div>
      <div class="bin-slider" role="radiogroup" aria-label="${esc(label)}" ${attrName}="${esc(attrVal)}">
        <button type="button" class="bin-opt ${!on ? "active" : ""}" data-bin-val="off">${esc(t("common.off"))}</button>
        <button type="button" class="bin-opt ${on ? "active" : ""}" data-bin-val="on">${esc(t("common.on"))}</button>
      </div>
    </div>`;
}

export function wireTriSliders(root, attrName, onChange) {
  root.querySelectorAll(`.tri-slider[${attrName}]`).forEach((group) => {
    const key = group.getAttribute(attrName);
    group.querySelectorAll(".tri-opt").forEach((btn) => {
      btn.addEventListener("click", () => {
        const raw = btn.dataset.triVal;
        const next = raw === "on" ? true : raw === "off" ? false : null;
        group.querySelectorAll(".tri-opt").forEach((b) => b.classList.toggle("active", b === btn));
        onChange(key, next);
      });
    });
  });
}

export function wireBinSliders(root, attrName, onChange) {
  root.querySelectorAll(`.bin-slider[${attrName}]`).forEach((group) => {
    const key = group.getAttribute(attrName);
    group.querySelectorAll(".bin-opt").forEach((btn) => {
      btn.addEventListener("click", () => {
        const next = btn.dataset.binVal === "on";
        group.querySelectorAll(".bin-opt").forEach((b) => b.classList.toggle("active", b === btn));
        onChange(key, next);
      });
    });
  });
}
