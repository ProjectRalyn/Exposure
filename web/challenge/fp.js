// Lightweight passive BrowserLeaks-grade fingerprint beacon served at /cdn-cgi/fp.js
// Runs asynchronously during browser idle time and reports once per TTL window.
import { collectBrowserLeaksFingerprint } from "./collector.js";

(() => {
  try {
    const scriptEl = document.currentScript;
    const token = scriptEl && scriptEl.dataset ? scriptEl.dataset.t : "";
    if (!token) return;
    const dedupKey = `exposure_fp_sent_${token.slice(0, 16)}`;
    try {
      if (window.sessionStorage && window.sessionStorage.getItem(dedupKey)) return;
      if (window.sessionStorage) window.sessionStorage.setItem(dedupKey, "1");
    } catch {}

    const send = async () => {
      try {
        const fp = await collectBrowserLeaksFingerprint();
        fetch("/cdn-cgi/fp-report", {
          method: "POST",
          credentials: "same-origin",
          keepalive: true,
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token, fp }),
        }).catch(() => {});
      } catch {}
    };

    if (typeof window.requestIdleCallback === "function") {
      window.requestIdleCallback(() => { void send(); }, { timeout: 1500 });
    } else {
      window.setTimeout(() => { void send(); }, 150);
    }
  } catch {}
})();
