// Lightweight passive browser fingerprint beacon served at /cdn-cgi/fp.js
// Runs asynchronously during browser idle time and reports once per TTL window.
(() => {
  try {
    const scriptEl = document.currentScript;
    const token = scriptEl && scriptEl.dataset ? scriptEl.dataset.t : "";
    if (!token) return;

    const collect = () => {
      let webgl = "";
      try {
        const c = document.createElement("canvas");
        const gl = c.getContext("webgl") || c.getContext("experimental-webgl");
        if (gl) {
          const dbg = gl.getExtension("WEBGL_debug_renderer_info");
          webgl = dbg
            ? `${gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL)}|${gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)}`
            : String(gl.getParameter(gl.RENDERER) || "");
        }
      } catch {}

      let canvasHash = "";
      try {
        const c = document.createElement("canvas");
        c.width = 160;
        c.height = 32;
        const ctx = c.getContext("2d");
        if (ctx) {
          ctx.fillStyle = "#0284c7";
          ctx.fillRect(4, 4, 40, 18);
          ctx.font = "14px sans-serif";
          ctx.fillStyle = "#e8eef7";
          ctx.fillText("browser-check", 8, 22);
          const d = c.toDataURL();
          let h = 2166136261;
          for (let i = 0; i < d.length; i++) {
            h ^= d.charCodeAt(i);
            h = Math.imul(h, 16777619);
          }
          canvasHash = (h >>> 0).toString(16);
        }
      } catch {}

      let tz = "";
      try {
        tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "";
      } catch {}

      let pluginsCount = 0;
      try {
        pluginsCount = navigator.plugins ? navigator.plugins.length : 0;
      } catch {}

      const dpr = String(window.devicePixelRatio || 1).slice(0, 16);

      return {
        webdriver: Boolean(navigator.webdriver),
        webgl: webgl.slice(0, 96),
        platform: String(navigator.platform || "").slice(0, 32),
        screen: `${screen.width || 0}x${screen.height || 0}x${screen.colorDepth || 0}`,
        tz: tz.slice(0, 48),
        lang: String(navigator.language || "").slice(0, 24),
        cores: Number(navigator.hardwareConcurrency || 0),
        mem: Number(navigator.deviceMemory || 0),
        touch: Number(navigator.maxTouchPoints || 0),
        canvas_hash: canvasHash,
        dpr,
        plugins_count: pluginsCount,
      };
    };

    const send = () => {
      try {
        const fp = collect();
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
      window.requestIdleCallback(send, { timeout: 1500 });
    } else {
      window.setTimeout(send, 150);
    }
  } catch {}
})();
