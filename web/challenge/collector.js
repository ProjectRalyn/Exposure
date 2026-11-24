// BrowserLeaks-inspired auxiliary client fingerprint collector.
// NOTE: Client JS signals are UNTRUSTED telemetry & tamper/headless detectors;
// server-side TLS/HTTP/AbuseIPDB signals remain the primary trust scoring authority.

function fnv1aHex(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

function collectCanvasHash() {
  try {
    const c = document.createElement("canvas");
    c.width = 240;
    c.height = 60;
    const ctx = c.getContext("2d");
    if (!ctx) return "";
    ctx.textBaseline = "alphabetic";
    const grad = ctx.createLinearGradient(0, 0, 240, 60);
    grad.addColorStop(0, "#0284c7");
    grad.addColorStop(0.5, "#6366f1");
    grad.addColorStop(1, "#ec4899");
    ctx.fillStyle = grad;
    ctx.fillRect(2, 2, 236, 56);

    ctx.beginPath();
    ctx.arc(42, 30, 18, 0, Math.PI * 2, true);
    ctx.arc(42, 30, 9, 0, Math.PI * 2, true);
    ctx.fillStyle = "rgba(255,255,255,0.65)";
    ctx.fill("evenodd");

    ctx.font = "15px 'Times New Roman', serif";
    ctx.fillStyle = "#0f172a";
    ctx.fillText("BrowserLeaks \u03c0 \u4e2d\u6587", 70, 24);
    ctx.font = "13px 'Courier New', monospace";
    ctx.fillStyle = "#f8fafc";
    ctx.fillText("Cwm fjordbank 123.45", 70, 44);
    return fnv1aHex(c.toDataURL());
  } catch {
    return "";
  }
}

function collectWebGl() {
  let webgl = "";
  let webgl_vendor = "";
  let webgl_ext_hash = "";
  let webgl_max_tex = 0;
  try {
    const c = document.createElement("canvas");
    const gl = c.getContext("webgl2") || c.getContext("webgl") || c.getContext("experimental-webgl");
    if (gl) {
      const dbg = gl.getExtension("WEBGL_debug_renderer_info");
      if (dbg) {
        webgl_vendor = String(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) || "");
        const rend = String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || "");
        webgl = webgl_vendor ? `${webgl_vendor}|${rend}` : rend;
      } else {
        webgl_vendor = String(gl.getParameter(gl.VENDOR) || "");
        webgl = String(gl.getParameter(gl.RENDERER) || "");
      }
      const exts = gl.getSupportedExtensions();
      if (Array.isArray(exts) && exts.length > 0) {
        webgl_ext_hash = fnv1aHex(exts.slice().sort().join(","));
      }
      webgl_max_tex = Math.max(0, Math.round(Number(gl.getParameter(gl.MAX_TEXTURE_SIZE) || 0)));
    }
  } catch {}
  return {
    webgl: webgl.slice(0, 96),
    webgl_vendor: webgl_vendor.slice(0, 64),
    webgl_ext_hash,
    webgl_max_tex,
  };
}

function collectFonts() {
  try {
    const c = document.createElement("canvas");
    const ctx = c.getContext("2d");
    if (!ctx) return { fonts_hash: "", fonts_count: 0 };
    const sample = "mmmmmmmmmmlli10OQ@W";
    const bases = ["monospace", "sans-serif", "serif"];
    const baseWidths = {};
    for (const b of bases) {
      ctx.font = `72px ${b}`;
      baseWidths[b] = ctx.measureText(sample).width;
    }
    const candidates = [
      "Arial", "Calibri", "Cambria", "Consolas", "Segoe UI", "Tahoma", "Verdana", "Trebuchet MS",
      "Georgia", "Times New Roman", "Courier New", "Impact", "Comic Sans MS", "Palatino",
      "Helvetica Neue", "SF Pro Display", "Menlo", "Monaco", "PingFang SC", "Hiragino Sans",
      "Microsoft YaHei", "SimSun", "Ubuntu", "DejaVu Sans", "Liberation Sans", "Noto Sans",
      "Roboto", "Cantarell",
    ];
    const detected = [];
    for (const f of candidates) {
      let matched = false;
      for (const b of bases) {
        ctx.font = `72px '${f}', ${b}`;
        if (Math.abs(ctx.measureText(sample).width - baseWidths[b]) > 0.25) {
          matched = true;
          break;
        }
      }
      if (matched) detected.push(f);
    }
    return {
      fonts_hash: detected.length ? fnv1aHex(detected.join(",")) : "",
      fonts_count: detected.length,
    };
  } catch {
    return { fonts_hash: "", fonts_count: 0 };
  }
}

async function collectAudioHash() {
  try {
    const Ctx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (!Ctx) return "";
    const renderPromise = new Promise((resolve) => {
      try {
        const ctx = new Ctx(1, 4410, 44100);
        const osc = ctx.createOscillator();
        osc.type = "triangle";
        osc.frequency.setValueAtTime(10000, ctx.currentTime);
        const comp = ctx.createDynamicsCompressor();
        comp.threshold.setValueAtTime(-50, ctx.currentTime);
        comp.knee.setValueAtTime(40, ctx.currentTime);
        comp.ratio.setValueAtTime(12, ctx.currentTime);
        comp.attack.setValueAtTime(0, ctx.currentTime);
        comp.release.setValueAtTime(0.25, ctx.currentTime);
        osc.connect(comp);
        comp.connect(ctx.destination);
        osc.start(0);
        ctx.oncomplete = (ev) => {
          try {
            const buf = ev.renderedBuffer.getChannelData(0);
            let acc = "";
            for (let i = 450; i < Math.min(buf.length, 650); i += 4) {
              acc += Math.round(buf[i] * 1e6).toString(36) + ",";
            }
            resolve(fnv1aHex(acc));
          } catch {
            resolve("");
          }
        };
        const p = ctx.startRendering();
        if (p && typeof p.then === "function") {
          p.then((rendered) => {
            try {
              const buf = rendered.getChannelData(0);
              let acc = "";
              for (let i = 450; i < Math.min(buf.length, 650); i += 4) {
                acc += Math.round(buf[i] * 1e6).toString(36) + ",";
              }
              resolve(fnv1aHex(acc));
            } catch {
              resolve("");
            }
          }).catch(() => resolve(""));
        }
      } catch {
        resolve("");
      }
    });
    const timeoutPromise = new Promise((resolve) => setTimeout(() => resolve(""), 250));
    return await Promise.race([renderPromise, timeoutPromise]);
  } catch {
    return "";
  }
}

function collectMediaPrefs() {
  const flags = [];
  const mm = (q) => {
    try {
      return Boolean(window.matchMedia && window.matchMedia(q).matches);
    } catch {
      return false;
    }
  };
  if (mm("(prefers-color-scheme: dark)")) flags.push("dark");
  else if (mm("(prefers-color-scheme: light)")) flags.push("light");
  if (mm("(prefers-reduced-motion: reduce)")) flags.push("reduced-motion");
  if (mm("(color-gamut: p3)")) flags.push("p3");
  else if (mm("(color-gamut: srgb)")) flags.push("srgb");
  if (mm("(dynamic-range: high)")) flags.push("hdr");
  if (mm("(hover: hover)")) flags.push("hover");
  if (mm("(pointer: fine)")) flags.push("fine");
  else if (mm("(pointer: coarse)")) flags.push("coarse");
  return flags.join(",").slice(0, 64);
}

function collectStorageAndCaps() {
  const flags = [];
  try { if (window.localStorage) flags.push("ls"); } catch {}
  try { if (window.sessionStorage) flags.push("ss"); } catch {}
  try { if (window.indexedDB) flags.push("idb"); } catch {}
  try { if (navigator.cookieEnabled) flags.push("cookie"); } catch {}
  try { if ("serviceWorker" in navigator) flags.push("sw"); } catch {}
  try { if (typeof window.RTCPeerConnection === "function") flags.push("webrtc"); } catch {}
  try { if ("gpu" in navigator) flags.push("webgpu"); } catch {}
  try { if (typeof WebAssembly === "object") flags.push("wasm"); } catch {}
  try { if (navigator.pdfViewerEnabled) flags.push("pdf"); } catch {}
  return flags.join(",").slice(0, 64);
}

function collectTamperFlags() {
  const flags = [];
  try { if (navigator.webdriver) flags.push("webdriver"); } catch {}
  try {
    if (window.__playwright || window.__pw_manual || window.__PW_inspect) {
      flags.push("playwright");
    }
  } catch {}
  try {
    if (window.__puppeteer_evaluation_script__) flags.push("puppeteer");
  } catch {}
  try {
    if (
      window._selenium ||
      window.callSelenium ||
      window.__webdriver_evaluate ||
      window.__driver_evaluate ||
      document.__webdriver_evaluate ||
      Object.keys(document).some((k) => k.startsWith("$cdc_"))
    ) {
      flags.push("selenium");
    }
  } catch {}
  try {
    if (window._phantom || window.callPhantom || window.__nightmare) {
      flags.push("phantom");
    }
  } catch {}
  try {
    if (window.outerWidth === 0 && window.outerHeight === 0) {
      flags.push("zero_outer_dims");
    }
  } catch {}
  try {
    const s = Function.prototype.toString.call(HTMLCanvasElement.prototype.toDataURL);
    if (s && !s.includes("[native code]")) {
      flags.push("native_fn_tampered");
    }
  } catch {}
  return flags.slice(0, 12);
}

function parseCandidateHostIps(rawLine, publicIps, localIps, state) {
  if (!rawLine || typeof rawLine !== "string") return;
  const tokens = rawLine.trim().split(/\s+/);
  const candidates = [];
  if (tokens.length >= 5 && (tokens[0].startsWith("candidate:") || tokens[0].startsWith("a=candidate:"))) {
    candidates.push(tokens[4]);
  }
  const raddrIdx = tokens.indexOf("raddr");
  if (raddrIdx !== -1 && tokens[raddrIdx + 1]) {
    candidates.push(tokens[raddrIdx + 1]);
  }
  if (!candidates.length) candidates.push(rawLine.trim());

  for (const rawHost of candidates) {
    const host = String(rawHost || "").trim().replace(/^\[|\]$/g, "").split("%")[0];
    if (!host) continue;
    if (host.endsWith(".local")) {
      state.mdns = true;
      continue;
    }
    const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
    if (ipv4) {
      const oct = [Number(ipv4[1]), Number(ipv4[2]), Number(ipv4[3]), Number(ipv4[4])];
      if (oct.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) continue;
      const isPriv =
        oct[0] === 0 ||
        oct[0] === 10 ||
        oct[0] === 127 ||
        (oct[0] === 169 && oct[1] === 254) ||
        (oct[0] === 172 && oct[1] >= 16 && oct[1] <= 31) ||
        (oct[0] === 192 && oct[1] === 168) ||
        (oct[0] === 100 && oct[1] >= 64 && oct[1] <= 127) ||
        oct[0] >= 224;
      const norm = oct.join(".");
      const target = isPriv ? localIps : publicIps;
      if (target.length < 4 && !target.includes(norm)) target.push(norm);
      continue;
    }
    if (host.includes(":") && /^[0-9a-fA-F:]+$/.test(host)) {
      const low = host.toLowerCase();
      const isPrivV6 =
        low === "::1" ||
        low === "::" ||
        low.startsWith("fe80:") ||
        low.startsWith("fc") ||
        low.startsWith("fd") ||
        low.startsWith("ff") ||
        low.startsWith("::ffff:");
      const target = isPrivV6 ? localIps : publicIps;
      if (target.length < 4 && !target.includes(low)) target.push(low);
    }
  }
}

async function collectWebRtcLeak() {
  const empty = (status) => ({
    webrtc_status: status,
    webrtc_public_ips: [],
    webrtc_local_ips: [],
    webrtc_mdns: false,
  });
  let RTC;
  try {
    RTC = window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
  } catch {
    return empty("blocked");
  }
  if (typeof RTC !== "function") {
    return empty("unsupported");
  }

  return new Promise((resolve) => {
    let pc = null;
    let settled = false;
    let hardTimer = null;
    let earlyTimer = null;
    const publicIps = [];
    const localIps = [];
    const state = { mdns: false };

    const finish = () => {
      if (settled) return;
      settled = true;
      if (hardTimer) clearTimeout(hardTimer);
      if (earlyTimer) clearTimeout(earlyTimer);
      try {
        if (pc && pc.localDescription && pc.localDescription.sdp) {
          for (const line of pc.localDescription.sdp.split(/\r?\n/)) {
            if (line.startsWith("a=candidate:")) {
              parseCandidateHostIps(line, publicIps, localIps, state);
            }
          }
        }
      } catch {}
      try {
        if (pc) {
          pc.onicecandidate = null;
          pc.onicegatheringstatechange = null;
          pc.close();
        }
      } catch {}
      let status = "no_candidates";
      if (publicIps.length || localIps.length) status = "leaked";
      else if (state.mdns) status = "mdns_only";
      resolve({
        webrtc_status: status,
        webrtc_public_ips: publicIps,
        webrtc_local_ips: localIps,
        webrtc_mdns: state.mdns,
      });
    };

    try {
      pc = new RTC({
        iceServers: [
          { urls: ["stun:stun.cloudflare.com:3478", "stun:stun.l.google.com:19302"] },
        ],
      });
      hardTimer = setTimeout(finish, 1200);
      pc.onicecandidate = (ev) => {
        if (!ev || !ev.candidate) {
          finish();
          return;
        }
        const cand = ev.candidate;
        if (cand.address) parseCandidateHostIps(cand.address, publicIps, localIps, state);
        if (cand.candidate) parseCandidateHostIps(cand.candidate, publicIps, localIps, state);
        if (publicIps.length > 0 && !earlyTimer) {
          earlyTimer = setTimeout(finish, 150);
        }
      };
      pc.onicegatheringstatechange = () => {
        if (pc && pc.iceGatheringState === "complete") finish();
      };
      pc.createDataChannel("p");
      pc.createOffer()
        .then((offer) => pc.setLocalDescription(offer))
        .catch(() => {
          settled = true;
          if (hardTimer) clearTimeout(hardTimer);
          if (earlyTimer) clearTimeout(earlyTimer);
          try { pc.close(); } catch {}
          resolve(empty("blocked"));
        });
    } catch {
      settled = true;
      if (hardTimer) clearTimeout(hardTimer);
      if (earlyTimer) clearTimeout(earlyTimer);
      try { if (pc) pc.close(); } catch {}
      resolve(empty("blocked"));
    }
  });
}

export async function collectBrowserLeaksFingerprint() {
  const gl = collectWebGl();
  const canvas_hash = collectCanvasHash();
  const fonts = collectFonts();
  const [audio_hash, webrtc] = await Promise.all([collectAudioHash(), collectWebRtcLeak()]);

  let tz = "";
  let intl_locale = "";
  try {
    const opts = Intl.DateTimeFormat().resolvedOptions();
    tz = opts.timeZone || "";
    intl_locale = opts.locale || "";
  } catch {}

  let tz_offset = 0;
  try {
    tz_offset = Math.round(Number(new Date().getTimezoneOffset() || 0));
  } catch {}

  let languages = "";
  try {
    if (Array.isArray(navigator.languages)) {
      languages = navigator.languages.slice(0, 8).join(",");
    }
  } catch {}

  let ua_brands = "";
  try {
    if (navigator.userAgentData && Array.isArray(navigator.userAgentData.brands)) {
      ua_brands = navigator.userAgentData.brands
        .map((b) => `${b.brand}/${b.version}`)
        .join(",");
    }
  } catch {}

  let plugins_count = 0;
  try {
    plugins_count = navigator.plugins ? navigator.plugins.length : 0;
  } catch {}

  let speech_voices = 0;
  try {
    if (window.speechSynthesis && typeof window.speechSynthesis.getVoices === "function") {
      speech_voices = window.speechSynthesis.getVoices().length;
    }
  } catch {}

  return {
    webdriver: Boolean(navigator.webdriver),
    webgl: gl.webgl,
    webgl_vendor: gl.webgl_vendor,
    webgl_ext_hash: gl.webgl_ext_hash,
    webgl_max_tex: gl.webgl_max_tex,
    platform: String(navigator.platform || "").slice(0, 32),
    screen: `${screen.width || 0}x${screen.height || 0}x${screen.colorDepth || 0}`,
    avail_screen: `${screen.availWidth || 0}x${screen.availHeight || 0}`,
    tz: tz.slice(0, 48),
    tz_offset,
    intl_locale: intl_locale.slice(0, 48),
    lang: String(navigator.language || "").slice(0, 24),
    languages: languages.slice(0, 96),
    ua_brands: ua_brands.slice(0, 96),
    cores: Math.max(0, Math.round(Number(navigator.hardwareConcurrency || 0))),
    mem: Math.max(0, Math.round(Number(navigator.deviceMemory || 0))),
    touch: Math.max(0, Math.round(Number(navigator.maxTouchPoints || 0))),
    canvas_hash,
    audio_hash,
    fonts_hash: fonts.fonts_hash,
    fonts_count: fonts.fonts_count,
    dpr: String(window.devicePixelRatio || 1).slice(0, 16),
    media_prefs: collectMediaPrefs(),
    storage_flags: collectStorageAndCaps(),
    plugins_count: Math.max(0, Math.round(Number(plugins_count || 0))),
    speech_voices: Math.max(0, Math.round(Number(speech_voices || 0))),
    tamper_flags: collectTamperFlags(),
    webrtc_status: webrtc.webrtc_status,
    webrtc_public_ips: webrtc.webrtc_public_ips,
    webrtc_local_ips: webrtc.webrtc_local_ips,
    webrtc_mdns: webrtc.webrtc_mdns,
  };
}
