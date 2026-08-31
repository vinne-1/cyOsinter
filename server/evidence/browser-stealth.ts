/**
 * Stealth hardening for the headless browser used to capture evidence.
 *
 * The evidence capture launches stock Chromium with `--no-sandbox` and a
 * User-Agent override. That combination fails the most basic automation checks:
 * `navigator.webdriver` is `true`, `Chrome/HeadlessChrome` appears in the UA
 * client hints, `window.chrome` is missing, the plugin and language arrays are
 * empty, and `Notification.permission` disagrees with the Permissions API.
 * Any one of those is enough for a site to serve a block page instead of the
 * content we are trying to screenshot — which silently degrades the report.
 *
 * ── What this is, and is not ────────────────────────────────────────────────
 * These are *driver-level* patches: stock Chromium plus JavaScript executed
 * before page scripts. That is the same tier as Patchright and puppeteer-extra's
 * stealth plugin, and it clears ordinary automation checks.
 *
 * It does NOT match an *engine-level* tool. Camoufox (Firefox) and CloakBrowser
 * (Chromium) patch fingerprint surfaces in C++ and recompile the binary, so
 * canvas, WebGL, audio and font metrics are consistent all the way down —
 * something injected JavaScript cannot fully achieve, because the injection
 * itself leaves traces (native-function `toString`, property descriptors,
 * prototype ordering).
 *
 * Adopting one of those is a deliberate future step, not a drop-in:
 *   - Patchright   — Apache-2.0, drop-in Playwright replacement. Cheapest win.
 *   - Camoufox     — engine-level Firefox, strongest fingerprint coverage, slow.
 *   - CloakBrowser — engine-level Chromium fork, drop-in for Playwright.
 *   - nodriver     — AGPL-3.0. The network-use copyleft is a real licensing
 *                    consideration for a self-hosted product and must be
 *                    reviewed before adoption.
 * Each ships its own browser binary, which materially changes the Docker image.
 */

/**
 * Chromium launch flags that remove automation signals.
 *
 * `--disable-blink-features=AutomationControlled` is the important one: without
 * it Blink sets `navigator.webdriver` at the engine level, where no amount of
 * page-side patching can convincingly remove it.
 */
export const STEALTH_LAUNCH_ARGS: readonly string[] = [
  "--disable-blink-features=AutomationControlled",
  "--no-sandbox",
  "--disable-dev-shm-usage",
  // Suppress the "Chrome is being controlled by automated test software" infobar
  // and the automation extension that advertises itself to page scripts.
  "--disable-infobars",
  "--exclude-switches=enable-automation",
  "--disable-features=IsolateOrigins,site-per-process,TranslateUI",
  // A default headless window is 800x600, which no real desktop reports.
  "--window-size=1920,1080",
  "--start-maximized",
  "--disable-background-timer-throttling",
  "--disable-backgrounding-occluded-windows",
  "--disable-renderer-backgrounding",
];

/** Context options that make the browser look like an ordinary desktop session. */
export interface StealthContextOptions {
  userAgent: string;
  viewport: { width: number; height: number };
  locale: string;
  timezoneId: string;
  deviceScaleFactor: number;
  isMobile: boolean;
  hasTouch: boolean;
  colorScheme: "light" | "dark";
  extraHTTPHeaders: Record<string, string>;
}

export function stealthContextOptions(userAgent: string): StealthContextOptions {
  return {
    userAgent,
    // 1920x1080 is the single most common desktop resolution; the viewport is
    // the usable area once browser chrome is subtracted.
    viewport: { width: 1920, height: 947 },
    locale: "en-US",
    timezoneId: "America/New_York",
    deviceScaleFactor: 1,
    isMobile: false,
    hasTouch: false,
    colorScheme: "light",
    // Client hints must agree with the UA string we are claiming.
    extraHTTPHeaders: {
      "accept-language": "en-US,en;q=0.9",
      "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
      "sec-ch-ua-mobile": "?0",
      "sec-ch-ua-platform": '"Windows"',
    },
  };
}

/**
 * Script evaluated in every frame BEFORE any page script runs.
 *
 * Each patch below corresponds to a check that public bot-detection test pages
 * (bot.sannysoft.com, CreepJS, fingerprint-scan) actually perform. Patches are
 * applied through `defineProperty` with the same descriptor shape the real
 * property has, because a detector can compare descriptors — an own, writable,
 * enumerable `webdriver` on the instance is as suspicious as `true`.
 */
export const STEALTH_INIT_SCRIPT = String.raw`
(() => {
  // ── navigator.webdriver ──
  // Deleting from the prototype is cleaner than assigning false: in a real
  // browser the property is absent entirely, not present-and-false.
  try {
    Object.defineProperty(Navigator.prototype, "webdriver", {
      get: () => undefined,
      configurable: true,
    });
    delete Object.getPrototypeOf(navigator).webdriver;
  } catch {}

  // ── window.chrome ──
  // Headless Chromium omits this object; every real Chrome has it.
  try {
    if (!window.chrome) {
      Object.defineProperty(window, "chrome", {
        value: {
          runtime: {},
          loadTimes: function () {},
          csi: function () {},
          app: { isInstalled: false, InstallState: {}, RunningState: {} },
        },
        configurable: true,
        writable: true,
      });
    }
  } catch {}

  // ── Permissions vs Notification.permission ──
  // Headless returns "denied" from Notification.permission while the Permissions
  // API reports "prompt". Real browsers agree; the mismatch is a classic check.
  try {
    const original = window.navigator.permissions.query.bind(window.navigator.permissions);
    window.navigator.permissions.query = (parameters) =>
      parameters && parameters.name === "notifications"
        ? Promise.resolve({ state: Notification.permission, onchange: null })
        : original(parameters);
  } catch {}

  // ── plugins and mimeTypes ──
  // Headless reports zero plugins. Real Chrome always exposes the five built-in
  // PDF entries, and detectors check both the length and the item() accessor.
  try {
    const pdfPlugins = [
      { name: "PDF Viewer", filename: "internal-pdf-viewer", description: "Portable Document Format" },
      { name: "Chrome PDF Viewer", filename: "internal-pdf-viewer", description: "Portable Document Format" },
      { name: "Chromium PDF Viewer", filename: "internal-pdf-viewer", description: "Portable Document Format" },
      { name: "Microsoft Edge PDF Viewer", filename: "internal-pdf-viewer", description: "Portable Document Format" },
      { name: "WebKit built-in PDF", filename: "internal-pdf-viewer", description: "Portable Document Format" },
    ];
    Object.defineProperty(Navigator.prototype, "plugins", {
      get: () => {
        const list = pdfPlugins.slice();
        list.item = (i) => list[i];
        list.namedItem = (n) => list.find((p) => p.name === n);
        list.refresh = () => {};
        return list;
      },
      configurable: true,
    });
  } catch {}

  // ── languages ──
  // Must agree with the Accept-Language header the context sends.
  try {
    Object.defineProperty(Navigator.prototype, "languages", {
      get: () => ["en-US", "en"],
      configurable: true,
    });
  } catch {}

  // ── hardware profile ──
  // Containers frequently report 1-2 cores and no deviceMemory at all, which
  // reads as a VM rather than a desktop.
  try {
    Object.defineProperty(Navigator.prototype, "hardwareConcurrency", { get: () => 8, configurable: true });
    Object.defineProperty(Navigator.prototype, "deviceMemory", { get: () => 8, configurable: true });
  } catch {}

  // ── WebGL vendor and renderer ──
  // Headless in a container reports SwiftShader (software rendering), which no
  // real desktop GPU does. Report a common discrete-GPU string instead.
  try {
    const patchGL = (proto) => {
      if (!proto) return;
      const getParameter = proto.getParameter;
      proto.getParameter = function (parameter) {
        // 37445 = UNMASKED_VENDOR_WEBGL, 37446 = UNMASKED_RENDERER_WEBGL
        if (parameter === 37445) return "Google Inc. (Intel)";
        if (parameter === 37446) return "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)";
        return getParameter.apply(this, arguments);
      };
    };
    patchGL(window.WebGLRenderingContext && WebGLRenderingContext.prototype);
    patchGL(window.WebGL2RenderingContext && WebGL2RenderingContext.prototype);
  } catch {}

  // ── hide the patches themselves ──
  // A patched method's toString() would otherwise reveal its JavaScript source
  // where a native one prints "[native code]". Detectors read this directly.
  try {
    const nativeToString = Function.prototype.toString;
    const patched = new WeakSet();
    for (const fn of [
      window.navigator.permissions && window.navigator.permissions.query,
      window.WebGLRenderingContext && WebGLRenderingContext.prototype.getParameter,
      window.WebGL2RenderingContext && WebGL2RenderingContext.prototype.getParameter,
    ]) {
      if (typeof fn === "function") patched.add(fn);
    }
    Function.prototype.toString = function () {
      if (patched.has(this)) return "function () { [native code] }";
      return nativeToString.call(this);
    };
    patched.add(Function.prototype.toString);
  } catch {}
})();
`;

/** Removes the headless marker Chromium leaves in its User-Agent. */
export function deheadlessUserAgent(userAgent: string): string {
  return userAgent.replace(/HeadlessChrome/gi, "Chrome");
}
