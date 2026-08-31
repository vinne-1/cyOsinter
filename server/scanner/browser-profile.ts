/**
 * Coherent browser identities for outbound requests.
 *
 * The scanner previously sent a Chrome User-Agent and nothing else. That is one
 * of the cheapest tells there is: real Chrome 124 always accompanies its UA with
 * `sec-ch-ua`, `sec-ch-ua-platform`, the four `Sec-Fetch-*` hints and a very
 * specific `Accept` string. A request claiming to be Chrome while sending none
 * of them is filtered by Cloudflare, DataDome and Akamai on the first hop —
 * before any behavioural analysis runs.
 *
 * A profile here is an *internally consistent set*: the UA, the client hints,
 * the Accept family and the platform all describe the same browser on the same
 * OS. Mixing them (a Firefox UA with Chrome's `sec-ch-ua`) is a stronger signal
 * than sending nothing, so profiles are always applied whole.
 *
 * ── What this does NOT fix ───────────────────────────────────────────────────
 * Header realism is layer 1 of roughly four. The deeper tells are below the
 * HTTP layer and are NOT addressable from Node's `fetch`:
 *
 *   - TLS fingerprint (JA3/JA4). Node/undici has a distinct cipher and
 *     extension order that does not match any shipping browser. Defeating this
 *     needs curl-impersonate / curl_cffi, or a real browser engine.
 *   - HTTP/2 fingerprint (Akamai). SETTINGS frame values, window size and
 *     pseudo-header order differ from Chrome's.
 *   - Header ORDER. undici normalises and re-orders headers, so we can control
 *     which headers are sent but not the wire order Chrome would use.
 *
 * So this raises the floor against naive filtering; it is not a Cloudflare
 * bypass. Anything behind a serious anti-bot must go through a real browser —
 * see `server/evidence/browser-stealth.ts`.
 */

export type BrowserEngine = "chrome" | "firefox" | "safari";
export type Platform = "windows" | "macos" | "linux";

export interface BrowserProfile {
  id: string;
  engine: BrowserEngine;
  platform: Platform;
  userAgent: string;
  /**
   * Headers for a top-level document request, in the order the real browser
   * emits them. Order is preserved here for documentation value and for any
   * transport that honours it, even though undici will re-order on the wire.
   */
  headers: Record<string, string>;
}

/** Chrome's Accept header for a navigation request, byte for byte. */
const CHROME_ACCEPT =
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
const FIREFOX_ACCEPT =
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
const SAFARI_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

/**
 * Builds Chrome's `sec-ch-ua` value. The "Not-A.Brand" entry is deliberate
 * GREASE — Chrome injects a nonsense brand so servers cannot assume a fixed
 * list. Omitting it is itself a fingerprint.
 */
function chromeBrands(major: number): string {
  return `"Chromium";v="${major}", "Google Chrome";v="${major}", "Not-A.Brand";v="99"`;
}

function chromeProfile(id: string, platform: Platform, major: number, uaPlatform: string): BrowserProfile {
  const platformToken =
    platform === "windows"
      ? "Windows NT 10.0; Win64; x64"
      : platform === "macos"
        ? "Macintosh; Intel Mac OS X 10_15_7"
        : "X11; Linux x86_64";

  return {
    id,
    engine: "chrome",
    platform,
    userAgent: `Mozilla/5.0 (${platformToken}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${major}.0.0.0 Safari/537.36`,
    headers: {
      "sec-ch-ua": chromeBrands(major),
      "sec-ch-ua-mobile": "?0",
      "sec-ch-ua-platform": `"${uaPlatform}"`,
      "upgrade-insecure-requests": "1",
      "user-agent": `Mozilla/5.0 (${platformToken}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${major}.0.0.0 Safari/537.36`,
      accept: CHROME_ACCEPT,
      "sec-fetch-site": "none",
      "sec-fetch-mode": "navigate",
      "sec-fetch-user": "?1",
      "sec-fetch-dest": "document",
      "accept-encoding": "gzip, deflate, br",
      "accept-language": "en-US,en;q=0.9",
    },
  };
}

function firefoxProfile(id: string, platform: Platform, major: number): BrowserProfile {
  const platformToken =
    platform === "windows"
      ? "Windows NT 10.0; Win64; x64"
      : platform === "macos"
        ? "Macintosh; Intel Mac OS X 10.15"
        : "X11; Linux x86_64";
  const ua = `Mozilla/5.0 (${platformToken}; rv:${major}.0) Gecko/20100101 Firefox/${major}.0`;

  return {
    id,
    engine: "firefox",
    platform,
    userAgent: ua,
    // Firefox sends NO sec-ch-ua headers at all — client hints are a Chromium
    // feature. Adding them to a Firefox UA is a contradiction a detector reads
    // immediately.
    headers: {
      "user-agent": ua,
      accept: FIREFOX_ACCEPT,
      "accept-language": "en-US,en;q=0.5",
      "accept-encoding": "gzip, deflate, br",
      "upgrade-insecure-requests": "1",
      "sec-fetch-dest": "document",
      "sec-fetch-mode": "navigate",
      "sec-fetch-site": "none",
      "sec-fetch-user": "?1",
    },
  };
}

function safariProfile(id: string, version: string): BrowserProfile {
  const ua = `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${version} Safari/605.1.15`;
  return {
    id,
    engine: "safari",
    // Safari only ships on Apple platforms; a "Safari on Windows" UA has not
    // been real since 2012 and is a common scraper mistake.
    platform: "macos",
    userAgent: ua,
    headers: {
      accept: SAFARI_ACCEPT,
      "user-agent": ua,
      "accept-language": "en-US,en;q=0.9",
      "accept-encoding": "gzip, deflate, br",
    },
  };
}

/**
 * The rotation pool. Weighted toward Chrome on Windows because that is what the
 * traffic actually looks like — a pool of exotic browsers is itself anomalous.
 */
export const BROWSER_PROFILES: readonly BrowserProfile[] = [
  chromeProfile("chrome-124-win", "windows", 124, "Windows"),
  chromeProfile("chrome-123-win", "windows", 123, "Windows"),
  chromeProfile("chrome-124-mac", "macos", 124, "macOS"),
  chromeProfile("chrome-124-linux", "linux", 124, "Linux"),
  firefoxProfile("firefox-125-win", "windows", 125),
  firefoxProfile("firefox-125-mac", "macos", 125),
  safariProfile("safari-17-mac", "17.4"),
];

/** The profile used when rotation is off — a plain, extremely common identity. */
export const DEFAULT_PROFILE: BrowserProfile = BROWSER_PROFILES[0]!;

export function profileById(id: string): BrowserProfile | undefined {
  return BROWSER_PROFILES.find((p) => p.id === id);
}

/**
 * Headers for a sub-resource (API/XHR) rather than a navigation.
 *
 * `Sec-Fetch-Dest: document` on a JSON endpoint is incoherent: a browser only
 * sends that for a top-level navigation. Detectors check exactly this.
 */
export function subResourceHeaders(profile: BrowserProfile): Record<string, string> {
  const headers: Record<string, string> = { ...profile.headers };

  if (profile.engine === "chrome" || profile.engine === "firefox") {
    headers["sec-fetch-dest"] = "empty";
    headers["sec-fetch-mode"] = "cors";
    headers["sec-fetch-site"] = "same-origin";
    // Sec-Fetch-User is only ever sent for user-initiated navigations.
    delete headers["sec-fetch-user"];
    delete headers["upgrade-insecure-requests"];
  }
  headers.accept = "application/json, text/plain, */*";
  return headers;
}

/**
 * Merges a profile's headers with caller overrides.
 *
 * Caller keys win, and comparison is case-insensitive: a caller passing
 * `User-Agent` must not end up alongside the profile's `user-agent`, which
 * would send the header twice with different values — a far louder signal than
 * either header alone.
 */
export function mergeHeaders(
  profileHeaders: Record<string, string>,
  overrides?: HeadersInit,
): Record<string, string> {
  const out: Record<string, string> = { ...profileHeaders };
  if (!overrides) return out;

  const entries: Array<[string, string]> =
    overrides instanceof Headers
      ? Array.from(overrides.entries())
      : Array.isArray(overrides)
        ? (overrides as Array<[string, string]>)
        : Object.entries(overrides as Record<string, string>);

  for (const [key, value] of entries) {
    const lower = key.toLowerCase();
    for (const existing of Object.keys(out)) {
      if (existing.toLowerCase() === lower) delete out[existing];
    }
    out[lower] = value;
  }
  return out;
}
