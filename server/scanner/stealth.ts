import { AsyncLocalStorage } from "node:async_hooks";

/**
 * Stealth engine — centralizes outbound request pacing, concurrency, and
 * User-Agent presentation for the scanner.
 *
 * The scanner has three modes:
 *  - "standard": capped breadth, fast (default).
 *  - "gold":     full breadth, fast and loud (aggressive).
 *  - "safe":     full breadth, but low-and-slow — a single global concurrency
 *                cap, jittered inter-request delays, and rotating browser-like
 *                User-Agents so a full-coverage scan stays quiet.
 *
 * Every outbound HTTP request in `http.ts` is routed through the active
 * {@link StealthController} (resolved from an AsyncLocalStorage context set by
 * the scan entrypoint). When no context is active, a passthrough default
 * controller is used so existing callers and tests behave exactly as before.
 */

export type ScanMode = "standard" | "gold" | "safe";

export interface NucleiProfile {
  /** requests per second cap passed to nuclei -rate-limit */
  rateLimit: number;
  /** nuclei -concurrency (parallel templates) */
  concurrency: number;
  /** nuclei -bulk-size (hosts per template) */
  bulkSize: number;
  /** hard wall-clock cap for the nuclei process */
  maxDurationMs: number;
  /** run the full template set (all severities) vs a targeted subset */
  allTemplates: boolean;
  /** milliseconds of random jitter between requests (nuclei -jitter) */
  jitterMs: number;
}

export interface ScanProfile {
  mode: ScanMode;
  /** use full wordlists / all ports / all templates (gold + safe) */
  fullCoverage: boolean;
  /** low-and-slow pacing active */
  stealth: boolean;
  /** global cap on concurrent outbound HTTP requests */
  httpConcurrency: number;
  /** min inter-request delay in ms (0 = no pacing) */
  minDelayMs: number;
  /** max inter-request delay in ms (0 = no pacing) */
  maxDelayMs: number;
  /** cap for DNS brute-force fan-out */
  dnsConcurrency: number;
  /** rotate through a browser-like User-Agent pool */
  rotateUserAgent: boolean;
  /** run intrusive/noisy probes (WAF bypass, aggressive DAST) */
  allowIntrusive: boolean;
  nuclei: NucleiProfile;
}

/**
 * Rotating pool of current, realistic desktop browser User-Agents. Used in
 * stealth mode so requests do not advertise a scanner. The passthrough default
 * uses a single modern Chrome UA (still browser-like, not "Cyshield-Scanner").
 */
export const USER_AGENTS: readonly string[] = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
];

export const DEFAULT_USER_AGENT = USER_AGENTS[0];

const STANDARD_PROFILE: ScanProfile = {
  mode: "standard",
  fullCoverage: false,
  stealth: false,
  httpConcurrency: 64,
  minDelayMs: 0,
  maxDelayMs: 0,
  dnsConcurrency: 20,
  rotateUserAgent: false,
  allowIntrusive: false,
  nuclei: { rateLimit: 100, concurrency: 15, bulkSize: 15, maxDurationMs: 8 * 60 * 1000, allTemplates: false, jitterMs: 0 },
};

const GOLD_PROFILE: ScanProfile = {
  mode: "gold",
  fullCoverage: true,
  stealth: false,
  httpConcurrency: 64,
  minDelayMs: 0,
  maxDelayMs: 0,
  dnsConcurrency: 40,
  rotateUserAgent: false,
  allowIntrusive: true,
  nuclei: { rateLimit: 150, concurrency: 25, bulkSize: 25, maxDurationMs: 30 * 60 * 1000, allTemplates: true, jitterMs: 0 },
};

const SAFE_PROFILE: ScanProfile = {
  mode: "safe",
  fullCoverage: true,
  stealth: true,
  httpConcurrency: 2,
  // Low-and-slow but not impractically so: pacing serializes dispatches, so
  // effective throughput is ~1/avgDelay ≈ 1.5 req/s — 30-60x quieter than the
  // default scanner burst, yet a full-coverage scan still finishes in a
  // reasonable window. Randomized jitter avoids a fixed request cadence.
  minDelayMs: 300,
  maxDelayMs: 1000,
  dnsConcurrency: 4,
  rotateUserAgent: true,
  allowIntrusive: false,
  // Full templates for coverage, but paced to a crawl: ~8 req/s, low parallelism,
  // extra jitter, and a generous wall-clock budget because it is slow by design.
  nuclei: { rateLimit: 8, concurrency: 3, bulkSize: 5, maxDurationMs: 60 * 60 * 1000, allTemplates: true, jitterMs: 400 },
};

/** Resolve a scan profile from a mode string. Unknown modes fall back to standard. */
export function resolveProfile(mode?: string | null): ScanProfile {
  switch (mode) {
    case "safe":
      return SAFE_PROFILE;
    case "gold":
      return GOLD_PROFILE;
    default:
      return STANDARD_PROFILE;
  }
}

/**
 * Governs outbound request pacing, concurrency, and UA presentation for a
 * single scan. Requests acquire a slot (bounded by httpConcurrency), then wait
 * a jittered interval since the last dispatch before firing.
 */
export class StealthController {
  private active = 0;
  private readonly waiters: Array<() => void> = [];
  private lastDispatch = 0;
  private uaIndex = 0;

  constructor(public readonly profile: ScanProfile) {}

  private acquireSlot(): Promise<void> {
    if (this.active < this.profile.httpConcurrency) {
      this.active++;
      return Promise.resolve();
    }
    return new Promise<void>((resolve) => {
      this.waiters.push(() => {
        this.active++;
        resolve();
      });
    });
  }

  private releaseSlot(): void {
    this.active--;
    const next = this.waiters.shift();
    if (next) next();
  }

  /** Enforce a jittered gap between successive dispatches (no-op when unpaced). */
  private async pace(): Promise<void> {
    if (this.profile.maxDelayMs <= 0) return;
    const { minDelayMs, maxDelayMs } = this.profile;
    const jitter = minDelayMs + Math.random() * Math.max(0, maxDelayMs - minDelayMs);
    const now = Date.now();
    const scheduled = Math.max(now, this.lastDispatch + jitter);
    this.lastDispatch = scheduled;
    const wait = scheduled - now;
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  }

  /** Run an async task under the controller's concurrency + pacing budget. */
  async run<T>(fn: () => Promise<T>): Promise<T> {
    await this.acquireSlot();
    try {
      await this.pace();
      return await fn();
    } finally {
      this.releaseSlot();
    }
  }

  /** Next User-Agent to present (rotates in stealth mode; fixed otherwise). */
  nextUserAgent(): string {
    if (!this.profile.rotateUserAgent) return DEFAULT_USER_AGENT;
    const ua = USER_AGENTS[this.uaIndex % USER_AGENTS.length];
    this.uaIndex++;
    return ua;
  }
}

const store = new AsyncLocalStorage<StealthController>();
const DEFAULT_CONTROLLER = new StealthController(STANDARD_PROFILE);

/**
 * Shared outbound-fetch helper used by every target-facing scanner module.
 * Applies the active stealth profile (concurrency, pacing, rotating UA) and a
 * hard timeout. A caller-supplied `User-Agent` in `init.headers` overrides the
 * rotating one; a caller-supplied `signal` is respected alongside the timeout.
 */
export async function stealthFetch(url: string, init: RequestInit = {}, timeoutMs = 8000): Promise<Response> {
  const stealth = getController();
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), timeoutMs);
  if (init.signal) {
    if (init.signal.aborted) abort.abort();
    else init.signal.addEventListener("abort", () => abort.abort(), { once: true });
  }
  try {
    return await stealth.run(() =>
      fetch(url, {
        ...init,
        signal: abort.signal,
        headers: { "User-Agent": stealth.nextUserAgent(), ...(init.headers ?? {}) },
      }),
    );
  } finally {
    clearTimeout(timer);
  }
}

/** The controller for the current async scan context, or a passthrough default. */
export function getController(): StealthController {
  return store.getStore() ?? DEFAULT_CONTROLLER;
}

/** The resolved scan profile for the current async scan context. */
export function currentProfile(): ScanProfile {
  return getController().profile;
}

/**
 * Run `fn` inside a stealth context for the given mode. If a context is already
 * active (e.g. a full scan wrapping EASM + OSINT), it is reused so pacing stays
 * global across the whole scan rather than resetting per sub-scan.
 */
export function runWithStealth<T>(mode: string | undefined | null, fn: () => Promise<T>): Promise<T> {
  if (store.getStore()) return fn();
  return store.run(new StealthController(resolveProfile(mode)), fn);
}
