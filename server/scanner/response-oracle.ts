/**
 * Response oracle — "is this 200 actually a real resource?"
 *
 * Every path-probing detector in this scanner used to treat `status === 200` as
 * proof that a path exists. On a single-page app, a framework with a catch-all
 * route, or any server with a custom error page, that is simply false: the
 * server answers 200 with `index.html` for `/.env`, `/api/v1/pods`, `/metrics`
 * and every other path in the wordlist. The result was a confident
 * "Kubernetes Pods API Exposed Without Authentication (critical)" for a static
 * marketing site.
 *
 * The previous defence was a single fingerprint string —
 * `${body.length}:${body.slice(0,100)}` compared with `===`. Exact equality is
 * the wrong test: real error pages embed the requested path, a CSRF token, a
 * request id, or a timestamp, so the fingerprint differs on every request and
 * the guard never fires. This module replaces it with what `ffuf` calls
 * auto-calibration:
 *
 * 1. Probe several random paths that certainly do not exist, in the shapes the
 *    detectors actually request (bare, `.json`, `.php`, trailing-slash).
 * 2. Record what the server does with them.
 * 3. Judge a real probe by SIMILARITY to those baselines, not equality.
 *
 * Similarity is deliberately computed on a normalised body — digits, hex blobs,
 * UUIDs and probe tokens are collapsed — so a nonce or a request id cannot make
 * an error page look unique.
 *
 * Fail-open on calibration failure: if no baseline could be established we say
 * "unknown", and callers fall back to their own content checks rather than
 * dropping everything. Fail-CLOSED on a positive soft-404 match.
 */

import { httpGet } from "./http.js";
import { createLogger } from "../logger.js";

const log = createLogger("response-oracle");

/** Shapes of path the detectors request; each can 404 differently. */
export type ProbeShape = "bare" | "json" | "php" | "dir";

/** Bodies below this many tokens carry too little text for Jaccard to mean anything. */
const MIN_TOKENS_FOR_JACCARD = 8;

/** Token overlap at or above this counts as "the same page". */
const JACCARD_THRESHOLD = 0.9;

/** Body-length agreement (relative) that counts as "the same page" on its own. */
const LENGTH_TOLERANCE = 0.05;

export interface BaselineSample {
  shape: ProbeShape;
  status: number;
  length: number;
  tokens: Set<string>;
  contentType: string;
  /** The final path, so we can spot "every unknown path lands on /login" behaviour. */
  finalPath: string;
}

export interface ResponseBaseline {
  origin: string;
  samples: BaselineSample[];
  /**
   * The host answered 2xx for paths that cannot exist. Every 200 from this host
   * is suspect until its body proves otherwise.
   */
  catchAll: boolean;
  /** The host funnels unknown paths to one location (login page, home page). */
  redirectsUnknownTo: string | null;
  /** False when calibration could not reach the host at all. */
  calibrated: boolean;
}

export type SoftNotFoundVerdict =
  | { verdict: "soft-404"; reason: string }
  | { verdict: "real"; reason: string }
  | { verdict: "unknown"; reason: string };

// ── normalisation & similarity ──────────────────────────────────────────────

/**
 * Strip the parts of a response that legitimately differ between two requests
 * for the same error page: ids, tokens, timestamps, and the echoed probe path.
 */
export function normalizeBody(body: string): string {
  return body
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, " ")
    .replace(/[0-9a-f]{16,}/gi, " ")
    .replace(/\d+/g, " ")
    .replace(/nxprobe[a-z0-9]*/gi, " ")
    .toLowerCase();
}

/** Word tokens of a normalised body, used for Jaccard similarity. */
export function bodyTokens(body: string): Set<string> {
  const out = new Set<string>();
  for (const t of normalizeBody(body).split(/[^a-z]+/)) {
    if (t.length >= 3) out.add(t);
  }
  return out;
}

export function jaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) return 1;
  if (a.size === 0 || b.size === 0) return 0;
  let shared = 0;
  const [small, large] = a.size <= b.size ? [a, b] : [b, a];
  small.forEach((t) => { if (large.has(t)) shared++; });
  return shared / (a.size + b.size - shared);
}

function lengthsAgree(a: number, b: number): boolean {
  const max = Math.max(a, b);
  if (max === 0) return true;
  return Math.abs(a - b) / max <= LENGTH_TOLERANCE;
}

/**
 * Are two responses the same page?
 *
 * Token overlap is authoritative whenever both sides carry enough text; body
 * size is only the fallback for bodies too short to tokenise. Treating the two
 * as interchangeable alternatives (`jaccard >= T || lengthsAgree`) is wrong in
 * both directions — two unrelated pages that happen to be a similar size would
 * be called identical.
 */
function sameResponse(
  a: { length: number; tokens: Set<string> },
  b: { length: number; tokens: Set<string> },
): { same: boolean; reason: string } {
  if (a.tokens.size >= MIN_TOKENS_FOR_JACCARD && b.tokens.size >= MIN_TOKENS_FOR_JACCARD) {
    const sim = jaccard(a.tokens, b.tokens);
    return { same: sim >= JACCARD_THRESHOLD, reason: `${(sim * 100).toFixed(0)}% token overlap` };
  }
  const agree = lengthsAgree(a.length, b.length);
  return { same: agree, reason: `body size ${a.length}B vs ${b.length}B` };
}

// ── calibration ─────────────────────────────────────────────────────────────

function randomToken(): string {
  return `nxprobe${Math.random().toString(36).slice(2, 12)}`;
}

function probePathFor(shape: ProbeShape): string {
  const t = randomToken();
  switch (shape) {
    case "json": return `/${t}.json`;
    case "php": return `/${t}.php`;
    case "dir": return `/${t}/`;
    default: return `/${t}`;
  }
}

function pathOf(url: string): string {
  try { return new URL(url).pathname; } catch { return url; }
}

/**
 * Establish how `origin` responds to paths that cannot exist.
 *
 * `origin` is a scheme+host (`https://example.com`). Two samples are taken per
 * shape so that a host whose error page is itself non-deterministic (a rotating
 * banner, an A/B test) is still recognised: if its two own baselines do not
 * match each other, similarity to a single one proves nothing, and the shape is
 * dropped rather than used to withhold real findings.
 */
export async function calibrate(
  origin: string,
  shapes: ProbeShape[] = ["bare", "json", "php", "dir"],
): Promise<ResponseBaseline> {
  const samples: BaselineSample[] = [];
  let reached = false;

  for (const shape of shapes) {
    const pair: BaselineSample[] = [];
    for (let i = 0; i < 2; i++) {
      const res = await httpGet(`${origin}${probePathFor(shape)}`);
      if (!res) continue;
      reached = true;
      pair.push({
        shape,
        status: res.status,
        length: res.body.length,
        tokens: bodyTokens(res.body),
        contentType: (res.headers["content-type"] ?? "").toLowerCase(),
        finalPath: pathOf(res.finalUrl),
      });
    }
    if (pair.length === 0) continue;
    if (pair.length === 2) {
      // Only keep a shape whose error response is stable enough to compare
      // against. An unstable one would silently withhold genuine findings.
      const stable = pair[0].status === pair[1].status && sameResponse(pair[0], pair[1]).same;
      if (!stable) {
        log.debug({ origin, shape }, "unstable not-found baseline — shape not used for soft-404 suppression");
        continue;
      }
    }
    samples.push(pair[0]);
  }

  const catchAll = samples.some((s) => s.status >= 200 && s.status < 300);
  const funnelled =
    samples.length > 0 &&
    samples.every((s) => s.finalPath === samples[0].finalPath) &&
    samples[0].finalPath !== "/";

  const baseline: ResponseBaseline = {
    origin,
    samples,
    catchAll,
    redirectsUnknownTo: funnelled ? samples[0].finalPath : null,
    calibrated: reached && samples.length > 0,
  };

  if (catchAll) {
    log.info(
      { origin, status: samples.find((s) => s.status < 300)?.status },
      "host answers 2xx for non-existent paths — 200 alone is not evidence here",
    );
  }
  return baseline;
}

function shapeOf(path: string): ProbeShape {
  if (path.endsWith("/")) return "dir";
  if (/\.json$/i.test(path)) return "json";
  if (/\.php$/i.test(path)) return "php";
  return "bare";
}

/**
 * Decide whether a response for `path` is a real resource or the host's
 * not-found page wearing a 200.
 *
 * Returns `unknown` when there is no usable baseline — the caller must then
 * rely on positive content evidence rather than treating this as a pass.
 */
export function classifyAgainstBaseline(
  baseline: ResponseBaseline | null | undefined,
  path: string,
  res: { status: number; body: string; finalUrl?: string; headers?: Record<string, string> },
): SoftNotFoundVerdict {
  if (!baseline || !baseline.calibrated) return { verdict: "unknown", reason: "no baseline" };

  const wanted = shapeOf(path);
  const candidates = baseline.samples.filter((s) => s.shape === wanted);
  const pool = candidates.length > 0 ? candidates : baseline.samples;
  if (pool.length === 0) return { verdict: "unknown", reason: "no baseline for shape" };

  // A host that funnels EVERY unknown path to one place (a login page, a
  // marketing home page) is answering "no" no matter what status it uses.
  // Gated on `redirectsUnknownTo`, which is only set when every calibrated
  // shape landed on that same non-root location — a single sample agreeing by
  // coincidence is not evidence of a funnel.
  if (baseline.redirectsUnknownTo && res.finalUrl) {
    const landed = pathOf(res.finalUrl);
    if (landed === baseline.redirectsUnknownTo && landed !== path) {
      return { verdict: "soft-404", reason: `landed on the same catch-all location (${landed}) as a random non-existent path` };
    }
  }

  const observed = { length: res.body.length, tokens: bodyTokens(res.body) };
  for (const s of pool) {
    if (s.status !== res.status) continue;
    const { same, reason } = sameResponse(observed, s);
    if (same) {
      return { verdict: "soft-404", reason: `indistinguishable from this host's response for a random non-existent path (${reason})` };
    }
  }

  return { verdict: "real", reason: "differs from the host's not-found response" };
}

/** Convenience: true only when we positively established this is a soft 404. */
export function isSoftNotFound(
  baseline: ResponseBaseline | null | undefined,
  path: string,
  res: { status: number; body: string; finalUrl?: string; headers?: Record<string, string> },
): boolean {
  return classifyAgainstBaseline(baseline, path, res).verdict === "soft-404";
}
