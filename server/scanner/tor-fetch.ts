/**
 * Tor-aware HTTP client — routes requests through a local SOCKS5 proxy.
 *
 * .onion addresses are not routable over the public internet; they require a
 * Tor circuit. The standard approach is a locally running Tor daemon exposing a
 * SOCKS5 proxy (default 127.0.0.1:9050). This module tunnels through it.
 *
 * ## Why this uses `node:http`, not `fetch`
 *
 * This originally passed the SOCKS agent to `fetch` as `dispatcher`. That does
 * not work, and it fails in the worst possible way:
 *
 *   `SocksProxyAgent` is a Node **http.Agent**. Node's global `fetch` is undici,
 *   and its `dispatcher` option requires an undici **Dispatcher** — a different
 *   interface entirely. Handing it an http.Agent throws
 *   `TypeError: agent.dispatch is not a function` before a single byte leaves
 *   the process.
 *
 * Both `torFetch` and `isTorAvailable` caught that TypeError and returned
 * `null` / `false`, which is indistinguishable from "the Tor daemon is not
 * running". So the feature reported **"Tor unavailable" on every run, even with
 * Tor running perfectly** — and an operator would go and debug their Tor setup,
 * because that is exactly what the message tells them to do.
 *
 * The unit tests did not catch it because they stub `globalThis.fetch`, which
 * mocks away the one thing that was broken. Verified empirically instead:
 * `fetch` + agent throws the TypeError above, while `http.request` + the same
 * agent dials 127.0.0.1:9050 and reports ECONNREFUSED when Tor is down — which
 * is the proxy actually being used.
 *
 * `socks-proxy-agent` is built for exactly this classic API, so no new
 * dependency is needed.
 *
 * ── Circuit rotation ─────────────────────────────────────────────────────────
 * Tor builds circuits automatically and SOCKS5 exposes no "rotate" primitive.
 * A fresh agent every few minutes is close to Tor's own `NewCircuitPeriod`.
 * Forcing rotation per request would destroy performance without meaningfully
 * improving anonymity — this is a scanner, not an anti-forensics tool.
 */

import http from "node:http";
import https from "node:https";
import { SocksProxyAgent } from "socks-proxy-agent";
import { createLogger } from "../logger.js";

const log = createLogger("tor-fetch");

/**
 * The SOCKS URL the agent will dial.
 *
 * `socks5://` resolves the destination on this machine before asking the
 * proxy. A `.onion` name has no DNS record, so that lookup fails with
 * `ENOTFOUND` in milliseconds and the request never reaches Tor.
 * `isTorAvailable()` still returns true in that state, because
 * `check.torproject.org` resolves locally and only the TCP connection goes
 * through the proxy. `socks5h://` hands the hostname to Tor, which is the
 * only resolver that knows a hidden service.
 *
 * An operator-supplied `socks5://` (or bare `socks://`) URL is rewritten.
 * Leaving the documented form in place would reintroduce the failure.
 */
export function normaliseTorProxyUrl(raw: string): string {
  const trimmed = raw.trim();
  const scheme = trimmed.match(/^(socks5|socks):\/\//i);
  if (!scheme) return trimmed;
  return `socks5h://${trimmed.slice(scheme[0].length)}`;
}

/**
 * SOCKS proxy address. Host dev uses the local daemon; the Compose app
 * service sets `socks5h://tor:9050` so it reaches the `tor` container.
 */
const PROXY_URL = normaliseTorProxyUrl(
  process.env.TOR_SOCKS_PROXY ?? "socks5h://127.0.0.1:9050",
);

/** Default timeout for dark web fetches — .onion services are slow. */
const DEFAULT_TIMEOUT_MS = 60_000;

/** How often to create a fresh agent (and thus a new Tor circuit). */
const AGENT_TTL_MS = 5 * 60 * 1000;

/**
 * Hard ceiling on a response body.
 *
 * Enforced WHILE streaming, not after. The previous version called
 * `res.text()` and then sliced the result, which cannot prevent the memory
 * problem its own comment described: by the time you can slice the string, the
 * whole body is already in memory. A hostile .onion serving an endless response
 * would exhaust the process before the slice ran.
 */
const MAX_BODY_BYTES = 500_000;

let agent: SocksProxyAgent | null = null;
let agentCreatedAt = 0;

/**
 * Returns a SOCKS5 agent, reusing a cached one while it is still fresh.
 *
 * NOT shared with clearnet fetches — it routes everything through Tor, which
 * would be wrong (and much slower) for ordinary requests. Clearnet callers use
 * `stealthFetch`.
 */
export function getTorAgent(): SocksProxyAgent {
  const now = Date.now();
  if (!agent || now - agentCreatedAt > AGENT_TTL_MS) {
    agent = new SocksProxyAgent(PROXY_URL);
    agentCreatedAt = now;
    log.debug({ proxy: PROXY_URL }, "Created new Tor SOCKS5 agent");
  }
  return agent;
}

/**
 * A response, reduced to what callers here actually use.
 *
 * Deliberately not typed as the DOM `Response`: this is not one, and claiming
 * otherwise invites a caller to reach for a method that does not exist.
 */
export interface TorResponse {
  ok: boolean;
  status: number;
  headers: Record<string, string>;
  text(): Promise<string>;
  json<T = unknown>(): Promise<T>;
  /** True when the body hit MAX_BODY_BYTES and was cut short. */
  truncated: boolean;
}

interface RequestOptions {
  timeoutMs?: number;
  headers?: Record<string, string>;
  method?: string;
  body?: string | Buffer;
}

/** One request through the SOCKS proxy, with the body capped as it streams. */
function requestThroughTor(url: string, opts: RequestOptions): Promise<TorResponse | null> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (value: TorResponse | null) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };

    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      log.warn({ url }, "Tor fetch given an unparseable URL");
      return done(null);
    }

    const transport = parsed.protocol === "https:" ? https : http;
    const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

    const req = transport.request(
      url,
      {
        method: opts.method ?? "GET",
        agent: getTorAgent(),
        timeout: timeoutMs,
        headers: {
          "User-Agent": "Cyshield-EASM/1.0 (dark web monitoring)",
          accept: "text/html,application/json",
          ...opts.headers,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        let truncated = false;

        res.on("data", (chunk: Buffer) => {
          if (truncated) return;
          const remaining = MAX_BODY_BYTES - size;
          if (chunk.length >= remaining) {
            chunks.push(chunk.subarray(0, remaining));
            size = MAX_BODY_BYTES;
            truncated = true;
            // Stop reading rather than buffering a body we will discard.
            res.destroy();
            return;
          }
          chunks.push(chunk);
          size += chunk.length;
        });

        const finish = () => {
          const status = res.statusCode ?? 0;
          const bodyText = Buffer.concat(chunks).toString("utf8");
          const headers: Record<string, string> = {};
          for (const [k, v] of Object.entries(res.headers)) {
            if (typeof v === "string") headers[k.toLowerCase()] = v;
            else if (Array.isArray(v)) headers[k.toLowerCase()] = v.join(", ");
          }
          done({
            ok: status >= 200 && status < 300,
            status,
            headers,
            truncated,
            text: async () => bodyText,
            json: async <T,>() => JSON.parse(bodyText) as T,
          });
        };

        res.on("end", finish);
        // `destroy()` on truncation emits `close` rather than `end`, so the
        // capped body still has to resolve.
        res.on("close", finish);
        res.on("error", () => done(null));
      },
    );

    req.on("timeout", () => {
      req.destroy();
      log.info({ url, timeoutMs }, "Tor request timed out");
      done(null);
    });

    req.on("error", (err: NodeJS.ErrnoException) => {
      // ECONNREFUSED on the proxy port means the Tor daemon is not running —
      // expected when Tor is not installed, so it is not an error-level event.
      if (err.code === "ECONNREFUSED" || err.code === "ENOTFOUND") {
        log.info({ proxy: PROXY_URL, url }, "Tor proxy unreachable");
      } else {
        log.warn({ err, url }, "Tor fetch failed");
      }
      done(null);
    });

    if (opts.body) req.write(opts.body);
    req.end();
  });
}

/**
 * Checks whether the Tor SOCKS5 proxy is reachable AND actually carrying
 * traffic over Tor.
 *
 * `IsTor: true` is the meaningful assertion — a proxy that answers but does not
 * route through Tor would let .onion lookups fail in a confusing way later.
 */
export async function isTorAvailable(timeoutMs = 5_000): Promise<boolean> {
  const res = await requestThroughTor("https://check.torproject.org/api/ip", { timeoutMs });
  if (!res?.ok) return false;
  try {
    const body = await res.json<{ IsTor?: boolean; IP?: string }>();
    return body.IsTor === true;
  } catch {
    return false;
  }
}

/**
 * Fetch through the Tor SOCKS5 proxy.
 *
 * Returns null on any failure, so a caller can distinguish "could not reach it"
 * from "reached it and there was nothing" — the same three-state rule the rest
 * of the scanner follows.
 */
export async function torFetch(url: string, opts: RequestOptions = {}): Promise<TorResponse | null> {
  return requestThroughTor(url, opts);
}

/** Fetch JSON through Tor. Null on failure or unparseable body. */
export async function torFetchJson<T = unknown>(
  url: string,
  opts: { timeoutMs?: number; headers?: Record<string, string> } = {},
): Promise<T | null> {
  const res = await torFetch(url, {
    ...opts,
    headers: { accept: "application/json", ...opts.headers },
  });
  if (!res?.ok) return null;
  // A body capped at MAX_BODY_BYTES is a PARTIAL read, and these two wrappers
  // flatten `TorResponse` down to a value that cannot express that. A caller
  // searching a truncated body for a domain mention and finding none would
  // report "nothing found" from evidence that was cut short — the same
  // could-not-check-versus-checked-and-clean confusion this module's callers
  // are built around. Logged here so the truncation is at least recorded; a
  // caller that needs to branch on it uses `torFetch` directly.
  if (res.truncated) {
    log.warn({ url, cap: MAX_BODY_BYTES }, "Tor response truncated — this read is partial, not complete");
  }
  try {
    return await res.json<T>();
  } catch {
    log.warn({ url }, "Failed to parse JSON from Tor response");
    return null;
  }
}

/** Fetch text through Tor. Null on failure. Body is capped while streaming. */
export async function torFetchText(
  url: string,
  opts: { timeoutMs?: number; headers?: Record<string, string> } = {},
): Promise<string | null> {
  const res = await torFetch(url, opts);
  if (!res?.ok) return null;
  if (res.truncated) {
    log.warn({ url, cap: MAX_BODY_BYTES }, "Tor response truncated — this read is partial, not complete");
  }
  try {
    return await res.text();
  } catch {
    log.warn({ url }, "Failed to read text from Tor response");
    return null;
  }
}

/** Clears the cached agent. Exposed for tests and shutdown. */
export function __resetTorAgent(): void {
  agent = null;
  agentCreatedAt = 0;
}

/** The configured proxy address, for diagnostics. */
export const TOR_PROXY_URL = PROXY_URL;
