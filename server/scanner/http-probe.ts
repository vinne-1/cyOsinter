/**
 * Enriched HTTP probing at scale — the `httpx` layer.
 *
 * ## What this replaces
 *
 * Live-host detection issued a HEAD to `https://host` and `http://host` and
 * kept one bit: did anything answer. Everything an analyst actually triages on
 * — what the page calls itself, what it runs, whether it redirects somewhere
 * else, how big it is — was either never collected or collected much later in a
 * separate gold-only pass. So a scan could report ninety live subdomains and
 * tell you nothing about any of them, and the operator had to open each one by
 * hand to find out which mattered.
 *
 * A single GET per host yields all of it for the same round trip: status, title,
 * server banner, content length, redirect target, detected technologies, and
 * WAF/CDN attribution. That is what `httpx` is for, and this is the same job
 * done natively so it works with no Go toolchain installed.
 *
 * ## Why GET rather than HEAD
 *
 * HEAD is cheaper and answers strictly less. Many servers handle it
 * inconsistently — returning 405, or a different status to the one GET would
 * give — so it is a worse liveness signal *and* carries no body to read a title
 * or fingerprint from. The response body is capped by `httpGet`, so the extra
 * cost is bounded.
 *
 * ## Scheme preference
 *
 * HTTPS is probed first and preferred. HTTP is only probed when HTTPS did not
 * answer, plus once more for the specific purpose of detecting whether cleartext
 * is served without an upgrade — which is a finding, not a curiosity.
 */

import { spawn } from "child_process";
import { createLogger } from "../logger.js";
import { httpGet } from "./http.js";
import { runWithConcurrency } from "./utils.js";
import { resolveExecutable } from "./utils.js";
import { detectTechStack, detectWAF, detectCDN } from "./detection.js";

const log = createLogger("http-probe");

export interface HostProbe {
  host: string;
  /** The URL that actually answered. */
  url: string;
  scheme: "https" | "http";
  status: number;
  title?: string;
  server?: string;
  contentLength?: number;
  /** Technology names detected from body, headers and cookies. */
  technologies: string[];
  /**
   * Detected client-side libraries that reported a VERSION, kept separately.
   *
   * `technologies` is a display list and flattens to names, which discarded the
   * one field a vulnerability lookup needs. The versions were being captured by
   * `tech-fingerprints.ts` and thrown away here, one line after they were found.
   * Only versioned entries are carried, because an unversioned library cannot be
   * assessed and padding the list with them would invite guessing.
   */
  libraryVersions: Array<{ name: string; version: string }>;
  /** Where the response redirected, when it landed somewhere else. */
  redirectsTo?: string;
  responseTimeMs: number;
  waf?: string;
  cdn?: string;
  /** True when plain HTTP served content without upgrading to HTTPS. */
  cleartextWithoutUpgrade: boolean;
}

export interface ProbeOptions {
  concurrency?: number;
  signal?: AbortSignal;
  /** Probe HTTP as well, to detect cleartext exposure. Costs one request/host. */
  checkCleartext?: boolean;
  /** Set false to skip the httpx binary even when installed (used by tests). */
  allowExternalEngine?: boolean;
  onProgress?: (done: number, total: number) => void;
}

/**
 * The `<title>` of a page, collapsed to a single line.
 *
 * Titles routinely wrap across lines and carry entities; a raw slice of the tag
 * makes an unreadable column in a report.
 */
export function extractTitle(html: string): string | undefined {
  // The length cap belongs on the RESULT, not in the pattern. With `{0,300}?`
  // in the regex, a title longer than the cap simply failed to match and the
  // host was reported with no title at all — the opposite of truncating it.
  const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (!m) return undefined;
  const text = m[1]
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/\s+/g, " ")
    .trim();
  return text.length > 0 ? text.slice(0, 200) : undefined;
}

/** `httpGet` caps the body it returns; see http.ts. */
const BODY_CAP = 5000;

/**
 * Content length, from the header where the server sent one.
 *
 * The body fallback is only used when the body is SHORTER than the cap. A
 * response that filled the cap was truncated by `httpGet`, and reporting 5000
 * for it states a measurement that was never taken — a 4 MB page and a 5 KB one
 * would appear identical, and the number would be wrong for both.
 */
function contentLengthOf(headers: Record<string, string>, body: string): number | undefined {
  const raw = headers["content-length"];
  const n = Number.parseInt(raw ?? "", 10);
  if (Number.isFinite(n) && n >= 0) return n;
  if (body.length === 0 || body.length >= BODY_CAP) return undefined;
  return body.length;
}

function pathOf(url: string): string {
  try { return new URL(url).host + new URL(url).pathname; } catch { return url; }
}

/** Probe one host, preferring HTTPS. Returns null when nothing answered. */
async function probeOne(host: string, opts: ProbeOptions): Promise<HostProbe | null> {
  const started = Date.now();
  const httpsRes = await httpGet(`https://${host}`).catch(() => null);
  const answered = httpsRes;
  const scheme: "https" | "http" = httpsRes ? "https" : "http";

  const res = answered ?? (await httpGet(`http://${host}`).catch(() => null));
  if (!res) return null;

  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(res.headers)) headers[k.toLowerCase()] = v;

  // Cleartext check: does plain HTTP serve content without sending us to HTTPS?
  // Only meaningful when HTTPS also works — otherwise the host is simply
  // HTTP-only, which the scheme field already says.
  let cleartextWithoutUpgrade = false;
  if (opts.checkCleartext && httpsRes) {
    const plain = await httpGet(`http://${host}`).catch(() => null);
    if (plain && plain.status >= 200 && plain.status < 400 && !plain.finalUrl.startsWith("https://")) {
      cleartextWithoutUpgrade = true;
    }
  }

  const waf = detectWAF(headers);
  const cdn = detectCDN(headers);
  // Detected once and used twice: the flat display list and the versioned
  // library list a vulnerability lookup needs.
  const techs = detectTechStack(res.body, headers);
  const requested = `${scheme}://${host}`;
  const landed = res.finalUrl || requested;

  return {
    host,
    url: landed,
    scheme,
    status: res.status,
    title: extractTitle(res.body),
    server: headers["server"],
    contentLength: contentLengthOf(headers, res.body),
    technologies: techs.map((t) => t.name).slice(0, 12),
    libraryVersions: techs
      .filter((t): t is typeof t & { version: string } => Boolean(t.version))
      .map((t) => ({ name: t.name, version: t.version }))
      .slice(0, 20),
    redirectsTo: pathOf(landed) !== pathOf(requested) ? landed : undefined,
    responseTimeMs: Date.now() - started,
    waf: waf.detected ? waf.provider : undefined,
    cdn: cdn !== "None" ? cdn : undefined,
    cleartextWithoutUpgrade,
  };
}

/**
 * Terminate a spawned child only when it is still running.
 *
 * Calling `kill()` on a handle that has already closed trips a libuv assertion
 * on Windows — `!(handle->flags & UV_HANDLE_CLOSING)` — which aborts the whole
 * Node process, not just the scan. The `close` handler necessarily runs after
 * the child is gone, so the settle path must check before killing.
 */
function killIfRunning(child: { exitCode: number | null; killed: boolean; kill: () => boolean }): void {
  if (child.exitCode !== null || child.killed) return;
  try { child.kill(); } catch { /* raced with exit */ }
}

/** ProjectDiscovery's httpx, when the operator has installed it. */
export function findHttpx(): string | null {
  return resolveExecutable("httpx");
}

/**
 * Delegate to httpx when present.
 *
 * Returns null on absence or failure so the caller falls back to the native
 * prober — an unavailable binary must never read as "no hosts are live".
 *
 * Note this is ProjectDiscovery's `httpx`, not the identically-named Python HTTP
 * client. The JSON shape is checked before any result is trusted, so the wrong
 * binary on PATH yields null rather than nonsense.
 */
async function probeWithHttpx(hosts: readonly string[], signal?: AbortSignal): Promise<HostProbe[] | null> {
  const bin = findHttpx();
  if (!bin || hosts.length === 0) return null;

  return new Promise((resolve) => {
    const args = ["-json", "-silent", "-no-color", "-title", "-tech-detect", "-status-code", "-content-length", "-follow-redirects"];
    const child = spawn(bin, args, { stdio: ["pipe", "pipe", "ignore"] });
    const out: HostProbe[] = [];
    let buf = "";
    let settled = false;

    const done = (v: HostProbe[] | null) => {
      if (settled) return;
      settled = true;
      killIfRunning(child);
      resolve(v);
    };
    const timer = setTimeout(() => done(out.length > 0 ? out : null), 180_000);
    signal?.addEventListener("abort", () => { clearTimeout(timer); done(null); }, { once: true });

    child.stdout.on("data", (chunk: Buffer) => {
      buf += chunk.toString();
      const lines = buf.split(/\r?\n/);
      buf = lines.pop() ?? "";
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const j = JSON.parse(line) as Record<string, unknown>;
          const url = typeof j.url === "string" ? j.url : undefined;
          const input = typeof j.input === "string" ? j.input : undefined;
          if (!url && !input) continue; // not httpx output — wrong binary
          const host = (input ?? url ?? "").replace(/^https?:\/\//, "").split("/")[0];
          out.push({
            host,
            url: url ?? `https://${host}`,
            scheme: (url ?? "").startsWith("http://") ? "http" : "https",
            status: typeof j["status_code"] === "number" ? (j["status_code"] as number) : 0,
            title: typeof j.title === "string" && j.title ? j.title : undefined,
            server: typeof j.webserver === "string" ? j.webserver : undefined,
            contentLength: typeof j["content_length"] === "number" ? (j["content_length"] as number) : undefined,
            technologies: Array.isArray(j.tech) ? (j.tech as string[]).slice(0, 12) : [],
            // httpx reports technology names without structured versions, so
            // there is nothing to assess from this path. Empty is honest here:
            // the native path supplies versions, and inventing them from a name
            // string would be guessing.
            libraryVersions: [],
            responseTimeMs: 0,
            cleartextWithoutUpgrade: false,
          });
        } catch { /* not a JSON line */ }
      }
    });
    child.on("error", () => { clearTimeout(timer); done(null); });
    child.on("close", () => { clearTimeout(timer); done(out.length > 0 ? out : null); });

    child.stdin.write(hosts.join("\n"));
    child.stdin.end();
  });
}

/**
 * Probe many hosts, returning one enriched record per host that answered.
 *
 * Hosts that answer nothing are omitted rather than represented as a zero-status
 * entry — "did not answer" is the absence of a probe result, and inventing a row
 * for it would put dead hosts in the live inventory.
 */
export async function probeHosts(hosts: readonly string[], opts: ProbeOptions = {}): Promise<HostProbe[]> {
  if (hosts.length === 0) return [];
  const concurrency = opts.concurrency ?? 20;

  if (opts.allowExternalEngine ?? true) {
    const viaHttpx = await probeWithHttpx(hosts, opts.signal);
    if (viaHttpx) {
      log.info({ hosts: hosts.length, live: viaHttpx.length, engine: "httpx" }, "host probe complete");
      return viaHttpx;
    }
  }

  let done = 0;
  const results = await runWithConcurrency(
    Array.from(hosts),
    concurrency,
    async (host) => {
      const r = await probeOne(host, opts);
      opts.onProgress?.(++done, hosts.length);
      return r;
    },
    opts.signal,
  );

  const live = results.filter((r): r is HostProbe => r !== null);
  log.info({ hosts: hosts.length, live: live.length, engine: "native" }, "host probe complete");
  return live;
}
