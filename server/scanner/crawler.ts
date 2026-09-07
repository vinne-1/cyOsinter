/**
 * Site crawler — building the real endpoint inventory.
 *
 * ## Why this exists
 *
 * The engine had no crawler. It fetched the main page, the sitemap and an
 * archive index, and that was the whole picture of the application. The
 * consequence showed up in DAST-lite: its XSS and open-redirect checks probed a
 * hardcoded guess list (`/?q=`, `/search?query=`, `/login?next=`) because
 * nothing had ever told it what the application's actual parameters were. An
 * active check that tests endpoints the target does not have will not find the
 * one it does.
 *
 * This module produces that inventory: reachable URLs, the query parameters
 * each accepts, and the forms on the way. It is the same job `katana` does, and
 * katana is used directly when it happens to be installed — but the native
 * crawler is the baseline, because a self-hosted scanner has to work out of the
 * box with no Go toolchain present.
 *
 * ## Deduplication by shape, not by string
 *
 * A shop with ten thousand products has ten thousand URLs and ONE endpoint.
 * Crawling stores `/product?id=1`, `/product?id=2`, … as distinct entries only
 * if you let it, and the result is a crawl that never terminates usefully and an
 * active-test list that probes the same parameter ten thousand times. URLs are
 * therefore keyed on their SHAPE — path plus the sorted set of parameter names —
 * so `/product?id=1` and `/product?id=999` collapse to one entry. This is the
 * single most important behaviour in the module.
 *
 * ## Scope
 *
 * Only the target's own registrable domain is ever fetched. The crawler follows
 * links, and links point anywhere; without a scope check this becomes an
 * open-ended fetcher driven by third-party content, which is both an SSRF
 * surface and a way to put scanner traffic on hosts nobody authorised.
 */

import { spawn } from "child_process";
import { createLogger } from "../logger.js";
import { httpGet } from "./http.js";
import { resolveExecutable } from "./utils.js";

const log = createLogger("crawler");

/** Extensions that are content, not endpoints — never worth fetching or testing. */
const ASSET_EXT =
  /\.(?:png|jpe?g|gif|svg|webp|avif|ico|bmp|tiff?|woff2?|ttf|eot|otf|mp[34]|m4[av]|ogg|webm|avi|mov|wmv|flv|pdf|zip|gz|tar|rar|7z|dmg|exe|msi|apk|iso|css|map)(?:$|\?)/i;

/**
 * Parameters that carry tracking or cache-busting data rather than input the
 * application acts on. Testing them spends the request budget on values nothing
 * ever reads.
 *
 * The prefix alternatives need their own `\w*`: anchored between `^(?:` and
 * `)$`, a bare `utm_` matches only the literal string "utm_", so every real
 * `utm_source` / `utm_campaign` sailed through.
 */
const NOISE_PARAMS = /^(?:utm_\w*|_ga\w*|_gid|fbclid|gclid|msclkid|mc_[ce]id|ref|referrer|v|ver|version|t|ts|timestamp|cache|cb|_)$/i;

export interface CrawledUrl {
  /** A representative concrete URL for this endpoint shape. */
  url: string;
  /** Query parameter names the endpoint accepts. */
  params: string[];
  depth: number;
  source: "seed" | "link" | "form" | "script" | "katana";
}

export interface CrawledForm {
  action: string;
  method: string;
  inputs: string[];
}

export interface CrawlResult {
  /** One entry per distinct endpoint shape. */
  urls: CrawledUrl[];
  /** The subset that accepts query parameters — the active-testing surface. */
  parameterised: CrawledUrl[];
  forms: CrawledForm[];
  engine: "katana" | "native";
  pagesFetched: number;
  /** True when a limit stopped the crawl before it ran out of links. */
  truncated: boolean;
}

export interface CrawlOptions {
  maxPages?: number;
  maxDepth?: number;
  concurrency?: number;
  signal?: AbortSignal;
  /** Set false to skip katana even when it is installed (used by tests). */
  allowExternalEngine?: boolean;
}

/** Registrable-ish scope root: the last two labels of the host. */
function scopeRoot(host: string): string {
  const parts = host.toLowerCase().replace(/\.$/, "").split(".");
  return parts.length <= 2 ? parts.join(".") : parts.slice(-2).join(".");
}

/** True when `url` is inside the target's own registrable domain. */
export function isInScope(url: string, domain: string): boolean {
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return false;
    const host = u.hostname.toLowerCase();
    const root = scopeRoot(domain);
    return host === root || host.endsWith(`.${root}`);
  } catch {
    return false;
  }
}

/**
 * The endpoint shape of a URL: origin + path + sorted parameter names.
 *
 * Two URLs sharing a shape are the same endpoint with different data, and the
 * crawler keeps only the first of them.
 */
export function endpointShape(url: string): string | null {
  try {
    const u = new URL(url);
    const names = Array.from(new Set(Array.from(u.searchParams.keys()))).sort();
    return `${u.origin}${u.pathname.replace(/\/+$/, "") || "/"}?${names.join("&")}`;
  } catch {
    return null;
  }
}

/** Testable parameter names on a URL — tracking and cache-busting excluded. */
export function testableParams(url: string): string[] {
  try {
    const u = new URL(url);
    return Array.from(new Set(Array.from(u.searchParams.keys())))
      .filter((p) => !NOISE_PARAMS.test(p))
      .sort();
  } catch {
    return [];
  }
}

/** Links, form targets and script-embedded paths in a page. */
export function extractLinks(html: string, baseUrl: string): Array<{ url: string; source: CrawledUrl["source"] }> {
  const out: Array<{ url: string; source: CrawledUrl["source"] }> = [];
  const push = (raw: string, source: CrawledUrl["source"]) => {
    const v = raw.trim();
    if (!v || v.startsWith("#") || /^(?:javascript|mailto|tel|data):/i.test(v)) return;
    try { out.push({ url: new URL(v, baseUrl).href, source }); } catch { /* unresolvable */ }
  };

  for (const m of Array.from(html.matchAll(/<a\b[^>]*\bhref\s*=\s*["']([^"']+)["']/gi))) push(m[1], "link");
  for (const m of Array.from(html.matchAll(/<form\b[^>]*\baction\s*=\s*["']([^"']+)["']/gi))) push(m[1], "form");
  for (const m of Array.from(html.matchAll(/<(?:script|iframe)\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi))) push(m[1], "script");
  // Paths embedded in inline JavaScript — often the only reference to an API route.
  for (const m of Array.from(html.matchAll(/["'`](\/(?:api|v\d|rest|graphql)\/[A-Za-z0-9_\-/.]{1,120})["'`]/g))) push(m[1], "script");
  return out;
}

/** Forms and their input names, for reporting and future active testing. */
export function extractForms(html: string, baseUrl: string): CrawledForm[] {
  const forms: CrawledForm[] = [];
  for (const m of Array.from(html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi))) {
    const attrs = m[1];
    const body = m[2];
    const action = attrs.match(/\baction\s*=\s*["']([^"']*)["']/i)?.[1] ?? "";
    const method = (attrs.match(/\bmethod\s*=\s*["']([^"']*)["']/i)?.[1] ?? "GET").toUpperCase();
    const inputs = Array.from(body.matchAll(/<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']([^"']+)["']/gi)).map((i) => i[1]);
    let resolved = action;
    try { resolved = new URL(action || baseUrl, baseUrl).href; } catch { /* keep raw */ }
    forms.push({ action: resolved, method, inputs: Array.from(new Set(inputs)) });
  }
  return forms;
}

// ── katana delegation ───────────────────────────────────────────────────────

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

/** katana's binary, when the operator has installed it. */
export function findKatana(): string | null {
  return resolveExecutable("katana");
}

/**
 * Run katana and read its JSONL output.
 *
 * Returns null when katana is absent, fails, or produces nothing usable, so the
 * caller falls back to the native crawler rather than reporting an empty site.
 */
async function crawlWithKatana(
  domain: string,
  opts: Required<Pick<CrawlOptions, "maxDepth">> & { signal?: AbortSignal },
): Promise<string[] | null> {
  const bin = findKatana();
  if (!bin) return null;

  return new Promise((resolve) => {
    const args = ["-u", `https://${domain}`, "-jsonl", "-silent", "-no-color", "-d", String(opts.maxDepth), "-fs", "rdn"];
    const child = spawn(bin, args, { stdio: ["ignore", "pipe", "ignore"] });
    const urls: string[] = [];
    let buf = "";
    let settled = false;

    const done = (v: string[] | null) => { if (!settled) { settled = true; killIfRunning(child); resolve(v); } };
    const timer = setTimeout(() => done(urls.length > 0 ? urls : null), 120_000);
    opts.signal?.addEventListener("abort", () => { clearTimeout(timer); done(null); }, { once: true });

    child.stdout.on("data", (chunk: Buffer) => {
      buf += chunk.toString();
      const lines = buf.split(/\r?\n/);
      buf = lines.pop() ?? "";
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const j = JSON.parse(line) as { request?: { endpoint?: string; url?: string }; url?: string };
          const u = j.request?.endpoint ?? j.request?.url ?? j.url;
          if (typeof u === "string") urls.push(u);
        } catch { /* not a JSON line */ }
      }
    });
    child.on("error", () => { clearTimeout(timer); done(null); });
    child.on("close", () => { clearTimeout(timer); done(urls.length > 0 ? urls : null); });
  });
}

// ── native crawler ──────────────────────────────────────────────────────────

/**
 * Crawl the site and return its endpoint inventory.
 *
 * Uses katana when installed, otherwise a breadth-first native crawl. Both paths
 * apply the same scope check and the same shape-deduplication, so the result is
 * comparable whichever engine ran.
 */
export async function crawlSite(domain: string, options: CrawlOptions = {}): Promise<CrawlResult> {
  const maxPages = options.maxPages ?? 120;
  const maxDepth = options.maxDepth ?? 3;
  const concurrency = options.concurrency ?? 4;
  const allowExternal = options.allowExternalEngine ?? true;

  const seen = new Map<string, CrawledUrl>();
  const forms: CrawledForm[] = [];
  let pagesFetched = 0;
  let truncated = false;

  const record = (url: string, depth: number, source: CrawledUrl["source"]): boolean => {
    if (!isInScope(url, domain)) return false;
    if (ASSET_EXT.test(url)) return false;
    const shape = endpointShape(url);
    if (!shape || seen.has(shape)) return false;
    seen.set(shape, { url, params: testableParams(url), depth, source });
    return true;
  };

  // Prefer katana when the operator has it: it is faster, handles JS-rendered
  // links, and is maintained by people who do only this.
  if (allowExternal) {
    const katanaUrls = await crawlWithKatana(domain, { maxDepth, signal: options.signal });
    if (katanaUrls) {
      for (const u of katanaUrls) record(u, 0, "katana");
      const urls = Array.from(seen.values());
      log.info({ domain, urls: urls.length, engine: "katana" }, "crawl complete");
      return {
        urls,
        parameterised: urls.filter((u) => u.params.length > 0),
        forms,
        engine: "katana",
        pagesFetched: katanaUrls.length,
        truncated: false,
      };
    }
  }

  const seedUrl = `https://${domain}/`;
  record(seedUrl, 0, "seed");
  let frontier: Array<{ url: string; depth: number }> = [{ url: seedUrl, depth: 0 }];
  const fetched = new Set<string>();

  while (frontier.length > 0 && pagesFetched < maxPages) {
    if (options.signal?.aborted) break;
    const batch = frontier.splice(0, concurrency);
    const next: Array<{ url: string; depth: number }> = [];

    await Promise.all(batch.map(async ({ url, depth }) => {
      if (fetched.has(url) || pagesFetched >= maxPages) return;
      fetched.add(url);
      const res = await httpGet(url);
      pagesFetched++;
      if (!res || res.status < 200 || res.status >= 400) return;
      if (!/text\/html|application\/xhtml/i.test(res.headers["content-type"] ?? "")) return;

      for (const f of extractForms(res.body, url)) {
        if (isInScope(f.action, domain)) forms.push(f);
      }
      if (depth >= maxDepth) return;
      for (const link of extractLinks(res.body, url)) {
        if (record(link.url, depth + 1, link.source)) next.push({ url: link.url, depth: depth + 1 });
      }
    }));

    frontier = frontier.concat(next);
  }

  if (frontier.length > 0 && pagesFetched >= maxPages) truncated = true;

  const urls = Array.from(seen.values());
  log.info(
    { domain, urls: urls.length, parameterised: urls.filter((u) => u.params.length > 0).length, pagesFetched, truncated },
    "crawl complete",
  );

  return {
    urls,
    parameterised: urls.filter((u) => u.params.length > 0),
    forms,
    engine: "native",
    pagesFetched,
    truncated,
  };
}
