import { stealthFetch } from "./stealth.js";

/**
 * Every scanner HTTP request goes through {@link stealthFetch} so it inherits
 * the active stealth profile: a global concurrency cap, jittered inter-request
 * pacing, and a browser-like (optionally rotating) User-Agent. When no stealth
 * context is active, a passthrough default applies.
 */

/**
 * JSON GET. Returns null when the source did not answer.
 *
 * `headers` exists for sources that require an API key. Note the contract every
 * caller depends on: **null means "did not answer", not "answered with
 * nothing"** — collapsing the two is how a rate-limited source came to be
 * reported as "0 subdomains found".
 */
export async function fetchJSON(
  url: string,
  timeoutMs = 10000,
  headers?: Record<string, string>,
): Promise<any> {
  try {
    const res = await stealthFetch(url, headers ? { headers } : {}, timeoutMs);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

export async function fetchText(url: string, timeoutMs = 10000): Promise<string | null> {
  try {
    const res = await stealthFetch(url, { redirect: "follow" }, timeoutMs);
    if (!res.ok) return null;
    return await res.text();
  } catch {
    return null;
  }
}

export async function httpHead(url: string, timeoutMs = 8000): Promise<{ status: number; headers: Record<string, string>; redirectUrl?: string } | null> {
  try {
    const res = await stealthFetch(url, { method: "HEAD", redirect: "follow" }, timeoutMs);
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    return { status: res.status, headers, redirectUrl: res.url !== url ? res.url : undefined };
  } catch {
    return null;
  }
}

export async function httpGet(url: string, timeoutMs = 8000): Promise<{ status: number; headers: Record<string, string>; body: string; finalUrl: string } | null> {
  try {
    const res = await stealthFetch(url, { redirect: "follow" }, timeoutMs);
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    const body = await res.text();
    return { status: res.status, headers, body: body.substring(0, 5000), finalUrl: res.url };
  } catch {
    return null;
  }
}

/**
 * A GET that returns raw BYTES rather than text.
 *
 * `httpGet` decodes to a string and truncates at 5,000 characters, both of which
 * destroy a binary body: an icon round-tripped through UTF-8 decoding is no
 * longer the bytes the server sent, so any hash of it is meaningless. Needed by
 * favicon hashing, where the exact bytes are the whole point.
 */
export async function httpGetBuffer(
  url: string,
  timeoutMs = 8000,
  maxBytes = 1024 * 1024,
): Promise<{ status: number; headers: Record<string, string>; body: Buffer; finalUrl: string } | null> {
  try {
    const res = await stealthFetch(url, { redirect: "follow" }, timeoutMs);
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    const buf = Buffer.from(await res.arrayBuffer());
    return {
      status: res.status,
      headers,
      body: buf.length > maxBytes ? buf.subarray(0, maxBytes) : buf,
      finalUrl: res.url,
    };
  } catch {
    return null;
  }
}

/**
 * A request with an explicit method and/or extra headers.
 *
 * Needed by checks whose whole point is what the server does with a specific
 * method or request header: an OPTIONS probe for allowed methods, a TRACE probe
 * for cross-site tracing, and a CORS probe that must actually send an `Origin`
 * (without one, a reflected-origin misconfiguration is invisible).
 */
export async function httpRequest(
  url: string,
  method: string,
  extraHeaders: Record<string, string> = {},
  timeoutMs = 8000,
  requestBody?: string,
): Promise<{ status: number; headers: Record<string, string>; body: string; finalUrl: string } | null> {
  try {
    const res = await stealthFetch(url, { method, headers: extraHeaders, body: requestBody, redirect: "manual" }, timeoutMs);
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    const body = await res.text();
    return { status: res.status, headers, body: body.substring(0, 5000), finalUrl: res.url };
  } catch {
    return null;
  }
}

export async function httpGetNoRedirect(url: string, timeoutMs = 6000): Promise<{ status: number; headers: Record<string, string>; location?: string } | null> {
  try {
    const res = await stealthFetch(url, { redirect: "manual" }, timeoutMs);
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    const location = res.headers.get("location") ?? undefined;
    return { status: res.status, headers, location };
  } catch {
    return null;
  }
}

export async function getRedirectChain(initialUrl: string, maxHops = 10): Promise<Array<{ status: number; url: string; location?: string }>> {
  const chain: Array<{ status: number; url: string; location?: string }> = [];
  let url: string | undefined = initialUrl;
  const seen = new Set<string>();
  while (url && chain.length < maxHops) {
    const u = url.toLowerCase();
    if (seen.has(u)) break;
    seen.add(u);
    const res = await httpGetNoRedirect(url);
    if (!res) break;
    chain.push({ status: res.status, url, location: res.location });
    if (res.status >= 300 && res.status < 400 && res.location) {
      try {
        url = res.location.startsWith("http") ? res.location : new URL(res.location, url).href;
      } catch { break; }
    } else {
      break;
    }
  }
  return chain;
}

export async function httpGetMainPage(url: string, timeoutMs = 10000): Promise<{ status: number; body: string; headers: Record<string, string>; setCookieStrings: string[]; finalUrl: string } | null> {
  try {
    const res = await stealthFetch(url, { redirect: "follow" }, timeoutMs);
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    const setCookieStrings = typeof (res.headers as any).getSetCookie === "function" ? (res.headers as any).getSetCookie() : (headers["set-cookie"] ? [headers["set-cookie"]] : []);
    const body = await res.text();
    return { status: res.status, body: body.substring(0, 100000), headers, setCookieStrings, finalUrl: res.url };
  } catch {
    return null;
  }
}

export function parseSetCookie(setCookieStrings: string[]): Array<{ name: string; secure?: boolean; httpOnly?: boolean; sameSite?: string; path?: string }> {
  const cookies: Array<{ name: string; secure?: boolean; httpOnly?: boolean; sameSite?: string; path?: string }> = [];
  for (const raw of setCookieStrings) {
    const parts = raw.split(";").map(p => p.trim());
    const nameValue = parts[0];
    const eq = nameValue.indexOf("=");
    const name = eq >= 0 ? nameValue.slice(0, eq).trim() : nameValue;
    const cookie: { name: string; secure?: boolean; httpOnly?: boolean; sameSite?: string; path?: string } = { name };
    for (let i = 1; i < parts.length; i++) {
      const p = parts[i].toLowerCase();
      if (p === "secure") cookie.secure = true;
      else if (p === "httponly") cookie.httpOnly = true;
      else if (p.startsWith("samesite=")) cookie.sameSite = p.slice(9).trim();
      else if (p.startsWith("path=")) cookie.path = p.slice(5).trim();
    }
    cookies.push(cookie);
  }
  return cookies;
}

export function parseSecurityTxt(body: string): Record<string, string> {
  const out: Record<string, string> = {};
  const lines = body.split(/\r?\n/);
  for (const line of lines) {
    const colon = line.indexOf(":");
    if (colon <= 0) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (key && value && ["contact", "expires", "canonical", "preferred-languages", "encryption", "acknowledgments", "policy", "hiring"].includes(key)) {
      out[key] = value;
    }
  }
  return out;
}

export function parseSitemapUrls(body: string, limit = 500): string[] {
  const urls: string[] = [];
  const locRegex = /<loc>\s*([^<]+)\s*<\/loc>/gi;
  let m: RegExpExecArray | null;
  while ((m = locRegex.exec(body)) !== null && urls.length < limit) {
    urls.push(m[1].trim());
  }
  return urls;
}

export async function fetchSitemapUrls(domain: string, limit: number): Promise<string[]> {
  const base = `https://${domain}`;
  const sitemapPaths = ["/sitemap.xml", "/sitemap_index.xml", "/sitemap1.xml", "/sitemap-index.xml"];
  let res = null;
  for (const p of sitemapPaths) {
    res = await httpGet(`${base}${p}`);
    if (res && res.status === 200 && res.body) break;
  }
  if (!res || res.status !== 200 || !res.body) return [];
  const body = res.body;
  // Filter URLs to only those on the target domain (SSRF prevention)
  const isOnDomain = (u: string) => {
    try { return new URL(u).hostname === domain || new URL(u).hostname.endsWith(`.${domain}`); }
    catch { return false; }
  };
  if (/<sitemapindex/i.test(body)) {
    const sitemapLocs = parseSitemapUrls(body, 20).filter(isOnDomain);
    const all: string[] = [];
    for (const loc of sitemapLocs) {
      const sub = await httpGet(loc);
      if (sub && sub.status === 200 && sub.body) all.push(...parseSitemapUrls(sub.body, Math.min(limit, 500)).filter(isOnDomain));
      if (all.length >= limit) break;
    }
    return all.slice(0, limit);
  }
  return parseSitemapUrls(body, limit).filter(isOnDomain);
}
