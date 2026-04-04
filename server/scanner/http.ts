export async function fetchJSON(url: string, timeoutMs = 10000): Promise<any> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "Cyshield-Scanner/1.0" },
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export async function fetchText(url: string, timeoutMs = 10000): Promise<string | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "Cyshield-Scanner/1.0" },
      redirect: "follow",
    });
    if (!res.ok) return null;
    return await res.text();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export async function httpHead(url: string, timeoutMs = 8000): Promise<{ status: number; headers: Record<string, string>; redirectUrl?: string } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: "HEAD",
      signal: controller.signal,
      headers: { "User-Agent": "Cyshield-Scanner/1.0" },
      redirect: "follow",
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    return { status: res.status, headers, redirectUrl: res.url !== url ? res.url : undefined };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export async function httpGet(url: string, timeoutMs = 8000): Promise<{ status: number; headers: Record<string, string>; body: string; finalUrl: string } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "Cyshield-Scanner/1.0" },
      redirect: "follow",
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    const body = await res.text();
    return { status: res.status, headers, body: body.substring(0, 5000), finalUrl: res.url };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export async function httpGetNoRedirect(url: string, timeoutMs = 6000): Promise<{ status: number; headers: Record<string, string>; location?: string } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "Cyshield-Scanner/1.0" },
      redirect: "manual",
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    const location = res.headers.get("location") ?? undefined;
    return { status: res.status, headers, location };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
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
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "Cyshield-Scanner/1.0" },
      redirect: "follow",
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    const setCookieStrings = typeof (res.headers as any).getSetCookie === "function" ? (res.headers as any).getSetCookie() : (headers["set-cookie"] ? [headers["set-cookie"]] : []);
    const body = await res.text();
    return { status: res.status, body: body.substring(0, 100000), headers, setCookieStrings, finalUrl: res.url };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
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
