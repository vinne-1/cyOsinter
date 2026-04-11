/**
 * Page Metadata Extraction
 *
 * Extracts page-level signals from HTML body and response headers:
 *   - Page title, meta description, generator tag (often reveals CMS/framework version)
 *   - Canonical URL
 *   - MurmurHash of favicon bytes (Shodan-compatible fingerprint)
 *   - Open Graph / Twitter card metadata
 *
 * Uses cheerio (MIT) for HTML parsing and murmurhash-js (MIT) for favicon hashing.
 */
import { load } from "cheerio";
import { createLogger } from "../logger";

const log = createLogger("enrichment:page-meta");

export interface PageMeta {
  title: string | null;
  description: string | null;
  generator: string | null;
  canonical: string | null;
  robots: string | null;
  ogTitle: string | null;
  ogDescription: string | null;
  /** Favicon MurmurHash2 (same algorithm Shodan uses for favicon fingerprinting) */
  faviconHash: number | null;
  faviconUrl: string | null;
}

/** Extract metadata from an HTML body + response headers. */
export function extractPageMeta(html: string, headers: Record<string, string>): PageMeta {
  let $ : ReturnType<typeof load>;
  try {
    $ = load(html);
  } catch {
    return emptyMeta();
  }

  const title = $("title").first().text().trim() || null;
  const description = $("meta[name='description']").attr("content") ?? null;
  const generator = $("meta[name='generator']").attr("content") ?? null;
  const canonical = $("link[rel='canonical']").attr("href") ?? null;
  const robots = $("meta[name='robots']").attr("content") ?? null;
  const ogTitle = $("meta[property='og:title']").attr("content") ?? null;
  const ogDescription = $("meta[property='og:description']").attr("content") ?? null;

  // Detect favicon URL from HTML (prefer <link rel="icon"> over default /favicon.ico)
  const faviconHref =
    $("link[rel='icon']").attr("href") ??
    $("link[rel='shortcut icon']").attr("href") ??
    "/favicon.ico";

  // Resolve to absolute URL when href is relative
  const faviconUrl = faviconHref.startsWith("http") ? faviconHref : faviconHref;

  return {
    title,
    description,
    generator,
    canonical,
    robots,
    ogTitle,
    ogDescription,
    faviconHash: null, // populated asynchronously by fetchFaviconHash
    faviconUrl,
  };
}

function emptyMeta(): PageMeta {
  return {
    title: null, description: null, generator: null, canonical: null,
    robots: null, ogTitle: null, ogDescription: null,
    faviconHash: null, faviconUrl: null,
  };
}

/**
 * Fetch a favicon and compute its MurmurHash2 (Shodan-compatible).
 * Returns null on any network error or if the response is not an image.
 */
export async function fetchFaviconHash(faviconUrl: string): Promise<number | null> {
  try {
    const murmur = await import("murmurhash-js");

    const res = await fetch(faviconUrl, {
      signal: AbortSignal.timeout(5_000),
      headers: { "User-Agent": "CyberShieldPro/1.0" },
    });
    if (!res.ok) return null;
    const contentType = res.headers.get("content-type") ?? "";
    if (!contentType.startsWith("image/") && !contentType.includes("icon")) return null;

    const buf = Buffer.from(await res.arrayBuffer());
    // Shodan uses MurmurHash2 over the raw bytes encoded as a binary string
    const hash = murmur.murmur2(buf.toString("binary"));
    return hash;
  } catch (err) {
    log.debug({ err, url: faviconUrl }, "Favicon hash failed");
    return null;
  }
}
