/**
 * Wappalyzer Tech Fingerprinting Engine
 *
 * Wraps simple-wappalyzer (MIT) to detect 1500+ technologies from
 * HTTP response headers and HTML body. Returns normalized tech detections
 * with confidence scores, version, and CPE strings for CVE lookups.
 */
import { createLogger } from "../logger";

const log = createLogger("enrichment:wappalyzer");

export interface WappalyzerTech {
  name: string;
  slug: string;
  version: string | null;
  confidence: number;
  cpe: string | null;
  categories: string[];
}

type WapAnalyzeInput = {
  url: string;
  headers: Record<string, string>;
  html: string;
};

// Lazy-loaded to avoid startup cost — only loaded on first call
let wapAnalyzeFn: ((input: WapAnalyzeInput) => Promise<WappalyzerTech[]>) | null = null;

async function getAnalyzeFn(): Promise<(input: WapAnalyzeInput) => Promise<WappalyzerTech[]>> {
  if (wapAnalyzeFn) return wapAnalyzeFn;
  // simple-wappalyzer is a CJS module, compatible with ESM dynamic import
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const mod = await import("simple-wappalyzer") as any;
  // CJS interop: the callable may be on .default or the module itself
  const fn = (typeof mod.default === "function" ? mod.default : mod) as (
    input: WapAnalyzeInput,
  ) => Promise<Array<{
    name: string; slug: string; version?: string; confidence: number;
    cpe?: string; categories: Array<{ name: string }>;
  }>>;
  wapAnalyzeFn = async (input) => {
    const raw = await fn(input);
    return raw.map((t) => ({
      name: t.name,
      slug: t.slug,
      version: t.version ?? null,
      confidence: t.confidence,
      cpe: t.cpe ?? null,
      categories: t.categories.map((c) => c.name),
    }));
  };
  return wapAnalyzeFn;
}

/**
 * Analyze a single URL's response for technologies.
 * Accepts raw HTTP headers (flat string map) and the HTML body.
 * Returns detected technologies sorted by confidence desc.
 */
export async function analyzeUrl(
  url: string,
  headers: Record<string, string>,
  html: string,
): Promise<WappalyzerTech[]> {
  try {
    const analyze = await getAnalyzeFn();
    const results = await analyze({ url, headers, html: html.slice(0, 50_000) });
    return results.sort((a, b) => b.confidence - a.confidence);
  } catch (err) {
    log.warn({ err, url }, "Wappalyzer analysis failed");
    return [];
  }
}

/**
 * Analyze all hosts in rawHeadersByHost + htmlByHost maps.
 * Returns a map of host → detected technologies.
 */
export async function analyzeHosts(
  rawHeadersByHost: Record<string, Record<string, string>>,
  htmlByHost: Record<string, string>,
): Promise<Map<string, WappalyzerTech[]>> {
  const results = new Map<string, WappalyzerTech[]>();

  for (const [host, headers] of Object.entries(rawHeadersByHost)) {
    const html = htmlByHost[host] ?? "";
    const url = `https://${host}`;
    const techs = await analyzeUrl(url, headers, html);
    if (techs.length > 0) {
      results.set(host, techs);
    }
  }

  return results;
}
