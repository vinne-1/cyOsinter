/**
 * Version Parser — extracts product/version from server banners and HTTP headers.
 * Pure module: no DB, no I/O.
 */

export interface DetectedTech {
  product: string;
  version: string | null;
  source: string;
  confidence: number;
}

/** EOL version rules: [product, maxEolVersion (exclusive), notes] */
const EOL_RULES: Array<{ product: string; eolBelow: string }> = [
  { product: "php", eolBelow: "8.1" },
  { product: "nginx", eolBelow: "1.18" },
  { product: "apache", eolBelow: "2.4" },
  { product: "openssl", eolBelow: "1.1.1" },
  { product: "python", eolBelow: "3.8" },
  { product: "node", eolBelow: "18" },
  { product: "iis", eolBelow: "10" },
  { product: "tomcat", eolBelow: "9" },
  { product: "jetty", eolBelow: "9.4" },
  { product: "wordpress", eolBelow: "6.0" },
  { product: "drupal", eolBelow: "9" },
  { product: "joomla", eolBelow: "4" },
];

/** Banner → (product, version) regex patterns. Each entry: [regex, productName, versionGroup] */
const BANNER_PATTERNS: Array<[RegExp, string, number]> = [
  [/nginx\/(\d+\.\d+(?:\.\d+)?)/i, "nginx", 1],
  [/apache\/(\d+\.\d+(?:\.\d+)?)/i, "apache", 1],
  [/openssl\/(\d+\.\d+(?:\.\d+)?[a-z]?)/i, "openssl", 1],
  [/php\/(\d+\.\d+(?:\.\d+)?)/i, "php", 1],
  [/tomcat\/(\d+\.\d+(?:\.\d+)?)/i, "tomcat", 1],
  [/jetty\/(\d+\.\d+(?:\.\d+)?)/i, "jetty", 1],
  [/microsoft-iis\/(\d+\.\d+)/i, "iis", 1],
  [/kestrel\/(\d+\.\d+(?:\.\d+)?)/i, "kestrel", 1],
  [/gunicorn\/(\d+\.\d+(?:\.\d+)?)/i, "gunicorn", 1],
  [/express\/(\d+\.\d+(?:\.\d+)?)/i, "express", 1],
  [/lighttpd\/(\d+\.\d+(?:\.\d+)?)/i, "lighttpd", 1],
  [/litespeed\/(\d+\.\d+(?:\.\d+)?)/i, "litespeed", 1],
  [/caddy\/(\d+\.\d+(?:\.\d+)?)/i, "caddy", 1],
  [/x-powered-by:\s*php\/(\d+\.\d+(?:\.\d+)?)/i, "php", 1],
  [/x-powered-by:\s*([a-z][a-z0-9_-]+)\/(\d+\.\d+(?:\.\d+)?)/i, "$1", 2],
  [/wp-(?:content|includes|login)/i, "wordpress", 0],
  [/drupal\s+(\d+)/i, "drupal", 1],
  [/joomla(?:!|\s+(\d+))?/i, "joomla", 1],
  [/struts\/(\d+\.\d+(?:\.\d+)?)/i, "struts", 1],
  [/jenkins\s+(\d+\.\d+(?:\.\d+)?)/i, "jenkins", 1],
  [/python\/(\d+\.\d+(?:\.\d+)?)/i, "python", 1],
  [/node\.js\/(\d+\.\d+(?:\.\d+)?)/i, "node", 1],
];

/** Compare two dotted version strings: returns -1, 0, or 1. */
export function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const da = pa[i] ?? 0;
    const db = pb[i] ?? 0;
    if (da < db) return -1;
    if (da > db) return 1;
  }
  return 0;
}

/** Determine if a detected version is EOL. */
export function isEol(product: string, version: string | null): boolean {
  if (!version) return false;
  const rule = EOL_RULES.find((r) => r.product === product.toLowerCase());
  if (!rule) return false;
  // Strip non-numeric suffix for comparison (1.1.1k → 1.1.1)
  const cleanVersion = version.replace(/[a-z]+$/i, "");
  return compareVersions(cleanVersion, rule.eolBelow) < 0;
}

/** Normalize product name to lowercase canonical form. */
export function normalizeProduct(raw: string): string {
  return raw
    .toLowerCase()
    .replace(/^x-powered-by:\s*/i, "")
    .replace(/^server:\s*/i, "")
    .trim();
}

/** Extract tech detections from a single banner string (Server header value, etc.). */
export function extractFromBanner(banner: string, source: string): DetectedTech[] {
  const results: DetectedTech[] = [];
  for (const [pattern, productName, group] of BANNER_PATTERNS) {
    const m = pattern.exec(banner);
    if (!m) continue;
    const product = normalizeProduct(
      productName === "$1" ? (m[1] ?? "unknown") : productName,
    );
    const version = group > 0 ? (m[group] ?? null) : null;
    if (!product || product === "unknown") continue;
    results.push({
      product,
      version,
      source,
      confidence: version ? 90 : 70,
    });
  }
  return results;
}

/** Extract tech from a headers map (key → value). */
export function extractFromHeaders(headers: Record<string, string>): DetectedTech[] {
  const results: DetectedTech[] = [];
  for (const [key, value] of Object.entries(headers)) {
    const headerLine = `${key}: ${value}`;
    results.push(...extractFromBanner(headerLine, "header"));
  }
  return results;
}
