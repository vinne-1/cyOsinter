import net from "net";
import { runWithConcurrency } from "./utils.js";
import { detectTechnologies, type DetectedTech, type TechCategory } from "./tech-fingerprints.js";

const SOFT_404_PATTERNS = /not found|404|page does not exist|file not found|does not exist/i;
const FORBIDDEN_PATTERNS = /403|forbidden|access denied|permission denied/i;
const UNAUTHORIZED_PATTERNS = /401|unauthorized|login|sign in|authentication/i;
const LOGIN_PATH_PATTERNS = /\/login|\/auth|\/signin|\/wp-login/i;
const SERVER_ERROR_PATTERNS = /500|server error|internal error|service unavailable/i;
const NOT_FOUND_PATTERNS = /404|not found|file not found|page not found/i;

export function classifyPathResponse(status: number): { responseType: string; severity: string } {
  if (status === 404) return { responseType: "not_found", severity: "info" };
  if (status === 403) return { responseType: "forbidden", severity: "medium" };
  if (status === 401) return { responseType: "unauthorized", severity: "low" };
  if (status >= 200 && status < 300) return { responseType: "success", severity: "low" };
  if ([301, 302, 307, 308].includes(status)) return { responseType: "redirect", severity: "low" };
  if (status >= 500) return { responseType: "server_error", severity: "low" };
  return { responseType: "other", severity: "info" };
}

export function validatePathResponse(
  status: number,
  body: string,
  finalUrl: string,
  requestedPath: string,
): { responseType: string; severity: string; validated: boolean; confidence: "high" | "medium" | "low"; redirectTarget?: string } {
  const bodyLower = (body || "").toLowerCase();
  let finalPath = "";
  try {
    finalPath = new URL(finalUrl).pathname;
  } catch {
    finalPath = finalUrl;
  }

  if (status === 404) {
    const validated = NOT_FOUND_PATTERNS.test(bodyLower);
    return { responseType: "not_found", severity: "info", validated, confidence: validated ? "high" : "medium" };
  }

  if (status === 403) {
    const validated = FORBIDDEN_PATTERNS.test(bodyLower);
    return { responseType: "forbidden", severity: "medium", validated, confidence: validated ? "high" : "medium" };
  }

  if (status === 401) {
    const bodyMatch = UNAUTHORIZED_PATTERNS.test(bodyLower);
    const urlMatch = LOGIN_PATH_PATTERNS.test(finalPath);
    const validated = bodyMatch || urlMatch;
    return { responseType: "unauthorized", severity: "low", validated, confidence: validated ? "high" : "medium", redirectTarget: urlMatch ? finalPath : undefined };
  }

  if (status >= 200 && status < 300) {
    if (SOFT_404_PATTERNS.test(bodyLower)) {
      return { responseType: "soft_404", severity: "info", validated: true, confidence: "high" };
    }
    if (requestedPath !== finalPath && LOGIN_PATH_PATTERNS.test(finalPath)) {
      return { responseType: "redirect_to_login", severity: "low", validated: true, confidence: "high", redirectTarget: finalPath };
    }
    return { responseType: "success", severity: "low", validated: true, confidence: "high" };
  }

  if ([301, 302, 307, 308].includes(status)) {
    const isLoginRedirect = LOGIN_PATH_PATTERNS.test(finalPath);
    return {
      responseType: isLoginRedirect ? "redirect_to_login" : "redirect",
      severity: "low",
      validated: true,
      confidence: "high",
      redirectTarget: isLoginRedirect ? finalPath : undefined,
    };
  }

  if (status >= 500) {
    const validated = SERVER_ERROR_PATTERNS.test(bodyLower);
    return { responseType: "server_error", severity: "low", validated, confidence: validated ? "high" : "medium" };
  }

  return { responseType: "other", severity: "info", validated: false, confidence: "low" };
}

/**
 * Detect the technology stack + embedded third-party services from a page's HTML,
 * response headers, and Set-Cookie names. Backed by the keyless fingerprint database
 * in tech-fingerprints.ts, plus generic meta-generator / server-header fallbacks that
 * catch tools not explicitly fingerprinted.
 */
export function detectTechStack(
  html: string,
  headers: Record<string, string>,
  cookies: string[] = [],
): DetectedTech[] {
  const techs = detectTechnologies(html, headers, cookies);
  const seen = new Set(techs.map((t) => t.name.toLowerCase()));
  const add = (name: string, source: string, category: TechCategory, thirdParty = false) => {
    const key = name.trim().toLowerCase();
    if (key && !seen.has(key)) { seen.add(key); techs.push({ name: name.trim(), category, source, thirdParty }); }
  };
  const h = (k: string) => headers[k.toLowerCase()] ?? headers[k];

  // Generic meta-generator / app-name (captures arbitrary tools: Hugo, Jekyll, etc.).
  const gen = html.match(/<meta\s+name=["']generator["']\s+content=["']([^"']+)["']/i);
  if (gen) add(gen[1], "meta generator", "cms");
  const appName = html.match(/<meta\s+name=["']application-name["']\s+content=["']([^"']+)["']/i);
  if (appName) add(appName[1], "meta application-name", "framework");
  // Raw header disclosures not already fingerprinted.
  if (h("x-powered-by")) add(h("x-powered-by"), "X-Powered-By header", "backend");
  if (h("x-generator")) add(h("x-generator"), "X-Generator header", "cms");
  const server = h("server");
  if (server && String(server).toLowerCase() !== "cloudflare") add(server, "Server header", "server");

  return techs;
}

export function scanOpenPorts(host: string, ports: number[], timeoutMs = 2000, concurrency = 25): Promise<number[]> {
  const tryPort = (port: number) =>
    new Promise<boolean>((resolve) => {
      const socket = new net.Socket();
      const timer = setTimeout(() => { socket.destroy(); resolve(false); }, timeoutMs);
      socket.on("connect", () => { clearTimeout(timer); socket.destroy(); resolve(true); });
      socket.on("error", () => { clearTimeout(timer); resolve(false); });
      socket.connect(port, host);
    });
  return runWithConcurrency(ports, concurrency, async (p) => ((await tryPort(p)) ? p : 0)).then((results) => results.filter((p) => p > 0));
}

export function parseSocialTags(html: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of Array.from(html.matchAll(/<meta\s+property=["']og:([^"']+)["']\s+content=["']([^"']*)["']/gi))) out[`og:${m[1].toLowerCase()}`] = m[2];
  for (const m of Array.from(html.matchAll(/<meta\s+name=["']twitter:([^"']+)["']\s+content=["']([^"']*)["']/gi))) out[`twitter:${m[1].toLowerCase()}`] = m[2];
  return out;
}

/** OWASP/securityheaders.com recommended headers with value validation. */
const SECURITY_HEADER_CHECKS = [
  { header: "strict-transport-security", label: "Strict-Transport-Security (HSTS)" },
  { header: "content-security-policy", label: "Content-Security-Policy (CSP)" },
  { header: "x-frame-options", label: "X-Frame-Options" },
  { header: "x-content-type-options", label: "X-Content-Type-Options" },
  { header: "permissions-policy", label: "Permissions-Policy" },
  { header: "referrer-policy", label: "Referrer-Policy" },
  { header: "x-xss-protection", label: "X-XSS-Protection" },
  { header: "cross-origin-embedder-policy", label: "Cross-Origin-Embedder-Policy" },
  { header: "cross-origin-opener-policy", label: "Cross-Origin-Opener-Policy" },
  { header: "cross-origin-resource-policy", label: "Cross-Origin-Resource-Policy" },
  { header: "x-dns-prefetch-control", label: "X-DNS-Prefetch-Control" },
] as const;

export function gradeHeader(header: string, value: string): "A" | "B" | "C" | "N/A" {
  const v = value.toLowerCase().trim();
  switch (header) {
    case "strict-transport-security": {
      const maxAge = v.match(/max-age\s*=\s*(\d+)/i)?.[1];
      if (!maxAge) return "C";
      const age = parseInt(maxAge, 10);
      return age >= 31536000 ? "A" : age >= 0 ? "B" : "C";
    }
    case "x-frame-options":
      return /^(deny|sameorigin|same-origin)$/i.test(v) ? "A" : "C";
    case "x-content-type-options":
      return /nosniff/i.test(v) ? "A" : "C";
    case "content-security-policy":
      return /default-src|script-src|frame-ancestors/i.test(v) ? "A" : "B";
    default:
      return v ? "A" : "N/A";
  }
}

export function checkSecurityHeaders(headers: Record<string, string>): Array<{ header: string; present: boolean; value?: string; issue?: string; grade: "A" | "B" | "C" | "N/A" }> {
  return SECURITY_HEADER_CHECKS.map(({ header, label }) => {
    const value = headers[header] ?? headers[header.toLowerCase()];
    if (!value) return { header: label, present: false, issue: `Missing ${label} header`, grade: "N/A" as const };
    const grade = gradeHeader(header, value);
    return { header: label, present: true, value, grade };
  });
}

export function detectServerInfo(headers: Record<string, string>): string[] {
  const leaks: string[] = [];
  const h = (k: string) => headers[k.toLowerCase()] ?? headers[k];
  if (h("server") && String(h("server")).toLowerCase() !== "cloudflare") leaks.push(`Server: ${h("server")}`);
  if (h("x-powered-by")) leaks.push(`X-Powered-By: ${h("x-powered-by")}`);
  if (h("x-aspnet-version")) leaks.push(`X-AspNet-Version: ${h("x-aspnet-version")}`);
  if (h("x-aspnetmvc-version")) leaks.push(`X-AspNetMvc-Version: ${h("x-aspnetmvc-version")}`);
  if (h("x-runtime")) leaks.push(`X-Runtime: ${h("x-runtime")}`);
  return leaks;
}

export function detectWAF(headers: Record<string, string>): { detected: boolean; provider: string } {
  const h = (k: string) => (headers[k.toLowerCase()] ?? headers[k] ?? "").toLowerCase();
  const server = h("server");

  if (server.includes("cloudflare") || h("cf-ray")) return { detected: true, provider: "Cloudflare" };
  if (h("x-sucuri-id") || h("x-sucuri-cache")) return { detected: true, provider: "Sucuri" };
  if (server.includes("akamaighost") || h("x-akamai-transformed")) return { detected: true, provider: "Akamai" };
  if (h("x-datadome")) return { detected: true, provider: "DataDome" };
  if (server.includes("imperva") || h("x-iinfo")) return { detected: true, provider: "Imperva" };
  if (server.includes("barracuda") || h("barra_counter_session")) return { detected: true, provider: "Barracuda" };
  if (h("x-cdn") === "incapsula" || h("x-cdn") === "imperva") return { detected: true, provider: "Imperva/Incapsula" };
  if (server.includes("awselb") || server.includes("awsalb")) return { detected: true, provider: "AWS WAF" };
  if (h("x-azure-ref")) return { detected: true, provider: "Azure Front Door" };
  return { detected: false, provider: "" };
}

export function detectCDN(headers: Record<string, string>): string {
  const h = (k: string) => (headers[k.toLowerCase()] ?? headers[k] ?? "").toLowerCase();
  const server = h("server");

  if (server.includes("cloudflare") || h("cf-ray") || h("cf-cache-status")) return "Cloudflare";
  if (server.includes("cloudfront") || h("x-amz-cf-id") || h("x-amz-cf-pop")) return "CloudFront";
  if (server.includes("akamaighost") || h("x-akamai-transformed")) return "Akamai";
  if (h("x-fastly-request-id") || h("fastly-debug-digest") || server.includes("fastly")) return "Fastly";
  if (h("x-vercel-id") || server.includes("vercel")) return "Vercel";
  if (h("x-served-by") && h("x-served-by").includes("cache-")) return "Fastly";
  if (h("x-cdn") === "bunny" || server.includes("bunnycdn")) return "BunnyCDN";
  if (h("x-azure-ref") || server.includes("azure")) return "Azure CDN";
  if (h("x-cache") && (h("via") || "").includes("squid")) return "Squid/Proxy";
  if (h("x-cache") || h("x-cache-hits")) return "CDN (unknown)";
  return "None";
}
