/**
 * DAST-Lite: Lightweight Dynamic Application Security Testing.
 * Performs active probes against live targets to detect common web vulnerabilities.
 * Tests: XSS reflection, open redirects, CORS misconfiguration, clickjacking,
 * security header checks, directory listing, HTTP method tampering, cookie security.
 */

import { createLogger } from "../logger";
import { stealthFetch } from "./stealth.js";

const log = createLogger("dast-lite");

export interface DASTFinding {
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  affectedAsset: string;
  evidence: Record<string, unknown>[];
  remediation: string;
}

export interface DASTResults {
  findings: DASTFinding[];
  testsRun: number;
  testsPassed: number;
  duration: number;
}

interface SecurityHeaders {
  contentSecurityPolicy: boolean;
  xFrameOptions: boolean;
  xContentTypeOptions: boolean;
  strictTransportSecurity: boolean;
  referrerPolicy: boolean;
  permissionsPolicy: boolean;
}

const DAST_TIMEOUT_MS = 8000;

async function safeFetch(url: string, options: RequestInit = {}): Promise<Response | null> {
  try {
    // Default to manual redirect (needed by the open-redirect test); callers
    // evaluating headers/cookies/CORS pass redirect:"follow" so they assess the
    // final 2xx response, not an apex->www redirect (a common false-positive).
    return await stealthFetch(url, { ...options, redirect: options.redirect ?? "manual" }, DAST_TIMEOUT_MS);
  } catch {
    return null;
  }
}

async function checkSecurityHeaders(domain: string): Promise<DASTFinding[]> {
  const findings: DASTFinding[] = [];
  const url = `https://${domain}`;
  const res = await safeFetch(url, { redirect: "follow" });
  if (!res) return findings;

  const headers: SecurityHeaders = {
    contentSecurityPolicy: !!res.headers.get("content-security-policy"),
    xFrameOptions: !!res.headers.get("x-frame-options"),
    xContentTypeOptions: !!res.headers.get("x-content-type-options"),
    strictTransportSecurity: !!res.headers.get("strict-transport-security"),
    referrerPolicy: !!res.headers.get("referrer-policy"),
    permissionsPolicy: !!res.headers.get("permissions-policy"),
  };

  if (!headers.contentSecurityPolicy) {
    findings.push({
      title: "Missing Content-Security-Policy Header",
      description: "The application does not set a Content-Security-Policy header, which helps prevent XSS and data injection attacks.",
      severity: "medium",
      category: "security_headers",
      affectedAsset: domain,
      evidence: [{ header: "Content-Security-Policy", present: false, url }],
      remediation: "Add a Content-Security-Policy header with appropriate directives (e.g., default-src 'self').",
    });
  }

  if (!headers.xFrameOptions) {
    findings.push({
      title: "Missing X-Frame-Options Header (Clickjacking)",
      description: "The application can be embedded in frames, making it susceptible to clickjacking attacks.",
      severity: "medium",
      category: "clickjacking",
      affectedAsset: domain,
      evidence: [{ header: "X-Frame-Options", present: false, url }],
      remediation: "Set the X-Frame-Options header to DENY or SAMEORIGIN.",
    });
  }

  if (!headers.xContentTypeOptions) {
    findings.push({
      title: "Missing X-Content-Type-Options Header",
      description: "Without nosniff, browsers may MIME-sniff responses, potentially executing malicious content.",
      severity: "low",
      category: "security_headers",
      affectedAsset: domain,
      evidence: [{ header: "X-Content-Type-Options", present: false, url }],
      remediation: "Set X-Content-Type-Options: nosniff.",
    });
  }

  if (!headers.strictTransportSecurity) {
    findings.push({
      title: "Missing Strict-Transport-Security (HSTS)",
      description: "The application does not enforce HTTPS via HSTS, allowing potential downgrade attacks.",
      severity: "medium",
      category: "transport_security",
      affectedAsset: domain,
      evidence: [{ header: "Strict-Transport-Security", present: false, url }],
      remediation: "Set Strict-Transport-Security with max-age of at least 31536000 and includeSubDomains.",
    });
  }

  if (!headers.referrerPolicy) {
    findings.push({
      title: "Missing Referrer-Policy Header",
      description: "Without a Referrer-Policy, sensitive URLs may be leaked in referrer headers.",
      severity: "low",
      category: "security_headers",
      affectedAsset: domain,
      evidence: [{ header: "Referrer-Policy", present: false, url }],
      remediation: "Set Referrer-Policy to strict-origin-when-cross-origin or no-referrer.",
    });
  }

  return findings;
}

async function checkCORSMisconfiguration(domain: string): Promise<DASTFinding[]> {
  const findings: DASTFinding[] = [];
  const url = `https://${domain}`;

  // Test with null origin
  const nullRes = await safeFetch(url, { headers: { Origin: "null" } });
  if (nullRes) {
    const acao = nullRes.headers.get("access-control-allow-origin");
    if (acao === "null") {
      findings.push({
        title: "CORS Allows Null Origin",
        description: "The server reflects the 'null' Origin in Access-Control-Allow-Origin, which can be exploited via sandboxed iframes.",
        severity: "high",
        category: "cors_misconfiguration",
        affectedAsset: domain,
        evidence: [{ origin: "null", acao, url }],
        remediation: "Do not reflect 'null' in CORS headers. Whitelist specific trusted origins.",
      });
    }
  }

  // Test with arbitrary origin
  const evilOrigin = "https://evil.attacker.com";
  const evilRes = await safeFetch(url, { headers: { Origin: evilOrigin }, redirect: "follow" });
  if (evilRes) {
    const acao = evilRes.headers.get("access-control-allow-origin");
    if (acao === evilOrigin || acao === "*") {
      const acac = evilRes.headers.get("access-control-allow-credentials");
      const isWildcard = acao === "*";
      const withCreds = acac === "true";
      // A bare `Access-Control-Allow-Origin: *` WITHOUT credentials is normal
      // for public APIs/CDNs and not a vulnerability — only credentialed or
      // reflected-origin CORS is genuinely exploitable.
      const severity = withCreds ? "critical" : isWildcard ? "low" : "medium";
      findings.push({
        title: isWildcard ? "CORS Wildcard Origin" : "CORS Reflects Arbitrary Origin",
        description: isWildcard
          ? (withCreds
              ? "The server allows any origin via wildcard CORS AND allows credentials — cross-origin credential theft is possible."
              : "The server sends a wildcard CORS header (Access-Control-Allow-Origin: *) without credentials. Common for public resources; informational unless sensitive data is served here.")
          : "The server reflects untrusted origins in CORS response headers, allowing cross-origin data theft.",
        severity,
        category: "cors_misconfiguration",
        affectedAsset: domain,
        evidence: [{ origin: evilOrigin, acao, credentials: acac, url }],
        remediation: "Implement a strict CORS allowlist of trusted origins. Never reflect arbitrary origins, and never combine a wildcard origin with credentials.",
      });
    }
  }

  return findings;
}

async function checkXSSReflection(domain: string): Promise<DASTFinding[]> {
  const findings: DASTFinding[] = [];
  // Inject an HTML-breaking payload and require it to reflect RAW (unencoded)
  // on a 2xx page. Merely finding the canary text somewhere (e.g. HTML-encoded,
  // or on a 404 error page) is NOT an exploitable reflection — that was a
  // frequent false positive. We only report a genuine, rendered HTML injection.
  const marker = `xqz${Date.now().toString(36)}`;
  const rawPayload = `"><b>${marker}</b>`;
  const rawNeedle = `<b>${marker}</b>`;
  const testPaths = ["/?q=", "/search?query=", "/?search=", "/?s=", "/?name="].map(
    (p) => `${p}${encodeURIComponent(rawPayload)}`,
  );

  for (const path of testPaths) {
    const url = `https://${domain}${path}`;
    const res = await safeFetch(url);
    if (!res) continue;
    // Reflected XSS only matters on a rendered (2xx) response, not an error page.
    if (res.status < 200 || res.status >= 300) continue;
    let body: string;
    try {
      body = await res.text();
    } catch {
      continue;
    }
    const rawReflected = body.includes(rawNeedle);
    if (!rawReflected) continue; // encoded (&lt;b&gt;) or absent => not exploitable
    const csp = res.headers.get("content-security-policy") ?? "";
    findings.push({
      title: "Reflected XSS — Unencoded HTML Injection",
      description: `An HTML-breaking payload injected via ${path} is reflected raw (unencoded) in the 2xx response body, confirming a cross-site scripting sink. ${csp ? "A CSP is present which may mitigate exploitation." : "No CSP header is present, increasing exploitability."}`,
      severity: csp ? "medium" : "high",
      category: "xss",
      affectedAsset: domain,
      evidence: [{ path, payload: rawPayload, rawReflected: true, statusCode: res.status, cspPresent: !!csp, url }],
      remediation: "Contextually encode all user input before rendering in HTML; implement a strong Content-Security-Policy.",
    });
    break; // one confirmed finding is enough
  }

  return findings;
}

async function checkOpenRedirect(domain: string): Promise<DASTFinding[]> {
  const findings: DASTFinding[] = [];
  const evilTarget = "https://evil.attacker.com";
  const testPaths = [
    `/redirect?url=${encodeURIComponent(evilTarget)}`,
    `/login?next=${encodeURIComponent(evilTarget)}`,
    `/goto?to=${encodeURIComponent(evilTarget)}`,
    `/?return_url=${encodeURIComponent(evilTarget)}`,
  ];

  for (const path of testPaths) {
    const url = `https://${domain}${path}`;
    const res = await safeFetch(url);
    if (!res) continue;
    const location = res.headers.get("location") ?? "";
    if ((res.status === 301 || res.status === 302 || res.status === 307 || res.status === 308) && location.includes("evil.attacker.com")) {
      findings.push({
        title: "Open Redirect Vulnerability",
        description: `The application redirects to user-controlled URLs at ${path}, enabling phishing attacks.`,
        severity: "medium",
        category: "open_redirect",
        affectedAsset: domain,
        evidence: [{ path, redirectTo: location, statusCode: res.status, url }],
        remediation: "Validate redirect URLs against a whitelist of allowed destinations. Do not accept full URLs from user input.",
      });
      break;
    }
  }

  return findings;
}

async function checkHTTPMethods(domain: string): Promise<DASTFinding[]> {
  const findings: DASTFinding[] = [];
  const url = `https://${domain}`;
  // TRACE/CONNECT are "forbidden" methods that the fetch API refuses to send
  // (they throw), so testing them here is dead code. Only PUT/DELETE are
  // testable via fetch; a raw-socket TRACE/XST test would be a separate feature.
  const dangerousMethods = ["PUT", "DELETE"];

  for (const method of dangerousMethods) {
    const res = await safeFetch(url, { method });
    if (!res) continue;
    // A generic 200 to PUT/DELETE usually means the server returned the normal
    // page WITHOUT processing the method (a "soft 200") — not a real exposure.
    // Require a strong signal that the method is actually honored:
    //  - 201 Created / 204 No Content (the write actually took effect), or
    //  - an Allow header that advertises the method, or
    //  - for TRACE, the request being echoed back in the body (classic XST).
    const allow = res.headers.get("allow") ?? "";
    let confirmed = false;
    let signal = `status ${res.status}`;
    if (res.status === 201 || res.status === 204) {
      confirmed = true;
      signal = `status ${res.status} (${method} processed)`;
    } else if (new RegExp(`\\b${method}\\b`, "i").test(allow)) {
      confirmed = true;
      signal = `Allow: ${allow}`;
    } else if (method === "TRACE") {
      let body = "";
      try { body = await res.text(); } catch { /* ignore */ }
      if (res.status === 200 && /TRACE\s+\/|X-Forwarded|Host:\s/i.test(body)) {
        confirmed = true;
        signal = "request echoed (Cross-Site Tracing)";
      }
    }
    if (confirmed) {
      findings.push({
        title: `Dangerous HTTP Method Enabled: ${method}`,
        description: `The server honors ${method} requests (${signal}), indicating the method is genuinely enabled.`,
        severity: method === "TRACE" ? "medium" : "low",
        category: "http_methods",
        affectedAsset: domain,
        evidence: [{ method, statusCode: res.status, signal, allow, url }],
        remediation: `Disable the ${method} HTTP method on the web server unless explicitly required.`,
      });
    }
  }

  return findings;
}

async function checkCookieSecurity(domain: string): Promise<DASTFinding[]> {
  const findings: DASTFinding[] = [];
  const url = `https://${domain}`;
  const res = await safeFetch(url, { redirect: "follow" });
  if (!res) return findings;

  const cookies = res.headers.getSetCookie?.() ?? [];
  for (const cookie of cookies) {
    const name = cookie.split("=")[0]?.trim() ?? "unknown";
    const lower = cookie.toLowerCase();
    const issues: string[] = [];

    if (!lower.includes("httponly")) issues.push("missing HttpOnly");
    if (!lower.includes("secure")) issues.push("missing Secure");
    if (!lower.includes("samesite")) issues.push("missing SameSite");

    if (issues.length > 0) {
      findings.push({
        title: `Insecure Cookie: ${name}`,
        description: `Cookie "${name}" is set without security attributes: ${issues.join(", ")}.`,
        severity: "medium",
        category: "cookie_security",
        affectedAsset: domain,
        evidence: [{ cookieName: name, issues, rawHeader: cookie.substring(0, 200) }],
        remediation: "Set HttpOnly, Secure, and SameSite=Strict (or Lax) on all cookies.",
      });
    }
  }

  return findings;
}

async function checkDirectoryListing(domain: string): Promise<DASTFinding[]> {
  const findings: DASTFinding[] = [];
  const testPaths = ["/images/", "/assets/", "/uploads/", "/static/", "/css/", "/js/", "/backup/", "/temp/"];

  for (const path of testPaths) {
    const url = `https://${domain}${path}`;
    const res = await safeFetch(url);
    if (!res || res.status !== 200) continue;
    try {
      const body = await res.text();
      if (body.includes("Index of") || body.includes("Directory listing") || body.includes("<pre>") && body.includes("Parent Directory")) {
        findings.push({
          title: `Directory Listing Enabled: ${path}`,
          description: `Directory listing is enabled at ${path}, exposing file structure and potentially sensitive files.`,
          severity: "medium",
          category: "information_disclosure",
          affectedAsset: domain,
          evidence: [{ path, url, indicator: "Directory listing detected" }],
          remediation: "Disable directory listing in the web server configuration.",
        });
      }
    } catch {
      // body read failure
    }
  }

  return findings;
}

/**
 * Run DAST-Lite scan against a target domain.
 */
export async function runDASTScan(
  domain: string,
  signal?: AbortSignal,
): Promise<DASTResults> {
  const startTime = Date.now();
  log.info({ domain }, "Starting DAST-Lite scan");

  const allFindings: DASTFinding[] = [];
  let testsRun = 0;
  let testsPassed = 0;

  const checks = [
    { name: "Security Headers", fn: () => checkSecurityHeaders(domain) },
    { name: "CORS Misconfiguration", fn: () => checkCORSMisconfiguration(domain) },
    { name: "XSS Reflection", fn: () => checkXSSReflection(domain) },
    { name: "Open Redirect", fn: () => checkOpenRedirect(domain) },
    { name: "HTTP Methods", fn: () => checkHTTPMethods(domain) },
    { name: "Cookie Security", fn: () => checkCookieSecurity(domain) },
    { name: "Directory Listing", fn: () => checkDirectoryListing(domain) },
  ];

  for (const check of checks) {
    if (signal?.aborted) break;
    testsRun++;
    try {
      const results = await check.fn();
      if (results.length === 0) testsPassed++;
      allFindings.push(...results);
    } catch (err) {
      log.warn({ err, check: check.name }, "DAST check failed");
    }
  }

  const duration = Date.now() - startTime;
  log.info({ domain, findingsCount: allFindings.length, testsRun, testsPassed, durationMs: duration }, "DAST-Lite scan complete");

  return {
    findings: allFindings,
    testsRun,
    testsPassed,
    duration,
  };
}
