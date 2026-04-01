/**
 * DAST-Lite: Lightweight Dynamic Application Security Testing.
 * Performs active probes against live targets to detect common web vulnerabilities.
 * Tests: XSS reflection, open redirects, CORS misconfiguration, clickjacking,
 * security header checks, directory listing, HTTP method tampering, cookie security.
 */

import { createLogger } from "../logger";

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
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DAST_TIMEOUT_MS);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal, redirect: "manual" });
    clearTimeout(timer);
    return res;
  } catch {
    clearTimeout(timer);
    return null;
  }
}

async function checkSecurityHeaders(domain: string): Promise<DASTFinding[]> {
  const findings: DASTFinding[] = [];
  const url = `https://${domain}`;
  const res = await safeFetch(url);
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
  const evilRes = await safeFetch(url, { headers: { Origin: evilOrigin } });
  if (evilRes) {
    const acao = evilRes.headers.get("access-control-allow-origin");
    if (acao === evilOrigin || acao === "*") {
      const acac = evilRes.headers.get("access-control-allow-credentials");
      findings.push({
        title: acao === "*" ? "CORS Wildcard Origin" : "CORS Reflects Arbitrary Origin",
        description: acao === "*"
          ? "The server allows any origin via wildcard CORS. If credentials are also allowed, this is exploitable."
          : "The server reflects untrusted origins in CORS headers, allowing cross-origin data theft.",
        severity: acac === "true" ? "critical" : "high",
        category: "cors_misconfiguration",
        affectedAsset: domain,
        evidence: [{ origin: evilOrigin, acao, credentials: acac, url }],
        remediation: "Implement a strict CORS whitelist. Never reflect arbitrary origins with credentials.",
      });
    }
  }

  return findings;
}

async function checkXSSReflection(domain: string): Promise<DASTFinding[]> {
  const findings: DASTFinding[] = [];
  const canary = `csp_xss_${Date.now()}`;
  const testPaths = [
    `/?q=${encodeURIComponent(canary)}`,
    `/search?query=${encodeURIComponent(canary)}`,
    `/?search=${encodeURIComponent(canary)}`,
    `/?name=${encodeURIComponent(canary)}`,
  ];

  for (const path of testPaths) {
    const url = `https://${domain}${path}`;
    const res = await safeFetch(url);
    if (!res) continue;
    try {
      const body = await res.text();
      if (body.includes(canary)) {
        const csp = res.headers.get("content-security-policy") ?? "";
        findings.push({
          title: "Potential XSS Reflection Point",
          description: `User input is reflected unencoded in the response body at ${path}. ${csp ? "CSP is present which may mitigate exploitation." : "No CSP header detected, increasing exploitability."}`,
          severity: csp ? "medium" : "high",
          category: "xss",
          affectedAsset: domain,
          evidence: [{ path, canary, reflected: true, cspPresent: !!csp, url }],
          remediation: "Encode all user input before rendering in HTML. Implement a Content-Security-Policy.",
        });
        break; // one finding is enough
      }
    } catch {
      // body read failed
    }
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
  const dangerousMethods = ["PUT", "DELETE", "TRACE", "CONNECT"];

  for (const method of dangerousMethods) {
    const res = await safeFetch(url, { method });
    if (!res) continue;
    if (res.status !== 405 && res.status !== 501 && res.status !== 403 && res.status < 400) {
      findings.push({
        title: `Dangerous HTTP Method Enabled: ${method}`,
        description: `The server responds with status ${res.status} to ${method} requests, indicating the method is enabled.`,
        severity: method === "TRACE" ? "medium" : "low",
        category: "http_methods",
        affectedAsset: domain,
        evidence: [{ method, statusCode: res.status, url }],
        remediation: `Disable the ${method} HTTP method on the web server unless explicitly required.`,
      });
    }
  }

  return findings;
}

async function checkCookieSecurity(domain: string): Promise<DASTFinding[]> {
  const findings: DASTFinding[] = [];
  const url = `https://${domain}`;
  const res = await safeFetch(url);
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
