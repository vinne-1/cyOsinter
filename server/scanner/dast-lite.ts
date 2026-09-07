/**
 * DAST-Lite: Lightweight Dynamic Application Security Testing.
 * Performs active probes against live targets to detect common web vulnerabilities.
 * Tests: XSS reflection, open redirects, CORS misconfiguration, clickjacking,
 * security header checks, directory listing, HTTP method tampering, cookie security.
 */

import { createLogger } from "../logger";
import { analyzeCsp, buildCspFinding } from "./csp-analysis.js";
import { looksLikeDirectoryListing } from "./body-signatures.js";
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

  /*
   * A CSP that EXISTS is not a CSP that protects. The presence bit above let
   * `script-src * 'unsafe-inline' 'unsafe-eval'` pass as configured — see
   * csp-analysis.ts, including the three nuances (nonce disables unsafe-inline,
   * strict-dynamic disables host allowlists, report-only enforces nothing) that
   * make naive CSP checks fire on correctly configured policies.
   */
  const cspHeader = res.headers.get("content-security-policy");
  const cspReportOnly = res.headers.get("content-security-policy-report-only");
  if (cspHeader || cspReportOnly) {
    const analysis = analyzeCsp(cspHeader, cspReportOnly);
    const cspFinding = buildCspFinding(domain, url, cspHeader ?? cspReportOnly ?? "", analysis);
    if (cspFinding) {
      findings.push({
        title: cspFinding.title,
        description: cspFinding.description,
        severity: cspFinding.severity,
        category: cspFinding.category,
        affectedAsset: cspFinding.affectedAsset,
        remediation: cspFinding.remediation,
        evidence: [cspFinding.evidence],
      });
    }
  }

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

/** A crawled endpoint and the parameters it accepts. */
export interface InjectionTarget {
  /** Path only — the domain is added by the check. */
  path: string;
  params: string[];
}

/**
 * Where to inject, most likely to matter first.
 *
 * The old list was five hardcoded guesses (`/?q=`, `/search?query=`, …). An
 * application whose search parameter is `keyword` was never tested at all,
 * while five requests were spent on paths it does not serve. Crawled parameters
 * go first; the guesses remain as the fallback for a site the crawler could not
 * reach, so behaviour never gets worse than it was.
 */
export function buildInjectionTargets(targets: InjectionTarget[], payload: string): string[] {
  const encoded = encodeURIComponent(payload);
  const fromCrawl = targets.flatMap((t) => t.params.map((p) => `${t.path}?${p}=${encoded}`));
  const fallback = ["/?q=", "/search?query=", "/?search=", "/?s=", "/?name="].map((p) => `${p}${encoded}`);
  // Cap the budget: an application with 200 parameters would otherwise turn one
  // check into 200 requests against a live target.
  return Array.from(new Set([...fromCrawl, ...fallback])).slice(0, 15);
}

async function checkXSSReflection(domain: string, targets: InjectionTarget[]): Promise<DASTFinding[]> {
  const findings: DASTFinding[] = [];
  // Inject an HTML-breaking payload and require it to reflect RAW (unencoded)
  // on a 2xx page. Merely finding the canary text somewhere (e.g. HTML-encoded,
  // or on a 404 error page) is NOT an exploitable reflection — that was a
  // frequent false positive. We only report a genuine, rendered HTML injection.
  const marker = `xqz${Date.now().toString(36)}`;
  const rawPayload = `"><b>${marker}</b>`;
  const rawNeedle = `<b>${marker}</b>`;
  // Real parameters found by crawling come first; the guess list is only the
  // fallback for a site the crawler could not reach. Probing `/?q=` on an
  // application whose search parameter is `keyword` tests nothing.
  const testPaths = buildInjectionTargets(targets, rawPayload);

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

async function checkOpenRedirect(domain: string, targets: InjectionTarget[]): Promise<DASTFinding[]> {
  const findings: DASTFinding[] = [];
  const evilTarget = "https://evil.attacker.com";
  // Crawled parameters whose NAME suggests a redirect target, plus the standard
  // guesses. A redirect parameter the application actually has beats four it
  // does not.
  const crawled = targets
    .flatMap((t) => t.params.filter((p) => /^(?:url|next|to|return|return_?url|redirect|redirect_?uri|dest|destination|continue|callback|goto|target)$/i.test(p))
      .map((p) => `${t.path}?${p}=${encodeURIComponent(evilTarget)}`));
  const testPaths = Array.from(new Set([
    ...crawled,
    `/redirect?url=${encodeURIComponent(evilTarget)}`,
    `/login?next=${encodeURIComponent(evilTarget)}`,
    `/goto?to=${encodeURIComponent(evilTarget)}`,
    `/?return_url=${encodeURIComponent(evilTarget)}`,
  ])).slice(0, 12);

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
      // Advertised, not exercised. The scanner will not issue a real PUT or
      // DELETE against a target to prove the point, so the claim has to stay
      // "the server says it accepts this", not "the server processed it".
      confirmed = true;
      signal = `advertised in Allow: ${allow}`;
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
        description: `The server reports that ${method} is enabled (${signal}).`,
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

/**
 * Cookie attribute audit for a host.
 *
 * Emits ONE finding per host rather than one per cookie. A site with 20 cookies
 * missing `Secure` has a single misconfiguration with 20 instances, not 20
 * findings — and reporting it as 20 buries genuinely distinct issues, inflates
 * the severity counts the posture score is built from, and makes every export
 * unreadable. The individual cookies are preserved as structured evidence, so
 * no detail is lost.
 *
 * Severity reflects the worst attribute missing anywhere on the host: a missing
 * `Secure` flag (credentials sent over cleartext) outranks a missing `SameSite`.
 */
// Exported for unit tests; the scan itself calls it through runDASTScan.
export async function checkCookieSecurity(domain: string): Promise<DASTFinding[]> {
  const url = `https://${domain}`;
  const res = await safeFetch(url, { redirect: "follow" });
  if (!res) return [];

  const cookies = res.headers.getSetCookie?.() ?? [];

  const affected: Array<{ cookieName: string; issues: string[]; rawHeader: string }> = [];
  const missing = { secure: 0, httpOnly: 0, sameSite: 0 };

  for (const cookie of cookies) {
    const name = cookie.split("=")[0]?.trim() ?? "unknown";
    const lower = cookie.toLowerCase();
    const issues: string[] = [];

    if (!lower.includes("httponly")) { issues.push("missing HttpOnly"); missing.httpOnly++; }
    if (!lower.includes("secure")) { issues.push("missing Secure"); missing.secure++; }
    if (!lower.includes("samesite")) { issues.push("missing SameSite"); missing.sameSite++; }

    if (issues.length > 0) {
      affected.push({ cookieName: name, issues, rawHeader: cookie.substring(0, 200) });
    }
  }

  if (affected.length === 0) return [];

  // Worst-attribute-wins: Secure is the only one whose absence exposes the
  // cookie value on the wire, so it drives severity on its own.
  const severity: DASTFinding["severity"] = missing.secure > 0 ? "medium" : "low";

  const summary = [
    missing.secure > 0 ? `${missing.secure} missing Secure` : null,
    missing.httpOnly > 0 ? `${missing.httpOnly} missing HttpOnly` : null,
    missing.sameSite > 0 ? `${missing.sameSite} missing SameSite` : null,
  ].filter(Boolean).join(", ");

  const names = affected.map((a) => a.cookieName);
  // Name a handful inline; the full list stays in evidence.
  const preview = names.slice(0, 5).join(", ") + (names.length > 5 ? `, +${names.length - 5} more` : "");

  return [
    {
      title: `Insecure cookie attributes on ${domain} (${affected.length} cookie${affected.length === 1 ? "" : "s"})`,
      description:
        `${affected.length} of ${cookies.length} cookie${cookies.length === 1 ? "" : "s"} set by ${domain} are missing ` +
        `one or more security attributes (${summary}). Affected: ${preview}.`,
      severity,
      category: "cookie_security",
      affectedAsset: domain,
      evidence: [
        { totalCookies: cookies.length, affectedCookies: affected.length, missingCounts: missing },
        ...affected,
      ],
      remediation:
        "Set Secure, HttpOnly and SameSite=Strict (or Lax) on all cookies. Secure is the priority: " +
        "without it the cookie is transmitted over plaintext HTTP. HttpOnly blocks JavaScript access, " +
        "limiting the impact of XSS; SameSite mitigates CSRF.",
    },
  ];
}

/**
 * Directories whose listing actually matters.
 *
 * `/css/`, `/js/`, `/static/`, `/images/` and `/assets/` hold files the site
 * already serves to every visitor by name — an index of them discloses nothing
 * an attacker could not enumerate from the page source. `/backup/`, `/uploads/`
 * and `/temp/` are where files land that nobody meant to publish, so the same
 * misconfiguration is a genuinely different risk there.
 */
const SENSITIVE_LISTING_DIRS = new Set(["/uploads/", "/backup/", "/temp/"]);

async function checkDirectoryListing(domain: string): Promise<DASTFinding[]> {
  const findings: DASTFinding[] = [];
  const testPaths = ["/images/", "/assets/", "/uploads/", "/static/", "/css/", "/js/", "/backup/", "/temp/"];

  for (const path of testPaths) {
    const url = `https://${domain}${path}`;
    const res = await safeFetch(url);
    if (!res || res.status !== 200) continue;
    try {
      const body = await res.text();
      // Shared signature: requires the index furniture (a parent link, sortable
      // column headers, the server's own index markup) — not just the phrase
      // "Index of", which appears in plenty of ordinary page copy.
      if (!looksLikeDirectoryListing(body)) continue;
      const sensitive = SENSITIVE_LISTING_DIRS.has(path);
      findings.push({
        title: `Directory Listing Enabled: ${path}`,
        description: sensitive
          ? `Directory listing is enabled at ${path}. This directory holds uploaded, temporary, or backup files that were not necessarily meant to be published, and anyone can now enumerate them.`
          : `Directory listing is enabled at ${path}. This directory holds static assets the site already serves publicly, so the disclosure is limited to the file inventory itself.`,
        severity: sensitive ? "medium" : "low",
        category: "information_disclosure",
        affectedAsset: domain,
        evidence: [{ path, url, indicator: "Server-generated directory index confirmed", snippet: body.slice(0, 400) }],
        remediation: "Disable directory listing in the web server configuration (Apache: `Options -Indexes`; nginx: `autoindex off`).",
      });
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
  injectionTargets: InjectionTarget[] = [],
): Promise<DASTResults> {
  const startTime = Date.now();
  log.info({ domain, crawledTargets: injectionTargets.length }, "Starting DAST-Lite scan");

  const allFindings: DASTFinding[] = [];
  let testsRun = 0;
  let testsPassed = 0;

  const checks = [
    { name: "Security Headers", fn: () => checkSecurityHeaders(domain) },
    { name: "CORS Misconfiguration", fn: () => checkCORSMisconfiguration(domain) },
    { name: "XSS Reflection", fn: () => checkXSSReflection(domain, injectionTargets) },
    { name: "Open Redirect", fn: () => checkOpenRedirect(domain, injectionTargets) },
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
