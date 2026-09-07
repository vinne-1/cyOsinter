/**
 * Per-asset findings — attributing observations to the host they were made on.
 *
 * ## The gap this closes
 *
 * A Gold scan discovers and analyses every live subdomain: it fetches each
 * one's certificate, grades its security headers, and records its server
 * banner. All of that landed in `reconData.perAssetTls` / `perAssetHeaders` /
 * `perAssetLeaks` and stopped there. **No finding was ever produced from it.**
 * The only header, TLS and disclosure findings a scan emitted were for the apex
 * domain.
 *
 * The consequence was measurable on a real workspace: 90 live subdomains
 * analysed, 263 assets in inventory, and all 31 findings attributed to
 * `example.com`. Because `asset-risk-scoring.ts` matches findings to assets by
 * hostname, it matched exactly ONE of 263 assets, and the Asset Risk page
 * reported 0.0 for everything. The scoring engine was correct; it was being fed
 * data that could not be attributed.
 *
 * ## Why one finding per host, and not one per issue
 *
 * Two failure modes bracket this decision:
 *
 * - One finding per (host, header) would be 90 hosts x 6 headers = 540 rows for
 *   a single misconfiguration. That is the mistake `checkCookieSecurity` was
 *   written to avoid.
 * - One roll-up finding listing every affected host reads well, but re-creates
 *   the attribution bug: it cannot be scored against an asset, assigned to an
 *   owner, or tracked to closure per host.
 *
 * So: **one finding per host per category**, with that host's individual issues
 * preserved as structured evidence. `finding-dedup.ts` then clusters them into
 * a single group for the inbox, and `computeSecurityScore`'s `sqrt(n)`
 * diminishing returns keeps 90 instances of one misconfiguration from behaving
 * like 90 independent problems.
 */

import type { VerifiedFinding } from "./types.js";

/** Headers whose absence is a real weakness rather than missing hardening. */
const CRITICAL_HEADER_LABELS = new Set([
  "Strict-Transport-Security (HSTS)",
  "Content-Security-Policy (CSP)",
  "X-Frame-Options",
  "X-Content-Type-Options",
]);

/**
 * Ceiling on findings emitted per category.
 *
 * A scan of a large estate can find thousands of live subdomains, and one
 * finding each would be unusable however well it is grouped. Past the cap the
 * remainder is summarised in a single overflow finding, so the count stays
 * honest without flooding the inbox.
 */
const PER_CATEGORY_CAP = 150;

export interface PerAssetInputs {
  perAssetHeaders?: Record<string, Record<string, { present?: boolean; value?: string | null }>>;
  perAssetTls?: Record<string, { subject?: string; issuer?: string; daysRemaining?: number; protocol?: string } | null>;
  perAssetLeaks?: Record<string, string[]>;
  /**
   * The scan target. Its own findings are emitted by the main scan path, so
   * re-emitting them here would duplicate every apex finding.
   */
  apex: string;
  now: string;
}

function overflowFinding(
  category: string,
  title: string,
  hidden: string[],
  apex: string,
  now: string,
): VerifiedFinding {
  return {
    title,
    description: `${hidden.length} further host(s) share this issue. They are listed here rather than as individual findings, because one finding per host past the first ${PER_CATEGORY_CAP} would bury every other result. Each remains in the asset inventory and will be reported individually once the count falls below the cap.`,
    severity: "info",
    category,
    kind: "recon",
    affectedAsset: apex,
    cvssScore: "0.0",
    remediation: "Address the issue at the platform or template level rather than host by host — a shared misconfiguration on this many hosts is almost always a single origin, load balancer, or base image.",
    evidence: [{
      type: "host_list",
      description: `${hidden.length} additional affected host(s)`,
      snippet: hidden.join("\n"),
      source: "per-asset analysis",
      verifiedAt: now,
    }],
  };
}

/**
 * Security-header findings, one per live host that is missing something.
 *
 * Mirrors the apex-level rule exactly: a finding is raised when a critical
 * header is absent, or when enough optional headers are absent to be worth a
 * hardening note.
 */
export function buildPerAssetHeaderFindings(input: PerAssetInputs): VerifiedFinding[] {
  const { perAssetHeaders, apex, now } = input;
  if (!perAssetHeaders) return [];

  const findings: VerifiedFinding[] = [];
  const overflow: string[] = [];

  for (const [host, headers] of Object.entries(perAssetHeaders)) {
    if (host === apex) continue; // the main scan path already reported the apex
    const checks = Object.entries(headers);
    if (checks.length === 0) continue;

    const missing = checks.filter(([, v]) => !v?.present).map(([label]) => label);
    const missingCritical = missing.filter((label) => CRITICAL_HEADER_LABELS.has(label));
    if (missingCritical.length === 0 && missing.length < 5) continue;

    if (findings.length >= PER_CATEGORY_CAP) { overflow.push(host); continue; }

    const severity = missingCritical.length >= 2 ? "medium" : missingCritical.length === 1 ? "low" : "info";
    const cvssScore = missingCritical.length >= 2 ? "5.0" : missingCritical.length === 1 ? "3.5" : "1.0";
    const criticalNote = missingCritical.length > 0
      ? ` Critical headers missing: ${missingCritical.join(", ")}.`
      : " All critical headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) are present; only optional hardening headers are missing.";

    findings.push({
      title: `Missing Security Headers on ${host}`,
      description: `${missing.length} of the ${checks.length} checked security headers are missing from the HTTP response on ${host}.${criticalNote} Missing headers: ${missing.join(", ")}.`,
      severity,
      category: "security_headers",
      affectedAsset: host,
      cvssScore,
      remediation: missingCritical.length > 0
        ? "Configure the web server to add the missing critical security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options), then the optional hardening headers."
        : "Optional hardening only: add the remaining headers (e.g. Permissions-Policy, Referrer-Policy) to further reduce attack surface. Not a material vulnerability.",
      evidence: [{
        type: "http_headers",
        description: "Security header analysis of live HTTP response",
        snippet: checks.map(([label, v]) => `${v?.present ? "[PASS]" : "[MISS]"} ${label}${v?.value ? `: ${v.value}` : ""}`).join("\n"),
        url: `https://${host}`,
        source: "HTTP response headers",
        verifiedAt: now,
      }],
    });
  }

  if (overflow.length > 0) {
    findings.push(overflowFinding("security_headers", `Security headers missing on ${overflow.length} further host(s)`, overflow, apex, now));
  }
  return findings;
}

/**
 * Certificate expiry findings, one per host whose certificate is close to — or
 * past — its validity window.
 *
 * A certificate that has already expired is a live outage as well as a security
 * problem, which is why it outranks one that merely expires soon.
 */
export function buildPerAssetTlsFindings(input: PerAssetInputs): VerifiedFinding[] {
  const { perAssetTls, apex, now } = input;
  if (!perAssetTls) return [];

  const findings: VerifiedFinding[] = [];
  const overflow: string[] = [];

  for (const [host, tls] of Object.entries(perAssetTls)) {
    if (host === apex) continue;
    const days = tls?.daysRemaining;
    if (typeof days !== "number" || !Number.isFinite(days)) continue;
    if (days > 30) continue;

    if (findings.length >= PER_CATEGORY_CAP) { overflow.push(host); continue; }

    const expired = days < 0;
    const severity = expired ? "critical" : days <= 14 ? "high" : "medium";
    const cvssScore = expired ? "9.1" : days <= 14 ? "7.4" : "5.3";

    findings.push({
      title: expired
        ? `Expired TLS Certificate on ${host}`
        : `TLS Certificate Expiring in ${days} Day(s) on ${host}`,
      description: expired
        ? `The TLS certificate served by ${host} expired ${Math.abs(days)} day(s) ago. Browsers will refuse the connection with an interstitial, and any client that has been configured to ignore the warning is no longer authenticating the server at all.`
        : `The TLS certificate served by ${host} expires in ${days} day(s). Once it lapses, browsers will block the site outright.`,
      severity,
      category: "ssl_issue",
      affectedAsset: host,
      cvssScore,
      remediation: "Renew the certificate and automate renewal (ACME/Let's Encrypt or the platform's managed certificate service) so expiry cannot recur. Verify the renewal actually reaches this host — a wildcard renewed on the load balancer does not update an origin serving its own certificate.",
      evidence: [{
        type: "tls_certificate",
        description: "Certificate observed on the live TLS endpoint",
        snippet: [
          `Host: ${host}`,
          `Subject: ${tls?.subject ?? "unknown"}`,
          `Issuer: ${tls?.issuer ?? "unknown"}`,
          `Protocol: ${tls?.protocol ?? "unknown"}`,
          `Days remaining: ${days}`,
        ].join("\n"),
        url: `https://${host}`,
        source: "TLS handshake",
        verifiedAt: now,
      }],
    });
  }

  if (overflow.length > 0) {
    findings.push(overflowFinding("ssl_issue", `TLS certificates expiring on ${overflow.length} further host(s)`, overflow, apex, now));
  }
  return findings;
}

/**
 * Server banner disclosure, one finding per host that advertises its software
 * version.
 */
export function buildPerAssetLeakFindings(input: PerAssetInputs): VerifiedFinding[] {
  const { perAssetLeaks, apex, now } = input;
  if (!perAssetLeaks) return [];

  const findings: VerifiedFinding[] = [];
  const overflow: string[] = [];

  for (const [host, leaks] of Object.entries(perAssetLeaks)) {
    if (host === apex) continue;
    if (!leaks || leaks.length === 0) continue;

    if (findings.length >= PER_CATEGORY_CAP) { overflow.push(host); continue; }

    findings.push({
      title: `Server Version Information Disclosed on ${host}`,
      description: `The web server at ${host} exposes version information in HTTP response headers, which lets an attacker match the host against known vulnerabilities for that exact build instead of probing for them.`,
      severity: "low",
      category: "information_disclosure",
      affectedAsset: host,
      cvssScore: "3.0",
      remediation: "Configure the web server to suppress version information in headers (nginx: `server_tokens off`; Apache: `ServerTokens Prod`; and remove `X-Powered-By` at the application layer).",
      evidence: [{
        type: "http_headers",
        description: "Server information leak in HTTP response headers",
        snippet: leaks.join("\n"),
        url: `https://${host}`,
        source: "HTTP response headers",
        verifiedAt: now,
      }],
    });
  }

  if (overflow.length > 0) {
    findings.push(overflowFinding("information_disclosure", `Server version disclosed on ${overflow.length} further host(s)`, overflow, apex, now));
  }
  return findings;
}

/** Every per-asset finding the collected recon supports. */
export function buildPerAssetFindings(input: PerAssetInputs): VerifiedFinding[] {
  return [
    ...buildPerAssetHeaderFindings(input),
    ...buildPerAssetTlsFindings(input),
    ...buildPerAssetLeakFindings(input),
  ];
}
