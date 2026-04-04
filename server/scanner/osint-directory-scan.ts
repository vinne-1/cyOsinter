/**
 * Directory bruteforce path classification for OSINT scans.
 *
 * Extracted from osint-scan.ts to keep the main scan orchestrator lean.
 */

import { httpGet } from "./http.js";
import { validatePathResponse } from "./detection.js";
import { OSINT_CREDENTIAL_PATHS, OSINT_DOCUMENT_PATHS, type VerifiedFinding } from "./constants.js";
import { hasCredentialPattern, redactCredentialValues } from "./osint-helpers.js";

type PathCheckResult = {
  path: string;
  label: string;
  result: { status: number; headers: Record<string, string>; body: string; finalUrl: string } | null;
};

export type ExposedPath = { path: string; label: string; status: number; snippet: string };

/**
 * Establish a soft-404 fingerprint by requesting a random non-existent path.
 * Returns null if the server returns a real 404 (no custom error page).
 */
export async function establishSoft404Fingerprint(domain: string): Promise<string | null> {
  const random = Math.random().toString(36).slice(2, 10);
  const testPath = `/nxtest-${random}-doesnotexist`;
  try {
    const r = await httpGet(`https://${domain}${testPath}`);
    if (r && r.status === 200 && r.body) {
      return `${r.body.length}:${r.body.slice(0, 100).replace(/\s+/g, "")}`;
    }
  } catch { /* ignore */ }
  return null;
}

export interface ClassifyResult {
  findings: VerifiedFinding[];
  exposedPaths: ExposedPath[];
}

/**
 * Classify each path check result into security findings.
 * Handles .env, .git, credentials, server-status, actuator, phpinfo,
 * directory listing, documents, robots.txt, and swagger/openapi.
 */
export function classifyPathResults(
  domain: string,
  pathCheckResults: PathCheckResult[],
  soft404Fingerprint: string | null,
  now: string,
): ClassifyResult {
  const findings: VerifiedFinding[] = [];
  const exposedPaths: ExposedPath[] = [];

  for (const r of pathCheckResults) {
    if (!r.result) continue;
    const { path: rPath, label, result } = r;
    const pathValidation = validatePathResponse(result.status, result.body, result.finalUrl, rPath);
    if (result.status !== 200) continue;

    // Soft-404 check
    if (soft404Fingerprint && result.body) {
      const bodyFingerprint = `${result.body.length}:${result.body.slice(0, 100).replace(/\s+/g, "")}`;
      if (bodyFingerprint === soft404Fingerprint) continue;
    }

    if (rPath === "/.env" && result.body) {
      const hasSecrets = hasCredentialPattern(result.body);
      const redacted = redactCredentialValues(result.body.substring(0, 500));
      findings.push({
        title: `Exposed Environment File (.env) on ${domain}`,
        description: hasSecrets
          ? `The .env file at ${domain}/.env is publicly accessible and appears to contain sensitive configuration values (passwords, API keys, tokens).`
          : `The .env file at ${domain}/.env is publicly accessible. It may contain sensitive configuration.`,
        severity: hasSecrets ? "critical" : "high",
        category: hasSecrets ? "leaked_credential" : "data_leak",
        affectedAsset: domain,
        cvssScore: hasSecrets ? "9.8" : "7.5",
        remediation: "Immediately block public access to .env files. Rotate all exposed credentials. Configure web server to deny access to dotfiles.",
        evidence: [{
          type: "http_response",
          description: hasSecrets ? "Publicly accessible .env file with sensitive data patterns" : "Publicly accessible .env file",
          url: `https://${domain}${rPath}`,
          snippet: `HTTP Status: 200 OK\nSensitive patterns detected: ${hasSecrets ? "Yes" : "No"}\n\nRedacted content preview:\n${redacted}`,
          source: "HTTP GET request",
          verifiedAt: now,
          validated: pathValidation.validated,
          confidence: pathValidation.confidence,
        }],
      });
      continue;
    }

    if (rPath === "/.git/config" && result.body.includes("[core]")) {
      const hasSecrets = hasCredentialPattern(result.body);
      const snippet = hasSecrets ? redactCredentialValues(result.body.substring(0, 300)) : result.body.substring(0, 300);
      findings.push({
        title: `Exposed Git Repository on ${domain}`,
        description: hasSecrets
          ? `The .git directory at ${domain}/.git/config is publicly accessible and contains credential-like patterns.`
          : `The .git directory at ${domain}/.git/config is publicly accessible. This can expose source code, commit history, and potentially sensitive files.`,
        severity: hasSecrets ? "critical" : "high",
        category: hasSecrets ? "leaked_credential" : "data_leak",
        affectedAsset: domain,
        cvssScore: hasSecrets ? "9.0" : "7.5",
        remediation: "Block public access to .git directories. Configure web server rules to deny access to all dotfiles and directories.",
        evidence: [{
          type: "http_response",
          description: "Git configuration file publicly accessible",
          url: `https://${domain}${rPath}`,
          snippet: `HTTP Status: 200 OK\n\nContent preview:\n${snippet}`,
          source: "HTTP GET request",
          verifiedAt: now,
          validated: pathValidation.validated,
          confidence: pathValidation.confidence,
        }],
      });
      continue;
    }

    if (OSINT_CREDENTIAL_PATHS.includes(rPath) && result.body && hasCredentialPattern(result.body)) {
      const redacted = redactCredentialValues(result.body.substring(0, 500));
      findings.push({
        title: `Exposed Credential File (${rPath}) on ${domain}`,
        description: `The file ${rPath} at ${domain} is publicly accessible and contains credential-like patterns (passwords, API keys, tokens).`,
        severity: "critical",
        category: "leaked_credential",
        affectedAsset: domain,
        cvssScore: "9.8",
        remediation: "Immediately block public access to credential and configuration files. Rotate all exposed credentials.",
        evidence: [{
          type: "http_response",
          description: "Publicly accessible credential file with sensitive data patterns",
          url: `https://${domain}${rPath}`,
          snippet: `HTTP Status: 200 OK\n\nRedacted content preview:\n${redacted}`,
          source: "HTTP GET request",
          verifiedAt: now,
          validated: pathValidation.validated,
          confidence: pathValidation.confidence,
        }],
      });
      continue;
    }

    if (rPath === "/server-status" && result.body.includes("Apache Server Status")) {
      findings.push({
        title: `Apache Server Status Page Exposed on ${domain}`,
        description: `The Apache server-status page is publicly accessible at ${domain}/server-status.`,
        severity: "medium",
        category: "infrastructure_disclosure",
        affectedAsset: domain,
        cvssScore: "5.3",
        remediation: "Restrict access to /server-status to internal networks or specific IP addresses only.",
        evidence: [{
          type: "http_response",
          description: "Apache server-status page publicly accessible",
          url: `https://${domain}${rPath}`,
          snippet: `HTTP Status: 200 OK\nContent includes: Apache Server Status\n\nPreview:\n${result.body.substring(0, 300)}`,
          source: "HTTP GET request",
          verifiedAt: now,
          validated: pathValidation.validated,
          confidence: pathValidation.confidence,
        }],
      });
      continue;
    }

    if ((rPath === "/actuator" || rPath === "/actuator/health") && result.body && (result.body.includes('"status"') || result.body.includes("UP"))) {
      findings.push({
        title: `Spring Boot Actuator Exposed on ${domain}`,
        description: `The actuator endpoint at ${domain}${rPath} is publicly accessible.`,
        severity: "medium",
        category: "infrastructure_disclosure",
        affectedAsset: domain,
        cvssScore: "5.3",
        remediation: "Restrict access to actuator endpoints. Use Spring Security to protect /actuator.",
        evidence: [{
          type: "http_response",
          description: "Spring Boot actuator publicly accessible",
          url: `https://${domain}${rPath}`,
          snippet: `HTTP Status: 200 OK\n\nPreview:\n${result.body.substring(0, 300)}`,
          source: "HTTP GET request",
          verifiedAt: now,
          validated: pathValidation.validated,
          confidence: pathValidation.confidence,
        }],
      });
      continue;
    }

    if ((rPath === "/phpinfo.php" || rPath === "/info.php") && (result.body.includes("PHP Version") || result.body.includes("phpinfo()"))) {
      findings.push({
        title: `PHP Info Page Exposed on ${domain}`,
        description: `The phpinfo page at ${domain}${rPath} is publicly accessible.`,
        severity: "medium",
        category: "infrastructure_disclosure",
        affectedAsset: domain,
        cvssScore: "5.3",
        remediation: "Remove or restrict access to phpinfo pages. Use them only in development environments.",
        evidence: [{
          type: "http_response",
          description: "phpinfo page publicly accessible",
          url: `https://${domain}${rPath}`,
          snippet: `HTTP Status: 200 OK\n\nPreview:\n${result.body.substring(0, 300)}`,
          source: "HTTP GET request",
          verifiedAt: now,
          validated: pathValidation.validated,
          confidence: pathValidation.confidence,
        }],
      });
      continue;
    }

    if (result.body && (result.body.includes("Index of /") || result.body.includes("Directory listing"))) {
      findings.push({
        title: `Directory Listing Exposed on ${domain}${rPath}`,
        description: `Directory listing is enabled at ${domain}${rPath}. This exposes file structure.`,
        severity: "medium",
        category: "data_leak",
        affectedAsset: domain,
        cvssScore: "5.3",
        remediation: "Disable directory listing in web server configuration.",
        evidence: [{
          type: "http_response",
          description: "Directory listing detected",
          url: `https://${domain}${rPath}`,
          snippet: `HTTP Status: 200 OK\n\nPreview:\n${result.body.substring(0, 400)}`,
          source: "HTTP GET request",
          verifiedAt: now,
          validated: pathValidation.validated,
          confidence: pathValidation.confidence,
        }],
      });
      continue;
    }

    if (OSINT_DOCUMENT_PATHS.includes(rPath)) {
      findings.push({
        title: `Exposed Document Path (${rPath}) on ${domain}`,
        description: `The path ${rPath} at ${domain} is publicly accessible. This may expose documents, backups, or uploads.`,
        severity: "medium",
        category: "data_leak",
        affectedAsset: domain,
        cvssScore: "5.3",
        remediation: "Restrict access to document directories. Ensure sensitive files are not publicly accessible.",
        evidence: [{
          type: "http_response",
          description: "Document path publicly accessible",
          url: `https://${domain}${rPath}`,
          snippet: `HTTP Status: 200 OK\n\nPreview:\n${result.body.substring(0, 400)}`,
          source: "HTTP GET request",
          verifiedAt: now,
          validated: pathValidation.validated,
          confidence: pathValidation.confidence,
        }],
      });
      continue;
    }

    if (rPath === "/robots.txt" && result.body) {
      const disallowLines = result.body.split("\n").filter((l: string) => l.trim().toLowerCase().startsWith("disallow:"));
      const sensitiveDisallows = disallowLines.filter((l: string) => {
        const p = l.split(":").slice(1).join(":").trim().toLowerCase();
        return /admin|backup|internal|private|secret|config|database|wp-admin|phpmyadmin|dashboard|api|debug/.test(p);
      });
      if (sensitiveDisallows.length > 0) {
        exposedPaths.push({ path: rPath, label, status: 200, snippet: result.body.substring(0, 500) });
      }
    }

    if ((rPath === "/swagger.json" || rPath === "/api/docs" || rPath === "/openapi.json") && result.body.length > 50) {
      findings.push({
        title: `Exposed API Documentation (Swagger/OpenAPI) on ${domain}`,
        description: `${rPath} at ${domain} is publicly accessible. This exposes API structure and potentially sensitive schema details.`,
        severity: "low",
        category: "infrastructure_disclosure",
        affectedAsset: domain,
        cvssScore: "3.1",
        remediation: `Restrict access to ${rPath} or ensure it does not expose sensitive API details.`,
        evidence: [{
          type: "http_response",
          description: "Swagger/OpenAPI documentation publicly accessible",
          url: `https://${domain}${rPath}`,
          snippet: `HTTP Status: 200 OK\n\nPreview:\n${result.body.substring(0, 400)}`,
          source: "HTTP GET request",
          verifiedAt: now,
          validated: pathValidation.validated,
          confidence: pathValidation.confidence,
        }],
      });
      continue;
    }
  }

  return { findings, exposedPaths };
}

/**
 * Convert collected exposed paths (robots.txt, etc.) into findings.
 */
export function buildExposedPathFindings(
  domain: string,
  exposedPaths: ExposedPath[],
  now: string,
): VerifiedFinding[] {
  const findings: VerifiedFinding[] = [];

  for (const ep of exposedPaths) {
    if (ep.path === "/robots.txt") {
      findings.push({
        title: `Robots.txt Reveals Sensitive Paths on ${domain}`,
        description: `The robots.txt file on ${domain} contains Disallow entries that hint at sensitive internal paths.`,
        severity: "info",
        category: "information_disclosure",
        affectedAsset: domain,
        cvssScore: "2.0",
        remediation: "Review robots.txt entries. Ensure listed paths are properly authenticated.",
        evidence: [{
          type: "http_response",
          description: "robots.txt reveals sensitive paths",
          url: `https://${domain}/robots.txt`,
          snippet: ep.snippet,
          source: "HTTP GET request",
          verifiedAt: now,
        }],
      });
    } else {
      findings.push({
        title: `Publicly Accessible ${ep.label} on ${domain}`,
        description: `${ep.label} (${ep.path}) is publicly accessible at ${domain}.`,
        severity: "low",
        category: "information_disclosure",
        affectedAsset: domain,
        cvssScore: "3.1",
        remediation: `Restrict access to ${ep.path} or ensure it does not expose sensitive information.`,
        evidence: [{
          type: "http_response",
          description: `${ep.label} publicly accessible`,
          url: `https://${domain}${ep.path}`,
          snippet: `HTTP Status: ${ep.status}\n\nPreview:\n${ep.snippet}`,
          source: "HTTP GET request",
          verifiedAt: now,
        }],
      });
    }
  }

  return findings;
}
