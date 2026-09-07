/**
 * Directory bruteforce path classification for OSINT scans.
 *
 * ## Every finding here needs positive content proof
 *
 * A 200 means "the server answered", not "the file exists". Two separate
 * failures produced confident nonsense before:
 *
 * - The soft-404 guard compared `` `${len}:${first100chars}` `` with `===`.
 *   Any error page carrying a request id, CSRF token, or the echoed path
 *   defeats exact equality, so on most real sites the guard never fired and
 *   every path in the wordlist looked like a hit.
 * - `/.env` needed only `status === 200 && body`. A single-page app serving
 *   `index.html` for unknown paths was reported as an
 *   "Exposed Environment File" at high — or, once its markup tripped the
 *   credential heuristic, at **critical**.
 *
 * Both gates now apply to every finding: the response must differ from this
 * host's answer for a random non-existent path (response-oracle.ts), AND the
 * body must positively be the artefact named (body-signatures.ts). Paths that
 * cannot be proven are recorded in {@link ClassifyResult.suppressed} rather
 * than reported, so "we looked and could not confirm" stays distinguishable
 * from "we never looked".
 */

import { validatePathResponse } from "./detection.js";
import { OSINT_CREDENTIAL_PATHS, OSINT_DOCUMENT_PATHS, type VerifiedFinding } from "./constants.js";
import { hasCredentialPattern, redactCredentialValues } from "./osint-helpers.js";
import { calibrate, isSoftNotFound, type ResponseBaseline } from "./response-oracle.js";
import {
  looksLikeEnvFile,
  looksLikeGitConfig,
  looksLikeDirectoryListing,
  looksLikePhpInfo,
  looksLikeApacheServerStatus,
  looksLikeSpringActuator,
  looksLikeOpenApiSpec,
  looksLikeHtml,
  looksLikeSqlDump,
  looksLikeLogFile,
  looksLikePrivateKey,
  looksLikeHtpasswd,
  looksLikeDotNetConfig,
  looksLikeTerraformState,
  looksLikeComposeManifest,
  isDocumentResponse,
} from "./body-signatures.js";

type PathCheckResult = {
  path: string;
  label: string;
  result: { status: number; headers: Record<string, string>; body: string; finalUrl: string } | null;
};

export type ExposedPath = { path: string; label: string; status: number; snippet: string };

/**
 * Establish how the host answers paths that do not exist.
 *
 * Replaces the old single-sample `establishSoft404Fingerprint`; see
 * response-oracle.ts for why exact-match fingerprinting could not work.
 */
export async function establishResponseBaseline(domain: string): Promise<ResponseBaseline> {
  return calibrate(`https://${domain}`);
}

export interface ClassifyResult {
  findings: VerifiedFinding[];
  exposedPaths: ExposedPath[];
  /** 200 responses that were NOT reported, with the reason. */
  suppressed: Array<{ path: string; reason: string }>;
}

/**
 * Does a credential-shaped file at this path carry real credential material?
 *
 * Several of the credential paths have a format of their own, and matching that
 * format is far stronger evidence than a keyword sweep. Falls back to the
 * generic pattern check for paths without a distinct shape.
 */
function confirmsCredentialFile(path: string, body: string): boolean {
  if (looksLikeHtml(body)) return false;
  if (/\.htpasswd$/.test(path)) return looksLikeHtpasswd(body);
  if (/web\.config$/i.test(path)) return looksLikeDotNetConfig(body) && hasCredentialPattern(body);
  if (/terraform\.tfstate$/.test(path)) return looksLikeTerraformState(body);
  if (/(?:id_rsa|\.ssh\/)/.test(path)) return looksLikePrivateKey(body);
  if (/docker-compose\.ya?ml$/.test(path)) return looksLikeComposeManifest(body) && hasCredentialPattern(body);
  if (/\.env/.test(path)) return looksLikeEnvFile(body) && hasCredentialPattern(body);
  return hasCredentialPattern(body);
}

/**
 * Classify each path check result into security findings.
 *
 * `baseline` may be null when calibration failed; the content gates below still
 * apply, so a missing baseline degrades precision rather than removing it.
 */
export function classifyPathResults(
  domain: string,
  pathCheckResults: PathCheckResult[],
  baseline: ResponseBaseline | null,
  now: string,
): ClassifyResult {
  const findings: VerifiedFinding[] = [];
  const exposedPaths: ExposedPath[] = [];
  const suppressed: ClassifyResult["suppressed"] = [];

  for (const r of pathCheckResults) {
    if (!r.result) continue;
    const { path: rPath, label, result } = r;
    const pathValidation = validatePathResponse(result.status, result.body, result.finalUrl, rPath);
    if (result.status !== 200) continue;

    const soft = isSoftNotFound(baseline, rPath, result);
    if (soft) {
      suppressed.push({ path: rPath, reason: "matches this host's response for a random non-existent path" });
      continue;
    }

    const withheld = (reason: string) => { suppressed.push({ path: rPath, reason }); };

    if (rPath === "/.env" && result.body) {
      if (!looksLikeEnvFile(result.body)) {
        withheld("200 response is not a dotenv file (no KEY=VALUE lines, or the server returned a web page)");
        continue;
      }
      const hasSecrets = hasCredentialPattern(result.body);
      const redacted = redactCredentialValues(result.body.substring(0, 500));
      findings.push({
        title: `Exposed Environment File (.env) on ${domain}`,
        description: hasSecrets
          ? `The .env file at ${domain}/.env is publicly accessible and contains sensitive configuration values (passwords, API keys, tokens).`
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
          snippet: `HTTP Status: 200 OK\nBody confirmed to be dotenv format (KEY=VALUE lines, not markup)\nSensitive patterns detected: ${hasSecrets ? "Yes" : "No"}\n\nRedacted content preview:\n${redacted}`,
          source: "HTTP GET request",
          verifiedAt: now,
          validated: pathValidation.validated,
          confidence: "high",
        }],
      });
      continue;
    }

    if (rPath === "/.git/config") {
      if (!looksLikeGitConfig(result.body)) {
        withheld("200 response is not a git config file");
        continue;
      }
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
          confidence: "high",
        }],
      });
      continue;
    }

    if (OSINT_CREDENTIAL_PATHS.includes(rPath) && result.body) {
      if (!confirmsCredentialFile(rPath, result.body)) {
        withheld("200 response does not match the format of this credential file, or contains no credential material");
        continue;
      }
      const redacted = redactCredentialValues(result.body.substring(0, 500));
      findings.push({
        title: `Exposed Credential File (${rPath}) on ${domain}`,
        description: `The file ${rPath} at ${domain} is publicly accessible and its content matches the expected format of a credential or configuration file containing secrets.`,
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
          confidence: "high",
        }],
      });
      continue;
    }

    if (rPath === "/server-status") {
      if (!looksLikeApacheServerStatus(result.body)) {
        withheld("200 response is not an Apache mod_status page");
        continue;
      }
      findings.push({
        title: `Apache Server Status Page Exposed on ${domain}`,
        description: `The Apache server-status page is publicly accessible at ${domain}/server-status, exposing request URLs, client IPs, and worker state.`,
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
          confidence: "high",
        }],
      });
      continue;
    }

    if (rPath === "/actuator" || rPath === "/actuator/health") {
      if (!looksLikeSpringActuator(result.body)) {
        withheld("200 response is not a Spring Boot Actuator document");
        continue;
      }
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
          confidence: "high",
        }],
      });
      continue;
    }

    if (rPath === "/phpinfo.php" || rPath === "/info.php") {
      if (!looksLikePhpInfo(result.body)) {
        withheld("200 response is not a phpinfo() page");
        continue;
      }
      findings.push({
        title: `PHP Info Page Exposed on ${domain}`,
        description: `The phpinfo page at ${domain}${rPath} is publicly accessible, disclosing PHP version, loaded modules, paths, and environment variables.`,
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
          confidence: "high",
        }],
      });
      continue;
    }

    if (looksLikeDirectoryListing(result.body)) {
      findings.push({
        title: `Directory Listing Exposed on ${domain}${rPath}`,
        description: `Directory listing is enabled at ${domain}${rPath}. This exposes the file structure and any files the directory holds.`,
        severity: "medium",
        category: "data_leak",
        affectedAsset: domain,
        cvssScore: "5.3",
        remediation: "Disable directory listing in web server configuration (Apache: `Options -Indexes`; nginx: `autoindex off`).",
        evidence: [{
          type: "http_response",
          description: "Directory listing detected",
          url: `https://${domain}${rPath}`,
          snippet: `HTTP Status: 200 OK\n\nPreview:\n${result.body.substring(0, 400)}`,
          source: "HTTP GET request",
          verifiedAt: now,
          validated: pathValidation.validated,
          confidence: "high",
        }],
      });
      continue;
    }

    if (OSINT_DOCUMENT_PATHS.includes(rPath)) {
      // `/docs`, `/media`, `/data`, `/reports`, `/private` and friends are
      // ordinary application routes on countless sites. A 200 alone said
      // nothing; only a served document, a browsable index, a dump, or a log
      // makes this an exposure rather than a page.
      const isDump = looksLikeSqlDump(result.body);
      const isLog = looksLikeLogFile(result.body);
      const isDoc = isDocumentResponse(result.headers, result.body);
      if (!isDump && !isLog && !isDoc) {
        withheld("200 response is an ordinary page, not a browsable index, served document, database dump, or log file");
        continue;
      }
      const what = isDump ? "a database dump" : isLog ? "an application log" : "a downloadable document";
      findings.push({
        title: `Exposed ${isDump ? "Database Dump" : isLog ? "Log File" : "Document"} (${rPath}) on ${domain}`,
        description: `The path ${rPath} at ${domain} is publicly accessible and serves ${what}.`,
        severity: isDump ? "high" : "medium",
        category: "data_leak",
        affectedAsset: domain,
        cvssScore: isDump ? "7.5" : "5.3",
        remediation: "Restrict access to this path. Move backups, dumps, and logs outside the web root.",
        evidence: [{
          type: "http_response",
          description: `Path serves ${what}`,
          url: `https://${domain}${rPath}`,
          snippet: `HTTP Status: 200 OK\nContent-Type: ${result.headers["content-type"] ?? "unknown"}\n\nPreview:\n${result.body.substring(0, 400)}`,
          source: "HTTP GET request",
          verifiedAt: now,
          validated: pathValidation.validated,
          confidence: "high",
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

    if (rPath === "/swagger.json" || rPath === "/api/docs" || rPath === "/openapi.json") {
      if (!looksLikeOpenApiSpec(result.body)) {
        withheld("200 response is not an OpenAPI/Swagger specification");
        continue;
      }
      findings.push({
        title: `Exposed API Documentation (Swagger/OpenAPI) on ${domain}`,
        description: `${rPath} at ${domain} serves a machine-readable API specification. This exposes the full API surface, including endpoints and schemas that are not linked from the site.`,
        severity: "low",
        category: "infrastructure_disclosure",
        affectedAsset: domain,
        cvssScore: "3.1",
        remediation: `Restrict access to ${rPath} or ensure it does not expose internal or undocumented API details.`,
        evidence: [{
          type: "http_response",
          description: "Swagger/OpenAPI documentation publicly accessible",
          url: `https://${domain}${rPath}`,
          snippet: `HTTP Status: 200 OK\n\nPreview:\n${result.body.substring(0, 400)}`,
          source: "HTTP GET request",
          verifiedAt: now,
          validated: pathValidation.validated,
          confidence: "high",
        }],
      });
      continue;
    }
  }

  return { findings, exposedPaths, suppressed };
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
