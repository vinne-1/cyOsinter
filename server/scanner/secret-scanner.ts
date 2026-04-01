/**
 * Secret Exposure Scanner Module
 *
 * Detects exposed secrets and credentials by:
 * 1. Pattern matching for API keys, tokens, and passwords in HTTP responses
 * 2. Checking common secret leak paths (.env, .git/config, etc.)
 * 3. Entropy-based detection for high-randomness strings
 * 4. GitHub/GitLab dork-style pattern matching in page content
 */

import { createLogger } from "../logger.js";
import { httpGet } from "./http.js";
import { shannonEntropy, redactCredentialValues } from "./osint-helpers.js";
import { runWithConcurrency } from "./utils.js";
import type { VerifiedFinding, EvidenceItem } from "./types.js";

const log = createLogger("scanner:secrets");

/** Patterns that match known API key and token formats */
const SECRET_PATTERNS: Array<{
  name: string;
  pattern: RegExp;
  severity: "critical" | "high" | "medium";
  description: string;
}> = [
  { name: "AWS Access Key", pattern: /AKIA[0-9A-Z]{16}/g, severity: "critical", description: "AWS IAM access key" },
  { name: "AWS Secret Key", pattern: /(?:aws_secret_access_key|secret_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi, severity: "critical", description: "AWS IAM secret access key" },
  { name: "GitHub Token", pattern: /gh[pousr]_[A-Za-z0-9_]{36,255}/g, severity: "critical", description: "GitHub personal access token" },
  { name: "GitLab Token", pattern: /glpat-[A-Za-z0-9\-_]{20,}/g, severity: "critical", description: "GitLab personal access token" },
  { name: "Slack Token", pattern: /xox[bpors]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g, severity: "high", description: "Slack API token" },
  { name: "Slack Webhook", pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/g, severity: "high", description: "Slack incoming webhook URL" },
  { name: "Google API Key", pattern: /AIza[0-9A-Za-z_-]{35}/g, severity: "high", description: "Google API key" },
  { name: "Stripe Secret Key", pattern: /sk_live_[0-9a-zA-Z]{24,}/g, severity: "critical", description: "Stripe live secret key" },
  { name: "Stripe Publishable Key", pattern: /pk_live_[0-9a-zA-Z]{24,}/g, severity: "medium", description: "Stripe live publishable key" },
  { name: "Heroku API Key", pattern: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g, severity: "high", description: "Potential Heroku API key (UUID)" },
  { name: "SendGrid API Key", pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g, severity: "critical", description: "SendGrid API key" },
  { name: "Twilio API Key", pattern: /SK[0-9a-fA-F]{32}/g, severity: "high", description: "Twilio API key" },
  { name: "Mailgun API Key", pattern: /key-[0-9a-zA-Z]{32}/g, severity: "high", description: "Mailgun API key" },
  { name: "Private Key", pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g, severity: "critical", description: "Private key material" },
  { name: "JSON Web Token", pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, severity: "high", description: "JSON Web Token (JWT)" },
  { name: "Basic Auth Header", pattern: /[Aa]uthorization:\s*Basic\s+[A-Za-z0-9+/=]{10,}/g, severity: "high", description: "Basic authentication credentials" },
  { name: "Bearer Token", pattern: /[Aa]uthorization:\s*Bearer\s+[A-Za-z0-9._-]{20,}/g, severity: "high", description: "Bearer token in source" },
  { name: "Database URL", pattern: /(?:postgres|mysql|mongodb|redis):\/\/[^\s'"<>]{10,}/gi, severity: "critical", description: "Database connection string" },
  { name: "NPM Token", pattern: /npm_[A-Za-z0-9]{36}/g, severity: "high", description: "NPM access token" },
  { name: "Firebase Key", pattern: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/g, severity: "high", description: "Firebase Cloud Messaging key" },
];

/** Paths known to commonly leak secrets */
const SECRET_LEAK_PATHS = [
  "/.env",
  "/.env.local",
  "/.env.production",
  "/.env.development",
  "/.env.backup",
  "/.env.bak",
  "/.env.old",
  "/.git/config",
  "/.git/HEAD",
  "/.gitconfig",
  "/.npmrc",
  "/.dockerenv",
  "/.docker/config.json",
  "/config.js",
  "/config.json",
  "/config.yml",
  "/config.yaml",
  "/.aws/credentials",
  "/.aws/config",
  "/wp-config.php",
  "/settings.py",
  "/appsettings.json",
  "/appsettings.Development.json",
  "/web.config",
  "/phpinfo.php",
  "/.htpasswd",
  "/.pgpass",
  "/debug.log",
  "/error.log",
  "/.bash_history",
  "/.ssh/id_rsa",
  "/.ssh/id_rsa.pub",
  "/.netrc",
  "/Dockerfile",
  "/docker-compose.yml",
  "/.terraform/terraform.tfstate",
  "/terraform.tfstate",
  "/composer.json",
  "/package.json",
  "/Gemfile",
  "/requirements.txt",
];

export interface SecretMatch {
  path: string;
  patternName: string;
  matchedValue: string; // redacted
  severity: "critical" | "high" | "medium";
}

export interface SecretScanResults {
  findings: VerifiedFinding[];
  matches: SecretMatch[];
  leakyPaths: string[];
}

/**
 * Check a single path for secret leaks.
 */
async function checkPathForSecrets(
  baseUrl: string,
  path: string,
): Promise<{ secrets: SecretMatch[]; isLeaky: boolean; rawSnippet: string } | null> {
  try {
    const result = await httpGet(`${baseUrl}${path}`);
    if (!result || result.status !== 200) return null;

    const body = result.body;

    // Skip HTML error pages
    if (body.trim().startsWith("<!DOCTYPE") || body.trim().startsWith("<html")) {
      // Exception: phpinfo pages are HTML but leak secrets
      if (!path.includes("phpinfo")) return null;
    }

    const secrets: SecretMatch[] = [];

    // Pattern matching
    for (const sp of SECRET_PATTERNS) {
      const regex = new RegExp(sp.pattern.source, sp.pattern.flags);
      let match: RegExpExecArray | null = regex.exec(body);
      while (match) {
        const value = match[1] ?? match[0];
        // Filter false positives: skip short matches and low entropy
        if (value.length >= 8 && shannonEntropy(value) >= 3.5) {
          secrets.push({
            path,
            patternName: sp.name,
            matchedValue: redactCredentialValues(value),
            severity: sp.severity,
          });
        }
        match = regex.exec(body);
      }
    }

    // Check for .env file format (KEY=VALUE lines)
    if (path.includes(".env") && !body.includes("<html")) {
      const envLines = body.split("\n").filter((l) => /^[A-Z_]+=.+/.test(l.trim()));
      if (envLines.length >= 2) {
        const sensitiveKeys = envLines.filter((l) =>
          /(?:KEY|SECRET|TOKEN|PASSWORD|PASS|AUTH|API_KEY|DATABASE|DB_|MONGO|REDIS|SMTP|MAIL|AWS|STRIPE|SENDGRID)/i.test(l),
        );
        if (sensitiveKeys.length > 0) {
          for (const line of sensitiveKeys.slice(0, 5)) {
            const keyName = line.split("=")[0].trim();
            secrets.push({
              path,
              patternName: "Environment Variable",
              matchedValue: `${keyName}=****REDACTED****`,
              severity: "critical",
            });
          }
        }
      }
    }

    // Check for Git config leak
    if (path === "/.git/config" && body.includes("[core]")) {
      secrets.push({
        path,
        patternName: "Git Repository Config",
        matchedValue: "Git configuration exposed — repository may be cloneable",
        severity: "critical",
      });
    }

    // High-entropy string detection in non-HTML responses
    if (!body.includes("<html") && secrets.length === 0) {
      const lines = body.split("\n").slice(0, 100);
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.length < 20 || trimmed.length > 500) continue;
        const valMatch = trimmed.match(/[:=]\s*['"]?([A-Za-z0-9/+=_-]{20,})['"]?\s*$/);
        if (valMatch) {
          const val = valMatch[1];
          if (shannonEntropy(val) >= 4.5 && val.length >= 20) {
            secrets.push({
              path,
              patternName: "High-Entropy Secret",
              matchedValue: redactCredentialValues(val),
              severity: "high",
            });
          }
        }
      }
    }

    const isLeaky = secrets.length > 0 || (path.includes(".env") && body.split("\n").filter((l) => l.includes("=")).length >= 2);
    const rawSnippet = redactCredentialValues(body.slice(0, 500));

    return { secrets, isLeaky, rawSnippet };
  } catch {
    return null;
  }
}

/**
 * Scan a domain for exposed secrets and credentials.
 */
export async function scanSecrets(
  domain: string,
  signal?: AbortSignal,
  additionalPaths: string[] = [],
): Promise<SecretScanResults> {
  const findings: VerifiedFinding[] = [];
  const allMatches: SecretMatch[] = [];
  const leakyPaths: string[] = [];
  const now = new Date().toISOString();
  const baseUrl = `https://${domain}`;

  const paths = Array.from(new Set([...SECRET_LEAK_PATHS, ...additionalPaths]));

  const results = await runWithConcurrency(
    paths,
    8,
    (path) => checkPathForSecrets(baseUrl, path),
    signal,
  );

  for (let i = 0; i < results.length; i++) {
    const result = results[i];
    if (!result) continue;

    if (result.isLeaky) leakyPaths.push(paths[i]);
    allMatches.push(...result.secrets);
  }

  // Group findings by severity for consolidated reporting
  const criticalSecrets = allMatches.filter((m) => m.severity === "critical");
  const highSecrets = allMatches.filter((m) => m.severity === "high");
  const mediumSecrets = allMatches.filter((m) => m.severity === "medium");

  if (criticalSecrets.length > 0) {
    const uniquePaths = Array.from(new Set(criticalSecrets.map((s) => s.path)));
    const uniqueTypes = Array.from(new Set(criticalSecrets.map((s) => s.patternName)));

    findings.push({
      title: `Critical Secrets Exposed on ${domain}`,
      description: `${criticalSecrets.length} critical secret(s) found across ${uniquePaths.length} path(s): ${uniqueTypes.join(", ")}. These could allow full account takeover, data exfiltration, or infrastructure compromise.`,
      severity: "critical",
      category: "secret_exposure",
      affectedAsset: domain,
      cvssScore: "9.8",
      remediation: "Immediately rotate all exposed credentials. Remove or restrict access to the files containing secrets. Implement .htaccess rules or server configuration to block access to sensitive files.",
      evidence: criticalSecrets.slice(0, 10).map((s) => ({
        type: "credential_leak",
        description: `${s.patternName} found at ${s.path}`,
        snippet: s.matchedValue,
        url: `${baseUrl}${s.path}`,
        source: "Secret Exposure Scanner",
        verifiedAt: now,
      })),
    });
  }

  if (highSecrets.length > 0) {
    const uniquePaths = Array.from(new Set(highSecrets.map((s) => s.path)));
    findings.push({
      title: `High-Severity Secrets Exposed on ${domain}`,
      description: `${highSecrets.length} high-severity secret(s) found across ${uniquePaths.length} path(s): ${Array.from(new Set(highSecrets.map((s) => s.patternName))).join(", ")}.`,
      severity: "high",
      category: "secret_exposure",
      affectedAsset: domain,
      cvssScore: "8.1",
      remediation: "Rotate exposed tokens and API keys. Review file permissions and server configuration to prevent future exposure.",
      evidence: highSecrets.slice(0, 10).map((s) => ({
        type: "credential_leak",
        description: `${s.patternName} found at ${s.path}`,
        snippet: s.matchedValue,
        url: `${baseUrl}${s.path}`,
        source: "Secret Exposure Scanner",
        verifiedAt: now,
      })),
    });
  }

  if (mediumSecrets.length > 0) {
    findings.push({
      title: `Potential Secrets Exposed on ${domain}`,
      description: `${mediumSecrets.length} potential secret(s) found that may be lower risk (e.g., publishable keys). Review to confirm exposure.`,
      severity: "medium",
      category: "secret_exposure",
      affectedAsset: domain,
      cvssScore: "5.3",
      remediation: "Review exposed values and determine if they grant access to sensitive resources. Even publishable keys should be scoped appropriately.",
      evidence: mediumSecrets.slice(0, 5).map((s) => ({
        type: "credential_leak",
        description: `${s.patternName} found at ${s.path}`,
        snippet: s.matchedValue,
        url: `${baseUrl}${s.path}`,
        source: "Secret Exposure Scanner",
        verifiedAt: now,
      })),
    });
  }

  // Finding for leaky paths without specific pattern matches (like exposed .env structure)
  const leakyOnly = leakyPaths.filter((p) => !allMatches.some((m) => m.path === p));
  if (leakyOnly.length > 0) {
    findings.push({
      title: `Sensitive Files Publicly Accessible on ${domain}`,
      description: `${leakyOnly.length} sensitive file(s) accessible without authentication: ${leakyOnly.join(", ")}. These files may contain configuration data or internal information.`,
      severity: "medium",
      category: "secret_exposure",
      affectedAsset: domain,
      cvssScore: "5.3",
      remediation: "Restrict access to configuration and environment files. Configure web server to deny access to dotfiles and configuration files.",
      evidence: leakyOnly.map((p) => ({
        type: "http_response",
        description: `Sensitive file accessible at ${p}`,
        url: `${baseUrl}${p}`,
        source: "Secret Exposure Scanner",
        verifiedAt: now,
      })),
    });
  }

  log.info({ domain, paths: paths.length, matches: allMatches.length, leaky: leakyPaths.length }, "Secret scan complete");
  return { findings, matches: allMatches, leakyPaths };
}
