/**
 * Secret Exposure Scanner
 *
 * Detects exposed secrets and credentials by fetching known leak paths and
 * matching issuer-shaped key formats in the response.
 *
 * ## Precision rules this module is built around
 *
 * Three changes separate it from a naive regex sweep, each closing a
 * false-positive class that was producing confident, wrong, high-severity
 * findings:
 *
 * 1. **No shape-only patterns.** A UUID was listed as a "Heroku API key" at
 *    high severity. Every request id, trace id and asset hash on the web is a
 *    UUID and clears the old entropy floor, so any page with one produced
 *    "High-Severity Secrets Exposed". Patterns that describe a *shape* rather
 *    than an *issuer* now require a nearby keyword before they count.
 * 2. **The path must exist.** A 200 is not proof on a host with a catch-all
 *    route; every hit is checked against the host's own response to random
 *    non-existent paths (response-oracle.ts).
 * 3. **Presence is only a finding for files that are secrets by definition.**
 *    `/package.json` and `/requirements.txt` are meant to be readable on plenty
 *    of deployments; reporting them as "Sensitive Files Publicly Accessible"
 *    was noise. They are still SCANNED for secrets — they just do not become a
 *    finding merely by existing.
 */

import { createLogger } from "../logger.js";
import { httpGet } from "./http.js";
import { redactCredentialValues, maskValue, shannonEntropy } from "./credential-detection.js";
import { runWithConcurrency } from "./utils.js";
import { checkAborted } from "./constants.js";
import {
  parsePackageJson,
  parseRequirementsTxt,
  checkDependencyConfusion,
  buildConfusionFindings,
  type DependencyRef,
} from "./dependency-confusion.js";
import { calibrate, isSoftNotFound, type ResponseBaseline } from "./response-oracle.js";
import {
  looksLikeHtml,
  looksLikeEnvFile,
  looksLikeGitConfig,
  looksLikeGitHead,
  looksLikePhpInfo,
  looksLikeHtpasswd,
  looksLikeTerraformState,
  looksLikePrivateKey,
  parseJsonBody,
} from "./body-signatures.js";
import type { VerifiedFinding } from "./types.js";

const log = createLogger("scanner:secrets");

/**
 * Is a JWT-shaped string an actual JWT?
 *
 * `eyJ...` is just base64 for `{"`, so the three-segment shape matches plenty of
 * encoded JSON that is not a token. Decoding the header and requiring the
 * registered `alg` claim removes that class outright.
 */
function isRealJwt(value: string): boolean {
  const parts = value.split(".");
  if (parts.length !== 3) return false;
  try {
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")) as Record<string, unknown>;
    return typeof header.alg === "string" && header.alg.length > 0;
  } catch {
    return false;
  }
}

/**
 * Patterns that match known API key and token formats.
 *
 * Exported so the code-leak watch scans repository content with exactly the
 * same detector set as the web scanner — two drifting copies would mean a
 * secret caught on a website but missed in a repo.
 *
 * `requiresContext` marks a pattern whose shape is not distinctive on its own:
 * the match only counts when the surrounding text names the service. `validate`
 * carries a format-specific check where one exists.
 */
export const SECRET_PATTERNS: Array<{
  name: string;
  pattern: RegExp;
  severity: "critical" | "high" | "medium";
  description: string;
  requiresContext?: RegExp;
  validate?: (value: string) => boolean;
}> = [
  { name: "AWS Access Key", pattern: /AKIA[0-9A-Z]{16}/g, severity: "critical", description: "AWS IAM access key" },
  { name: "AWS Secret Key", pattern: /(?:aws_secret_access_key|secret_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi, severity: "critical", description: "AWS IAM secret access key" },
  { name: "GitHub Token", pattern: /gh[pousr]_[A-Za-z0-9_]{36,255}/g, severity: "critical", description: "GitHub personal access token" },
  { name: "GitLab Token", pattern: /glpat-[A-Za-z0-9\-_]{20,}/g, severity: "critical", description: "GitLab personal access token" },
  { name: "Slack Token", pattern: /xox[bpors]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g, severity: "high", description: "Slack API token" },
  { name: "Slack Webhook", pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/g, severity: "high", description: "Slack incoming webhook URL" },
  { name: "Google API Key", pattern: /AIza[0-9A-Za-z_-]{35}/g, severity: "high", description: "Google API key" },
  { name: "Stripe Secret Key", pattern: /sk_live_[0-9a-zA-Z]{24,}/g, severity: "critical", description: "Stripe live secret key" },
  {
    // A Heroku key is a UUID — a shape shared with every request id, trace id
    // and asset hash on the web. Only counts when "heroku" is nearby.
    name: "Heroku API Key",
    pattern: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g,
    severity: "high",
    description: "Heroku API key",
    requiresContext: /heroku/i,
  },
  { name: "SendGrid API Key", pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g, severity: "critical", description: "SendGrid API key" },
  { name: "Twilio API Key", pattern: /SK[0-9a-fA-F]{32}/g, severity: "high", description: "Twilio API key", requiresContext: /twilio|ACCOUNT_SID|AUTH_TOKEN/i },
  { name: "Mailgun API Key", pattern: /key-[0-9a-zA-Z]{32}/g, severity: "high", description: "Mailgun API key", requiresContext: /mailgun/i },
  { name: "Private Key", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, severity: "critical", description: "Private key material" },
  { name: "JSON Web Token", pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, severity: "high", description: "JSON Web Token (JWT)", validate: isRealJwt },
  { name: "Basic Auth Header", pattern: /[Aa]uthorization:\s*Basic\s+[A-Za-z0-9+/=]{10,}/g, severity: "high", description: "Basic authentication credentials" },
  { name: "Bearer Token", pattern: /[Aa]uthorization:\s*Bearer\s+[A-Za-z0-9._-]{20,}/g, severity: "high", description: "Bearer token in source" },
  {
    // Only a connection string carrying credentials is a leak; a bare
    // `postgres://host/db` in documentation is not.
    name: "Database URL",
    pattern: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s'"<>:/@]+:[^\s'"<>:/@]+@[^\s'"<>]+/gi,
    severity: "critical",
    description: "Database connection string with embedded credentials",
  },
  { name: "NPM Token", pattern: /npm_[A-Za-z0-9]{36}/g, severity: "high", description: "NPM access token" },
  { name: "Firebase Key", pattern: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/g, severity: "high", description: "Firebase Cloud Messaging key" },
];

/**
 * Files that are a finding by their mere presence — they exist only to hold
 * secrets or repository internals, so a public one is wrong regardless of what
 * the scan can read from it.
 */
const ALWAYS_SENSITIVE_PATHS = [
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
  "/.docker/config.json",
  "/.aws/credentials",
  "/.aws/config",
  "/wp-config.php",
  "/.htpasswd",
  "/.pgpass",
  "/.bash_history",
  "/.ssh/id_rsa",
  "/.netrc",
  "/.terraform/terraform.tfstate",
  "/terraform.tfstate",
];

/**
 * Files worth SCANNING for secrets, but not a finding merely by existing.
 *
 * A public `package.json` or `requirements.txt` is normal on a great many
 * deployments; reporting each as "Sensitive Files Publicly Accessible" buried
 * the real findings under medium-severity noise.
 */
const SCAN_ONLY_PATHS = [
  "/config.js",
  "/config.json",
  "/config.yml",
  "/config.yaml",
  "/settings.py",
  "/appsettings.json",
  "/appsettings.Development.json",
  "/web.config",
  "/phpinfo.php",
  "/debug.log",
  "/error.log",
  "/.ssh/id_rsa.pub",
  "/Dockerfile",
  "/docker-compose.yml",
  "/composer.json",
  "/package.json",
  "/Gemfile",
  "/requirements.txt",
];

/** Paths known to commonly leak secrets. */
const SECRET_LEAK_PATHS = [...ALWAYS_SENSITIVE_PATHS, ...SCAN_ONLY_PATHS];

/**
 * Manifests whose DEPENDENCY LIST is worth analysing, not just their secrets.
 *
 * These were already being fetched and scanned for credentials, and the
 * dependency list — the dependency-confusion signal — was discarded. The body
 * is carried back from the same request rather than fetched again.
 */
const DEPENDENCY_MANIFESTS = new Set(["/package.json", "/requirements.txt"]);

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
  /** 200 responses that were not reported, with the reason. */
  suppressed: Array<{ path: string; reason: string }>;
}

/**
 * Confirm that a path claimed to be sensitive really served that file.
 *
 * Returns null when the path has no distinctive format — the caller then falls
 * back to whether a secret was actually matched in the body.
 */
function confirmsSensitiveFile(path: string, body: string): boolean | null {
  if (/\.env(?:\.|$)/.test(path)) return looksLikeEnvFile(body);
  if (path === "/.git/config" || path === "/.gitconfig") return looksLikeGitConfig(body);
  // Uses the shared signature rather than an inline regex. The inline copy was
  // both a duplicate and weaker: it matched `ref: refs/` anywhere on any line,
  // so a large HTML page containing that text passed. The shared one requires
  // the full ref form AND a short body, which a real .git/HEAD always has.
  if (path === "/.git/HEAD") return looksLikeGitHead(body);
  if (path === "/.htpasswd") return looksLikeHtpasswd(body);
  if (path.endsWith("terraform.tfstate")) return looksLikeTerraformState(body);
  if (path === "/.ssh/id_rsa") return looksLikePrivateKey(body);
  if (path === "/.aws/credentials" || path === "/.aws/config") return /^\s*\[(?:default|profile\s)/m.test(body) && !looksLikeHtml(body);
  if (path === "/.npmrc") return /(?:registry|_auth|_authToken|always-auth)\s*=/.test(body) && !looksLikeHtml(body);
  if (path === "/.netrc") return /^\s*machine\s+\S+/m.test(body) && !looksLikeHtml(body);
  if (path === "/.pgpass") return /^[^:\n]+:[^:\n]+:[^:\n]+:[^:\n]+:/m.test(body) && !looksLikeHtml(body);
  if (path === "/.docker/config.json") {
    const j = parseJsonBody(body);
    return !!j && typeof j === "object" && "auths" in (j as Record<string, unknown>);
  }
  if (path === "/wp-config.php") {
    // PHP source is normally executed, so a readable wp-config means the
    // handler broke — the file's own defines are the proof.
    return /define\s*\(\s*['"](?:DB_NAME|DB_PASSWORD|AUTH_KEY)['"]/.test(body);
  }
  if (path === "/.bash_history") return !looksLikeHtml(body) && body.split(/\r?\n/).filter((l) => l.trim()).length >= 3;
  if (path === "/phpinfo.php") return looksLikePhpInfo(body);
  return null;
}

/**
 * Check a single path for secret leaks.
 */
async function checkPathForSecrets(
  baseUrl: string,
  path: string,
  baseline: ResponseBaseline | null,
): Promise<{ secrets: SecretMatch[]; isLeaky: boolean; rawSnippet: string; suppressedReason?: string; manifestBody?: string } | null> {
  const result = await httpGet(`${baseUrl}${path}`);
  if (!result || result.status !== 200) return null;

  const body = result.body;

  if (isSoftNotFound(baseline, path, result)) {
    return { secrets: [], isLeaky: false, rawSnippet: "", suppressedReason: "matches this host's response for a random non-existent path" };
  }

  // Markup is the server's page, not the file we asked for. phpinfo is the one
  // artefact that is legitimately HTML and legitimately leaks.
  if (looksLikeHtml(body) && !path.includes("phpinfo")) {
    return { secrets: [], isLeaky: false, rawSnippet: "", suppressedReason: "server returned a web page, not the requested file" };
  }

  const secrets: SecretMatch[] = [];

  for (const sp of SECRET_PATTERNS) {
    if (sp.requiresContext && !sp.requiresContext.test(body)) continue;
    const regex = new RegExp(sp.pattern.source, sp.pattern.flags);
    let match: RegExpExecArray | null = regex.exec(body);
    while (match) {
      const value = match[1] ?? match[0];
      const passesFormat = sp.validate ? sp.validate(value) : true;
      if (passesFormat && value.length >= 8 && shannonEntropy(value) >= 3.5) {
        secrets.push({ path, patternName: sp.name, matchedValue: maskValue(value), severity: sp.severity });
      }
      match = regex.exec(body);
    }
  }

  // A dotenv file's own assignments, when the key names say they hold secrets.
  if (/\.env(?:\.|$)/.test(path) && looksLikeEnvFile(body)) {
    const envLines = body.split("\n").filter((l) => /^[A-Z_]+=.+/.test(l.trim()));
    const sensitiveKeys = envLines.filter((l) =>
      /(?:KEY|SECRET|TOKEN|PASSWORD|PASS|AUTH|API_KEY|DATABASE|DB_|MONGO|REDIS|SMTP|MAIL|AWS|STRIPE|SENDGRID)/i.test(l),
    );
    for (const line of sensitiveKeys.slice(0, 5)) {
      const [keyName, ...rest] = line.split("=");
      const value = rest.join("=").trim();
      if (!value) continue; // `DB_PASSWORD=` with no value is a template, not a leak
      secrets.push({ path, patternName: "Environment Variable", matchedValue: `${keyName.trim()}=${maskValue(value)}`, severity: "critical" });
    }
  }

  if (path === "/.git/config" && looksLikeGitConfig(body)) {
    secrets.push({
      path,
      patternName: "Git Repository Config",
      matchedValue: "Git configuration exposed — repository may be cloneable",
      severity: "critical",
    });
  }

  // High-entropy values in a non-HTML config file, only on the right-hand side
  // of an assignment. Free-floating tokens are asset hashes far more often than
  // they are secrets.
  if (secrets.length === 0) {
    for (const line of body.split("\n").slice(0, 200)) {
      const trimmed = line.trim();
      if (trimmed.length < 20 || trimmed.length > 500) continue;
      const valMatch = trimmed.match(/[:=]\s*['"]?([A-Za-z0-9/+=_-]{24,})['"]?\s*[,;]?$/);
      if (!valMatch) continue;
      const val = valMatch[1];
      if (shannonEntropy(val) >= 4.5) {
        secrets.push({ path, patternName: "High-Entropy Secret", matchedValue: maskValue(val), severity: "high" });
      }
    }
  }

  // Presence alone is a finding only for files that exist to hold secrets, and
  // only when the body proves the real file was served.
  const shapeConfirmed = confirmsSensitiveFile(path, body);
  const isLeaky = ALWAYS_SENSITIVE_PATHS.includes(path)
    ? shapeConfirmed !== false
    : false;

  // A manifest carries its dependency list back even when it holds no secrets:
  // an exposed package.json with clean contents is still the map of internal
  // package names an attacker uses for dependency confusion.
  const manifestBody = DEPENDENCY_MANIFESTS.has(path) ? body : undefined;

  if (!isLeaky && secrets.length === 0) {
    return {
      secrets,
      isLeaky,
      rawSnippet: "",
      manifestBody,
      suppressedReason: shapeConfirmed === false
        ? "200 response does not match the format of this file"
        : "no secret material found in the response",
    };
  }

  return { secrets, isLeaky, rawSnippet: redactCredentialValues(body.slice(0, 500)), manifestBody };
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
  const suppressed: SecretScanResults["suppressed"] = [];
  const now = new Date().toISOString();
  const baseUrl = `https://${domain}`;

  const baseline = await calibrate(baseUrl);
  const paths = Array.from(new Set([...SECRET_LEAK_PATHS, ...additionalPaths]));

  const results = await runWithConcurrency(
    paths,
    8,
    (path) => checkPathForSecrets(baseUrl, path, baseline),
    signal,
  );

  const manifests: Array<{ path: string; body: string }> = [];
  for (let i = 0; i < results.length; i++) {
    const result = results[i];
    if (!result) continue;
    if (result.suppressedReason) suppressed.push({ path: paths[i], reason: result.suppressedReason });
    if (result.isLeaky) leakyPaths.push(paths[i]);
    allMatches.push(...result.secrets);
    if (result.manifestBody) manifests.push({ path: paths[i], body: result.manifestBody });
  }

  /*
   * Dependency confusion.
   *
   * An exposed manifest is normal on plenty of deployments and is deliberately
   * NOT a finding by itself — but the names inside it are. Any it references
   * that nobody owns on the public registry can be registered by an attacker,
   * whose install scripts then run inside a build that falls back to public.
   *
   * The manifest was already fetched for secret scanning; only the analysis is
   * new. See dependency-confusion.ts for why an unclaimed name is reported as
   * claimable rather than as a confirmed compromise path.
   */
  for (const manifest of manifests) {
    checkAborted(signal);
    const refs: DependencyRef[] = manifest.path.endsWith(".json")
      ? parsePackageJson(manifest.body)
      : parseRequirementsTxt(manifest.body);
    if (refs.length === 0) continue;

    const confusion = await checkDependencyConfusion(refs);
    for (const f of buildConfusionFindings(domain, manifest.path, confusion)) {
      findings.push({
        title: f.title,
        description: f.description,
        severity: f.severity,
        category: f.category,
        affectedAsset: f.affectedAsset,
        cvssScore: f.cvssScore,
        remediation: f.remediation,
        evidence: [{
          type: "dependency_manifest",
          description: `Dependencies declared in ${manifest.path}`,
          url: `${baseUrl}${manifest.path}`,
          snippet: JSON.stringify(f.evidence, null, 2).slice(0, 4000),
          source: "Public package registry lookup",
          verifiedAt: now,
        }],
      });
    }
  }

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

  // Files that are sensitive by definition and were served, but whose content
  // yielded no individual pattern match.
  const leakyOnly = leakyPaths.filter((p) => !allMatches.some((m) => m.path === p));
  if (leakyOnly.length > 0) {
    findings.push({
      title: `Sensitive Files Publicly Accessible on ${domain}`,
      description: `${leakyOnly.length} file(s) that exist to hold configuration or repository internals are readable without authentication: ${leakyOnly.join(", ")}.`,
      severity: "medium",
      category: "secret_exposure",
      affectedAsset: domain,
      cvssScore: "5.3",
      remediation: "Restrict access to configuration and environment files. Configure the web server to deny access to dotfiles and configuration files.",
      evidence: leakyOnly.map((p) => ({
        type: "http_response",
        description: `Sensitive file accessible at ${p}`,
        url: `${baseUrl}${p}`,
        source: "Secret Exposure Scanner",
        verifiedAt: now,
      })),
    });
  }

  log.info(
    { domain, paths: paths.length, matches: allMatches.length, leaky: leakyPaths.length, suppressed: suppressed.length },
    "Secret scan complete",
  );
  return { findings, matches: allMatches, leakyPaths, suppressed };
}
