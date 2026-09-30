/**
 * Source-code leak monitoring.
 *
 * Secrets escape through developer repositories far more often than through the
 * perimeter: a config committed "temporarily", a fork of an internal tool, a
 * personal account holding a work project. The existing secret scanner only
 * inspects pages it happened to fetch from the target, so none of that is
 * visible to it.
 *
 * This searches public code for the organisation's own identifiers — its
 * domains and internal hostnames — and runs the SAME detector set over the
 * results, so a pattern caught on a website is also caught in a repository.
 *
 * ── Credentials ─────────────────────────────────────────────────────────────
 * GitHub's code search API requires authentication; there is no unauthenticated
 * equivalent. A personal access token with NO scopes is enough for public code
 * and is free, so this is not a paid dependency — but it does need one piece of
 * setup, and without it the module reports "not configured" rather than
 * returning an empty result. Reporting "no leaks found" when nothing was
 * actually searched would be the dangerous failure here.
 */

import { createLogger } from "../logger.js";
import { SECRET_PATTERNS } from "./secret-scanner.js";


const log = createLogger("code-leak-watch");

const GITHUB_API = "https://api.github.com";
/** Code search is limited to 10 requests/minute even when authenticated. */
const SEARCH_DELAY_MS = 6500;
const REQUEST_TIMEOUT_MS = 20_000;
/** Cap on files fetched per sweep, so one run cannot exhaust the hour's budget. */
const MAX_FILES_INSPECTED = 30;

export interface CodeLeakHit {
  /** owner/repo */
  repository: string;
  path: string;
  htmlUrl: string;
  /** Which of the organisation's identifiers matched. */
  matchedTerm: string;
  /** Secret types found in the file, if any. */
  secrets: Array<{ name: string; severity: "critical" | "high" | "medium"; redacted: string }>;
  /** True when the file contains a recognised secret, not merely the domain. */
  hasSecret: boolean;
}

export interface CodeLeakResult {
  terms: string[];
  /** Files actually retrieved and pattern-scanned. */
  filesInspected: number;
  hits: CodeLeakHit[];
  counts: { withSecrets: number; mentionsOnly: number };
  scannedAt: string;
  /** Set when the sweep could not run; `hits` is then meaningless, not empty. */
  error?: string;
}

export interface CodeLeakOptions {
  /** Extra identifiers: internal hostnames, product code names. */
  aliases?: string[];
  token?: string;
  maxFiles?: number;
  /** Injected in tests. */
  fetchImpl?: typeof fetch;
}

function authHeaders(token: string): Record<string, string> {
  return {
    Accept: "application/vnd.github+json",
    Authorization: `Bearer ${token}`,
    "X-GitHub-Api-Version": "2022-11-28",
    // GitHub asks for an identifying User-Agent, and honouring that is the
    // difference between a well-behaved client and a rate-limited one.
    "User-Agent": "Cyshield-EASM/1.0 (code leak monitoring)",
  };
}

async function timedFetch(
  impl: typeof fetch,
  url: string,
  headers: Record<string, string>,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    return await impl(url, { headers, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Masks a matched secret so the finding can be stored and rendered safely.
 *
 * Keeps a short prefix, because the prefix is what identifies the key TYPE
 * (`AKIA`, `ghp_`, `sk_live_`) and is the useful part for triage, then masks the
 * rest and never reports the true length.
 *
 * Deliberately not `redactCredentialValues`: that helper only rewrites
 * `name=value` shapes, so a bare token like an AWS key passed through it
 * completely untouched — which is how a live credential would have ended up in
 * a stored finding and in exported reports.
 */
export function maskSecret(raw: string): string {
  const value = raw.trim();
  // Structured material has no useful prefix to preserve.
  if (value.startsWith("-----BEGIN")) return "-----BEGIN … PRIVATE KEY----- [REDACTED]";
  const prefix = value.slice(0, 4);
  return `${prefix}${"*".repeat(8)}[REDACTED]`;
}

/** Scans text with the shared detector set, redacting anything it matches. */
export function findSecretsInText(
  text: string,
): Array<{ name: string; severity: "critical" | "high" | "medium"; redacted: string }> {
  const found: Array<{ name: string; severity: "critical" | "high" | "medium"; redacted: string }> = [];
  const seen = new Set<string>();

  for (const p of SECRET_PATTERNS) {
    // A pattern whose shape is not distinctive on its own (a UUID, a bare hex
    // run) only counts when the surrounding text names the service. Skipping
    // this check here would mean a repository file with any UUID in it reported
    // as a leaked Heroku key — the detector set carries the guard, so every
    // consumer of it must honour the guard.
    if (p.requiresContext && !p.requiresContext.test(text)) continue;

    // Patterns are module-level and carry /g, so lastIndex must be reset or a
    // previous file's scan position leaks into this one.
    p.pattern.lastIndex = 0;
    let match = p.pattern.exec(text);
    while (match && p.validate && !p.validate(match[1] ?? match[0])) {
      match = p.pattern.exec(text);
    }
    if (match && !seen.has(p.name)) {
      seen.add(p.name);
      found.push({
        name: p.name,
        severity: p.severity,
        // The finding must never carry the live credential: this record is
        // stored, exported into reports and shown in a browser.
        redacted: maskSecret(match[0]),
      });
    }
    p.pattern.lastIndex = 0;
  }
  return found;
}

/**
 * Searches public code for the organisation's identifiers and inspects the
 * results for secrets.
 *
 * A hit that only mentions the domain is reported separately from one that
 * carries a credential — a domain appearing in an open-source project is
 * usually harmless, and mixing the two would bury the real leaks.
 */
export async function watchForCodeLeaks(
  domain: string,
  opts: CodeLeakOptions = {},
): Promise<CodeLeakResult> {
  const token = opts.token ?? process.env.GITHUB_TOKEN ?? process.env.GITHUB_PAT;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const maxFiles = opts.maxFiles ?? MAX_FILES_INSPECTED;

  const terms = Array.from(
    new Set([domain.trim().toLowerCase(), ...(opts.aliases ?? []).map((a) => a.trim().toLowerCase())]),
  ).filter(Boolean);

  const base: CodeLeakResult = {
    terms,
    filesInspected: 0,
    hits: [],
    counts: { withSecrets: 0, mentionsOnly: 0 },
    scannedAt: new Date().toISOString(),
  };

  if (!token) {
    // Explicit, not silent. "No leaks found" and "we never looked" must not
    // render identically.
    return {
      ...base,
      error:
        "GitHub code search requires a token. Set GITHUB_TOKEN to a personal access token " +
        "(no scopes needed for public code) to enable this check.",
    };
  }

  const hits: CodeLeakHit[] = [];
  let filesInspected = 0;

  try {
    for (const term of terms) {
      if (filesInspected >= maxFiles) break;

      // Quoted so the domain matches as a phrase rather than as separate tokens.
      const url = `${GITHUB_API}/search/code?q=${encodeURIComponent(`"${term}"`)}&per_page=20`;
      const res = await timedFetch(fetchImpl, url, authHeaders(token));

      if (res.status === 401 || res.status === 403) {
        const remaining = res.headers.get("x-ratelimit-remaining");
        return {
          ...base,
          hits,
          filesInspected,
          error:
            remaining === "0"
              ? "GitHub rate limit reached. Code search allows 10 requests per minute; try again shortly."
              : "GitHub rejected the token. Check that GITHUB_TOKEN is valid and not expired.",
        };
      }
      if (!res.ok) {
        log.warn({ term, status: res.status }, "Code search returned an error");
        continue;
      }

      const body = (await res.json()) as { items?: Array<{ repository?: { full_name?: string }; path?: string; html_url?: string; url?: string }> };

      for (const item of body.items ?? []) {
        if (filesInspected >= maxFiles) break;
        const repository = item.repository?.full_name ?? "unknown";
        const path = item.path ?? "";
        if (!item.url) continue;

        // The search result carries no content, so fetch the file to scan it.
        const fileRes = await timedFetch(fetchImpl, item.url, authHeaders(token)).catch(() => null);
        filesInspected++;
        if (!fileRes?.ok) continue;

        const file = (await fileRes.json().catch(() => null)) as { content?: string; encoding?: string } | null;
        let text = "";
        if (file?.content && file.encoding === "base64") {
          text = Buffer.from(file.content, "base64").toString("utf8");
        }

        const secrets = findSecretsInText(text);
        hits.push({
          repository,
          path,
          htmlUrl: item.html_url ?? "",
          matchedTerm: term,
          secrets,
          hasSecret: secrets.length > 0,
        });
      }

      // Stay inside the 10/min code-search budget.
      if (terms.indexOf(term) < terms.length - 1) {
        await new Promise((r) => setTimeout(r, SEARCH_DELAY_MS));
      }
    }
  } catch (err) {
    log.error({ err, domain }, "Code leak sweep failed");
    return {
      ...base,
      hits,
      filesInspected,
      error: "Code leak sweep failed before completing — results may be incomplete",
    };
  }

  // Files carrying a credential first; a bare domain mention is usually benign.
  hits.sort((a, b) => Number(b.hasSecret) - Number(a.hasSecret));

  const counts = {
    withSecrets: hits.filter((h) => h.hasSecret).length,
    mentionsOnly: hits.filter((h) => !h.hasSecret).length,
  };

  log.info({ domain, filesInspected, ...counts }, "Code leak sweep complete");
  return { ...base, hits, filesInspected, counts };
}

/** Whether the check can run at all, for the UI to explain itself. */
export function isCodeLeakConfigured(): boolean {
  return !!(process.env.GITHUB_TOKEN ?? process.env.GITHUB_PAT);
}

export interface CodeLeakFinding {
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  affectedAsset: string;
  cvssScore: string;
  remediation: string;
  evidence: Record<string, unknown>;
}

const BAND_SCORE: Record<CodeLeakFinding["severity"], string> = {
  critical: "9.1", high: "7.5", medium: "5.3", low: "3.1", info: "0.0",
};

/**
 * Renders a code-leak sweep as findings.
 *
 * One finding for files carrying a recognised secret, one for files that only
 * mention an identifier — the same "strongest evidence in its own row"
 * separation `breach-exposure.ts` and `ransomware-watch.ts` use, because a
 * bare domain mention in someone's fork is a very different fact from a
 * matched AWS key in a committed config.
 */
export function buildCodeLeakFindings(domain: string, result: CodeLeakResult): CodeLeakFinding[] {
  const findings: CodeLeakFinding[] = [];

  if (result.error) {
    findings.push({
      title: `Code leak sweep incomplete for ${domain}`,
      description: `${result.error}. This is not a clean result — it means the check did not fully run.`,
      severity: "info",
      category: "brand_threat",
      affectedAsset: domain,
      cvssScore: BAND_SCORE.info,
      remediation: "Re-run when GitHub's code search API is reachable.",
      evidence: { terms: result.terms, filesInspected: result.filesInspected, error: result.error },
    });
    return findings;
  }

  const withSecrets = result.hits.filter((h) => h.hasSecret);
  const mentionsOnly = result.hits.filter((h) => !h.hasSecret);

  if (withSecrets.length > 0) {
    const hasCritical = withSecrets.some((h) => h.secrets.some((s) => s.severity === "critical"));
    const severity: CodeLeakFinding["severity"] = hasCritical ? "critical" : "high";
    const repos = withSecrets.map((h) => `${h.repository}/${h.path}`);
    findings.push({
      title: `${withSecrets.length} public repository file${withSecrets.length === 1 ? "" : "s"} contain${withSecrets.length === 1 ? "s" : ""} a credential matching ${domain}`,
      description:
        `${withSecrets.length} file${withSecrets.length === 1 ? "" : "s"} in public GitHub repositories mention ${domain} (or a related identifier) AND contain a recognised ` +
        `secret pattern: ${repos.slice(0, 6).join(", ")}${repos.length > 6 ? `, and ${repos.length - 6} more` : ""}. This is a live credential exposed in developer-facing ` +
        `code, which is typically reachable long before it is noticed on the production perimeter.`,
      severity,
      category: "brand_threat",
      affectedAsset: domain,
      cvssScore: BAND_SCORE[severity],
      remediation: "Rotate every matched credential immediately, then request removal or history rewrite from the repository owner. Treat as already compromised.",
      evidence: { terms: result.terms, filesInspected: result.filesInspected, hits: withSecrets },
    });
  }

  if (mentionsOnly.length > 0) {
    findings.push({
      title: `${mentionsOnly.length} public repository file${mentionsOnly.length === 1 ? "" : "s"} mention ${domain} with no secret detected`,
      description:
        `${mentionsOnly.length} file${mentionsOnly.length === 1 ? "" : "s"} in public repositories reference ${domain} or a related identifier, but no recognised secret ` +
        `pattern was found in them. This is commonly a legitimate integration, documentation, or a former employee's personal project — worth a quick look, not an incident.`,
      severity: "low",
      category: "brand_threat",
      affectedAsset: domain,
      cvssScore: BAND_SCORE.low,
      remediation: "Spot-check a few for anything unexpected (internal hostnames, architecture detail). No action needed if they are benign integrations.",
      evidence: { terms: result.terms, filesInspected: result.filesInspected, hits: mentionsOnly },
    });
  }

  if (result.hits.length === 0) {
    findings.push({
      title: `No public code leaks found mentioning ${domain}`,
      description: `Searched public GitHub code for ${result.terms.join(", ")} across ${result.filesInspected} file(s) — no matches.`,
      severity: "info",
      category: "brand_threat",
      affectedAsset: domain,
      cvssScore: BAND_SCORE.info,
      remediation: "No action needed now. Re-run periodically — new commits happen constantly.",
      evidence: { terms: result.terms, filesInspected: result.filesInspected },
    });
  }

  return findings;
}
