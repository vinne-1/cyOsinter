/**
 * GitHub code dorking — surfaces public source code that references the target
 * domain alongside secret-like tokens (leaked credentials, .env files, configs).
 *
 * GitHub's code-search API REQUIRES authentication, so this is an OPTIONAL,
 * key-gated capability (like the VirusTotal / AbuseIPDB integrations): it runs
 * only when GITHUB_TOKEN is set and otherwise no-ops. This mirrors the manual
 * GitHub-dork links other recon tools provide, but automated and de-duplicated.
 * Every hit is emitted as an `osint_exposure` finding (third-party corroboration,
 * not an active target defect — kept by the verification gate as unverifiable).
 */

import type { VerifiedFinding } from "./constants.js";
import { createLogger } from "../logger.js";

const log = createLogger("github-dork");

/** Search queries that pair the target domain with secret-like indicators. */
export function buildGithubDorks(domain: string): string[] {
  const d = `"${domain}"`;
  return [
    `${d} password`,
    `${d} api_key`,
    `${d} secret`,
    `${d} token`,
    `${d} filename:.env`,
    `${d} filename:config`,
  ];
}

export interface GithubDorkHit {
  query: string;
  repo: string;
  path: string;
  url: string;
}

interface GithubSearchResponse {
  items?: Array<{ repository?: { full_name?: string }; path?: string; html_url?: string }>;
}

/** Low-level: run a single code-search query. Exported for testing. */
export async function githubCodeSearch(
  query: string,
  token: string,
  fetchImpl: typeof fetch = fetch,
  signal?: AbortSignal,
): Promise<GithubDorkHit[]> {
  const res = await fetchImpl(`https://api.github.com/search/code?q=${encodeURIComponent(query)}&per_page=5`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "cyshield-scanner",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    signal,
  });
  if (!res.ok) return [];
  const json = (await res.json()) as GithubSearchResponse;
  return (json.items ?? []).map((it) => ({
    query,
    repo: it.repository?.full_name ?? "",
    path: it.path ?? "",
    url: it.html_url ?? "",
  }));
}

/**
 * Run the full dork set. No-op (returns []) without GITHUB_TOKEN. Best-effort and
 * fail-soft; paced to respect GitHub's authenticated code-search rate limit
 * (~10 req/min).
 */
export async function runGithubDorks(
  domain: string,
  now: string,
  opts: { token?: string; fetchImpl?: typeof fetch; signal?: AbortSignal; delayMs?: number } = {},
): Promise<VerifiedFinding[]> {
  const token = opts.token ?? process.env.GITHUB_TOKEN;
  if (!token) {
    log.info({ domain }, "GITHUB_TOKEN not set — skipping GitHub code dorking (requires auth)");
    return [];
  }
  const fetchImpl = opts.fetchImpl ?? fetch;
  const delayMs = opts.delayMs ?? 6500;
  const hits: GithubDorkHit[] = [];
  const seen = new Set<string>();
  const dorks = buildGithubDorks(domain);
  for (let i = 0; i < dorks.length; i++) {
    try {
      const found = await githubCodeSearch(dorks[i], token, fetchImpl, opts.signal);
      for (const h of found) {
        const key = `${h.repo}/${h.path}`;
        if (!seen.has(key)) { seen.add(key); hits.push(h); }
      }
    } catch (err) {
      log.warn({ err, query: dorks[i] }, "GitHub dork query failed (non-fatal)");
    }
    if (i < dorks.length - 1) await new Promise((r) => setTimeout(r, delayMs));
  }
  if (hits.length === 0) return [];

  return [{
    title: `Public GitHub code references ${domain} near secret-like tokens`,
    description: `GitHub code search returned ${hits.length} public source file(s) that mention ${domain} alongside secret indicators (password/api_key/secret/token/.env/config). These may expose credentials or internal configuration. Manual review is required to confirm whether any are live secrets.`,
    severity: "medium",
    category: "osint_exposure",
    affectedAsset: domain,
    cvssScore: "5.0",
    remediation: "Review each referenced repository/file. Rotate any exposed credentials, remove secrets from source history, and adopt secret-scanning + pre-commit hooks.",
    evidence: hits.slice(0, 20).map((h) => ({
      type: "github_dork",
      description: `Matched query: ${h.query}`,
      snippet: `${h.repo}/${h.path}`,
      url: h.url,
      source: "GitHub code search",
      verifiedAt: now,
    })),
  }];
}
