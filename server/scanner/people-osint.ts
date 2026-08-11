/**
 * Keyless people / employee-exposure OSINT — organizational, public-data only.
 *
 * Scope & ethics: this surfaces employees/emails ALREADY PUBLIC and TIED TO THE
 * TARGET DOMAIN (git commit metadata, Gravatar public profiles), so an authorized
 * assessment can show the org its own phishing/exposure surface. It deliberately
 * does NOT probe individuals' accounts across third-party sites (holehe/Sherlock),
 * scrape LinkedIn, or target anyone outside the target organization. Everything is
 * domain-scoped, rate-limited, and fail-soft.
 *
 * All sources are keyless; an optional GITHUB_TOKEN merely raises GitHub's rate
 * limit (60/hr unauth → 5000/hr) but is never required.
 */

import crypto from "crypto";
import { fetchJSON } from "./http.js";
import type { VerifiedFinding } from "./constants.js";
import { createLogger } from "../logger.js";

const log = createLogger("people-osint");

export interface Person {
  name?: string;
  email?: string;
  emailInferred?: boolean; // true when permuted from a name, not observed
  source: string; // github-commit | email-harvest | inferred | gravatar
  gravatar?: { displayName?: string; location?: string; accounts?: string[]; profileUrl?: string };
}

// ── Email-format inference & permutation (pure) ──

export type EmailFormat =
  | "first.last" | "firstlast" | "flast" | "f.last" | "first_last" | "first.l" | "first" | "last" | "lastfirst";

const FORMAT_BUILDERS: Record<EmailFormat, (f: string, l: string) => string | undefined> = {
  "first.last": (f, l) => (f && l ? `${f}.${l}` : undefined),
  "firstlast": (f, l) => (f && l ? `${f}${l}` : undefined),
  "flast": (f, l) => (f && l ? `${f[0]}${l}` : undefined),
  "f.last": (f, l) => (f && l ? `${f[0]}.${l}` : undefined),
  "first_last": (f, l) => (f && l ? `${f}_${l}` : undefined),
  "first.l": (f, l) => (f && l ? `${f}.${l[0]}` : undefined),
  "first": (f) => f || undefined,
  "last": (_f, l) => l || undefined,
  "lastfirst": (f, l) => (f && l ? `${l}${f}` : undefined),
};

/** Split a display name into normalized [first, last] ASCII tokens. */
export function splitName(name: string): { first: string; last: string } {
  const cleaned = name
    .normalize("NFKD").replace(/[̀-ͯ]/g, "") // strip combining diacritics
    .toLowerCase().replace(/[^a-z\s'-]/g, " ").replace(/\s+/g, " ").trim();
  const parts = cleaned.split(" ").filter(Boolean);
  if (parts.length === 0) return { first: "", last: "" };
  if (parts.length === 1) return { first: parts[0], last: "" };
  return { first: parts[0], last: parts[parts.length - 1] };
}

/**
 * Infer the org's dominant email local-part format from observed (name,email)
 * pairs whose email is @domain. Returns the most frequent matching format, or
 * undefined when there is no confident signal.
 */
export function inferEmailFormat(
  pairs: Array<{ name: string; email: string }>,
  domain: string,
): EmailFormat | undefined {
  const tally = new Map<EmailFormat, number>();
  for (const { name, email } of pairs) {
    const [local, host] = email.toLowerCase().split("@");
    if (!local || host !== domain.toLowerCase()) continue;
    const { first, last } = splitName(name);
    if (!first) continue;
    for (const fmt of Object.keys(FORMAT_BUILDERS) as EmailFormat[]) {
      if (FORMAT_BUILDERS[fmt](first, last) === local) tally.set(fmt, (tally.get(fmt) ?? 0) + 1);
    }
  }
  let best: EmailFormat | undefined;
  let bestN = 0;
  for (const [fmt, n] of Array.from(tally)) if (n > bestN) { best = fmt; bestN = n; }
  return best;
}

/** Build the most-likely email for a name under an inferred format. */
export function permuteEmail(name: string, format: EmailFormat, domain: string): string | undefined {
  const { first, last } = splitName(name);
  const local = FORMAT_BUILDERS[format](first, last);
  return local ? `${local}@${domain.toLowerCase()}` : undefined;
}

// ── GitHub commit harvesting (keyless) ──

/** Candidate GitHub org/user handles derived from a domain (heuristic). */
export function candidateGithubHandles(domain: string): string[] {
  const label = domain.split(".")[0].toLowerCase().replace(/[^a-z0-9-]/g, "");
  return Array.from(new Set([label, label.replace(/-/g, "")].filter((h) => h.length >= 2)));
}

async function ghApi<T>(path: string, token?: string): Promise<T | null> {
  const headers: Record<string, string> = { Accept: "application/vnd.github+json", "User-Agent": "cyshield-scanner", "X-GitHub-Api-Version": "2022-11-28" };
  if (token) headers.Authorization = `Bearer ${token}`;
  try {
    const { stealthFetch } = await import("./stealth.js");
    const res = await stealthFetch(`https://api.github.com${path}`, { headers }, 12000);
    if (!res.ok) return null; // 403 (rate limit) / 404 → fail-soft
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

interface GhRepo { name: string; full_name: string; fork: boolean; }
interface GhCommit { commit?: { author?: { name?: string; email?: string } }; }

/**
 * Harvest employee names+emails from an org/user's public commits. Only emails
 * ending in @domain are kept (a wrong org guess yields nothing — self-correcting).
 * Aggressively capped and fail-soft to respect the unauthenticated rate limit.
 */
export async function harvestGithubPeople(
  domain: string,
  opts: { token?: string; maxRepos?: number } = {},
): Promise<Person[]> {
  const token = opts.token ?? process.env.GITHUB_TOKEN;
  const maxRepos = opts.maxRepos ?? 5;
  const people = new Map<string, Person>(); // key: email
  const dl = domain.toLowerCase();

  for (const handle of candidateGithubHandles(domain)) {
    // Try org repos first, then user repos.
    let repos = await ghApi<GhRepo[]>(`/orgs/${handle}/repos?per_page=${maxRepos}&sort=pushed`, token);
    if (!repos) repos = await ghApi<GhRepo[]>(`/users/${handle}/repos?per_page=${maxRepos}&sort=pushed`, token);
    if (!repos || repos.length === 0) continue;

    for (const repo of repos.filter((r) => !r.fork).slice(0, maxRepos)) {
      const commits = await ghApi<GhCommit[]>(`/repos/${repo.full_name}/commits?per_page=100`, token);
      if (!commits) continue;
      for (const c of commits) {
        const email = c.commit?.author?.email?.toLowerCase();
        const name = c.commit?.author?.name;
        if (!email) continue;
        const host = email.split("@")[1];
        if (host !== dl) continue; // domain-scoped only
        if (!people.has(email)) people.set(email, { email, name: name || undefined, source: "github-commit" });
      }
    }
    if (people.size > 0) break; // found the org — stop guessing handles
  }
  return Array.from(people.values());
}

// ── Gravatar enrichment (keyless) ──

interface GravatarEntry { entry?: Array<{ displayName?: string; currentLocation?: string; profileUrl?: string; accounts?: Array<{ shortname?: string; url?: string }> }>; }

export function gravatarHash(email: string): string {
  return crypto.createHash("md5").update(email.trim().toLowerCase()).digest("hex");
}

export async function gravatarLookup(email: string): Promise<Person["gravatar"] | null> {
  const data = await fetchJSON(`https://gravatar.com/${gravatarHash(email)}.json`, 8000) as GravatarEntry | null;
  const e = data?.entry?.[0];
  if (!e) return null;
  return {
    displayName: e.displayName,
    location: e.currentLocation,
    profileUrl: e.profileUrl,
    accounts: (e.accounts ?? []).map((a) => a.url || a.shortname).filter((x): x is string => !!x),
  };
}

// ── Orchestrator ──

export interface PeopleOsintResult {
  findings: VerifiedFinding[];
  people: Person[];
  emailFormat?: EmailFormat;
}

/**
 * Full keyless people-OSINT pass. `seedEmails`/`seedNames` come from the scan's
 * existing email harvesting so inference/permutation use everything available.
 */
export async function runPeopleOsint(
  domain: string,
  seedEmails: string[],
  now: string,
  opts: { token?: string; gravatar?: boolean; maxRepos?: number } = {},
): Promise<PeopleOsintResult> {
  const dl = domain.toLowerCase();
  // 1. GitHub commit harvest (names + emails).
  let ghPeople: Person[] = [];
  try {
    ghPeople = await harvestGithubPeople(domain, opts);
  } catch (err) {
    log.warn({ err, domain }, "GitHub people harvest failed (non-fatal)");
  }

  // 2. Merge observed emails (seed + GitHub) into a people map.
  const byEmail = new Map<string, Person>();
  for (const email of seedEmails) {
    const e = email.toLowerCase();
    if (e.split("@")[1] === dl && !byEmail.has(e)) byEmail.set(e, { email: e, source: "email-harvest" });
  }
  for (const p of ghPeople) {
    if (!p.email) continue;
    const existing = byEmail.get(p.email);
    if (!existing) byEmail.set(p.email, p);
    else if (!existing.name && p.name) existing.name = p.name; // enrich harvested email with a name
  }

  // 3. Infer the org email format from (name,email) pairs.
  const pairs = Array.from(byEmail.values())
    .filter((p): p is Person & { name: string; email: string } => !!p.name && !!p.email)
    .map((p) => ({ name: p.name, email: p.email }));
  const emailFormat = inferEmailFormat(pairs, domain);

  // 4. Permute emails for harvested names that have no observed @domain address.
  if (emailFormat) {
    for (const p of ghPeople) {
      if (!p.name) continue;
      const guess = permuteEmail(p.name, emailFormat, domain);
      if (guess && !byEmail.has(guess)) byEmail.set(guess, { name: p.name, email: guess, emailInferred: true, source: "inferred" });
    }
  }

  // 5. Gravatar enrichment for OBSERVED emails only (never for inferred guesses).
  if (opts.gravatar !== false) {
    const observed = Array.from(byEmail.values()).filter((p) => p.email && !p.emailInferred).slice(0, 15);
    for (const p of observed) {
      try {
        const g = await gravatarLookup(p.email!);
        if (g) { p.gravatar = g; if (!p.name && g.displayName) p.name = g.displayName; }
      } catch { /* fail-soft */ }
    }
  }

  const people = Array.from(byEmail.values());
  const observedCount = people.filter((p) => !p.emailInferred).length;
  const findings: VerifiedFinding[] = [];
  if (observedCount > 0) {
    const withGravatar = people.filter((p) => p.gravatar).length;
    findings.push({
      title: `Employee / people exposure: ${observedCount} public identit${observedCount === 1 ? "y" : "ies"} for ${domain}`,
      description: `Public sources (git commit metadata, prior email harvesting${withGravatar ? ", Gravatar profiles" : ""}) expose ${observedCount} employee email address(es) tied to ${domain}${emailFormat ? `, revealing the organization's email format "${emailFormat}"` : ""}. This information aids targeted phishing and should inform user-awareness training. ${people.length - observedCount} additional likely-address(es) were inferred from the format for known names.`,
      severity: "low",
      category: "osint_exposure",
      affectedAsset: domain,
      cvssScore: "3.5",
      remediation: "Treat exposed staff addresses as phishing targets: enforce MFA, run phishing-awareness training, and consider using role-based aliases and commit-email privacy (GitHub noreply) for staff repositories.",
      evidence: people.slice(0, 40).map((p) => ({
        type: "people_osint",
        description: p.emailInferred ? "Inferred address (unverified)" : `Observed via ${p.source}`,
        snippet: [p.name, p.email, p.emailInferred ? "(inferred)" : undefined, p.gravatar?.profileUrl ? `gravatar:${p.gravatar.profileUrl}` : undefined, p.gravatar?.accounts?.length ? `accounts:${p.gravatar.accounts.join(",")}` : undefined].filter(Boolean).join(" · "),
        source: p.source,
        verifiedAt: now,
      })),
    });
  }
  return { findings, people, emailFormat };
}
