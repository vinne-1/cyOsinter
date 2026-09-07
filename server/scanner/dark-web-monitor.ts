/**
 * Dark web monitoring — monitors dark web for mentions of the target.
 *
 * The dark web hosts marketplaces, forums, paste sites and leak databases
 * where compromised data is traded. An organisation that appears there is
 * already compromised or being targeted, and the signal often arrives before
 * any internal detection.
 *
 * This module leverages Tor (via tor-fetch.ts) and clearnet aggregators to
 * check multiple dark web sources:
 *
 *   1. Ahmia.fi — public search engine for .onion content (clearnet API)
 *   2. Onion.live — directory of live .onion services with breach data
 *   3. Dark paste sites — .onion paste services checked via Tor
 *   4. Dark web credential dumps — known dump aggregators
 *
 * ── Matching tiers ─────────────────────────────────────────────────────────────
 *   confirmed   the target's exact domain appears in a listing, or a credential
 *               set includes an email at the target's domain
 *   possible    the organisation's name appears in context (brand mention,
 *               employee name match) — lower confidence, always marked as
 *               requiring verification
 *
 * ── Error handling ─────────────────────────────────────────────────────────────
 * A source that cannot be reached returns an `error` rather than an empty
 * result set. "We could not check" and "nothing was found" must never render
 * identically — the same rule that governs ransomware-watch and code-leak-watch.
 */

import { createLogger } from "../logger.js";
import { torFetchJson, torFetchText, isTorAvailable, TOR_PROXY_URL } from "./tor-fetch.js";
import { checkRansomwareExposure } from "./ransomware-watch.js";

const log = createLogger("dark-web-monitor");

/** Ahmia.fi public search API — no key required. */
const AHMIA_API = "https://ahmia.fi/api/v1";

/** Onion.live public API — directory of live .onion services. */
const ONION_LIVE_API = "https://onion.live/api";

/** Cache TTL: the dark web changes slowly; refetching per request is wasteful. */
const CACHE_TTL_MS = 6 * 60 * 60 * 1000;

const FETCH_TIMEOUT_MS = 45_000;

// ── Types ──────────────────────────────────────────────────────────────────────

export interface DarkWebMention {
  /** Source where the mention was found. */
  source: string;
  /** Title or heading of the listing. */
  title: string;
  /** URL of the listing (may be .onion). */
  url: string | null;
  /** Snippet of the matching content. */
  snippet: string | null;
  /** When the listing was published or indexed, if known. */
  publishedAt: string | null;
  /** Domain or email that matched the target. */
  matchedTerm: string;
  /** Confirmed (exact domain match) or possible (name/context match). */
  confidence: "confirmed" | "possible";
  /** Why this matched. */
  reason: string;
}

export interface DarkWebLeakDump {
  /** Source of the dump listing. */
  source: string;
  /** Number of records in the dump, if known. */
  recordCount: number | null;
  /** Types of data leaked (emails, passwords, hashes, etc.). */
  dataTypes: string[];
  /** When the dump was published, if known. */
  publishedAt: string | null;
  /** URL of the listing. */
  url: string | null;
  /** Whether the target's domain was explicitly named. */
  confirmed: boolean;
  /** The matching term (domain or email pattern). */
  matchedTerm: string;
  reason: string;
}

export interface DarkWebForumMention {
  source: string;
  /** Forum name. */
  forum: string;
  /** Thread or post title. */
  title: string;
  /** URL of the post. */
  url: string | null;
  /** When the post was made. */
  postedAt: string | null;
  /** Snippet of the relevant content. */
  snippet: string | null;
  /** The term that matched. */
  matchedTerm: string;
  confidence: "confirmed" | "possible";
  reason: string;
}

export interface DarkWebMonitorResult {
  target: string;
  mentions: DarkWebMention[];
  leakDumps: DarkWebLeakDump[];
  forumMentions: DarkWebForumMention[];
  counts: {
    confirmedMentions: number;
    possibleMentions: number;
    leakDumps: number;
    forumMentions: number;
  };
  sourcesChecked: string[];
  /** Sources that failed to respond. */
  sourcesFailed: string[];
  torAvailable: boolean;
  scannedAt: string;
  /** Set when the check could not run; results are meaningless. */
  error?: string;
}

interface CachedResult {
  result: DarkWebMonitorResult;
  fetchedAt: number;
}

let cache: CachedResult | null = null;
let inFlight: Promise<DarkWebMonitorResult> | null = null;

// ── Helpers ────────────────────────────────────────────────────────────────────

function normaliseDomain(input: string): string {
  return input
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .replace(/[/:?#].*$/, "")
    .replace(/\.$/, "");
}

function normaliseForSearch(input: string): string {
  return input
    .toLowerCase()
    .replace(/[^a-z0-9\s.-]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/** Generate email domain patterns to search for (e.g. "@example.com"). */
function emailPatterns(domain: string): string[] {
  const d = normaliseDomain(domain);
  return [`@${d}`, `"${d}"`, d.replace(/\./g, " ")];
}

/** Extract domain from an email address. */
function domainFromEmail(email: string): string | null {
  const match = email.match(/@([a-z0-9.-]+\.[a-z]{2,})/i);
  return match ? match[1].toLowerCase() : null;
}

/**
 * Whether `text` genuinely mentions `domain`, rather than merely containing it
 * as a substring.
 *
 * Plain `includes()` is wrong here and wrong in the most damaging direction:
 * this module's whole purpose is to avoid telling a team they are on the dark
 * web when they are not. `"leaked data from notexample.com".includes("example.com")`
 * is `true`, and so is `"dump for example.com.evil.net"` — a listing about
 * somebody else's domain entirely.
 *
 * The boundaries encode what a domain mention actually looks like:
 *  - **before:** anything except a letter, digit or hyphen, so `www.example.com`
 *    and `@example.com` match while `notexample.com` does not;
 *  - **after:** not a letter/digit/hyphen, so `example.commerce` does not match;
 *    and not `.` followed by a letter, so `example.com.evil.net` does not either.
 *
 * Same attribution discipline as `inScopeSans` and the crawler's `isInScope`.
 */
export function textMentionsDomain(text: string, domain: string): boolean {
  const d = domain.trim().toLowerCase();
  if (!d) return false;
  const escaped = d.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(?<![a-z0-9-])${escaped}(?![a-z0-9-])(?!\\.[a-z0-9])`, "i").test(text);
}

// ── Removed sources: Ahmia.fi and Onion.live ──────────────────────────────────
//
// Both were deleted rather than left failing. They could not work:
//
//   - `https://ahmia.fi/api/v1` answers 404 — that API does not exist. Ahmia's
//     own `/search/?q=` answers 302 to its homepage for any non-interactive
//     client, and does the same over its .onion service, so routing through Tor
//     does not help either. Verified against both in November 2026.
//   - `https://onion.live/api` answers 404 likewise.
//
// Left in place they reported two permanent failures on every run, which is
// worse than having fewer sources: `sourcesFailed` is the field that says
// whether "nothing found" can be trusted, and a reader who sees it always
// non-empty stops reading it. A source that cannot succeed is not a degraded
// source, it is a missing one, and the panel should say so by not listing it.

// ── Dark paste sites (via Tor) ─────────────────────────────────────────────────

/**
 * Well-known .onion paste sites. These are checked via the Tor SOCKS5
 * proxy. Each site has a search or recent-pastes endpoint.
 *
 * The list is deliberately short: we check a few reliable sources rather
 * than probing dozens of unreliable ones. A paste site that is down is
 * logged in `sourcesFailed`, never treated as "nothing found".
 */
/**
 * .onion paste sources.
 *
 * EMPTY, and deliberately so. The one address this shipped with
 * (`paste2vlj…onion`) no longer publishes a hidden-service descriptor: Tor
 * resolves it in 8ms with a failure, which is a dead service rather than a slow
 * one. Verified through a working local Tor circuit in November 2026.
 *
 * It is not replaced with a guess. Onion paste sites churn constantly, and
 * shipping an address that has not been verified reachable recreates exactly
 * the problem this module has just been dug out of: a source that fails on
 * every run, which trains a reader to ignore `sourcesFailed`.
 *
 * The Tor transport itself works and is exercised by `isTorAvailable()`, so
 * adding a verified address here is a one-line change when one is available.
 */
const DARK_PASTE_SOURCES: Array<{
  name: string;
  searchUrl: (q: string) => string;
  type: "api";
}> = [];

interface PasteResult {
  title?: string;
  url?: string;
  content?: string;
  date?: string;
}

async function searchDarkPasteSites(
  domain: string,
  organisationName: string | null,
): Promise<{ mentions: DarkWebMention[]; failed: boolean }> {
  const mentions: DarkWebMention[] = [];
  const searchTerms = emailPatterns(domain);
  if (organisationName && organisationName.length >= 5) {
    searchTerms.push(organisationName);
  }

  // Reachability is TRACKED, not assumed. This function used to
  // `return { failed: false }` unconditionally, so a run where every paste site
  // was unreachable reported itself as a completed check that found nothing —
  // the exact failure this module's own documentation forbids, and it made the
  // panel's "all sources answered" green state partly untrue.
  let attempted = 0;
  let answered = 0;

  for (const source of DARK_PASTE_SOURCES) {
    for (const term of searchTerms.slice(0, 3)) {
      const query = normaliseForSearch(term);
      if (!query) continue;

      attempted++;
      const results = await torFetchJson<PasteResult[] | { pastes?: PasteResult[] }>(
        source.searchUrl(query),
        { timeoutMs: FETCH_TIMEOUT_MS },
      );

      if (results === null) {
        // Could not reach this source — log it but continue checking others.
        log.info({ source: source.name }, "Dark paste site unreachable");
        continue;
      }
      answered++;

      const items = Array.isArray(results) ? results : (results as { pastes?: PasteResult[] }).pastes ?? [];

      for (const item of items) {
        const content = (item.content ?? "").toLowerCase();
        const title = (item.title ?? "").toLowerCase();
        const combined = `${title} ${content}`;

        let confidence: DarkWebMention["confidence"] | null = null;
        let reason = "";

        // Boundary-aware, NOT `includes`: "leaked data from notexample.com"
        // contains "example.com" as a substring, and telling a team they are on
        // the dark web when they are not is the failure this module most has to
        // avoid. `textMentionsDomain` was written for exactly this and — found
        // during an audit — had been wired into nothing, so the bug it fixes
        // was still live in both matchers while its own tests passed.
        if (textMentionsDomain(combined, domain)) {
          confidence = "confirmed";
          reason = `Domain or email at "${domain}" found in paste`;
        } else if (organisationName && organisationName.length >= 5) {
          const nameLower = normaliseForSearch(organisationName);
          if (combined.includes(nameLower)) {
            confidence = "possible";
            reason = `Organisation name mentioned in paste — verify before acting`;
          }
        }

        if (!confidence) continue;

        mentions.push({
          source: source.name,
          title: item.title ?? "(untitled paste)",
          url: item.url ?? null,
          snippet: item.content ? item.content.slice(0, 500) : null,
          publishedAt: item.date ?? null,
          matchedTerm: term,
          confidence,
          reason,
        });
      }
    }
  }

  // Nothing answered means the check did not run, however many sources existed.
  return { mentions, failed: attempted > 0 && answered === 0 };
}

// ── Credential dump aggregators (via Tor) ──────────────────────────────────────

/**
 * Known dark web dump aggregators. These are .onion services that index
 * credential dumps and data breaches. Checked via Tor SOCKS5 proxy.
 */
/**
 * .onion credential-dump aggregators.
 *
 * EMPTY. The address this shipped with, `2l3uq6jnojweppqy.onion`, is a **v2**
 * onion — sixteen characters. Tor removed v2 onion support entirely in October
 * 2021, so that address has not been resolvable by any current Tor client for
 * over five years; it could never have returned anything. It was not a stale
 * service, it was an impossible one.
 *
 * Per-account credential exposure is also the capability that is deliberately
 * gated elsewhere in this product (see `breach-exposure.ts`): it enumerates
 * individuals, and the paid HIBP domain search requires proof of domain
 * ownership for that reason. An unvetted .onion aggregator is not the way
 * around that.
 */
const DUMP_SOURCES: Array<{
  name: string;
  searchUrl: (q: string) => string;
  type: "intelx";
}> = [];

interface IntelXResult {
  records?: Array<{ name?: string; url?: string; domain?: string; date?: string }>;
}

async function searchCredentialDumps(
  domain: string,
  _organisationName: string | null,
): Promise<{ dumps: DarkWebLeakDump[]; failed: boolean }> {
  const dumps: DarkWebLeakDump[] = [];
  const searchTerms = emailPatterns(domain);
  // Reachability tracked, not assumed — see searchDarkPasteSites.
  let attemptedDumps = 0;
  let answeredDumps = 0;

  for (const source of DUMP_SOURCES) {
    for (const term of searchTerms.slice(0, 2)) {
      const query = normaliseForSearch(term);
      if (!query) continue;

      attemptedDumps++;
      const results = await torFetchJson<IntelXResult>(
        source.searchUrl(query),
        { timeoutMs: FETCH_TIMEOUT_MS },
      );

      if (results === null) {
        log.info({ source: source.name }, "Dump aggregator unreachable");
        continue;
      }
      answeredDumps++;

      for (const record of results.records ?? []) {
        const recordDomain = record.domain?.toLowerCase() ?? "";
        const recordName = (record.name ?? "").toLowerCase();

        // Boundary-aware for the same reason as the paste matcher above.
        const confirmed =
          textMentionsDomain(recordDomain, domain) || textMentionsDomain(recordName, domain);

        dumps.push({
          source: source.name,
          recordCount: null,
          dataTypes: ["credentials"],
          publishedAt: record.date ?? null,
          url: record.url ?? null,
          confirmed,
          matchedTerm: term,
          reason: confirmed
            ? `Credential dump contains data for "${domain}"`
            : `Possible match in dump — verify before acting`,
        });
      }
    }
  }

  return { dumps, failed: attemptedDumps > 0 && answeredDumps === 0 };
}

// ── Main entry point ───────────────────────────────────────────────────────────

export interface DarkWebMonitorOptions {
  /** Extra domains belonging to the organisation. */
  aliases?: string[];
  /** Organisation name for the lower-confidence name tier. */
  organisationName?: string;
  /** Skip cache and force a fresh scan. */
  force?: boolean;
}

/**
 * Monitors the dark web for mentions of the target domain, leaked credentials,
 * and forum discussions.
 *
 * Returns a result with `error` set (not thrown) when the check could not run,
 * following the established pattern of ransomware-watch and code-leak-watch.
 */
export async function monitorDarkWeb(
  target: string,
  opts: DarkWebMonitorOptions = {},
): Promise<DarkWebMonitorResult> {
  const primary = normaliseDomain(target);
  const aliases = (opts.aliases ?? [])
    .map(normaliseDomain)
    .filter((d) => d.includes("."));

  const allDomains = [primary, ...aliases];
  const orgName = opts.organisationName ?? null;

  // Check cached result unless forced — return immediately without any
  // network calls (including the isTorAvailable probe).
  if (!opts.force && cache && Date.now() - cache.fetchedAt < CACHE_TTL_MS) {
    return cache.result;
  }

  // De-duplicate concurrent calls.
  if (inFlight) return inFlight;

  const base: DarkWebMonitorResult = {
    target: primary,
    mentions: [],
    leakDumps: [],
    forumMentions: [],
    counts: { confirmedMentions: 0, possibleMentions: 0, leakDumps: 0, forumMentions: 0 },
    sourcesChecked: [],
    sourcesFailed: [],
    torAvailable: false,
    scannedAt: new Date().toISOString(),
  };

  // Check if Tor is available — report it, but do not block clearnet sources.
  const torAvailable = await isTorAvailable();
  base.torAvailable = torAvailable;

  if (!torAvailable) {
    log.warn(
      { proxy: TOR_PROXY_URL },
      "Tor SOCKS5 proxy unreachable — .onion sources will be skipped",
    );
  }

  inFlight = runChecks(allDomains, orgName, base, torAvailable)
    .then((result) => {
      cache = { result, fetchedAt: Date.now() };
      return result;
    })
    .finally(() => {
      inFlight = null;
    });

  try {
    return await inFlight;
  } catch (err) {
    // Serve stale cache on failure — old data is more useful than none.
    if (cache) {
      log.warn({ err }, "Dark web check failed; serving cached data");
      return cache.result;
    }
    throw err;
  }
}

async function runChecks(
  domains: string[],
  orgName: string | null,
  base: DarkWebMonitorResult,
  torAvailable: boolean,
): Promise<DarkWebMonitorResult> {
  const primary = domains[0];
  if (!primary) return base;

  const allMentions: DarkWebMention[] = [];
  let sourcesFailed = 0;

  /*
   * 1. Ransomware leak sites (clearnet mirror of .onion victim postings).
   *
   * This replaced Ahmia and Onion.live, both of which were REMOVED because they
   * cannot work, not because they were flaky:
   *
   *   - `ahmia.fi/api/v1` returns 404 — that API does not exist. Ahmia's own
   *     `/search/` endpoint answers 302 to its homepage for a non-interactive
   *     client, and does so over its .onion service too, so Tor does not help.
   *     Verified against both in November 2026.
   *   - `onion.live/api` returns 404 likewise.
   *
   * Every run therefore reported two permanent failures, which is worse than
   * having fewer sources: it trained a reader to ignore `sourcesFailed`, the
   * one field that says whether the answer can be trusted.
   *
   * The leak-site corpus is the substitute because it is the part of "dark web
   * monitoring" that is genuinely reachable without credentials or vetted
   * forum access: ransomware groups publish victims on .onion sites, and
   * ransomware.live aggregates those postings. A hit here is the single
   * highest-severity dark-web signal there is — it means the organisation is
   * already being extorted.
   */
  try {
    const leaks = await checkRansomwareExposure(primary, { organisationName: orgName ?? undefined });
    base.sourcesChecked.push("ransomware_leak_sites");
    if (leaks.error) {
      base.sourcesFailed.push("ransomware_leak_sites");
      sourcesFailed++;
    } else {
      for (const m of leaks.matches) {
        allMentions.push({
          source: "ransomware_leak_sites",
          title: `${m.group} leak-site posting: ${m.victim}`,
          url: m.postUrl,
          snippet: [m.sector, m.country].filter(Boolean).join(" · ") || null,
          publishedAt: m.publishedAt ?? m.discoveredAt,
          matchedTerm: m.website ?? m.victim,
          // The corpus already grades its own matches the same way this module
          // does — exact domain confirmed, organisation name a lead — so the
          // value is carried across rather than re-derived.
          confidence: m.confidence,
          reason: m.reason,
        });
      }
    }
  } catch (err) {
    log.warn({ err }, "Ransomware leak-site check failed");
    base.sourcesFailed.push("ransomware_leak_sites");
    sourcesFailed++;
  }

  // 3. Dark paste sites (Tor only)
  // A source set with no verified addresses is neither checked nor failed — it
  // is absent, and listing it either way would misdescribe the run.
  if (torAvailable && DARK_PASTE_SOURCES.length > 0) {
    try {
      const pastes = await searchDarkPasteSites(primary, orgName);
      allMentions.push(...pastes.mentions);
      base.sourcesChecked.push("dark_paste_sites");
      // The `failed` flag was computed and then DISCARDED here, so a source
      // that reached nothing still counted as checked. Both halves had to be
      // wrong for the bug to show, and both were.
      if (pastes.failed) {
        base.sourcesFailed.push("dark_paste_sites");
        sourcesFailed++;
      }
    } catch (err) {
      log.warn({ err }, "Dark paste site search failed");
      base.sourcesFailed.push("dark_paste_sites");
      sourcesFailed++;
    }
  } else if (DARK_PASTE_SOURCES.length > 0) {
    base.sourcesFailed.push("dark_paste_sites");
  }

  // 4. Credential dump aggregators (Tor only)
  if (torAvailable && DUMP_SOURCES.length > 0) {
    try {
      const dumps = await searchCredentialDumps(primary, orgName);
      base.leakDumps.push(...dumps.dumps);
      base.sourcesChecked.push("credential_dumps");
      if (dumps.failed) {
        base.sourcesFailed.push("credential_dumps");
        sourcesFailed++;
      }
    } catch (err) {
      log.warn({ err }, "Credential dump search failed");
      base.sourcesFailed.push("credential_dumps");
      sourcesFailed++;
    }
  } else if (DUMP_SOURCES.length > 0) {
    base.sourcesFailed.push("credential_dumps");
  }

  // De-duplicate mentions across sources.
  const seen = new Set<string>();
  for (const mention of allMentions) {
    const key = `${mention.source}|${mention.title}|${mention.matchedTerm}`;
    if (seen.has(key)) continue;
    seen.add(key);
    base.mentions.push(mention);
  }

  // Sort: confirmed first, then by source reliability.
  const sourceRank: Record<string, number> = {
    ransomware_leak_sites: 0,
    credential_dumps: 0,
    dark_paste_sites: 1,
  };
  const confRank = { confirmed: 0, possible: 1 } as const;
  base.mentions.sort(
    (a, b) =>
      confRank[a.confidence] - confRank[b.confidence] ||
      (sourceRank[a.source] ?? 99) - (sourceRank[b.source] ?? 99),
  );

  base.counts.confirmedMentions = base.mentions.filter(
    (m) => m.confidence === "confirmed",
  ).length;
  base.counts.possibleMentions = base.mentions.filter(
    (m) => m.confidence === "possible",
  ).length;
  base.counts.leakDumps = base.leakDumps.length;
  base.counts.forumMentions = base.forumMentions.length;

  log.info(
    {
      target: primary,
      sourcesChecked: base.sourcesChecked.length,
      sourcesFailed: sourcesFailed,
      ...base.counts,
    },
    "Dark web monitoring complete",
  );

  return base;
}

/** Clears the result cache. Exposed for tests. */
export function __resetDarkWebCache(): void {
  cache = null;
  inFlight = null;
}
