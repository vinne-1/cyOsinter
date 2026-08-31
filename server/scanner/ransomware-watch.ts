/**
 * Ransomware leak-site exposure.
 *
 * Ransomware crews publish their victims on Tor leak sites before, or instead
 * of, the victim disclosing a breach. Appearing there is the single loudest
 * signal a security team can receive about itself, and it routinely arrives
 * before any internal detection does.
 *
 * The corpus comes from ransomware.live's public dataset — an aggregation of
 * those leak sites maintained by Julien Mousqueton. It needs no API key, which
 * is why this is the entry point into deep/dark-web monitoring rather than a
 * paid threat-intel feed.
 *
 * ── Matching ────────────────────────────────────────────────────────────────
 * Two tiers, kept apart on purpose:
 *
 *   confirmed  the victim's published website resolves to the same registrable
 *              domain as the workspace target. This is an identity match.
 *   possible   the victim's *name* resembles the organisation's name. Company
 *              names are not unique ("Delta", "Apex", "Orion"), so these are
 *              reported separately and never counted as confirmed.
 *
 * Conflating the two would be worse than not shipping the feature: telling a
 * team they have been ransomed when they have not destroys trust in every other
 * finding the platform produces.
 */

import { createLogger } from "../logger.js";
import { splitDomain } from "./typosquat.js";

const log = createLogger("ransomware-watch");

/** Public, keyless dataset of leak-site posts. */
const FEED_URL = process.env.RANSOMWARE_FEED_URL ?? "https://data.ransomware.live/posts.json";

/** The corpus changes slowly; refetching per request would be abusive and slow. */
const CACHE_TTL_MS = Number(process.env.RANSOMWARE_FEED_TTL_MS ?? 6 * 60 * 60 * 1000);
const FETCH_TIMEOUT_MS = 60_000;

/** One post on a leak site, as published in the feed. */
export interface LeakPost {
  post_title?: string;
  group_name?: string;
  discovered?: string;
  published?: string;
  website?: string;
  country?: string;
  activity?: string;
  description?: string;
  post_url?: string;
}

export interface RansomwareMatch {
  /** Victim name as the crew published it. */
  victim: string;
  group: string;
  /** Domain the crew listed for the victim, when they listed one. */
  website: string | null;
  country: string | null;
  sector: string | null;
  publishedAt: string | null;
  discoveredAt: string | null;
  /** Leak-site URL, usually a .onion address. Never fetched by this scanner. */
  postUrl: string | null;
  confidence: "confirmed" | "possible";
  /** Why this matched, so an analyst can dismiss a false positive quickly. */
  reason: string;
}

export interface RansomwareWatchResult {
  target: string;
  /** Records compared. Reported so an empty result is distinguishable from a failed fetch. */
  recordsChecked: number;
  matches: RansomwareMatch[];
  counts: { confirmed: number; possible: number };
  feedFetchedAt: string;
  /** Set when the feed could not be reached; matches will be empty. */
  error?: string;
}

interface CachedFeed {
  posts: LeakPost[];
  fetchedAt: number;
}

let cache: CachedFeed | null = null;
/** De-duplicates concurrent fetches so ten workspaces do not pull 30MB ten times. */
let inFlight: Promise<CachedFeed> | null = null;

/** Registrable domain (`shop.example.co.uk` → `example.co.uk`), lowercased. */
export function registrableDomain(input: string): string {
  const cleaned = input
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .replace(/[/:?#].*$/, "")
    .replace(/\.$/, "");
  if (!cleaned || !cleaned.includes(".")) return cleaned;
  const { name, tld } = splitDomain(cleaned);
  return tld ? `${name}.${tld}` : name;
}

/**
 * Normalises an organisation name for comparison: lowercase, strip punctuation
 * and the usual corporate suffixes, collapse whitespace.
 */
export function normaliseOrgName(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .replace(
      /\b(inc|llc|ltd|limited|corp|corporation|company|co|gmbh|srl|sa|nv|bv|plc|pvt|private|group|holdings|international|technologies|technology|solutions|services|systems)\b/g,
      " ",
    )
    .replace(/\s+/g, " ")
    .trim();
}

async function fetchFeed(): Promise<CachedFeed> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(FEED_URL, {
      signal: controller.signal,
      headers: {
        // Identify the client honestly: this is a public dataset offered for
        // exactly this use, and spoofing a browser to fetch it would be rude.
        "User-Agent": "Cyshield-EASM/1.0 (ransomware exposure check)",
        accept: "application/json",
      },
    });
    if (!res.ok) throw new Error(`Feed returned HTTP ${res.status}`);

    const parsed = (await res.json()) as unknown;
    if (!Array.isArray(parsed)) throw new Error("Feed did not return an array");

    log.info({ records: parsed.length }, "Ransomware leak feed fetched");
    return { posts: parsed as LeakPost[], fetchedAt: Date.now() };
  } finally {
    clearTimeout(timer);
  }
}

/** Returns the cached feed, refetching when stale. */
export async function getFeed(opts: { force?: boolean } = {}): Promise<CachedFeed> {
  if (!opts.force && cache && Date.now() - cache.fetchedAt < CACHE_TTL_MS) return cache;
  if (inFlight) return inFlight;

  inFlight = fetchFeed()
    .then((feed) => {
      cache = feed;
      return feed;
    })
    .finally(() => {
      inFlight = null;
    });

  try {
    return await inFlight;
  } catch (err) {
    // Serve a stale cache rather than failing the check outright — old data is
    // far more useful here than no data.
    if (cache) {
      log.warn({ err }, "Feed refresh failed; serving cached data");
      return cache;
    }
    throw err;
  }
}

/** Clears the cache. Exposed for tests. */
export function __resetFeedCache(): void {
  cache = null;
  inFlight = null;
}

export interface CheckOptions {
  /** Extra names/domains belonging to the same organisation. */
  aliases?: string[];
  /** Organisation name, enabling the lower-confidence name tier. */
  organisationName?: string;
  posts?: LeakPost[];
}

/**
 * Checks a target against the leak-site corpus.
 *
 * A fetch failure returns a result carrying `error` rather than throwing, so a
 * transient outage shows as "could not check" instead of "you are clean" — the
 * latter would be a dangerous thing to report incorrectly.
 */
export async function checkRansomwareExposure(
  target: string,
  opts: CheckOptions = {},
): Promise<RansomwareWatchResult> {
  const primary = registrableDomain(target);
  const domains = new Set<string>([primary]);
  for (const alias of opts.aliases ?? []) {
    const d = registrableDomain(alias);
    if (d.includes(".")) domains.add(d);
  }

  const orgName = opts.organisationName ? normaliseOrgName(opts.organisationName) : "";
  // Very short names ("MEQ", "ABC") match far too much to be useful.
  const nameMatchable = orgName.length >= 5;

  let posts: LeakPost[];
  let fetchedAt = Date.now();
  if (opts.posts) {
    posts = opts.posts;
  } else {
    try {
      const feed = await getFeed();
      posts = feed.posts;
      fetchedAt = feed.fetchedAt;
    } catch (err) {
      log.error({ err, target }, "Could not check ransomware exposure");
      return {
        target: primary,
        recordsChecked: 0,
        matches: [],
        counts: { confirmed: 0, possible: 0 },
        feedFetchedAt: new Date(fetchedAt).toISOString(),
        error: "Leak-site feed unavailable — exposure could not be checked",
      };
    }
  }

  const matches: RansomwareMatch[] = [];
  const seen = new Set<string>();

  for (const post of posts) {
    const victim = (post.post_title ?? "").trim();
    const site = (post.website ?? "").trim();

    let confidence: RansomwareMatch["confidence"] | null = null;
    let reason = "";

    if (site) {
      const siteDomain = registrableDomain(site);
      if (siteDomain && domains.has(siteDomain)) {
        confidence = "confirmed";
        reason = `Leak-site listing names ${siteDomain}`;
      }
    }

    // Only consider a name match when the domain did not already confirm it.
    if (!confidence && nameMatchable && victim) {
      const victimName = normaliseOrgName(victim);
      if (victimName.length >= 5 && victimName === orgName) {
        confidence = "possible";
        reason = `Victim name "${victim}" matches the organisation name — verify before acting`;
      }
    }

    if (!confidence) continue;

    // The same victim is often posted by several crews, or twice by one.
    const key = `${post.group_name ?? "?"}|${victim}|${post.published ?? post.discovered ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);

    matches.push({
      victim: victim || site || "(unnamed)",
      group: post.group_name ?? "unknown",
      website: site || null,
      country: post.country ?? null,
      sector: post.activity && post.activity !== "Not Found" ? post.activity : null,
      publishedAt: post.published ?? null,
      discoveredAt: post.discovered ?? null,
      postUrl: post.post_url ?? null,
      confidence,
      reason,
    });
  }

  // Confirmed first, then newest — an analyst should see identity matches and
  // recent activity before anything speculative.
  const rank = { confirmed: 0, possible: 1 } as const;
  matches.sort(
    (a, b) =>
      rank[a.confidence] - rank[b.confidence] ||
      new Date(b.publishedAt ?? b.discoveredAt ?? 0).getTime() -
        new Date(a.publishedAt ?? a.discoveredAt ?? 0).getTime(),
  );

  const counts = {
    confirmed: matches.filter((m) => m.confidence === "confirmed").length,
    possible: matches.filter((m) => m.confidence === "possible").length,
  };

  log.info({ target: primary, records: posts.length, ...counts }, "Ransomware exposure check complete");

  return {
    target: primary,
    recordsChecked: posts.length,
    matches,
    counts,
    feedFetchedAt: new Date(fetchedAt).toISOString(),
  };
}
