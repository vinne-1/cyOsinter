/**
 * Subdomain permutation — the discovery method that learns the target's own
 * naming convention instead of guessing from a generic list.
 *
 * ## The gap this fills
 *
 * Discovery ran three ways: certificate transparency, a 2,258-word list, and
 * nine passive indexes. All three can only return a name that already exists
 * *somewhere* — in a certificate, in a wordlist, in somebody's index. An asset
 * that has never been issued a certificate, never been crawled, and is not named
 * after a common English word is invisible to all of them.
 *
 * Organisations do not name hosts randomly. They name them by convention, and
 * the convention is visible in the hosts already found: an estate containing
 * `api.example.com` and `staging-api.example.com` very likely also has
 * `dev-api`, `uat-api`, or `api2`. This module generates those candidates from
 * what discovery already returned — the same idea as ProjectDiscovery's `alterx`
 * and `dnsgen`, done natively so it works with no Go toolchain present, matching
 * how `nuclei`, `katana` and `httpx` are treated here.
 *
 * ## The vocabulary is learned, not fixed
 *
 * A curated environment list (`dev`, `uat`, `staging`, …) is the obvious half.
 * The valuable half is the **tokens observed in the target's own hostnames**: an
 * organisation using `corp`, `intl` or `emea` gets those permuted too, and no
 * generic wordlist would ever have contained them. That is the whole reason this
 * beats simply making the wordlist longer.
 *
 * ## Budget is the hard part
 *
 * Permutation is combinatorial. Ninety discovered hosts against forty words and
 * three join styles is tens of thousands of DNS queries against one target, so
 * candidates are generated in **descending order of likelihood** and hard-capped.
 * Cutting the list at a cap is only defensible if what survives the cut is the
 * part worth trying — the same reasoning as the crawler's `maxPages`.
 *
 * ## Wildcards
 *
 * This module resolves nothing; the caller feeds candidates through the SAME
 * `checkDNSWildcard` filter the wordlist bruteforce already uses. That matters
 * more here than anywhere else in the engine: on a wildcard domain every
 * generated name "resolves", so an unfiltered permutation stage would invent
 * thousands of hosts that do not exist.
 */

/**
 * Environment and role words that appear in nearly every corporate estate.
 *
 * Deliberately short. Every entry multiplies the candidate count by the number
 * of discovered hosts, so a word earns its place by being common in real
 * infrastructure, not by being plausible.
 */
const ENV_WORDS: readonly string[] = [
  "dev", "test", "staging", "stage", "uat", "qa", "prod", "preprod",
  "internal", "int", "admin", "api", "app", "web", "portal",
  "new", "old", "beta", "demo", "backup", "legacy", "temp",
  "v1", "v2", "eu", "us", "corp",
];

/** Separators organisations actually use between name parts. */
const JOINERS: readonly string[] = ["-", "."];

/** Max distinct tokens learned from observed hostnames. */
const MAX_LEARNED_WORDS = 25;

/** A DNS label: letters, digits, hyphens; not leading/trailing hyphen; ≤63 chars. */
const VALID_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export interface PermutationOptions {
  /** Hard ceiling on generated candidates. */
  maxCandidates?: number;
  /** Extra vocabulary, e.g. words an operator knows the organisation uses. */
  extraWords?: string[];
}

/**
 * The part of a hostname below the apex.
 *
 * `api.example.com` under `example.com` gives `api`; `a.b.example.com` gives
 * `a.b`. Returns null for the apex itself and for anything not under the domain.
 */
export function subdomainPrefix(host: string, domain: string): string | null {
  const h = host.trim().toLowerCase().replace(/\.$/, "");
  const d = domain.trim().toLowerCase().replace(/\.$/, "");
  if (h === d) return null;
  if (!h.endsWith(`.${d}`)) return null;
  const prefix = h.slice(0, h.length - d.length - 1);
  return prefix.length > 0 ? prefix : null;
}

/**
 * Splits a prefix into the words the organisation composed it from.
 *
 * `staging-api` → `staging`, `api`. `api2` → `api`. Splitting on the
 * digit boundary matters: without it the vocabulary fills with `api2`, `api3`,
 * `web01` rather than the reusable stem.
 */
export function tokenize(prefix: string): string[] {
  return prefix
    .split(/[.\-_]+/)
    .flatMap((part) => {
      const m = /^([a-z]+)(\d+)$/.exec(part);
      return m ? [m[1]] : [part];
    })
    .filter((t) => t.length >= 2 && /^[a-z][a-z0-9]*$/.test(t));
}

/**
 * Number mutations for a prefix.
 *
 * `api` → `api1`, `api2`, `api01`. `web2` → `web1`, `web3`, `web02`.
 * Sequential hostnames are extremely common and a wordlist cannot express them,
 * because the interesting number depends on what already exists.
 */
export function numberMutations(prefix: string): string[] {
  const out: string[] = [];
  const m = /^(.*?)(\d+)$/.exec(prefix);

  if (m) {
    const [, stem, digits] = m;
    const n = Number(digits);
    const width = digits.length;
    for (const next of [n - 1, n + 1, n + 2]) {
      if (next < 0) continue;
      out.push(`${stem}${next}`);
      // Preserve zero padding when the original had it: an estate naming hosts
      // `web01` almost never also has `web2`.
      if (width > 1) out.push(`${stem}${String(next).padStart(width, "0")}`);
    }
  } else {
    for (const n of [1, 2, 3]) out.push(`${prefix}${n}`);
    out.push(`${prefix}01`, `${prefix}02`);
  }

  return out;
}

/**
 * Generates candidate hostnames from the hosts discovery already found.
 *
 * Pure: no DNS, no network, no clock. The caller resolves the result through the
 * existing wildcard-aware path.
 *
 * Candidates are emitted in descending order of likelihood, so truncating at
 * `maxCandidates` keeps the part worth trying:
 *   1. environment/role word joined to an existing prefix (`dev-api`, `api-dev`)
 *   2. number mutations of an existing prefix (`api2`, `web02`)
 *   3. learned-vocabulary joins (the organisation's own words)
 *   4. concatenations without a separator (`devapi`) — real, but rarer
 */
export function generatePermutations(
  domain: string,
  knownHosts: string[],
  options: PermutationOptions = {},
): string[] {
  const maxCandidates = options.maxCandidates ?? 5000;
  if (maxCandidates <= 0) return [];

  const apex = domain.trim().toLowerCase().replace(/\.$/, "");

  // Only permute names that were actually observed. Permuting a guess compounds
  // guesses and burns the budget on candidates two steps from any evidence.
  const prefixes = Array.from(
    new Set(
      knownHosts
        .map((h) => subdomainPrefix(h, apex))
        .filter((p): p is string => p !== null),
    ),
  ).sort();

  if (prefixes.length === 0) return [];

  const known = new Set(prefixes);

  // Vocabulary learned from the target, ordered by how often it appears — a
  // token used across many hosts is a naming convention, one used once is a
  // coincidence.
  const counts = new Map<string, number>();
  for (const p of prefixes) {
    for (const t of tokenize(p)) counts.set(t, (counts.get(t) ?? 0) + 1);
  }
  const learned = Array.from(counts.entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([t]) => t)
    .filter((t) => !ENV_WORDS.includes(t))
    .slice(0, MAX_LEARNED_WORDS);

  const extra = (options.extraWords ?? [])
    .map((w) => w.trim().toLowerCase())
    .filter((w) => VALID_LABEL.test(w));

  const out: string[] = [];
  const seen = new Set<string>();

  const emit = (candidatePrefix: string): boolean => {
    if (out.length >= maxCandidates) return false;
    const p = candidatePrefix.toLowerCase();
    if (known.has(p) || seen.has(p)) return true;
    // Every label must be valid on its own: a prefix like `dev.api` is two.
    if (!p.split(".").every((label) => VALID_LABEL.test(label))) return true;
    seen.add(p);
    out.push(`${p}.${apex}`);
    return true;
  };

  // ── Tier 1: environment/role words joined to observed prefixes ──
  for (const word of [...ENV_WORDS, ...extra]) {
    for (const p of prefixes) {
      for (const j of JOINERS) {
        if (!emit(`${word}${j}${p}`)) return out;
        if (!emit(`${p}${j}${word}`)) return out;
      }
    }
  }

  // ── Tier 2: number mutations ──
  for (const p of prefixes) {
    for (const mutated of numberMutations(p)) {
      if (!emit(mutated)) return out;
    }
  }

  // ── Tier 3: the organisation's own vocabulary ──
  for (const word of learned) {
    for (const p of prefixes) {
      for (const j of JOINERS) {
        if (!emit(`${word}${j}${p}`)) return out;
        if (!emit(`${p}${j}${word}`)) return out;
      }
    }
  }

  // ── Tier 4: separator-free concatenations ──
  for (const word of [...ENV_WORDS, ...extra]) {
    for (const p of prefixes) {
      if (!emit(`${word}${p}`)) return out;
      if (!emit(`${p}${word}`)) return out;
    }
  }

  return out;
}
