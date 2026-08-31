/**
 * Deep SPF and DMARC analysis.
 *
 * The existing checks were string matches on the record text: SPF looked for
 * `+all`/`?all`/`-all`, DMARC looked for `p=none` and `pct=`. That catches the
 * obvious cases and misses the ones that actually bite, because the dangerous
 * failures here are silent — the record LOOKS right and provides no protection.
 *
 * ── The SPF lookup limit ────────────────────────────────────────────────────
 * RFC 7208 §4.6.4 caps an SPF evaluation at 10 DNS-querying mechanisms. Exceed
 * it and a conforming receiver returns `permerror`, which per §8.7 is treated
 * as though the domain had published NO SPF AT ALL. Every `include:` of a SaaS
 * provider brings its own nested includes, so a marketing team adding one more
 * vendor silently switches off the domain's SPF. The record still reads
 * perfectly. Nothing warns anyone. This is the single most common real-world
 * SPF failure and the previous check could not see it, because counting
 * requires actually resolving the include tree rather than reading the string.
 *
 * ── The DMARC gaps ──────────────────────────────────────────────────────────
 *   no rua=     nobody ever receives the aggregate reports, so the policy can
 *               never be tightened with any confidence — p=none becomes
 *               permanent because no one has the data to move off it
 *   sp=none     subdomains are exempt even when p=reject. An attacker spoofs
 *               mail.victim.com rather than victim.com and walks straight past
 *               a policy everyone believes is enforcing
 *   external
 *   rua         reports sent to a different domain require that domain to
 *               publish an authorisation record. Without it the reports are
 *               silently discarded and the owner sees an empty dashboard,
 *               concluding they have no problems
 */

/**
 * DNS-querying mechanisms, per RFC 7208 §4.6.4.
 *
 * Each name must be followed by ":", "/" or the end of the term. Written as a
 * bare alternation (`a|mx|ptr`), the `a` matches the first letter of `-all` and
 * every record's own terminator is counted as a lookup — which inflated every
 * count by one and would have reported domains as over the limit when they were
 * not. `include` and `exists` always carry a colon; `a` and `mx` may appear
 * bare, with a domain, or with a CIDR (`a/24`, `a:mail.example.com/24`).
 */
const LOOKUP_MECHANISMS = /^(\+|-|~|\?)?(include:|exists:|(a|mx)([:/]|$)|ptr(:|$))/i;

/** RFC 7208 §4.6.4 — evaluation must not exceed ten DNS-querying terms. */
export const SPF_LOOKUP_LIMIT = 10;

/** RFC 7208 §4.6.4 — more than two "void" lookups is also a permerror. */
export const SPF_VOID_LOOKUP_LIMIT = 2;

export interface SpfLookupResult {
  /** DNS-querying mechanisms encountered across the whole include tree. */
  count: number;
  /** Lookups that returned no usable record. */
  voidLookups: number;
  /** Domains visited, in order, for the evidence trail. */
  chain: string[];
  /** The evaluation exceeds a limit and therefore returns permerror. */
  exceeded: boolean;
  /** True when an include loop was detected and cut. */
  loop: boolean;
}

export type TxtLookup = (name: string) => Promise<string[][]>;

/** Joins the character-strings DNS splits a long TXT record into. */
function joinTxt(chunks: string[][]): string[] {
  return chunks.map((parts) => parts.join(""));
}

/** Finds the SPF record among a domain's TXT records. */
export function findSpfRecord(records: string[]): string | undefined {
  return records.find((r) => /^v=spf1(\s|$)/i.test(r.trim()));
}

/**
 * Counts the DNS-querying mechanisms in an SPF record, following `include:`
 * and `redirect=` exactly as a receiving mail server would.
 *
 * `seen` cuts include loops: a domain that includes itself, directly or through
 * a chain, would otherwise recurse until the stack gives out. Real SPF records
 * do contain loops, usually by accident after a provider migration.
 */
export async function countSpfLookups(
  domain: string,
  record: string,
  lookupTxt: TxtLookup,
  seen: Set<string> = new Set(),
  state: { count: number; voidLookups: number; chain: string[]; loop: boolean } = {
    count: 0,
    voidLookups: 0,
    chain: [],
    loop: false,
  },
): Promise<SpfLookupResult> {
  const key = domain.toLowerCase();
  if (seen.has(key)) {
    state.loop = true;
    return { ...state, exceeded: isExceeded(state) };
  }
  seen.add(key);
  state.chain.push(domain);

  for (const rawTerm of record.trim().split(/\s+/).slice(1)) {
    // Stop counting once the limit is blown: a receiver aborts too, and
    // resolving hundreds more names to produce a bigger number helps nobody.
    if (isExceeded(state)) break;

    const term = rawTerm.trim();
    if (!term) continue;

    const redirect = /^redirect=(.+)$/i.exec(term);
    if (redirect) {
      state.count += 1;
      await recurse(redirect[1], lookupTxt, seen, state);
      continue;
    }

    if (!LOOKUP_MECHANISMS.test(term)) continue;
    state.count += 1;

    const include = /^(\+|-|~|\?)?include:(.+)$/i.exec(term);
    if (include) await recurse(include[2], lookupTxt, seen, state);
  }

  return { ...state, exceeded: isExceeded(state) };
}

function isExceeded(state: { count: number; voidLookups: number }): boolean {
  return state.count > SPF_LOOKUP_LIMIT || state.voidLookups > SPF_VOID_LOOKUP_LIMIT;
}

async function recurse(
  target: string,
  lookupTxt: TxtLookup,
  seen: Set<string>,
  state: { count: number; voidLookups: number; chain: string[]; loop: boolean },
): Promise<void> {
  let nested: string | undefined;
  try {
    nested = findSpfRecord(joinTxt(await lookupTxt(target)));
  } catch {
    nested = undefined;
  }
  if (!nested) {
    // An include that resolves to nothing is a void lookup, and two of them are
    // themselves a permerror — a stale include of a decommissioned vendor is a
    // common way for this to happen without anyone noticing.
    state.voidLookups += 1;
    return;
  }
  await countSpfLookups(target, nested, lookupTxt, seen, state);
}

export interface SpfAnalysis {
  found: boolean;
  record: string;
  issues: string[];
  lookups?: SpfLookupResult;
}

/** Full SPF assessment, including the lookup budget. */
export async function analyzeSpfDeep(
  domain: string,
  txtRecords: string[][],
  lookupTxt: TxtLookup,
): Promise<SpfAnalysis> {
  const records = joinTxt(txtRecords).filter((r) => /^v=spf1(\s|$)/i.test(r.trim()));
  if (records.length === 0) return { found: false, record: "", issues: ["No SPF record found"] };

  const record = records[0];
  const issues: string[] = [];

  if (records.length > 1) {
    // Two SPF records is a permerror in itself: a receiver cannot choose
    // between them, so it rejects both and the domain has no SPF.
    issues.push(
      `${records.length} SPF records published; RFC 7208 permits exactly one, and a receiver treats this as permerror (no SPF protection)`,
    );
  }

  if (/[\s^]\+?all\b/i.test(record) && /\+all\b/i.test(record)) {
    issues.push("SPF ends in +all, which authorises every sender on the internet to use this domain");
  } else if (/\?all\b/i.test(record)) {
    issues.push("SPF ends in ?all (neutral), which asks receivers to treat unauthorised senders no differently");
  } else if (/~all\b/i.test(record)) {
    issues.push("SPF ends in ~all (softfail); mail from unauthorised senders is usually still delivered, to spam");
  } else if (!/-all\b/i.test(record)) {
    issues.push("SPF has no 'all' terminator, so senders not listed are neither authorised nor rejected");
  }

  // ptr was deprecated by RFC 7208 §5.5: it is slow, unreliable, and receivers
  // are explicitly told they may skip it, so anything relying on it may fail.
  if (/(^|\s)(\+|-|~|\?)?ptr\b/i.test(record)) {
    issues.push("SPF uses the 'ptr' mechanism, deprecated by RFC 7208 §5.5 — receivers are permitted to ignore it");
  }

  for (const cidr of record.match(/ip4:\S+\/(\d+)/gi) ?? []) {
    const bits = Number.parseInt(cidr.split("/")[1], 10);
    if (bits <= 8) {
      issues.push(`SPF authorises an extremely broad range (${cidr}), covering millions of unrelated hosts`);
    }
  }

  const lookups = await countSpfLookups(domain, record, lookupTxt);
  if (lookups.count > SPF_LOOKUP_LIMIT) {
    issues.push(
      `SPF evaluation needs ${lookups.count} DNS lookups, over the RFC 7208 limit of ${SPF_LOOKUP_LIMIT}; ` +
        `receivers return permerror and treat this domain as having NO SPF record at all`,
    );
  } else if (lookups.count >= SPF_LOOKUP_LIMIT - 1) {
    issues.push(
      `SPF uses ${lookups.count} of the ${SPF_LOOKUP_LIMIT} permitted DNS lookups; adding one more provider will break it`,
    );
  }
  if (lookups.voidLookups > SPF_VOID_LOOKUP_LIMIT) {
    issues.push(
      `SPF contains ${lookups.voidLookups} lookups that resolve to nothing, over the limit of ${SPF_VOID_LOOKUP_LIMIT} — likely includes of decommissioned providers`,
    );
  }
  if (lookups.loop) {
    issues.push("SPF include chain contains a loop, which a receiver evaluates as permerror");
  }

  return { found: true, record, issues, lookups };
}

export interface DmarcAnalysis {
  found: boolean;
  record: string;
  issues: string[];
  policy?: string;
  subdomainPolicy?: string;
  rua: string[];
}

/** Parses `k=v; k=v` tags. */
function tags(record: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of record.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    out[part.slice(0, idx).trim().toLowerCase()] = part.slice(idx + 1).trim();
  }
  return out;
}

/**
 * Full DMARC assessment.
 *
 * `lookupTxt` is optional. Without it the external-reporter authorisation check
 * is SKIPPED rather than guessed at — most large domains legitimately send
 * their reports to a DMARC vendor and do publish the authorisation record, so
 * asserting a problem without looking would put a false positive on nearly
 * every well-run domain. Measured on salesforce.com, which uses two vendors.
 */
export async function analyzeDmarcDeep(
  domain: string,
  txtRecords: string[][],
  lookupTxt?: TxtLookup,
): Promise<DmarcAnalysis> {
  const records = joinTxt(txtRecords).filter((r) => /^v=DMARC1/i.test(r.trim()));
  if (records.length === 0) return { found: false, record: "", issues: ["No DMARC record found"], rua: [] };

  const record = records[0];
  const t = tags(record);
  const issues: string[] = [];
  const policy = t.p?.toLowerCase();
  const subdomainPolicy = t.sp?.toLowerCase();
  const rua = (t.rua ?? "").split(",").map((s) => s.trim()).filter(Boolean);

  if (records.length > 1) issues.push(`${records.length} DMARC records published; RFC 7489 permits exactly one`);

  if (!policy) {
    issues.push("DMARC record has no p= tag, so it specifies no policy and is ignored");
  } else if (policy === "none") {
    issues.push("DMARC policy is p=none (monitoring only): messages failing authentication are still delivered");
  } else if (!["quarantine", "reject"].includes(policy)) {
    issues.push(`DMARC policy value "${t.p}" is not valid; receivers ignore the record`);
  }

  // The subdomain bypass. An attacker does not need to spoof the apex if any
  // subdomain is exempt — mail from "billing.victim.com" is just as convincing.
  if (subdomainPolicy === "none" && (policy === "quarantine" || policy === "reject")) {
    issues.push(
      `DMARC enforces p=${policy} on ${domain} but sets sp=none, exempting every subdomain — an attacker can spoof a subdomain and bypass the policy entirely`,
    );
  }

  if (rua.length === 0) {
    issues.push(
      "DMARC has no rua= address, so no aggregate reports are sent anywhere and the policy cannot be tightened with any confidence",
    );
  }

  // Reports to another domain need that domain's permission, published as a
  // record at <this-domain>._report._dmarc.<their-domain>. Without it the
  // reports are silently dropped and the owner sees an empty dashboard.
  const external = rua
    .map((u) => /^mailto:[^@]+@(.+)$/i.exec(u.trim())?.[1]?.toLowerCase())
    .filter((d): d is string => !!d && d !== domain.toLowerCase() && !d.endsWith(`.${domain.toLowerCase()}`));

  if (external.length > 0 && lookupTxt) {
    const unauthorised: string[] = [];
    for (const ext of Array.from(new Set(external))) {
      try {
        const authz = joinTxt(await lookupTxt(`${domain}._report._dmarc.${ext}`));
        if (!authz.some((r) => /^v=DMARC1/i.test(r.trim()))) unauthorised.push(ext);
      } catch {
        // NXDOMAIN is the answer we are looking for: no authorisation exists.
        unauthorised.push(ext);
      }
    }
    if (unauthorised.length > 0) {
      issues.push(
        `DMARC reports are sent to ${unauthorised.join(", ")}, which ${unauthorised.length === 1 ? "does" : "do"} not ` +
          `publish the required authorisation record (${domain}._report._dmarc.${unauthorised[0]}), so those reports are ` +
          `silently discarded and the absence of reports looks like an absence of problems`,
      );
    }
  }

  const pct = Number.parseInt(t.pct ?? "100", 10);
  if (Number.isFinite(pct) && pct < 100) {
    issues.push(`DMARC pct=${pct}, so the policy is applied to only ${pct}% of failing messages`);
  }

  return { found: true, record, issues, policy, subdomainPolicy, rua };
}
