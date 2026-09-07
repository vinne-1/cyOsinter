/**
 * ASN / BGP-driven attack-surface expansion.
 *
 * ## The discovery vector this adds
 *
 * Every other discovery method here starts from a NAME: a subdomain wordlist, a
 * certificate transparency entry, an archived URL. All of them are blind to an
 * asset with no DNS record pointing at it — a forgotten VPN concentrator, a
 * decommissioned mail relay, a jump host addressed only by IP. Those are
 * routinely the way in, and they are exactly what an organisation does not know
 * it still owns.
 *
 * Routing data finds them from the other end. If the organisation runs its own
 * autonomous system, the global BGP table already publishes every prefix it
 * announces — the complete list of IP space it is responsible for, whether or
 * not anything resolves to it. This is the discovery substrate Censys ASM and
 * Cortex Xpanse are built on, and BGPView publishes it for free with no key.
 *
 * ## Why attribution is the whole problem
 *
 * Naively expanding the ASN behind a target's IP is catastrophic. A site behind
 * Cloudflare resolves into AS13335, which announces well over ten million
 * addresses belonging to every Cloudflare customer on earth. Expanding it would
 * attribute a large slice of the internet to one customer — the same
 * attribution error as claiming a stranger's S3 bucket because the name
 * matched, scaled up by six orders of magnitude.
 *
 * So expansion is REFUSED unless the AS is positively attributable to the
 * organisation, and refusal is the default:
 *
 *  - a known hosting, CDN, cloud or transit provider is never expanded, however
 *    the name matches;
 *  - the AS name or description must correspond to the organisation's own name
 *    or registrable domain;
 *  - an AS announcing more addresses than any single organisation plausibly
 *    operates directly is treated as shared infrastructure.
 *
 * Anything not positively attributed is reported as `shared` or `unknown` and
 * contributes no assets. The result is recon, never a finding: owning IP space
 * is not a weakness, it is the map you need before you can look for one.
 */

import { createLogger } from "../logger.js";
import { formatCount } from "../utils/format.js";
import { fetchJSON } from "./http.js";
import { fetchBGPView } from "../api-integrations.js";

const log = createLogger("asn-expansion");

/**
 * Networks whose address space belongs to their customers, not to whoever
 * happens to resolve into them.
 *
 * Matched against the AS name and description. The list is deliberately broad:
 * a false "shared" verdict costs one missed expansion, while a false "owned"
 * verdict attributes somebody else's infrastructure to the customer and puts
 * scanner traffic on it.
 */
const SHARED_INFRA_PATTERNS: RegExp[] = [
  /cloudflare/i,
  /\bamazon\b|\baws\b|amazon-\d|ec2/i,
  /\bgoogle\b|gcp|google-cloud/i,
  /microsoft|azure/i,
  /akamai/i,
  /fastly/i,
  /digitalocean/i,
  /linode|akamai-linode/i,
  /hetzner/i,
  /\bovh\b/i,
  /vultr|choopa/i,
  /rackspace/i,
  /\bibm\b|softlayer/i,
  /oracle.*cloud|oracle-bmc/i,
  /alibaba|aliyun/i,
  /tencent/i,
  /godaddy/i,
  /namecheap/i,
  /squarespace|wix|shopify|hubspot|wpengine|automattic/i,
  /incapsula|imperva|sucuri|stackpath|bunny|cdn77|keycdn/i,
  /netlify|vercel|heroku|render\.com|fly\.io/i,
  /leaseweb|contabo|scaleway|online\.net|hostinger|bluehost|dreamhost|siteground/i,
  /\bcdn\b|content delivery|hosting|datacenter|data center|colocation/i,
  /telecom|telekom|communications|broadband|internet service|\bisp\b|transit|backbone/i,
];

/**
 * Above this many IPv4 addresses, an AS is infrastructure rather than one
 * organisation's own estate.
 *
 * Two things make this number what it is.
 *
 * **It counts IPv4 only.** IPv6 allocation size is not a proxy for
 * organisational scale — a /32 is the standard allocation for a single
 * organisation and covers 2^96 addresses. Counting IPv6 classified *every*
 * IPv6-announcing organisation as shared infrastructure the moment the first
 * live test ran against a university that announces one, which would have made
 * the gate useless on the modern internet.
 *
 * **It is deliberately generous.** Large universities and enterprises really do
 * announce a /14 — Stanford's AS32 announces roughly 330,000 IPv4 addresses and
 * is unambiguously its own estate. The provider-name list above is the primary
 * defence; this is the backstop for a carrier that list does not name, so it is
 * set where genuine carrier scale begins rather than where a big enterprise
 * ends.
 */
const MAX_PLAUSIBLE_OWNED_IPV4 = 2_097_152; // a /11 equivalent

export type AsnAttribution = "owned" | "shared" | "unknown";

export interface AsnRecord {
  asn: number;
  name: string;
  description: string;
  countryCode?: string;
  attribution: AsnAttribution;
  /** Why the attribution was reached — surfaced so a reader can disagree. */
  reason: string;
}

export interface AsnPrefix {
  prefix: string;
  /** Number of addresses the prefix covers. */
  size: number;
  name?: string;
  description?: string;
  countryCode?: string;
}

export interface AsnExpansionResult {
  /** Every AS observed behind the target's addresses. */
  asns: AsnRecord[];
  /** Prefixes belonging to ASNs positively attributed to the organisation. */
  ownedPrefixes: AsnPrefix[];
  /** Total addresses across `ownedPrefixes`. */
  ownedAddressCount: number;
  /** True when routing data could not be reached at all. */
  unavailable: boolean;
  /** Human-readable account of what was expanded and what was refused. */
  notes: string[];
}

/** Addresses covered by a CIDR, for IPv4 and IPv6 alike. */
export function addressesInPrefix(prefix: string): number {
  const [, bitsRaw] = prefix.split("/");
  const bits = Number.parseInt(bitsRaw ?? "", 10);
  if (!Number.isFinite(bits)) return 0;
  const width = prefix.includes(":") ? 128 : 32;
  if (bits < 0 || bits > width) return 0;
  const host = width - bits;
  // IPv6 prefixes dwarf Number.MAX_SAFE_INTEGER; cap rather than overflow.
  return host > 52 ? Number.MAX_SAFE_INTEGER : 2 ** host;
}

/** True when the AS belongs to a provider whose space is its customers'. */
export function looksLikeSharedInfrastructure(name: string, description = ""): boolean {
  const hay = `${name} ${description}`;
  return SHARED_INFRA_PATTERNS.some((re) => re.test(hay));
}

/** Comparable form of an organisation or AS name: lowercase alphanumerics. */
function normaliseName(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}

/**
 * Decide whether an AS is the organisation's own.
 *
 * `orgTokens` are the identifiers we are willing to match on — normally the
 * registrable domain's label and, where known, the organisation name. A short
 * token is ignored: matching on "bt" or "ge" would attribute unrelated networks
 * on a two-letter coincidence.
 */
export function attributeAsn(
  asn: { asn: number; name?: string; description?: string; countryCode?: string },
  orgTokens: readonly string[],
  ipv4Addresses?: number,
): AsnRecord {
  const name = asn.name ?? "";
  const description = asn.description ?? "";
  const base: Omit<AsnRecord, "attribution" | "reason"> = {
    asn: asn.asn,
    name,
    description,
    countryCode: asn.countryCode,
  };

  if (looksLikeSharedInfrastructure(name, description)) {
    return {
      ...base,
      attribution: "shared",
      reason: `AS${asn.asn} (${name || "unnamed"}) is a hosting, CDN, cloud or transit network — its address space belongs to its customers, not to this organisation`,
    };
  }

  if (typeof ipv4Addresses === "number" && ipv4Addresses > MAX_PLAUSIBLE_OWNED_IPV4) {
    return {
      ...base,
      attribution: "shared",
      reason: `AS${asn.asn} announces ${formatCount(ipv4Addresses)} IPv4 addresses — larger than any single organisation plausibly operates directly, so it is treated as infrastructure`,
    };
  }

  const haystack = normaliseName(`${name} ${description}`);
  const matched = orgTokens
    .map(normaliseName)
    .filter((tok) => tok.length >= 4)
    .find((tok) => haystack.includes(tok));

  if (matched) {
    return {
      ...base,
      attribution: "owned",
      reason: `AS${asn.asn} (${name || "unnamed"}) names the organisation ("${matched}"), and is not a known provider network`,
    };
  }

  return {
    ...base,
    attribution: "unknown",
    reason: `AS${asn.asn} (${name || "unnamed"}) could not be tied to this organisation by name — no expansion performed`,
  };
}

/**
 * Every prefix an AS announces. Returns null when routing data is unavailable.
 *
 * RIPEstat is tried first and BGPView second. That order is deliberate:
 * RIPEstat is the RIPE NCC's own service, is keyless, and answered reliably in
 * testing, whereas `api.bgpview.io` was not resolvable at all from the
 * development network — which is precisely the kind of single-source dependency
 * that turns "this organisation announces nothing" into a confident wrong
 * answer. Two independent sources also mean a format change at one does not
 * silently blank the feature.
 */
export async function fetchAsnPrefixes(asn: number): Promise<AsnPrefix[] | null> {
  const fromRipe = await fetchAsnPrefixesFromRipeStat(asn);
  if (fromRipe !== null) return fromRipe;
  return fetchAsnPrefixesFromBgpView(asn);
}

/** RIPEstat announced-prefixes (primary). */
async function fetchAsnPrefixesFromRipeStat(asn: number): Promise<AsnPrefix[] | null> {
  const data = await fetchJSON(`https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${asn}`, 20000);
  const rows = (data as { data?: { prefixes?: unknown[] } })?.data?.prefixes;
  if (!Array.isArray(rows)) return null;

  const out: AsnPrefix[] = [];
  for (const row of rows) {
    const prefix = (row as { prefix?: string })?.prefix;
    if (!prefix) continue;
    out.push({ prefix, size: addressesInPrefix(prefix) });
  }
  return out;
}

/** BGPView asn/prefixes (fallback). */
async function fetchAsnPrefixesFromBgpView(asn: number): Promise<AsnPrefix[] | null> {
  const data = await fetchJSON(`https://api.bgpview.io/asn/${asn}/prefixes`, 15000);
  const v4 = (data as { data?: { ipv4_prefixes?: unknown[] } })?.data?.ipv4_prefixes;
  const v6 = (data as { data?: { ipv6_prefixes?: unknown[] } })?.data?.ipv6_prefixes;
  if (!Array.isArray(v4) && !Array.isArray(v6)) return null;

  const out: AsnPrefix[] = [];
  for (const row of [...(v4 ?? []), ...(v6 ?? [])]) {
    const r = row as { prefix?: string; name?: string; description?: string; country_code?: string };
    if (!r?.prefix) continue;
    out.push({
      prefix: r.prefix,
      size: addressesInPrefix(r.prefix),
      name: r.name,
      description: r.description,
      countryCode: r.country_code,
    });
  }
  return out;
}

/**
 * Expand the organisation's routed footprint from the addresses its domain
 * resolves to.
 *
 * `orgTokens` should carry the registrable domain label and any known
 * organisation name. Fail-soft throughout: unreachable routing data yields
 * `unavailable: true` rather than an empty result that reads as "this
 * organisation announces nothing".
 */
export async function runAsnExpansion(
  ips: readonly string[],
  orgTokens: readonly string[],
  opts: { maxAsns?: number } = {},
): Promise<AsnExpansionResult> {
  const maxAsns = opts.maxAsns ?? 5;
  const asns = new Map<number, AsnRecord>();
  const notes: string[] = [];
  let reachedRouting = false;

  for (const ip of ips) {
    const bgp = await fetchBGPView(ip);
    if (!bgp) continue;
    reachedRouting = true;
    for (const prefix of bgp.prefixes ?? []) {
      const a = prefix.asn;
      if (!a?.asn || asns.has(a.asn)) continue;
      asns.set(
        a.asn,
        attributeAsn(
          { asn: a.asn, name: a.name, description: a.description, countryCode: a.country_code },
          orgTokens,
        ),
      );
    }
  }

  if (!reachedRouting) {
    return {
      asns: [],
      ownedPrefixes: [],
      ownedAddressCount: 0,
      unavailable: true,
      notes: ["Routing data was unavailable, so the organisation's announced address space could not be checked. This is not evidence that it announces none."],
    };
  }

  const ownedPrefixes: AsnPrefix[] = [];
  const candidates = Array.from(asns.values());

  for (const record of candidates.filter((a) => a.attribution === "owned").slice(0, maxAsns)) {
    const prefixes = await fetchAsnPrefixes(record.asn);
    if (prefixes === null) {
      notes.push(`AS${record.asn} is attributed to this organisation, but its prefix list could not be retrieved.`);
      continue;
    }
    // IPv4 only: an IPv6 /32 is a standard single-organisation allocation and
    // covers 2^96 addresses, so including it would classify every IPv6-capable
    // organisation as a carrier.
    const ipv4Total = prefixes
      .filter((p) => !p.prefix.includes(":"))
      .reduce((sum, p) => sum + p.size, 0);

    // Re-attribute with the real size now that it is known. An AS can name the
    // organisation and still be a carrier — the size check is what catches that,
    // and it can only run once the prefixes are in hand.
    const resized = attributeAsn(
      { asn: record.asn, name: record.name, description: record.description, countryCode: record.countryCode },
      orgTokens,
      ipv4Total,
    );
    if (resized.attribution !== "owned") {
      asns.set(record.asn, resized);
      notes.push(resized.reason);
      continue;
    }
    ownedPrefixes.push(...prefixes);
  }

  for (const a of candidates) {
    if (a.attribution !== "owned") notes.push(a.reason);
  }

  // Reported as IPv4 addresses: summing IPv6 would produce an unreadable number
  // dominated by a single allocation and tell the reader nothing.
  const ownedAddressCount = ownedPrefixes
    .filter((p) => !p.prefix.includes(":"))
    .reduce((sum, p) => sum + p.size, 0);
  log.info(
    { asns: asns.size, owned: ownedPrefixes.length, addresses: ownedAddressCount },
    "ASN expansion complete",
  );

  return {
    asns: Array.from(asns.values()),
    ownedPrefixes,
    ownedAddressCount,
    unavailable: false,
    notes,
  };
}
