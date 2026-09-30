/**
 * DNSSEC detection.
 *
 * The previous check was `checkDNSSEC`, and it did this:
 *
 *     resolveSoa(domain).then(() => ({ soaPresent: true }))
 *
 * Every domain that resolves at all has an SOA record, so that returned true
 * for essentially every target — and the generated DOCX report printed it as
 * "DNSSEC: SOA present (zone signed / responsive)". The tool was telling
 * customers their zone was signed on the basis of a check that says nothing
 * about DNSSEC whatsoever.
 *
 * Node's resolver cannot ask for DNSKEY, DS or RRSIG records and has no way to
 * see the AD (Authenticated Data) flag, so a real check has to go out over
 * DNS-over-HTTPS. Cloudflare and Google both answer DoH in JSON, free and
 * without a key.
 *
 * What actually establishes that a zone is signed:
 *
 *   DS at the parent  — the parent zone vouches for this zone's key. Without a
 *                       DS record the chain of trust stops above the zone and
 *                       publishing DNSKEYs achieves nothing.
 *   DNSKEY in-zone    — the zone publishes signing keys.
 *   AD flag           — a validating resolver checked the signatures and they
 *                       verified. This is the strongest single signal, because
 *                       it is a third party's verdict rather than our reading
 *                       of the records.
 *
 * A zone is reported as signed only when the chain holds. DNSKEYs with no DS is
 * a real and distinct state — it is a half-finished DNSSEC rollout, which is
 * worth telling the owner about rather than rounding to "signed" or "not".
 */

import type { VerifiedFinding } from "./constants.js";
import { createLogger } from "../logger.js";

const log = createLogger("dnssec");

/** JSON shape returned by both Cloudflare and Google DoH endpoints. */
interface DohResponse {
  Status?: number;
  /** Authenticated Data: the resolver validated the signatures. */
  AD?: boolean;
  Answer?: Array<{ name?: string; type?: number; TTL?: number; data?: string }>;
  Authority?: Array<{ name?: string; type?: number; data?: string }>;
}

export type DohFetcher = (url: string, headers: Record<string, string>) => Promise<DohResponse | null>;

export interface DnssecStatus {
  /** The zone is signed and the chain of trust from the parent holds. */
  signed: boolean;
  /** Parent zone publishes a DS record delegating trust to this zone. */
  dsPresent: boolean;
  /** Zone publishes DNSKEY records. */
  dnskeyPresent: boolean;
  /** A validating resolver confirmed the signatures verify. */
  authenticatedData: boolean;
  /** DNSKEY algorithm numbers seen, for the report. */
  algorithms: number[];
  /**
   * Plain-language state. `unverifiable` is distinct from `unsigned` — it means
   * the lookup failed, not that the zone is unprotected, and conflating the two
   * would make a network blip look like a security finding.
   */
  state: "signed" | "keys-without-delegation" | "unsigned" | "unverifiable";
  /** Why we concluded what we did, for evidence. */
  detail: string;
}

const DNSKEY = 48;
const DS = 43;

/**
 * Distinguishes a TLS-interception failure from an ordinary network error, so
 * a warning log can say WHY a resolver was unreachable instead of just THAT
 * it was. `SELF_SIGNED_CERT_IN_CHAIN` / `UNABLE_TO_VERIFY_LEAF_SIGNATURE` are
 * what Node reports when something between this process and the resolver
 * re-signs the TLS connection with its own certificate — the signature of a
 * network appliance or corporate proxy actively intercepting the connection,
 * which is a common policy specifically for DNS-over-HTTPS (it lets a client
 * bypass DNS-based filtering and logging otherwise).
 */
export function classifyFetchFailure(err: unknown): string {
  const cause = (err as { cause?: { code?: string } } | undefined)?.cause;
  if (cause?.code === "SELF_SIGNED_CERT_IN_CHAIN" || cause?.code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE" || cause?.code === "CERT_HAS_EXPIRED") {
    return "TLS certificate validation failed — a network device between this server and the resolver may be intercepting the connection";
  }
  if (err instanceof Error && (err.name === "AbortError" || /timeout|timed out/i.test(err.message))) {
    return "timed out";
  }
  if (cause?.code) return `network error (${cause.code})`;
  return err instanceof Error ? err.message : "unknown error";
}

/** Default fetcher. Cloudflare first, Google second, NextDNS third. */
export const defaultDohFetcher: DohFetcher = async (url, headers) => {
  try {
    const res = await fetch(url, { headers, signal: AbortSignal.timeout(6000) });
    if (!res.ok) {
      log.warn({ url, status: res.status }, "DoH provider answered with a non-OK status");
      return null;
    }
    return (await res.json()) as DohResponse;
  } catch (err) {
    log.warn({ url, reason: classifyFetchFailure(err) }, "DoH provider unreachable");
    return null;
  }
};

/**
 * Queries one record type, trying Cloudflare, then Google, then NextDNS.
 *
 * A third provider exists because "both resolvers unreachable" is not always
 * a real network outage — some networks specifically block or TLS-intercept
 * DNS-over-HTTPS to the two best-known public resolvers (it is a common
 * corporate/security-appliance policy, precisely because DoH lets a client
 * bypass DNS-based filtering and logging), while leaving other DoH providers
 * untouched. NextDNS's JSON API returns the identical shape Cloudflare and
 * Google do, so it slots into the exact same parsing path.
 */
async function query(domain: string, type: "DNSKEY" | "DS", fetcher: DohFetcher): Promise<DohResponse | null> {
  const encoded = encodeURIComponent(domain);
  const cloudflare = await fetcher(`https://cloudflare-dns.com/dns-query?name=${encoded}&type=${type}&do=1`, {
    accept: "application/dns-json",
  });
  if (cloudflare) return cloudflare;
  const google = await fetcher(`https://dns.google/resolve?name=${encoded}&type=${type}&do=1`, { accept: "application/json" });
  if (google) return google;
  return fetcher(`https://dns.nextdns.io/dns-query?name=${encoded}&type=${type}&do=1`, { accept: "application/dns-json" });
}

/** Pulls the algorithm number from a DNSKEY rdata string: "flags protocol alg key". */
function algorithmsFrom(answers: DohResponse["Answer"]): number[] {
  const algs = new Set<number>();
  for (const a of answers ?? []) {
    if (a.type !== DNSKEY || !a.data) continue;
    const parts = a.data.trim().split(/\s+/);
    const alg = Number.parseInt(parts[2] ?? "", 10);
    if (Number.isFinite(alg)) algs.add(alg);
  }
  return Array.from(algs).sort((x, y) => x - y);
}

/**
 * Determines whether a zone is signed.
 *
 * `fetchDoh` is injected so this is testable without network access.
 */
export async function checkDnssec(domain: string, fetchDoh: DohFetcher = defaultDohFetcher): Promise<DnssecStatus> {
  const [dnskey, ds] = await Promise.all([query(domain, "DNSKEY", fetchDoh), query(domain, "DS", fetchDoh)]);

  // Both providers unreachable. Saying "unsigned" here would invent a finding
  // out of a network failure.
  if (!dnskey && !ds) {
    return {
      signed: false,
      dsPresent: false,
      dnskeyPresent: false,
      authenticatedData: false,
      algorithms: [],
      state: "unverifiable",
      detail:
        "DNS-over-HTTPS lookups to Cloudflare, Google, and NextDNS all failed to complete; DNSSEC state could not be " +
        "determined. If this persists, check the server's outbound network logs for this domain — a TLS certificate " +
        "error (rather than a timeout) to all three usually means a network device between this server and the public " +
        "internet is intercepting DNS-over-HTTPS, which is a common policy since DoH otherwise bypasses DNS-based " +
        "filtering and logging.",
    };
  }

  const dnskeyAnswers = (dnskey?.Answer ?? []).filter((a) => a.type === DNSKEY);
  const dsAnswers = (ds?.Answer ?? []).filter((a) => a.type === DS);
  const dnskeyPresent = dnskeyAnswers.length > 0;
  const dsPresent = dsAnswers.length > 0;
  // Either query's AD flag is evidence: both are answers about this zone.
  const authenticatedData = Boolean(dnskey?.AD || ds?.AD);
  const algorithms = algorithmsFrom(dnskey?.Answer);

  if (dsPresent && dnskeyPresent) {
    return {
      signed: true,
      dsPresent,
      dnskeyPresent,
      authenticatedData,
      algorithms,
      state: "signed",
      detail:
        `Parent zone publishes ${dsAnswers.length} DS record(s) and the zone publishes ${dnskeyAnswers.length} DNSKEY record(s)` +
        (authenticatedData ? "; a validating resolver confirmed the signatures verify" : ""),
    };
  }

  if (dnskeyPresent && !dsPresent) {
    // A half-finished rollout: the zone is signed but nothing above it says so,
    // so no validating resolver will ever check those signatures.
    return {
      signed: false,
      dsPresent,
      dnskeyPresent,
      authenticatedData,
      algorithms,
      state: "keys-without-delegation",
      detail:
        `The zone publishes ${dnskeyAnswers.length} DNSKEY record(s) but the parent zone has no DS record, so the chain of ` +
        `trust is broken and no validating resolver will check these signatures`,
    };
  }

  return {
    signed: false,
    dsPresent,
    dnskeyPresent,
    authenticatedData,
    algorithms,
    state: "unsigned",
    detail: "No DNSKEY or DS records found; the zone is not signed",
  };
}

/** Human-readable line for the report, replacing the old SOA-based claim. */
export function describeDnssec(status: DnssecStatus): string {
  switch (status.state) {
    case "signed":
      return status.algorithms.length
        ? `Signed (algorithm ${status.algorithms.join(", ")})`
        : "Signed";
    case "keys-without-delegation":
      return "Keys published but not delegated (no DS record at parent)";
    case "unsigned":
      return "Not signed";
    default:
      return "Could not be determined";
  }
}

/**
 * Findings for DNSSEC state.
 *
 * Deliberately only one case raises a finding. The great majority of domains
 * are simply unsigned, and flagging every one of them would add a low-severity
 * row to every report that no reader would ever act on — the definition of
 * noise. "Keys published but not delegated" is different: somebody started a
 * DNSSEC rollout and it is silently doing nothing, which is a genuine
 * misconfiguration and a fixable one.
 */
export function buildDnssecFindings(domain: string, status: DnssecStatus, now: string): VerifiedFinding[] {
  if (status.state !== "keys-without-delegation") return [];

  return [
    {
      title: `DNSSEC is configured but not active for ${domain}`,
      description:
        `${domain} publishes DNSKEY records, so someone has signed the zone, but the parent zone publishes no DS record. ` +
        `The chain of trust therefore stops above this zone and no validating resolver will ever check those signatures. ` +
        `The domain has the operational cost of DNSSEC — key management, rollovers, a zone that breaks if signing fails — ` +
        `and none of the protection, so cache-poisoning and spoofed-response attacks remain possible.`,
      severity: "low",
      category: "dns_misconfiguration",
      affectedAsset: domain,
      cvssScore: "3.7",
      remediation:
        `Submit the DS record for the zone's key-signing key to the registrar so the parent zone can publish it. ` +
        `Verify afterwards that a validating resolver returns the AD flag for ${domain}.`,
      evidence: [
        {
          type: "dns",
          description: "DNSKEY and DS record state over DNS-over-HTTPS",
          snippet:
            `DNSKEY records: present${status.algorithms.length ? ` (algorithm ${status.algorithms.join(", ")})` : ""}\n` +
            `DS record at parent: absent\nValidating resolver AD flag: ${status.authenticatedData ? "set" : "not set"}\n\n${status.detail}`,
          source: "Cloudflare / Google DNS-over-HTTPS",
          verifiedAt: now,
        },
      ],
    },
  ];
}
