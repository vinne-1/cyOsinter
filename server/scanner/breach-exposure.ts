/**
 * Breach-corpus exposure — is this organisation named in a public breach?
 *
 * ## Why this is buildable, when "dark web monitoring" mostly is not
 *
 * The phrase covers several very different things. This module does the part
 * that can be done from clearnet, with no credential handling and no Tor:
 * it asks the public breach corpus whether the organisation being scanned
 * appears in it as the **breached party**.
 *
 * HaveIBeenPwned's account-search API needs a paid key. Its **breach metadata**
 * endpoint does not — `/api/v3/breaches?Domain=` is keyless, and that is the
 * half that answers "was this organisation breached, when, how many records,
 * and what kind of data". No password, hash or email address is transmitted or
 * received: this is a catalogue of incidents, not a dump.
 *
 * ## The distinction that must not be blurred
 *
 * There are two completely different questions, and conflating them would be a
 * serious overclaim:
 *
 *  - **What this answers:** "acme.com appears in N public breach records as the
 *    organisation that was breached."
 *  - **What this does NOT answer:** "these 400 @acme.com accounts appear in
 *    third-party breaches." That is HIBP's domain-search feature, and it
 *    requires a paid subscription *and* proof of domain ownership — deliberately,
 *    because it enumerates individuals. It is out of scope here and the finding
 *    says so rather than letting a reader assume the broader coverage.
 *
 * ## HIBP's own quality flags are honoured, not ignored
 *
 * The corpus is not uniformly trustworthy and HIBP says so per record. Reporting
 * every hit at the same weight would manufacture alarm:
 *
 *  - `IsFabricated` — HIBP believes the "breach" is invented. Reporting it as an
 *    exposure would be repeating a hoax back to the customer as fact, so these
 *    are **excluded from findings entirely** and recorded separately.
 *  - `IsVerified: false` — HIBP has not been able to confirm it. Reported, but
 *    explicitly as unconfirmed and never at high severity.
 *  - `IsSpamList` — a marketing list, not a security incident.
 *  - `IsStealerLog` — sourced from infostealer malware output. Different cause
 *    and different remediation from a server-side breach, so it is labelled.
 *
 * ## Three states
 *
 * If the corpus cannot be reached the result is `unavailable`, never an empty
 * list. "We could not check whether you appear in any breach" and "you appear in
 * none" are opposite conclusions, and only one of them is reassuring.
 */

import { createLogger } from "../logger.js";
import { stealthFetch } from "./stealth.js";
import { formatCount } from "../utils/format.js";

const log = createLogger("breach-exposure");

const HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches";
const REQUEST_TIMEOUT_MS = 20_000;

/**
 * HIBP asks callers to identify themselves. This is their documented
 * requirement, not an attempt to look like a browser.
 */
const USER_AGENT = "Cyshield-EASM (self-hosted attack surface monitor)";

/** Data classes whose exposure materially raises the severity of a breach. */
const CREDENTIAL_CLASSES = [
  "passwords",
  "password hints",
  "security questions and answers",
  "auth tokens",
  "private messages",
  "bank account numbers",
  "credit cards",
  "social security numbers",
  "government issued ids",
  "partial credit card data",
];

export interface BreachRecord {
  name: string;
  title: string;
  domain: string;
  /** ISO date the breach occurred, per HIBP. */
  breachDate: string;
  /** ISO timestamp the record was added to the corpus. */
  addedDate?: string;
  /** Accounts in the breach. */
  pwnCount: number;
  /** What was exposed, e.g. ["Email addresses", "Passwords"]. */
  dataClasses: string[];
  /** HIBP has independently confirmed the breach is real. */
  verified: boolean;
  /** HIBP believes the breach is invented. Never reported as exposure. */
  fabricated: boolean;
  /** A marketing/spam list rather than a security incident. */
  spamList: boolean;
  /** Sourced from infostealer malware rather than a server-side compromise. */
  stealerLog: boolean;
  /** Distributed by malware. */
  malware: boolean;
  /** True when the breach exposed credentials or financial/identity data. */
  exposedCredentials: boolean;
}

export interface BreachExposureResult {
  domain: string;
  /** Verified, non-fabricated breaches naming this domain. */
  confirmed: BreachRecord[];
  /** Real records HIBP has not verified. Reported, but never as confirmed fact. */
  unverified: BreachRecord[];
  /** Records HIBP flags as fabricated. Recorded, never reported as exposure. */
  fabricated: BreachRecord[];
  /**
   * What this check structurally cannot see, stated so a clean result is not
   * read as broader assurance than it is.
   */
  notCovered: string[];
  /** The corpus could not be reached. NOT the same as "no breaches found". */
  unavailable: boolean;
  /**
   * WHY no conclusion was reached. "The catalogue is down" and "you gave me a
   * label, not a domain" are different problems with different fixes, and a
   * reader who is told the wrong one goes and debugs the wrong thing.
   */
  unavailableReason?: "no-domain" | "corpus-unreachable";
}

interface HibpBreach {
  Name?: string;
  Title?: string;
  Domain?: string;
  BreachDate?: string;
  AddedDate?: string;
  PwnCount?: number;
  DataClasses?: string[];
  IsVerified?: boolean;
  IsFabricated?: boolean;
  IsSpamList?: boolean;
  IsStealerLog?: boolean;
  IsMalware?: boolean;
}

/**
 * Whether a string is usable as a domain for this lookup.
 *
 * Half the workspaces in a live database have no `domain` set, and the routes
 * fall back to the workspace NAME. Sometimes that name is a domain
 * (`mydesk.theranym.com`) and sometimes it is a label (`Bigbaskt`). Querying a
 * breach catalogue for "bigbaskt" returns nothing, and reporting that as "no
 * breaches found" hands the reader reassurance that was never established —
 * the same three-state failure as treating an unreachable source as a clean one.
 */
export function isUsableDomain(input: string): boolean {
  const host = input.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0] ?? "";
  // Needs at least one dot and a plausible TLD; a bare label is a name.
  return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$/.test(host);
}

/** Registrable-ish root, so `www.acme.com` and `acme.com` query the same thing. */
export function breachDomainFor(input: string): string {
  const host = input.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0]!.replace(/\.$/, "");
  const parts = host.split(".");
  return parts.length <= 2 ? host : parts.slice(-2).join(".");
}

/** Maps a raw HIBP record onto this engine's shape. */
export function toBreachRecord(b: HibpBreach): BreachRecord {
  const dataClasses = (b.DataClasses ?? []).map(String);
  return {
    name: String(b.Name ?? ""),
    title: String(b.Title ?? b.Name ?? ""),
    domain: String(b.Domain ?? ""),
    breachDate: String(b.BreachDate ?? ""),
    addedDate: b.AddedDate,
    pwnCount: Number(b.PwnCount ?? 0),
    dataClasses,
    verified: b.IsVerified === true,
    fabricated: b.IsFabricated === true,
    spamList: b.IsSpamList === true,
    stealerLog: b.IsStealerLog === true,
    malware: b.IsMalware === true,
    exposedCredentials: dataClasses.some((c) => CREDENTIAL_CLASSES.includes(c.toLowerCase())),
  };
}

/**
 * Checks the public breach corpus for records naming this domain.
 *
 * Never throws: a corpus outage must not fail a scan, and it must not be
 * recorded as a clean result either.
 */
export async function checkBreachExposure(domain: string): Promise<BreachExposureResult> {
  const target = breachDomainFor(domain);

  const result: BreachExposureResult = {
    domain: target,
    confirmed: [],
    unverified: [],
    fabricated: [],
    notCovered: [
      "Accounts at this domain that appear in OTHER organisations' breaches. That is HIBP's domain-search feature, which requires a paid subscription and proof of domain ownership because it enumerates individuals.",
      "Dark-web forums, marketplaces and paste sites. Those require Tor access and, in most cases, vetted membership; this check reads only the public clearnet breach catalogue.",
    ],
    unavailable: false,
  };

  if (!target || !isUsableDomain(target)) {
    // Not an outage — there is simply nothing to ask. Flagged so the finding
    // says "no domain configured" rather than "no breaches found".
    result.unavailable = true;
    result.unavailableReason = "no-domain";
    result.notCovered.unshift(
      `"${domain}" is not a domain name, so the breach catalogue could not be queried. Set the workspace's domain to enable this check.`,
    );
    return result;
  }

  try {
    const res = await stealthFetch(
      `${HIBP_BREACHES_URL}?Domain=${encodeURIComponent(target)}`,
      { headers: { "User-Agent": USER_AGENT, accept: "application/json" } },
      REQUEST_TIMEOUT_MS,
    );

    // 404 is HIBP's documented "no breach for this domain" answer, which is a
    // real result rather than a failure.
    if (res.status === 404) return result;

    if (!res.ok) {
      log.warn({ status: res.status, domain: target }, "Breach corpus query failed");
      result.unavailable = true;
      result.unavailableReason = "corpus-unreachable";
      return result;
    }

    const body = (await res.json()) as unknown;
    if (!Array.isArray(body)) {
      result.unavailable = true;
      result.unavailableReason = "corpus-unreachable";
      return result;
    }

    for (const raw of body) {
      const rec = toBreachRecord(raw as HibpBreach);
      if (!rec.name) continue;
      if (rec.fabricated) result.fabricated.push(rec);
      else if (rec.verified) result.confirmed.push(rec);
      else result.unverified.push(rec);
    }

    // Most recent first: a 2024 breach is more actionable than a 2013 one.
    const byDate = (a: BreachRecord, b: BreachRecord) => (b.breachDate ?? "").localeCompare(a.breachDate ?? "");
    result.confirmed.sort(byDate);
    result.unverified.sort(byDate);
  } catch (err) {
    log.warn({ err, domain: target }, "Breach corpus unreachable");
    result.unavailable = true;
    result.unavailableReason = "corpus-unreachable";
  }

  return result;
}

export interface BreachFinding {
  title: string;
  description: string;
  severity: "high" | "medium" | "low" | "info";
  category: string;
  affectedAsset: string;
  cvssScore: string;
  remediation: string;
  evidence: Record<string, unknown>;
}

/** Band-representative scores; the precise risk depends on data this cannot see. */
const BAND_SCORE: Record<BreachFinding["severity"], string> = {
  high: "7.5",
  medium: "5.3",
  low: "3.7",
  info: "0.0",
};

/**
 * Renders the result as findings.
 *
 * One finding for the confirmed set and one for the unverified set, rather than
 * one per breach: they are a single piece of work for one person, and a row per
 * historical incident would bury a current problem under a decade of history.
 */
export function buildBreachFindings(domain: string, result: BreachExposureResult): BreachFinding[] {
  const findings: BreachFinding[] = [];

  if (result.confirmed.length > 0) {
    const withCreds = result.confirmed.filter((b) => b.exposedCredentials);
    const stealer = result.confirmed.filter((b) => b.stealerLog);
    const total = result.confirmed.reduce((n, b) => n + b.pwnCount, 0);
    const names = result.confirmed.map((b) => `${b.title} (${b.breachDate?.slice(0, 4) || "date unknown"})`);

    // Credential exposure is the line that matters: an email-only breach is a
    // phishing input, a password breach is a credential-stuffing input.
    const severity: BreachFinding["severity"] = withCreds.length > 0 ? "high" : "medium";

    findings.push({
      title: `${domain} appears in ${result.confirmed.length} confirmed public breach record${result.confirmed.length === 1 ? "" : "s"}`,
      description:
        `The public breach corpus names ${domain} as the breached organisation in ${result.confirmed.length} verified ` +
        `record${result.confirmed.length === 1 ? "" : "s"}, covering roughly ${formatCount(total)} accounts in total: ` +
        `${names.slice(0, 6).join("; ")}${names.length > 6 ? `; and ${names.length - 6} more` : ""}. ` +
        (withCreds.length > 0
          ? `${withCreds.length} of these exposed credentials or financial data, which is the material fact: those accounts are credential-stuffing inputs against every other service the same people use. `
          : `None of these records lists credentials among the exposed data, so the practical risk is targeted phishing rather than account takeover. `) +
        (stealer.length > 0
          ? `${stealer.length} originated from infostealer malware rather than a server-side compromise, which points at infected endpoints rather than at your application. `
          : "") +
        `This describes historical incidents already in the public record; it does not indicate a current, ongoing compromise.`,
      severity,
      category: "data_leak",
      affectedAsset: domain,
      cvssScore: BAND_SCORE[severity],
      remediation:
        (withCreds.length > 0
          ? "Force a password reset for any account that has not changed credentials since the most recent of these dates, and enforce multi-factor authentication so a leaked password alone is not sufficient. "
          : "Brief staff that their addresses are publicly associated with this organisation and are likely phishing targets. ") +
        "Where a breach is attributed to infostealer malware, the remediation is endpoint cleanup, not an application fix.",
      evidence: {
        source: "HaveIBeenPwned public breach corpus (keyless metadata endpoint)",
        domain,
        totalAccounts: total,
        breaches: result.confirmed,
        notCovered: result.notCovered,
      },
    });
  }

  if (result.unverified.length > 0) {
    findings.push({
      title: `${domain} appears in ${result.unverified.length} unverified breach record${result.unverified.length === 1 ? "" : "s"}`,
      description:
        `${result.unverified.length} record${result.unverified.length === 1 ? "" : "s"} in the public corpus name ${domain}, ` +
        `but the corpus maintainer has not been able to confirm ${result.unverified.length === 1 ? "it is" : "they are"} genuine: ` +
        `${result.unverified.map((b) => b.title).slice(0, 5).join(", ")}. ` +
        `Unverified data circulates and is sometimes recycled or invented, so this is reported as a lead to check rather than as an established exposure.`,
      severity: "low",
      category: "data_leak",
      affectedAsset: domain,
      cvssScore: BAND_SCORE.low,
      remediation:
        "Treat as a lead. If the data is genuine you would expect internal corroboration — matching account identifiers, or a known incident on those dates. Absent that, do not act on it as fact.",
      evidence: {
        source: "HaveIBeenPwned public breach corpus",
        domain,
        breaches: result.unverified,
        note: "Unverified by the corpus maintainer.",
      },
    });
  }

  // Coverage is always stated. A clean result must not read as broader
  // assurance than this check can give.
  findings.push({
    title: result.unavailableReason === "no-domain"
      ? `No domain configured, so ${domain} was not checked against the breach corpus`
      : result.unavailable
        ? `Breach corpus could not be checked for ${domain}`
        : `Breach exposure check coverage for ${domain}`,
    description: result.unavailableReason === "no-domain"
      ? `"${domain}" is a workspace name, not a domain name, so there was nothing to ask the breach catalogue. Set the workspace's domain to enable this check. This is not a statement that the organisation appears in no breach.`
      : result.unavailable
      ? `The public breach corpus could not be reached, so no conclusion was reached about whether ${domain} appears in it. This is not a statement that it does not.`
      : `${domain} was checked against the public breach corpus` +
        (result.confirmed.length === 0 && result.unverified.length === 0 ? " and no records name it" : "") +
        `. What this check cannot see: ${result.notCovered.join(" ")}` +
        (result.fabricated.length > 0
          ? ` ${result.fabricated.length} record(s) naming this domain are flagged by the corpus as fabricated and were deliberately excluded rather than reported as exposure.`
          : ""),
    severity: "info",
    category: "data_leak",
    affectedAsset: domain,
    cvssScore: BAND_SCORE.info,
    remediation: result.unavailableReason === "no-domain"
      ? "Set the workspace's domain, then re-run this check."
      : result.unavailable
      ? "Re-run when the corpus is reachable."
      : "For per-account exposure across third-party breaches, a paid HaveIBeenPwned subscription with verified domain ownership is required — deliberately, because that data identifies individuals.",
    evidence: {
      unavailable: result.unavailable,
      notCovered: result.notCovered,
      fabricatedExcluded: result.fabricated.map((b) => b.title),
      confirmedCount: result.confirmed.length,
      unverifiedCount: result.unverified.length,
    },
  });

  return findings;
}
