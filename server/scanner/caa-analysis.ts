/**
 * CAA (Certification Authority Authorization) analysis.
 *
 * The scanner already fetched CAA records and printed them in the DNS panel.
 * It never looked at what they said, which meant the most useful thing about
 * them went unreported: whether they exist at all.
 *
 * Without a CAA record, ANY of the ~50 publicly trusted certificate authorities
 * may issue a certificate for the domain, and all of them are obliged to honour
 * a CAA record if one is present (CA/Browser Forum Baseline Requirements make
 * the check mandatory). A single CA with a weak or compromised domain-validation
 * process is therefore enough to mint a valid certificate for a domain that
 * publishes nothing — and the certificate will be trusted by every browser.
 * Publishing CAA reduces that exposure from every CA on earth to the handful
 * the organisation actually uses.
 *
 * This is not a substitute for Certificate Transparency monitoring, which
 * catches issuance after the fact; CAA is the control that prevents it.
 *
 * ── What is deliberately NOT a finding ──────────────────────────────────────
 * A missing `iodef`. It is optional, and measured against real domains it fired
 * on google.com and github.com, both of which restrict issuance properly and
 * simply do not collect violation reports. It is recorded in the posture view,
 * where it is useful, and kept out of the findings list, where it is noise.
 */

import type { VerifiedFinding } from "./constants.js";

export interface CaaRecord {
  tag: string;
  value: string;
}

export interface CaaAnalysis {
  present: boolean;
  /** CAs authorised to issue non-wildcard certificates. */
  issuers: string[];
  /** CAs authorised to issue wildcard certificates. */
  wildcardIssuers: string[];
  /** Where violation reports are sent. */
  iodef: string[];
  /** True when the policy forbids all issuance (`issue ";"`). */
  forbidsAll: boolean;
  issues: string[];
}

/** Reads the CA domain out of a CAA value, ignoring any parameters. */
function issuerOf(value: string): string {
  // RFC 8659 allows "ca.example.net; account=123"; the CA is the first field.
  return value.split(";")[0].trim().toLowerCase();
}

export function analyzeCaa(domain: string, records: CaaRecord[] | undefined): CaaAnalysis {
  const list = records ?? [];
  const issuers: string[] = [];
  const wildcardIssuers: string[] = [];
  const iodef: string[] = [];
  const issues: string[] = [];
  let forbidsAll = false;

  for (const r of list) {
    const tag = r.tag?.toLowerCase();
    const value = (r.value ?? "").trim();
    if (tag === "issue") {
      const ca = issuerOf(value);
      // `issue ";"` is the RFC 8659 way of saying "no CA may issue". It is a
      // deliberate lockdown, not an empty record.
      if (ca === "" || ca === ";") forbidsAll = true;
      else issuers.push(ca);
    } else if (tag === "issuewild") {
      const ca = issuerOf(value);
      if (ca !== "" && ca !== ";") wildcardIssuers.push(ca);
    } else if (tag === "iodef") {
      iodef.push(value);
    }
  }

  const present = list.length > 0;

  if (!present) {
    issues.push(
      `No CAA record is published for ${domain}, so any publicly trusted certificate authority may issue a certificate for it`,
    );
    return { present, issuers, wildcardIssuers, iodef, forbidsAll, issues };
  }

  if (issuers.length === 0 && !forbidsAll && wildcardIssuers.length === 0) {
    // Records exist but none of them authorise anyone or forbid anyone — most
    // often a typo'd tag, which leaves the domain in the same position as
    // publishing nothing while looking configured.
    issues.push(
      "CAA records are published but contain no issue, issuewild or iodef directive, so they authorise nothing and restrict nothing",
    );
  }

  if (iodef.length === 0) {
    issues.push(
      "CAA has no iodef directive, so a CA that is asked to issue a certificate in violation of this policy has nowhere to report it",
    );
  }

  return { present, issuers, wildcardIssuers, iodef, forbidsAll, issues };
}

/**
 * Findings for CAA state.
 *
 * A missing CAA record is graded `low`. It is a real reduction in exposure and
 * worth fixing, but it is a hardening measure rather than a live weakness —
 * grading it higher would put it above findings that represent something
 * actually broken, and severity inflation is what teaches people to ignore a
 * scanner's output.
 */
export function buildCaaFindings(domain: string, analysis: CaaAnalysis, now: string): VerifiedFinding[] {
  const missing = !analysis.present;
  // A missing iodef alone is NOT a finding. It is optional, and measured against
  // real domains it fired on google.com and github.com — both of which restrict
  // issuance perfectly well and simply do not collect violation reports.
  // Telling those two their CAA is "incomplete" is the severity inflation this
  // file's own comment warns about. It stays in `issues` for the posture view,
  // where it is useful, and out of the findings list, where it is noise.
  const authorisesNothing =
    analysis.present && analysis.issuers.length === 0 && analysis.wildcardIssuers.length === 0 && !analysis.forbidsAll;

  if (!missing && !authorisesNothing) return [];

  return [
    {
      title: missing
        ? `No CAA record restricting certificate issuance for ${domain}`
        : `CAA policy for ${domain} is incomplete`,
      description: missing
        ? `${domain} publishes no CAA record. Every publicly trusted certificate authority — roughly fifty of them — is ` +
          `therefore permitted to issue a certificate for this domain, and browsers will trust any of them. A single CA ` +
          `with a weak or subverted domain-validation process is enough to mint a valid certificate for the domain and ` +
          `impersonate it. Publishing CAA is mandatory for CAs to honour under the CA/Browser Forum Baseline ` +
          `Requirements, so it reduces that exposure from every CA on earth to the ones actually in use. Certificate ` +
          `Transparency tells you afterwards; CAA is what stops it happening.`
        : `The CAA policy for ${domain} does not fully restrict issuance: ${analysis.issues.join("; ")}.`,
      severity: "low",
      category: "certificate_authority",
      affectedAsset: domain,
      cvssScore: "3.7",
      remediation: missing
        ? `Publish CAA records naming only the CAs you use, for example: ${domain}. IN CAA 0 issue "letsencrypt.org" ` +
          `and ${domain}. IN CAA 0 iodef "mailto:security@${domain}". Add an issuewild entry if you use wildcard ` +
          `certificates, and confirm the list covers every CA your certificates are currently issued by before publishing.`
        : `Add the missing directives to the CAA record set at ${domain}, including an iodef address so violations are reported.`,
      evidence: [
        {
          type: "dns",
          description: "CAA record analysis",
          snippet:
            `Domain: ${domain}\n` +
            `CAA records: ${analysis.present ? "present" : "none"}\n` +
            `Authorised issuers: ${analysis.issuers.length ? analysis.issuers.join(", ") : "(none)"}\n` +
            `Wildcard issuers: ${analysis.wildcardIssuers.length ? analysis.wildcardIssuers.join(", ") : "(inherits issue)"}\n` +
            `Violation reporting (iodef): ${analysis.iodef.length ? analysis.iodef.join(", ") : "(none)"}\n\n` +
            `Issues:\n${analysis.issues.map((i) => `- ${i}`).join("\n")}`,
          source: "DNS CAA",
          verifiedAt: now,
        },
      ],
    },
  ];
}
