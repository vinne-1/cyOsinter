/**
 * DNS/Email analysis for OSINT scans.
 *
 * Extracted from osint-scan.ts to keep the main scan orchestrator lean.
 * Handles SPF/DMARC finding generation and email harvesting.
 */

import type { VerifiedFinding } from "./constants.js";

interface SPFAnalysis {
  found: boolean;
  record: string;
  issues: string[];
}

interface DMARCAnalysis {
  found: boolean;
  record: string;
  issues: string[];
}

/**
 * Mail-context signals that determine whether a missing SPF/DMARC record is a
 * material spoofing risk. A web-only subdomain with no MX whose organizational
 * domain already publishes DMARC is effectively covered and should not be flagged
 * (or only informationally), which is where SPF/DMARC false positives come from.
 */
export interface MailContext {
  /** MX records for the domain (empty ⇒ the host is not a mail domain). */
  hasMx?: boolean;
  /** True when `domain` is a subdomain (not the registrable/organizational apex). */
  isSubdomain?: boolean;
  /** True when the organizational (parent) domain publishes a DMARC record. */
  orgDmarcFound?: boolean;
}

/**
 * Derive the mail context for a domain: whether it has MX, whether it is a subdomain,
 * and whether its organizational (parent) domain publishes DMARC. Used to suppress /
 * downgrade SPF/DMARC findings that are false positives on non-mail subdomains.
 *
 * `lookupTxt` is injected so this module stays free of a direct DNS dependency.
 */
export async function deriveMailContext(
  domain: string,
  mxRecords: Array<{ exchange: string }> | undefined,
  lookupTxt: (name: string) => Promise<string[][]>,
): Promise<MailContext> {
  const labels = domain.split(".").filter(Boolean);
  // Heuristic apex detection: 2 labels ⇒ apex. Multipart TLDs (co.uk) may be
  // misclassified, but the hasMx/orgDmarc gates keep that harmless (a real apex has MX).
  const isSubdomain = labels.length > 2;
  let orgDmarcFound = false;
  if (isSubdomain) {
    const parent = labels.slice(1).join(".");
    try {
      const txt = await lookupTxt(`_dmarc.${parent}`);
      orgDmarcFound = txt.flat().some((r) => /v=DMARC1/i.test(r));
    } catch {
      /* parent lookup best-effort */
    }
  }
  return { hasMx: (mxRecords?.length ?? 0) > 0, isSubdomain, orgDmarcFound };
}

/**
 * Generate findings for SPF record issues.
 */
export function buildSPFFindings(
  domain: string,
  spfAnalysis: SPFAnalysis,
  txtRecords: string[][],
  now: string,
  mail: MailContext = {},
): VerifiedFinding[] {
  const findings: VerifiedFinding[] = [];

  if (!spfAnalysis.found) {
    // A missing SPF record on a host that neither receives (no MX) nor is the
    // organizational apex is low-value: spoofing of a non-mail subdomain is already
    // constrained by the org domain's DMARC policy. Downgrade rather than cry medium.
    const nonMailSubdomain = mail.isSubdomain === true && mail.hasMx === false;
    if (nonMailSubdomain) {
      findings.push({
        title: `No SPF Record on Non-Mail Subdomain ${domain}`,
        description: `${domain} has no SPF record. This subdomain has no MX records and does not appear to send or receive mail, so the practical spoofing risk is limited${mail.orgDmarcFound ? " and the organizational domain already publishes a DMARC policy that governs its subdomains" : ""}. Publishing an explicit "v=spf1 -all" record is still recommended as defence-in-depth.`,
        severity: "info",
        category: "dns_misconfiguration",
        affectedAsset: domain,
        cvssScore: "1.0",
        remediation: `Optionally add a hard-fail SPF record ("v=spf1 -all") to ${domain} to explicitly disallow mail from this non-sending host.`,
        evidence: [{
          type: "dns_query",
          description: "DNS TXT/MX lookup: no SPF and no MX on this host",
          snippet: `Domain: ${domain}\nSPF Record: Not Found\nMX Records: none\nOrg DMARC present: ${mail.orgDmarcFound ? "yes" : "unknown"}`,
          source: "DNS TXT/MX record lookup",
          verifiedAt: now,
        }],
      });
      return findings;
    }
    findings.push({
      title: `No SPF Record Found for ${domain}`,
      description: `The domain ${domain} does not have an SPF (Sender Policy Framework) DNS record. This means any server can send emails claiming to be from ${domain}, enabling email spoofing attacks.`,
      severity: "medium",
      category: "dns_misconfiguration",
      affectedAsset: domain,
      cvssScore: "5.3",
      remediation: "Add an SPF TXT record to the domain's DNS configuration to specify authorized email senders.",
      evidence: [{
        type: "dns_query",
        description: "DNS TXT record lookup returned no SPF record",
        snippet: `Domain: ${domain}\nQuery: TXT records\nSPF Record: Not Found\n\nAll TXT records found:\n${txtRecords.flat().length > 0 ? txtRecords.flat().join("\n") : "(none)"}`,
        source: "DNS TXT record lookup",
        verifiedAt: now,
      }],
    });
  } else if (spfAnalysis.issues.length > 0) {
    findings.push({
      title: `SPF Record Issues for ${domain}`,
      description: `The SPF record for ${domain} has configuration issues that may weaken email authentication: ${spfAnalysis.issues.join("; ")}.`,
      severity: spfAnalysis.record.includes("+all") ? "high" : "low",
      category: "dns_misconfiguration",
      affectedAsset: domain,
      cvssScore: spfAnalysis.record.includes("+all") ? "7.1" : "3.5",
      remediation: "Update the SPF record to use '-all' or '~all' to restrict unauthorized senders.",
      evidence: [{
        type: "dns_query",
        description: "SPF record analysis",
        snippet: `Domain: ${domain}\nSPF Record: ${spfAnalysis.record}\n\nIssues:\n${spfAnalysis.issues.map(i => `- ${i}`).join("\n")}`,
        source: "DNS TXT record lookup",
        verifiedAt: now,
      }],
    });
  }

  return findings;
}

/**
 * Generate findings for DMARC record issues.
 */
export function buildDMARCFindings(
  domain: string,
  dmarcAnalysis: DMARCAnalysis,
  now: string,
  mail: MailContext = {},
): VerifiedFinding[] {
  const findings: VerifiedFinding[] = [];

  if (!dmarcAnalysis.found) {
    // DMARC is published at the organizational domain and applies to its subdomains
    // (via the `sp` tag / policy inheritance). If the parent domain already publishes
    // DMARC, a subdomain lacking its own _dmarc record is NOT a finding — reporting it
    // is a false positive. Suppress it entirely.
    if (mail.isSubdomain === true && mail.orgDmarcFound === true) {
      return findings;
    }
    // Non-mail subdomain with no parent DMARC signal: informational, not medium.
    const lowValue = mail.isSubdomain === true && mail.hasMx === false;
    findings.push({
      title: `No DMARC Record Found for ${domain}`,
      description: `The domain ${domain} does not have a DMARC (Domain-based Message Authentication) DNS record at _dmarc.${domain}. Without DMARC, there is no policy to handle emails that fail SPF/DKIM checks.${lowValue ? " Note: this is a non-mail subdomain; the organizational domain's DMARC policy typically governs it." : ""}`,
      severity: lowValue ? "info" : "medium",
      category: "dns_misconfiguration",
      affectedAsset: domain,
      cvssScore: lowValue ? "1.0" : "5.3",
      remediation: `Add a DMARC TXT record at _dmarc.${domain} with at least a 'p=quarantine' policy${lowValue ? ", or rely on the organizational domain's policy with an appropriate 'sp' tag" : ""}.`,
      evidence: [{
        type: "dns_query",
        description: "DNS TXT record lookup for _dmarc subdomain returned no DMARC record",
        snippet: `Domain: _dmarc.${domain}\nQuery: TXT records\nDMARC Record: Not Found\nMX Records: ${mail.hasMx ? "present" : "none"}\nOrg DMARC present: ${mail.orgDmarcFound ? "yes" : "no/unknown"}`,
        source: "DNS TXT record lookup",
        verifiedAt: now,
      }],
    });
  } else if (dmarcAnalysis.issues.length > 0) {
    findings.push({
      title: `DMARC Policy Weakness for ${domain}`,
      description: `The DMARC record for ${domain} has a weak configuration: ${dmarcAnalysis.issues.join("; ")}.`,
      severity: "low",
      category: "dns_misconfiguration",
      affectedAsset: domain,
      cvssScore: "3.5",
      remediation: "Update the DMARC policy to 'quarantine' or 'reject' and set pct=100.",
      evidence: [{
        type: "dns_query",
        description: "DMARC record analysis",
        snippet: `Domain: _dmarc.${domain}\nDMARC Record: ${dmarcAnalysis.record}\n\nIssues:\n${dmarcAnalysis.issues.map(i => `- ${i}`).join("\n")}`,
        source: "DNS TXT record lookup",
        verifiedAt: now,
      }],
    });
  }

  return findings;
}

/**
 * Build email findings and return both the findings and domainEmails map.
 */
export function processHarvestedEmails(
  domain: string,
  emailSources: Map<string, Set<string>>,
  now: string,
): { findings: VerifiedFinding[]; domainEmails: Map<string, Set<string>> } {
  const findings: VerifiedFinding[] = [];

  const domainEmails = new Map<string, Set<string>>();
  const otherEmails: string[] = [];
  for (const [email, sources] of Array.from(emailSources)) {
    if (email.endsWith(`@${domain}`) || email.endsWith(`.${domain}`)) {
      domainEmails.set(email, sources);
    } else {
      otherEmails.push(email);
    }
  }

  if (domainEmails.size > 0) {
    const sourceGroups = new Map<string, string[]>();
    for (const [email, sources] of Array.from(domainEmails)) {
      const redacted = `${email.split("@")[0].slice(0, 2)}***@${email.split("@")[1]}`;
      for (const src of Array.from(sources)) {
        if (!sourceGroups.has(src)) sourceGroups.set(src, []);
        sourceGroups.get(src)!.push(redacted);
      }
    }
    const sourceLines = Array.from(sourceGroups.entries())
      .map(([src, emails]) => `${src}: ${emails.slice(0, 3).join(", ")}${emails.length > 3 ? ` (+${emails.length - 3} more)` : ""}`)
      .join("\n");
    findings.push({
      title: `Discovered ${domainEmails.size} email address(es) for ${domain}`,
      description: `Email addresses associated with ${domain} were found across ${sourceGroups.size} source(s).`,
      severity: "info",
      category: "osint_exposure",
      affectedAsset: domain,
      cvssScore: "2.0",
      remediation: "Consider whether exposed emails should be public. Use contact forms instead of raw email addresses where possible.",
      evidence: [{
        type: "osint",
        description: "Email addresses discovered from public sources",
        snippet: `Found ${domainEmails.size} email(s) from ${sourceGroups.size} source(s):\n${sourceLines}`,
        source: Array.from(sourceGroups.keys()).join(", "),
        verifiedAt: now,
      }],
    });
  }

  if (otherEmails.length > 0) {
    findings.push({
      title: `WHOIS/DNS Contact Emails Discovered for ${domain}`,
      description: `${otherEmails.length} contact email(s) not matching the target domain were found in WHOIS or DNS records.`,
      severity: "info",
      category: "osint_exposure",
      affectedAsset: domain,
      cvssScore: "2.0",
      remediation: "Review WHOIS privacy settings. Consider using domain privacy protection.",
      evidence: [{
        type: "osint",
        description: "Non-domain contact emails from WHOIS/DNS",
        snippet: `Contact emails: ${otherEmails.slice(0, 5).join(", ")}${otherEmails.length > 5 ? ` (+${otherEmails.length - 5} more)` : ""}`,
        source: "WHOIS lookup, DNS records",
        verifiedAt: now,
      }],
    });
  }

  return { findings, domainEmails };
}
