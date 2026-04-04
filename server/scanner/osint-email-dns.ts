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
 * Generate findings for SPF record issues.
 */
export function buildSPFFindings(
  domain: string,
  spfAnalysis: SPFAnalysis,
  txtRecords: string[][],
  now: string,
): VerifiedFinding[] {
  const findings: VerifiedFinding[] = [];

  if (!spfAnalysis.found) {
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
): VerifiedFinding[] {
  const findings: VerifiedFinding[] = [];

  if (!dmarcAnalysis.found) {
    findings.push({
      title: `No DMARC Record Found for ${domain}`,
      description: `The domain ${domain} does not have a DMARC (Domain-based Message Authentication) DNS record at _dmarc.${domain}. Without DMARC, there is no policy to handle emails that fail SPF/DKIM checks.`,
      severity: "medium",
      category: "dns_misconfiguration",
      affectedAsset: domain,
      cvssScore: "5.3",
      remediation: `Add a DMARC TXT record at _dmarc.${domain} with at least a 'p=quarantine' policy.`,
      evidence: [{
        type: "dns_query",
        description: "DNS TXT record lookup for _dmarc subdomain returned no DMARC record",
        snippet: `Domain: _dmarc.${domain}\nQuery: TXT records\nDMARC Record: Not Found`,
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
