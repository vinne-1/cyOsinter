/**
 * Mail transport security: MTA-STS, TLS-RPT and BIMI.
 *
 * The engine already checked SPF, DKIM and DMARC — the three controls that
 * answer "is this mail authentic?". It checked nothing that answers "is this
 * mail encrypted in transit, and would we ever hear about it if it wasn't?".
 *
 *   MTA-STS  (RFC 8461) — tells a sending server to REFUSE to deliver over an
 *                         unencrypted or untrusted connection. Without it, SMTP
 *                         falls back to cleartext on a downgrade attack and the
 *                         mail is read in transit. SPF/DKIM/DMARC do not help:
 *                         they authenticate the message, not the channel.
 *   TLS-RPT  (RFC 8460) — asks senders to report failed TLS negotiations. This
 *                         is the only way a domain owner learns an active
 *                         downgrade is happening at all.
 *   BIMI                — displays a verified brand logo in the recipient's
 *                         inbox. Its security value is indirect but real: a
 *                         published BIMI record on a domain whose DMARC is not
 *                         at enforcement is a misconfiguration, because BIMI
 *                         requires p=quarantine or p=reject to have any effect.
 *
 * Every lookup here is a plain DNS TXT query plus one well-known HTTPS fetch —
 * no API key, no account, no rate limit to negotiate.
 *
 * ── False positives ─────────────────────────────────────────────────────────
 * These controls only mean something for a domain that actually handles mail.
 * A web-only subdomain with no MX cannot receive mail, so "missing MTA-STS" on
 * it is noise — the same discipline `buildDMARCFindings` already applies. The
 * MX gate is therefore checked before anything is reported.
 */

import type { VerifiedFinding } from "./constants.js";
import type { MailContext } from "./osint-email-dns.js";

/** Minimal HTTP shape needed here; injected so this module stays testable. */
export type PolicyFetcher = (
  url: string,
) => Promise<{ status: number; body: string; headers?: Record<string, string> } | null>;

export interface MtaStsPolicy {
  /** TXT record at _mta-sts.<domain>, when present. */
  record?: string;
  /** Policy id from the TXT record. */
  id?: string;
  /** Body of https://mta-sts.<domain>/.well-known/mta-sts.txt, when reachable. */
  policyBody?: string;
  /** enforce | testing | none, parsed from the policy file. */
  mode?: string;
  /** MX patterns the policy authorises. */
  mx: string[];
  maxAge?: number;
  /** Problems found in the record or the policy file. */
  issues: string[];
}

export interface TlsRptPolicy {
  record?: string;
  /** Report destinations (mailto: or https:). */
  rua: string[];
  issues: string[];
}

export interface BimiPolicy {
  record?: string;
  /** Logo SVG URL (`l=`). */
  logoUrl?: string;
  /** Verified Mark Certificate URL (`a=`). */
  vmcUrl?: string;
  issues: string[];
}

export interface MailTransportAnalysis {
  mtaSts: MtaStsPolicy;
  tlsRpt: TlsRptPolicy;
  bimi: BimiPolicy;
}

/** Joins a TXT answer's character-strings, which DNS splits at 255 bytes. */
function joinTxt(chunks: string[][]): string[] {
  return chunks.map((parts) => parts.join(""));
}

/**
 * Parses an MTA-STS policy file.
 *
 * The format is line-oriented `key: value`, and the RFC allows CRLF, so a naive
 * split on "\n" leaves a trailing carriage return on every value and makes
 * `mode` compare unequal to "enforce" for a perfectly valid policy.
 */
export function parseMtaStsPolicy(body: string): {
  version?: string;
  mode?: string;
  mx: string[];
  maxAge?: number;
} {
  const mx: string[] = [];
  let version: string | undefined;
  let mode: string | undefined;
  let maxAge: number | undefined;

  for (const rawLine of body.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const idx = line.indexOf(":");
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (key === "version") version = value;
    else if (key === "mode") mode = value.toLowerCase();
    else if (key === "mx") mx.push(value.toLowerCase());
    else if (key === "max_age") {
      const n = Number.parseInt(value, 10);
      if (Number.isFinite(n)) maxAge = n;
    }
  }
  return { version, mode, mx, maxAge };
}

/** Extracts `k=v` tags from a TXT policy record (MTA-STS, TLS-RPT, BIMI share the shape). */
function parseTags(record: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of record.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim().toLowerCase();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = v;
  }
  return out;
}

/**
 * Collects MTA-STS, TLS-RPT and BIMI state for a domain.
 *
 * `lookupTxt` and `fetchPolicy` are injected so this runs under test without
 * touching the network — the same pattern `deriveMailContext` uses.
 */
export async function analyseMailTransport(
  domain: string,
  lookupTxt: (name: string) => Promise<string[][]>,
  fetchPolicy: PolicyFetcher,
): Promise<MailTransportAnalysis> {
  const mtaSts: MtaStsPolicy = { mx: [], issues: [] };
  const tlsRpt: TlsRptPolicy = { rua: [], issues: [] };
  const bimi: BimiPolicy = { issues: [] };

  // ── MTA-STS ───────────────────────────────────────────────────────────────
  try {
    const txt = joinTxt(await lookupTxt(`_mta-sts.${domain}`));
    const record = txt.find((r) => /v\s*=\s*STSv1/i.test(r));
    if (record) {
      mtaSts.record = record;
      const tags = parseTags(record);
      mtaSts.id = tags.id;
      // Without an id a sender cannot tell that the policy changed, so it keeps
      // serving a cached copy — the record is present but functionally inert.
      if (!tags.id) mtaSts.issues.push("MTA-STS record has no policy id, so senders cannot detect policy updates");
    }
  } catch {
    /* absence is the signal; a lookup error is indistinguishable and handled below */
  }

  // The policy FILE is what actually binds. A TXT record pointing at a policy
  // that 404s means MTA-STS is advertised but not in force, which is worse than
  // not advertising it — the domain looks protected and is not.
  if (mtaSts.record) {
    const res = await fetchPolicy(`https://mta-sts.${domain}/.well-known/mta-sts.txt`).catch(() => null);
    if (!res || res.status !== 200 || !res.body) {
      mtaSts.issues.push(
        `MTA-STS is advertised in DNS but the policy file at https://mta-sts.${domain}/.well-known/mta-sts.txt is not retrievable`,
      );
    } else {
      mtaSts.policyBody = res.body;
      const parsed = parseMtaStsPolicy(res.body);
      mtaSts.mode = parsed.mode;
      mtaSts.mx = parsed.mx;
      mtaSts.maxAge = parsed.maxAge;
      if (parsed.version && !/^STSv1$/i.test(parsed.version)) {
        mtaSts.issues.push(`MTA-STS policy declares unsupported version "${parsed.version}"`);
      }
      // testing/none collect reports but never refuse a downgraded delivery.
      if (parsed.mode === "testing") {
        mtaSts.issues.push("MTA-STS policy is in testing mode, so a downgraded connection is reported but still allowed");
      } else if (parsed.mode === "none") {
        mtaSts.issues.push("MTA-STS policy mode is 'none', which disables enforcement entirely");
      } else if (parsed.mode !== "enforce") {
        mtaSts.issues.push(`MTA-STS policy has an invalid mode "${parsed.mode ?? "(absent)"}"`);
      }
      if (parsed.mx.length === 0) {
        mtaSts.issues.push("MTA-STS policy lists no mx patterns, so no sending host can validate the destination");
      }
      // RFC 8461 recommends at least a few weeks; a short max_age means the
      // policy is barely cached and offers little downgrade protection.
      if (parsed.maxAge !== undefined && parsed.maxAge < 86400) {
        mtaSts.issues.push(`MTA-STS max_age is ${parsed.maxAge}s, too short to resist a downgrade attack`);
      }
    }
  }

  // ── TLS-RPT ───────────────────────────────────────────────────────────────
  try {
    const txt = joinTxt(await lookupTxt(`_smtp._tls.${domain}`));
    const record = txt.find((r) => /v\s*=\s*TLSRPTv1/i.test(r));
    if (record) {
      tlsRpt.record = record;
      const rua = parseTags(record).rua ?? "";
      tlsRpt.rua = rua.split(",").map((s) => s.trim()).filter(Boolean);
      if (tlsRpt.rua.length === 0) {
        tlsRpt.issues.push("TLS-RPT record has no rua destination, so failure reports have nowhere to go");
      }
    }
  } catch {
    /* absent */
  }

  // ── BIMI ──────────────────────────────────────────────────────────────────
  try {
    const txt = joinTxt(await lookupTxt(`default._bimi.${domain}`));
    const record = txt.find((r) => /v\s*=\s*BIMI1/i.test(r));
    if (record) {
      bimi.record = record;
      const tags = parseTags(record);
      bimi.logoUrl = tags.l || undefined;
      bimi.vmcUrl = tags.a || undefined;
      // A BIMI record with an empty `l=` is the documented opt-out; only flag a
      // record that claims a logo it cannot serve over TLS.
      if (bimi.logoUrl && !/^https:\/\//i.test(bimi.logoUrl)) {
        bimi.issues.push("BIMI logo URL is not served over HTTPS");
      }
    }
  } catch {
    /* absent */
  }

  return { mtaSts, tlsRpt, bimi };
}

/**
 * Turns the analysis into findings.
 *
 * `dmarcPolicy` is the `p=` value of the domain's DMARC record, used only for
 * the BIMI enforcement check.
 */
export function buildMailTransportFindings(
  domain: string,
  analysis: MailTransportAnalysis,
  now: string,
  mail: MailContext,
  dmarcPolicy?: string,
): VerifiedFinding[] {
  const findings: VerifiedFinding[] = [];

  // No MX means the domain cannot receive mail, so transport controls for it are
  // not a gap. Reporting them anyway is how a scanner earns a reputation for
  // noise, which is the fastest way to get its real findings ignored.
  if (!mail.hasMx) return findings;

  const { mtaSts, tlsRpt, bimi } = analysis;

  if (!mtaSts.record) {
    findings.push({
      title: `MTA-STS not configured for ${domain}`,
      description:
        `${domain} receives mail (MX records are published) but does not publish an MTA-STS policy at _mta-sts.${domain}. ` +
        `Without MTA-STS a sending server will silently fall back to an unencrypted or unauthenticated SMTP connection when TLS ` +
        `negotiation is stripped or a forged MX is injected, so message contents and credentials can be read in transit. ` +
        `SPF, DKIM and DMARC do not mitigate this: they authenticate the message, not the connection carrying it.`,
      severity: "medium",
      category: "email_security",
      affectedAsset: domain,
      cvssScore: "5.3",
      remediation:
        `Publish a TXT record at _mta-sts.${domain} of the form "v=STSv1; id=<timestamp>", serve a policy file at ` +
        `https://mta-sts.${domain}/.well-known/mta-sts.txt listing your MX hosts, and start with "mode: testing" before ` +
        `moving to "mode: enforce" once reports show no legitimate delivery failures.`,
      evidence: [
        {
          type: "dns",
          description: `TXT lookup for _mta-sts.${domain} returned no MTA-STS policy`,
          snippet: `Query: TXT _mta-sts.${domain}\nResult: no v=STSv1 record\nMX records: present`,
          source: "DNS",
          verifiedAt: now,
        },
      ],
    });
  } else if (mtaSts.issues.length > 0) {
    // An advertised-but-broken policy is ranked above a missing one: the domain
    // presents as protected while offering no actual enforcement.
    const enforcing = mtaSts.mode === "enforce";
    findings.push({
      title: `MTA-STS policy is not enforcing for ${domain}`,
      description:
        `${domain} publishes an MTA-STS record but the policy does not provide downgrade protection: ` +
        `${mtaSts.issues.join("; ")}.`,
      severity: enforcing ? "low" : "medium",
      category: "email_security",
      affectedAsset: domain,
      cvssScore: enforcing ? "3.1" : "5.3",
      remediation:
        `Serve a reachable policy at https://mta-sts.${domain}/.well-known/mta-sts.txt with "mode: enforce", every ` +
        `MX host listed, and a max_age of at least 86400 seconds.`,
      evidence: [
        {
          type: "dns",
          description: "MTA-STS record and policy file analysis",
          snippet:
            `TXT _mta-sts.${domain}: ${mtaSts.record}\n` +
            `Policy mode: ${mtaSts.mode ?? "(unavailable)"}\n` +
            `Policy mx: ${mtaSts.mx.length ? mtaSts.mx.join(", ") : "(none)"}\n` +
            `max_age: ${mtaSts.maxAge ?? "(absent)"}\n\nIssues:\n${mtaSts.issues.map((i) => `- ${i}`).join("\n")}`,
          source: "DNS + MTA-STS policy file",
          verifiedAt: now,
        },
      ],
    });
  }

  if (!tlsRpt.record) {
    findings.push({
      title: `SMTP TLS reporting (TLS-RPT) not configured for ${domain}`,
      description:
        `${domain} does not publish a TLS-RPT record at _smtp._tls.${domain}. TLS-RPT is the mechanism by which sending ` +
        `providers report failed or downgraded TLS negotiations to the receiving domain. Without it an active downgrade ` +
        `against this domain's mail produces no signal anywhere the owner can see.`,
      severity: "low",
      category: "email_security",
      affectedAsset: domain,
      cvssScore: "2.6",
      remediation:
        `Publish a TXT record at _smtp._tls.${domain} of the form "v=TLSRPTv1; rua=mailto:tls-reports@${domain}" and ` +
        `route the resulting reports to a monitored mailbox.`,
      evidence: [
        {
          type: "dns",
          description: `TXT lookup for _smtp._tls.${domain} returned no TLS-RPT record`,
          snippet: `Query: TXT _smtp._tls.${domain}\nResult: no v=TLSRPTv1 record`,
          source: "DNS",
          verifiedAt: now,
        },
      ],
    });
  } else if (tlsRpt.issues.length > 0) {
    findings.push({
      title: `TLS-RPT record is misconfigured for ${domain}`,
      description: `The TLS-RPT record for ${domain} is present but unusable: ${tlsRpt.issues.join("; ")}.`,
      severity: "low",
      category: "email_security",
      affectedAsset: domain,
      cvssScore: "2.6",
      remediation: `Add a valid rua= destination to the TLS-RPT record at _smtp._tls.${domain}.`,
      evidence: [
        {
          type: "dns",
          description: "TLS-RPT record analysis",
          snippet: `TXT _smtp._tls.${domain}: ${tlsRpt.record}\n\nIssues:\n${tlsRpt.issues.map((i) => `- ${i}`).join("\n")}`,
          source: "DNS",
          verifiedAt: now,
        },
      ],
    });
  }

  // BIMI is only reported when it is PRESENT and broken. A domain without BIMI
  // is not less secure — flagging its absence would be a brand-marketing
  // recommendation dressed up as a security finding.
  if (bimi.record) {
    const enforced = dmarcPolicy === "quarantine" || dmarcPolicy === "reject";
    if (!enforced) {
      bimi.issues.push(
        `BIMI requires a DMARC policy of quarantine or reject; the current policy is "${dmarcPolicy ?? "none/absent"}"`,
      );
    }
    if (!bimi.vmcUrl) {
      bimi.issues.push("BIMI record has no Verified Mark Certificate (a=), so most mailbox providers will not display the logo");
    }
    if (bimi.issues.length > 0) {
      findings.push({
        title: `BIMI record is published but not effective for ${domain}`,
        description:
          `${domain} publishes a BIMI record, which signals an intent to display a verified brand logo in recipients' inboxes. ` +
          `It will not take effect: ${bimi.issues.join("; ")}. A brand logo that fails to appear where customers expect it ` +
          `weakens the visual cue they use to distinguish genuine mail from a phishing lookalike.`,
        severity: "low",
        category: "email_security",
        affectedAsset: domain,
        cvssScore: "2.6",
        remediation:
          `Move the DMARC policy at _dmarc.${domain} to p=quarantine or p=reject, and reference a Verified Mark Certificate ` +
          `with the a= tag in the BIMI record.`,
        evidence: [
          {
            type: "dns",
            description: "BIMI record analysis",
            snippet:
              `TXT default._bimi.${domain}: ${bimi.record}\n` +
              `Logo: ${bimi.logoUrl ?? "(none)"}\nVMC: ${bimi.vmcUrl ?? "(none)"}\n` +
              `DMARC policy: ${dmarcPolicy ?? "none/absent"}\n\nIssues:\n${bimi.issues.map((i) => `- ${i}`).join("\n")}`,
            source: "DNS",
            verifiedAt: now,
          },
        ],
      });
    }
  }

  return findings;
}

/**
 * The controls this domain has in place, for the posture view.
 *
 * A scanner that only ever reports problems gives no credit for work already
 * done, which makes its output read as an indictment rather than an assessment.
 */
export function mailTransportControls(analysis: MailTransportAnalysis): string[] {
  const controls: string[] = [];
  if (analysis.mtaSts.record && analysis.mtaSts.mode === "enforce") controls.push("MTA-STS");
  if (analysis.tlsRpt.record && analysis.tlsRpt.rua.length > 0) controls.push("TLS-RPT");
  if (analysis.bimi.record && analysis.bimi.vmcUrl) controls.push("BIMI");
  return controls;
}
