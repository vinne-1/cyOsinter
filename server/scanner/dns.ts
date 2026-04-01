import dns from "dns/promises";
import { createLogger } from "../logger.js";

const log = createLogger("scanner");

export async function resolveDNS(hostname: string): Promise<{ ips: string[]; cnames: string[] }> {
  const result = { ips: [] as string[], cnames: [] as string[] };
  try {
    const addresses = await dns.resolve4(hostname);
    result.ips = addresses;
  } catch (e) {
    log.warn({ err: e, hostname }, "DNS lookup failed");
  }
  try {
    const cnames = await dns.resolveCname(hostname);
    result.cnames = cnames;
  } catch (e) {
    log.warn({ err: e, hostname }, "DNS lookup failed");
  }
  return result;
}

export async function getDNSTxtRecords(domain: string): Promise<string[][]> {
  try {
    return await dns.resolveTxt(domain);
  } catch (e) {
    log.warn({ err: e, domain }, "DNS lookup failed");
    return [];
  }
}

export async function getMXRecords(domain: string): Promise<Array<{ priority: number; exchange: string }>> {
  try {
    return await dns.resolveMx(domain);
  } catch (e) {
    log.warn({ err: e, domain }, "DNS lookup failed");
    return [];
  }
}

export async function getNSRecords(domain: string): Promise<string[]> {
  try {
    return await dns.resolveNs(domain);
  } catch (e) {
    log.warn({ err: e, domain }, "DNS lookup failed");
    return [];
  }
}

export async function getFullDNSRecords(domain: string): Promise<{
  a: string[];
  aaaa: string[];
  cname: string[];
  soa: { nsname: string; hostmaster: string; serial: number; refresh: number; retry: number; expire: number; minttl: number } | null;
  txt: string[][];
  mx: Array<{ priority: number; exchange: string }>;
  ns: string[];
  caa: Array<{ tag: string; value: string }>;
}> {
  const out = { a: [] as string[], aaaa: [] as string[], cname: [] as string[], soa: null as any, txt: [] as string[][], mx: [] as Array<{ priority: number; exchange: string }>, ns: [] as string[], caa: [] as Array<{ tag: string; value: string }> };
  try { out.a = await dns.resolve4(domain); } catch (e) { log.warn({ err: e, domain }, "DNS lookup failed"); }
  try { out.aaaa = await dns.resolve6(domain); } catch (e) { log.warn({ err: e, domain }, "DNS lookup failed"); }
  try { out.cname = await dns.resolveCname(domain); } catch (e) { log.warn({ err: e, domain }, "DNS lookup failed"); }
  try { out.soa = await dns.resolveSoa(domain); } catch (e) { log.warn({ err: e, domain }, "DNS lookup failed"); }
  try { out.txt = await dns.resolveTxt(domain); } catch (e) { log.warn({ err: e, domain }, "DNS lookup failed"); }
  try { out.mx = await dns.resolveMx(domain); } catch (e) { log.warn({ err: e, domain }, "DNS lookup failed"); }
  try { out.ns = await dns.resolveNs(domain); } catch (e) { log.warn({ err: e, domain }, "DNS lookup failed"); }
  try {
    const resolveCaa = (dns as any).resolveCaa;
    if (typeof resolveCaa === "function") {
      const caa = await resolveCaa(domain);
      if (Array.isArray(caa)) out.caa = caa.map((r: { tag: string; value: string }) => ({ tag: r.tag, value: r.value }));
    }
  } catch (e) {
    log.warn({ err: e, domain }, "DNS lookup failed");
  }
  return out;
}

export function checkDNSSEC(domain: string): Promise<{ soaPresent: boolean }> {
  return dns.resolveSoa(domain).then(() => ({ soaPresent: true })).catch(() => ({ soaPresent: false }));
}

export function analyzeSPF(txtRecords: string[][]): { found: boolean; record: string; issues: string[] } {
  const spfRecords = txtRecords.flat().filter(r => r.startsWith("v=spf1"));
  if (spfRecords.length === 0) return { found: false, record: "", issues: ["No SPF record found"] };
  const record = spfRecords[0];
  const issues: string[] = [];
  if (record.includes("+all")) issues.push("SPF uses +all (allows any sender)");
  if (record.includes("?all")) issues.push("SPF uses ?all (neutral policy - no enforcement)");
  if (!record.includes("-all") && !record.includes("~all")) {
    if (!record.includes("+all") && !record.includes("?all")) {
      issues.push("SPF record may not have a restrictive -all or ~all terminator");
    }
  }
  if (spfRecords.length > 1) issues.push("Multiple SPF records found (RFC violation)");
  return { found: true, record, issues };
}

export function analyzeDMARC(txtRecords: string[][]): { found: boolean; record: string; issues: string[] } {
  const dmarcRecords = txtRecords.flat().filter(r => r.startsWith("v=DMARC1"));
  if (dmarcRecords.length === 0) return { found: false, record: "", issues: ["No DMARC record found"] };
  const record = dmarcRecords[0];
  const issues: string[] = [];
  if (record.includes("p=none")) issues.push("DMARC policy is 'none' (monitoring only, no enforcement)");
  const pctMatch = record.match(/pct=(\d+)/);
  if (pctMatch && parseInt(pctMatch[1]) < 100) issues.push(`DMARC only applies to ${pctMatch[1]}% of messages`);
  return { found: true, record, issues };
}

export function extractCloudProvidersFromSPF(spfRecord: string, mxRecords: Array<{ exchange: string }>): Array<{ provider: string; confidence: number; evidence: string[] }> {
  const providers: Array<{ provider: string; confidence: number; evidence: string[] }> = [];
  const record = (spfRecord || "").toLowerCase();
  const mxHosts = (mxRecords || []).map((m) => m.exchange?.toLowerCase() ?? "").join(" ");
  if (record.includes("include:_spf.google.com") || record.includes("include:spf.google.com") || mxHosts.includes("google")) providers.push({ provider: "Google Workspace", confidence: 90, evidence: ["SPF include or MX"] });
  if (record.includes("include:amazonses.com") || record.includes("include:spf.amazonses.com")) providers.push({ provider: "AWS SES", confidence: 95, evidence: ["SPF include"] });
  if (record.includes("include:sendgrid.net") || record.includes("include:spf.sendgrid.net")) providers.push({ provider: "SendGrid", confidence: 95, evidence: ["SPF include"] });
  if (record.includes("include:mailgun.org") || record.includes("include:spf.mailgun.org")) providers.push({ provider: "Mailgun", confidence: 95, evidence: ["SPF include"] });
  if (record.includes("include:zoho.com") || record.includes("include:spf.zoho.com")) providers.push({ provider: "Zoho", confidence: 95, evidence: ["SPF include"] });
  if (record.includes("include:outlook.com") || record.includes("include:spf.protection.outlook.com") || mxHosts.includes("outlook") || mxHosts.includes("microsoft")) providers.push({ provider: "Microsoft 365", confidence: 90, evidence: ["SPF include or MX"] });
  if (record.includes("include:spf.mailjet.com") || record.includes("include:mailjet.com")) providers.push({ provider: "Mailjet", confidence: 95, evidence: ["SPF include"] });
  if (record.includes("include:spf.mandrillapp.com") || record.includes("include:mandrillapp.com")) providers.push({ provider: "Mandrill", confidence: 95, evidence: ["SPF include"] });
  return providers;
}

export function extractEmailsFromDNS(txtRecords: string[][], dmarcTxt: string[][]): string[] {
  const emails: string[] = [];
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  // DMARC rua/ruf mailto
  for (const rec of dmarcTxt.flat()) {
    const matches = rec.match(/(?:rua|ruf)=mailto:([^;,\s]+)/gi);
    if (matches) {
      for (const m of matches) {
        const email = m.replace(/(?:rua|ruf)=mailto:/i, "");
        if (email) emails.push(email.toLowerCase());
      }
    }
  }
  // General TXT records
  for (const rec of txtRecords.flat()) {
    const matches = rec.match(emailRegex);
    if (matches) emails.push(...matches.map(e => e.toLowerCase()));
  }
  return Array.from(new Set(emails));
}
