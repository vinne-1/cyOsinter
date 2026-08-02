import dns from "dns/promises";
import { createLogger } from "../logger.js";

const log = createLogger("scanner");

// Query public resolvers rather than the host's default DNS. Some environments
// (and flaky/Cloudflare-fronted zones) return ETIMEOUT/ESERVFAIL from the local
// resolver for names that public resolvers answer fine — which silently caused
// real subdomains (e.g. mail., autodiscover.) to be missed during enumeration
// and left dns_overview empty. 1.1.1.1 + 8.8.8.8 are fast and authoritative.
const PUBLIC_DNS_SERVERS = ["1.1.1.1", "8.8.8.8"];

function makeResolver(timeout: number, tries: number): dns.Resolver {
  const r = new dns.Resolver({ timeout, tries });
  try {
    r.setServers(PUBLIC_DNS_SERVERS);
  } catch {
    /* keep system defaults if setServers is unavailable */
  }
  return r;
}

// Fast, bounded resolver for the subdomain-bruteforce hot path. Short timeout
// keeps thousands of non-existent names from stalling gold scans; 2 tries
// recovers real subdomains that would otherwise be dropped on a single
// transient timeout (public DNS answers NXDOMAIN quickly, so the retry cost
// only applies to the rare genuine timeout, not to every miss).
const fastResolver = makeResolver(2500, 2);

// More forgiving resolver for authoritative record lookups (A/MX/NS/TXT/SOA/CAA)
// where completeness matters more than raw speed.
const recordResolver = makeResolver(5000, 2);

export async function resolveDNS(hostname: string): Promise<{ ips: string[]; cnames: string[] }> {
  const result = { ips: [] as string[], cnames: [] as string[] };
  // Resolve A and CNAME concurrently — they are independent, so serializing
  // them doubled per-host latency across the whole wordlist.
  const [a, c] = await Promise.allSettled([
    fastResolver.resolve4(hostname),
    fastResolver.resolveCname(hostname),
  ]);
  if (a.status === "fulfilled") result.ips = a.value;
  if (c.status === "fulfilled") result.cnames = c.value;
  // Non-existent names are the overwhelmingly common case during bruteforce;
  // logging each failure floods the logs and adds no signal, so stay silent.
  return result;
}

export async function getDNSTxtRecords(domain: string): Promise<string[][]> {
  try {
    return await recordResolver.resolveTxt(domain);
  } catch (e) {
    log.warn({ err: e, domain }, "DNS lookup failed");
    return [];
  }
}

export async function getMXRecords(domain: string): Promise<Array<{ priority: number; exchange: string }>> {
  try {
    return await recordResolver.resolveMx(domain);
  } catch (e) {
    log.warn({ err: e, domain }, "DNS lookup failed");
    return [];
  }
}

export async function getNSRecords(domain: string): Promise<string[]> {
  try {
    return await recordResolver.resolveNs(domain);
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
  try { out.a = await recordResolver.resolve4(domain); } catch (e) { log.warn({ err: e, domain }, "DNS lookup failed"); }
  try { out.aaaa = await recordResolver.resolve6(domain); } catch (e) { log.warn({ err: e, domain }, "DNS lookup failed"); }
  try { out.cname = await recordResolver.resolveCname(domain); } catch (e) { log.warn({ err: e, domain }, "DNS lookup failed"); }
  try { out.soa = await recordResolver.resolveSoa(domain); } catch (e) { log.warn({ err: e, domain }, "DNS lookup failed"); }
  try { out.txt = await recordResolver.resolveTxt(domain); } catch (e) { log.warn({ err: e, domain }, "DNS lookup failed"); }
  try { out.mx = await recordResolver.resolveMx(domain); } catch (e) { log.warn({ err: e, domain }, "DNS lookup failed"); }
  try { out.ns = await recordResolver.resolveNs(domain); } catch (e) { log.warn({ err: e, domain }, "DNS lookup failed"); }
  try {
    const resolveCaa = (recordResolver as any).resolveCaa?.bind(recordResolver);
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
  return recordResolver.resolveSoa(domain).then(() => ({ soaPresent: true })).catch(() => ({ soaPresent: false }));
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
