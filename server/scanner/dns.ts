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
//
// Exported (not just the functions below) so a caller that needs its OWN
// error-classification logic — e.g. `ai-follow-up.ts` distinguishing "did not
// answer" from "answered with no records", which `getDNSTxtRecords` below
// collapses into a single `[]` — can still use the same hardened public
// resolvers instead of falling back to the OS default (see the module
// comment above on why that matters: it returns ETIMEOUT/ESERVFAIL for names
// public resolvers answer fine).
export const recordResolver = makeResolver(5000, 2);

export interface ResolvedHost {
  /** IPv4 addresses. */
  ips: string[];
  /** IPv6 addresses. A host may have these and no A record at all. */
  ipv6: string[];
  cnames: string[];
  /**
   * Whether the name exists. Computed HERE rather than by each caller.
   *
   * Six call sites open-coded `ips.length === 0 && cnames.length === 0`, so
   * adding IPv6 meant six chances to forget one — and a caller added later would
   * inherit the old, IPv4-only meaning of "live" by default.
   */
  resolved: boolean;
}

/**
 * Resolves a hostname across A, AAAA and CNAME.
 *
 * **AAAA was missing.** This function backs every discovery path — the wordlist
 * bruteforce, permutation, and certificate-SAN validation — and it asked only
 * for A and CNAME. A host published solely on IPv6 therefore resolved to nothing
 * and was discarded as non-existent, so an entire class of asset (increasingly
 * ordinary: cloud load balancers, modern ingress, v6-only estates) was invisible
 * to discovery.
 *
 * The inconsistency was visible inside this codebase: `isPrivateHost` checks
 * both A and AAAA precisely because ignoring AAAA there was a security hole,
 * while discovery ignored it and silently lost assets.
 *
 * All three queries run concurrently, so this costs one more DNS query per host
 * but no additional latency.
 */
export async function resolveDNS(hostname: string): Promise<ResolvedHost> {
  const result: ResolvedHost = { ips: [], ipv6: [], cnames: [], resolved: false };
  const [a, aaaa, c] = await Promise.allSettled([
    fastResolver.resolve4(hostname),
    fastResolver.resolve6(hostname),
    fastResolver.resolveCname(hostname),
  ]);
  if (a.status === "fulfilled") result.ips = a.value;
  if (aaaa.status === "fulfilled") result.ipv6 = aaaa.value;
  if (c.status === "fulfilled") result.cnames = c.value;
  result.resolved = result.ips.length > 0 || result.ipv6.length > 0 || result.cnames.length > 0;
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

/**
 * SRV lookup on the shared record resolver, so SRV discovery inherits the same
 * timeout and retry budget as every other record type instead of using node's
 * default resolver with its much longer timeout.
 */
export async function getSRVRecords(
  name: string,
): Promise<Array<{ priority: number; weight: number; port: number; name: string }>> {
  return recordResolver.resolveSrv(name);
}

// checkDNSSEC used to live here. It resolved an SOA record — which every
// resolvable domain has — and callers reported the result as "zone signed".
// Real DNSSEC detection needs DNSKEY/DS records and the AD flag, none of which
// node's resolver can ask for; see scanner/dnssec.ts.



// analyzeSPF and analyzeDMARC used to live here. Both were string matches on
// the record text, which cannot see the failures that matter: an SPF record
// over the RFC 7208 ten-lookup budget is a permerror and therefore NO SPF at
// all, and DMARC's sp=none subdomain bypass is invisible to a `p=` check.
// Replaced by scanner/spf-dmarc-deep.ts, and deleted rather than left in place
// because a second implementation of the same idea is exactly how the nuclei
// classifier and VerifiedFinding copies drifted from the originals.
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
