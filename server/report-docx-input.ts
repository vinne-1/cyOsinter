import { storage } from "./storage";
import type { ReportDocxInput, ReportFinding } from "./report-docx";

/**
 * Assemble a {@link ReportDocxInput} from a workspace's stored scan data
 * (findings + recon modules). Maps the DB shapes into the report generator's
 * input, defensively (any module may be absent). Optional `images` (screenshot
 * evidence keyed by finding id) are embedded when provided.
 */

interface ReconModuleLike { moduleType: string; data: Record<string, unknown> }

function moduleData(modules: ReconModuleLike[], type: string): Record<string, unknown> | undefined {
  return modules.find((m) => m.moduleType === type)?.data;
}

/** First on-target http(s) URL found in a finding's evidence, for screenshotting. */
function firstEvidenceUrl(evidence: unknown, domain: string): string | undefined {
  if (!Array.isArray(evidence)) return undefined;
  for (const e of evidence) {
    const u = e && typeof e === "object" ? (e as Record<string, unknown>).url : undefined;
    if (typeof u === "string" && /^https?:\/\//i.test(u)) {
      try {
        const h = new URL(u).hostname;
        if (h === domain || h.endsWith(`.${domain}`)) return u;
      } catch { /* bad url */ }
    }
  }
  return undefined;
}

function evidenceToText(evidence: unknown): string | undefined {
  if (!Array.isArray(evidence)) return undefined;
  const lines = evidence
    .map((e) => (e && typeof e === "object" ? (e as Record<string, unknown>).snippet ?? (e as Record<string, unknown>).description : undefined))
    .filter((x): x is string => typeof x === "string" && x.length > 0);
  return lines.length ? lines.join("\n") : undefined;
}

export async function buildDocxInput(
  workspaceId: string,
  opts: { findingIds?: string[]; images?: Record<string, Buffer>; scanMode?: string; falsePositives?: ReportDocxInput["falsePositives"]; captureEvidence?: boolean } = {},
): Promise<ReportDocxInput> {
  const ws = await storage.getWorkspace(workspaceId);
  // The most recent (completed) scan is authoritative for the report's target
  // and mode: the workspace name may be an arbitrary label, and the scan target
  // is the domain actually scanned (e.g. a specific subdomain).
  const { data: scans } = await storage.getScans(workspaceId, { limit: 25, offset: 0 });
  const latestScan = scans.find((s) => s.status === "completed") ?? scans[0];
  const scanTarget = latestScan?.target?.trim().toLowerCase();
  const scanModeRaw = (latestScan?.summary as Record<string, unknown> | undefined)?.mode as string | undefined;
  const MODE_LABEL: Record<string, string> = {
    gold: "Gold (comprehensive, full coverage)",
    safe: "Safe / stealth (rate-limited, low-and-slow)",
    standard: "Standard (fast)",
  };
  const scanMode = opts.scanMode ?? (scanModeRaw ? (MODE_LABEL[scanModeRaw] ?? scanModeRaw) : undefined);
  const withheldCount = (latestScan?.summary as Record<string, unknown> | undefined)?.withheldCount as number | undefined;
  const target = scanTarget || ((ws as { domain?: string | null } | undefined)?.domain || ws?.name || "unknown").toLowerCase();
  const { data: allFindings } = await storage.getFindings(workspaceId, { limit: 2000, offset: 0 });
  const { data: modules } = await storage.getReconModules(workspaceId, { limit: 200, offset: 0 });
  const mods = modules as unknown as ReconModuleLike[];

  const includeAll = (opts.findingIds?.length ?? 0) === 0;
  const selected = allFindings.filter((f) => includeAll || opts.findingIds!.includes(f.id));

  // ── Recon mapping ──
  const attack = moduleData(mods, "attack_surface");
  const email = moduleData(mods, "cloud_footprint");
  const portSvc = moduleData(mods, "port_services");
  const web = moduleData(mods, "web_presence");
  const dnsOv = moduleData(mods, "dns_overview");
  const tech = moduleData(mods, "tech_stack");
  const domainInfoMod = moduleData(mods, "domain_info");
  const redirectMod = moduleData(mods, "redirect_chain");
  const websiteMod = moduleData(mods, "website_overview");
  const peopleMod = moduleData(mods, "people_exposure");

  const ips = ((attack?.dns as Record<string, unknown> | undefined)?.ips as string[] | undefined)
    ?? ((dnsOv?.dnsRecords as Record<string, unknown> | undefined)?.a as string[] | undefined) ?? [];
  const ns = ((attack?.dns as Record<string, unknown> | undefined)?.ns as string[] | undefined)
    ?? ((dnsOv?.dnsRecords as Record<string, unknown> | undefined)?.ns as string[] | undefined) ?? [];

  // Subdomains from web_presence
  const discovered = (web?.discoveredDomains as Array<{ domain: string }> | undefined)?.map((d) => d.domain) ?? [];
  const liveSubs = (web?.liveSubdomains as string[] | undefined) ?? [];
  const subdomains = Array.from(new Set([...discovered, ...liveSubs])).filter(Boolean);

  // Ports from port_services.portScan (Record<ip, [{port,service,banner}]>)
  const portScan = (portSvc?.portScan as Record<string, Array<{ port: number; service?: string; banner?: string }>> | undefined) ?? {};
  const ports = Object.values(portScan).flat();

  // Tech stack (frontend + backend)
  const techFront = (tech?.frontend as Array<{ name: string; source?: string }> | undefined) ?? [];
  const techBack = (tech?.backend as Array<{ name: string; source?: string }> | undefined) ?? [];
  const techStack = [...techFront, ...techBack];

  const em = email?.emailSecurity as Record<string, unknown> | undefined;

  // ── Previously-collected-but-dropped lookups, now surfaced ──
  // Reverse DNS (PTR): Record<ip, string[]>
  const ptr = (attack?.reverseDns as Record<string, string[]> | undefined);
  // Reverse-IP co-hosted domains: Record<ip, string[]>
  const coHostedDomains = (attack?.coHostedDomains as Record<string, string[]> | undefined);
  // People / employee exposure (keyless, org-scoped).
  const peopleList = peopleMod?.people as NonNullable<NonNullable<ReportDocxInput["recon"]>["people"]>["list"] | undefined;
  const people = peopleList && peopleList.length
    ? { emailFormat: peopleMod?.emailFormat as string | undefined, list: peopleList }
    : undefined;
  // Full DNS record set + DNSSEC from the dns_overview module.
  const dnsRecords = dnsOv?.dnsRecords as NonNullable<ReportDocxInput["recon"]>["dnsRecords"];
  const dnssec = dnsOv?.dnssec as { soaPresent?: boolean } | undefined;
  // WHOIS / domain registration.
  const whois = domainInfoMod?.domainInfo as Record<string, string> | undefined;
  // Server geolocation (from website_overview.serverLocation).
  const geo = websiteMod?.serverLocation as { country?: string; region?: string; city?: string; org?: string } | undefined;
  // Redirect chain.
  const redirectChain = redirectMod?.redirectChain as Array<{ status: number; url: string; location?: string }> | undefined;
  // IP reputation: flatten threatIntel Record<ip,{abuseipdb,virustotal,bgp}> → rows.
  const threat = attack?.ipReputation as Record<string, { abuseipdb?: Record<string, unknown> | null; virustotal?: Record<string, unknown> | null; bgp?: Record<string, unknown> | null }> | undefined;
  const ipReputation = threat
    ? Object.entries(threat).map(([ip, t]) => {
        const abuse = t.abuseipdb as { abuseConfidenceScore?: number; totalReports?: number; isp?: string; countryName?: string } | null | undefined;
        const vt = t.virustotal as { malicious?: number; as_owner?: string; country?: string } | null | undefined;
        const bgp = t.bgp as { prefixes?: Array<{ asn?: { asn?: number; name?: string; country_code?: string } }>; maxmind?: { city?: string | null; country_code?: string }; ptr_record?: string | null } | null | undefined;
        const asnObj = bgp?.prefixes?.[0]?.asn;
        return {
          ip,
          abuseScore: abuse?.abuseConfidenceScore,
          totalReports: abuse?.totalReports,
          vtMalicious: vt?.malicious,
          asn: asnObj?.asn,
          asnName: asnObj?.name ?? vt?.as_owner,
          isp: abuse?.isp,
          country: abuse?.countryName ?? vt?.country ?? bgp?.maxmind?.country_code,
          city: bgp?.maxmind?.city ?? undefined,
          ptr: bgp?.ptr_record ?? ptr?.[ip]?.[0],
        };
      }).filter((r) => r.abuseScore != null || r.vtMalicious != null || r.asn != null || r.ptr)
    : undefined;

  // Optionally capture live screenshot evidence, keyed per finding, so EVERY
  // finding is illustrated (fail-soft — no browser ⇒ text-only report).
  const images: Record<string, Buffer> = { ...(opts.images ?? {}) };
  if (opts.captureEvidence) {
    try {
      const { captureEvidence } = await import("./evidence/screenshot-service.js");
      const evFindings = selected.map((f) => ({
        id: f.id,
        category: f.category,
        title: f.title,
        affectedAsset: f.affectedAsset ?? undefined,
        evidenceUrl: firstEvidenceUrl(f.evidence, target),
      }));
      const shots = await captureEvidence(target, evFindings, { ip: ips[0] });
      for (const [id, buf] of Object.entries(shots)) if (!images[id]) images[id] = buf;
    } catch {
      /* evidence best-effort */
    }
  }

  const findings: ReportFinding[] = selected.map((f) => ({
    title: f.title,
    severity: f.severity,
    category: f.category,
    affectedAsset: f.affectedAsset ?? target,
    description: f.description,
    cvssScore: f.cvssScore ?? undefined,
    remediation: f.remediation ?? undefined,
    evidenceText: evidenceToText(f.evidence),
    evidenceImageKey: images[f.id] ? f.id : undefined,
  }));

  return {
    target,
    org: ws?.name ?? target,
    ipAddress: ips[0],
    generatedAt: new Date().toISOString(),
    scanMode,
    recon: {
      ips,
      ns,
      ptr,
      subdomains,
      ssl: attack?.ssl as NonNullable<ReportDocxInput["recon"]>["ssl"],
      emailSecurity: em ? {
        spf: em.spf as { found?: boolean; record?: string } | undefined,
        dmarc: em.dmarc as { found?: boolean; record?: string } | undefined,
        dkim: em.dkim as { found?: boolean; selector?: string; record?: string } | undefined,
        mx: em.mx as Array<{ exchange: string }> | undefined,
      } : undefined,
      ports: ports.length ? ports : undefined,
      techStack: techStack.length ? techStack : undefined,
      dnsRecords,
      dnssec,
      whois,
      ipReputation: ipReputation && ipReputation.length ? ipReputation : undefined,
      geo,
      redirectChain: redirectChain && redirectChain.length ? redirectChain : undefined,
      coHostedDomains: coHostedDomains && Object.keys(coHostedDomains).length ? coHostedDomains : undefined,
      people,
    },
    findings,
    falsePositives: opts.falsePositives,
    images: Object.keys(images).length ? images : undefined,
    withheldCount,
  };
}
