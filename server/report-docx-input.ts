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
  // Prefer the explicit scan target domain; fall back to the workspace name.
  const target = ((ws as { domain?: string | null } | undefined)?.domain || ws?.name || "unknown").toLowerCase();
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
    scanMode: opts.scanMode,
    recon: {
      ips,
      ns,
      subdomains,
      ssl: attack?.ssl as NonNullable<ReportDocxInput["recon"]>["ssl"],
      emailSecurity: em ? {
        spf: em.spf as { found?: boolean; record?: string } | undefined,
        dmarc: em.dmarc as { found?: boolean; record?: string } | undefined,
        dkim: em.dkim as { found?: boolean } | undefined,
        mx: em.mx as Array<{ exchange: string }> | undefined,
      } : undefined,
      ports: ports.length ? ports : undefined,
      techStack: techStack.length ? techStack : undefined,
    },
    findings,
    falsePositives: opts.falsePositives,
    images: Object.keys(images).length ? images : undefined,
  };
}
