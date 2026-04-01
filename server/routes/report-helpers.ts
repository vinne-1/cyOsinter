import { storage } from "../storage";
import { enrichIPs } from "../api-integrations";
import { getOllamaConfig } from "../api-integrations";
import { generateReportSummary } from "../ai-service";
import { isSafeExternalUrl } from "./middleware";
import { createLogger } from "../logger";

const routeLog = createLogger("routes");

type ReconModule = { moduleType: string; confidence: number | null; data: Record<string, unknown> };

export async function buildReportContent(
  workspaceId: string,
  findingIds: string[] | undefined,
  reportType?: string
): Promise<{ content: Record<string, unknown>; summary: string }> {
  const { data: allFindings } = await storage.getFindings(workspaceId);
  let includedFindings = (findingIds?.length ?? 0) > 0
    ? allFindings.filter((f) => findingIds!.includes(f.id))
    : allFindings;

  if (reportType === "executive_summary") {
    includedFindings = includedFindings.filter((f) => {
      const evidence = (f.evidence || []) as Array<{ validated?: boolean; confidence?: string }>;
      const hasLowConfidence = evidence.some((e) => e.validated === false && e.confidence === "low");
      return !hasLowConfidence;
    });
  }

  if (reportType === "evidence_pack") {
    const reVerifyCategories = ["exposed_content", "infrastructure_disclosure", "leaked_credential"];
    const now = new Date().toISOString();
    for (const f of includedFindings) {
      if (!reVerifyCategories.includes(f.category)) continue;
      const evidence = (f.evidence || []) as Array<Record<string, unknown>>;
      for (const e of evidence) {
        const url = e.url as string | undefined;
        if (!url || typeof url !== "string" || !url.startsWith("http")) continue;
        if (!isSafeExternalUrl(url)) continue;
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 5000);
          const res = await fetch(url, { method: "HEAD", signal: controller.signal, redirect: "follow" });
          clearTimeout(timer);
          e.reVerifiedAt = now;
          e.validated = res.ok;
          e.reVerifyStatus = res.status;
        } catch {
          e.reVerifiedAt = now;
          e.validated = false;
          e.reVerifyStatus = 0;
        }
      }
    }
  }

  const { data: modules } = await storage.getReconModules(workspaceId);
  const modulesByType = (modules as ReconModule[]).reduce((acc, m) => {
    if (!(m.moduleType in acc)) acc[m.moduleType] = m;
    return acc;
  }, {} as Record<string, ReconModule>);

  const attackSurface = modulesByType.attack_surface?.data as Record<string, unknown> | undefined;
  const cloudFootprint = modulesByType.cloud_footprint?.data as Record<string, unknown> | undefined;

  const osintCategories = ["leaked_credential", "data_leak", "infrastructure_disclosure", "osint_exposure"];
  const osintFindings = includedFindings.filter((f) => osintCategories.includes(f.category));
  const byCategory: Record<string, number> = {};
  for (const c of osintCategories) {
    byCategory[c] = osintFindings.filter((f) => f.category === c).length;
  }

  const content: Record<string, unknown> = {
    totalFindings: includedFindings.length,
    criticalCount: includedFindings.filter((f) => f.severity === "critical").length,
    highCount: includedFindings.filter((f) => f.severity === "high").length,
    mediumCount: includedFindings.filter((f) => f.severity === "medium").length,
    lowCount: includedFindings.filter((f) => f.severity === "low").length,
    resolvedCount: includedFindings.filter((f) => f.status === "resolved").length,
    categories: Array.from(new Set(includedFindings.map((f) => f.category))),
    generatedAt: new Date().toISOString(),
    reconModules: modules.map((m) => ({
      moduleType: m.moduleType,
      confidence: m.confidence ?? 0,
      dataSummary: Object.keys(m.data || {}).slice(0, 5),
    })),
    moduleCoverage: modules.map((m) => ({
      moduleType: m.moduleType,
      included: true,
      summary: `${m.moduleType} (${m.confidence ?? 0}% confidence)`,
    })),
    dnsOverview: modulesByType.dns_overview?.data ?? null,
    redirectChain: modulesByType.redirect_chain?.data ?? null,
    exposedContent: modulesByType.exposed_content?.data ?? null,
    techStack: modulesByType.tech_stack?.data ?? null,
    websiteOverview: modulesByType.website_overview?.data ?? null,
    bgpRouting: modulesByType.bgp_routing?.data ?? null,
    nuclei: modulesByType.nuclei?.data ?? null,
    attackSurface: attackSurface
      ? {
          surfaceRiskScore: attackSurface.surfaceRiskScore,
          tlsGrade: (attackSurface.tlsPosture as Record<string, unknown> | undefined)?.grade,
          securityHeadersGrade: Array.isArray(attackSurface.securityHeaders) ? (attackSurface.securityHeaders[0] as Record<string, unknown>)?.grade : undefined,
        }
      : null,
    securityHeadersMatrix: attackSurface?.securityHeaders
      ? (Array.isArray(attackSurface.securityHeaders)
        ? (attackSurface.securityHeaders as Array<{ header: string; present: boolean; value?: string; grade?: string }>).map((h) => ({
            header: h.header,
            present: !!h.present,
            grade: h.grade ?? "N/A",
            value: h.value ?? null,
          }))
        : Object.entries(attackSurface.securityHeaders as Record<string, { present?: boolean; value?: string | null; grade?: string }>).map(([header, h]) => ({
            header,
            present: !!h?.present,
            grade: h?.grade ?? "N/A",
            value: h?.value ?? null,
          })))
      : [],
    securityHeadersCoverage: attackSurface?.securityHeaders
      ? (() => {
          const arr = Array.isArray(attackSurface.securityHeaders)
            ? attackSurface.securityHeaders as Array<{ header: string; present?: boolean; grade?: string }>
            : Object.entries(attackSurface.securityHeaders as Record<string, { present?: boolean; grade?: string }>).map(([name, h]) => ({ header: name, ...h }));
          const total = arr.length;
          const passing = arr.filter((h) => h.present && (h.grade === "A" || h.grade === "B")).length;
          const missing = arr.filter((h) => !h.present).map((h) => h.header);
          return { passing, total, missing };
        })()
      : null,
    attackSurfaceSummary: attackSurface
      ? (() => {
          const inv = (attackSurface.assetInventory || []) as Array<{ host: string; riskScore: number; waf: string }>;
          const totalHosts = inv.length || 0;
          const highRiskCount = inv.filter((a) => a.riskScore >= 60).length;
          const wafCoverage = totalHosts > 0 ? Math.round((inv.filter((a) => a.waf).length / totalHosts) * 100) : 0;
          return { totalHosts, highRiskCount, wafCoverage };
        })()
      : null,
    attackSurfaceAssets: attackSurface?.assetInventory ?? [],
    cloudFootprint: cloudFootprint
      ? {
          grades: cloudFootprint.grades,
          spfStatus: (cloudFootprint.emailSecurity as Record<string, unknown>)?.spf && typeof (cloudFootprint.emailSecurity as Record<string, unknown>).spf === "object"
            ? ((cloudFootprint.emailSecurity as Record<string, unknown>).spf as Record<string, unknown>)?.status
            : undefined,
          dmarcStatus: (cloudFootprint.emailSecurity as Record<string, unknown>)?.dmarc && typeof (cloudFootprint.emailSecurity as Record<string, unknown>).dmarc === "object"
            ? ((cloudFootprint.emailSecurity as Record<string, unknown>).dmarc as Record<string, unknown>)?.status
            : undefined,
        }
      : null,
    osintDiscovery: {
      leakedCredentials: osintFindings.filter((f) => f.category === "leaked_credential").map((f) => ({ id: f.id, title: f.title, severity: f.severity, affectedAsset: f.affectedAsset })),
      exposedDocuments: osintFindings.filter((f) => f.category === "data_leak").map((f) => ({ id: f.id, title: f.title, severity: f.severity, affectedAsset: f.affectedAsset })),
      infrastructureDisclosure: osintFindings.filter((f) => f.category === "infrastructure_disclosure").map((f) => ({ id: f.id, title: f.title, severity: f.severity, affectedAsset: f.affectedAsset })),
      osintExposure: osintFindings.filter((f) => f.category === "osint_exposure").map((f) => ({ id: f.id, title: f.title, severity: f.severity, affectedAsset: f.affectedAsset })),
      summary: { total: osintFindings.length, byCategory },
    },
  };

  if (reportType === "evidence_pack") {
    const verifiedFindings = includedFindings.filter((f) => {
      const ev = (f.evidence || []) as Array<Record<string, unknown>>;
      return ev.some((e) => e.reVerifiedAt);
    });
    const passedCount = verifiedFindings.filter((f) => {
      const ev = (f.evidence || []) as Array<Record<string, unknown>>;
      return ev.every((e) => !e.reVerifiedAt || e.validated === true);
    }).length;
    content.evidenceVerification = {
      totalVerified: verifiedFindings.length,
      passed: passedCount,
      failed: verifiedFindings.length - passedCount,
      verifiedAt: new Date().toISOString(),
    };
  }

  const postureHistory = await storage.getPostureHistory(workspaceId, 10);
  content.postureTrend = postureHistory.map((p) => ({
    snapshotAt: p.snapshotAt?.toISOString?.() ?? new Date().toISOString(),
    surfaceRiskScore: p.surfaceRiskScore,
    securityScore: p.securityScore,
    findingsCount: p.findingsCount,
    criticalCount: p.criticalCount,
    highCount: p.highCount,
    wafCoverage: p.wafCoverage,
  }));

  const { data: ipAssets } = await storage.getAssets(workspaceId);
  const ipsFromAssets = ipAssets.filter((a) => a.type === "ip").map((a) => a.value);
  const publicIPs = attackSurface?.publicIPs as Array<{ ip: string }> | undefined;
  const ipsFromSurface = (publicIPs ?? []).map((p) => (typeof p === "string" ? p : p?.ip)).filter(Boolean);
  const allIPs = Array.from(new Set([...ipsFromAssets, ...ipsFromSurface]));
  if (allIPs.length > 0) {
    try {
      const ipEnrichment = await enrichIPs(allIPs);
      content.ipEnrichment = ipEnrichment;
    } catch (err) {
      routeLog.error({ err }, "IP enrichment error");
    }
  }

  const crit = content.criticalCount as number;
  const high = content.highCount as number;
  const osintTotal = osintFindings.length;
  const surfaceScore = attackSurface?.surfaceRiskScore as number | undefined;
  const cloudGrade = (cloudFootprint?.grades as Record<string, string> | undefined)?.overall;

  let summary = `This report covers ${includedFindings.length} security findings across ${(content.categories as string[]).length} categories. `;
  if (crit > 0 || high > 0) {
    summary += `${crit} critical and ${high} high severity findings require immediate attention. `;
  }
  if (modules.length > 0) {
    summary += `Intelligence data includes ${modules.length} recon modules. `;
  }
  if (surfaceScore != null) {
    summary += `Attack surface risk score: ${surfaceScore}/100. `;
  }
  if (cloudGrade) {
    summary += `Email security grade: ${cloudGrade}. `;
  }
  if (osintTotal > 0) {
    summary += `OSINT discovery identified ${osintTotal} items (credentials, exposed docs, infrastructure). `;
  }
  if (content.ipEnrichment && Object.keys(content.ipEnrichment as object).length > 0) {
    summary += `IP reputation data from AbuseIPDB and VirusTotal included.`;
  }
  summary = summary.trimEnd();

  const originalSummary = summary;
  const ollamaConfig = getOllamaConfig();
  if (ollamaConfig.enabled && includedFindings.length > 0) {
    try {
      const aiSummary = await generateReportSummary(includedFindings, content);
      if (aiSummary && aiSummary.trim()) {
        summary = aiSummary.trim();
        (content as Record<string, unknown>).aiNarrative = summary;
        (content as Record<string, unknown>).originalSummary = originalSummary;
      }
    } catch (err) {
      routeLog.error({ err }, "AI report summary failed, using fallback");
    }
  }

  return { content, summary };
}
