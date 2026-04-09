import { storage } from "./storage";
import { createLogger } from "./logger";
import { runEASMScan, runOSINTScan, runNucleiScan, buildReconModules, runDASTScan } from "./scanner";
import { computeSecurityScore } from "@shared/scoring";
import { fetchBGPViewForIPs } from "./api-integrations";
import { enrichFinding } from "./ai-service";
import { emitScanCompleted, emitScanFailed, emitNewCriticalFinding } from "./notifications";
import { generateAllComplianceReports } from "./compliance-mapper";
import { autoSeedRiskRegister } from "./compliance-workflows";
import type { ScanProfileConfig } from "@shared/schema";

const log = createLogger("scan-trigger");

// ── Types ──

type ProgressFn = (msg: string, percent: number, step: string, etaSeconds?: number) => Promise<void>;
type ScanMode = "standard" | "gold";

interface ScanResults {
  easmResults: Awaited<ReturnType<typeof runEASMScan>> | null;
  osintResults: Awaited<ReturnType<typeof runOSINTScan>> | null;
  nucleiResults: Awaited<ReturnType<typeof runNucleiScan>> | null;
  dastResults: Awaited<ReturnType<typeof runDASTScan>> | null;
}

interface RawFinding {
  title: string;
  description: string;
  severity: string;
  category: string;
  affectedAsset: string;
  remediation: string;
  cvssScore?: string;
  evidence?: Record<string, unknown>[];
  tags?: string[];
  checkId?: string;
  resourceType?: string;
  resourceId?: string;
  provider?: string;
  complianceTags?: string[];
}

interface RawAsset {
  type: string;
  value: string;
  tags?: string[];
}

// ── Scanner Orchestration ──

async function runScanners(
  target: string,
  type: string,
  mode: ScanMode,
  onProgress: ProgressFn,
  profileConfig: ScanProfileConfig | undefined,
  signal: AbortSignal | undefined,
): Promise<ScanResults> {
  const results: ScanResults = {
    easmResults: null,
    osintResults: null,
    nucleiResults: null,
    dastResults: null,
  };
  const scanOptions = { signal, mode, ...profileConfig };
  const gold = mode === "gold";

  if (type === "full") {
    const easmProgress: ProgressFn = (m, p, s, e) =>
      onProgress(`[EASM] ${m}`, Math.round(Math.min(40, (p * 40) / 100)), `easm_${s}`, e ? Math.ceil(e * 0.4) : undefined);
    results.easmResults = await runEASMScan(target, easmProgress, scanOptions);

    const osintProgress: ProgressFn = (m, p, s, e) =>
      onProgress(`[OSINT] ${m}`, Math.round(40 + (p * 40) / 100), `osint_${s}`, e ? Math.ceil(e * 0.4) : undefined);
    results.osintResults = await runOSINTScan(target, osintProgress, scanOptions);

    const nucleiUrls = buildNucleiUrls(target, results.easmResults, gold);
    const nucleiProgress: ProgressFn = (m, p, s, e) =>
      onProgress(`[Nuclei] ${m}`, Math.round(75 + (p * 15) / 100), `nuclei_${s}`, e ? Math.ceil(e * 0.15) : undefined);
    if (profileConfig?.enableNuclei === false) {
      results.nucleiResults = {
        findings: [],
        nucleiResults: [],
        skipped: true,
        reason: "Disabled by selected scan profile",
      };
    } else {
      try {
        results.nucleiResults = await runNucleiScan(target, nucleiUrls, nucleiProgress, { mode, signal, ...profileConfig });
      } catch (nucleiErr) {
        log.warn({ err: nucleiErr }, "Nuclei scan unavailable (non-fatal) — install nuclei for full vulnerability scanning");
        results.nucleiResults = { findings: [], nucleiResults: [], skipped: true, reason: String(nucleiErr instanceof Error ? nucleiErr.message : nucleiErr) };
      }
    }

    if (signal?.aborted) throw new Error("Scan aborted");
    await onProgress("[DAST] Running active security tests...", 92, "dast_start");
    try {
      results.dastResults = await runDASTScan(target);
    } catch (dastErr) {
      log.warn({ err: dastErr }, "DAST-Lite scan failed (non-fatal)");
    }
    await onProgress("[DAST] Active testing complete", 97, "dast_done");
  } else if (type === "easm") {
    results.easmResults = await runEASMScan(target, onProgress, scanOptions);
  } else if (type === "dast") {
    if (signal?.aborted) throw new Error("Scan aborted");
    await onProgress("[DAST] Running active security tests...", 10, "dast_start");
    try {
      results.dastResults = await runDASTScan(target);
    } catch (dastErr) {
      log.warn({ err: dastErr }, "DAST-Lite scan failed");
    }
    await onProgress("[DAST] Active testing complete", 100, "dast_done");
  } else {
    results.osintResults = await runOSINTScan(target, onProgress, scanOptions);
  }

  return results;
}

function buildNucleiUrls(
  target: string,
  easmResults: Awaited<ReturnType<typeof runEASMScan>> | null,
  gold: boolean,
): string[] {
  const urls = [`https://${target}`, `http://${target}`];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const discoveredDomains = (easmResults?.reconData as any)?.discoveredDomains as Array<{ domain: string }> | undefined;
  const cap = gold ? 0 : 50;
  const domains = cap === 0 ? (discoveredDomains ?? []) : (discoveredDomains ?? []).slice(0, cap);
  for (const d of domains) {
    urls.push(`https://${d.domain}`, `http://${d.domain}`);
  }
  return urls;
}

// ── Asset Persistence ──

async function persistAssets(workspaceId: string, allAssets: RawAsset[]): Promise<void> {
  for (const asset of allAssets) {
    try {
      const exists = await storage.assetExists(workspaceId, asset.type, asset.value);
      if (!exists) {
        await storage.createAsset({ workspaceId, type: asset.type, value: asset.value, status: "active", tags: asset.tags });
      }
    } catch (err) {
      log.warn({ err }, "Failed to create asset");
    }
  }
}

// ── Finding Persistence ──

async function persistFindings(
  workspaceId: string,
  scanId: string,
  allFindings: RawFinding[],
): Promise<string[]> {
  const createdIds: string[] = [];
  for (const f of allFindings) {
    try {
      const exists = await storage.findingExists(workspaceId, f.title, f.affectedAsset, f.category);
      if (exists) continue;
      const checkIdFromTags = f.tags?.find((tag) => tag.startsWith("check:"))?.slice("check:".length);
      const created = await storage.createFinding({
        ...f,
        workspaceId,
        scanId,
        status: "open",
        evidence: f.evidence ?? [],
        checkId: f.checkId ?? checkIdFromTags ?? f.category ?? null,
        resourceType: f.resourceType ?? null,
        resourceId: f.resourceId ?? f.affectedAsset ?? null,
        provider: f.provider ?? null,
        complianceTags: f.complianceTags ?? [],
      });
      createdIds.push(created.id);
      if (created.severity === "critical" || created.severity === "high") {
        emitNewCriticalFinding(created).catch((err) => log.warn({ err }, "Failed to emit finding alert"));
      }
    } catch (err) {
      log.error({ err, title: f.title }, "Failed to create finding");
    }
  }
  return createdIds;
}

// ── Recon Module Storage ──

async function storeReconModules(
  workspaceId: string,
  scanId: string,
  target: string,
  results: ScanResults,
  type: string,
): Promise<void> {
  // Core recon modules from EASM + OSINT
  let reconMods: Awaited<ReturnType<typeof buildReconModules>> = [];
  try {
    reconMods = await buildReconModules(target, results.easmResults, results.osintResults);
  } catch (err) {
    log.error({ err }, "Failed to build recon modules");
  }

  for (const mod of reconMods) {
    try {
      await storage.createReconModule({
        workspaceId, scanId, target,
        moduleType: mod.moduleType,
        data: mod.data,
        confidence: mod.confidence,
      });
    } catch (err) {
      log.error({ err, moduleType: mod.moduleType }, "Failed to create recon module");
    }
  }

  // BGP enrichment
  await storeBGPModule(workspaceId, scanId, target, results, reconMods);

  // Nuclei module
  if (results.nucleiResults && type === "full") {
    try {
      await storage.createReconModule({
        workspaceId, scanId, target,
        moduleType: "nuclei",
        data: {
          source: "Nuclei scanner (all templates)",
          hits: results.nucleiResults.nucleiResults ?? [],
          templateCount: results.nucleiResults.nucleiResults?.length ?? 0,
          allTemplatesLoaded: !results.nucleiResults.skipped,
          skipped: results.nucleiResults.skipped ?? false,
          skipReason: results.nucleiResults.reason,
          verifiedAt: new Date().toISOString(),
        },
        confidence: 95,
      });
    } catch (err) {
      log.error({ err }, "Nuclei module create error");
    }
  }

  // DAST module
  if (results.dastResults) {
    try {
      await storage.createReconModule({
        workspaceId, scanId, target,
        moduleType: "dast_lite",
        data: {
          source: "DAST-Lite active testing",
          testsRun: results.dastResults.testsRun,
          testsPassed: results.dastResults.testsPassed,
          duration: results.dastResults.duration,
          findings: results.dastResults.findings,
          verifiedAt: new Date().toISOString(),
        },
        confidence: 85,
      });
    } catch (err) {
      log.error({ err }, "DAST module create error");
    }
  }
}

async function storeBGPModule(
  workspaceId: string,
  scanId: string,
  target: string,
  results: ScanResults,
  reconMods: Awaited<ReturnType<typeof buildReconModules>>,
): Promise<void> {
  const ipsFromAttackSurface = reconMods
    .find((m) => m.moduleType === "attack_surface")
    ?.data?.publicIPs as Array<{ ip: string }> | undefined;
  const allAssets = [...(results.easmResults?.assets ?? []), ...(results.osintResults?.assets ?? [])];
  const ipsFromAssets = allAssets.filter((a) => a.type === "ip").map((a) => a.value);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const ipsFromDiscovered = (results.easmResults?.reconData as any)?.discoveredDomains
    ?.flatMap((d: { dns?: { ips?: string[] } }) => d.dns?.ips ?? []) ?? [];
  const allIPs = Array.from(new Set([
    ...(ipsFromAttackSurface ?? []).map((p) => (typeof p === "string" ? p : p?.ip)).filter(Boolean),
    ...ipsFromAssets,
    ...ipsFromDiscovered,
  ]));

  if (allIPs.length > 0) {
    try {
      const bgpData = await fetchBGPViewForIPs(allIPs) as Record<string, unknown>;
      await storage.createReconModule({
        workspaceId, scanId, target,
        moduleType: "bgp_routing",
        data: { ips: bgpData, source: "BGPView API", verifiedAt: new Date().toISOString() },
        confidence: 90,
      });
    } catch (err) {
      log.error({ err }, "BGP routing error");
    }
  }
}

// ── Posture Snapshot ──

async function createPostureSnapshot(
  workspaceId: string,
  scanId: string,
  target: string,
  mode: string,
  allFindings: RawFinding[],
): Promise<void> {
  try {
    const { data: modules } = await storage.getReconModules(workspaceId);
    const attackSurface = modules.find((m) => m.moduleType === "attack_surface")?.data as Record<string, unknown> | undefined;
    const assetInventory = (attackSurface?.assetInventory || []) as Array<{ riskScore: number; waf: string }>;
    const totalHosts = assetInventory.length || 0;
    const wafCoverage = totalHosts > 0 ? Math.round((assetInventory.filter((a) => a.waf).length / totalHosts) * 100) : null;
    const tlsPosture = attackSurface?.tlsPosture as { grade?: string } | undefined;

    await storage.createPostureSnapshot({
      workspaceId, scanId, target,
      snapshotAt: new Date(),
      surfaceRiskScore: attackSurface?.surfaceRiskScore as number | undefined ?? null,
      tlsGrade: tlsPosture?.grade ?? null,
      securityScore: allFindings.length > 0 ? computeSecurityScore(allFindings) : null,
      findingsCount: allFindings.length,
      criticalCount: allFindings.filter((f) => f.severity === "critical").length,
      highCount: allFindings.filter((f) => f.severity === "high").length,
      openPortsCount: 0,
      wafCoverage,
      metadata: { mode },
    });
  } catch (err) {
    log.error({ err }, "Scan posture snapshot error");
  }
}

async function buildComplianceSummary(workspaceId: string): Promise<Record<string, unknown> | null> {
  try {
    const { data: findings } = await storage.getFindings(workspaceId);
    const reports = generateAllComplianceReports(findings);
    return {
      updatedAt: new Date().toISOString(),
      frameworks: Object.fromEntries(
        Object.entries(reports).map(([framework, report]) => [
          framework,
          {
            score: report.score,
            assessedControls: report.assessedControls,
            totalControls: report.totalControls,
            hasAssessmentData: report.hasAssessmentData,
          },
        ]),
      ),
    };
  } catch (err) {
    log.warn({ err }, "Failed to build compliance summary for scan");
    return null;
  }
}

// ── Background Enrichment ──

async function runBackgroundEnrichment(workspaceId: string): Promise<void> {
  try {
    const { data: wsFindings } = await storage.getFindings(workspaceId);
    const toEnrich = wsFindings
      .filter((f) => (f.severity === "critical" || f.severity === "high") && !(f.aiEnrichment as Record<string, unknown>)?.enhancedDescription)
      .slice(0, 2);
    const { data: modules } = await storage.getReconModules(workspaceId);
    for (const f of toEnrich) {
      try {
        const result = await enrichFinding(f, modules);
        const existing = (f.aiEnrichment as Record<string, unknown>) ?? {};
        await storage.updateFinding(f.id, {
          aiEnrichment: { ...existing, ...result, enrichedAt: new Date().toISOString() },
        });
      } catch {
        /* skip failed enrichment */
      }
    }
  } catch {
    /* batch enrichment is best-effort */
  }
}

// ── Main Entry Point ──

/**
 * Programmatically trigger a scan. Returns the scan ID.
 * Used by both the POST /api/scans route and the scan scheduler.
 */
export async function triggerScan(
  target: string,
  type: string,
  workspaceId: string,
  mode: string,
  profileConfig?: ScanProfileConfig,
): Promise<string> {
  const scan = await storage.createScan({
    workspaceId, target, type, status: "pending",
  });

  await storage.updateScan(scan.id, { status: "running", startedAt: new Date() });

  const onProgress: ProgressFn = async (msg, percent, step, etaSeconds) => {
    await storage.updateScan(scan.id, {
      progressMessage: msg,
      progressPercent: Math.round(percent),
      currentStep: step,
      estimatedSecondsRemaining: etaSeconds != null ? Math.round(etaSeconds) : null,
    });
  };

  // Fire-and-forget the actual scan work
  (async () => {
    const timeoutMinutes = profileConfig?.timeoutMinutes;
    const timeoutMs = timeoutMinutes && timeoutMinutes > 0 ? timeoutMinutes * 60_000 : null;
    const abortController = new AbortController();
    const timeoutHandle = timeoutMs
      ? setTimeout(() => abortController.abort(), timeoutMs)
      : null;
    try {
      const scanMode = mode as ScanMode;
      const results = await runScanners(target, type, scanMode, onProgress, profileConfig, abortController.signal);

      const allFindings: RawFinding[] = [
        ...(results.easmResults?.findings ?? []),
        ...(results.osintResults?.findings ?? []),
        ...(results.nucleiResults?.findings ?? []),
        ...(results.dastResults?.findings ?? []),
      ];
      const allAssets: RawAsset[] = [
        ...(results.easmResults?.assets ?? []),
        ...(results.osintResults?.assets ?? []),
      ];
      const mergedSubdomains = Array.from(new Set([
        ...(results.easmResults?.subdomains ?? []),
        ...(results.osintResults?.subdomains ?? []),
      ]));

      await persistAssets(workspaceId, allAssets);
      const createdFindingIds = await persistFindings(workspaceId, scan.id, allFindings);
      await storeReconModules(workspaceId, scan.id, target, results, type);
      const complianceSummary = await buildComplianceSummary(workspaceId);

      await storage.updateScan(scan.id, {
        status: "completed",
        completedAt: new Date(),
        findingsCount: createdFindingIds.length,
        progressMessage: null,
        progressPercent: null,
        currentStep: null,
        estimatedSecondsRemaining: null,
        summary: {
          assetsDiscovered: allAssets.length,
          findingsGenerated: createdFindingIds.length,
          criticalCount: allFindings.filter((f) => f.severity === "critical").length,
          highCount: allFindings.filter((f) => f.severity === "high").length,
          subdomainsFound: mergedSubdomains.length,
          verifiedOnly: true,
          mode: scanMode,
          compliance: complianceSummary,
        },
      });

      await createPostureSnapshot(workspaceId, scan.id, target, scanMode, allFindings);
      autoSeedRiskRegister(workspaceId).catch((err) =>
        log.warn({ err }, "Risk register auto-seed failed after scan"));

      const updatedScan = await storage.getScan(scan.id);
      if (updatedScan) {
        emitScanCompleted(updatedScan, createdFindingIds.length).catch((err) =>
          log.warn({ err }, "Failed to emit scan completed alert"));
      }

      runBackgroundEnrichment(workspaceId).catch((err) =>
        log.warn({ err }, "Background enrichment failed"));
    } catch (err) {
      const abortedByTimeout = abortController.signal.aborted;
      const timeoutMessage = timeoutMinutes
        ? `Scan timed out after ${timeoutMinutes} minute(s) per selected scan profile`
        : "Scan aborted";
      log.error({ err }, "Scan processing error");
      try {
        await storage.updateScan(scan.id, {
          status: "failed",
          completedAt: new Date(),
          errorMessage: abortedByTimeout
            ? timeoutMessage
            : (err instanceof Error ? err.message : String(err)),
          progressMessage: null,
          progressPercent: null,
          currentStep: null,
          estimatedSecondsRemaining: null,
        });

        const failedScan = await storage.getScan(scan.id);
        if (failedScan) {
          emitScanFailed(
            failedScan,
            abortedByTimeout
              ? timeoutMessage
              : (err instanceof Error ? err.message : String(err)),
          )
            .catch((alertErr) => log.warn({ err: alertErr }, "Failed to emit scan failed alert"));
        }
      } catch (updateErr) {
        log.error({ err: updateErr }, "CRITICAL: Failed to mark scan as failed");
      }
    } finally {
      if (timeoutHandle) clearTimeout(timeoutHandle);
    }
  })().catch((err) => {
    log.error({ err }, "Unhandled scan error");
  });

  return scan.id;
}
