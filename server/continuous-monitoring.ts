import { storage } from "./storage";
import { runEASMScan, runOSINTScan, buildReconModules } from "./scanner";
import { computeSecurityScore } from "@shared/scoring";
import { createLogger } from "./logger";

const log = createLogger("monitoring");

const INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

interface MonitoringSession {
  workspaceId: string;
  target: string;
  abortController: AbortController;
  iteration: number;
  progressPercent: number;
  progressMessage: string;
  currentStep: string;
  cmId: string;
}

const activeSessions = new Map<string, MonitoringSession>();

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Sleep that checks abort signal every second so Stop can interrupt the 5-min wait. */
async function sleepWithAbort(ms: number, signal: AbortSignal): Promise<void> {
  const interval = 1000;
  let elapsed = 0;
  while (elapsed < ms) {
    if (signal.aborted) return;
    await sleep(Math.min(interval, ms - elapsed));
    elapsed += interval;
  }
}

export function isMonitoringActive(workspaceId: string): boolean {
  return activeSessions.has(workspaceId);
}

export function getMonitoringStatus(workspaceId: string): {
  running: boolean;
  iteration: number;
  progressPercent: number;
  progressMessage: string;
  currentStep: string;
} {
  const session = activeSessions.get(workspaceId);
  if (!session) {
    return { running: false, iteration: 0, progressPercent: 0, progressMessage: "", currentStep: "" };
  }
  return {
    running: true,
    iteration: session.iteration,
    progressPercent: session.progressPercent,
    progressMessage: session.progressMessage,
    currentStep: session.currentStep,
  };
}

export function stopMonitoring(workspaceId: string): boolean {
  const session = activeSessions.get(workspaceId);
  if (!session) return false;
  session.abortController.abort();
  activeSessions.delete(workspaceId);
  storage.updateContinuousMonitoring(session.cmId, { status: "stopped" }).catch((err: Error) => {
    log.warn({ err }, "Failed to update status to stopped");
  });
  return true;
}

export async function startMonitoring(target: string, workspaceId?: string, userId?: string): Promise<{ workspaceId: string; continuousMonitoringId: string }> {
  let wsId = workspaceId;
  if (!wsId) {
    let ws = await storage.getWorkspaceByName(target);
    if (!ws) {
      ws = await storage.createWorkspace({ name: target, description: null, status: "active" });
      // Add the initiating user as owner so the workspace is visible
      if (userId) {
        await storage.addWorkspaceMember(ws.id, userId, "owner");
      }
    }
    wsId = ws.id;
  }

  if (activeSessions.has(wsId)) {
    throw new Error("Continuous monitoring is already running for this workspace");
  }

  const cm = await storage.createContinuousMonitoring({
    workspaceId: wsId,
    target,
    status: "running",
    iterationCount: 0,
  });

  const abortController = new AbortController();
  const session: MonitoringSession = {
    workspaceId: wsId,
    target,
    abortController,
    iteration: 0,
    progressPercent: 0,
    progressMessage: "Starting...",
    currentStep: "init",
    cmId: cm.id,
  };
  activeSessions.set(wsId, session);

  (async () => {
    const signal = abortController.signal;
    while (!signal.aborted) {
      session.iteration += 1;
      session.progressMessage = `Iteration ${session.iteration} - Starting full scan`;
      session.currentStep = "easm";
      session.progressPercent = 0;

      const scan = await storage.createScan({
        workspaceId: wsId!,
        target,
        type: "full",
        status: "running",
      });
      await storage.updateScan(scan.id, { status: "running", startedAt: new Date() });

      try {
        const onProgress = async (msg: string, percent: number, step: string) => {
          if (signal.aborted) return;
          session.progressPercent = Math.round(percent);
          session.progressMessage = `Iteration ${session.iteration} - ${msg}`;
          session.currentStep = step;
          await storage.updateContinuousMonitoring(cm.id, {
            iterationCount: session.iteration,
            progressPercent: session.progressPercent,
            progressMessage: session.progressMessage,
            currentStep: session.currentStep,
            lastIterationAt: new Date(),
          });
          await storage.updateScan(scan.id, {
            progressMessage: msg,
            progressPercent: Math.round(percent),
            currentStep: step,
          });
        };

        const easmProgress = (m: string, p: number, s: string) =>
          onProgress(`[EASM] ${m}`, Math.min(45, (p * 45) / 100), `easm_${s}`);
        const osintProgress = (m: string, p: number, s: string) =>
          onProgress(`[OSINT] ${m}`, 45 + (p * 55) / 100, `osint_${s}`);

        const easmResults = await runEASMScan(target, easmProgress, { signal, mode: "gold" });
        if (signal.aborted) break;

        const osintResults = await runOSINTScan(target, osintProgress, { signal, mode: "gold" });
        if (signal.aborted) break;

        const allFindings = [...(easmResults?.findings ?? []), ...(osintResults?.findings ?? [])];
        const allAssets = [...(easmResults?.assets ?? []), ...(osintResults?.assets ?? [])];
        const mergedSubdomains = Array.from(new Set([...(easmResults?.subdomains ?? []), ...(osintResults?.subdomains ?? [])]));

        let newAssetsCount = 0;
        for (const asset of allAssets) {
          const exists = await storage.assetExists(wsId!, asset.type, asset.value);
          if (!exists) {
            try {
              await storage.createAsset({ workspaceId: wsId!, type: asset.type, value: asset.value, status: "active", tags: asset.tags });
              newAssetsCount++;
            } catch (assetErr) {
              log.warn({ err: assetErr }, "Failed to create asset");
            }
          }
        }

        let newFindingsCount = 0;
        for (const f of allFindings) {
          try {
            const exists = await storage.findingExists(wsId!, f.title, f.affectedAsset ?? "", f.category);
            if (!exists) {
              await storage.createFinding({ ...f, workspaceId: wsId!, scanId: scan.id, status: "open" });
              newFindingsCount++;
            }
          } catch (findErr) {
            log.error({ err: findErr, title: f.title }, "Failed to create finding");
          }
        }

        const reconModulesList = await buildReconModules(target, easmResults, osintResults);
        for (const mod of reconModulesList) {
          const existing = await storage.getReconModulesByType(wsId!, mod.moduleType);
          const payload = {
            workspaceId: wsId!,
            scanId: scan.id,
            target,
            moduleType: mod.moduleType,
            data: mod.data,
            confidence: mod.confidence,
          };
          if (existing.length > 0) {
            await storage.updateReconModule(existing[0].id, { data: mod.data, confidence: mod.confidence });
          } else {
            await storage.createReconModule(payload);
          }
        }

        await storage.updateScan(scan.id, {
          status: "completed",
          completedAt: new Date(),
          findingsCount: newFindingsCount,
          progressMessage: null,
          progressPercent: null,
          currentStep: null,
          estimatedSecondsRemaining: null,
          summary: {
            mode: "gold",
            assetsDiscovered: allAssets.length,
            findingsGenerated: newFindingsCount,
            newAssetsAdded: newAssetsCount,
            newFindingsAdded: newFindingsCount,
            criticalCount: allFindings.filter((f) => f.severity === "critical").length,
            highCount: allFindings.filter((f) => f.severity === "high").length,
            subdomainsFound: mergedSubdomains.length,
            verifiedOnly: true,
          },
        });

        try {
          const { data: modules } = await storage.getReconModules(wsId!);
          const attackSurface = modules.find((m) => m.moduleType === "attack_surface")?.data as Record<string, unknown> | undefined;
          const assetInventory = (attackSurface?.assetInventory || []) as Array<{ riskScore: number; waf: string }>;
          const totalHosts = assetInventory.length || 0;
          const wafCoverage = totalHosts > 0 ? Math.round((assetInventory.filter((a) => a.waf).length / totalHosts) * 100) : null;
          const tlsPosture = attackSurface?.tlsPosture as { grade?: string } | undefined;
          await storage.createPostureSnapshot({
            workspaceId: wsId!,
            scanId: scan.id,
            target,
            snapshotAt: new Date(),
            surfaceRiskScore: attackSurface?.surfaceRiskScore as number | undefined ?? null,
            tlsGrade: tlsPosture?.grade ?? null,
            securityScore: computeSecurityScore(allFindings),
            findingsCount: allFindings.length,
            criticalCount: allFindings.filter((f) => (f.severity ?? "").toLowerCase() === "critical").length,
            highCount: allFindings.filter((f) => (f.severity ?? "").toLowerCase() === "high").length,
            openPortsCount: 0,
            wafCoverage,
            metadata: { mode: "gold", iteration: session.iteration },
          });
        } catch (snapErr) {
          const err = snapErr instanceof Error ? snapErr : new Error(String(snapErr));
          log.error({ err }, "Posture snapshot error");
        }

        await storage.updateContinuousMonitoring(cm.id, {
          iterationCount: session.iteration,
          progressPercent: 100,
          progressMessage: `Iteration ${session.iteration} complete. New: ${newFindingsCount} findings, ${newAssetsCount} assets`,
          currentStep: "idle",
          lastIterationAt: new Date(),
        });
        session.progressPercent = 100;
        session.progressMessage = `Iteration ${session.iteration} complete. Waiting 5 min...`;
        session.currentStep = "idle";
      } catch (err) {
        if (err instanceof Error && err.message === "Scan aborted") {
          await storage.updateScan(scan.id, { status: "failed", completedAt: new Date(), errorMessage: "Stopped by user" });
          break;
        }
        log.error({ err }, "Continuous monitoring scan error");
        await storage.updateScan(scan.id, {
          status: "failed",
          completedAt: new Date(),
          errorMessage: err instanceof Error ? err.message : String(err),
        });
      }

      if (signal.aborted) break;
      await sleepWithAbort(INTERVAL_MS, signal);
    }

    activeSessions.delete(wsId!);
    await storage.updateContinuousMonitoring(cm.id, { status: "stopped" });
  })();

  return { workspaceId: wsId!, continuousMonitoringId: cm.id };
}
