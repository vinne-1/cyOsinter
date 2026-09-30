import { storage } from "./storage";
import { createLogger } from "./logger";
import { acquireSlot, MAX_CONCURRENT_SCANS } from "./scan-slots.js";
import { runEASMScan, runOSINTScan, runNucleiScan, buildReconModules, runDASTScan, runPassiveScan } from "./scanner";
import { runWithStealth } from "./scanner/stealth.js";
import { crawlSite } from "./scanner/crawler.js";
import type { InjectionTarget } from "./scanner/dast-lite.js";
import { runVerificationGate } from "./scanner/verification-gate.js";
import { reEnrichWorkspaceThreatIntel } from "./enrichment-service.js";
import { computeSecurityScore } from "@shared/scoring";
import { fetchBGPViewForIPs } from "./api-integrations";
import { correlateExploitability } from "./cve-service";
import { enrichFinding } from "./ai-service";
import { generateAndPersistWorkspaceInsights } from "./workspace-insights.js";
import { emitScanCompleted, emitScanFailed, emitNewCriticalFinding } from "./notifications";

const log = createLogger("scan-trigger");

/**
 * In-flight scans, so a running one can be stopped.
 *
 * The scanner was already threaded for cancellation end to end —
 * `checkAborted(signal)` between phases, `signal` passed into every
 * `runWithConcurrency` — but `scanOptions.signal` was hardcoded `undefined`
 * and no route ever asked to cancel. The whole mechanism was unreachable, so a
 * Gold scan aimed at the wrong domain ran for its full thirty-plus minutes with
 * no way to stop the outbound traffic.
 *
 * In memory on purpose: an AbortController cannot survive a restart, and a scan
 * whose process died is no longer running anyway. The queue reconciles orphaned
 * rows separately.
 */
const inFlight = new Map<string, AbortController>();

/**
 * Ask a running scan to stop. Returns false when it is not running here —
 * already finished, never started, or owned by another instance.
 */
export function requestScanCancellation(scanId: string): boolean {
  const controller = inFlight.get(scanId);
  if (!controller) return false;
  controller.abort();
  log.info({ scanId }, "scan cancellation requested");
  return true;
}

/** Whether this instance is currently executing the scan. */
export function isScanRunningHere(scanId: string): boolean {
  return inFlight.has(scanId);
}

// ── Types ──

type ProgressFn = (msg: string, percent: number, step: string, etaSeconds?: number) => Promise<void>;
type ScanMode = "standard" | "gold" | "safe";

interface ScanResults {
  easmResults: Awaited<ReturnType<typeof runEASMScan>> | null;
  osintResults: Awaited<ReturnType<typeof runOSINTScan>> | null;
  nucleiResults: Awaited<ReturnType<typeof runNucleiScan>> | null;
  dastResults: Awaited<ReturnType<typeof runDASTScan>> | null;
  /** What the crawl found, so a report can say how wide the active tests reached. */
  crawlResults?: { engine: string; urls: number; parameterised: number; forms: number; truncated: boolean };
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
}

interface RawAsset {
  type: string;
  value: string;
  tags?: string[];
}

// ── Scanner Orchestration ──

/** Called after each scan phase completes so results can be persisted live. */
type PhaseFn = (results: ScanResults) => Promise<void>;

function runScanners(
  target: string,
  type: string,
  mode: ScanMode,
  onProgress: ProgressFn,
  onPhase?: PhaseFn,
  knownHosts?: string[],
  signal?: AbortSignal,
): Promise<ScanResults> {
  // Wrap the entire scan in a stealth context so every downstream outbound
  // request inherits the mode's pacing/concurrency/User-Agent profile.
  return runWithStealth(mode, () => runScannersInner(target, type, mode, onProgress, onPhase, knownHosts, signal));
}

async function runScannersInner(
  target: string,
  type: string,
  mode: ScanMode,
  onProgress: ProgressFn,
  onPhase?: PhaseFn,
  knownHosts?: string[],
  signal?: AbortSignal,
): Promise<ScanResults> {
  const results: ScanResults = {
    easmResults: null,
    osintResults: null,
    nucleiResults: null,
    dastResults: null,
  };
  const scanOptions = { signal, mode, knownHosts };
  const gold = mode === "gold";

  /**
   * Tags a scanner's progress with which scanner it came from.
   *
   * The full-scan branch below has always done this so its four scanners can
   * share one 0-100 range. The single-type branches passed `onProgress`
   * straight through, so the SAME scanner reported `easm_takeover_check` in a
   * full scan and a bare `takeover_check` in an EASM-only one — one step
   * vocabulary or two depending on how the scan was started.
   *
   * Nothing consumed `currentStep` closely enough to notice until the live scan
   * view began deriving the running phase from it, at which point an EASM-only
   * scan showed every phase as "not started" while plainly running. Tagging
   * here keeps the vocabulary uniform; percentages are untouched, because a
   * single-type scan legitimately owns the whole range.
   */
  const tagged = (label: string, prefix: string): ProgressFn =>
    (m, p, st, e) => onProgress(`[${label}] ${m}`, p, `${prefix}_${st}`, e);

  if (type === "full") {
    const easmProgress: ProgressFn = (m, p, s, e) =>
      onProgress(`[EASM] ${m}`, Math.round(Math.min(40, (p * 40) / 100)), `easm_${s}`, e ? Math.ceil(e * 0.4) : undefined);
    results.easmResults = await runEASMScan(target, easmProgress, scanOptions);
    await onPhase?.(results); // persist EASM results live

    const osintProgress: ProgressFn = (m, p, s, e) =>
      onProgress(`[OSINT] ${m}`, Math.round(40 + (p * 40) / 100), `osint_${s}`, e ? Math.ceil(e * 0.4) : undefined);
    results.osintResults = await runOSINTScan(target, osintProgress, scanOptions);
    await onPhase?.(results); // persist OSINT results live

    const nucleiUrls = buildNucleiUrls(target, results.easmResults, gold);
    // Nuclei maps to overall 80→92 (OSINT ends at 80, so starting here avoids a
    // visible backwards jump).
    const nucleiProgress: ProgressFn = (m, p, s, e) =>
      onProgress(`[Nuclei] ${m}`, Math.round(80 + (p * 12) / 100), `nuclei_${s}`, e ? Math.ceil(e * 0.12) : undefined);
    try {
      results.nucleiResults = await runNucleiScan(target, nucleiUrls, nucleiProgress, { mode });
    } catch (nucleiErr) {
      log.warn({ err: nucleiErr }, "Nuclei scan unavailable (non-fatal) — install nuclei for full vulnerability scanning");
      results.nucleiResults = { findings: [], nucleiResults: [], skipped: true, reason: String(nucleiErr instanceof Error ? nucleiErr.message : nucleiErr) };
    }
    await onPhase?.(results); // persist Nuclei results live

    await onProgress("[DAST] Crawling for real endpoints...", 92, "dast_crawl");
    // Crawl BEFORE the active tests so they probe parameters the application
    // actually has. Without this the XSS and open-redirect checks fall back to
    // a hardcoded guess list and test endpoints the target does not serve.
    let injectionTargets: InjectionTarget[] = [];
    try {
      const crawl = await crawlSite(target);
      injectionTargets = crawl.parameterised.map((u) => ({ path: new URL(u.url).pathname, params: u.params }));
      const crawlSummary = {
        engine: crawl.engine,
        urls: crawl.urls.length,
        parameterised: crawl.parameterised.length,
        forms: crawl.forms.length,
        truncated: crawl.truncated,
      };
      results.crawlResults = crawlSummary;
      // Attach to the OSINT recon data so `buildReconModules` can surface it.
      // Left only on the local object it was dead data — written by the scan
      // and read by nothing, which is the failure mode this codebase documents.
      if (results.osintResults) results.osintResults.reconData.crawl = crawlSummary;
      log.info({ target, engine: crawl.engine, urls: crawl.urls.length, parameterised: crawl.parameterised.length }, "crawl fed the active tests");
    } catch (crawlErr) {
      log.warn({ err: crawlErr }, "crawl failed (non-fatal) — active tests fall back to their guess list");
    }

    await onProgress("[DAST] Running active security tests...", 94, "dast_start");
    try {
      results.dastResults = await runDASTScan(target, undefined, injectionTargets);
    } catch (dastErr) {
      log.warn({ err: dastErr }, "DAST-Lite scan failed (non-fatal)");
    }
    await onProgress("[DAST] Active testing complete", 97, "dast_done");
    await onPhase?.(results); // persist DAST results live
  } else if (type === "easm") {
    results.easmResults = await runEASMScan(target, tagged("EASM", "easm"), scanOptions);
    await onPhase?.(results);
  } else if (type === "dast") {
    await onProgress("[DAST] Running active security tests...", 10, "dast_start");
    try {
      results.dastResults = await runDASTScan(target);
    } catch (dastErr) {
      log.warn({ err: dastErr }, "DAST-Lite scan failed");
    }
    await onProgress("[DAST] Active testing complete", 100, "dast_done");
    await onPhase?.(results);
  } else if (type === "passive") {
    // Strictly non-intrusive recon — safe for targets where only passive
    // OSINT is authorized. Populates the osintResults slot (no active EASM).
    results.osintResults = await runPassiveScan(target, tagged("OSINT", "osint"), scanOptions);
    await onPhase?.(results);
  } else {
    results.osintResults = await runOSINTScan(target, tagged("OSINT", "osint"), scanOptions);
    await onPhase?.(results);
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

const assetKey = (a: RawAsset): string => `${a.type} ${a.value}`;

async function persistAssets(workspaceId: string, allAssets: RawAsset[], seen?: Set<string>): Promise<void> {
  for (const asset of allAssets) {
    const key = assetKey(asset);
    if (seen?.has(key)) continue; // already inserted this run — skip the DB round-trip
    try {
      // createAsset uses onConflictDoNothing — no need for a separate existence check
      await storage.createAsset({ workspaceId, type: asset.type, value: asset.value, status: "active", tags: asset.tags });
      seen?.add(key);
    } catch (err) {
      log.warn({ err }, "Failed to create asset");
    }
  }
}

// ── Finding Persistence ──

const findingKey = (f: RawFinding): string => `${f.title} ${f.affectedAsset ?? ""} ${f.category}`;

export interface WithheldFinding {
  title: string;
  category: string;
  affectedAsset: string;
  reason: string;
}

async function persistFindings(
  workspaceId: string,
  scanId: string,
  target: string,
  allFindings: RawFinding[],
  seen?: Set<string>,
  withheldSink?: WithheldFinding[],
): Promise<string[]> {
  const createdIds: string[] = [];

  // 1. Reduce to findings not already handled this run and not already in the DB —
  //    only these are probed, so the fail-closed gate never re-verifies prior-phase
  //    findings on each incremental persist.
  const fresh: RawFinding[] = [];
  const batchKeys = new Set<string>(); // dedup identical findings WITHIN this batch
  for (const f of allFindings) {
    const key = findingKey(f);
    if (seen?.has(key)) continue;
    if (batchKeys.has(key)) continue; // same title+asset+category already queued this batch
    try {
      const exists = await storage.findingExists(workspaceId, f.title, f.affectedAsset, f.category);
      if (exists) { seen?.add(key); continue; }
      batchKeys.add(key);
      fresh.push(f);
    } catch (err) {
      log.warn({ err, title: f.title }, "Finding existence check failed — will retry next phase");
    }
  }
  if (fresh.length === 0) return createdIds;

  // 2. Fail-closed verification gate: every fresh finding must have its evidence
  //    reproduced by a live probe, else it is withheld (never persisted). This is the
  //    single choke point that keeps false positives out of the DB, dashboard, and
  //    every report — regardless of target.
  let confirmed: RawFinding[] = fresh;
  try {
    const gate = await runVerificationGate(fresh, { target });
    confirmed = gate.confirmed;
    for (const w of gate.withheld) {
      // Mark withheld findings seen so they are not re-probed on later phases.
      seen?.add(findingKey({ title: w.title, affectedAsset: w.affectedAsset, category: w.category } as RawFinding));
      withheldSink?.push({ title: w.title, category: w.category, affectedAsset: w.affectedAsset, reason: w.reason });
    }
  } catch (err) {
    // If the gate itself fails, fail CLOSED: withhold this batch rather than persist
    // unverified findings. They will be retried (and re-gated) on the next phase.
    log.error({ err }, "Verification gate errored — withholding batch (fail-closed)");
    return createdIds;
  }

  // 3. Persist only the confirmed findings.
  for (const f of confirmed) {
    const key = findingKey(f);
    try {
      const created = await storage.createFinding({ ...f, workspaceId, scanId, status: "open" });
      createdIds.push(created.id);
      seen?.add(key); // mark seen only after a confirmed persist, so failures retry next phase
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
  withheld: WithheldFinding[] = [],
): Promise<void> {
  // Recon modules are rebuilt from the full accumulated results on each call
  // (findings/assets/recon populate live as each scan phase completes), so
  // clear this scan's prior modules first to avoid duplicates.
  try {
    await storage.deleteReconModulesByScan(scanId);
  } catch (err) {
    log.warn({ err }, "Failed to clear prior recon modules");
  }

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

  // ── Verification summary ──
  // The gate withholds findings whose evidence a live probe could not reproduce,
  // and until now it did so silently: the list existed only to keep withheld
  // findings out of the counts, then went out of scope. Persisting it turns the
  // work into something a reader can see — "we checked N, confirmed M, withheld
  // K and here is why" — and lets an operator audit a withholding they disagree
  // with instead of wondering why a finding they expected never appeared.
  try {
    await storage.createReconModule({
      workspaceId, scanId, target,
      moduleType: "verification_summary",
      data: {
        source: "Fail-closed verification gate",
        confirmedCount: Array.from(new Set(results.easmResults?.findings.map((f) => f.title) ?? [])).length
          + Array.from(new Set(results.osintResults?.findings.map((f) => f.title) ?? [])).length,
        withheldCount: withheld.length,
        withheld: withheld.slice(0, 100),
        verifiedAt: new Date().toISOString(),
      },
      confidence: 100,
    });
  } catch (err) {
    log.error({ err }, "Failed to create verification summary module");
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

    // Count distinct open ports across all discovered IPs (deduped per host:port).
    const openPortsByIp = (attackSurface?.openPortsByIp || {}) as Record<string, number[]>;
    const openPortsCount = Object.values(openPortsByIp)
      .reduce((sum, ports) => sum + (Array.isArray(ports) ? ports.length : 0), 0);

    await storage.createPostureSnapshot({
      workspaceId, scanId, target,
      snapshotAt: new Date(),
      surfaceRiskScore: attackSurface?.surfaceRiskScore as number | undefined ?? null,
      tlsGrade: tlsPosture?.grade ?? null,
      securityScore: allFindings.length > 0 ? computeSecurityScore(allFindings) : null,
      findingsCount: allFindings.length,
      criticalCount: allFindings.filter((f) => f.severity === "critical").length,
      highCount: allFindings.filter((f) => f.severity === "high").length,
      openPortsCount,
      wafCoverage,
      metadata: { mode },
    });
  } catch (err) {
    log.error({ err }, "Scan posture snapshot error");
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
const DOMAIN_REGEX = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/;
const VALID_SCAN_TYPES = ["full", "easm", "osint", "dast", "passive"];
const VALID_SCAN_MODES: ScanMode[] = ["standard", "gold", "safe"];

/**
 * How long a scan waits for a slot before giving up. Generous, because queueing
 * behind other scans is normal; failing fast would just push the retry onto the
 * user.
 */
const SLOT_WAIT_MS = Number(process.env.SCAN_SLOT_WAIT_MS ?? 20 * 60 * 1000);

export async function triggerScan(
  target: string,
  type: string,
  workspaceId: string,
  mode: string,
  opts: { autoGenerateReport?: boolean; aiEnrich?: boolean } = {},
): Promise<string> {
  // Defensive validation — route layer validates too, but this is also called by the scheduler
  const normalizedTarget = target.trim().toLowerCase().replace(/[./]+$/, "");
  if (!DOMAIN_REGEX.test(normalizedTarget)) {
    throw new Error("Invalid scan target domain");
  }
  if (!VALID_SCAN_TYPES.includes(type)) {
    throw new Error(`Invalid scan type: ${type}`);
  }

  const scan = await storage.createScan({
    workspaceId, target: normalizedTarget, type, status: "pending",
  });

  // Deliberately left "pending": the scan is not running until it holds a
  // global slot. Flipping to "running" here made the status a lie and hid the
  // fact that unbounded concurrent scans were all executing at once.

  const onProgress: ProgressFn = async (msg, percent, step, etaSeconds) => {
    await storage.updateScan(scan.id, {
      progressMessage: msg,
      progressPercent: Math.round(percent),
      currentStep: step,
      estimatedSecondsRemaining: etaSeconds != null ? Math.round(etaSeconds) : null,
    });
  };

  // Fire-and-forget the actual scan work, gated on a global concurrency slot.
  (async () => {
    // Wait for one of the MAX_CONCURRENT_SCANS slots shared across every
    // instance. Without this, N simultaneous requests ran N full scans, each
    // fanning out hundreds of DNS and HTTP requests.
    const slot = await acquireSlot({ timeoutMs: SLOT_WAIT_MS });
    if (!slot) {
      log.warn({ scanId: scan.id, target: normalizedTarget }, "No scan slot available before timeout");
      await storage.updateScan(scan.id, {
        status: "failed",
        completedAt: new Date(),
        errorMessage: `Server is at capacity (${MAX_CONCURRENT_SCANS} concurrent scans). Please retry shortly.`,
      }).catch(() => { /* best effort */ });
      return;
    }

    try {
      await storage.updateScan(scan.id, { status: "running", startedAt: new Date() });
      const scanMode: ScanMode = VALID_SCAN_MODES.includes(mode as ScanMode) ? (mode as ScanMode) : "standard";

      // ── Live persistence ──
      // Persist findings/assets/recon after EACH scan phase so the dashboard
      // fills up in real time instead of only at completion. persistFindings
      // dedups and storeReconModules replaces this scan's modules, so repeated
      // calls with the growing result set are idempotent.
      const createdFindingIds = new Set<string>();
      const seenFindingKeys = new Set<string>();
      const seenAssetKeys = new Set<string>();
      const withheldFindings: WithheldFinding[] = [];
      let lastFindings: RawFinding[] = [];
      let phaseRan = false;
      const persistProgress: PhaseFn = async (partial) => {
        phaseRan = true;
        const rawFindings: RawFinding[] = [
          ...(partial.easmResults?.findings ?? []),
          ...(partial.osintResults?.findings ?? []),
          ...(partial.nucleiResults?.findings ?? []),
          ...(partial.dastResults?.findings ?? []),
        ];
        let allFindings: RawFinding[] = rawFindings;
        try {
          // Elevate KEV-referenced findings to critical (evidence-backed).
          allFindings = await correlateExploitability(rawFindings);
        } catch (err) {
          log.warn({ err }, "CVE/KEV correlation failed — using un-elevated findings");
        }
        lastFindings = allFindings;
        const allAssets: RawAsset[] = [
          ...(partial.easmResults?.assets ?? []),
          ...(partial.osintResults?.assets ?? []),
        ];
        try {
          // seen-sets skip already-persisted items so later phases add no
          // redundant DB round-trips (findings/assets fill up incrementally).
          await persistAssets(workspaceId, allAssets, seenAssetKeys);
          const ids = await persistFindings(workspaceId, scan.id, target, allFindings, seenFindingKeys, withheldFindings);
          ids.forEach((id) => createdFindingIds.add(id));
          await storage.updateScan(scan.id, { findingsCount: seenFindingKeys.size });
        } catch (err) {
          log.warn({ err }, "Incremental persist failed (will retry next phase)");
        }
      };

      // Change-detection baseline: the hosts this workspace already knew about.
      //
      // Left undefined when the workspace has never completed a scan. That is a
      // third state, not an empty baseline — with nothing to compare against,
      // every host would be labelled "new", which is true and useless.
      // `newSinceLastRun` was hardcoded false before this, so the UI's
      // "New Since Last Run" counter and per-host New/Known badge always read
      // Known no matter what had appeared.
      let knownHosts: string[] | undefined;
      try {
        const { data: priorScans } = await storage.getScans(workspaceId, { limit: 5, offset: 0 });
        if (priorScans.some((s) => s.status === "completed" && s.id !== scan.id)) {
          const { data: priorAssets } = await storage.getAssets(workspaceId, { limit: 10000, offset: 0 });
          knownHosts = priorAssets
            .filter((a) => a.type === "subdomain" || a.type === "domain")
            .map((a) => a.value.toLowerCase());
          log.info({ workspaceId, baseline: knownHosts.length }, "change-detection baseline loaded");
        } else {
          log.info({ workspaceId }, "no completed prior scan — change detection has no baseline this run");
        }
      } catch (err) {
        // A failed lookup must leave this undefined, so the scan reports
        // "no baseline" rather than inventing one and calling every host new.
        log.warn({ err, workspaceId }, "could not load change-detection baseline");
      }

      // Registered for the duration so a cancel request can reach this scan.
      const controller = new AbortController();
      inFlight.set(scan.id, controller);
      let results: ScanResults;
      try {
        results = await runScanners(target, type, scanMode, onProgress, persistProgress, knownHosts, controller.signal);
      } finally {
        inFlight.delete(scan.id);
      }

      // Safety net only if no phase ever fired the callback.
      if (!phaseRan) {
        await persistProgress(results);
      }

      // Recon modules are built ONCE from the final result set — they involve
      // external BGP lookups and a full delete/re-insert, so doing it per phase
      // would 4x the external calls and briefly blank the dashboard cards.
      try {
        await storeReconModules(workspaceId, scan.id, target, results, type, withheldFindings);
      } catch (err) {
        log.warn({ err }, "Recon module storage failed");
      }

      const mergedSubdomains = Array.from(new Set([
        ...(results.easmResults?.subdomains ?? []),
        ...(results.osintResults?.subdomains ?? []),
      ]));

      // Consistent counts from the DISTINCT accumulated finding set (so
      // findingsGenerated always agrees with critical/high counts). Findings withheld
      // by the verification gate are excluded — they were never persisted, so they
      // must not inflate the summary, severity counts, or the posture snapshot.
      const withheldKeys = new Set(withheldFindings.map((w) =>
        findingKey({ title: w.title, affectedAsset: w.affectedAsset, category: w.category } as RawFinding)));
      const distinctFindings = Array.from(new Map(lastFindings.map((f) => [findingKey(f), f])).values())
        .filter((f) => !withheldKeys.has(findingKey(f)));
      const findingsTotal = distinctFindings.length;

      await storage.updateScan(scan.id, {
        status: "completed",
        completedAt: new Date(),
        findingsCount: findingsTotal,
        progressMessage: null,
        progressPercent: null,
        currentStep: null,
        estimatedSecondsRemaining: null,
        summary: {
          assetsDiscovered: seenAssetKeys.size,
          findingsGenerated: findingsTotal,
          criticalCount: distinctFindings.filter((f) => f.severity === "critical").length,
          highCount: distinctFindings.filter((f) => f.severity === "high").length,
          subdomainsFound: mergedSubdomains.length,
          verifiedOnly: true,
          withheldCount: withheldFindings.length,
          mode: scanMode,
        },
      });

      await createPostureSnapshot(workspaceId, scan.id, target, scanMode, distinctFindings);

      const updatedScan = await storage.getScan(scan.id);
      if (updatedScan) {
        emitScanCompleted(updatedScan, findingsTotal).catch((err) =>
          log.warn({ err }, "Failed to emit scan completed alert"));
      }

      /*
       * Auto-generate the report the operator asked for.
       *
       * `autoGenerateReport` was accepted by the request schema, sent by the
       * dashboard's checkbox, and read by NOTHING — and the UI said so out
       * loud: ticking it produced a toast reading "(report will be
       * auto-generated)" and no report was ever created. Same defect as
       * `api_keys.scope` and `scan_profiles.isDefault`, except this one stated
       * the promise to the user's face.
       *
       * Not awaited, and its failure is logged rather than thrown: a report
       * that could not be built must not turn a completed scan into a failed
       * one. The scope is left to `selectReportFindings` — no `findingIds`
       * means "this workspace's outstanding exposure".
       */
      if (opts.autoGenerateReport) {
        void (async () => {
          try {
            const report = await storage.createReport({
              workspaceId,
              title: `${normalizedTarget} — automatic report`,
              type: "full_report",
              status: "generating",
            });
            const { buildReportContent } = await import("./routes/report-helpers.js");
            const { content, summary } = await buildReportContent(workspaceId, undefined, "full_report");
            await storage.updateReport(report.id, {
              status: "completed",
              content,
              summary,
              generatedAt: new Date(),
            });
            log.info({ scanId: scan.id, reportId: report.id }, "Auto-generated report for completed scan");
          } catch (err) {
            log.warn({ err, scanId: scan.id }, "Auto report generation failed");
          }
        })();
      }

      runBackgroundEnrichment(workspaceId).catch((err) =>
        log.warn({ err }, "Background enrichment failed"));

      // Auto threat-intel enrichment: if API keys were saved during this scan (after
      // its inline enrichment step), retroactively fill the recon module now. No-op
      // when no keyed provider is configured. Reads keys live; caches were cleared on
      // any mid-scan key save.
      reEnrichWorkspaceThreatIntel(workspaceId).catch((err) =>
        log.warn({ err }, "Auto re-enrichment failed"));

      /*
       * AI-enriched scan: the operator asked for GLM to verify and synthesize
       * on top of this scan, not just discover. Same choke point as the other
       * two post-completion steps above, and the same function the manual
       * "Generate" button and the Intelligence panel use — one implementation
       * of "what does this workspace's AI insights say right now", regardless
       * of what triggered it.
       *
       * Not awaited: a slow or rate-limited GLM call must not hold a scan in
       * "completing" state, the same reasoning as auto-report generation
       * above. Runs after `runBackgroundEnrichment` so the per-finding
       * enrichment it does is available as extra context if GLM reads it.
       */
      if (opts.aiEnrich) {
        void generateAndPersistWorkspaceInsights(workspaceId, { knownTarget: normalizedTarget }).catch((err) =>
          log.warn({ err, scanId: scan.id }, "AI-enriched scan: insights generation failed"));
      }
    } catch (err) {
      log.error({ err }, "Scan processing error");
      // Surface a friendly, non-leaky message to the user (raw error stays in
      // the server log above). Detect the common unreachable/invalid-target case.
      const raw = err instanceof Error ? err.message : String(err);
      // A cancellation is not a failure. Recording it as one puts a deliberate
      // operator action into the failure count every dashboard and alert reads,
      // and tells the person who pressed the button that something went wrong.
      const cancelled = /aborted/i.test(raw);
      const friendly = /ENOTFOUND|EAI_AGAIN|ENODATA|getaddrinfo|querya/i.test(raw)
        ? "Scan failed — the target domain could not be resolved. Verify the domain is spelled correctly and publicly reachable, then retry."
        : cancelled
          ? "Scan was cancelled."
          : "Scan failed due to an internal error. Please retry; if it persists, contact support.";
      try {
        await storage.updateScan(scan.id, {
          status: cancelled ? "cancelled" : "failed",
          completedAt: new Date(),
          errorMessage: friendly,
          progressMessage: null,
          progressPercent: null,
          currentStep: null,
          estimatedSecondsRemaining: null,
        });

        // No failure alert for a cancellation: the operator who cancelled does
        // not need paging about their own action, and a SIEM should not see it
        // as an incident.
        const finalScan = await storage.getScan(scan.id);
        if (finalScan && !cancelled) {
          emitScanFailed(finalScan, err instanceof Error ? err.message : String(err))
            .catch((alertErr) => log.warn({ err: alertErr }, "Failed to emit scan failed alert"));
        }
      } catch (updateErr) {
        log.error({ err: updateErr }, "CRITICAL: Failed to record the scan's final status");
      }
    } finally {
      // Always hand the slot back, including when the scan threw — otherwise
      // capacity leaks away one failed scan at a time.
      await slot.release();
    }
  })().catch((err) => {
    log.error({ err }, "Unhandled scan error");
  });

  return scan.id;
}
