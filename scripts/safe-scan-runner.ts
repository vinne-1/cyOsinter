/**
 * Standalone SAFE-MODE full-coverage scan runner.
 *
 * Drives the scanner modules directly (no DB / HTTP server / queue) so a
 * complete OSINT + EASM pass can run headless and dump results to JSON. Wraps
 * everything in the "safe" stealth context so all outbound HTTP is rate-limited,
 * jittered, and uses rotating browser User-Agents.
 *
 * Nuclei is intentionally skipped here (local scoop build hangs; Docker image
 * unavailable in this environment) — EASM + OSINT + DAST-Lite still provide
 * comprehensive coverage. Usage: npx tsx scripts/safe-scan-runner.ts <domain> [outfile]
 */

import fs from "fs/promises";
import { appendFileSync } from "node:fs";
import { runWithStealth } from "../server/scanner/stealth.js";
import { runEASMScan } from "../server/scanner/easm-scan.js";
import { runOSINTScan } from "../server/scanner/osint-scan.js";
import { runDASTScan } from "../server/scanner/dast-lite.js";
import { buildReconModules } from "../server/scanner/recon-builder.js";

const rawArg = process.argv[2] ?? "procellbiologics.com";
const domain = rawArg.replace(/^https?:\/\//i, "").replace(/\/.*$/, "").replace(/[./]+$/, "").toLowerCase();
const outFile = process.argv[3] ?? `scan-${domain}.json`;
const logFile = process.argv[4] ?? outFile.replace(/\.json$/, "") + ".log";

function ts() {
  return new Date().toISOString().replace("T", " ").replace(/\..+/, "");
}
// Write progress to a FILE, never stdout — a detached run must not deadlock on
// a stdout pipe whose reader has gone away.
function log(s: string) {
  try { appendFileSync(logFile, s + "\n"); } catch { /* ignore */ }
}
const progress = async (msg: string, pct: number, step: string) => {
  log(`[${ts()}] ${String(pct).padStart(3)}% ${step.padEnd(24)} ${msg}`);
};

type ScanRes = Awaited<ReturnType<typeof runEASMScan>>;
type DastRes = Awaited<ReturnType<typeof runDASTScan>>;

async function main() {
  const startedAt = Date.now();
  log(`\n=== SAFE-MODE full-coverage scan: ${domain} @ ${ts()} ===\n`);

  // Heartbeat so liveness is visible even during silent phases (e.g. the
  // directory brute-force, which emits no per-request progress).
  let currentPhaseLabel = "init";
  const heartbeat = setInterval(() => {
    log(`  [hb ${ts()}] alive | elapsed=${Math.round((Date.now() - startedAt) / 1000)}s | phase=${currentPhaseLabel}`);
  }, 30000);
  heartbeat.unref?.();

  // Outer-scope state so we can flush a partial report after EACH phase — a
  // safe-mode full scan is slow, so we never want to lose completed work.
  let easm: ScanRes | null = null;
  let osint: ScanRes | null = null;
  let dast: DastRes | null = null;
  let reconModules: unknown[] = [];
  let phase = "starting";

  const flush = async () => {
    let recon: unknown[] = reconModules;
    try {
      recon = await buildReconModules(domain, easm, osint);
      reconModules = recon;
    } catch { /* keep last */ }
    const allFindings = [
      ...(easm?.findings ?? []),
      ...(osint?.findings ?? []),
      ...(dast?.findings ?? []).map((f) => ({ ...f, cvssScore: (f as { cvssScore?: string }).cvssScore ?? "" })),
    ];
    const output = {
      target: domain,
      mode: "safe",
      lastPhaseCompleted: phase,
      generatedAt: new Date().toISOString(),
      durationSeconds: Math.round((Date.now() - startedAt) / 1000),
      nucleiSkipped: true,
      nucleiSkipReason: "scoop nuclei hangs; Docker image unavailable in this environment",
      summary: {
        subdomains: easm?.subdomains?.length ?? 0,
        assets: (easm?.assets?.length ?? 0) + (osint?.assets?.length ?? 0),
        findings: allFindings.length,
        reconModules: recon.length,
        dastFindings: dast?.findings?.length ?? 0,
      },
      subdomains: easm?.subdomains ?? [],
      easmAssets: easm?.assets ?? [],
      osintAssets: osint?.assets ?? [],
      findings: allFindings,
      easmReconData: easm?.reconData ?? {},
      osintReconData: osint?.reconData ?? {},
      dast,
      reconModules: recon,
    };
    await fs.writeFile(outFile, JSON.stringify(output, null, 2), "utf-8");
    log(`  [flush] phase=${phase} findings=${output.summary.findings} subs=${output.summary.subdomains} @ ${ts()}`);
  };

  await runWithStealth("safe", async () => {
    const opts = { mode: "safe" as const };

    try {
      log("\n--- EASM (safe) ---");
      currentPhaseLabel = "easm";
      easm = await runEASMScan(domain, progress, opts);
      phase = "easm";
    } catch (err) {
      log("EASM failed: " + (err instanceof Error ? err.stack ?? err.message : String(err)));
    }
    await flush();

    try {
      log("\n--- OSINT (safe) ---");
      currentPhaseLabel = "osint";
      osint = await runOSINTScan(domain, progress, opts);
      phase = "osint";
    } catch (err) {
      log("OSINT failed: " + (err instanceof Error ? err.stack ?? err.message : String(err)));
    }
    await flush();

    try {
      log("\n--- DAST-Lite (safe) ---");
      currentPhaseLabel = "dast";
      dast = await runDASTScan(domain);
      phase = "dast";
    } catch (err) {
      log("DAST failed: " + (err instanceof Error ? err.stack ?? err.message : String(err)));
    }
    phase = "complete";
    await flush();
  });

  clearInterval(heartbeat);
  log(`\n=== DONE in ${Math.round((Date.now() - startedAt) / 1000)}s @ ${ts()} ===`);
}

main().then(() => process.exit(0)).catch((err) => {
  log("FATAL: " + (err instanceof Error ? err.stack ?? err.message : String(err)));
  process.exit(1);
});
