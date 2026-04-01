import { spawn } from "child_process";
import fs from "fs/promises";
import os from "os";
import path from "path";
import { checkCISAKEV } from "../cve-service.js";
import { createLogger } from "../logger.js";
import type { ScanProgressCallback, ScanOptions } from "./types.js";

const log = createLogger("scanner");

interface EvidenceItem {
  [key: string]: unknown;
  type: string;
  description: string;
  url?: string;
  snippet?: string;
  source?: string;
  verifiedAt?: string;
  raw?: Record<string, unknown>;
}

interface VerifiedFinding {
  title: string;
  description: string;
  severity: string;
  category: string;
  affectedAsset: string;
  cvssScore: string;
  remediation: string;
  evidence: EvidenceItem[];
}

export interface NucleiHit {
  templateId: string;
  templateName?: string;
  severity: string;
  host: string;
  matchedAt?: string;
  type?: string;
  info?: { name?: string; description?: string };
  matcherName?: string;
  extractedResults?: string[];
}

export interface NucleiScanResult {
  findings: VerifiedFinding[];
  nucleiResults: NucleiHit[];
  templateCount?: number;
  skipped?: boolean;
  reason?: string;
}

function checkAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new Error("Scan aborted");
}

export async function runNucleiScan(
  domain: string,
  urls: string[],
  onProgress?: ScanProgressCallback,
  options?: ScanOptions,
): Promise<NucleiScanResult> {
  const signal = options?.signal;
  const report = async (msg: string, pct: number, step: string, eta?: number) => {
    checkAborted(signal);
    if (onProgress) await onProgress(msg, pct, step, eta);
  };

  const targetUrls = Array.from(new Set(urls.length > 0 ? urls : [`https://${domain}`, `http://${domain}`]));
  const targetUrlsNormalized = targetUrls.map((u) => {
    try {
      const parsed = new URL(u.startsWith("http") ? u : `https://${u}`);
      return parsed.origin;
    } catch {
      return u.startsWith("http") ? u : `https://${u}`;
    }
  });

  const goBin = path.join(os.homedir(), "go", "bin");
  const pathWithGo = [goBin, process.env.PATH].filter(Boolean).join(path.delimiter);
  const spawnEnv = { ...process.env, PATH: pathWithGo };

  const checkNuclei = (nucleiPath: string): Promise<boolean> =>
    new Promise((resolve) => {
      let proc: ReturnType<typeof spawn> | null = null;
      const timeout = setTimeout(() => {
        try { proc?.kill(); } catch {}
        resolve(false);
      }, 5000);
      try {
        proc = spawn(nucleiPath, ["-version"], { stdio: ["ignore", "pipe", "pipe"], env: spawnEnv });
      } catch {
        clearTimeout(timeout);
        resolve(false);
        return;
      }
      proc.stdout?.on("data", () => {});
      proc.stderr?.on("data", () => {});
      proc.on("close", (code) => { clearTimeout(timeout); resolve(code === 0); });
      proc.on("error", () => { clearTimeout(timeout); resolve(false); });
    });

  let nucleiPath: string | null = null;
  if (await checkNuclei("nuclei")) {
    nucleiPath = "nuclei";
  } else {
    const altPath = path.join(goBin, "nuclei");
    if (await checkNuclei(altPath)) {
      nucleiPath = altPath;
    }
  }
  if (!nucleiPath) {
    throw new Error(
      "Nuclei is required for full scans but is not installed or not in PATH. " +
      "Use Docker: docker compose up -d (app image includes Nuclei). " +
      "Or install locally: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    );
  }

  const isGoldScan = options?.mode === "gold";
  // Standard: 8 min cap (severity + http-only); Gold: 30 min full scan
  const NUCLEI_MAX_DURATION_MS = isGoldScan ? 30 * 60 * 1000 : 8 * 60 * 1000;
  await report(`Running Nuclei scan against ${targetUrls.length} target(s)...`, 0, "nuclei_scan", 300);
  const tempFile = path.join(os.tmpdir(), `nuclei-targets-${Date.now()}-${Math.random().toString(36).slice(2)}.txt`);
  try {
    await fs.writeFile(tempFile, targetUrlsNormalized.join("\n"), "utf-8");
  } catch (err) {
    log.error({ err }, "Failed to write Nuclei targets file");
    throw new Error("Failed to write Nuclei targets file: " + (err instanceof Error ? err.message : String(err)));
  }

  const nucleiResults: NucleiHit[] = [];
  const findings: VerifiedFinding[] = [];
  const now = new Date().toISOString();

  let procRef: ReturnType<typeof spawn> | null = null;
  const nucleiPromise = new Promise<NucleiScanResult>((resolve, reject) => {
    const args = [
      "-l", tempFile, "-jsonl", "-silent", "-no-color",
      "-timeout", "30",
      "-rate-limit", isGoldScan ? "150" : "100",
      "-bulk-size", isGoldScan ? "25" : "15",
      "-concurrency", isGoldScan ? "25" : "15",
      // Standard: targeted template dirs (~2.5k templates) — fast + relevant for EASM
      // Gold: all templates, all severities (full 12k+ templates)
      ...(isGoldScan
        ? []
        : ["-t", "http/technologies/", "-t", "http/misconfiguration/", "-t", "http/exposures/"]),
    ];
    const proc = spawn(nucleiPath, args, { stdio: ["ignore", "pipe", "pipe"], env: spawnEnv });
    procRef = proc;
    let buffer = "";
    let templatesSeen = 0;
    let lastProgressReport = Date.now();

    proc.stdout?.on("data", (chunk: Buffer) => {
      buffer += chunk.toString();
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const j = JSON.parse(line) as Record<string, unknown>;
          const templateId = String(j["template-id"] ?? j.templateID ?? "");
          const info = j.info as Record<string, unknown> | undefined;
          const hit: NucleiHit = {
            templateId,
            templateName: (info?.name as string) ?? (j["template-name"] as string),
            severity: String(info?.severity ?? j.severity ?? "info").toLowerCase(),
            host: String(j.host ?? j["matched-at"] ?? ""),
            matchedAt: j["matched-at"] ? String(j["matched-at"]) : (j.matched ? String(j.matched) : undefined),
            type: j.type as string | undefined,
            info: info ? { name: info.name as string, description: info.description as string } : undefined,
            matcherName: j["matcher-name"] as string | undefined,
            extractedResults: j["extracted-results"] as string[] | undefined,
          };
          nucleiResults.push(hit);
          templatesSeen++;

          // Report progress every 30 seconds
          const now2 = Date.now();
          if (now2 - lastProgressReport > 30000) {
            lastProgressReport = now2;
            report(`Nuclei scanning... ${templatesSeen} template hit(s) so far on ${targetUrls.length} target(s)`, 50, "nuclei_scan").catch(() => {});
          }

          const severityMap: Record<string, string> = {
            critical: "critical",
            high: "high",
            medium: "medium",
            low: "low",
            info: "info",
          };
          const severity = severityMap[hit.severity] ?? "info";
          // Many Nuclei template IDs encode the CVE directly, e.g. "CVE-2021-44228"
          const cveMatch = templateId.match(/\b(CVE-\d{4}-\d+)\b/i);
          const detectedCveId = cveMatch ? cveMatch[1].toUpperCase() : undefined;
          findings.push({
            title: `${(info?.name as string) ?? templateId} on ${hit.host}`,
            description: (info?.description as string) ?? `Nuclei template ${templateId} matched at ${hit.host}`,
            severity,
            category: "vulnerability",
            affectedAsset: hit.host,
            cvssScore: severity === "critical" ? "9.0" : severity === "high" ? "7.5" : severity === "medium" ? "5.5" : "3.0",
            remediation: "Review the vulnerability and apply patches or mitigations as recommended by the template.",
            evidence: [
              {
                type: "nuclei",
                description: `Nuclei template ${templateId} matched`,
                snippet: hit.matchedAt ? `Matched at: ${hit.matchedAt}` : hit.templateName ?? templateId,
                source: "Nuclei scanner",
                verifiedAt: now,
                ...(detectedCveId ? { cveId: detectedCveId } : {}),
              },
            ],
          });
        } catch {
          // Skip malformed JSONL lines
        }
      }
    });

    let stderrBuf = "";
    proc.stderr?.on("data", (d) => {
      stderrBuf += d.toString();
      const lines = stderrBuf.split("\n");
      stderrBuf = lines.pop() ?? "";
      for (const line of lines) {
        const clean = line.replace(/\x1b\[[0-9;]*m/g, "").trim(); // strip ANSI codes
        if (!clean) continue;
        // Show nuclei template load/scan progress
        if (clean.includes("templates") || clean.includes("Executing") || clean.includes("INF")) {
          log.info({ line: clean }, "Nuclei progress");
        }
      }
    });

    proc.on("close", (code, sig) => {
      fs.unlink(tempFile).catch(() => {});
      if (signal?.aborted) {
        reject(new Error("Scan aborted"));
        return;
      }
      if (code !== 0 && code !== null && nucleiResults.length === 0) {
        log.warn({ code, signal: sig }, "Nuclei exited with non-zero code");
      }
      resolve({
        findings,
        nucleiResults,
        templateCount: nucleiResults.length,
      });
    });

    proc.on("error", (err) => {
      fs.unlink(tempFile).catch(() => {});
      reject(err);
    });

    signal?.addEventListener?.("abort", () => {
      try {
        proc.kill("SIGTERM");
      } catch {}
    });
  });

  let timeoutId: ReturnType<typeof setTimeout> | null = null;
  const timeoutPromise = new Promise<NucleiScanResult>((resolve) => {
    timeoutId = setTimeout(() => {
      timeoutId = null;
      if (procRef) {
        log.warn({ maxMinutes: Math.round(NUCLEI_MAX_DURATION_MS / 60000) }, "Nuclei scan exceeded max duration, terminating");
        try {
          procRef.kill("SIGTERM");
          // Give 3s for graceful shutdown before SIGKILL
          setTimeout(() => { try { procRef?.kill("SIGKILL"); } catch {} }, 3000);
        } catch {}
      }
      // Wait 4s for final stdout flush before resolving
      setTimeout(() => {
        procRef = null;
        fs.unlink(tempFile).catch(() => {});
        resolve({
          findings,
          nucleiResults,
          templateCount: nucleiResults.length,
        });
      }, 4000);
    }, NUCLEI_MAX_DURATION_MS);
  });

  const result = await Promise.race([nucleiPromise, timeoutPromise]).finally(() => {
    if (timeoutId) clearTimeout(timeoutId);
  });

  // Enrich Nuclei findings that contain a CVE ID with CISA KEV data
  const kevEnrichments = result.findings.map(async (finding) => {
    const evidence = finding.evidence ?? [];
    for (const ev of evidence) {
      const cveId = ev.cveId as string | undefined;
      if (!cveId) continue;
      try {
        const kevInfo = await checkCISAKEV(cveId);
        if (kevInfo?.inKEV) {
          ev.kev = {
            inKEV: true,
            dueDate: kevInfo.dueDate,
            knownRansomware: kevInfo.knownRansomware,
            notes: kevInfo.notes,
          };
          // Flag the finding description so it's visible without drilling into evidence
          finding.description = `[CISA KEV] ${finding.description}`;
        }
      } catch {
        // KEV enrichment failure is non-fatal
      }
    }
  });
  await Promise.allSettled(kevEnrichments);

  return result;
}
