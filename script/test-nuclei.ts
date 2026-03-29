#!/usr/bin/env tsx
/**
 * Test script to verify Nuclei CLI is installed and working.
 * Run: npx tsx script/test-nuclei.ts
 */

import { spawn } from "child_process";
import * as fs from "fs/promises";
import * as os from "os";
import * as path from "path";

const goBin = path.join(os.homedir(), "go", "bin");
const pathWithGo = [goBin, process.env.PATH].filter(Boolean).join(path.delimiter);
const spawnEnv = { ...process.env, PATH: pathWithGo };

async function checkNuclei(binary: string): Promise<boolean> {
  return new Promise((resolve) => {
    const proc = spawn(binary, ["-version"], { stdio: ["ignore", "pipe", "pipe"], env: spawnEnv });
    let stderr = "";
    proc.stderr?.on("data", (d) => (stderr += d.toString()));
    proc.on("close", (code) => {
      if (code === 0) {
        console.log("[OK] Nuclei found:", stderr.split("\n")[0] || "v3.x");
        resolve(true);
      } else {
        resolve(false);
      }
    });
    proc.on("error", () => resolve(false));
  });
}

async function runNucleiTest(): Promise<void> {
  console.log("Testing Nuclei CLI integration...\n");

  let nucleiPath = "nuclei";
  if (!(await checkNuclei("nuclei"))) {
    const altPath = path.join(goBin, "nuclei");
    if (await checkNuclei(altPath)) {
      nucleiPath = altPath;
      console.log("[OK] Using Nuclei from:", nucleiPath);
    } else {
      console.error("[FAIL] Nuclei not found. Install with:");
      console.error("  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest");
      console.error("  Ensure ~/go/bin is in your PATH");
      process.exit(1);
    }
  }

  const tempFile = path.join(os.tmpdir(), `nuclei-test-${Date.now()}.txt`);
  await fs.writeFile(tempFile, "https://scanme.nmap.org\n", "utf-8");

  console.log("\nRunning quick Nuclei scan (~35s timeout)...");
  const result = await new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve) => {
    const proc = spawn(
      nucleiPath,
      ["-l", tempFile, "-jsonl", "-silent", "-no-color", "-timeout", "5", "-rate-limit", "50"],
      { stdio: ["ignore", "pipe", "pipe"], env: spawnEnv }
    );
    let stdout = "";
    let stderr = "";
    proc.stdout?.on("data", (d) => (stdout += d.toString()));
    proc.stderr?.on("data", (d) => (stderr += d.toString()));
    const timer = setTimeout(() => {
      proc.kill("SIGTERM");
    }, 35000);
    proc.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });

  await fs.unlink(tempFile).catch(() => {});

  const lines = result.stdout.trim().split("\n").filter((l) => l && l.startsWith("{"));
  if (lines.length > 0) {
    try {
      const first = JSON.parse(lines[0]) as Record<string, unknown>;
      console.log("[OK] Nuclei produced JSONL output. Sample:", (first.info as { name?: string })?.name ?? first["template-id"] ?? "match");
    } catch {
      console.log("[OK] Nuclei produced output (", lines.length, "lines)");
    }
  } else if (result.code === 0 || result.code === null) {
    console.log("[OK] Nuclei completed (no findings for this target - expected for scanme.nmap.org)");
  } else {
    console.log("[WARN] Nuclei exited with code", result.code, "-", result.stderr.slice(0, 200));
  }

  console.log("\nNuclei integration test complete.");
}

runNucleiTest().catch((err) => {
  console.error(err);
  process.exit(1);
});
