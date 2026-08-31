/**
 * Unit tests for server/scanner/nuclei.ts
 *
 * We test the internal `checkNuclei` timeout behavior by mocking `child_process.spawn`
 * so that the spawned process never emits events and the 5-second timeout fires.
 * We observe this indirectly via runNucleiScan which skips to the "not installed" error
 * after all checkNuclei probes return false.
 *
 * We also test the scan-abort behaviour and the JSONL parsing pipeline by having the
 * mock process emit synthetic stdout data and close normally.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { ChildProcess } from "child_process";
import { EventEmitter } from "events";

// ---------------------------------------------------------------------------
// Helper — build a fake ChildProcess that behaves like spawn(nuclei, [...])
// ---------------------------------------------------------------------------
function makeFakeProc(overrides: Partial<{
  stdoutData: string[];
  closeCode: number;
  errorOnSpawn: Error;
  delayCloseMs: number;
}> = {}): ChildProcess {
  const proc = new EventEmitter() as ChildProcess;
  const stdout = new EventEmitter();
  const stderr = new EventEmitter();
  (proc as any).stdout = stdout;
  (proc as any).stderr = stderr;
  (proc as any).kill = vi.fn(() => {
    setTimeout(() => proc.emit("close", null, "SIGTERM"), 10);
  });

  if (overrides.errorOnSpawn) {
    setTimeout(() => proc.emit("error", overrides.errorOnSpawn), 0);
  } else {
    const delay = overrides.delayCloseMs ?? 0;
    setTimeout(() => {
      if (overrides.stdoutData) {
        for (const chunk of overrides.stdoutData) {
          stdout.emit("data", Buffer.from(chunk));
        }
      }
      setTimeout(() => {
        proc.emit("close", overrides.closeCode ?? 0, null);
      }, delay);
    }, 5);
  }

  return proc;
}

// ---------------------------------------------------------------------------
// Mock child_process so we control what spawn returns
// ---------------------------------------------------------------------------
const spawnMock = vi.fn();

vi.mock("child_process", () => ({
  spawn: (...args: unknown[]) => spawnMock(...args),
}));

// Also mock fs/promises so writeFile / unlink don't touch the filesystem
vi.mock("fs/promises", () => ({
  default: {
    writeFile: vi.fn().mockResolvedValue(undefined),
    unlink: vi.fn().mockResolvedValue(undefined),
  },
  writeFile: vi.fn().mockResolvedValue(undefined),
  unlink: vi.fn().mockResolvedValue(undefined),
}));

// Mock cve-service to avoid network calls
vi.mock("../../../server/cve-service", () => ({
  checkCISAKEV: vi.fn().mockResolvedValue(null),
}));

// ---------------------------------------------------------------------------
// checkNuclei timeout: spawn hangs and the 5-second timeout resolves false
// ---------------------------------------------------------------------------
describe("checkNuclei — timeout behaviour", () => {
  beforeEach(() => {
    spawnMock.mockReset();
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("throws 'not installed' error when nuclei probe times out", async () => {
    // Return a process that NEVER emits close/error — triggering the 5s timeout
    spawnMock.mockImplementation(() => {
      const proc = new EventEmitter() as ChildProcess;
      (proc as any).stdout = new EventEmitter();
      (proc as any).stderr = new EventEmitter();
      (proc as any).kill = vi.fn(() => {
        // After kill, simulate the process eventually closing (after timeout fires)
        setImmediate(() => proc.emit("close", null, "SIGTERM"));
      });
      return proc;
    });

    const { runNucleiScan } = await import("../../../server/scanner/nuclei");

    // Attach rejection handler immediately to prevent unhandled rejection warning
    const scanPromise = runNucleiScan("example.com", []);
    const rejectedPromise = expect(scanPromise).rejects.toThrow("Nuclei is required");

    // Advance past the 5-second checkNuclei timeout for every probed candidate.
    // Detection probes a deduped list (resolved path, "nuclei", go-bin variants),
    // each with a 5s timeout, tried sequentially — advance generously to cover all.
    await vi.advanceTimersByTimeAsync(5000 * 6 + 500);

    await rejectedPromise;
  });
});

// ---------------------------------------------------------------------------
// checkNuclei — nuclei exits non-zero (not found on PATH)
// ---------------------------------------------------------------------------
describe("checkNuclei — process error behaviour", () => {
  beforeEach(() => {
    spawnMock.mockReset();
  });

  it("throws 'not installed' when nuclei exits with code 1", async () => {
    // Emit close with code 1 — checkNuclei resolves false
    spawnMock.mockImplementation(() => makeFakeProc({ closeCode: 1 }));

    const { runNucleiScan } = await import("../../../server/scanner/nuclei");
    await expect(runNucleiScan("example.com", [])).rejects.toThrow("Nuclei is required");
  });

  it("throws 'not installed' when nuclei emits an error event", async () => {
    spawnMock.mockImplementation(() =>
      makeFakeProc({ errorOnSpawn: new Error("ENOENT") }),
    );

    const { runNucleiScan } = await import("../../../server/scanner/nuclei");
    await expect(runNucleiScan("example.com", [])).rejects.toThrow("Nuclei is required");
  });
});

// ---------------------------------------------------------------------------
// JSONL parsing — valid nuclei output produces findings
// ---------------------------------------------------------------------------
describe("runNucleiScan — JSONL parsing", () => {
  beforeEach(() => {
    spawnMock.mockReset();
  });

  it("parses a valid JSONL nuclei hit into a finding", async () => {
    const nucleiHit = JSON.stringify({
      "template-id": "CVE-2021-44228",
      info: { name: "Log4Shell", description: "Critical RCE", severity: "critical" },
      host: "https://example.com",
      "matched-at": "https://example.com/log4j",
    });

    let callCount = 0;
    spawnMock.mockImplementation((cmd: string, args: string[]) => {
      callCount++;
      // First three calls are checkNuclei probes — return success (code 0)
      if (args.includes("-version")) {
        return makeFakeProc({ closeCode: 0 });
      }
      // Actual scan call — emit JSONL and close cleanly
      return makeFakeProc({ stdoutData: [nucleiHit + "\n"], closeCode: 0 });
    });

    const { runNucleiScan } = await import("../../../server/scanner/nuclei");
    const result = await runNucleiScan("example.com", ["https://example.com"]);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("critical");
    expect(result.findings[0].title).toContain("Log4Shell");
    expect(result.nucleiResults).toHaveLength(1);
    expect(result.nucleiResults[0].templateId).toBe("CVE-2021-44228");
  });

  it("skips malformed (non-JSON) JSONL lines without crashing", async () => {
    const validHit = JSON.stringify({
      "template-id": "test-id",
      info: { name: "Test", severity: "medium" },
      host: "https://example.com",
    });

    spawnMock.mockImplementation((_cmd: string, args: string[]) => {
      if (args.includes("-version")) {
        return makeFakeProc({ closeCode: 0 });
      }
      return makeFakeProc({
        stdoutData: ["this is not json\n", validHit + "\n", "{broken json\n"],
        closeCode: 0,
      });
    });

    const { runNucleiScan } = await import("../../../server/scanner/nuclei");
    const result = await runNucleiScan("example.com", ["https://example.com"]);

    // Only the valid hit should be parsed
    expect(result.findings).toHaveLength(1);
    expect(result.nucleiResults[0].templateId).toBe("test-id");
  });

  it("returns empty findings array when nuclei emits no output", async () => {
    spawnMock.mockImplementation((_cmd: string, args: string[]) => {
      if (args.includes("-version")) {
        return makeFakeProc({ closeCode: 0 });
      }
      return makeFakeProc({ stdoutData: [], closeCode: 0 });
    });

    const { runNucleiScan } = await import("../../../server/scanner/nuclei");
    const result = await runNucleiScan("example.com", ["https://example.com"]);

    expect(result.findings).toHaveLength(0);
    expect(result.nucleiResults).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Abort signal
// ---------------------------------------------------------------------------
describe("runNucleiScan — abort signal", () => {
  beforeEach(() => {
    spawnMock.mockReset();
  });

  it("rejects with 'Scan aborted' when AbortSignal fires before scan starts", async () => {
    const controller = new AbortController();
    // Abort immediately before scan runs
    controller.abort();

    // checkNuclei must succeed so we get past availability check
    spawnMock.mockImplementation((_cmd: string, args: string[]) => {
      if (args.includes("-version")) {
        return makeFakeProc({ closeCode: 0 });
      }
      // Scan process
      return makeFakeProc({ stdoutData: [], closeCode: 0 });
    });

    const { runNucleiScan } = await import("../../../server/scanner/nuclei");
    await expect(
      runNucleiScan("example.com", ["https://example.com"], undefined, {
        signal: controller.signal,
      }),
    ).rejects.toThrow("Scan aborted");
  });
});

describe("nuclei classification (delegated to the shared taxonomy)", () => {
  // nuclei.ts used to carry its own copy of this logic. The copy drifted from the
  // rest of the engine, so the same observation could be categorised two ways
  // depending on which module saw it first. The classifier now lives in one place
  // and these cases pin the behaviour nuclei.ts depends on.
  const c = async () => (await import("../../../server/scanner/finding-taxonomy")).classifyObservation;

  it("drops pure-recon enumeration (cert details, tech detection)", async () => {
    const classify = await c();
    for (const [id, name] of [
      ["ssl-dns-names", "SSL DNS Names"],
      ["ssl-issuer", "Detect SSL Certificate Issuer"],
      ["tech-detect", "Technology Detection"],
    ]) {
      const r = classify(id, name, "info", false);
      expect(r.kind, name).toBe("recon");
      expect(r.skip, name).toBe(true);
    }
  });

  it("routes header/cookie/cors templates to verifiable categories (so the gate re-checks them)", async () => {
    const classify = await c();
    expect(classify("http-missing-security-headers", "HTTP Missing Security Headers", "info", false))
      .toMatchObject({ kind: "security", category: "security_headers", skip: false });
    expect(classify("cookie-samesite", "Missing Cookie SameSite Strict", "info", false))
      .toMatchObject({ kind: "security", category: "cookie_security", skip: false });
    expect(classify("cors-misconfig", "CORS Misconfiguration", "low", false))
      .toMatchObject({ kind: "security", category: "cors_misconfiguration", skip: false });
  });

  it("keeps CVE-backed and graded templates as security findings", async () => {
    const classify = await c();
    // A CVE keeps the generic `vulnerability` category — the CVE id is the
    // identity that matters and the NVD/OSV enrichment carries the detail.
    expect(classify("CVE-2021-44228", "Log4j RCE", "critical", true))
      .toMatchObject({ kind: "security", category: "vulnerability", skip: false });
    // A non-CVE RCE is routed to the class of flaw it actually is, which is more
    // useful on a triage board than a second "vulnerability" pile.
    expect(classify("apache-struts-rce", "Struts RCE", "high", false))
      .toMatchObject({ kind: "security", category: "injection", skip: false });
  });

  it("still catches a real certificate problem", async () => {
    const classify = await c();
    expect(classify("expired-cert", "Expired TLS certificate", "medium", false))
      .toMatchObject({ kind: "security", category: "ssl_issue" });
  });
});

describe("nuclei keeps controls and drops recon", () => {
  // The classifier decides all three kinds, but for a while nuclei.ts dropped
  // anything non-security outright, so a domain got no credit for a control the
  // scanner had positively observed.
  const c = async () => (await import("../../../server/scanner/finding-taxonomy")).classifyObservation;

  it("marks a control so it can be stored as posture rather than discarded", async () => {
    const classify = await c();
    const r = classify("dnssec-detection", "DNSSEC Detection", "info", false);
    expect(r.kind).toBe("control");
    // nuclei.ts drops only kind === "recon"; a control is persisted with this
    // kind, which keeps it out of the inbox and out of the score.
    expect(r.kind).not.toBe("recon");
  });

  it("still marks pure enumeration as recon so it is not stored twice", async () => {
    // The tech-stack and fingerprint recon modules already report this; storing
    // it again as findings rows would duplicate the same fact in two places.
    const classify = await c();
    expect(classify("tech-detect", "Apache Detection", "info", false).kind).toBe("recon");
  });
});
