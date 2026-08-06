/**
 * Unit tests for server/scanner/verification-gate.ts — the fail-closed verification
 * gate that keeps false positives out of the DB and every report. http.js, net, tls,
 * and dns/promises are mocked so probes are deterministic.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const httpGet = vi.fn();
const httpGetNoRedirect = vi.fn();
const httpGetMainPage = vi.fn();
vi.mock("../../../server/scanner/http.js", () => ({
  httpGet: (...a: unknown[]) => httpGet(...a),
  httpGetNoRedirect: (...a: unknown[]) => httpGetNoRedirect(...a),
  httpGetMainPage: (...a: unknown[]) => httpGetMainPage(...a),
  parseSetCookie: (strings: string[]) =>
    strings.map((s) => {
      const lower = s.toLowerCase();
      return { name: s.split("=")[0], secure: lower.includes("secure"), httpOnly: lower.includes("httponly") };
    }),
}));

const tcpConnect = vi.fn();
vi.mock("net", () => ({
  Socket: class {
    private handlers: Record<string, () => void> = {};
    setTimeout() { /* noop */ }
    once(ev: string, cb: () => void) { this.handlers[ev] = cb; return this; }
    destroy() { /* noop */ }
    connect() { tcpConnect(this.handlers); }
  },
}));

vi.mock("tls", () => ({ connect: () => ({ once() { return this; }, destroy() { /* noop */ }, getPeerCertificate: () => ({}) }) }));

const resolveCname = vi.fn();
vi.mock("dns/promises", () => ({ resolveCname: (...a: unknown[]) => resolveCname(...a) }));

import { runVerificationGate } from "../../../server/scanner/verification-gate";

interface F {
  title: string; description: string; severity: string; category: string;
  affectedAsset: string; remediation: string; cvssScore?: string;
  evidence?: Record<string, unknown>[];
}
const mk = (o: Partial<F> & { category: string; affectedAsset: string }): F => ({
  title: o.title ?? "t", description: o.description ?? "d", severity: o.severity ?? "medium",
  remediation: o.remediation ?? "r", cvssScore: o.cvssScore, evidence: o.evidence, ...o,
});

beforeEach(() => {
  httpGet.mockReset(); httpGetNoRedirect.mockReset(); httpGetMainPage.mockReset();
  tcpConnect.mockReset(); resolveCname.mockReset();
});

describe("runVerificationGate", () => {
  it("keeps a missing-header finding when the header is still absent", async () => {
    httpGet.mockResolvedValue({ status: 200, headers: { "content-type": "text/html" }, body: "", finalUrl: "https://x.com" });
    const { confirmed, withheld } = await runVerificationGate(
      [mk({ title: "Missing Strict-Transport-Security", category: "security_headers", affectedAsset: "x.com" })],
      { target: "x.com" },
    );
    expect(confirmed).toHaveLength(1);
    expect(withheld).toHaveLength(0);
    // Verification evidence is appended.
    expect(confirmed[0].evidence?.some((e) => (e as Record<string, unknown>).verificationStatus === "confirmed")).toBe(true);
  });

  it("withholds a missing-header finding when the header is now present", async () => {
    httpGet.mockResolvedValue({ status: 200, headers: { "strict-transport-security": "max-age=63072000" }, body: "", finalUrl: "https://x.com" });
    const { confirmed, withheld } = await runVerificationGate(
      [mk({ title: "Missing Strict-Transport-Security", category: "security_headers", affectedAsset: "x.com" })],
    );
    expect(confirmed).toHaveLength(0);
    expect(withheld).toHaveLength(1);
    expect(withheld[0].strict).toBe(true);
  });

  it("fails closed: an unreachable host withholds the finding", async () => {
    httpGet.mockResolvedValue(null);
    const { confirmed, withheld } = await runVerificationGate(
      [mk({ title: "Missing X-Frame-Options", category: "security_headers", affectedAsset: "down.example" })],
    );
    expect(confirmed).toHaveLength(0);
    expect(withheld).toHaveLength(1);
  });

  it("keeps an unverifiable category (vulnerability / Nuclei) by policy", async () => {
    const { confirmed, withheld } = await runVerificationGate(
      [mk({ title: "CVE-2023-1234", category: "vulnerability", affectedAsset: "x.com" })],
    );
    expect(confirmed).toHaveLength(1);
    expect(withheld).toHaveLength(0);
    expect(confirmed[0].evidence?.some((e) => (e as Record<string, unknown>).verificationStatus === "unverifiable")).toBe(true);
    // No network probe was attempted for an unverifiable category.
    expect(httpGet).not.toHaveBeenCalled();
  });

  it("confirms an exposed-content finding only when the content marker is still served", async () => {
    const evidence = [{ url: "https://x.com/.env", snippet: "DB_PASSWORD=supersecret123" }];
    httpGet.mockResolvedValue({ status: 200, headers: {}, body: "APP_ENV=prod\nDB_PASSWORD=supersecret123\n", finalUrl: "https://x.com/.env" });
    const kept = await runVerificationGate([mk({ title: ".env exposed", category: "secret_exposure", affectedAsset: "x.com", evidence })]);
    expect(kept.confirmed).toHaveLength(1);

    httpGet.mockResolvedValue({ status: 200, headers: {}, body: "<html>login</html>", finalUrl: "https://x.com/.env" });
    const gone = await runVerificationGate([mk({ title: ".env exposed", category: "secret_exposure", affectedAsset: "x.com", evidence })]);
    expect(gone.confirmed).toHaveLength(0);
    expect(gone.withheld).toHaveLength(1);
  });

  it("withholds an exposed-content finding that no longer returns 2xx", async () => {
    httpGet.mockResolvedValue({ status: 404, headers: {}, body: "Not Found", finalUrl: "https://x.com/backup.zip" });
    const { confirmed, withheld } = await runVerificationGate(
      [mk({ title: "Backup exposed", category: "data_leak", affectedAsset: "x.com", evidence: [{ url: "https://x.com/backup.zip" }] })],
    );
    expect(confirmed).toHaveLength(0);
    expect(withheld).toHaveLength(1);
  });

  it("confirms an exposed service when the TCP port is reachable, withholds when refused", async () => {
    tcpConnect.mockImplementation((handlers: Record<string, () => void>) => handlers["connect"]?.());
    const up = await runVerificationGate([mk({ title: "MySQL exposed", category: "exposed_service", affectedAsset: "1.2.3.4:3306" })]);
    expect(up.confirmed).toHaveLength(1);

    tcpConnect.mockImplementation((handlers: Record<string, () => void>) => handlers["error"]?.());
    const down = await runVerificationGate([mk({ title: "MySQL exposed", category: "exposed_service", affectedAsset: "1.2.3.4:3306" })]);
    expect(down.confirmed).toHaveLength(0);
    expect(down.withheld).toHaveLength(1);
  });

  it("withholds a subdomain takeover with no dangling CNAME (NXDOMAIN)", async () => {
    resolveCname.mockRejectedValue(new Error("ENOTFOUND"));
    const { confirmed, withheld } = await runVerificationGate(
      [mk({ title: "Takeover", category: "subdomain_takeover", affectedAsset: "gone.x.com" })],
    );
    expect(confirmed).toHaveLength(0);
    expect(withheld).toHaveLength(1);
  });
});
