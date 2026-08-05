/**
 * Unit tests for server/report-docx-input.ts — maps stored findings + recon
 * modules into the DOCX generator input. Storage is mocked.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const getWorkspace = vi.fn();
const getFindings = vi.fn();
const getReconModules = vi.fn();
vi.mock("../../../server/storage", () => ({
  storage: {
    getWorkspace: (...a: unknown[]) => getWorkspace(...a),
    getFindings: (...a: unknown[]) => getFindings(...a),
    getReconModules: (...a: unknown[]) => getReconModules(...a),
  },
}));

import { buildDocxInput } from "../../../server/report-docx-input";

beforeEach(() => {
  getWorkspace.mockReset();
  getFindings.mockReset();
  getReconModules.mockReset();
});

function seed() {
  getWorkspace.mockResolvedValue({ id: "ws1", name: "example.com" });
  getFindings.mockResolvedValue({
    data: [
      { id: "f1", title: "MySQL exposed", severity: "high", category: "network_exposure", affectedAsset: "1.2.3.4:3306", description: "3306 open", cvssScore: "7.5", remediation: "Firewall", evidence: [{ snippet: "1.2.3.4:3306 MySQL" }] },
      { id: "f2", title: "No DMARC", severity: "medium", category: "email_security", affectedAsset: "example.com", description: "missing", cvssScore: "5.9", remediation: "Publish", evidence: null },
    ],
  });
  getReconModules.mockResolvedValue({
    data: [
      { moduleType: "attack_surface", data: { ssl: { issuer: "Let's Encrypt", protocol: "TLSv1.3", daysRemaining: 69 }, dns: { ips: ["1.2.3.4"], ns: ["ns1.example.net"] } } },
      { moduleType: "cloud_footprint", data: { emailSecurity: { spf: { found: true, record: "v=spf1 -all" }, dmarc: { found: false }, dkim: { found: true }, mx: [{ exchange: "mx.example.com" }] } } },
      { moduleType: "port_services", data: { portScan: { "1.2.3.4": [{ port: 3306, service: "MySQL", banner: "5.7.23" }, { port: 443, service: "https" }] } } },
      { moduleType: "web_presence", data: { discoveredDomains: [{ domain: "www.example.com" }], liveSubdomains: ["mail.example.com"] } },
      { moduleType: "tech_stack", data: { frontend: [{ name: "jQuery" }], backend: [{ name: "WordPress" }] } },
    ],
  });
}

describe("buildDocxInput", () => {
  it("maps findings and recon modules into the report input", async () => {
    seed();
    const input = await buildDocxInput("ws1", {});
    expect(input.target).toBe("example.com");
    expect(input.findings).toHaveLength(2);
    expect(input.findings[0]).toMatchObject({ title: "MySQL exposed", severity: "high", cvssScore: "7.5" });
    expect(input.findings[0].evidenceText).toContain("1.2.3.4:3306");
    expect(input.ipAddress).toBe("1.2.3.4");
    expect(input.recon?.ns).toContain("ns1.example.net");
    expect(input.recon?.ssl?.issuer).toBe("Let's Encrypt");
    expect(input.recon?.emailSecurity?.dmarc?.found).toBe(false);
    expect(input.recon?.ports).toHaveLength(2);
    expect(input.recon?.subdomains).toEqual(expect.arrayContaining(["www.example.com", "mail.example.com"]));
    expect(input.recon?.techStack?.map((t) => t.name)).toEqual(expect.arrayContaining(["jQuery", "WordPress"]));
  });

  it("filters findings by findingIds when provided", async () => {
    seed();
    const input = await buildDocxInput("ws1", { findingIds: ["f2"] });
    expect(input.findings).toHaveLength(1);
    expect(input.findings[0].title).toBe("No DMARC");
  });

  it("is resilient to missing recon modules", async () => {
    getWorkspace.mockResolvedValue({ id: "ws1", name: "bare.com" });
    getFindings.mockResolvedValue({ data: [] });
    getReconModules.mockResolvedValue({ data: [] });
    const input = await buildDocxInput("ws1", {});
    expect(input.target).toBe("bare.com");
    expect(input.findings).toHaveLength(0);
    expect(input.recon?.ports).toBeUndefined();
  });
});
