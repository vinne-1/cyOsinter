/**
 * Unit tests for server/enrichment-service.ts — auto re-enrichment of scanned
 * data when API keys are saved during or after a scan. storage + api-integrations
 * are mocked.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const getIntegrationsStatus = vi.fn();
const enrichIP = vi.fn();
const fetchBGPView = vi.fn();
const shodanHostLookup = vi.fn();
vi.mock("../../../server/api-integrations", () => ({
  getIntegrationsStatus: () => getIntegrationsStatus(),
  enrichIP: (...a: unknown[]) => enrichIP(...a),
  fetchBGPView: (...a: unknown[]) => fetchBGPView(...a),
  shodanHostLookup: (...a: unknown[]) => shodanHostLookup(...a),
}));

const getReconModulesByType = vi.fn();
const updateReconModule = vi.fn();
const findingExists = vi.fn();
const createFinding = vi.fn();
const getWorkspaces = vi.fn();
const getScans = vi.fn();
vi.mock("../../../server/storage", () => ({
  storage: {
    getReconModulesByType: (...a: unknown[]) => getReconModulesByType(...a),
    updateReconModule: (...a: unknown[]) => updateReconModule(...a),
    findingExists: (...a: unknown[]) => findingExists(...a),
    createFinding: (...a: unknown[]) => createFinding(...a),
    getWorkspaces: () => getWorkspaces(),
    getScans: (...a: unknown[]) => getScans(...a),
  },
}));

import { reEnrichWorkspaceThreatIntel, reEnrichRecentWorkspaces } from "../../../server/enrichment-service";

beforeEach(() => {
  getIntegrationsStatus.mockReset(); enrichIP.mockReset(); fetchBGPView.mockReset(); shodanHostLookup.mockReset();
  getReconModulesByType.mockReset(); updateReconModule.mockReset(); findingExists.mockReset(); createFinding.mockReset();
  getWorkspaces.mockReset(); getScans.mockReset();
});

describe("reEnrichWorkspaceThreatIntel", () => {
  it("no-ops when no keyed provider is configured", async () => {
    getIntegrationsStatus.mockReturnValue({ abuseipdb: { configured: false }, virustotal: { configured: false }, shodan: { configured: false } });
    const updated = await reEnrichWorkspaceThreatIntel("ws1");
    expect(updated).toBe(0);
    expect(getReconModulesByType).not.toHaveBeenCalled();
  });

  it("enriches module IPs and updates the recon module when a key is configured", async () => {
    getIntegrationsStatus.mockReturnValue({ abuseipdb: { configured: true }, virustotal: { configured: false }, shodan: { configured: true } });
    getReconModulesByType.mockResolvedValue([
      { id: "m1", scanId: "s1", data: { publicIPs: [{ ip: "1.2.3.4" }], ipReputation: {}, assetInventory: { domain: "acme.com" } } },
    ]);
    enrichIP.mockResolvedValue({ abuseipdb: { abuseConfidenceScore: 10 }, virustotal: null, shodanInternetDB: null });
    fetchBGPView.mockResolvedValue({ ip: "1.2.3.4" });
    shodanHostLookup.mockResolvedValue({ ip: "1.2.3.4", ports: [80, 443], vulns: ["CVE-2021-1"], hostnames: [], products: ["nginx"] });
    findingExists.mockResolvedValue(false);
    createFinding.mockResolvedValue({ id: "f1" });

    const updated = await reEnrichWorkspaceThreatIntel("ws1");
    expect(updated).toBe(1);
    expect(enrichIP).toHaveBeenCalledWith("1.2.3.4");
    expect(shodanHostLookup).toHaveBeenCalledWith("1.2.3.4");
    // A Shodan CVE finding was created (with a stable title).
    expect(createFinding).toHaveBeenCalledOnce();
    expect(createFinding.mock.calls[0][0].title).toBe("Shodan-indexed exposure for 1.2.3.4");
    // The module was updated with the enriched ipReputation.
    const updateArg = updateReconModule.mock.calls[0][1];
    expect(updateArg.data.ipReputation["1.2.3.4"].shodan.vulns).toContain("CVE-2021-1");
  });

  it("does not duplicate a Shodan finding that already exists", async () => {
    getIntegrationsStatus.mockReturnValue({ abuseipdb: { configured: false }, virustotal: { configured: false }, shodan: { configured: true } });
    getReconModulesByType.mockResolvedValue([{ id: "m1", scanId: "s1", data: { publicIPs: [{ ip: "1.2.3.4" }], ipReputation: {} } }]);
    enrichIP.mockResolvedValue({ abuseipdb: null, virustotal: null, shodanInternetDB: null });
    fetchBGPView.mockResolvedValue(null);
    shodanHostLookup.mockResolvedValue({ ip: "1.2.3.4", ports: [80], vulns: ["CVE-x"], hostnames: [], products: [] });
    findingExists.mockResolvedValue(true); // already exists
    await reEnrichWorkspaceThreatIntel("ws1");
    expect(createFinding).not.toHaveBeenCalled();
  });
});

describe("reEnrichRecentWorkspaces", () => {
  it("enriches running and recently-completed workspaces, skips stale ones", async () => {
    getIntegrationsStatus.mockReturnValue({ abuseipdb: { configured: true }, virustotal: { configured: false }, shodan: { configured: false } });
    getWorkspaces.mockResolvedValue([{ id: "running" }, { id: "recent" }, { id: "stale" }, { id: "noscan" }]);
    getScans.mockImplementation(async (wsId: string) => {
      if (wsId === "running") return { data: [{ status: "running" }] };
      if (wsId === "recent") return { data: [{ status: "completed", completedAt: new Date().toISOString() }] };
      if (wsId === "stale") return { data: [{ status: "completed", completedAt: new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString() }] };
      return { data: [] };
    });
    getReconModulesByType.mockResolvedValue([]); // enrichment itself no-ops on empty modules

    await reEnrichRecentWorkspaces();
    // Only running + recent trigger a module fetch; stale + noscan are skipped.
    const enrichedWs = getReconModulesByType.mock.calls.map((c) => c[0]);
    expect(enrichedWs).toContain("running");
    expect(enrichedWs).toContain("recent");
    expect(enrichedWs).not.toContain("stale");
    expect(enrichedWs).not.toContain("noscan");
  });
});
