/**
 * Unit tests for server/scanner/takeover.ts — subdomain takeover detection,
 * focusing on the passive (DNS-only, httpProbe:false) path used by the passive
 * scan. resolveDNS and httpGet are mocked so no network is touched.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../../server/logger", () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));

const resolveDNSMock = vi.fn();
const httpGetMock = vi.fn();

vi.mock("../../../server/scanner/dns.js", () => ({
  resolveDNS: (host: string) => resolveDNSMock(host),
}));
vi.mock("../../../server/scanner/http.js", () => ({
  httpGet: (url: string) => httpGetMock(url),
}));

import { scanSubdomainTakeover } from "../../../server/scanner/takeover";

beforeEach(() => {
  resolveDNSMock.mockReset();
  httpGetMock.mockReset();
});

describe("scanSubdomainTakeover — passive (httpProbe: false)", () => {
  it("flags a dangling CNAME to a known unclaimed service as a critical finding without any HTTP probe", async () => {
    resolveDNSMock.mockImplementation((host: string) => {
      if (host === "gone.example.com") return Promise.resolve({ ips: [], cnames: ["victim.github.io"] });
      if (host === "victim.github.io") return Promise.resolve({ ips: [], cnames: [] }); // NXDOMAIN
      return Promise.resolve({ ips: [], cnames: [] });
    });

    const { findings, results } = await scanSubdomainTakeover(["gone.example.com"], undefined, { httpProbe: false });

    expect(httpGetMock).not.toHaveBeenCalled(); // strictly passive
    expect(results).toHaveLength(1);
    expect(results[0].confidence).toBe("high");
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("critical");
    expect(findings[0].category).toBe("subdomain_takeover");
    expect(findings[0].affectedAsset).toBe("gone.example.com");
  });

  it("does not flag a subdomain whose CNAME target still resolves", async () => {
    resolveDNSMock.mockImplementation((host: string) => {
      if (host === "ok.example.com") return Promise.resolve({ ips: [], cnames: ["app.herokuapp.com"] });
      if (host === "app.herokuapp.com") return Promise.resolve({ ips: ["10.0.0.5"], cnames: [] }); // resolves
      return Promise.resolve({ ips: [], cnames: [] });
    });

    const { findings } = await scanSubdomainTakeover(["ok.example.com"], undefined, { httpProbe: false });
    // CNAME resolves and there is no HTTP probe in passive mode → no finding
    expect(findings).toHaveLength(0);
    expect(httpGetMock).not.toHaveBeenCalled();
  });

  it("ignores subdomains without a CNAME", async () => {
    resolveDNSMock.mockResolvedValue({ ips: ["1.2.3.4"], cnames: [] });
    const { findings, results } = await scanSubdomainTakeover(["a.example.com"], undefined, { httpProbe: false });
    expect(findings).toHaveLength(0);
    expect(results).toHaveLength(0);
  });

  it("returns empty for no subdomains", async () => {
    const { findings, results } = await scanSubdomainTakeover([], undefined, { httpProbe: false });
    expect(findings).toEqual([]);
    expect(results).toEqual([]);
  });
});
