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
const getNSRecordsMock = vi.fn();
const httpGetMock = vi.fn();

vi.mock("../../../server/scanner/dns.js", () => ({
  resolveDNS: (host: string) => resolveDNSMock(host),
  getNSRecords: (domain: string) => getNSRecordsMock(domain),
}));
vi.mock("../../../server/scanner/http.js", () => ({
  httpGet: (url: string) => httpGetMock(url),
}));

import { scanSubdomainTakeover } from "../../../server/scanner/takeover";

/**
 * Builds a resolveDNS result with the same `resolved` semantics as production.
 *
 * The fixtures used to be bare `{ ips, cnames }` literals. When AAAA support
 * added a computed `resolved` flag, those literals silently yielded
 * `resolved: undefined` — falsy — and a "CNAME target still resolves" case
 * started reporting a takeover. A builder keeps the mock honest.
 */
const dnsResult = (ips: string[] = [], cnames: string[] = [], ipv6: string[] = []) => ({
  ips,
  ipv6,
  cnames,
  resolved: ips.length + ipv6.length + cnames.length > 0,
});

beforeEach(() => {
  resolveDNSMock.mockReset();
  httpGetMock.mockReset();
  getNSRecordsMock.mockReset();
  getNSRecordsMock.mockResolvedValue([]);
});

describe("scanSubdomainTakeover — passive (httpProbe: false)", () => {
  it("flags a dangling CNAME to a known unclaimed service as a critical finding without any HTTP probe", async () => {
    resolveDNSMock.mockImplementation((host: string) => {
      if (host === "gone.example.com") return Promise.resolve(dnsResult([], ["victim.github.io"]));
      if (host === "victim.github.io") return Promise.resolve(dnsResult()); // NXDOMAIN
      return Promise.resolve(dnsResult());
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
      if (host === "ok.example.com") return Promise.resolve(dnsResult([], ["app.herokuapp.com"]));
      if (host === "app.herokuapp.com") return Promise.resolve(dnsResult(["10.0.0.5"])); // resolves
      return Promise.resolve(dnsResult());
    });

    const { findings } = await scanSubdomainTakeover(["ok.example.com"], undefined, { httpProbe: false });
    // CNAME resolves and there is no HTTP probe in passive mode → no finding
    expect(findings).toHaveLength(0);
    expect(httpGetMock).not.toHaveBeenCalled();
  });

  it("ignores subdomains without a CNAME", async () => {
    resolveDNSMock.mockResolvedValue(dnsResult(["1.2.3.4"]));
    const { findings, results } = await scanSubdomainTakeover(["a.example.com"], undefined, { httpProbe: false });
    expect(findings).toHaveLength(0);
    expect(results).toHaveLength(0);
  });

  it("returns empty for no subdomains", async () => {
    const { findings, results } = await scanSubdomainTakeover([], undefined, { httpProbe: false });
    expect(findings).toEqual([]);
    expect(results).toEqual([]);
  });

  /**
   * A dangling CNAME is not automatically a takeover. If the target's
   * registrable domain is still registered and delegated to somebody else's
   * nameservers, nobody can claim that name — it is a broken record. Reporting
   * it as a critical takeover is a false positive, and a loud one.
   */
  it("reports a dangling CNAME into a registered third-party zone as low-severity hygiene, not a takeover", async () => {
    resolveDNSMock.mockImplementation((host: string) => {
      if (host === "old.example.com") return Promise.resolve(dnsResult([], ["retired.partner-corp.com"]));
      return Promise.resolve(dnsResult()); // target is NXDOMAIN
    });
    getNSRecordsMock.mockResolvedValue(["ns1.partner-corp.com", "ns2.partner-corp.com"]);

    const { findings, results } = await scanSubdomainTakeover(["old.example.com"], undefined, { httpProbe: false });

    expect(results).toHaveLength(1);
    expect(results[0].takeoverable).toBe(false);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("low");
    expect(findings[0].category).toBe("dns_misconfiguration");
    expect(findings[0].title).toMatch(/Dangling DNS Record/);
  });

  it("still reports a takeover when the CNAME target's own domain is unregistered", async () => {
    resolveDNSMock.mockImplementation((host: string) => {
      if (host === "old.example.com") return Promise.resolve(dnsResult([], ["app.expired-vendor.com"]));
      return Promise.resolve(dnsResult());
    });
    getNSRecordsMock.mockResolvedValue([]); // apex has no delegation — buyable

    const { findings, results } = await scanSubdomainTakeover(["old.example.com"], undefined, { httpProbe: false });

    expect(results[0].takeoverable).toBe(true);
    expect(findings[0].severity).toBe("high");
    expect(findings[0].category).toBe("subdomain_takeover");
  });

  it("does not pay for an NS lookup when the target matches a known claimable service", async () => {
    resolveDNSMock.mockImplementation((host: string) => {
      if (host === "gone.example.com") return Promise.resolve(dnsResult([], ["victim.github.io"]));
      return Promise.resolve(dnsResult());
    });

    await scanSubdomainTakeover(["gone.example.com"], undefined, { httpProbe: false });
    expect(getNSRecordsMock).not.toHaveBeenCalled();
  });
});
