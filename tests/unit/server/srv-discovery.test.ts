import { describe, it, expect, vi } from "vitest";
import {
  discoverSrvRecords,
  buildSrvFindings,
  summariseSrv,
  SRV_SERVICES,
  type SrvRecord,
} from "../../../server/scanner/srv-discovery";

const NOW = "2026-09-01T00:00:00.000Z";

/** Resolver stub: a map of full name -> SRV answers. Unknown names NXDOMAIN. */
function resolver(zone: Record<string, Array<{ priority: number; weight: number; port: number; name: string }>>) {
  return async (name: string) => {
    const answer = zone[name];
    if (!answer) throw Object.assign(new Error("queryA ENOTFOUND"), { code: "ENOTFOUND" });
    return answer;
  };
}

const srv = (name: string, port: number, priority = 0, weight = 100) => ({ priority, weight, port, name });

describe("discoverSrvRecords", () => {
  it("returns nothing for a domain publishing no SRV records", async () => {
    expect(await discoverSrvRecords("example.com", resolver({}))).toEqual([]);
  });

  it("finds a domain controller record", async () => {
    const records = await discoverSrvRecords(
      "corp.example.com",
      resolver({ "_ldap._tcp.dc._msdcs.corp.example.com": [srv("dc01.corp.example.com", 389)] }),
    );
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      service: "_ldap._tcp.dc._msdcs",
      target: "dc01.corp.example.com",
      port: 389,
    });
  });

  it("keeps every target when a service has several", async () => {
    const records = await discoverSrvRecords(
      "example.com",
      resolver({ "_sip._tls.example.com": [srv("sip1.example.com", 5061), srv("sip2.example.com", 5061, 10)] }),
    );
    expect(records.map((r) => r.target)).toEqual(["sip1.example.com", "sip2.example.com"]);
  });

  it('ignores the RFC 2782 "." target meaning the service is unavailable', async () => {
    // Recording this as a live service would invent infrastructure that the
    // record explicitly says does not exist.
    const records = await discoverSrvRecords("example.com", resolver({ "_sip._tls.example.com": [srv(".", 0)] }));
    expect(records).toEqual([]);
  });

  it("treats NXDOMAIN as a normal answer, not an error", async () => {
    // Most labels do not exist; if a rejection propagated, one missing label
    // would abort the whole sweep.
    const zone = { "_sip._tls.example.com": [srv("sip.example.com", 5061)] };
    await expect(discoverSrvRecords("example.com", resolver(zone))).resolves.toHaveLength(1);
  });

  it("queries in bounded batches rather than all at once", async () => {
    // 25 simultaneous queries is enough to trip a resolver's rate limit, and a
    // dropped batch looks identical to "this domain publishes no SRV records".
    let inFlight = 0;
    let peak = 0;
    const slow = async () => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 1));
      inFlight -= 1;
      return [];
    };
    await discoverSrvRecords("example.com", slow, SRV_SERVICES, 4);
    expect(peak).toBeLessThanOrEqual(4);
  });

  it("probes every configured service label exactly once", async () => {
    const seen: string[] = [];
    const spy = vi.fn(async (name: string) => { seen.push(name); return []; });
    await discoverSrvRecords("example.com", spy);
    expect(seen).toHaveLength(SRV_SERVICES.length);
    expect(new Set(seen).size).toBe(SRV_SERVICES.length);
    expect(seen).toContain("_ldap._tcp.dc._msdcs.example.com");
  });
});

describe("buildSrvFindings", () => {
  const rec = (service: string, target: string, port: number): SrvRecord => ({
    name: `${service}.example.com`, service, priority: 0, weight: 100, port, target,
  });

  it("reports nothing when no SRV records were found", () => {
    expect(buildSrvFindings("example.com", [], NOW)).toEqual([]);
  });

  it("does not report public services as findings", () => {
    // SIP, XMPP and autodiscover are meant to be published. Flagging them would
    // bury the records that genuinely should not be there.
    const records = [
      rec("_sip._tls", "sip.example.com", 5061),
      rec("_xmpp-server._tcp", "xmpp.example.com", 5269),
      rec("_autodiscover._tcp", "autodiscover.example.com", 443),
    ];
    expect(buildSrvFindings("example.com", records, NOW)).toEqual([]);
  });

  it("does not call a lone public LDAP service a domain controller", () => {
    // Measured against the real google.com zone: _ldap._tcp.google.com answers
    // with ldap.google.com, which Google publishes deliberately. Reporting that
    // as a leaked domain controller is the kind of false positive that gets a
    // scanner's real findings ignored.
    const records = [
      rec("_ldap._tcp", "ldap.google.com", 389),
      rec("_caldavs._tcp", "calendar.google.com", 443),
    ];
    expect(buildSrvFindings("google.com", records, NOW)).toEqual([]);
  });

  it("escalates a bare LDAP record once something AD-specific corroborates it", () => {
    // _kerberos._tcp alongside it means this really is a Windows domain.
    const records = [
      rec("_ldap._tcp", "dc01.corp.example.com", 389),
      rec("_kerberos._tcp", "dc01.corp.example.com", 88),
    ];
    const f = buildSrvFindings("corp.example.com", records, NOW);
    expect(f).toHaveLength(1);
    expect(f[0].title).toMatch(/Active Directory/i);
    expect(f[0].evidence?.[0].snippet).toMatch(/_ldap\._tcp/);
  });

  it("reports exposed directory-service records at medium", () => {
    const records = [
      rec("_ldap._tcp.dc._msdcs", "dc01.example.com", 389),
      rec("_kerberos._tcp", "dc01.example.com", 88),
    ];
    const f = buildSrvFindings("example.com", records, NOW);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("medium");
    expect(f[0].title).toMatch(/Active Directory/i);
    expect(f[0].description).toMatch(/dc01\.example\.com/);
  });

  it("explains the attack the exposure enables", () => {
    // A finding that only says "this record is public" gets closed as won't-fix.
    const f = buildSrvFindings("example.com", [rec("_ldap._tcp.dc._msdcs", "dc01.example.com", 389)], NOW);
    expect(f[0].description).toMatch(/kerberoast|AS-REP/i);
    expect(f[0].remediation).toMatch(/split-horizon/i);
  });

  it("separates non-directory internal services and grades them lower", () => {
    const f = buildSrvFindings("example.com", [rec("_ssh._tcp", "bastion.example.com", 22)], NOW);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("low");
    expect(f[0].title).toMatch(/Internal service records/i);
  });

  it("raises directory and other internal findings separately", () => {
    const records = [
      rec("_ldap._tcp.dc._msdcs", "dc01.example.com", 389),
      rec("_vpn._tcp", "vpn.example.com", 443),
    ];
    const f = buildSrvFindings("example.com", records, NOW);
    expect(f).toHaveLength(2);
    expect(f.map((x) => x.severity)).toEqual(["medium", "low"]);
  });

  it("lists the host and port in evidence so it can be verified", () => {
    const f = buildSrvFindings("example.com", [rec("_ldap._tcp.dc._msdcs", "dc01.example.com", 389)], NOW);
    expect(f[0].evidence?.[0].snippet).toMatch(/dc01\.example\.com:389/);
  });

  it("does not repeat a host that several records point at", () => {
    const records = [
      rec("_ldap._tcp.dc._msdcs", "dc01.example.com", 389),
      rec("_kerberos._tcp", "dc01.example.com", 88),
      rec("_gc._tcp", "dc01.example.com", 3268),
    ];
    const f = buildSrvFindings("example.com", records, NOW);
    expect(f[0].description).toMatch(/1 internal host/);
  });
});

describe("summariseSrv", () => {
  it("groups records by service with their targets", () => {
    const records: SrvRecord[] = [
      { name: "_sip._tls.example.com", service: "_sip._tls", priority: 0, weight: 100, port: 5061, target: "sip1.example.com" },
      { name: "_sip._tls.example.com", service: "_sip._tls", priority: 10, weight: 100, port: 5061, target: "sip2.example.com" },
    ];
    expect(summariseSrv(records)).toEqual([
      {
        service: "_sip._tls",
        description: "SIP over TLS (VoIP signalling)",
        exposure: "public",
        targets: ["sip1.example.com:5061", "sip2.example.com:5061"],
      },
    ]);
  });

  it("returns an empty summary for a domain with no SRV records", () => {
    expect(summariseSrv([])).toEqual([]);
  });
});

describe("SRV_SERVICES", () => {
  it("has no duplicate labels", () => {
    const labels = SRV_SERVICES.map((s) => s.label);
    expect(new Set(labels).size).toBe(labels.length);
  });

  it("classifies AD directory services as internal", () => {
    for (const label of ["_ldap._tcp.dc._msdcs", "_kerberos._tcp", "_gc._tcp"]) {
      expect(SRV_SERVICES.find((s) => s.label === label)?.exposure, label).toBe("internal");
    }
  });

  it("describes every service in plain language", () => {
    for (const s of SRV_SERVICES) {
      expect(s.description.length, s.label).toBeGreaterThan(5);
      expect(s.description, s.label).not.toMatch(/^_/);
    }
  });
});
