import { describe, it, expect } from "vitest";
import { buildReconModules } from "../../../server/scanner/recon-builder";
import type { ScanResults } from "../../../server/scanner/types";

/**
 * Does the data the scanner collects actually reach the screen?
 *
 * This repo has a repeated failure mode: a module that looks finished, is
 * covered by its own unit tests, and is never called from anywhere — an audit
 * trail with zero rows, a scan queue nothing enqueued to, an SLA clock no
 * finding was ever given a due date by. Each one passed its own tests.
 *
 * `buildReconModules` is the single seam between what the scanner gathers and
 * what the UI can render, so these tests assert the crossing itself. A field
 * that survives here is reachable by the panels; one that does not is dead no
 * matter how well the module producing it is tested.
 */

/** A ScanResults with only the recon fields a given test cares about. */
function osint(reconData: Partial<ScanResults["reconData"]>): ScanResults {
  return { findings: [], reconData: reconData as ScanResults["reconData"] } as ScanResults;
}

const EMAIL_SEC = {
  spf: { found: true, record: "v=spf1 -all", issues: [] },
  dmarc: { found: true, record: "v=DMARC1; p=reject", issues: [] },
  mx: [{ priority: 10, exchange: "mail.example.com" }],
};

/** Pulls the cloud_footprint module, which is what CloudFootprintPanel renders. */
async function cloudFootprint(reconData: Partial<ScanResults["reconData"]>) {
  const mods = await buildReconModules("example.com", null, osint(reconData));
  return mods.find((m) => m.moduleType === "cloud_footprint")?.data as Record<string, any> | undefined;
}

describe("mail transport security reaches the UI", () => {
  it("carries an enforcing MTA-STS through to the module data", async () => {
    const data = await cloudFootprint({
      emailSecurity: EMAIL_SEC,
      mailTransport: { mtaStsMode: "enforce", mtaStsMx: ["mail.example.com"], tlsRptDestinations: [], controls: ["MTA-STS"] },
    });
    expect(data?.mailTransport).toBeDefined();
    expect(data!.mailTransport.mtaSts).toBe("pass");
    expect(data!.mailTransport.mtaStsMx).toEqual(["mail.example.com"]);
  });

  it("marks a testing-mode policy as partial, not as passing", async () => {
    // testing mode reports a downgrade and still delivers over it. Showing that
    // as a pass would tell the user they are protected when they are not.
    const data = await cloudFootprint({
      emailSecurity: EMAIL_SEC,
      mailTransport: { mtaStsMode: "testing", tlsRptDestinations: [] },
    });
    expect(data!.mailTransport.mtaSts).toBe("partial");
  });

  it("marks an absent policy as not configured", async () => {
    const data = await cloudFootprint({ emailSecurity: EMAIL_SEC, mailTransport: { tlsRptDestinations: [] } });
    expect(data!.mailTransport.mtaSts).toBe("none");
  });

  it('reports "n/a" rather than a failure when the domain has no MX', async () => {
    // A host that cannot receive mail is not failing a mail control. Grading it
    // as a failure here would contradict the scanner, which deliberately raises
    // no finding in the same situation.
    const data = await cloudFootprint({
      emailSecurity: { ...EMAIL_SEC, mx: [] },
      mailTransport: { tlsRptDestinations: [] },
    });
    expect(data!.mailTransport.mtaSts).toBe("n/a");
    expect(data!.mailTransport.tlsRpt).toBe("n/a");
  });

  it("passes TLS-RPT destinations through so they can be shown", async () => {
    const data = await cloudFootprint({
      emailSecurity: EMAIL_SEC,
      mailTransport: { tlsRptDestinations: ["mailto:tls@example.com"] },
    });
    expect(data!.mailTransport.tlsRpt).toBe("pass");
    expect(data!.mailTransport.tlsRptDestinations).toEqual(["mailto:tls@example.com"]);
  });

  it("treats a BIMI record without a VMC as partial", async () => {
    const data = await cloudFootprint({
      emailSecurity: EMAIL_SEC,
      mailTransport: { tlsRptDestinations: [], bimiLogoUrl: "https://example.com/logo.svg" },
    });
    expect(data!.mailTransport.bimi).toBe("partial");
  });

  it("treats a VMC-backed BIMI record as passing", async () => {
    const data = await cloudFootprint({
      emailSecurity: EMAIL_SEC,
      mailTransport: { tlsRptDestinations: [], bimiLogoUrl: "https://e/l.svg", bimiVmcUrl: "https://e/v.pem" },
    });
    expect(data!.mailTransport.bimi).toBe("pass");
  });

  it("omits the transport block entirely when the scan did not collect it", async () => {
    // An older scan has no mailTransport. The panel must render without it
    // rather than showing an empty card of "not configured" rows that would
    // read as a finding the scan never actually made.
    const data = await cloudFootprint({ emailSecurity: EMAIL_SEC });
    expect(data?.mailTransport).toBeUndefined();
  });
});

describe("the SPF lookup budget reaches the UI", () => {
  it("carries the lookup count and limit through", async () => {
    // At 10 of 10 a domain's SPF still reads perfectly and the next provider
    // anyone adds silently turns it off. If the number does not reach the
    // panel, nobody ever sees the problem coming.
    const data = await cloudFootprint({
      emailSecurity: {
        ...EMAIL_SEC,
        spf: { found: true, record: "v=spf1 include:a -all", issues: [], lookups: { count: 10, voidLookups: 0, chain: [], exceeded: false, loop: false } },
      } as never,
    });
    expect(data!.emailSecurity.spf.lookups).toBe(10);
    expect(data!.emailSecurity.spf.lookupLimit).toBe(10);
    expect(data!.emailSecurity.spf.lookupsExceeded).toBe(false);
  });

  it("marks an over-budget record as exceeded", async () => {
    const data = await cloudFootprint({
      emailSecurity: {
        ...EMAIL_SEC,
        spf: { found: true, record: "v=spf1 -all", issues: ["over limit"], lookups: { count: 14, voidLookups: 0, chain: [], exceeded: true, loop: false } },
      } as never,
    });
    expect(data!.emailSecurity.spf.lookupsExceeded).toBe(true);
    expect(data!.emailSecurity.spf.lookups).toBe(14);
  });

  it("omits the count for an older scan that never measured it", async () => {
    // undefined must render as nothing, not as "0 of 10", which would claim a
    // measurement the scan never made.
    const data = await cloudFootprint({ emailSecurity: EMAIL_SEC });
    expect(data!.emailSecurity.spf.lookups).toBeUndefined();
  });
});

describe("SRV services reach the UI", () => {
  it("passes discovered services through with their exposure", async () => {
    const data = await cloudFootprint({
      emailSecurity: EMAIL_SEC,
      srvServices: [
        { service: "_sip._tls", description: "SIP over TLS (VoIP signalling)", exposure: "public", targets: ["sip.example.com:5061"] },
      ],
    });
    expect(data!.srvServices).toHaveLength(1);
    expect(data!.srvServices[0]).toMatchObject({ exposure: "public", targets: ["sip.example.com:5061"] });
  });

  it("defaults to an empty list rather than undefined", async () => {
    // The panel guards on `.length`, so undefined here would throw.
    const data = await cloudFootprint({ emailSecurity: EMAIL_SEC });
    expect(data!.srvServices).toEqual([]);
  });
});

/** Pulls the dns_overview module, which is what DNSOverviewPanel renders. */
async function dnsOverview(reconData: Partial<ScanResults["reconData"]>) {
  const mods = await buildReconModules("example.com", null, osint(reconData));
  return mods.find((m) => m.moduleType === "dns_overview")?.data as Record<string, any> | undefined;
}

describe("DNS posture reaches the UI", () => {
  const DNS = { a: ["1.2.3.4"], ns: ["ns1.example.com"] };

  it("carries the real DNSSEC state, not just a boolean", async () => {
    const data = await dnsOverview({
      dnsRecords: DNS,
      dnssec: {
        signed: true, dsPresent: true, dnskeyPresent: true, authenticatedData: true,
        algorithms: [13], state: "signed", detail: "chain verified",
      },
    });
    expect(data!.dnssec.state).toBe("signed");
    expect(data!.dnssec.algorithms).toEqual([13]);
  });

  it("carries the zone-transfer result, including when every server refused", async () => {
    // A refusal is a positive statement — "we asked and it is closed" is not
    // the same as "nobody looked" — so it must survive to the panel too.
    const data = await dnsOverview({
      dnsRecords: DNS,
      zoneTransfer: [
        { nameserver: "ns1.example.com", transferred: false, recordCount: 0, detail: "DNS rcode 5 (REFUSED)" },
      ],
    });
    expect(data!.zoneTransfer).toHaveLength(1);
    expect(data!.zoneTransfer[0].transferred).toBe(false);
    expect(data!.zoneTransfer[0].detail).toMatch(/REFUSED/);
  });

  it("carries the CAA analysis, including the absence of any record", async () => {
    // "No CAA" is the consequential state and is invisible in a raw record
    // table — it looks exactly like "no records shown".
    const data = await dnsOverview({
      dnsRecords: DNS,
      caaAnalysis: { present: false, issuers: [], wildcardIssuers: [], iodef: [], forbidsAll: false },
    });
    expect(data!.caaAnalysis).toBeDefined();
    expect(data!.caaAnalysis.present).toBe(false);
  });

  it("carries the authorised issuers through", async () => {
    const data = await dnsOverview({
      dnsRecords: DNS,
      caaAnalysis: { present: true, issuers: ["letsencrypt.org"], wildcardIssuers: [], iodef: ["mailto:s@example.com"], forbidsAll: false },
    });
    expect(data!.caaAnalysis.issuers).toEqual(["letsencrypt.org"]);
  });

  it("carries a permissive nameserver through", async () => {
    const data = await dnsOverview({
      dnsRecords: DNS,
      zoneTransfer: [
        { nameserver: "ns1.example.com", transferred: true, recordCount: 52, detail: "transferred 52 records" },
      ],
    });
    expect(data!.zoneTransfer[0].transferred).toBe(true);
    expect(data!.zoneTransfer[0].recordCount).toBe(52);
  });
});

/** Pulls the attack_surface module, which is what AttackSurfacePanel renders. */
async function attackSurface(reconData: Record<string, unknown>) {
  // The EASM branch reads subdomains and assets as well as reconData, so a
  // reconData-only fixture is not enough to reach the module builder.
  const easm = { findings: [], subdomains: [], assets: [], reconData } as unknown as ScanResults;
  const mods = await buildReconModules("example.com", easm, null);
  return mods.find((m) => m.moduleType === "attack_surface")?.data as Record<string, any> | undefined;
}

describe("accepted TLS versions reach the UI", () => {
  const BASE = { ssl: { subject: "example.com", issuer: "R3", daysRemaining: 60, protocol: "TLSv1.3" }, dns: { ips: ["1.2.3.4"] } };

  it("carries the accepted versions and flags obsolete ones", async () => {
    // The TLS grade beside this is derived from the single version negotiated,
    // which is always the best one both sides support. A host accepting TLS 1.0
    // as well earns a good grade and is still downgradable, so both numbers
    // have to reach the screen.
    const data = await attackSurface({
      ...BASE,
      tlsVersions: { accepted: ["TLSv1", "TLSv1.2", "TLSv1.3"], obsoleteAccepted: ["TLSv1"], indeterminate: [] },
    });
    expect(data!.tlsVersions.accepted).toEqual(["TLSv1", "TLSv1.2", "TLSv1.3"]);
    expect(data!.tlsVersions.obsoleteAccepted).toEqual(["TLSv1"]);
  });

  it("carries a clean modern-only host through with nothing obsolete", async () => {
    const data = await attackSurface({
      ...BASE,
      tlsVersions: { accepted: ["TLSv1.2", "TLSv1.3"], obsoleteAccepted: [], indeterminate: ["TLSv1"] },
    });
    expect(data!.tlsVersions.obsoleteAccepted).toEqual([]);
    // Kept so the panel can say "could not check" rather than implying refusal.
    expect(data!.tlsVersions.indeterminate).toEqual(["TLSv1"]);
  });

  it("omits the block for a scan that never enumerated versions", async () => {
    const data = await attackSurface(BASE);
    expect(data!.tlsVersions).toBeUndefined();
  });
});

describe("the existing email module is unchanged by the addition", () => {
  it("still grades SPF and DMARC", async () => {
    const data = await cloudFootprint({ emailSecurity: EMAIL_SEC });
    expect(data!.grades.spf).toBe("A");
    expect(data!.grades.dmarc).toBe("A");
    expect(data!.emailSecurity.spf.record).toBe("v=spf1 -all");
  });
});
