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

describe("the existing email module is unchanged by the addition", () => {
  it("still grades SPF and DMARC", async () => {
    const data = await cloudFootprint({ emailSecurity: EMAIL_SEC });
    expect(data!.grades.spf).toBe("A");
    expect(data!.grades.dmarc).toBe("A");
    expect(data!.emailSecurity.spf.record).toBe("v=spf1 -all");
  });
});
