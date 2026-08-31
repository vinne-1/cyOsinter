import { describe, it, expect } from "vitest";
import { analyzeCaa, buildCaaFindings } from "../../../server/scanner/caa-analysis";

const NOW = "2026-09-01T00:00:00.000Z";

describe("analyzeCaa", () => {
  it("reports the absence of any CAA record", () => {
    const r = analyzeCaa("example.com", []);
    expect(r.present).toBe(false);
    expect(r.issues.join(" ")).toMatch(/any publicly trusted certificate authority may issue/i);
  });

  it("treats undefined the same as an empty set", () => {
    // A scan that could not read CAA and a domain with no CAA are both "no
    // restriction in force" as far as a CA is concerned.
    expect(analyzeCaa("example.com", undefined).present).toBe(false);
  });

  it("reads authorised issuers", () => {
    const r = analyzeCaa("example.com", [
      { tag: "issue", value: "letsencrypt.org" },
      { tag: "issue", value: "digicert.com" },
      { tag: "iodef", value: "mailto:security@example.com" },
    ]);
    expect(r.issuers).toEqual(["letsencrypt.org", "digicert.com"]);
    expect(r.iodef).toEqual(["mailto:security@example.com"]);
    expect(r.issues).toEqual([]);
  });

  it("separates wildcard issuers from ordinary ones", () => {
    const r = analyzeCaa("example.com", [
      { tag: "issue", value: "letsencrypt.org" },
      { tag: "issuewild", value: "digicert.com" },
      { tag: "iodef", value: "mailto:s@example.com" },
    ]);
    expect(r.issuers).toEqual(["letsencrypt.org"]);
    expect(r.wildcardIssuers).toEqual(["digicert.com"]);
  });

  it("ignores CAA parameters when reading the CA name", () => {
    // RFC 8659 allows 'ca.example.net; account=12345'.
    const r = analyzeCaa("example.com", [
      { tag: "issue", value: "letsencrypt.org; validationmethods=dns-01" },
      { tag: "iodef", value: "mailto:s@example.com" },
    ]);
    expect(r.issuers).toEqual(["letsencrypt.org"]);
  });

  it('recognises issue ";" as a deliberate lockdown, not an empty record', () => {
    const r = analyzeCaa("example.com", [
      { tag: "issue", value: ";" },
      { tag: "iodef", value: "mailto:s@example.com" },
    ]);
    expect(r.forbidsAll).toBe(true);
    expect(r.issues).toEqual([]);
  });

  it("flags records that authorise nothing and restrict nothing", () => {
    // Usually a typo'd tag. The domain looks configured and is in exactly the
    // same position as one publishing nothing.
    const r = analyzeCaa("example.com", [{ tag: "issuedns", value: "letsencrypt.org" }]);
    expect(r.issues.join(" ")).toMatch(/authorise nothing and restrict nothing/i);
  });

  it("flags a policy with no violation reporting address", () => {
    const r = analyzeCaa("example.com", [{ tag: "issue", value: "letsencrypt.org" }]);
    expect(r.issues.join(" ")).toMatch(/no iodef/i);
  });

  it("is case-insensitive about tags", () => {
    const r = analyzeCaa("example.com", [
      { tag: "ISSUE", value: "LetsEncrypt.org" },
      { tag: "IODEF", value: "mailto:s@example.com" },
    ]);
    expect(r.issuers).toEqual(["letsencrypt.org"]);
    expect(r.issues).toEqual([]);
  });
});

describe("buildCaaFindings", () => {
  it("reports nothing for a fully configured policy", () => {
    const a = analyzeCaa("example.com", [
      { tag: "issue", value: "letsencrypt.org" },
      { tag: "iodef", value: "mailto:s@example.com" },
    ]);
    expect(buildCaaFindings("example.com", a, NOW)).toEqual([]);
  });

  it("raises one low-severity finding when CAA is absent", () => {
    // Deliberately low: this is hardening, not something currently broken.
    // Grading it higher would rank it above findings that represent a live
    // failure, and severity inflation is what teaches people to ignore a
    // scanner.
    const f = buildCaaFindings("example.com", analyzeCaa("example.com", []), NOW);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("low");
    expect(f[0].category).toBe("certificate_authority");
  });

  it("explains what CAA prevents that Certificate Transparency does not", () => {
    // A finding that only says "no CAA record" gets closed as won't-fix.
    const f = buildCaaFindings("example.com", analyzeCaa("example.com", []), NOW);
    expect(f[0].description).toMatch(/Certificate Transparency tells you afterwards/i);
    expect(f[0].description).toMatch(/Baseline Requirements/i);
  });

  it("gives a remediation with a record that can be copied", () => {
    const f = buildCaaFindings("example.com", analyzeCaa("example.com", []), NOW);
    expect(f[0].remediation).toMatch(/IN CAA 0 issue/);
    expect(f[0].remediation).toMatch(/iodef/);
    // Publishing CAA that omits a CA you actually use breaks renewals, so the
    // remediation has to say so rather than just handing over a snippet.
    expect(f[0].remediation).toMatch(/every CA your certificates are currently issued by/i);
  });

  it("does not raise a finding for a missing iodef alone", () => {
    // Measured against real domains: google.com and github.com both restrict
    // issuance properly and publish no iodef. Calling their CAA "incomplete"
    // is noise, and it stays in the posture view instead.
    const a = analyzeCaa("example.com", [{ tag: "issue", value: "letsencrypt.org" }]);
    expect(a.issues.join(" ")).toMatch(/no iodef/i);
    expect(buildCaaFindings("example.com", a, NOW)).toEqual([]);
  });

  it("distinguishes a policy that authorises nobody from a missing one", () => {
    // Records present with a typo'd tag: looks configured, restricts nothing.
    const a = analyzeCaa("example.com", [{ tag: "issuedns", value: "letsencrypt.org" }]);
    const f = buildCaaFindings("example.com", a, NOW);
    expect(f).toHaveLength(1);
    expect(f[0].title).toMatch(/incomplete/i);
    expect(f[0].title).not.toMatch(/No CAA record/i);
  });

  it("records the authorised issuers in evidence", () => {
    const a = analyzeCaa("example.com", [{ tag: "issuedns", value: "x" }, { tag: "iodef", value: "mailto:s@e.com" }]);
    const f = buildCaaFindings("example.com", a, NOW);
    expect(f[0].evidence?.[0].snippet).toMatch(/CAA records: present/);
  });
});
