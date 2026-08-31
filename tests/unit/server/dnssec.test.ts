import { describe, it, expect, vi } from "vitest";
import { checkDnssec, describeDnssec, buildDnssecFindings, type DohFetcher } from "../../../server/scanner/dnssec";

const DNSKEY = 48;
const DS = 43;

/** DoH stub keyed by record type in the request URL. */
function doh(responses: { dnskey?: unknown; ds?: unknown }): DohFetcher {
  return async (url: string) => {
    if (/type=DNSKEY/.test(url)) return (responses.dnskey ?? null) as any;
    if (/type=DS/.test(url)) return (responses.ds ?? null) as any;
    return null;
  };
}

const key = (alg: number) => ({ type: DNSKEY, data: `257 3 ${alg} AwEAAb...` });
const ds = () => ({ type: DS, data: "12345 13 2 ABCDEF" });

describe("checkDnssec", () => {
  it("reports a fully signed zone", () => {
    return expect(
      checkDnssec("example.com", doh({ dnskey: { AD: true, Answer: [key(13)] }, ds: { AD: true, Answer: [ds()] } })),
    ).resolves.toMatchObject({
      signed: true,
      state: "signed",
      dsPresent: true,
      dnskeyPresent: true,
      authenticatedData: true,
      algorithms: [13],
    });
  });

  it("reports an unsigned zone", async () => {
    const r = await checkDnssec("example.com", doh({ dnskey: { Status: 0, Answer: [] }, ds: { Status: 0, Answer: [] } }));
    expect(r.state).toBe("unsigned");
    expect(r.signed).toBe(false);
  });

  it("distinguishes keys published without a DS record at the parent", async () => {
    // A half-finished rollout. Rounding it to "signed" would be wrong (nothing
    // validates), and rounding it to "unsigned" hides work already done.
    const r = await checkDnssec("example.com", doh({ dnskey: { Answer: [key(8)] }, ds: { Answer: [] } }));
    expect(r.state).toBe("keys-without-delegation");
    expect(r.signed).toBe(false);
    expect(r.dnskeyPresent).toBe(true);
    expect(r.detail).toMatch(/chain of trust is broken/i);
  });

  it('reports "unverifiable" rather than "unsigned" when both resolvers fail', async () => {
    // The distinction is the whole point: inventing a security finding out of a
    // network failure is worse than reporting nothing.
    const r = await checkDnssec("example.com", async () => null);
    expect(r.state).toBe("unverifiable");
    expect(r.signed).toBe(false);
    expect(r.detail).toMatch(/could not be determined/i);
  });

  it("falls back to the second provider when the first is unreachable", async () => {
    const seen: string[] = [];
    const fetcher: DohFetcher = async (url) => {
      seen.push(url);
      if (url.includes("cloudflare")) return null;
      return /type=DNSKEY/.test(url) ? ({ Answer: [key(13)] } as any) : ({ Answer: [ds()] } as any);
    };
    const r = await checkDnssec("example.com", fetcher);
    expect(r.signed).toBe(true);
    expect(seen.some((u) => u.includes("cloudflare"))).toBe(true);
    expect(seen.some((u) => u.includes("dns.google"))).toBe(true);
  });

  it("ignores answers of the wrong record type", async () => {
    // A CNAME in the Answer section must not be counted as a signing key.
    const r = await checkDnssec("example.com", doh({ dnskey: { Answer: [{ type: 5, data: "x.example.com." }] }, ds: { Answer: [] } }));
    expect(r.dnskeyPresent).toBe(false);
    expect(r.state).toBe("unsigned");
  });

  it("collects distinct DNSKEY algorithms", async () => {
    const r = await checkDnssec("example.com", doh({ dnskey: { Answer: [key(8), key(13), key(13)] }, ds: { Answer: [ds()] } }));
    expect(r.algorithms).toEqual([8, 13]);
  });

  it("survives malformed DNSKEY rdata", async () => {
    const r = await checkDnssec("example.com", doh({ dnskey: { Answer: [{ type: DNSKEY, data: "garbage" }] }, ds: { Answer: [ds()] } }));
    expect(r.signed).toBe(true);
    expect(r.algorithms).toEqual([]);
  });

  it("requests the DO bit so signatures are returned", async () => {
    const spy = vi.fn(async () => null);
    await checkDnssec("example.com", spy);
    expect(spy.mock.calls.every(([url]) => (url as string).includes("do=1"))).toBe(true);
  });

  it("url-encodes the domain", async () => {
    const spy = vi.fn(async () => null);
    await checkDnssec("sub.example.com", spy);
    expect((spy.mock.calls[0][0] as string)).toContain("name=sub.example.com");
  });
});

describe("describeDnssec", () => {
  it("does not claim a zone is signed on the strength of an SOA record", async () => {
    // The bug this module replaces: the old check resolved SOA — which every
    // resolvable domain has — and the DOCX report printed
    // "DNSSEC: SOA present (zone signed / responsive)" for every target.
    const r = await checkDnssec("example.com", doh({ dnskey: { Answer: [] }, ds: { Answer: [] } }));
    expect(describeDnssec(r)).toBe("Not signed");
    expect(describeDnssec(r)).not.toMatch(/signed \/ responsive|SOA/i);
  });

  it("names the algorithm when the zone is signed", async () => {
    const r = await checkDnssec("example.com", doh({ dnskey: { Answer: [key(13)] }, ds: { Answer: [ds()] } }));
    expect(describeDnssec(r)).toBe("Signed (algorithm 13)");
  });

  it("says so plainly when the state could not be determined", async () => {
    const r = await checkDnssec("example.com", async () => null);
    expect(describeDnssec(r)).toBe("Could not be determined");
  });

  it("describes a half-finished rollout as such", async () => {
    const r = await checkDnssec("example.com", doh({ dnskey: { Answer: [key(13)] }, ds: { Answer: [] } }));
    expect(describeDnssec(r)).toMatch(/not delegated/i);
  });
});

describe("buildDnssecFindings", () => {
  const NOW = "2026-09-01T00:00:00.000Z";
  const status = async (responses: { dnskey?: unknown; ds?: unknown }) => checkDnssec("example.com", doh(responses));

  it("raises nothing for an unsigned zone", async () => {
    // Most domains are unsigned. A low-severity row on every single report is
    // noise nobody acts on, and it buries the findings that matter.
    expect(buildDnssecFindings("example.com", await status({ dnskey: { Answer: [] }, ds: { Answer: [] } }), NOW)).toEqual([]);
  });

  it("raises nothing for a correctly signed zone", async () => {
    expect(
      buildDnssecFindings("example.com", await status({ dnskey: { Answer: [key(13)] }, ds: { Answer: [ds()] } }), NOW),
    ).toEqual([]);
  });

  it("raises nothing when the state could not be determined", async () => {
    // A network failure must not become a security finding.
    const s = await checkDnssec("example.com", async () => null);
    expect(buildDnssecFindings("example.com", s, NOW)).toEqual([]);
  });

  it("raises a finding for a half-finished rollout", async () => {
    // Somebody signed the zone and the signing does nothing. That is a real,
    // fixable misconfiguration rather than an absence.
    const f = buildDnssecFindings("example.com", await status({ dnskey: { Answer: [key(13)] }, ds: { Answer: [] } }), NOW);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("low");
    expect(f[0].category).toBe("dns_misconfiguration");
    expect(f[0].description).toMatch(/cost of DNSSEC/i);
    expect(f[0].remediation).toMatch(/DS record.*registrar/i);
    expect(f[0].evidence?.[0].snippet).toMatch(/DS record at parent: absent/);
  });
});
