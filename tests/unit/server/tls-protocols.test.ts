import { describe, it, expect, vi } from "vitest";
import {
  enumerateTlsVersions,
  buildTlsProtocolFindings,
  TLS_VERSIONS,
  OBSOLETE_VERSIONS,
  type TlsVersion,
  type TlsVersionResult,
  type TlsProtocolReport,
} from "../../../server/scanner/tls-protocols";

const NOW = "2026-09-01T00:00:00.000Z";

/** Fake server: accepts exactly the listed versions, refuses the rest. */
function server(accepts: TlsVersion[]) {
  return async (_h: string, _p: number, version: TlsVersion): Promise<TlsVersionResult> =>
    accepts.includes(version)
      ? { version, supported: true, indeterminate: false, cipher: "ECDHE-RSA-AES128-SHA" }
      : { version, supported: false, indeterminate: false, error: "ERR_SSL_UNSUPPORTED_PROTOCOL" };
}

/** A host that answers nothing at all. */
const unreachable = async (_h: string, _p: number, version: TlsVersion): Promise<TlsVersionResult> => ({
  version,
  supported: false,
  indeterminate: true,
  error: "ECONNREFUSED",
});

describe("enumerateTlsVersions", () => {
  it("probes every known version", async () => {
    const probe = vi.fn(server([]));
    await enumerateTlsVersions("example.com", 443, probe);
    expect(probe).toHaveBeenCalledTimes(TLS_VERSIONS.length);
  });

  it("separates obsolete from modern acceptance", async () => {
    const r = await enumerateTlsVersions("example.com", 443, server(["TLSv1", "TLSv1.2", "TLSv1.3"]));
    expect(r.obsoleteAccepted).toEqual(["TLSv1"]);
    expect(r.modernAccepted).toEqual(["TLSv1.2", "TLSv1.3"]);
    expect(r.unreachable).toBe(false);
  });

  it("reports a modern-only server as having no obsolete support", async () => {
    const r = await enumerateTlsVersions("example.com", 443, server(["TLSv1.2", "TLSv1.3"]));
    expect(r.obsoleteAccepted).toEqual([]);
  });

  it("marks a host unreachable when every probe is indeterminate", async () => {
    // "Supports no TLS at all" would be a confident wrong answer about a host
    // that simply did not answer.
    const r = await enumerateTlsVersions("example.com", 443, unreachable);
    expect(r.unreachable).toBe(true);
    expect(r.obsoleteAccepted).toEqual([]);
  });

  it("is not fooled into 'unreachable' when only some probes are indeterminate", async () => {
    const probe = async (_h: string, _p: number, version: TlsVersion): Promise<TlsVersionResult> =>
      version === "TLSv1.3"
        ? { version, supported: false, indeterminate: true, error: "timeout" }
        : { version, supported: version === "TLSv1.2", indeterminate: false };
    const r = await enumerateTlsVersions("example.com", 443, probe);
    expect(r.unreachable).toBe(false);
    expect(r.modernAccepted).toEqual(["TLSv1.2"]);
  });

  it("probes sequentially rather than opening four handshakes at once", async () => {
    let inFlight = 0;
    let peak = 0;
    const probe = async (_h: string, _p: number, version: TlsVersion): Promise<TlsVersionResult> => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 1));
      inFlight -= 1;
      return { version, supported: false, indeterminate: false };
    };
    await enumerateTlsVersions("example.com", 443, probe);
    expect(peak).toBe(1);
  });
});

describe("buildTlsProtocolFindings", () => {
  const report = (over: Partial<TlsProtocolReport>): TlsProtocolReport => ({
    host: "example.com",
    port: 443,
    results: [],
    obsoleteAccepted: [],
    modernAccepted: [],
    unreachable: false,
    ...over,
  });

  it("reports nothing for a modern-only server", () => {
    expect(buildTlsProtocolFindings("example.com", report({ modernAccepted: ["TLSv1.2", "TLSv1.3"] }), NOW)).toEqual([]);
  });

  it("reports nothing when the host could not be reached", () => {
    // Silence is the correct output for a host we learned nothing about.
    expect(buildTlsProtocolFindings("example.com", report({ unreachable: true }), NOW)).toEqual([]);
  });

  it("never reports the absence of TLS 1.3", () => {
    // A server without TLS 1.3 is not insecure; flagging it would put a
    // modernisation suggestion in a list of security problems.
    const f = buildTlsProtocolFindings("example.com", report({ modernAccepted: ["TLSv1.2"] }), NOW);
    expect(f).toEqual([]);
  });

  it("grades a server that also supports modern TLS as medium", () => {
    const f = buildTlsProtocolFindings(
      "example.com",
      report({ obsoleteAccepted: ["TLSv1"], modernAccepted: ["TLSv1.2", "TLSv1.3"] }),
      NOW,
    );
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("medium");
  });

  it("names versions the way people write them, not as OpenSSL identifiers", () => {
    // Left raw, the title read "accepts obsolete TLS TLSv1".
    const f = buildTlsProtocolFindings(
      "example.com",
      report({ obsoleteAccepted: ["TLSv1", "TLSv1.1"], modernAccepted: ["TLSv1.2"] }),
      NOW,
    );
    expect(f[0].title).toContain("obsolete TLS 1.0/1.1");
    expect(f[0].title).not.toContain("TLSv");
  });

  it("grades an obsolete-only server as high", () => {
    const f = buildTlsProtocolFindings("example.com", report({ obsoleteAccepted: ["TLSv1", "TLSv1.1"] }), NOW);
    expect(f[0].severity).toBe("high");
    expect(f[0].description).toMatch(/no modern version at all/i);
  });

  it("explains why a server that negotiates TLS 1.3 normally is still a problem", () => {
    // Without this, the finding reads as pedantry: "we use TLS 1.3, what is the
    // issue?" The answer is downgrade, and it has to be stated.
    const f = buildTlsProtocolFindings(
      "example.com",
      report({ obsoleteAccepted: ["TLSv1"], modernAccepted: ["TLSv1.3"] }),
      NOW,
    );
    expect(f[0].description).toMatch(/invisible in normal use/i);
    expect(f[0].description).toMatch(/force the connection/i);
  });

  it("cites the standards, because compliance is often what gets it fixed", () => {
    const f = buildTlsProtocolFindings("example.com", report({ obsoleteAccepted: ["TLSv1"] }), NOW);
    expect(f[0].description).toMatch(/RFC 8996/);
    expect(f[0].description).toMatch(/PCI DSS/);
  });

  it("warns about legacy clients in the remediation", () => {
    // Disabling TLS 1.0 can cut off real users; a remediation that omits that
    // invites an outage.
    const f = buildTlsProtocolFindings("example.com", report({ obsoleteAccepted: ["TLSv1"] }), NOW);
    expect(f[0].remediation).toMatch(/Android 4\.4|IE10/);
  });

  it("distinguishes refused from could-not-determine in the evidence", () => {
    // The difference matters: one is the server's answer, the other is ours.
    const f = buildTlsProtocolFindings(
      "example.com",
      report({
        obsoleteAccepted: ["TLSv1"],
        modernAccepted: ["TLSv1.2"],
        results: [
          { version: "TLSv1", supported: true, indeterminate: false, cipher: "AES128-SHA" },
          { version: "TLSv1.1", supported: false, indeterminate: false, error: "ERR_SSL_UNSUPPORTED_PROTOCOL" },
          { version: "TLSv1.2", supported: true, indeterminate: false },
          { version: "TLSv1.3", supported: false, indeterminate: true, error: "timeout" },
        ],
      }),
      NOW,
    );
    const snippet = String(f[0].evidence?.[0].snippet);
    expect(snippet).toMatch(/TLSv1: accepted \(AES128-SHA\)/);
    expect(snippet).toMatch(/TLSv1\.1: refused/);
    expect(snippet).toMatch(/TLSv1\.3: could not determine/);
  });
});

describe("version vocabulary", () => {
  it("treats exactly TLS 1.0 and 1.1 as obsolete", () => {
    expect(OBSOLETE_VERSIONS).toEqual(["TLSv1", "TLSv1.1"]);
    expect(OBSOLETE_VERSIONS).not.toContain("TLSv1.2");
  });

  it("lists versions oldest first", () => {
    expect(TLS_VERSIONS[0]).toBe("TLSv1");
    expect(TLS_VERSIONS[TLS_VERSIONS.length - 1]).toBe("TLSv1.3");
  });
});
