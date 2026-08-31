import { describe, it, expect } from "vitest";
import {
  analyseMailTransport,
  buildMailTransportFindings,
  mailTransportControls,
  parseMtaStsPolicy,
  type MailTransportAnalysis,
} from "../../../server/scanner/mail-transport-security";

const NOW = "2026-09-01T00:00:00.000Z";
const MAIL = { hasMx: true };

/** DNS stub: a map of name -> TXT strings. Unknown names resolve empty. */
function dns(records: Record<string, string[]>) {
  return async (name: string): Promise<string[][]> => (records[name] ?? []).map((r) => [r]);
}

/** HTTP stub for the well-known policy file. */
function http(bodies: Record<string, { status: number; body: string }>) {
  return async (url: string) => bodies[url] ?? null;
}

const NO_HTTP = async () => null;

describe("parseMtaStsPolicy", () => {
  it("parses a well-formed policy", () => {
    const p = parseMtaStsPolicy("version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: mail2.example.com\nmax_age: 604800");
    expect(p).toEqual({ version: "STSv1", mode: "enforce", mx: ["mail.example.com", "mail2.example.com"], maxAge: 604800 });
  });

  it("handles CRLF line endings", () => {
    // The RFC allows CRLF. Splitting on "\n" alone leaves a trailing carriage
    // return on every value, so `mode` would not equal "enforce" for a policy
    // that is completely valid.
    const p = parseMtaStsPolicy("version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\n");
    expect(p.mode).toBe("enforce");
    expect(p.mx).toEqual(["mail.example.com"]);
  });

  it("ignores blank and malformed lines rather than throwing", () => {
    const p = parseMtaStsPolicy("\n\nmode: enforce\ngarbage line with no colon\n\n");
    expect(p.mode).toBe("enforce");
  });
});

describe("analyseMailTransport", () => {
  it("reports nothing configured for a bare domain", async () => {
    const a = await analyseMailTransport("example.com", dns({}), NO_HTTP);
    expect(a.mtaSts.record).toBeUndefined();
    expect(a.tlsRpt.record).toBeUndefined();
    expect(a.bimi.record).toBeUndefined();
  });

  it("reads a fully enforcing MTA-STS setup", async () => {
    const a = await analyseMailTransport(
      "example.com",
      dns({ "_mta-sts.example.com": ["v=STSv1; id=20260101T000000"] }),
      http({
        "https://mta-sts.example.com/.well-known/mta-sts.txt": {
          status: 200,
          body: "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800",
        },
      }),
    );
    expect(a.mtaSts.mode).toBe("enforce");
    expect(a.mtaSts.mx).toEqual(["mail.example.com"]);
    expect(a.mtaSts.issues).toEqual([]);
  });

  it("flags a record whose policy file is unreachable", async () => {
    // Advertised but not in force is worse than not advertised: the domain
    // presents as protected and is not.
    const a = await analyseMailTransport(
      "example.com",
      dns({ "_mta-sts.example.com": ["v=STSv1; id=1"] }),
      http({}),
    );
    expect(a.mtaSts.issues.join(" ")).toMatch(/not retrievable/i);
  });

  it("flags testing mode as non-enforcing", async () => {
    const a = await analyseMailTransport(
      "example.com",
      dns({ "_mta-sts.example.com": ["v=STSv1; id=1"] }),
      http({
        "https://mta-sts.example.com/.well-known/mta-sts.txt": {
          status: 200,
          body: "version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 604800",
        },
      }),
    );
    expect(a.mtaSts.issues.join(" ")).toMatch(/testing mode/i);
  });

  it("flags a max_age too short to resist a downgrade", async () => {
    const a = await analyseMailTransport(
      "example.com",
      dns({ "_mta-sts.example.com": ["v=STSv1; id=1"] }),
      http({
        "https://mta-sts.example.com/.well-known/mta-sts.txt": {
          status: 200,
          body: "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 300",
        },
      }),
    );
    expect(a.mtaSts.issues.join(" ")).toMatch(/max_age is 300s/);
  });

  it("flags an MTA-STS record with no policy id", async () => {
    const a = await analyseMailTransport(
      "example.com",
      dns({ "_mta-sts.example.com": ["v=STSv1"] }),
      http({
        "https://mta-sts.example.com/.well-known/mta-sts.txt": {
          status: 200,
          body: "version: STSv1\nmode: enforce\nmx: m.example.com\nmax_age: 604800",
        },
      }),
    );
    expect(a.mtaSts.issues.join(" ")).toMatch(/no policy id/i);
  });

  it("reads TLS-RPT destinations", async () => {
    const a = await analyseMailTransport(
      "example.com",
      dns({ "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:a@example.com,mailto:b@example.com"] }),
      NO_HTTP,
    );
    expect(a.tlsRpt.rua).toEqual(["mailto:a@example.com", "mailto:b@example.com"]);
    expect(a.tlsRpt.issues).toEqual([]);
  });

  it("flags a TLS-RPT record with no reporting destination", async () => {
    const a = await analyseMailTransport("example.com", dns({ "_smtp._tls.example.com": ["v=TLSRPTv1;"] }), NO_HTTP);
    expect(a.tlsRpt.issues.join(" ")).toMatch(/no rua destination/i);
  });

  it("reads a BIMI record with logo and VMC", async () => {
    const a = await analyseMailTransport(
      "example.com",
      dns({ "default._bimi.example.com": ["v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"] }),
      NO_HTTP,
    );
    expect(a.bimi.logoUrl).toBe("https://example.com/logo.svg");
    expect(a.bimi.vmcUrl).toBe("https://example.com/vmc.pem");
  });

  it("flags a BIMI logo not served over HTTPS", async () => {
    const a = await analyseMailTransport(
      "example.com",
      dns({ "default._bimi.example.com": ["v=BIMI1; l=http://example.com/logo.svg"] }),
      NO_HTTP,
    );
    expect(a.bimi.issues.join(" ")).toMatch(/not served over HTTPS/i);
  });

  it("reassembles a TXT record DNS split into 255-byte chunks", async () => {
    // node's resolveTxt returns an array of character-strings per record. A long
    // policy arrives split, and joining with anything but "" corrupts it.
    const lookup = async (): Promise<string[][]> => [["v=STSv1; ", "id=20260101T000000"]];
    const a = await analyseMailTransport("example.com", lookup, http({}));
    expect(a.mtaSts.record).toBe("v=STSv1; id=20260101T000000");
    expect(a.mtaSts.id).toBe("20260101T000000");
  });

  it("survives a DNS lookup that throws", async () => {
    const lookup = async () => { throw new Error("ENOTFOUND"); };
    await expect(analyseMailTransport("example.com", lookup, NO_HTTP)).resolves.toBeDefined();
  });
});

describe("buildMailTransportFindings", () => {
  const empty: MailTransportAnalysis = {
    mtaSts: { mx: [], issues: [] },
    tlsRpt: { rua: [], issues: [] },
    bimi: { issues: [] },
  };

  it("reports nothing for a domain with no MX", () => {
    // A web-only host cannot receive mail, so transport controls are not a gap.
    // This is the discipline that keeps the findings list credible.
    expect(buildMailTransportFindings("www.example.com", empty, NOW, { hasMx: false })).toEqual([]);
  });

  it("reports missing MTA-STS and TLS-RPT for a mail domain", () => {
    const f = buildMailTransportFindings("example.com", empty, NOW, MAIL);
    expect(f.map((x) => x.title)).toEqual([
      "MTA-STS not configured for example.com",
      "SMTP TLS reporting (TLS-RPT) not configured for example.com",
    ]);
    expect(f[0].severity).toBe("medium");
    expect(f[1].severity).toBe("low");
  });

  it("explains why SPF/DKIM/DMARC do not cover this", () => {
    // The most common pushback on an MTA-STS finding is "we already have DMARC".
    const f = buildMailTransportFindings("example.com", empty, NOW, MAIL);
    expect(f[0].description).toMatch(/authenticate the message, not the connection/i);
  });

  it("does not re-report MTA-STS as missing when it is enforcing", () => {
    const a: MailTransportAnalysis = {
      ...empty,
      mtaSts: { record: "v=STSv1; id=1", mode: "enforce", mx: ["m.example.com"], issues: [] },
    };
    const titles = buildMailTransportFindings("example.com", a, NOW, MAIL).map((x) => x.title);
    expect(titles.some((t) => /MTA-STS/.test(t))).toBe(false);
  });

  it("ranks a non-enforcing policy as medium and an enforcing-but-imperfect one as low", () => {
    const testing: MailTransportAnalysis = {
      ...empty,
      mtaSts: { record: "v=STSv1; id=1", mode: "testing", mx: ["m"], issues: ["MTA-STS policy is in testing mode"] },
    };
    const enforcing: MailTransportAnalysis = {
      ...empty,
      mtaSts: { record: "v=STSv1; id=1", mode: "enforce", mx: ["m"], maxAge: 300, issues: ["max_age too short"] },
    };
    expect(buildMailTransportFindings("example.com", testing, NOW, MAIL)[0].severity).toBe("medium");
    expect(buildMailTransportFindings("example.com", enforcing, NOW, MAIL)[0].severity).toBe("low");
  });

  it("never reports a missing BIMI record", () => {
    // Absent BIMI is not a security weakness; flagging it would be a marketing
    // recommendation dressed up as a finding.
    const f = buildMailTransportFindings("example.com", empty, NOW, MAIL);
    expect(f.some((x) => /BIMI/i.test(x.title))).toBe(false);
  });

  it("reports BIMI published without DMARC at enforcement", () => {
    const a: MailTransportAnalysis = {
      ...empty,
      bimi: { record: "v=BIMI1; l=https://e/l.svg; a=https://e/v.pem", logoUrl: "https://e/l.svg", vmcUrl: "https://e/v.pem", issues: [] },
    };
    const f = buildMailTransportFindings("example.com", a, NOW, MAIL, "none");
    const bimi = f.find((x) => /BIMI/i.test(x.title));
    expect(bimi).toBeDefined();
    expect(bimi!.description).toMatch(/quarantine or reject/i);
  });

  it("accepts a BIMI record backed by an enforcing DMARC policy and a VMC", () => {
    const a: MailTransportAnalysis = {
      ...empty,
      bimi: { record: "v=BIMI1; l=https://e/l.svg; a=https://e/v.pem", logoUrl: "https://e/l.svg", vmcUrl: "https://e/v.pem", issues: [] },
    };
    const f = buildMailTransportFindings("example.com", a, NOW, MAIL, "reject");
    expect(f.some((x) => /BIMI/i.test(x.title))).toBe(false);
  });

  it("gives every finding a remediation with the exact record to publish", () => {
    const f = buildMailTransportFindings("example.com", empty, NOW, MAIL);
    expect(f[0].remediation).toMatch(/v=STSv1/);
    expect(f[1].remediation).toMatch(/v=TLSRPTv1/);
  });

  it("attaches evidence naming the query that was made", () => {
    const f = buildMailTransportFindings("example.com", empty, NOW, MAIL);
    expect(f[0].evidence?.[0].snippet).toMatch(/_mta-sts\.example\.com/);
    expect(f[1].evidence?.[0].snippet).toMatch(/_smtp\._tls\.example\.com/);
  });
});

describe("mailTransportControls", () => {
  it("credits only controls that are actually effective", () => {
    const a: MailTransportAnalysis = {
      mtaSts: { record: "v=STSv1", mode: "testing", mx: [], issues: [] },
      tlsRpt: { record: "v=TLSRPTv1", rua: ["mailto:a@e.com"], issues: [] },
      bimi: { record: "v=BIMI1", issues: [] },
    };
    // testing-mode MTA-STS and a VMC-less BIMI do not earn credit.
    expect(mailTransportControls(a)).toEqual(["TLS-RPT"]);
  });

  it("credits a fully configured domain", () => {
    const a: MailTransportAnalysis = {
      mtaSts: { record: "v=STSv1", mode: "enforce", mx: ["m"], issues: [] },
      tlsRpt: { record: "v=TLSRPTv1", rua: ["mailto:a@e.com"], issues: [] },
      bimi: { record: "v=BIMI1", vmcUrl: "https://e/v.pem", issues: [] },
    };
    expect(mailTransportControls(a)).toEqual(["MTA-STS", "TLS-RPT", "BIMI"]);
  });
});
