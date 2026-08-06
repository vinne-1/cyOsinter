/**
 * Unit tests for server/scanner/osint-email-dns.ts — SPF/DMARC finding builders and
 * the mail-context derivation that suppresses / downgrades false positives on
 * non-mail subdomains covered by an organizational DMARC policy.
 */
import { describe, it, expect } from "vitest";
import { buildSPFFindings, buildDMARCFindings, deriveMailContext } from "../../../server/scanner/osint-email-dns";

const now = "2026-01-01T00:00:00.000Z";
const noSpf = { found: false, record: "", issues: [] };
const noDmarc = { found: false, record: "", issues: [] };

describe("buildSPFFindings", () => {
  it("flags medium on an apex/mail domain with no SPF", () => {
    const f = buildSPFFindings("example.com", noSpf, [], now, { hasMx: true, isSubdomain: false });
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("medium");
  });

  it("downgrades to info on a non-mail subdomain (no MX)", () => {
    const f = buildSPFFindings("app.example.com", noSpf, [], now, { hasMx: false, isSubdomain: true, orgDmarcFound: true });
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("info");
    expect(f[0].title).toMatch(/non-mail subdomain/i);
  });
});

describe("buildDMARCFindings", () => {
  it("flags medium on an apex domain with no DMARC", () => {
    const f = buildDMARCFindings("example.com", noDmarc, now, { hasMx: true, isSubdomain: false });
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("medium");
  });

  it("SUPPRESSES entirely on a subdomain whose org domain has DMARC (false positive)", () => {
    const f = buildDMARCFindings("mydesk.example.com", noDmarc, now, { hasMx: false, isSubdomain: true, orgDmarcFound: true });
    expect(f).toHaveLength(0);
  });

  it("downgrades to info on a non-mail subdomain with no org DMARC signal", () => {
    const f = buildDMARCFindings("app.example.com", noDmarc, now, { hasMx: false, isSubdomain: true, orgDmarcFound: false });
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("info");
  });
});

describe("deriveMailContext", () => {
  it("marks an apex domain (2 labels) as not a subdomain and reads MX", async () => {
    const ctx = await deriveMailContext("example.com", [{ exchange: "mx.example.com" }], async () => []);
    expect(ctx.isSubdomain).toBe(false);
    expect(ctx.hasMx).toBe(true);
    expect(ctx.orgDmarcFound).toBe(false);
  });

  it("detects a subdomain and finds the parent DMARC record", async () => {
    const ctx = await deriveMailContext(
      "mydesk.example.com",
      [],
      async (name: string) => (name === "_dmarc.example.com" ? [["v=DMARC1; p=reject"]] : []),
    );
    expect(ctx.isSubdomain).toBe(true);
    expect(ctx.hasMx).toBe(false);
    expect(ctx.orgDmarcFound).toBe(true);
  });

  it("is resilient when the parent DMARC lookup throws", async () => {
    const ctx = await deriveMailContext("a.b.example.com", undefined, async () => { throw new Error("dns fail"); });
    expect(ctx.isSubdomain).toBe(true);
    expect(ctx.orgDmarcFound).toBe(false);
    expect(ctx.hasMx).toBe(false);
  });
});
