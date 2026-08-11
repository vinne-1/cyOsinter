/**
 * Unit tests for server/report-docx.ts — the Node DOCX report generator.
 */
import { describe, it, expect } from "vitest";
import JSZip from "jszip";
import { generateReportDocx, type ReportDocxInput } from "../../../server/report-docx";

/** Extract the concatenated visible text of a generated DOCX for assertions. */
async function docText(buf: Buffer): Promise<string> {
  const zip = await JSZip.loadAsync(buf);
  const xml = await zip.file("word/document.xml")!.async("string");
  return xml
    .replace(/<[^>]+>/g, " ")
    .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'")
    .replace(/\s+/g, " ");
}

// Minimal valid 1x1 PNG.
const PNG_1x1 = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
  "base64",
);

const baseInput: ReportDocxInput = {
  target: "example.com",
  org: "Example Corp",
  ipAddress: "1.2.3.4",
  scanMode: "safe",
  recon: {
    ips: ["1.2.3.4"],
    ns: ["ns1.example.net"],
    subdomains: ["www.example.com", "mail.example.com"],
    ssl: { subject: "*.example.com", issuer: "Let's Encrypt", protocol: "TLSv1.3", daysRemaining: 69, altNames: ["*.example.com"] },
    emailSecurity: { spf: { found: true, record: "v=spf1 -all" }, dmarc: { found: false }, dkim: { found: true }, mx: [{ exchange: "mx.example.com" }] },
    ports: [{ port: 3306, service: "MySQL", banner: "5.7.23" }, { port: 443, service: "https" }],
    wordpress: { isWordPress: true, users: [{ id: 1, slug: "admin_x" }], xmlrpcEnabled: true },
  },
  findings: [
    { title: "MySQL exposed to Internet", severity: "high", category: "network_exposure", affectedAsset: "1.2.3.4:3306", description: "Port 3306 reachable.", cvssScore: "7.5", remediation: "Firewall it.", evidenceText: "1.2.3.4:3306 MySQL 5.7.23", evidenceImageKey: "shodan" },
    { title: "No DMARC record", severity: "medium", category: "email_security", affectedAsset: "example.com", description: "No _dmarc TXT.", cvssScore: "5.9", remediation: "Publish DMARC." },
    { title: "Subdomains via CT", severity: "info", category: "osint", affectedAsset: "*.example.com", description: "2 subdomains." },
  ],
  falsePositives: [{ claim: "S3 bucket", result: "404 NoSuchBucket", verdict: "FALSE POSITIVE" }],
  images: { shodan: PNG_1x1 },
};

describe("generateReportDocx", () => {
  it("produces a valid, non-trivial DOCX (zip) buffer", async () => {
    const buf = await generateReportDocx(baseInput);
    expect(Buffer.isBuffer(buf)).toBe(true);
    // DOCX is a ZIP — must start with the PK\x03\x04 local file header.
    expect(buf.subarray(0, 2).toString("latin1")).toBe("PK");
    expect(buf.length).toBeGreaterThan(3000);
  });

  it("works with no recon, no images, and empty findings (fail-soft)", async () => {
    const buf = await generateReportDocx({ target: "x.com", findings: [] });
    expect(buf.subarray(0, 2).toString("latin1")).toBe("PK");
    expect(buf.length).toBeGreaterThan(1500);
  });

  it("handles findings without optional fields", async () => {
    const buf = await generateReportDocx({
      target: "x.com",
      findings: [{ title: "Bare finding", severity: "low", category: "misc", affectedAsset: "x.com" }],
    });
    expect(buf.subarray(0, 2).toString("latin1")).toBe("PK");
  });

  it("surfaces every collected lookup: DNS records, WHOIS, IP reputation, reverse DNS, redirect chain", async () => {
    const rich: ReportDocxInput = {
      target: "example.com",
      findings: [],
      recon: {
        ips: ["1.2.3.4"],
        ptr: { "1.2.3.4": ["host.example.net"] },
        dnsRecords: {
          a: ["1.2.3.4"], aaaa: ["2001:db8::1"], ns: ["ns1.example.net"],
          mx: [{ priority: 10, exchange: "mx1.example.com" }],
          caa: [{ tag: "issue", value: "letsencrypt.org" }],
          soa: { nsname: "ns1.example.net", hostmaster: "hostmaster.example.com" },
          txt: [["v=spf1 -all"]],
        },
        dnssec: { soaPresent: true },
        whois: { Registrar: "GoDaddy", "Creation Date": "2001-01-01", "Registry Expiry Date": "2030-01-01" },
        ipReputation: [{ ip: "1.2.3.4", abuseScore: 42, totalReports: 7, vtMalicious: 3, asn: 15169, asnName: "GOOGLE", country: "US", city: "Mountain View", ptr: "host.example.net" }],
        geo: { country: "US", city: "Mountain View", org: "Google LLC" },
        redirectChain: [{ status: 301, url: "http://example.com", location: "https://example.com" }, { status: 200, url: "https://example.com" }],
        coHostedDomains: { "1.2.3.4": ["neighbour-one.com", "neighbour-two.org"] },
      },
    };
    const text = await docText(await generateReportDocx(rich));
    // DNS records section
    expect(text).toContain("DNS Records");
    expect(text).toContain("mx1.example.com (pri 10)");
    expect(text).toContain("letsencrypt.org"); // CAA
    expect(text).toContain("DNSSEC");
    // WHOIS
    expect(text).toContain("Domain Registration (WHOIS)");
    expect(text).toContain("GoDaddy");
    // IP reputation
    expect(text).toContain("IP Reputation & Hosting");
    expect(text).toContain("AS15169");
    expect(text).toMatch(/42%/);
    // Reverse DNS (PTR) in Target Information
    expect(text).toContain("host.example.net");
    // Redirect chain
    expect(text).toContain("HTTP Redirect Chain");
    // Co-hosted domains (reverse IP)
    expect(text).toContain("Co-hosted Domains (Reverse IP)");
    expect(text).toContain("neighbour-one.com");
  });

  it("omits the new sections entirely when their data is absent (no empty tables)", async () => {
    const text = await docText(await generateReportDocx({ target: "bare.com", findings: [] }));
    expect(text).not.toContain("DNS Records");
    expect(text).not.toContain("Domain Registration (WHOIS)");
    expect(text).not.toContain("IP Reputation & Hosting");
    expect(text).not.toContain("HTTP Redirect Chain");
    expect(text).not.toContain("Co-hosted Domains (Reverse IP)");
  });
});
