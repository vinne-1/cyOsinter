/**
 * Unit tests for server/report-docx.ts — the Node DOCX report generator.
 */
import { describe, it, expect } from "vitest";
import { generateReportDocx, type ReportDocxInput } from "../../../server/report-docx";

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
});
