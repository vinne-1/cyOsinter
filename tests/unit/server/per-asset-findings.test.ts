/**
 * Unit tests for server/scanner/per-asset-findings.ts.
 *
 * The behaviour under test decides whether findings can be attributed to an
 * asset at all. Before it existed, a Gold scan analysed every live subdomain and
 * emitted findings only for the apex, so `asset-risk-scoring.ts` — which matches
 * findings to assets by hostname — scored every non-apex asset at zero.
 */
import { describe, it, expect } from "vitest";
import {
  buildPerAssetFindings,
  buildPerAssetHeaderFindings,
  buildPerAssetTlsFindings,
  buildPerAssetLeakFindings,
} from "../../../server/scanner/per-asset-findings";

const NOW = "2026-01-01T00:00:00.000Z";
const APEX = "example.com";

const headers = (present: string[]) => {
  const all = [
    "Strict-Transport-Security (HSTS)",
    "Content-Security-Policy (CSP)",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
  ];
  return Object.fromEntries(all.map((h) => [h, { present: present.includes(h), value: present.includes(h) ? "set" : null }]));
};

describe("buildPerAssetHeaderFindings", () => {
  it("attributes each finding to the host it was observed on, not the apex", () => {
    const out = buildPerAssetHeaderFindings({
      apex: APEX,
      now: NOW,
      perAssetHeaders: {
        "api.example.com": headers([]),
        "admin.example.com": headers(["X-Frame-Options"]),
      },
    });
    expect(out.map((f) => f.affectedAsset).sort()).toEqual(["admin.example.com", "api.example.com"]);
    expect(out.every((f) => f.affectedAsset !== APEX)).toBe(true);
  });

  it("does not re-report the apex, which the main scan path already covers", () => {
    const out = buildPerAssetHeaderFindings({
      apex: APEX,
      now: NOW,
      perAssetHeaders: { [APEX]: headers([]) },
    });
    expect(out).toHaveLength(0);
  });

  /**
   * One finding per (host, header) would be 90 hosts x 6 headers for a single
   * misconfiguration — the mistake per-host cookie aggregation exists to avoid.
   */
  it("emits ONE finding per host with the individual headers as evidence", () => {
    const out = buildPerAssetHeaderFindings({
      apex: APEX,
      now: NOW,
      perAssetHeaders: { "api.example.com": headers([]) },
    });
    expect(out).toHaveLength(1);
    expect(out[0].evidence[0].snippet).toContain("[MISS] Strict-Transport-Security (HSTS)");
    expect(out[0].evidence[0].snippet).toContain("[MISS] Content-Security-Policy (CSP)");
  });

  it("scales severity with how many CRITICAL headers are absent", () => {
    const two = buildPerAssetHeaderFindings({
      apex: APEX, now: NOW,
      perAssetHeaders: { "a.example.com": headers(["X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]) },
    });
    expect(two[0].severity).toBe("medium");

    const one = buildPerAssetHeaderFindings({
      apex: APEX, now: NOW,
      perAssetHeaders: { "b.example.com": headers(["X-Frame-Options", "X-Content-Type-Options", "Content-Security-Policy (CSP)", "Referrer-Policy"]) },
    });
    expect(one[0].severity).toBe("low");
  });

  it("says nothing about a host whose critical headers are all present", () => {
    const out = buildPerAssetHeaderFindings({
      apex: APEX, now: NOW,
      perAssetHeaders: {
        "good.example.com": headers([
          "Strict-Transport-Security (HSTS)", "Content-Security-Policy (CSP)",
          "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy",
        ]),
      },
    });
    expect(out).toHaveLength(0);
  });

  it("caps the per-category output and summarises the remainder instead of flooding", () => {
    const many: Record<string, ReturnType<typeof headers>> = {};
    for (let i = 0; i < 200; i++) many[`h${i}.example.com`] = headers([]);
    const out = buildPerAssetHeaderFindings({ apex: APEX, now: NOW, perAssetHeaders: many });

    // 150 individual findings plus one overflow summary.
    expect(out).toHaveLength(151);
    const overflow = out[out.length - 1];
    expect(overflow.severity).toBe("info");
    expect(overflow.kind).toBe("recon");
    expect(overflow.title).toContain("50 further host(s)");
  });
});

describe("buildPerAssetTlsFindings", () => {
  it("ranks an expired certificate above one that merely expires soon", () => {
    const out = buildPerAssetTlsFindings({
      apex: APEX, now: NOW,
      perAssetTls: {
        "expired.example.com": { daysRemaining: -3, subject: "CN=expired", issuer: "CN=CA", protocol: "TLSv1.3" },
        "soon.example.com": { daysRemaining: 7, subject: "CN=soon", issuer: "CN=CA", protocol: "TLSv1.3" },
        "later.example.com": { daysRemaining: 25, subject: "CN=later", issuer: "CN=CA", protocol: "TLSv1.3" },
      },
    });
    const bySeverity = Object.fromEntries(out.map((f) => [f.affectedAsset, f.severity]));
    expect(bySeverity["expired.example.com"]).toBe("critical");
    expect(bySeverity["soon.example.com"]).toBe("high");
    expect(bySeverity["later.example.com"]).toBe("medium");
  });

  it("ignores healthy certificates and hosts with no certificate data", () => {
    const out = buildPerAssetTlsFindings({
      apex: APEX, now: NOW,
      perAssetTls: {
        "fine.example.com": { daysRemaining: 200 },
        "unknown.example.com": null,
        "nodata.example.com": { subject: "CN=x" },
      },
    });
    expect(out).toHaveLength(0);
  });
});

describe("buildPerAssetLeakFindings", () => {
  it("reports a banner per host and carries the leaked headers as evidence", () => {
    const out = buildPerAssetLeakFindings({
      apex: APEX, now: NOW,
      perAssetLeaks: {
        "api.example.com": ["Server: nginx/1.18.0", "X-Powered-By: PHP/7.4.3"],
        "clean.example.com": [],
      },
    });
    expect(out).toHaveLength(1);
    expect(out[0].affectedAsset).toBe("api.example.com");
    expect(out[0].severity).toBe("low");
    expect(out[0].evidence[0].snippet).toContain("nginx/1.18.0");
  });
});

describe("buildPerAssetFindings", () => {
  it("produces attributable findings across all three categories at once", () => {
    const out = buildPerAssetFindings({
      apex: APEX,
      now: NOW,
      perAssetHeaders: { "api.example.com": headers([]) },
      perAssetTls: { "api.example.com": { daysRemaining: 2 } },
      perAssetLeaks: { "api.example.com": ["Server: nginx/1.18.0"] },
    });
    expect(out).toHaveLength(3);
    expect(new Set(out.map((f) => f.category))).toEqual(
      new Set(["security_headers", "ssl_issue", "information_disclosure"]),
    );
    // The whole point: every one of them names the host, so asset-risk scoring
    // can match them to an asset in the inventory.
    expect(out.every((f) => f.affectedAsset === "api.example.com")).toBe(true);
  });

  it("returns nothing when no per-asset analysis ran", () => {
    expect(buildPerAssetFindings({ apex: APEX, now: NOW })).toEqual([]);
  });
});
