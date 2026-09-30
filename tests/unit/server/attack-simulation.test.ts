/**
 * Unit tests for server/attack-simulation.ts — attack playbooks must match the
 * scanner's REAL finding categories (underscore-style), not just OWASP hyphen names.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const getFindings = vi.fn();
vi.mock("../../../server/storage", () => ({
  storage: { getFindings: (...a: unknown[]) => getFindings(...a) },
}));

import { simulateAttack, getPlaybooks } from "../../../server/attack-simulation";

// A finding with a given real scanner category.
const f = (category: string, extra: Record<string, unknown> = {}) => ({
  id: `f-${category}-${Math.random().toString(36).slice(2, 6)}`,
  category, severity: "high", title: category, affectedAsset: "x.com", ...extra,
});

beforeEach(() => getFindings.mockReset());

describe("attack playbooks match real scanner categories", () => {
  it("exposes 6 playbooks", () => {
    expect(getPlaybooks().length).toBe(6);
  });

  it("XSS→ATO is exploitable from xss + cookie_security findings", async () => {
    getFindings.mockResolvedValue({ data: [f("xss"), f("cookie_security")] });
    const r = await simulateAttack("ws", "xss-account-takeover");
    expect(r.matchedSteps.length).toBeGreaterThanOrEqual(2);
    expect(r.exploitable).toBe(true);
  });

  it("Subdomain takeover matches subdomain_takeover findings (underscore vs hyphen)", async () => {
    getFindings.mockResolvedValue({ data: [f("subdomain_takeover"), f("dns_misconfiguration"), f("cloud_exposure")] });
    const r = await simulateAttack("ws", "subdomain-takeover");
    expect(r.matchedSteps.length).toBeGreaterThanOrEqual(2);
    expect(r.exploitable).toBe(true);
  });

  it("SSRF cloud-metadata matches open_redirect + cloud/secret exposure", async () => {
    getFindings.mockResolvedValue({ data: [f("open_redirect"), f("cloud_exposure"), f("secret_exposure")] });
    const r = await simulateAttack("ws", "ssrf-cloud-metadata");
    expect(r.matchedSteps.length).toBeGreaterThanOrEqual(2);
  });

  it("API auth bypass matches api_exposure + data_leak", async () => {
    getFindings.mockResolvedValue({ data: [f("api_exposure"), f("data_leak"), f("information_disclosure")] });
    const r = await simulateAttack("ws", "api-auth-bypass");
    expect(r.matchedSteps.length).toBeGreaterThanOrEqual(2);
    expect(r.exploitable).toBe(true);
  });

  it("Privilege escalation matches leaked_credential + vulnerability + api_exposure", async () => {
    getFindings.mockResolvedValue({ data: [f("leaked_credential"), f("vulnerability"), f("api_exposure")] });
    const r = await simulateAttack("ws", "privilege-escalation");
    expect(r.matchedSteps.length).toBeGreaterThanOrEqual(2);
  });

  it("SQL injection chain matches vulnerability + data_leak + leaked_credential", async () => {
    getFindings.mockResolvedValue({ data: [f("vulnerability"), f("data_leak"), f("leaked_credential"), f("information_disclosure")] });
    const r = await simulateAttack("ws", "sqli-chain");
    expect(r.matchedSteps.length).toBeGreaterThanOrEqual(2);
  });

  it("every playbook matches at least one step given a full spread of real categories", async () => {
    const cats = ["xss", "cookie_security", "subdomain_takeover", "dns_misconfiguration", "cloud_exposure",
      "container_exposure", "secret_exposure", "leaked_credential", "api_exposure", "information_disclosure",
      "data_leak", "vulnerability", "open_redirect", "infrastructure_disclosure"];
    getFindings.mockResolvedValue({ data: cats.map((c) => f(c)) });
    for (const pb of getPlaybooks()) {
      const r = await simulateAttack("ws", pb.id);
      expect(r.matchedSteps.length, `playbook ${pb.id} should match`).toBeGreaterThan(0);
    }
  });

  it("reports not-exploitable when no findings match", async () => {
    getFindings.mockResolvedValue({ data: [f("fonts"), f("analytics")] });
    const r = await simulateAttack("ws", "sqli-chain");
    expect(r.matchedSteps.length).toBe(0);
    expect(r.exploitable).toBe(false);
    expect(r.riskScore).toBe(0);
  });

  // Regression: a single weak, generic "Robots.txt Reveals Sensitive Paths"
  // (information_disclosure) finding was the ONLY evidence in a real workspace,
  // yet the SQL Injection Chain and API Authentication Bypass playbooks both
  // rendered as confident multi-step chains (Risk: 50 and 67) built entirely
  // from it. information_disclosure must no longer satisfy SQLi-chain steps at
  // all, and a lone info-disclosure finding must not carry API Auth Bypass past
  // its first (weakest) step.
  it("a single generic information_disclosure finding does not fabricate a SQLi chain", async () => {
    getFindings.mockResolvedValue({ data: [f("information_disclosure")] });
    const r = await simulateAttack("ws", "sqli-chain");
    expect(r.matchedSteps.length).toBe(0);
    expect(r.exploitable).toBe(false);
  });

  it("a single generic information_disclosure finding does not fabricate an API auth bypass chain past step 1", async () => {
    getFindings.mockResolvedValue({ data: [f("information_disclosure")] });
    const r = await simulateAttack("ws", "api-auth-bypass");
    expect(r.matchedSteps.length).toBe(1);
    expect(r.exploitable).toBe(false);
    expect(r.riskScore).toBeLessThan(30);
  });

  it("flags lowConfidence when the entire matched chain rests on one finding", async () => {
    const shared = f("leaked_credential");
    getFindings.mockResolvedValue({ data: [shared] });
    const r = await simulateAttack("ws", "privilege-escalation");
    expect(r.matchedSteps.length).toBeGreaterThanOrEqual(2);
    expect(r.lowConfidence).toBe(true);
    expect(r.exploitable).toBe(false);
    expect(r.riskScore).toBeLessThanOrEqual(35);
  });

  it("does not flag lowConfidence when distinct findings back the chain, even with adjacent overlap", async () => {
    getFindings.mockResolvedValue({ data: [f("api_exposure"), f("data_leak"), f("information_disclosure")] });
    const r = await simulateAttack("ws", "api-auth-bypass");
    expect(r.lowConfidence).toBe(false);
    expect(r.exploitable).toBe(true);
  });
});
