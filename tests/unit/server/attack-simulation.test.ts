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
});
