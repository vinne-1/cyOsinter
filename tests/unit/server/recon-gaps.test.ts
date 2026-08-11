/**
 * Unit tests for the recon-coverage gap-fills: reverse-IP co-hosted domains,
 * DigitalOcean Spaces / Firebase bucket targets, and (key-gated) GitHub dorking.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ── passive-sources.reverseIpLookup (mock the shared HTTP helpers) ──
const fetchText = vi.fn();
vi.mock("../../../server/scanner/http.js", () => ({
  fetchText: (...a: unknown[]) => fetchText(...a),
  fetchJSON: vi.fn(),
}));

import { reverseIpLookup } from "../../../server/scanner/passive-sources";
import { buildBucketTargets } from "../../../server/scanner/cloud-discovery";
import { buildGithubDorks, githubCodeSearch, runGithubDorks } from "../../../server/scanner/github-dork";

beforeEach(() => { fetchText.mockReset(); });

describe("reverseIpLookup", () => {
  it("returns co-hosted domains, excluding the target's own apex and subdomains", async () => {
    fetchText.mockResolvedValue("example.com\nwww.example.com\nneighbour-one.com\nother-site.org\n");
    const out = await reverseIpLookup(["1.2.3.4"], "example.com");
    expect(out["1.2.3.4"]).toEqual(["neighbour-one.com", "other-site.org"]);
  });

  it("treats API error sentences as no result (fail-soft)", async () => {
    fetchText.mockResolvedValue("API count exceeded - Increase Quota with Membership");
    const out = await reverseIpLookup(["1.2.3.4"], "example.com");
    expect(out["1.2.3.4"]).toBeUndefined();
  });

  it("skips IPs with no data and dedups", async () => {
    fetchText.mockResolvedValue("neighbour.com\nneighbour.com\n");
    const out = await reverseIpLookup(["9.9.9.9"], "example.com");
    expect(out["9.9.9.9"]).toEqual(["neighbour.com"]);
  });
});

describe("buildBucketTargets — expanded cloud providers", () => {
  it("includes DigitalOcean Spaces and Firebase Realtime DB targets", () => {
    const urls = buildBucketTargets("acme.com").map((t) => t.url);
    expect(urls.some((u) => /\.nyc3\.digitaloceanspaces\.com/.test(u))).toBe(true);
    expect(urls.some((u) => /\.firebaseio\.com\/\.json$/.test(u))).toBe(true);
    // Still covers the originals.
    expect(urls.some((u) => /\.s3\.amazonaws\.com/.test(u))).toBe(true);
    expect(urls.some((u) => /\.blob\.core\.windows\.net/.test(u))).toBe(true);
  });
  it("tags providers correctly", () => {
    const providers = new Set(buildBucketTargets("acme.com").map((t) => t.provider));
    expect(providers.has("DigitalOcean")).toBe(true);
    expect(providers.has("Firebase")).toBe(true);
  });
});

describe("GitHub dorking (key-gated)", () => {
  it("builds domain-scoped secret dorks", () => {
    const dorks = buildGithubDorks("acme.com");
    expect(dorks).toContain('"acme.com" filename:.env');
    expect(dorks.some((d) => d.includes("password"))).toBe(true);
  });

  it("no-ops without a token", async () => {
    const findings = await runGithubDorks("acme.com", "2026-01-01T00:00:00Z", { token: undefined });
    expect(findings).toEqual([]);
  });

  it("parses code-search hits and emits a single osint_exposure finding", async () => {
    const fakeFetch = vi.fn(async () => ({
      ok: true,
      json: async () => ({ items: [
        { repository: { full_name: "acme/leaky" }, path: ".env", html_url: "https://github.com/acme/leaky/blob/main/.env" },
        { repository: { full_name: "acme/leaky" }, path: ".env", html_url: "https://github.com/acme/leaky/blob/main/.env" }, // dup
      ] }),
    })) as unknown as typeof fetch;
    const findings = await runGithubDorks("acme.com", "2026-01-01T00:00:00Z", { token: "t", fetchImpl: fakeFetch, delayMs: 0 });
    expect(findings).toHaveLength(1);
    expect(findings[0].category).toBe("osint_exposure");
    // Deduped across queries → one evidence row.
    expect(findings[0].evidence).toHaveLength(1);
    expect(findings[0].evidence[0].url).toContain("github.com/acme/leaky");
  });

  it("githubCodeSearch returns [] on a non-OK response", async () => {
    const fakeFetch = vi.fn(async () => ({ ok: false, json: async () => ({}) })) as unknown as typeof fetch;
    expect(await githubCodeSearch('"acme.com" secret', "t", fakeFetch)).toEqual([]);
  });
});
