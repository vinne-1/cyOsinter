/**
 * Unit tests for server/scanner/asn-expansion.ts.
 *
 * The attribution gate is the whole module. Expanding the AS behind a target's
 * IP without one would enumerate Cloudflare's ten-million-address space and
 * attribute it to a single customer — the S3 bucket-attribution error scaled up
 * by six orders of magnitude, with scanner traffic attached. Most of these tests
 * therefore assert REFUSAL.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const fetchJSON = vi.fn();
const fetchBGPView = vi.fn();
vi.mock("../../../server/scanner/http.js", () => ({ fetchJSON: (...a: unknown[]) => fetchJSON(...a) }));
vi.mock("../../../server/api-integrations.js", () => ({ fetchBGPView: (...a: unknown[]) => fetchBGPView(...a) }));
vi.mock("../../../server/logger.js", () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));

import {
  runAsnExpansion,
  attributeAsn,
  looksLikeSharedInfrastructure,
  addressesInPrefix,
  fetchAsnPrefixes,
} from "../../../server/scanner/asn-expansion";

const ORG = ["acmecorp", "Acme Corporation"];

beforeEach(() => {
  fetchJSON.mockReset();
  fetchBGPView.mockReset();
});

describe("addressesInPrefix", () => {
  it("counts IPv4 address space", () => {
    expect(addressesInPrefix("192.0.2.0/24")).toBe(256);
    expect(addressesInPrefix("10.0.0.0/16")).toBe(65536);
    expect(addressesInPrefix("203.0.113.5/32")).toBe(1);
  });

  it("caps enormous IPv6 prefixes rather than overflowing", () => {
    expect(addressesInPrefix("2001:db8::/32")).toBe(Number.MAX_SAFE_INTEGER);
  });

  it("returns 0 for a malformed prefix", () => {
    expect(addressesInPrefix("not-a-prefix")).toBe(0);
    expect(addressesInPrefix("10.0.0.0/99")).toBe(0);
  });
});

describe("looksLikeSharedInfrastructure", () => {
  it("recognises the providers whose space belongs to their customers", () => {
    for (const n of ["CLOUDFLARENET", "AMAZON-02", "GOOGLE", "MICROSOFT-CORP-MSN-AS-BLOCK", "AKAMAI-AS", "FASTLY", "DIGITALOCEAN-ASN", "OVH SAS", "HETZNER-AS"]) {
      expect(looksLikeSharedInfrastructure(n), n).toBe(true);
    }
  });

  it("does not flag an ordinary corporate AS name", () => {
    expect(looksLikeSharedInfrastructure("ACMECORP-AS", "Acme Corporation")).toBe(false);
  });
});

describe("attributeAsn", () => {
  /**
   * The failure this module exists to prevent. A site behind Cloudflare
   * resolves into AS13335; expanding it would claim a large slice of the
   * internet for one customer.
   */
  it("refuses to expand a CDN even when the description mentions the org", () => {
    const r = attributeAsn({ asn: 13335, name: "CLOUDFLARENET", description: "Cloudflare, Inc. — acmecorp" }, ORG);
    expect(r.attribution).toBe("shared");
    expect(r.reason).toMatch(/customers/i);
  });

  it("attributes an AS that names the organisation and is not a provider", () => {
    const r = attributeAsn({ asn: 64500, name: "ACMECORP-AS", description: "Acme Corporation" }, ORG);
    expect(r.attribution).toBe("owned");
  });

  it("returns unknown — never owned — when nothing ties the AS to the org", () => {
    const r = attributeAsn({ asn: 64501, name: "SOMEONE-ELSE-AS", description: "Unrelated Ltd" }, ORG);
    expect(r.attribution).toBe("unknown");
    expect(r.reason).toMatch(/no expansion performed/i);
  });

  /**
   * A carrier can legitimately carry the organisation's name. Size is what
   * separates "our /24" from "our national telco".
   */
  it("treats an implausibly large AS as infrastructure even when the name matches", () => {
    const r = attributeAsn({ asn: 64502, name: "ACMECORP-AS" }, ORG, 5_000_000);
    expect(r.attribution).toBe("shared");
    expect(r.reason).toMatch(/larger than any single organisation/i);
  });

  it("ignores short org tokens that would match on coincidence", () => {
    const r = attributeAsn({ asn: 64503, name: "BTX-NETWORKS" }, ["bt"]);
    expect(r.attribution).toBe("unknown");
  });
});

describe("runAsnExpansion", () => {
  it("expands only the owned AS and reports why the others were refused", async () => {
    fetchBGPView.mockResolvedValue({
      ip: "203.0.113.10",
      prefixes: [
        { prefix: "203.0.113.0/24", asn: { asn: 64500, name: "ACMECORP-AS", description: "Acme Corporation" } },
        { prefix: "203.0.113.0/24", asn: { asn: 13335, name: "CLOUDFLARENET", description: "Cloudflare, Inc." } },
      ],
    });
    fetchJSON.mockResolvedValue({
      data: { prefixes: [{ prefix: "203.0.113.0/24" }, { prefix: "198.51.100.0/24" }] },
    });

    const out = await runAsnExpansion(["203.0.113.10"], ORG);

    expect(out.unavailable).toBe(false);
    expect(out.ownedPrefixes.map((p) => p.prefix)).toEqual(["203.0.113.0/24", "198.51.100.0/24"]);
    expect(out.ownedAddressCount).toBe(512);
    // Cloudflare's prefix list must never have been requested.
    expect(fetchJSON).toHaveBeenCalledTimes(1);
    expect(out.notes.some((n) => /CLOUDFLARENET/.test(n))).toBe(true);
  });

  /**
   * The size gate can only run once the prefixes are in hand, so an AS that
   * passes on name must be re-checked and dropped if it turns out to be a
   * carrier.
   */
  it("drops an AS that passes on name but turns out to announce carrier-scale space", async () => {
    fetchBGPView.mockResolvedValue({
      ip: "203.0.113.10",
      prefixes: [{ prefix: "203.0.113.0/24", asn: { asn: 64500, name: "ACMECORP-AS" } }],
    });
    fetchJSON.mockResolvedValue({ data: { prefixes: [{ prefix: "10.0.0.0/8" }] } }); // 16.7M IPv4

    const out = await runAsnExpansion(["203.0.113.10"], ORG);

    expect(out.ownedPrefixes).toEqual([]);
    expect(out.asns.find((a) => a.asn === 64500)!.attribution).toBe("shared");
    expect(out.notes.some((n) => /larger than any single organisation/i.test(n))).toBe(true);
  });

  /**
   * "We could not check" must never render as "this organisation announces
   * nothing" — the same rule every other check in the scanner follows.
   */
  it("reports unavailable when routing data cannot be reached", async () => {
    fetchBGPView.mockResolvedValue(null);
    const out = await runAsnExpansion(["203.0.113.10"], ORG);
    expect(out.unavailable).toBe(true);
    expect(out.ownedPrefixes).toEqual([]);
    expect(out.notes[0]).toMatch(/not evidence that it announces none/i);
  });

  it("notes an owned AS whose prefix list could not be retrieved", async () => {
    fetchBGPView.mockResolvedValue({
      ip: "203.0.113.10",
      prefixes: [{ prefix: "203.0.113.0/24", asn: { asn: 64500, name: "ACMECORP-AS" } }],
    });
    fetchJSON.mockResolvedValue(null);

    const out = await runAsnExpansion(["203.0.113.10"], ORG);
    expect(out.ownedPrefixes).toEqual([]);
    expect(out.notes.some((n) => /could not be retrieved/i.test(n))).toBe(true);
  });
});

describe("fetchAsnPrefixes", () => {
  it("reads RIPEstat announced-prefixes and sizes each", async () => {
    fetchJSON.mockResolvedValue({ data: { prefixes: [{ prefix: "192.0.2.0/24" }, { prefix: "2001:db8::/48" }] } });
    const out = await fetchAsnPrefixes(64500);
    expect(out).toHaveLength(2);
    expect(out![0].size).toBe(256);
    expect(fetchJSON.mock.calls[0][0]).toContain("stat.ripe.net");
  });

  /**
   * A single routing source is how "this organisation announces nothing"
   * becomes a confident wrong answer: api.bgpview.io was not resolvable at all
   * from the development network, while RIPEstat answered fine.
   */
  it("falls back to BGPView when RIPEstat does not answer", async () => {
    fetchJSON.mockImplementation(async (url: string) =>
      url.includes("ripe.net")
        ? null
        : { data: { ipv4_prefixes: [{ prefix: "198.51.100.0/24" }], ipv6_prefixes: [] } },
    );
    const out = await fetchAsnPrefixes(64500);
    expect(out!.map((p) => p.prefix)).toEqual(["198.51.100.0/24"]);
    expect(fetchJSON.mock.calls.some((c) => String(c[0]).includes("bgpview"))).toBe(true);
  });

  it("returns null — not an empty list — when both sources are unavailable", async () => {
    fetchJSON.mockResolvedValue(null);
    expect(await fetchAsnPrefixes(64500)).toBeNull();
  });
});
