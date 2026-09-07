/**
 * Unit tests for the provenance layer in server/scanner/passive-sources.ts.
 *
 * Aggregating nine free indexes into one flat set threw away the strongest
 * quality signal available at zero cost: whether independent collectors agree.
 * These tests cover the attribution, the corroboration grading, and — equally
 * important — that a collector which THREW is recorded separately from one that
 * legitimately found nothing.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const fetchJSON = vi.fn();
const fetchText = vi.fn();
vi.mock("../../../server/scanner/http.js", () => ({
  fetchJSON: (...a: unknown[]) => fetchJSON(...a),
  fetchText: (...a: unknown[]) => fetchText(...a),
}));
vi.mock("../../../server/logger.js", () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));

import {
  fetchSubdomainsFromFreeSources,
  confidenceFromSources,
  normalizeHost,
  extractHostsFromText,
} from "../../../server/scanner/passive-sources";

const DOMAIN = "example.com";

beforeEach(() => {
  fetchJSON.mockReset();
  fetchText.mockReset();
  fetchJSON.mockResolvedValue(null);
  fetchText.mockResolvedValue(null);
});

describe("confidenceFromSources", () => {
  /**
   * Deliberately conservative: one source is `low` even when that source is
   * usually reliable, because the signal being graded is independence.
   */
  it("grades on how many independent sources agree", () => {
    expect(confidenceFromSources(["crtsh", "otx", "anubis"])).toBe("high");
    expect(confidenceFromSources(["crtsh", "otx"])).toBe("medium");
    expect(confidenceFromSources(["rapiddns"])).toBe("low");
    expect(confidenceFromSources([])).toBe("low");
  });
});

describe("normalizeHost", () => {
  it("strips wildcards, schemes, ports and trailing dots", () => {
    expect(normalizeHost("*.api.example.com", DOMAIN)).toBe("api.example.com");
    expect(normalizeHost("https://api.example.com:8443/path", DOMAIN)).toBe("api.example.com");
    expect(normalizeHost("API.Example.Com.", DOMAIN)).toBe("api.example.com");
  });

  it("rejects the apex and anything off-domain", () => {
    expect(normalizeHost("example.com", DOMAIN)).toBeNull();
    expect(normalizeHost("api.notexample.com", DOMAIN)).toBeNull();
    expect(normalizeHost("evil-example.com", DOMAIN)).toBeNull();
  });
});

describe("fetchSubdomainsFromFreeSources", () => {
  it("records which sources named each host", async () => {
    // crt.sh and certspotter both see api; only anubis sees legacy.
    fetchJSON.mockImplementation(async (url: string) => {
      if (url.includes("crt.sh")) return [{ name_value: "api.example.com" }];
      if (url.includes("certspotter")) return [{ dns_names: ["api.example.com"] }];
      if (url.includes("jldc.me")) return ["legacy.example.com"];
      return null;
    });

    const out = await fetchSubdomainsFromFreeSources(DOMAIN);

    expect(out.subdomains).toEqual(["api.example.com", "legacy.example.com"]);
    expect(out.provenance["api.example.com"]).toEqual(["certspotter", "crtsh"]);
    expect(out.provenance["legacy.example.com"]).toEqual(["anubis"]);
    expect(confidenceFromSources(out.provenance["api.example.com"])).toBe("medium");
    expect(confidenceFromSources(out.provenance["legacy.example.com"])).toBe("low");
  });

  it("mines hostnames out of the wayback URL index", async () => {
    fetchJSON.mockImplementation(async (url: string) =>
      url.includes("web.archive.org")
        ? [["original"], ["http://old.example.com/index.html"], ["https://shop.example.com/cart"]]
        : null,
    );
    const out = await fetchSubdomainsFromFreeSources(DOMAIN);
    expect(out.subdomains).toEqual(["old.example.com", "shop.example.com"]);
    expect(out.provenance["old.example.com"]).toEqual(["wayback"]);
  });

  /**
   * The rule the whole scanner follows: a check that could not run must never
   * read as a check that found nothing.
   */
  it("separates a collector that threw from one that found nothing", async () => {
    fetchJSON.mockImplementation(async (url: string) => {
      if (url.includes("crt.sh")) throw new Error("crt.sh timed out");
      if (url.includes("certspotter")) return [];
      return null;
    });

    const out = await fetchSubdomainsFromFreeSources(DOMAIN);

    expect(out.sourcesFailed).toContain("crtsh");
    expect(out.bySource).not.toHaveProperty("crtsh");
    expect(out.bySource.certspotter).toBe(0);
  });

  /**
   * The subtler half of the same rule, and the one a live run actually caught:
   * `fetchJSON` returns null both when a request FAILS and when a body is
   * empty. Treating a null fetch as "answered with nothing" reported a
   * timed-out crt.sh as "crtsh: 0 subdomains" for a domain with hundreds of
   * certificates.
   */
  it("treats a null fetch as source-unavailable, not as an empty result", async () => {
    // Every source returns null (the shape fetchJSON/fetchText use for failure).
    const out = await fetchSubdomainsFromFreeSources(DOMAIN);
    expect(out.sourcesFailed).toEqual(
      expect.arrayContaining(["crtsh", "certspotter", "anubis", "threatminer", "urlscan", "wayback"]),
    );
    expect(out.bySource).toEqual({});
  });

  /**
   * OTX is KEYED now, not keyless: AlienVault ended anonymous access to the
   * passive-dns endpoint and answers `429 {"detail": "Anonymous access to this
   * endpoint is limited."}` to every unauthenticated request. Left in the
   * keyless set it failed on every scan, which put a permanent entry in
   * `sourcesFailed` and conflated "the operator has no key" with "this source
   * did not answer" — only the second says anything about the target, and a
   * `sourcesFailed` that is never empty is one nobody reads.
   */
  it("does not attempt OTX, or report it failed, when no key is configured", async () => {
    const prev = process.env.OTX_API_KEY;
    delete process.env.OTX_API_KEY;
    try {
      const out = await fetchSubdomainsFromFreeSources(DOMAIN);
      expect(out.sourcesFailed).not.toContain("otx");
      expect(Object.keys(out.bySource)).not.toContain("otx");
    } finally {
      if (prev !== undefined) process.env.OTX_API_KEY = prev;
    }
  });

  it("records a rate-limit sentence as unavailable rather than as zero hosts", async () => {
    fetchText.mockImplementation(async (url: string) =>
      url.includes("hackertarget") ? "error API count exceeded" : null,
    );
    const out = await fetchSubdomainsFromFreeSources(DOMAIN);
    expect(out.sourcesFailed).toContain("hackertarget");
    expect(out.bySource).not.toHaveProperty("hackertarget");
  });

  it("dedupes across sources and keeps the merged list sorted", async () => {
    fetchJSON.mockImplementation(async (url: string) => {
      if (url.includes("crt.sh")) return [{ name_value: "zeta.example.com\nalpha.example.com" }];
      if (url.includes("jldc.me")) return ["alpha.example.com"];
      return null;
    });
    const out = await fetchSubdomainsFromFreeSources(DOMAIN);
    expect(out.subdomains).toEqual(["alpha.example.com", "zeta.example.com"]);
    expect(out.provenance["alpha.example.com"]).toEqual(["anubis", "crtsh"]);
  });

  it("returns an empty-but-valid result when every source is silent", async () => {
    const out = await fetchSubdomainsFromFreeSources(DOMAIN);
    expect(out.subdomains).toEqual([]);
    expect(out.provenance).toEqual({});
    // Silence is unavailability here, and every source is reported as such.
    expect(out.sourcesFailed.length).toBeGreaterThan(0);
  });
});

describe("extractHostsFromText", () => {
  it("pulls on-domain hosts out of arbitrary text and ignores the rest", () => {
    const text = "see api.example.com and cdn.example.com, but not api.other.com";
    expect(extractHostsFromText(text, DOMAIN).sort()).toEqual(["api.example.com", "cdn.example.com"]);
  });
});
