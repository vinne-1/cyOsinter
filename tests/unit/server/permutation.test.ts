/**
 * Subdomain permutation.
 *
 * Discovery ran three ways — certificate transparency, a 2,258-word list, and
 * nine passive indexes — and all three can only return a name that already
 * exists somewhere public. A host never certificated, never crawled, and not
 * named after a common word was invisible to every one of them.
 *
 * This generates candidates from the target's OWN naming convention, so the
 * tests below are mostly about two things: that the convention is actually
 * learned, and that the combinatorial budget stays bounded.
 */
import { describe, it, expect } from "vitest";
import {
  generatePermutations,
  subdomainPrefix,
  tokenize,
  numberMutations,
} from "../../../server/scanner/permutation";

describe("subdomainPrefix", () => {
  it("returns the part below the apex", () => {
    expect(subdomainPrefix("api.example.com", "example.com")).toBe("api");
    expect(subdomainPrefix("a.b.example.com", "example.com")).toBe("a.b");
  });

  it("returns null for the apex itself", () => {
    expect(subdomainPrefix("example.com", "example.com")).toBeNull();
  });

  /** `notexample.com` must not be read as a subdomain of `example.com`. */
  it("refuses a host that merely ends with the domain text", () => {
    expect(subdomainPrefix("notexample.com", "example.com")).toBeNull();
    expect(subdomainPrefix("example.com.evil.net", "example.com")).toBeNull();
  });

  it("is case- and trailing-dot-insensitive", () => {
    expect(subdomainPrefix("API.Example.com.", "example.com")).toBe("api");
  });
});

describe("tokenize", () => {
  it("splits on the separators organisations compose names with", () => {
    expect(tokenize("staging-api")).toEqual(["staging", "api"]);
    expect(tokenize("corp.vpn")).toEqual(["corp", "vpn"]);
  });

  /**
   * Splitting the digit boundary is what makes the vocabulary reusable: without
   * it the learned words are `web01`, `web02`, `web03` rather than `web`.
   */
  it("strips a trailing number to recover the stem", () => {
    expect(tokenize("web01")).toEqual(["web"]);
    expect(tokenize("api2")).toEqual(["api"]);
  });

  it("drops fragments too short to be meaningful", () => {
    expect(tokenize("a-api")).toEqual(["api"]);
  });
});

describe("numberMutations", () => {
  it("suggests neighbours of an existing number", () => {
    expect(numberMutations("web2")).toContain("web1");
    expect(numberMutations("web2")).toContain("web3");
  });

  /** An estate naming hosts `web01` almost never also has `web2`. */
  it("preserves zero padding", () => {
    const m = numberMutations("web01");
    expect(m).toContain("web02");
    expect(m).toContain("web2"); // both forms offered; padding is not assumed
  });

  it("adds numbers to an unnumbered prefix", () => {
    const m = numberMutations("api");
    expect(m).toContain("api1");
    expect(m).toContain("api2");
    expect(m).toContain("api01");
  });

  it("never produces a negative number", () => {
    expect(numberMutations("web0").every((v) => !v.includes("-"))).toBe(true);
  });
});

describe("generatePermutations", () => {
  const apex = "example.com";

  it("joins environment words to observed prefixes", () => {
    const out = generatePermutations(apex, ["api.example.com"], { maxCandidates: 500 });
    expect(out).toContain("dev-api.example.com");
    expect(out).toContain("api-dev.example.com");
    expect(out).toContain("uat-api.example.com");
  });

  /**
   * The real payoff. An organisation using `corp` gets `corp` permuted onto its
   * other hosts — a token no generic wordlist would contain.
   */
  it("learns vocabulary from the target's own hostnames", () => {
    const out = generatePermutations(
      apex,
      ["corp-vpn.example.com", "corp-mail.example.com", "gateway.example.com"],
      { maxCandidates: 5000 },
    );
    expect(out).toContain("corp-gateway.example.com");
  });

  it("accepts operator-supplied vocabulary", () => {
    const out = generatePermutations(apex, ["api.example.com"], {
      maxCandidates: 5000,
      extraWords: ["acmecorp"],
    });
    expect(out).toContain("acmecorp-api.example.com");
  });

  /** Permuting a guess compounds guesses; only observed names are a base. */
  it("returns nothing when no hosts were discovered", () => {
    expect(generatePermutations(apex, [], { maxCandidates: 500 })).toEqual([]);
    expect(generatePermutations(apex, ["example.com"], { maxCandidates: 500 })).toEqual([]);
  });

  it("never re-suggests a host that is already known", () => {
    const known = ["api.example.com", "dev-api.example.com"];
    const out = generatePermutations(apex, known, { maxCandidates: 5000 });
    expect(out).not.toContain("dev-api.example.com");
    expect(out).not.toContain("api.example.com");
  });

  it("produces no duplicates", () => {
    const out = generatePermutations(apex, ["api.example.com", "dev.example.com"], { maxCandidates: 5000 });
    expect(new Set(out).size).toBe(out.length);
  });

  /** Combinatorial growth is the whole risk; the cap is what makes it safe. */
  it("respects the candidate cap exactly", () => {
    const many = Array.from({ length: 50 }, (_, i) => `host${i}.example.com`);
    expect(generatePermutations(apex, many, { maxCandidates: 100 })).toHaveLength(100);
    expect(generatePermutations(apex, many, { maxCandidates: 0 })).toEqual([]);
  });

  /**
   * Truncating at a cap is only defensible if what survives is the part worth
   * trying, so the highest-probability tier must come first.
   */
  it("emits the most likely candidates first", () => {
    const out = generatePermutations(apex, ["api.example.com"], { maxCandidates: 4 });
    // Tier 1 is environment-word joins, led by the most common word.
    expect(out[0]).toBe("dev-api.example.com");
    expect(out.every((h) => h.includes("dev"))).toBe(true);
  });

  it("emits only syntactically valid hostnames", () => {
    const out = generatePermutations(apex, ["api.example.com", "a-b.example.com"], { maxCandidates: 2000 });
    for (const host of out) {
      expect(host.endsWith(`.${apex}`)).toBe(true);
      for (const label of host.split(".")) {
        expect(label).toMatch(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/);
      }
    }
  });

  it("is deterministic", () => {
    const hosts = ["api.example.com", "web01.example.com", "corp-vpn.example.com"];
    const a = generatePermutations(apex, hosts, { maxCandidates: 300 });
    const b = generatePermutations(apex, hosts, { maxCandidates: 300 });
    expect(a).toEqual(b);
  });

  it("includes number mutations of observed hosts", () => {
    const out = generatePermutations(apex, ["web01.example.com"], { maxCandidates: 5000 });
    expect(out).toContain("web02.example.com");
  });
});
