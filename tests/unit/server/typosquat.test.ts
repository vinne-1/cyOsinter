import { describe, it, expect, vi } from "vitest";
import {
  splitDomain,
  generatePermutations,
  resolveLookalikes,
  scanForLookalikes,
  type Permutation,
} from "../../../server/scanner/typosquat";

describe("splitDomain", () => {
  it("splits a plain domain", () => {
    expect(splitDomain("example.com")).toEqual({ name: "example", tld: "com" });
  });

  it("keeps two-part public suffixes intact", () => {
    expect(splitDomain("example.co.uk")).toEqual({ name: "example", tld: "co.uk" });
    expect(splitDomain("acme.com.au")).toEqual({ name: "acme", tld: "com.au" });
    expect(splitDomain("bank.co.in")).toEqual({ name: "bank", tld: "co.in" });
  });

  it("uses the registrable name, not a subdomain", () => {
    expect(splitDomain("mail.corp.example.com")).toEqual({ name: "example", tld: "com" });
  });

  it("normalises scheme, path, trailing dot and case", () => {
    expect(splitDomain("HTTPS://Example.COM/login?x=1")).toEqual({ name: "example", tld: "com" });
    expect(splitDomain("example.com.")).toEqual({ name: "example", tld: "com" });
  });
});

describe("generatePermutations", () => {
  const perms = generatePermutations("example.com");
  const domains = perms.map((p) => p.domain);

  it("never returns the original domain", () => {
    expect(domains).not.toContain("example.com");
  });

  it("produces no duplicates", () => {
    expect(new Set(domains).size).toBe(domains.length);
  });

  it("finds character omissions", () => {
    expect(domains).toContain("exmple.com");
  });

  it("finds transpositions", () => {
    expect(domains).toContain("exmaple.com");
  });

  it("finds keyboard-adjacent replacements", () => {
    // 'a' neighbours 's' on QWERTY.
    expect(domains).toContain("exsmple.com");
  });

  it("finds repetitions", () => {
    expect(domains).toContain("exaample.com");
  });

  it("finds homoglyph substitutions", () => {
    // 'l' → '1' is the classic confusable.
    expect(domains).toContain("examp1e.com");
  });

  it("finds hyphenation and subdomain splits", () => {
    expect(domains).toContain("ex-ample.com");
    expect(domains).toContain("ex.ample.com");
  });

  it("finds TLD swaps but not the original TLD", () => {
    expect(domains).toContain("example.net");
    expect(domains).toContain("example.io");
    expect(domains.filter((d) => d === "example.com")).toHaveLength(0);
  });

  it("finds combosquats in both positions", () => {
    expect(domains).toContain("example-login.com");
    expect(domains).toContain("secure-example.com");
  });

  it("tags every permutation with the family that produced it", () => {
    const kinds = new Set(perms.map((p) => p.kind));
    for (const expected of ["omission", "transposition", "homoglyph", "tld-swap", "combosquat"]) {
      expect(kinds).toContain(expected);
    }
  });

  it("emits only DNS-valid labels", () => {
    for (const d of domains) {
      for (const label of d.split(".")) {
        expect(label.length).toBeGreaterThan(0);
        expect(label.length).toBeLessThanOrEqual(63);
        expect(label.startsWith("-")).toBe(false);
        expect(label.endsWith("-")).toBe(false);
      }
    }
  });

  it("preserves a two-part suffix rather than mangling it", () => {
    const ukDomains = generatePermutations("example.co.uk").map((p) => p.domain);
    expect(ukDomains).toContain("exmple.co.uk");
    // The suffix itself must never be permuted.
    expect(ukDomains.some((d) => d.endsWith(".c0.uk"))).toBe(false);
  });

  it("honours the limit", () => {
    expect(generatePermutations("example.com", { limit: 25 })).toHaveLength(25);
  });

  it("honours a kind filter", () => {
    const only = generatePermutations("example.com", { kinds: ["tld-swap"] });
    expect(only.every((p) => p.kind === "tld-swap")).toBe(true);
    expect(only.length).toBeGreaterThan(0);
  });

  it("returns nothing for a name too short to permute meaningfully", () => {
    expect(generatePermutations("a.com")).toEqual([]);
  });
});

/** DNS double whose answers are driven by a fixture map. */
function fakeResolver(fixtures: Record<string, { a?: string[]; mx?: string[]; ns?: string[] }>) {
  const miss = () => Promise.reject(new Error("ENOTFOUND"));
  return {
    resolve4: (h: string) => (fixtures[h]?.a ? Promise.resolve(fixtures[h]!.a!) : miss()),
    resolveMx: (h: string) =>
      fixtures[h]?.mx
        ? Promise.resolve(fixtures[h]!.mx!.map((exchange) => ({ exchange, priority: 10 })))
        : miss(),
    resolveNs: (h: string) => (fixtures[h]?.ns ? Promise.resolve(fixtures[h]!.ns!) : miss()),
  };
}

describe("resolveLookalikes", () => {
  const perms: Permutation[] = [
    { domain: "live-and-mail.com", kind: "omission" },
    { domain: "live-only.com", kind: "replacement" },
    { domain: "parked.com", kind: "tld-swap" },
    { domain: "unregistered.com", kind: "homoglyph" },
  ];

  const resolver = fakeResolver({
    "live-and-mail.com": { a: ["1.2.3.4"], mx: ["mail.evil.com"], ns: ["ns1.evil.com"] },
    "live-only.com": { a: ["5.6.7.8"] },
    "parked.com": { ns: ["ns1.parking.com"] },
  });

  it("drops candidates that do not exist at all", async () => {
    const found = await resolveLookalikes(perms, { resolver });
    expect(found.map((f) => f.domain)).not.toContain("unregistered.com");
    expect(found).toHaveLength(3);
  });

  it("rates a resolving, mail-capable lookalike highest", async () => {
    const found = await resolveLookalikes(perms, { resolver });
    expect(found.find((f) => f.domain === "live-and-mail.com")!.risk).toBe("high");
  });

  it("rates a resolving lookalike without MX as medium", async () => {
    const found = await resolveLookalikes(perms, { resolver });
    expect(found.find((f) => f.domain === "live-only.com")!.risk).toBe("medium");
  });

  it("still reports a registered-but-parked name as low risk", async () => {
    const found = await resolveLookalikes(perms, { resolver });
    const parked = found.find((f) => f.domain === "parked.com")!;
    expect(parked.risk).toBe("low");
    expect(parked.resolves).toBe(false);
  });

  it("returns results ordered by risk", async () => {
    const found = await resolveLookalikes(perms, { resolver });
    expect(found.map((f) => f.risk)).toEqual(["high", "medium", "low"]);
  });

  it("carries the permutation kind through to the result", async () => {
    const found = await resolveLookalikes(perms, { resolver });
    expect(found.find((f) => f.domain === "live-and-mail.com")!.kind).toBe("omission");
  });

  it("respects the concurrency limit", async () => {
    let inFlight = 0;
    let peak = 0;
    const slow = {
      resolve4: async (_h: string) => {
        inFlight++;
        peak = Math.max(peak, inFlight);
        await new Promise((r) => setTimeout(r, 5));
        inFlight--;
        throw new Error("ENOTFOUND");
      },
      resolveMx: async () => { throw new Error("ENOTFOUND"); },
      resolveNs: async () => { throw new Error("ENOTFOUND"); },
    };
    const many = Array.from({ length: 30 }, (_, i) => ({ domain: `d${i}.com`, kind: "omission" as const }));
    await resolveLookalikes(many, { resolver: slow, concurrency: 4 });
    expect(peak).toBeLessThanOrEqual(4);
  });

  it("ignores ICANN name-collision answers rather than reporting them as live", async () => {
    // A delegated-but-unregistered name answers with 127.0.53.53 and a
    // placeholder MX; a live sweep of bigbasket.com reported `bigbasket.web`
    // as high risk purely because of this.
    const collision = fakeResolver({
      "collide.web": {
        a: ["127.0.53.53"],
        mx: ["your-dns-needs-immediate-attention.web"],
      },
    });
    const found = await resolveLookalikes(
      [{ domain: "collide.web", kind: "tld-swap" }],
      { resolver: collision },
    );
    expect(found).toEqual([]);
  });

  it("does not count a localhost MX as mail capability", async () => {
    const parkedMx = fakeResolver({
      "parked-mx.com": { a: ["203.0.113.7"], mx: ["localhost"] },
    });
    const [found] = await resolveLookalikes(
      [{ domain: "parked-mx.com", kind: "tld-swap" }],
      { resolver: parkedMx },
    );
    expect(found!.mx).toEqual([]);
    expect(found!.risk).toBe("medium");
  });

  it("survives a resolver that throws for every lookup", async () => {
    const dead = {
      resolve4: () => Promise.reject(new Error("ESERVFAIL")),
      resolveMx: () => Promise.reject(new Error("ESERVFAIL")),
      resolveNs: () => Promise.reject(new Error("ESERVFAIL")),
    };
    await expect(resolveLookalikes(perms, { resolver: dead })).resolves.toEqual([]);
  });
});

describe("scanForLookalikes", () => {
  it("reports generated, checked and per-risk counts", async () => {
    const resolver = fakeResolver({
      "exmple.com": { a: ["1.2.3.4"], mx: ["mx.evil.com"] },
      "example.net": { a: ["9.9.9.9"] },
    });

    const result = await scanForLookalikes("example.com", { resolver, limit: 400 });

    expect(result.target).toBe("example.com");
    expect(result.generated).toBeGreaterThan(0);
    expect(result.checked).toBe(result.generated);
    expect(result.counts.high).toBe(1);
    expect(result.counts.medium).toBe(1);
    expect(result.registered.map((r) => r.domain).sort()).toEqual(["example.net", "exmple.com"]);
  });

  it("returns an empty, well-formed result when nothing is registered", async () => {
    const result = await scanForLookalikes("example.com", { resolver: fakeResolver({}), limit: 50 });
    expect(result.registered).toEqual([]);
    expect(result.counts).toEqual({ high: 0, medium: 0, low: 0 });
  });
});
