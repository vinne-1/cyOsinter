/**
 * SPF `redirect=` evaluation.
 *
 * A record that ends in `redirect=` and carries no `all` of its own is correct,
 * ordinary configuration: RFC 7208 §6.1 makes the redirect target's policy this
 * domain's policy, and says that if `all` IS present the redirect must be
 * ignored. The terminator check tested only the local record, so every domain
 * using a hosting provider's SPF was reported as having no policy at all.
 *
 * This was a measured false positive, not a hypothetical: a real scan of
 * alkemlabs.com (`v=spf1 redirect=_spf.mailhostbox.com`, whose target publishes
 * `~all`) reported "SPF has no 'all' terminator".
 */
import { describe, it, expect, vi } from "vitest";

vi.mock("../../../server/logger", () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));

import {
  terminatorOf,
  effectiveTerminator,
  analyzeSpfDeep,
} from "../../../server/scanner/spf-dmarc-deep";

/** Builds a TXT lookup over a fixed zone; unknown names resolve to nothing. */
const zone = (records: Record<string, string>) => async (name: string): Promise<string[][]> => {
  const v = records[name.toLowerCase()];
  return v ? [[v]] : [];
};

describe("terminatorOf", () => {
  it("reads the qualifier off an all mechanism", () => {
    expect(terminatorOf("v=spf1 ip4:1.2.3.4 -all")).toBe("-all");
    expect(terminatorOf("v=spf1 ~all")).toBe("~all");
    expect(terminatorOf("v=spf1 ?all")).toBe("?all");
    expect(terminatorOf("v=spf1 +all")).toBe("+all");
  });

  /** RFC 7208 §4.6.2 — a bare qualifier defaults to pass. */
  it("treats a bare all as +all", () => {
    expect(terminatorOf("v=spf1 include:x.example all")).toBe("+all");
  });

  /**
   * The substring trap that caused the bug. `all` is a term, not a fragment:
   * "mailhostbox.com" and "install" must not register as terminators.
   */
  it("does not match 'all' inside another term", () => {
    expect(terminatorOf("v=spf1 redirect=_spf.mailhostbox.com")).toBeNull();
    expect(terminatorOf("v=spf1 include:install.example.com")).toBeNull();
    expect(terminatorOf("v=spf1 include:_spf.small.example")).toBeNull();
  });

  it("returns null when there is no all mechanism", () => {
    expect(terminatorOf("v=spf1 ip4:1.2.3.4")).toBeNull();
  });
});

describe("effectiveTerminator", () => {
  it("follows a redirect to the policy that actually applies", async () => {
    const lookup = zone({ "_spf.provider.example": "v=spf1 ip4:1.2.3.4 -all" });
    const r = await effectiveTerminator("v=spf1 redirect=_spf.provider.example", lookup);
    expect(r.terminator).toBe("-all");
    expect(r.via).toBe("_spf.provider.example");
  });

  /** RFC 7208 §6.1: a present `all` means the redirect is ignored entirely. */
  it("ignores redirect when the record has its own all", async () => {
    const lookup = zone({ "_spf.provider.example": "v=spf1 -all" });
    const r = await effectiveTerminator("v=spf1 redirect=_spf.provider.example ~all", lookup);
    expect(r.terminator).toBe("~all");
    expect(r.via).toBeUndefined();
  });

  it("follows a chain of redirects", async () => {
    const lookup = zone({
      "a.example": "v=spf1 redirect=b.example",
      "b.example": "v=spf1 -all",
    });
    const r = await effectiveTerminator("v=spf1 redirect=a.example", lookup);
    expect(r.terminator).toBe("-all");
  });

  /**
   * Three states, not two: an unreachable target means the policy is UNKNOWN,
   * which is a different claim from "there is no policy".
   */
  it("reports unresolved rather than 'no terminator' when the target has no SPF", async () => {
    const r = await effectiveTerminator("v=spf1 redirect=missing.example", zone({}));
    expect(r.unresolved).toBe(true);
    expect(r.terminator).toBeNull();
    expect(r.via).toBe("missing.example");
  });

  it("reports unresolved when the lookup throws", async () => {
    const boom = async () => { throw new Error("SERVFAIL"); };
    const r = await effectiveTerminator("v=spf1 redirect=broken.example", boom);
    expect(r.unresolved).toBe(true);
  });

  it("terminates on a redirect loop instead of recursing forever", async () => {
    const lookup = zone({
      "a.example": "v=spf1 redirect=b.example",
      "b.example": "v=spf1 redirect=a.example",
    });
    const r = await effectiveTerminator("v=spf1 redirect=a.example", lookup);
    expect(r.unresolved).toBe(true);
  });

  it("still reports no terminator when there is genuinely neither", async () => {
    const r = await effectiveTerminator("v=spf1 ip4:1.2.3.4", zone({}));
    expect(r.terminator).toBeNull();
    expect(r.unresolved).toBeFalsy();
  });
});

describe("analyzeSpfDeep — the measured false positive", () => {
  /** The exact shape that produced a wrong finding on a live scan. */
  it("does not claim a redirect-only record lacks a terminator", async () => {
    const lookup = zone({
      "alkemlabs.com": "v=spf1 redirect=_spf.mailhostbox.com",
      "_spf.mailhostbox.com": "v=spf1 include:_netblocks1.mailhostbox.com ~all",
      "_netblocks1.mailhostbox.com": "v=spf1 ip4:1.2.3.0/24 ~all",
    });
    const r = await analyzeSpfDeep("alkemlabs.com", [["v=spf1 redirect=_spf.mailhostbox.com"]], lookup);

    expect(r.issues.join(" ")).not.toMatch(/no 'all' terminator/);
    // It reports the policy that actually applies, and says where it came from.
    expect(r.issues.join(" ")).toMatch(/~all/);
    expect(r.issues.join(" ")).toMatch(/inherited from redirect=_spf\.mailhostbox\.com/);
  });

  it("reports a hard-fail redirect chain as clean", async () => {
    const lookup = zone({
      "example.com": "v=spf1 redirect=_spf.provider.example",
      "_spf.provider.example": "v=spf1 ip4:1.2.3.4 -all",
    });
    const r = await analyzeSpfDeep("example.com", [["v=spf1 redirect=_spf.provider.example"]], lookup);
    expect(r.issues.filter((i) => /all/.test(i))).toEqual([]);
  });

  it("still flags a genuinely permissive policy reached through a redirect", async () => {
    const lookup = zone({ "_spf.bad.example": "v=spf1 +all" });
    const r = await analyzeSpfDeep("example.com", [["v=spf1 redirect=_spf.bad.example"]], lookup);
    expect(r.issues.join(" ")).toMatch(/\+all/);
  });
});
