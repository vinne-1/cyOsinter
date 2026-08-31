import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * Covers the aggregation contract for cookie findings: one finding per host,
 * every affected cookie preserved as evidence. A live scan of a real site
 * produced 20 separate "Insecure Cookie: <name>" findings, which crowded out
 * every other issue and distorted the severity counts the posture score uses.
 */

// dast-lite wraps every request in a local safeFetch() over stealthFetch, so
// stealthFetch is the seam a test can control.
const stealthFetch = vi.fn();
vi.mock("../../../server/scanner/stealth.js", () => ({ stealthFetch }));

let checkCookieSecurity: (domain: string) => Promise<Array<Record<string, any>>>;

beforeEach(async () => {
  vi.resetModules();
  stealthFetch.mockReset();
  const mod: any = await import("../../../server/scanner/dast-lite");
  checkCookieSecurity = mod.checkCookieSecurity;
});

afterEach(() => {
  vi.restoreAllMocks();
});

/** Builds a fetch-like response exposing `getSetCookie`. */
function responseWithCookies(cookies: string[]) {
  return { headers: { getSetCookie: () => cookies }, status: 200 };
}

describe("checkCookieSecurity", () => {
  it("returns nothing when every cookie is fully attributed", async () => {
    stealthFetch.mockResolvedValue(
      responseWithCookies([
        "sid=1; Secure; HttpOnly; SameSite=Strict",
        "pref=2; Secure; HttpOnly; SameSite=Lax",
      ]),
    );
    expect(await checkCookieSecurity("example.com")).toEqual([]);
  });

  it("returns nothing when the host sets no cookies", async () => {
    stealthFetch.mockResolvedValue(responseWithCookies([]));
    expect(await checkCookieSecurity("example.com")).toEqual([]);
  });

  it("returns nothing when the host is unreachable", async () => {
    stealthFetch.mockRejectedValue(new Error("ECONNREFUSED"));
    expect(await checkCookieSecurity("example.com")).toEqual([]);
  });

  it("collapses many insecure cookies into ONE finding", async () => {
    const cookies = Array.from({ length: 20 }, (_, i) => `_bb_c${i}=v${i}`);
    stealthFetch.mockResolvedValue(responseWithCookies(cookies));

    const findings = await checkCookieSecurity("bigbasket.com");

    expect(findings).toHaveLength(1);
    expect(findings[0]!.category).toBe("cookie_security");
    expect(findings[0]!.affectedAsset).toBe("bigbasket.com");
    expect(findings[0]!.title).toContain("20 cookies");
  });

  it("preserves every affected cookie as evidence, losing no detail", async () => {
    const cookies = Array.from({ length: 20 }, (_, i) => `_bb_c${i}=v${i}`);
    stealthFetch.mockResolvedValue(responseWithCookies(cookies));

    const [finding] = await checkCookieSecurity("bigbasket.com");
    const named = finding!.evidence.filter((e: any) => typeof e.cookieName === "string");

    expect(named).toHaveLength(20);
    expect(named.map((e: any) => e.cookieName)).toContain("_bb_c19");
    // A summary row carries the aggregate counts.
    expect(finding!.evidence[0]).toMatchObject({
      totalCookies: 20,
      affectedCookies: 20,
      missingCounts: { secure: 20, httpOnly: 20, sameSite: 20 },
    });
  });

  it("counts only the cookies that are actually deficient", async () => {
    stealthFetch.mockResolvedValue(
      responseWithCookies([
        "good=1; Secure; HttpOnly; SameSite=Strict",
        "bad=2",
        "alsobad=3; Secure",
      ]),
    );

    const [finding] = await checkCookieSecurity("example.com");
    expect(finding!.evidence[0]).toMatchObject({ totalCookies: 3, affectedCookies: 2 });
    expect(finding!.evidence[0].missingCounts).toEqual({ secure: 1, httpOnly: 2, sameSite: 2 });
  });

  it("rates a missing Secure flag above a missing SameSite alone", async () => {
    stealthFetch.mockResolvedValue(responseWithCookies(["a=1; HttpOnly; Secure"]));
    const [sameSiteOnly] = await checkCookieSecurity("example.com");
    expect(sameSiteOnly!.severity).toBe("low");

    stealthFetch.mockResolvedValue(responseWithCookies(["a=1; HttpOnly; SameSite=Lax"]));
    const [missingSecure] = await checkCookieSecurity("example.com");
    expect(missingSecure!.severity).toBe("medium");
  });

  it("names a few cookies inline and abbreviates the rest", async () => {
    const cookies = Array.from({ length: 9 }, (_, i) => `c${i}=v`);
    stealthFetch.mockResolvedValue(responseWithCookies(cookies));

    const [finding] = await checkCookieSecurity("example.com");
    expect(finding!.description).toContain("c0");
    expect(finding!.description).toContain("+4 more");
  });

  it("is case-insensitive about attribute spelling", async () => {
    stealthFetch.mockResolvedValue(responseWithCookies(["a=1; secure; httponly; samesite=lax"]));
    expect(await checkCookieSecurity("example.com")).toEqual([]);
  });

  it("handles a response with no getSetCookie helper", async () => {
    stealthFetch.mockResolvedValue({ headers: {}, status: 200 });
    expect(await checkCookieSecurity("example.com")).toEqual([]);
  });
});
