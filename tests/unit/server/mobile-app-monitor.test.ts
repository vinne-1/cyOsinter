/**
 * Mobile apps published under the target's brand.
 *
 * "Rogue app detection" is a headline module in every digital-risk product and
 * this engine had none: `typosquat.ts` watches lookalike DOMAINS, and nothing
 * looked at app stores.
 *
 * The attribution tests carry the weight. A live run against `stripe.com`
 * initially reported *FacilePay: Stripe Payments*, published by **vBridge
 * Technologies Inc.**, as an official Stripe app — because its bundle identifier
 * is `com.stripe.credit.card.payment`. Bundle identifiers are self-declared and
 * Apple does not verify them against domain ownership, so that check would have
 * adopted a stranger's software into the customer's inventory.
 */
import { describe, it, expect, vi, afterEach } from "vitest";

vi.mock("../../../server/logger", () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));

import {
  brandTokenFor,
  attributeApp,
  findBrandedApps,
  buildMobileAppFindings,
} from "../../../server/scanner/mobile-app-monitor";

const mockStore = (results: unknown[], opts: { fail?: boolean; status?: number } = {}) =>
  vi.fn(async () => {
    if (opts.fail) throw new Error("ENOTFOUND");
    if (opts.status && opts.status !== 200) return { ok: false, status: opts.status, json: async () => ({}) };
    return { ok: true, status: 200, json: async () => ({ results }) };
  });

afterEach(() => vi.unstubAllGlobals());

describe("brandTokenFor", () => {
  it("takes the first label of the domain", () => {
    expect(brandTokenFor("stripe.com")).toBe("stripe");
    expect(brandTokenFor("www.shopify.com")).toBe("shopify");
    expect(brandTokenFor("Example.CO.UK")).toBe("example");
  });

  /** Same rule and reason as asn-expansion's org token: "hp" matches half the store. */
  it("refuses a brand token too short to search", () => {
    expect(brandTokenFor("hp.com")).toBeNull();
    expect(brandTokenFor("ge.com")).toBeNull();
  });
});

describe("attributeApp", () => {
  /** The only signal that confers ownership: the developer's own stated site. */
  it("attributes an app whose developer website is the target domain", () => {
    const r = attributeApp({ sellerUrl: "https://stripe.com" }, "stripe.com");
    expect(r.attribution).toBe("official");
    expect(r.reason).toMatch(/developer's listed website/);
  });

  it("accepts a subdomain or path on the target's site", () => {
    expect(attributeApp({ sellerUrl: "https://www.stripe.com/lp/app" }, "stripe.com").attribution).toBe("official");
  });

  /**
   * The measured false positive. `com.stripe.credit.card.payment` is published
   * by vBridge Technologies, not Stripe — identifiers are self-declared.
   */
  it("does NOT treat a brand-matching bundle identifier as ownership", () => {
    const r = attributeApp(
      { bundleId: "com.stripe.credit.card.payment", sellerUrl: "https://facilepay.example" },
      "stripe.com",
    );
    expect(r.attribution).toBe("third-party");
    expect(r.brandInBundleId).toBe(true);
    expect(r.reason).toMatch(/self-declared/);
  });

  it("flags brand-in-identifier even with no seller URL at all", () => {
    const r = attributeApp({ bundleId: "com.stripe.something" }, "stripe.com");
    expect(r.attribution).toBe("third-party");
    expect(r.brandInBundleId).toBe(true);
  });

  it("reports no tie when neither signal matches", () => {
    const r = attributeApp({ sellerUrl: "https://other.example", bundleId: "com.other.app" }, "stripe.com");
    expect(r.attribution).toBe("third-party");
    expect(r.brandInBundleId).toBe(false);
  });

  it("treats an unparseable seller URL as proving nothing", () => {
    expect(attributeApp({ sellerUrl: "not a url" }, "stripe.com").attribution).toBe("third-party");
  });

  /** `notstripe.com` must not read as being stripe.com. */
  it("is not fooled by a domain that merely ends with the target text", () => {
    expect(attributeApp({ sellerUrl: "https://notstripe.com" }, "stripe.com").attribution).toBe("third-party");
  });
});

describe("findBrandedApps", () => {
  const app = (over: Record<string, unknown> = {}) => ({
    trackName: "Stripe Dashboard",
    sellerName: "Stripe, LLC",
    sellerUrl: "https://stripe.com",
    bundleId: "com.stripe.dashboard",
    userRatingCount: 100,
    ...over,
  });

  it("separates the domain owner's apps from everyone else's", async () => {
    vi.stubGlobal("fetch", mockStore([
      app(),
      app({ trackName: "Payment for Stripe", sellerName: "PocketVendor Inc", sellerUrl: "https://paymentforstripe.com", bundleId: "com.pocketvendor.pay" }),
    ]));

    const r = await findBrandedApps("stripe.com");

    expect(r.official.map((a) => a.name)).toEqual(["Stripe Dashboard"]);
    expect(r.thirdParty.map((a) => a.name)).toEqual(["Payment for Stripe"]);
    expect(r.unavailable).toBe(false);
  });

  /**
   * The store's relevance engine returns competitors: searching "stripe" also
   * returns Square's point-of-sale app. Reporting those as brand usage would
   * bury the real signal.
   */
  it("drops results that do not mention the brand at all", async () => {
    vi.stubGlobal("fetch", mockStore([
      app({ trackName: "Square Point of Sale", sellerName: "Block, Inc.", sellerUrl: "https://squareup.com", bundleId: "com.squareup.pos" }),
    ]));
    const r = await findBrandedApps("stripe.com");
    expect(r.official).toEqual([]);
    expect(r.thirdParty).toEqual([]);
  });

  /** A third party shipping com.<yourbrand>.* deserves the first look. */
  it("sorts brand-in-identifier apps ahead of merely popular ones", async () => {
    vi.stubGlobal("fetch", mockStore([
      app({ trackName: "Popular Stripe Tool", sellerName: "X", sellerUrl: "https://x.example", bundleId: "com.x.tool", userRatingCount: 9000 }),
      app({ trackName: "Stripe Clone", sellerName: "Y", sellerUrl: "https://y.example", bundleId: "com.stripe.clone", userRatingCount: 3 }),
    ]));
    const r = await findBrandedApps("stripe.com");
    expect(r.thirdParty[0].name).toBe("Stripe Clone");
  });

  /** "We could not check" and "nothing found" are opposite conclusions. */
  it("reports unavailable when the store cannot be reached", async () => {
    vi.stubGlobal("fetch", mockStore([], { fail: true }));
    const r = await findBrandedApps("stripe.com");
    expect(r.unavailable).toBe(true);
    expect(r.storesChecked).toEqual([]);
  });

  it("reports unavailable on a non-200 store response", async () => {
    vi.stubGlobal("fetch", mockStore([], { status: 503 }));
    expect((await findBrandedApps("stripe.com")).unavailable).toBe(true);
  });

  /** Android coverage is absent and must be stated, never implied. */
  it("always records Google Play as not checked", async () => {
    vi.stubGlobal("fetch", mockStore([app()]));
    const r = await findBrandedApps("stripe.com");
    expect(r.storesNotChecked.some((s) => /Google Play/.test(s.store))).toBe(true);
  });

  it("does not search at all for a too-short brand, and says why", async () => {
    const fetchMock = mockStore([app()]);
    vi.stubGlobal("fetch", fetchMock);
    const r = await findBrandedApps("hp.com");
    expect(fetchMock).not.toHaveBeenCalled();
    expect(r.storesNotChecked.some((s) => /Apple/.test(s.store))).toBe(true);
  });
});

describe("buildMobileAppFindings", () => {
  const result = (over: Record<string, unknown> = {}) => ({
    brand: "stripe",
    official: [],
    thirdParty: [],
    storesChecked: ["Apple App Store"],
    storesNotChecked: [],
    unavailable: false,
    ...over,
  }) as Parameters<typeof buildMobileAppFindings>[1];

  const tp = (name: string, seller: string) => ({
    name, seller, store: "apple" as const, attribution: "third-party" as const, reason: "x",
  });

  /** One review task for one person; a row each would read as accusations. */
  it("emits ONE finding listing every third-party app", () => {
    const findings = buildMobileAppFindings("stripe.com", result({
      thirdParty: [tp("A for Stripe", "Alpha"), tp("Stripe B", "Beta")],
    }));
    const medium = findings.filter((f) => f.severity === "medium");
    expect(medium).toHaveLength(1);
    expect(medium[0].title).toMatch(/2 App Store apps/);
  });

  /**
   * The claim must stay inside what was established. Many brand-named apps are
   * legitimate integrations, resellers or partner clients.
   */
  /** "1 app ... carry ... but is published" shipped once; verbs must agree. */
  it("keeps verb agreement for a single app", () => {
    const [f] = buildMobileAppFindings("stripe.com", result({ thirdParty: [tp("X for Stripe", "Alpha")] }));
    expect(f.description).toMatch(/1 app on the Apple App Store carries the/);
    expect(f.description).toMatch(/but is published by/);
    expect(f.title).toMatch(/1 App Store app using/);
  });

  it("pluralises correctly for several apps", () => {
    const [f] = buildMobileAppFindings("stripe.com", result({
      thirdParty: [tp("A for Stripe", "Alpha"), tp("Stripe B", "Beta")],
    }));
    expect(f.description).toMatch(/2 apps on the Apple App Store carry the/);
    expect(f.description).toMatch(/but are published by/);
  });

  it("disclaims the stronger claim instead of making it", () => {
    const [f] = buildMobileAppFindings("stripe.com", result({ thirdParty: [tp("X for Stripe", "Alpha")] }));

    // The word "fake" DOES appear — in the sentence that rules it out. Banning
    // the token was the wrong assertion; what matters is that every mention is a
    // disclaimer and the affirmative claim stays narrow.
    expect(f.description).toMatch(/does NOT establish that any of them is fake/i);
    expect(f.description).toMatch(/worth confirming is authorised/i);
    // Every mention of the stronger word sits inside the negation. Asserting
    // the token never appears was wrong — it appears precisely to rule it out.
    const mentions = f.description.match(/fake|impersonat/gi) ?? [];
    expect(mentions).toHaveLength(1);

    // The title is what a reader skims, so the accusation must not live there.
    expect(f.title).not.toMatch(/fake|impersonat|rogue/i);
  });

  it("records the owner's own apps as info, not as a problem", () => {
    const findings = buildMobileAppFindings("stripe.com", result({
      official: [{ name: "Stripe Dashboard", seller: "Stripe, LLC", store: "apple", attribution: "official", reason: "x" }],
    }));
    expect(findings[0].severity).toBe("info");
    expect(findings[0].title).toMatch(/confirmed published by/);
  });

  it("states an unreachable store rather than implying nothing was found", () => {
    const findings = buildMobileAppFindings("stripe.com", result({ unavailable: true }));
    expect(findings).toHaveLength(1);
    expect(findings[0].description).toMatch(/not a statement that none exist/i);
  });

  it("emits nothing when the sweep was clean and complete", () => {
    expect(buildMobileAppFindings("stripe.com", result())).toEqual([]);
  });
});
