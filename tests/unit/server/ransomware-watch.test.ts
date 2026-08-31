import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  registrableDomain,
  normaliseOrgName,
  checkRansomwareExposure,
  getFeed,
  __resetFeedCache,
  type LeakPost,
} from "../../../server/scanner/ransomware-watch";

/**
 * The dangerous failure here is a FALSE POSITIVE: telling a team they appear on
 * a ransomware leak site when they do not. Most of these tests exist to pin the
 * separation between an identity match (domain) and a guess (company name).
 */

const POSTS: LeakPost[] = [
  { post_title: "Acme Manufacturing Inc", group_name: "lockbit", website: "www.acme-manufacturing.com", country: "US", activity: "Manufacturing", published: "2026-03-01T00:00:00Z", discovered: "2026-03-02T00:00:00Z", post_url: "http://abc.onion/1" },
  { post_title: "Acme Manufacturing Inc", group_name: "cl0p", website: "acme-manufacturing.com", country: "US", activity: "Not Found", published: "2026-05-10T00:00:00Z", post_url: "http://def.onion/2" },
  { post_title: "Northwind Traders Ltd", group_name: "play", website: "", country: "GB", activity: "Retail", published: "2026-04-01T00:00:00Z", post_url: "http://ghi.onion/3" },
  { post_title: "Unrelated Corp", group_name: "akira", website: "https://shop.unrelated.co.uk/products", country: "GB", published: "2026-02-01T00:00:00Z" },
  { post_title: "MEQ", group_name: "play", website: "meq.example", published: "2026-01-01T00:00:00Z" },
];

beforeEach(() => __resetFeedCache());
afterEach(() => { vi.restoreAllMocks(); __resetFeedCache(); });

describe("registrableDomain", () => {
  it("strips scheme, www, path and trailing dot", () => {
    expect(registrableDomain("https://www.Example.com/a/b?c=1")).toBe("example.com");
    expect(registrableDomain("example.com.")).toBe("example.com");
  });

  it("reduces a subdomain to the registrable domain", () => {
    expect(registrableDomain("shop.eu.example.com")).toBe("example.com");
  });

  it("keeps two-part public suffixes intact", () => {
    expect(registrableDomain("shop.example.co.uk")).toBe("example.co.uk");
  });

  it("passes through a bare token unchanged", () => {
    expect(registrableDomain("notadomain")).toBe("notadomain");
  });
});

describe("normaliseOrgName", () => {
  it("drops corporate suffixes and punctuation", () => {
    expect(normaliseOrgName("Acme Manufacturing, Inc.")).toBe("acme manufacturing");
    expect(normaliseOrgName("Northwind Traders Ltd")).toBe("northwind traders");
  });

  it("collapses whitespace and lowercases", () => {
    expect(normaliseOrgName("  ACME   Manufacturing  ")).toBe("acme manufacturing");
  });
});

describe("checkRansomwareExposure — domain matching", () => {
  it("confirms a victim whose listed website matches the target", async () => {
    const r = await checkRansomwareExposure("acme-manufacturing.com", { posts: POSTS });
    expect(r.counts.confirmed).toBe(2);
    expect(r.matches.every((m) => m.confidence === "confirmed")).toBe(true);
  });

  it("matches regardless of www or scheme in the feed", async () => {
    const r = await checkRansomwareExposure("acme-manufacturing.com", { posts: POSTS });
    expect(r.matches.map((m) => m.group).sort()).toEqual(["cl0p", "lockbit"]);
  });

  it("matches a subdomain listing to the registrable domain", async () => {
    // The feed lists "https://shop.unrelated.co.uk/products".
    const r = await checkRansomwareExposure("unrelated.co.uk", { posts: POSTS });
    expect(r.counts.confirmed).toBe(1);
  });

  it("finds nothing for an unaffected domain", async () => {
    const r = await checkRansomwareExposure("definitely-clean.com", { posts: POSTS });
    expect(r.matches).toEqual([]);
    expect(r.counts).toEqual({ confirmed: 0, possible: 0 });
    // recordsChecked proves the corpus was actually searched.
    expect(r.recordsChecked).toBe(POSTS.length);
  });

  it("checks aliases as well as the primary domain", async () => {
    const r = await checkRansomwareExposure("something-else.com", {
      posts: POSTS,
      aliases: ["acme-manufacturing.com"],
    });
    expect(r.counts.confirmed).toBe(2);
  });
});

describe("checkRansomwareExposure — name matching stays separate", () => {
  it("reports a name-only match as possible, never confirmed", async () => {
    // Northwind has no website in the feed, so only the name can match.
    const r = await checkRansomwareExposure("northwind.com", {
      posts: POSTS,
      organisationName: "Northwind Traders Ltd",
    });
    expect(r.counts.confirmed).toBe(0);
    expect(r.counts.possible).toBe(1);
    expect(r.matches[0]!.reason).toMatch(/verify before acting/i);
  });

  it("does not name-match without an organisation name", async () => {
    const r = await checkRansomwareExposure("northwind.com", { posts: POSTS });
    expect(r.matches).toEqual([]);
  });

  it("ignores very short names, which would match far too much", async () => {
    // "MEQ" normalises to 3 characters; matching on it would be noise.
    const r = await checkRansomwareExposure("meq.com", { posts: POSTS, organisationName: "MEQ" });
    expect(r.counts.possible).toBe(0);
  });

  it("prefers the confirmed tier when both could apply", async () => {
    const r = await checkRansomwareExposure("acme-manufacturing.com", {
      posts: POSTS,
      organisationName: "Acme Manufacturing Inc",
    });
    // Two domain matches, and the name must not add duplicates on top.
    expect(r.counts.confirmed).toBe(2);
    expect(r.counts.possible).toBe(0);
  });
});

describe("checkRansomwareExposure — result shape", () => {
  it("orders confirmed before possible, then newest first", async () => {
    const r = await checkRansomwareExposure("acme-manufacturing.com", {
      posts: POSTS,
      aliases: ["northwind.com"],
      organisationName: "Northwind Traders Ltd",
    });
    expect(r.matches[0]!.confidence).toBe("confirmed");
    expect(r.matches[0]!.group).toBe("cl0p"); // published 2026-05, newer than lockbit's 2026-03
    expect(r.matches.at(-1)!.confidence).toBe("possible");
  });

  it("carries the leak-site url through for investigation", async () => {
    const r = await checkRansomwareExposure("acme-manufacturing.com", { posts: POSTS });
    expect(r.matches.some((m) => m.postUrl?.includes(".onion"))).toBe(true);
  });

  it('normalises the "Not Found" sector placeholder to null', async () => {
    const r = await checkRansomwareExposure("acme-manufacturing.com", { posts: POSTS });
    const clop = r.matches.find((m) => m.group === "cl0p")!;
    expect(clop.sector).toBeNull();
  });

  it("de-duplicates an identical post appearing twice", async () => {
    const dupes = [POSTS[0]!, { ...POSTS[0]! }];
    const r = await checkRansomwareExposure("acme-manufacturing.com", { posts: dupes });
    expect(r.matches).toHaveLength(1);
  });
});

describe("feed failure handling", () => {
  it("reports an error instead of claiming the target is clean", async () => {
    // Silently returning "no matches" when the feed is unreachable would be a
    // dangerously wrong thing to tell a security team.
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network down")));

    const r = await checkRansomwareExposure("example.com");

    expect(r.error).toMatch(/could not be checked/i);
    expect(r.matches).toEqual([]);
    expect(r.recordsChecked).toBe(0);
  });

  it("treats a non-200 response as a failure", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 503 }));
    const r = await checkRansomwareExposure("example.com");
    expect(r.error).toBeTruthy();
  });

  it("rejects a feed that is not an array", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ oops: true }) }));
    const r = await checkRansomwareExposure("example.com");
    expect(r.error).toBeTruthy();
  });
});

describe("feed caching", () => {
  it("fetches once and serves the cache on subsequent calls", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => POSTS });
    vi.stubGlobal("fetch", fetchMock);

    await getFeed();
    await getFeed();
    await getFeed();

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("collapses concurrent fetches into one request", async () => {
    // Ten workspaces checking at once must not pull the corpus ten times.
    const fetchMock = vi.fn().mockImplementation(
      () => new Promise((r) => setTimeout(() => r({ ok: true, status: 200, json: async () => POSTS }), 20)),
    );
    vi.stubGlobal("fetch", fetchMock);

    await Promise.all(Array.from({ length: 10 }, () => getFeed()));

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("serves stale data rather than failing when a refresh breaks", async () => {
    const good = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => POSTS });
    vi.stubGlobal("fetch", good);
    const first = await getFeed();
    expect(first.posts).toHaveLength(POSTS.length);

    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("down")));
    const second = await getFeed({ force: true });
    expect(second.posts).toHaveLength(POSTS.length);
  });
});
