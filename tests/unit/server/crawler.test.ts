/**
 * Unit tests for server/scanner/crawler.ts.
 *
 * The engine had no crawler, so DAST-lite probed a hardcoded guess list
 * (`/?q=`, `/search?query=`) rather than the application's real parameters. The
 * two behaviours that make a crawler usable rather than merely present are
 * shape-deduplication (a shop with 10,000 products has ONE endpoint) and a
 * scope check (links point anywhere, and following them off-domain is both an
 * SSRF surface and unauthorised traffic).
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const httpGet = vi.fn();
vi.mock("../../../server/scanner/http.js", () => ({ httpGet: (...a: unknown[]) => httpGet(...a) }));
vi.mock("../../../server/logger.js", () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));
vi.mock("../../../server/scanner/utils.js", () => ({ resolveExecutable: () => null }));

import {
  crawlSite,
  isInScope,
  endpointShape,
  testableParams,
  extractLinks,
  extractForms,
} from "../../../server/scanner/crawler";
import { buildInjectionTargets } from "../../../server/scanner/dast-lite";

const DOMAIN = "example.com";
const html = (body: string) => ({
  status: 200,
  headers: { "content-type": "text/html; charset=utf-8" },
  body,
  finalUrl: `https://${DOMAIN}/`,
});

beforeEach(() => {
  httpGet.mockReset();
  httpGet.mockResolvedValue(null);
});

describe("isInScope", () => {
  it("accepts the apex and its subdomains", () => {
    expect(isInScope("https://example.com/a", DOMAIN)).toBe(true);
    expect(isInScope("https://api.example.com/a", DOMAIN)).toBe(true);
  });

  it("refuses off-domain links and non-http schemes", () => {
    expect(isInScope("https://evil.com/a", DOMAIN)).toBe(false);
    // The lookalike an unanchored suffix check would have let through.
    expect(isInScope("https://notexample.com/a", DOMAIN)).toBe(false);
    expect(isInScope("https://example.com.evil.net/a", DOMAIN)).toBe(false);
    expect(isInScope("file:///etc/passwd", DOMAIN)).toBe(false);
    expect(isInScope("javascript:alert(1)", DOMAIN)).toBe(false);
  });
});

describe("endpointShape", () => {
  /**
   * The single most important behaviour here: without it, a catalogue of ten
   * thousand products becomes ten thousand crawl entries and ten thousand
   * active-test requests against one parameter.
   */
  it("collapses the same endpoint with different data", () => {
    const a = endpointShape("https://example.com/product?id=1");
    const b = endpointShape("https://example.com/product?id=99999");
    expect(a).toBe(b);
  });

  it("keeps endpoints with different parameter sets apart", () => {
    expect(endpointShape("https://example.com/p?id=1")).not.toBe(endpointShape("https://example.com/p?id=1&sort=asc"));
  });

  it("ignores parameter order and a trailing slash", () => {
    expect(endpointShape("https://example.com/p?b=2&a=1")).toBe(endpointShape("https://example.com/p/?a=9&b=8"));
  });
});

describe("testableParams", () => {
  it("drops tracking and cache-busting parameters", () => {
    expect(testableParams("https://example.com/p?q=x&utm_source=nl&fbclid=abc&gclid=z")).toEqual(["q"]);
  });

  it("returns the real parameters sorted and deduped", () => {
    expect(testableParams("https://example.com/s?b=1&a=2&a=3")).toEqual(["a", "b"]);
  });
});

describe("extractLinks / extractForms", () => {
  it("finds anchors, form actions, script sources and API paths in inline JS", () => {
    const body = `
      <a href="/about">About</a>
      <form action="/search"><input name="q"></form>
      <script src="/static/app.js"></script>
      <script>fetch("/api/v1/orders")</script>
      <a href="mailto:x@example.com">mail</a>
      <a href="#top">top</a>`;
    const urls = extractLinks(body, "https://example.com/").map((l) => l.url);
    expect(urls).toContain("https://example.com/about");
    expect(urls).toContain("https://example.com/search");
    expect(urls).toContain("https://example.com/api/v1/orders");
    // Neither a mail link nor a fragment is an endpoint.
    expect(urls.some((u) => u.startsWith("mailto:"))).toBe(false);
    expect(urls.some((u) => u.endsWith("#top"))).toBe(false);
  });

  it("captures form method and input names", () => {
    const forms = extractForms('<form action="/login" method="post"><input name="user"><input name="pass"></form>', "https://example.com/");
    expect(forms).toHaveLength(1);
    expect(forms[0].method).toBe("POST");
    expect(forms[0].inputs).toEqual(["user", "pass"]);
    expect(forms[0].action).toBe("https://example.com/login");
  });
});

describe("crawlSite", () => {
  it("walks in-scope links and collects the parameterised endpoints", async () => {
    httpGet.mockImplementation(async (url: string) => {
      if (url === "https://example.com/") {
        return html('<a href="/search?keyword=shoes">s</a><a href="/about">a</a><a href="https://evil.com/x">e</a>');
      }
      if (url.startsWith("https://example.com/search")) return html("<p>results</p>");
      if (url === "https://example.com/about") return html("<p>about</p>");
      return null;
    });

    const out = await crawlSite(DOMAIN, { allowExternalEngine: false, maxDepth: 2 });

    expect(out.engine).toBe("native");
    expect(out.parameterised.map((u) => u.params)).toEqual([["keyword"]]);
    // The off-domain link must never have been fetched.
    expect(httpGet.mock.calls.every((c) => String(c[0]).includes("example.com"))).toBe(true);
  });

  it("collapses a catalogue of identical endpoint shapes", async () => {
    httpGet.mockImplementation(async (url: string) => {
      if (url === "https://example.com/") {
        const links = Array.from({ length: 50 }, (_, i) => `<a href="/product?id=${i}">p</a>`).join("");
        return html(links);
      }
      return html("<p>product</p>");
    });

    const out = await crawlSite(DOMAIN, { allowExternalEngine: false, maxDepth: 1 });
    const products = out.urls.filter((u) => u.url.includes("/product"));
    expect(products).toHaveLength(1);
  });

  it("does not fetch asset files", async () => {
    httpGet.mockImplementation(async (url: string) =>
      url === "https://example.com/" ? html('<a href="/logo.png">i</a><a href="/style.css">c</a><a href="/real">r</a>') : html("<p>x</p>"),
    );
    await crawlSite(DOMAIN, { allowExternalEngine: false, maxDepth: 2 });
    expect(httpGet.mock.calls.some((c) => String(c[0]).endsWith(".png"))).toBe(false);
    expect(httpGet.mock.calls.some((c) => String(c[0]).endsWith(".css"))).toBe(false);
  });

  it("stops at maxPages and says it truncated", async () => {
    httpGet.mockImplementation(async () =>
      html(Array.from({ length: 30 }, (_, i) => `<a href="/p${i}?x=1">p</a>`).join("")),
    );
    const out = await crawlSite(DOMAIN, { allowExternalEngine: false, maxPages: 5, maxDepth: 5 });
    expect(out.pagesFetched).toBeLessThanOrEqual(6);
    expect(out.truncated).toBe(true);
  });

  it("ignores non-HTML responses", async () => {
    httpGet.mockResolvedValue({ status: 200, headers: { "content-type": "application/json" }, body: '{"a":1}', finalUrl: "https://example.com/" });
    const out = await crawlSite(DOMAIN, { allowExternalEngine: false });
    expect(out.forms).toEqual([]);
  });
});

describe("buildInjectionTargets", () => {
  /**
   * The point of crawling: probing `/?q=` on an application whose search
   * parameter is `keyword` tests nothing at all.
   */
  it("puts real crawled parameters ahead of the hardcoded guesses", () => {
    const out = buildInjectionTargets([{ path: "/search", params: ["keyword"] }], "<b>x</b>");
    expect(out[0]).toContain("/search?keyword=");
    expect(out.some((u) => u.startsWith("/?q="))).toBe(true); // fallback retained
  });

  it("still returns the guess list when the crawl found nothing", () => {
    const out = buildInjectionTargets([], "<b>x</b>");
    expect(out.length).toBeGreaterThan(0);
    expect(out[0]).toContain("/?q=");
  });

  it("caps the request budget for an application with many parameters", () => {
    const many = Array.from({ length: 100 }, (_, i) => ({ path: `/p${i}`, params: [`a${i}`] }));
    expect(buildInjectionTargets(many, "x").length).toBeLessThanOrEqual(15);
  });
});
