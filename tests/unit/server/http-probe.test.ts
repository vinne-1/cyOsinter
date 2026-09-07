/**
 * Unit tests for server/scanner/http-probe.ts.
 *
 * Live-host detection used to keep one bit — did anything answer — so a scan
 * could report ninety live subdomains and say nothing about any of them. These
 * tests cover the enrichment that replaced it, and the two behaviours that keep
 * it honest: HTTPS preference, and omitting hosts that did not answer rather
 * than inventing a zero-status row for them.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const httpGet = vi.fn();
vi.mock("../../../server/scanner/http.js", () => ({ httpGet: (...a: unknown[]) => httpGet(...a) }));
vi.mock("../../../server/logger.js", () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));
vi.mock("../../../server/scanner/utils.js", async (orig) => {
  const actual = await (orig() as Promise<Record<string, unknown>>);
  return { ...actual, resolveExecutable: () => null }; // never delegate to httpx in tests
});

import { probeHosts, extractTitle } from "../../../server/scanner/http-probe";

const page = (opts: Partial<{ status: number; body: string; headers: Record<string, string>; finalUrl: string }> = {}) => ({
  status: opts.status ?? 200,
  headers: { "content-type": "text/html", ...(opts.headers ?? {}) },
  body: opts.body ?? "<html><head><title>Home</title></head><body>hi</body></html>",
  finalUrl: opts.finalUrl ?? "https://a.example.com/",
});

beforeEach(() => {
  httpGet.mockReset();
  httpGet.mockResolvedValue(null);
});

describe("extractTitle", () => {
  it("collapses whitespace and decodes entities", () => {
    expect(extractTitle("<title>\n  Acme &amp;  Co\n</title>")).toBe("Acme & Co");
  });

  it("returns undefined when there is no usable title", () => {
    expect(extractTitle("<html><body>no title</body></html>")).toBeUndefined();
    expect(extractTitle("<title>   </title>")).toBeUndefined();
  });

  it("caps a runaway title", () => {
    expect(extractTitle(`<title>${"x".repeat(500)}</title>`)!.length).toBeLessThanOrEqual(200);
  });
});

describe("probeHosts", () => {
  it("captures title, server, tech, status and length in one pass", async () => {
    httpGet.mockImplementation(async (url: string) =>
      url.startsWith("https://")
        ? page({
            headers: { server: "nginx/1.18.0", "content-length": "1234", "x-powered-by": "PHP/8.1" },
            body: '<html><head><title>Acme Admin</title><meta name="generator" content="WordPress 6.4"></head></html>',
          })
        : null,
    );

    const [p] = await probeHosts(["a.example.com"], { allowExternalEngine: false });

    expect(p.scheme).toBe("https");
    expect(p.status).toBe(200);
    expect(p.title).toBe("Acme Admin");
    expect(p.server).toBe("nginx/1.18.0");
    expect(p.contentLength).toBe(1234);
    expect(p.technologies.length).toBeGreaterThan(0);
  });

  it("prefers HTTPS and only falls back to HTTP when HTTPS is silent", async () => {
    httpGet.mockImplementation(async (url: string) =>
      url.startsWith("http://") ? page({ finalUrl: "http://b.example.com/" }) : null,
    );
    const [p] = await probeHosts(["b.example.com"], { allowExternalEngine: false });
    expect(p.scheme).toBe("http");
  });

  /**
   * "Did not answer" is the absence of a result. Inventing a zero-status row
   * would put dead hosts into the live inventory.
   */
  it("omits hosts that answered nothing", async () => {
    httpGet.mockResolvedValue(null);
    expect(await probeHosts(["dead.example.com"], { allowExternalEngine: false })).toEqual([]);
  });

  it("records where a host redirected to", async () => {
    httpGet.mockImplementation(async (url: string) =>
      url.startsWith("https://") ? page({ finalUrl: "https://www.example.com/landing" }) : null,
    );
    const [p] = await probeHosts(["example.com"], { allowExternalEngine: false });
    expect(p.redirectsTo).toBe("https://www.example.com/landing");
  });

  it("does not report a redirect when the host served its own URL", async () => {
    httpGet.mockImplementation(async (url: string) =>
      url.startsWith("https://") ? page({ finalUrl: "https://a.example.com/" }) : null,
    );
    const [p] = await probeHosts(["a.example.com"], { allowExternalEngine: false });
    expect(p.redirectsTo).toBeUndefined();
  });

  /**
   * Cleartext is only a finding when HTTPS also works — an HTTP-only host is
   * described by the scheme field, not by a transport-security finding.
   */
  it("flags cleartext without upgrade only when HTTPS is also available", async () => {
    httpGet.mockImplementation(async (url: string) =>
      url.startsWith("https://")
        ? page()
        : page({ finalUrl: "http://a.example.com/" }),
    );
    const [withHttps] = await probeHosts(["a.example.com"], { allowExternalEngine: false, checkCleartext: true });
    expect(withHttps.cleartextWithoutUpgrade).toBe(true);

    // HTTP-only host: no HTTPS, so nothing to upgrade from.
    httpGet.mockImplementation(async (url: string) =>
      url.startsWith("http://") ? page({ finalUrl: "http://c.example.com/" }) : null,
    );
    const [httpOnly] = await probeHosts(["c.example.com"], { allowExternalEngine: false, checkCleartext: true });
    expect(httpOnly.cleartextWithoutUpgrade).toBe(false);
  });

  it("does not flag cleartext when HTTP upgrades to HTTPS", async () => {
    httpGet.mockImplementation(async (url: string) =>
      url.startsWith("https://")
        ? page()
        : page({ finalUrl: "https://a.example.com/" }), // upgraded
    );
    const [p] = await probeHosts(["a.example.com"], { allowExternalEngine: false, checkCleartext: true });
    expect(p.cleartextWithoutUpgrade).toBe(false);
  });

  it("reports progress and handles an empty host list", async () => {
    expect(await probeHosts([], { allowExternalEngine: false })).toEqual([]);

    httpGet.mockImplementation(async (url: string) => (url.startsWith("https://") ? page() : null));
    const seen: number[] = [];
    await probeHosts(["a.example.com", "b.example.com"], {
      allowExternalEngine: false,
      onProgress: (done) => seen.push(done),
    });
    expect(seen).toHaveLength(2);
  });

  /**
   * A body that filled httpGet's cap was truncated, so its length is not the
   * page's length. Reporting the cap states a measurement never taken.
   */
  it("does not report the body-truncation cap as a real content length", async () => {
    httpGet.mockImplementation(async (url: string) =>
      url.startsWith("https://")
        ? page({ body: "x".repeat(5000), headers: {} })
        : null,
    );
    const [truncated] = await probeHosts(["a.example.com"], { allowExternalEngine: false });
    expect(truncated.contentLength).toBeUndefined();

    httpGet.mockImplementation(async (url: string) =>
      url.startsWith("https://") ? page({ body: "<html>short</html>", headers: {} }) : null,
    );
    const [short] = await probeHosts(["b.example.com"], { allowExternalEngine: false });
    expect(short.contentLength).toBe(18);
  });

  it("attributes WAF and CDN from the response headers", async () => {
    httpGet.mockImplementation(async (url: string) =>
      url.startsWith("https://") ? page({ headers: { server: "cloudflare", "cf-ray": "abc123" } }) : null,
    );
    const [p] = await probeHosts(["a.example.com"], { allowExternalEngine: false });
    expect(p.waf).toBe("Cloudflare");
    expect(p.cdn).toBe("Cloudflare");
  });
});
