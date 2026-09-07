/**
 * Unit tests for server/scanner/response-oracle.ts.
 *
 * The behaviour under test is the one that decides whether every path-probing
 * detector in the scanner reports a finding at all, so the cases here are the
 * real-world shapes that defeated the previous exact-match fingerprint: an error
 * page carrying a request id, one echoing the requested path, and a host that
 * answers 200 for everything.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const httpGet = vi.fn();
vi.mock("../../../server/scanner/http.js", () => ({
  httpGet: (...a: unknown[]) => httpGet(...a),
}));

import { calibrate, classifyAgainstBaseline, isSoftNotFound, jaccard, bodyTokens, normalizeBody } from "../../../server/scanner/response-oracle";

const res = (status: number, body: string, finalUrl = "https://x.com/whatever") => ({
  status, body, headers: { "content-type": "text/html" }, finalUrl,
});

beforeEach(() => { httpGet.mockReset(); });

describe("normalizeBody", () => {
  it("collapses the identifiers that legitimately differ between two error pages", () => {
    const a = normalizeBody("Request 550e8400-e29b-41d4-a716-446655440000 failed at 1712345678");
    const b = normalizeBody("Request 6ba7b810-9dad-11d1-80b4-00c04fd430c8 failed at 1799999999");
    expect(a).toBe(b);
  });
});

describe("jaccard", () => {
  it("is 1 for identical token sets and 0 when one side is empty", () => {
    expect(jaccard(bodyTokens("alpha beta gamma"), bodyTokens("gamma beta alpha"))).toBe(1);
    expect(jaccard(bodyTokens("alpha"), new Set<string>())).toBe(0);
  });
});

describe("calibrate", () => {
  it("marks a host that answers 2xx for non-existent paths as catch-all", async () => {
    httpGet.mockResolvedValue(res(200, "<html><body>Acme home page with plenty of words to compare</body></html>"));
    const b = await calibrate("https://x.com", ["bare"]);
    expect(b.calibrated).toBe(true);
    expect(b.catchAll).toBe(true);
  });

  it("reports not calibrated when the host cannot be reached", async () => {
    httpGet.mockResolvedValue(null);
    const b = await calibrate("https://x.com", ["bare"]);
    expect(b.calibrated).toBe(false);
    expect(b.samples).toHaveLength(0);
  });

  /**
   * A host whose own error page differs between two requests gives us nothing
   * to compare against. Keeping such a sample would withhold real findings, so
   * the shape is dropped instead.
   */
  it("drops a shape whose not-found response is not stable between two probes", async () => {
    let n = 0;
    httpGet.mockImplementation(async () => {
      n++;
      return n === 1
        ? res(200, "completely different alpha beta gamma delta epsilon zeta eta theta")
        : res(200, "nothing alike here whatsoever lorem ipsum dolor sit amet consectetur");
    });
    const b = await calibrate("https://x.com", ["bare"]);
    expect(b.samples).toHaveLength(0);
    expect(b.calibrated).toBe(false);
  });
});

describe("classifyAgainstBaseline", () => {
  const notFoundPage = (id: string) =>
    `<html><head><title>Page not found</title></head><body><h1>We could not find that page</h1><p>Try the search box or return to the home page.</p><!-- request ${id} --></body></html>`;

  async function catchAllBaseline() {
    let n = 0;
    // Each calibration probe requests its own random path, so the final URL
    // differs per probe exactly as it does against a real host.
    httpGet.mockImplementation(async (url: string) => res(200, notFoundPage(`id-${n++}-abcdef0123456789`), url));
    return calibrate("https://x.com", ["bare"]);
  }

  /**
   * The exact-match fingerprint this replaced compared body length plus the
   * first hundred characters. A request id shifts both, so the old guard never
   * fired and every wordlist path became a "hit".
   */
  it("recognises a soft 404 despite a per-request id that changes the body", async () => {
    const baseline = await catchAllBaseline();
    const verdict = classifyAgainstBaseline(baseline, "/.env", res(200, notFoundPage("id-999-fedcba9876543210")));
    expect(verdict.verdict).toBe("soft-404");
  });

  it("passes through a genuinely different response on the same catch-all host", async () => {
    const baseline = await catchAllBaseline();
    const verdict = classifyAgainstBaseline(baseline, "/.env", res(200, "APP_ENV=production\nDB_PASSWORD=hunter2\nAWS_REGION=eu-west-1\n"));
    expect(verdict.verdict).toBe("real");
  });

  it("says unknown — never 'real' — when there is no baseline", () => {
    expect(classifyAgainstBaseline(null, "/.env", res(200, "anything")).verdict).toBe("unknown");
    expect(isSoftNotFound(null, "/.env", res(200, "anything"))).toBe(false);
  });

  it("does not suppress a response whose status differs from the baseline", async () => {
    const baseline = await catchAllBaseline();
    expect(isSoftNotFound(baseline, "/admin", res(403, notFoundPage("x")))).toBe(false);
  });

  it("compares short bodies by size when there is too little text for token overlap", async () => {
    httpGet.mockImplementation(async (url: string) => res(200, "{}", url));
    const baseline = await calibrate("https://x.com", ["json"]);
    expect(isSoftNotFound(baseline, "/config.json", res(200, "{}"))).toBe(true);
    expect(isSoftNotFound(baseline, "/config.json", res(200, JSON.stringify({ awsSecretKey: "AKIAIOSFODNN7EXAMPLE", region: "eu-west-1" })))).toBe(false);
  });
});
