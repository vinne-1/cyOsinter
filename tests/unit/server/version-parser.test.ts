import { describe, it, expect } from "vitest";
import {
  compareVersions,
  isEol,
  normalizeProduct,
  extractFromBanner,
  extractFromHeaders,
} from "../../../server/enrichment/version-parser";

describe("compareVersions", () => {
  it("returns 0 for equal versions", () => {
    expect(compareVersions("1.2.3", "1.2.3")).toBe(0);
  });

  it("returns -1 when a < b", () => {
    expect(compareVersions("1.0", "2.0")).toBe(-1);
    expect(compareVersions("1.17.9", "1.18.0")).toBe(-1);
  });

  it("returns 1 when a > b", () => {
    expect(compareVersions("2.0", "1.9")).toBe(1);
    expect(compareVersions("1.18.1", "1.18.0")).toBe(1);
  });

  it("handles versions with different segment counts", () => {
    expect(compareVersions("1.18", "1.18.0")).toBe(0);
    expect(compareVersions("2", "1.9.9")).toBe(1);
  });
});

describe("isEol", () => {
  it("returns false when version is null", () => {
    expect(isEol("nginx", null)).toBe(false);
  });

  it("returns false for unknown product", () => {
    expect(isEol("somecustom", "1.0")).toBe(false);
  });

  it("marks EOL nginx version as EOL", () => {
    expect(isEol("nginx", "1.14.2")).toBe(true);
  });

  it("marks current nginx version as NOT EOL", () => {
    expect(isEol("nginx", "1.24.0")).toBe(false);
  });

  it("marks EOL PHP version as EOL", () => {
    expect(isEol("php", "7.4.30")).toBe(true);
  });

  it("marks current PHP as not EOL", () => {
    expect(isEol("php", "8.2.0")).toBe(false);
  });

  it("strips trailing letter suffix before comparison (e.g. openssl 1.0.1k)", () => {
    expect(isEol("openssl", "1.0.1k")).toBe(true);
  });

  it("handles case-insensitive product matching", () => {
    expect(isEol("NGINX", "1.10.0")).toBe(true);
  });

  it("treats boundary version as EOL (strictly less than)", () => {
    // eolBelow: "1.18" — nginx 1.18 itself is not EOL (it's not < 1.18)
    expect(isEol("nginx", "1.18.0")).toBe(false);
  });
});

describe("normalizeProduct", () => {
  it("lowercases the product name", () => {
    expect(normalizeProduct("Nginx")).toBe("nginx");
  });

  it("strips x-powered-by prefix", () => {
    expect(normalizeProduct("x-powered-by: PHP")).toBe("php");
  });

  it("strips server prefix", () => {
    expect(normalizeProduct("Server: Apache")).toBe("apache");
  });

  it("trims whitespace", () => {
    expect(normalizeProduct("  nginx  ")).toBe("nginx");
  });
});

describe("extractFromBanner", () => {
  it("extracts nginx product and version", () => {
    const results = extractFromBanner("nginx/1.24.0", "header");
    expect(results).toHaveLength(1);
    expect(results[0].product).toBe("nginx");
    expect(results[0].version).toBe("1.24.0");
    expect(results[0].source).toBe("header");
    expect(results[0].confidence).toBe(90);
  });

  it("extracts apache version", () => {
    const results = extractFromBanner("Apache/2.4.52 (Ubuntu)", "banner");
    expect(results.some((r) => r.product === "apache" && r.version === "2.4.52")).toBe(true);
  });

  it("extracts php via x-powered-by header line", () => {
    const results = extractFromBanner("x-powered-by: PHP/8.1.0", "header");
    expect(results.some((r) => r.product === "php" && r.version === "8.1.0")).toBe(true);
  });

  it("detects wordpress from URL path", () => {
    const results = extractFromBanner("/wp-content/themes/default/", "html");
    expect(results.some((r) => r.product === "wordpress")).toBe(true);
  });

  it("returns low confidence when no version found (wordpress)", () => {
    const results = extractFromBanner("/wp-includes/js/main.js", "html");
    const wp = results.find((r) => r.product === "wordpress");
    expect(wp?.confidence).toBe(70);
  });

  it("returns empty array for unrecognized banner", () => {
    const results = extractFromBanner("some random string with no tech", "banner");
    expect(results).toHaveLength(0);
  });

  it("extracts IIS version", () => {
    const results = extractFromBanner("Microsoft-IIS/10.0", "header");
    expect(results.some((r) => r.product === "iis" && r.version === "10.0")).toBe(true);
  });
});

describe("extractFromHeaders", () => {
  it("extracts from Server header", () => {
    const results = extractFromHeaders({ server: "nginx/1.20.2" });
    expect(results.some((r) => r.product === "nginx" && r.version === "1.20.2")).toBe(true);
  });

  it("extracts from multiple headers", () => {
    const results = extractFromHeaders({
      server: "Apache/2.4.0",
      "x-powered-by": "PHP/8.0.0",
    });
    expect(results.some((r) => r.product === "apache")).toBe(true);
    expect(results.some((r) => r.product === "php")).toBe(true);
  });

  it("returns empty array for empty headers", () => {
    expect(extractFromHeaders({})).toHaveLength(0);
  });
});
