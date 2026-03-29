import { describe, it, expect } from "vitest";
import { shannonEntropy, hasCredentialPattern, classifyPathResponse, extractEmailsFromText } from "../../../server/scanner";

describe("shannonEntropy", () => {
  it("returns 0 for empty string", () => {
    expect(shannonEntropy("")).toBe(0);
  });

  it("returns 0 for null/undefined-ish input", () => {
    expect(shannonEntropy("")).toBe(0);
  });

  it("returns 0 for single repeated character", () => {
    expect(Math.abs(shannonEntropy("aaaa"))).toBe(0);
  });

  it("returns ~1 for two equally distributed chars", () => {
    const e = shannonEntropy("abababab");
    expect(e).toBeCloseTo(1.0, 1);
  });

  it("returns high entropy for random-looking strings", () => {
    const e = shannonEntropy("aB3kL9mNp2xRtWz7");
    expect(e).toBeGreaterThan(3.5);
  });

  it("returns entropy proportional to character variety", () => {
    const low = shannonEntropy("aaabbb");
    const high = shannonEntropy("abcdef");
    expect(high).toBeGreaterThan(low);
  });
});

describe("hasCredentialPattern", () => {
  it("detects password=value patterns", () => {
    expect(hasCredentialPattern('password=mysecret123')).toBe(true);
    expect(hasCredentialPattern('DB_PASS="hunter2"')).toBe(true);
    expect(hasCredentialPattern("api_key: sk_live_abc123def456")).toBe(true);
  });

  it("detects AWS access key", () => {
    expect(hasCredentialPattern("AKIAIOSFODNN7EXAMPLE")).toBe(true);
  });

  it("detects GitHub PAT", () => {
    expect(hasCredentialPattern("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi0")).toBe(true);
  });

  it("detects Stripe key", () => {
    expect(hasCredentialPattern("sk_live_" + "1234567890abcdefghijklmn")).toBe(true);
  });

  it("detects JWT token", () => {
    expect(hasCredentialPattern("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")).toBe(true);
  });

  it("detects PEM private key header", () => {
    expect(hasCredentialPattern("-----BEGIN RSA PRIVATE KEY-----")).toBe(true);
  });

  it("detects SendGrid key", () => {
    expect(hasCredentialPattern("SG." + "abcdefghijklmnopqrstuw.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq")).toBe(true);
  });

  it("detects high-entropy tokens", () => {
    // 24 char mixed alphanumeric token with high entropy
    expect(hasCredentialPattern("aK3mL9pN2xRtWz7bQ4jF8cY5d")).toBe(true);
  });

  it("does NOT flag normal text", () => {
    expect(hasCredentialPattern("Hello world this is a normal page")).toBe(false);
    expect(hasCredentialPattern("Welcome to our documentation")).toBe(false);
    expect(hasCredentialPattern("<html><body>Login page</body></html>")).toBe(false);
  });

  it("does NOT flag short tokens", () => {
    expect(hasCredentialPattern("abc123")).toBe(false);
  });
});

describe("classifyPathResponse", () => {
  it("classifies 404 as not_found", () => {
    expect(classifyPathResponse(404)).toEqual({ responseType: "not_found", severity: "info" });
  });

  it("classifies 403 as forbidden", () => {
    expect(classifyPathResponse(403)).toEqual({ responseType: "forbidden", severity: "medium" });
  });

  it("classifies 401 as unauthorized", () => {
    expect(classifyPathResponse(401)).toEqual({ responseType: "unauthorized", severity: "low" });
  });

  it("classifies 200 as success", () => {
    expect(classifyPathResponse(200)).toEqual({ responseType: "success", severity: "low" });
  });

  it("classifies 301 as redirect", () => {
    expect(classifyPathResponse(301)).toEqual({ responseType: "redirect", severity: "low" });
  });

  it("classifies 500 as server_error", () => {
    expect(classifyPathResponse(500)).toEqual({ responseType: "server_error", severity: "low" });
  });

  it("classifies unknown status as other", () => {
    expect(classifyPathResponse(418)).toEqual({ responseType: "other", severity: "info" });
  });
});

describe("extractEmailsFromText", () => {
  it("extracts emails matching the domain", () => {
    const text = 'Contact us at admin@example.com or sales@example.com';
    const result = extractEmailsFromText(text, "example.com");
    expect(result).toContain("admin@example.com");
    expect(result).toContain("sales@example.com");
  });

  it("extracts mailto: links", () => {
    const text = '<a href="mailto:info@test.org">email us</a>';
    const result = extractEmailsFromText(text, "test.org");
    expect(result).toContain("info@test.org");
  });

  it("filters out emails from other domains", () => {
    const text = "user@example.com other@gmail.com";
    const result = extractEmailsFromText(text, "example.com");
    expect(result).toContain("user@example.com");
    expect(result).not.toContain("other@gmail.com");
  });

  it("includes subdomain emails", () => {
    const text = "admin@sub.example.com";
    const result = extractEmailsFromText(text, "example.com");
    expect(result).toContain("admin@sub.example.com");
  });

  it("returns empty for no matches", () => {
    const result = extractEmailsFromText("no emails here", "example.com");
    expect(result).toEqual([]);
  });

  it("lowercases extracted emails", () => {
    const text = "Admin@Example.COM";
    const result = extractEmailsFromText(text, "example.com");
    expect(result).toContain("admin@example.com");
  });

  it("deduplicates emails", () => {
    const text = "user@example.com user@example.com user@example.com";
    const result = extractEmailsFromText(text, "example.com");
    expect(result.length).toBe(1);
  });
});
