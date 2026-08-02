/**
 * Unit tests for server/scanner/passive-sources.ts — the pure parsing helpers
 * that normalize and extract subdomains from free third-party OSINT sources.
 */

import { describe, it, expect } from "vitest";
import { normalizeHost, extractHostsFromText } from "../../../server/scanner/passive-sources";

describe("normalizeHost", () => {
  const domain = "example.com";

  it("accepts a valid subdomain", () => {
    expect(normalizeHost("api.example.com", domain)).toBe("api.example.com");
  });

  it("lowercases and trims", () => {
    expect(normalizeHost("  API.Example.COM  ", domain)).toBe("api.example.com");
  });

  it("strips a wildcard prefix", () => {
    expect(normalizeHost("*.example.com", domain)).toBe(null); // apex after strip → not a subdomain
    expect(normalizeHost("*.api.example.com", domain)).toBe("api.example.com");
  });

  it("strips a trailing dot", () => {
    expect(normalizeHost("api.example.com.", domain)).toBe("api.example.com");
  });

  it("strips scheme and path if a URL slips through", () => {
    expect(normalizeHost("https://api.example.com/login", domain)).toBe("api.example.com");
    expect(normalizeHost("http://api.example.com:8443", domain)).toBe("api.example.com");
  });

  it("rejects the apex domain itself", () => {
    expect(normalizeHost("example.com", domain)).toBe(null);
  });

  it("rejects names outside the target domain", () => {
    expect(normalizeHost("api.evil.com", domain)).toBe(null);
    expect(normalizeHost("notexample.com", domain)).toBe(null);
    expect(normalizeHost("example.com.evil.com", domain)).toBe(null);
  });

  it("rejects empty / malformed input", () => {
    expect(normalizeHost("", domain)).toBe(null);
    expect(normalizeHost("   ", domain)).toBe(null);
  });

  it("handles deep multi-level subdomains", () => {
    expect(normalizeHost("a.b.c.example.com", domain)).toBe("a.b.c.example.com");
  });
});

describe("extractHostsFromText", () => {
  const domain = "example.com";

  it("extracts hosts from HackerTarget-style host,ip lines", () => {
    const text = "api.example.com,1.2.3.4\nmail.example.com,5.6.7.8\nwww.example.com,9.9.9.9";
    const hosts = extractHostsFromText(text, domain);
    expect(hosts.sort()).toEqual(["api.example.com", "mail.example.com", "www.example.com"]);
  });

  it("extracts hosts embedded in HTML", () => {
    const html = `<table><tr><td>dev.example.com</td></tr><tr><td>staging.example.com</td></tr></table>`;
    const hosts = extractHostsFromText(html, domain);
    expect(hosts).toContain("dev.example.com");
    expect(hosts).toContain("staging.example.com");
  });

  it("dedupes repeated hosts", () => {
    const text = "api.example.com api.example.com api.example.com";
    expect(extractHostsFromText(text, domain)).toEqual(["api.example.com"]);
  });

  it("ignores hosts from other domains", () => {
    const text = "api.example.com attacker.evil.com cdn.other.net";
    expect(extractHostsFromText(text, domain)).toEqual(["api.example.com"]);
  });

  it("returns empty for text with no matching hosts", () => {
    expect(extractHostsFromText("no domains here at all", domain)).toEqual([]);
  });

  it("does not treat the bare apex as a subdomain", () => {
    expect(extractHostsFromText("visit example.com today", domain)).toEqual([]);
  });

  it("escapes regex metacharacters in the domain safely", () => {
    // A domain is normal, but ensure a dot is treated literally (not 'any char').
    const text = "api.exampleXcom is not a match; api.example.com is";
    expect(extractHostsFromText(text, domain)).toEqual(["api.example.com"]);
  });
});
