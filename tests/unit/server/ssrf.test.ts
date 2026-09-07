/**
 * SSRF guard.
 *
 * Two guards existed and disagreed. The one actually used on the report
 * re-verification path was a hostname STRING blocklist, which fails against
 * everything that matters: a host that merely resolves to 127.0.0.1, decimal
 * and hex IP literals, `127.0.0.2`, IPv6 spellings. Resolution collapses all of
 * those into one question — what address will the socket connect to?
 *
 * Most of these tests assert REFUSAL. A guard that lets something through when
 * it could not check is not a guard, so the fail-closed cases matter as much as
 * the obvious ones.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const resolve4 = vi.fn();
const resolve6 = vi.fn();
vi.mock("dns/promises", () => ({
  default: {
    resolve4: (...a: unknown[]) => resolve4(...a),
    resolve6: (...a: unknown[]) => resolve6(...a),
  },
}));

import { isPrivateHost, isPrivateIpv4, isPrivateIpv6, isSafeOutboundUrl } from "../../../server/utils/ssrf";

beforeEach(() => {
  resolve4.mockReset();
  resolve6.mockReset();
  resolve4.mockRejectedValue(new Error("ENOTFOUND"));
  resolve6.mockRejectedValue(new Error("ENOTFOUND"));
});

describe("isPrivateIpv4", () => {
  it("refuses every non-routable range", () => {
    for (const ip of [
      "127.0.0.1", "127.0.0.2", "127.255.255.254",   // loopback beyond the usual literal
      "10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1",
      "169.254.169.254",                              // AWS/Azure metadata
      "100.100.100.200",                              // Alibaba metadata (RFC6598)
      "0.0.0.0", "192.0.0.1", "198.18.0.1", "224.0.0.1",
    ]) {
      expect(isPrivateIpv4(ip), ip).toBe(true);
    }
  });

  it("allows genuinely public addresses", () => {
    for (const ip of ["8.8.8.8", "1.1.1.1", "93.184.216.34", "172.32.0.1", "192.169.0.1", "100.63.255.255"]) {
      expect(isPrivateIpv4(ip), ip).toBe(false);
    }
  });

  it("refuses malformed input rather than passing it through", () => {
    for (const bad of ["", "1.2.3", "1.2.3.4.5", "999.1.1.1", "a.b.c.d"]) {
      expect(isPrivateIpv4(bad), bad).toBe(true);
    }
  });
});

describe("isPrivateIpv6", () => {
  it("refuses loopback, link-local, unique-local and IPv4-mapped private", () => {
    for (const ip of ["::1", "[::1]", "fe80::1", "fc00::1", "fd12:3456::1", "::ffff:127.0.0.1", "fd00:ec2::254"]) {
      expect(isPrivateIpv6(ip), ip).toBe(true);
    }
  });

  it("allows a public IPv6 address", () => {
    expect(isPrivateIpv6("2606:4700:4700::1111")).toBe(false);
  });
});

describe("isPrivateHost", () => {
  /** The case no string blocklist can ever catch. */
  it("refuses a public-looking hostname that RESOLVES to loopback", async () => {
    resolve4.mockResolvedValue(["127.0.0.1"]);
    expect(await isPrivateHost("totally-legit.example.com")).toBe(true);
  });

  it("refuses when any resolved address is private, even if others are public", async () => {
    resolve4.mockResolvedValue(["93.184.216.34", "10.0.0.5"]);
    expect(await isPrivateHost("split-horizon.example.com")).toBe(true);
  });

  /**
   * A host with a public A record and a loopback AAAA would otherwise slip
   * through whenever the runtime preferred IPv6.
   */
  it("checks AAAA as well as A", async () => {
    resolve4.mockResolvedValue(["93.184.216.34"]);
    resolve6.mockResolvedValue(["::1"]);
    expect(await isPrivateHost("dual-stack.example.com")).toBe(true);
  });

  it("allows a host that resolves only to public addresses", async () => {
    resolve4.mockResolvedValue(["93.184.216.34"]);
    expect(await isPrivateHost("example.com")).toBe(false);
  });

  it("fails closed when nothing resolves", async () => {
    expect(await isPrivateHost("does-not-exist.invalid")).toBe(true);
  });

  it("fails closed on an empty host", async () => {
    expect(await isPrivateHost("")).toBe(true);
  });

  /** Packed IP literals: all of these are 127.0.0.1. */
  it("decodes decimal, hex and octal IP literals instead of guessing", async () => {
    expect(await isPrivateHost("2130706433")).toBe(true);   // decimal
    expect(await isPrivateHost("0x7f000001")).toBe(true);   // hex
    expect(await isPrivateHost("017700000001")).toBe(true); // octal
    // A packed PUBLIC address is correctly allowed rather than blanket-refused.
    expect(await isPrivateHost("134744072")).toBe(false);   // 8.8.8.8
  });

  it("judges bare literals without resolving them", async () => {
    expect(await isPrivateHost("127.0.0.2")).toBe(true);
    expect(await isPrivateHost("8.8.8.8")).toBe(false);
    expect(resolve4).not.toHaveBeenCalled();
  });
});

describe("isSafeOutboundUrl", () => {
  it("allows a public https URL", async () => {
    resolve4.mockResolvedValue(["93.184.216.34"]);
    expect(await isSafeOutboundUrl("https://example.com/evidence")).toBe(true);
  });

  it("refuses non-http schemes", async () => {
    for (const u of ["file:///etc/passwd", "gopher://x/", "ftp://x/", "data:text/plain,x"]) {
      expect(await isSafeOutboundUrl(u), u).toBe(false);
    }
  });

  it("refuses a malformed URL", async () => {
    expect(await isSafeOutboundUrl("not a url")).toBe(false);
  });

  it("refuses the cloud metadata endpoint however it is written", async () => {
    expect(await isSafeOutboundUrl("http://169.254.169.254/latest/meta-data/")).toBe(false);
    expect(await isSafeOutboundUrl("http://[fd00:ec2::254]/latest/meta-data/")).toBe(false);
  });
});

/**
 * Every outbound path that posts to a USER-SUPPLIED URL must re-check at the
 * moment it connects, and must not follow redirects.
 *
 * Validating on save is not enough, and the webhook dispatcher proved it: the
 * create, update and test routes all guarded the URL, and delivery — which
 * happens days or months later, carrying the signature header and the
 * decrypted secret — did not. Two holes at once:
 *
 *   · a host that resolved public when the endpoint was saved can resolve to
 *     127.0.0.1 or 169.254.169.254 by the time a critical finding fires;
 *   · `fetch` defaults to `redirect: "follow"`, so a public receiver can 302
 *     the POST to an address nothing vetted — the exact defect the report
 *     evidence path was fixed for.
 *
 * A static scan, in the same spirit as `bare-id-authorization.test.ts`:
 * removing either protection fails here rather than in production.
 */
describe("user-supplied outbound URLs are re-checked at connect time", () => {
  const SOURCES = [
    { file: "../../../server/routes/webhooks.ts", what: "webhook delivery" },
    // Carries `Authorization: Basic <email:apiToken>` to a customer-supplied
    // Jira host, so a followed redirect would hand those credentials to
    // whatever address the 302 names.
    { file: "../../../server/routes/integrations-tickets.ts", what: "Jira ticket creation" },
  ];

  for (const { file, what } of SOURCES) {
    it(`${what} verifies the destination and refuses redirects`, async () => {
      const fs = await import("fs");
      const path = await import("path");
      const src = fs.readFileSync(path.resolve(__dirname, file), "utf8");

      // The guard must appear, and it must be the RESOLVING one — a hostname
      // string test misses `127.0.0.2`, decimal/octal literals and every IPv6
      // form, which is why the old `isSafeExternalUrl` was deleted.
      expect(src, "must call the resolving guard").toMatch(/isSafeOutboundUrl\s*\(/);
      expect(src, "must not follow redirects on a user-supplied URL")
        .toMatch(/redirect:\s*"manual"/);
    });
  }
});
