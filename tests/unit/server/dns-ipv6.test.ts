/**
 * IPv6 in discovery.
 *
 * `resolveDNS` backs every discovery path — the wordlist bruteforce, permutation
 * and certificate-SAN validation — and asked only for A and CNAME. A host
 * published solely on IPv6 therefore resolved to nothing and was discarded as
 * non-existent, so an entire class of asset was invisible.
 *
 * The inconsistency was already visible inside this codebase: `isPrivateHost`
 * checks A *and* AAAA precisely because ignoring AAAA there was a security hole,
 * while discovery ignored it and silently lost assets.
 *
 * Verified against real hosts before the fix: `ipv6.test-ipv6.com`,
 * `v6.ipv6-test.com` and `ipv6.lookup.test-ipv6.com` all publish AAAA with no A
 * and no CNAME, and were found by nothing.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// `vi.hoisted` because vi.mock is lifted above ordinary const declarations, so a
// plain `const resolve4 = vi.fn()` is still in its temporal dead zone when the
// factory runs.
const { resolve4, resolve6, resolveCname } = vi.hoisted(() => ({
  resolve4: vi.fn(),
  resolve6: vi.fn(),
  resolveCname: vi.fn(),
}));

vi.mock("dns/promises", () => {
  class Resolver {
    setServers() { /* ignored in tests */ }
    resolve4(...a: unknown[]) { return resolve4(...a); }
    resolve6(...a: unknown[]) { return resolve6(...a); }
    resolveCname(...a: unknown[]) { return resolveCname(...a); }
  }
  return { default: { Resolver, resolve4, resolve6, resolveCname } };
});

vi.mock("../../../server/logger", () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));

import { resolveDNS } from "../../../server/scanner/dns";

const nx = () => Promise.reject(Object.assign(new Error("queryA ENOTFOUND"), { code: "ENOTFOUND" }));

beforeEach(() => {
  resolve4.mockReset();
  resolve6.mockReset();
  resolveCname.mockReset();
  resolve4.mockImplementation(nx);
  resolve6.mockImplementation(nx);
  resolveCname.mockImplementation(nx);
});

describe("resolveDNS", () => {
  /** The case that was invisible: AAAA only, no A, no CNAME. */
  it("treats an IPv6-only host as resolved", async () => {
    resolve6.mockResolvedValue(["2606:4700::1111"]);

    const d = await resolveDNS("v6only.example.com");

    expect(d.ipv6).toEqual(["2606:4700::1111"]);
    expect(d.ips).toEqual([]);
    expect(d.cnames).toEqual([]);
    expect(d.resolved).toBe(true);
  });

  it("still resolves an IPv4-only host", async () => {
    resolve4.mockResolvedValue(["93.184.216.34"]);
    const d = await resolveDNS("v4only.example.com");
    expect(d.resolved).toBe(true);
    expect(d.ipv6).toEqual([]);
  });

  it("returns both families when a host is dual-stack", async () => {
    resolve4.mockResolvedValue(["93.184.216.34"]);
    resolve6.mockResolvedValue(["2606:2800::1"]);
    const d = await resolveDNS("dual.example.com");
    expect(d.ips).toHaveLength(1);
    expect(d.ipv6).toHaveLength(1);
    expect(d.resolved).toBe(true);
  });

  it("resolves a CNAME-only host", async () => {
    resolveCname.mockResolvedValue(["target.example.net"]);
    const d = await resolveDNS("alias.example.com");
    expect(d.resolved).toBe(true);
  });

  it("reports a non-existent name as unresolved", async () => {
    const d = await resolveDNS("nope.example.com");
    expect(d).toMatchObject({ ips: [], ipv6: [], cnames: [], resolved: false });
  });

  /**
   * `resolved` is computed in one place on purpose. Six call sites open-coded
   * `ips.length === 0 && cnames.length === 0`, which is exactly how IPv6 came to
   * be missed — and how a caller added later would inherit the wrong meaning of
   * "live" without noticing.
   */
  it("derives `resolved` from all three record types", async () => {
    resolve6.mockResolvedValue(["2606:4700::1111"]);
    const v6 = await resolveDNS("a.example.com");

    resolve6.mockImplementation(nx);
    resolveCname.mockResolvedValue(["t.example.net"]);
    const cname = await resolveDNS("b.example.com");

    resolveCname.mockImplementation(nx);
    resolve4.mockResolvedValue(["1.2.3.4"]);
    const v4 = await resolveDNS("c.example.com");

    expect([v6.resolved, cname.resolved, v4.resolved]).toEqual([true, true, true]);
  });

  /** One family failing must not discard the other's answer. */
  it("survives a partial resolver failure", async () => {
    resolve4.mockRejectedValue(new Error("ESERVFAIL"));
    resolve6.mockResolvedValue(["2606:4700::1111"]);
    const d = await resolveDNS("partial.example.com");
    expect(d.resolved).toBe(true);
    expect(d.ipv6).toHaveLength(1);
  });

  /** All three queries are issued together, so AAAA costs no extra latency. */
  it("queries all three record types concurrently", async () => {
    await resolveDNS("x.example.com");
    expect(resolve4).toHaveBeenCalledOnce();
    expect(resolve6).toHaveBeenCalledOnce();
    expect(resolveCname).toHaveBeenCalledOnce();
  });
});
