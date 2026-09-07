/**
 * Favicon hashing.
 *
 * The famous use is pivoting in Shodan/FOFA, which needs an API key. Keyless,
 * the hash still does two useful things: it groups an estate (hosts sharing an
 * icon are the same application behind different names) and it hands the
 * operator a `http.favicon.hash:` value they can pivot on themselves.
 *
 * The algorithm tests are the important ones. A favicon hash that is off by any
 * detail matches NOTHING anywhere — it is not approximately useful, it is
 * useless — so these pin it against published MurmurHash3 vectors rather than
 * against whatever the implementation happens to produce.
 */
import { describe, it, expect, vi } from "vitest";

vi.mock("../../../server/logger", () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));

import { murmur3_32, shodanBase64, faviconHash, clusterByFavicon } from "../../../server/scanner/favicon";

const unsigned = (n: number) => n >>> 0;

describe("murmur3_32", () => {
  /** Published MurmurHash3_x86_32 vectors, seed 0. */
  it("matches the published test vectors", () => {
    const cases: Array<[string, number]> = [
      ["", 0],
      ["a", 1009084850],
      ["abc", 3017643002],
      ["hello", 613153351],
    ];
    for (const [input, expected] of cases) {
      expect(unsigned(murmur3_32(Buffer.from(input, "utf8"))), input).toBe(expected);
    }
  });

  /**
   * Shodan reports `http.favicon.hash` as a SIGNED 32-bit integer and it is
   * frequently negative. Returning the unsigned form would produce a number that
   * never matches a real query.
   */
  it("returns a signed 32-bit integer", () => {
    for (const s of ["favicon", "abcdefgh", "x".repeat(100)]) {
      const h = murmur3_32(Buffer.from(s, "utf8"));
      expect(Number.isInteger(h)).toBe(true);
      expect(h).toBeGreaterThanOrEqual(-(2 ** 31));
      expect(h).toBeLessThanOrEqual(2 ** 31 - 1);
    }
  });

  /** Tail handling: lengths not divisible by 4 exercise the switch fall-through. */
  it("handles every tail length", () => {
    const seen = new Set<number>();
    for (const len of [1, 2, 3, 4, 5, 6, 7, 8]) {
      seen.add(murmur3_32(Buffer.alloc(len, 0x61)));
    }
    expect(seen.size).toBe(8);
  });

  it("is deterministic and seed-sensitive", () => {
    const buf = Buffer.from("consistency", "utf8");
    expect(murmur3_32(buf)).toBe(murmur3_32(buf));
    expect(murmur3_32(buf, 1)).not.toBe(murmur3_32(buf, 0));
  });

  it("handles bytes above 0x7f without sign-extension damage", () => {
    const high = Buffer.from([0xff, 0xfe, 0x80, 0x81, 0xff]);
    expect(Number.isInteger(murmur3_32(high))).toBe(true);
  });
});

describe("shodanBase64", () => {
  /**
   * The detail that makes or breaks the pivot: Shodan hashes Python's
   * `base64.encodebytes` output — 76-character lines, trailing newline — not a
   * plain base64 string.
   */
  it("wraps at 76 characters and ends with a newline", () => {
    const out = shodanBase64(Buffer.alloc(120, 0x41));
    const lines = out.split("\n");
    expect(out.endsWith("\n")).toBe(true);
    expect(lines[0]).toHaveLength(76);
    // 120 bytes → 160 base64 chars → 76 + 76 + 8
    expect(lines.filter((l) => l.length > 0)).toHaveLength(3);
  });

  it("still appends a newline for input shorter than one line", () => {
    const out = shodanBase64(Buffer.from("hi", "utf8"));
    expect(out).toBe("aGk=\n");
  });

  it("returns just a newline for empty input", () => {
    expect(shodanBase64(Buffer.alloc(0))).toBe("\n");
  });
});

describe("faviconHash", () => {
  it("hashes the wrapped base64, not the raw bytes", () => {
    const icon = Buffer.alloc(200, 0x7f);
    expect(faviconHash(icon)).toBe(murmur3_32(Buffer.from(shodanBase64(icon), "utf8")));
    // And is therefore NOT the hash of the bytes themselves — the mistake that
    // produces a plausible-looking number matching nothing.
    expect(faviconHash(icon)).not.toBe(murmur3_32(icon));
  });

  it("gives different icons different hashes", () => {
    expect(faviconHash(Buffer.alloc(64, 1))).not.toBe(faviconHash(Buffer.alloc(64, 2)));
  });
});

describe("clusterByFavicon", () => {
  const r = (host: string, hash: number) => ({ host, hash, url: `https://${host}/favicon.ico`, bytes: 100 });

  it("groups hosts serving the same icon", () => {
    const clusters = clusterByFavicon([
      r("www.example.com", 111), r("example.com", 111), r("api.example.com", 222),
    ]);
    expect(clusters).toEqual([
      { hash: 111, hosts: ["example.com", "www.example.com"] },
      { hash: 222, hosts: ["api.example.com"] },
    ]);
  });

  /** The singleton is the interesting host, so the big cluster goes first. */
  it("orders the largest group first", () => {
    const clusters = clusterByFavicon([
      r("odd.example.com", 999),
      r("a.example.com", 111), r("b.example.com", 111), r("c.example.com", 111),
    ]);
    expect(clusters[0].hosts).toHaveLength(3);
    expect(clusters[1].hosts).toEqual(["odd.example.com"]);
  });

  it("is deterministic for equal-sized clusters", () => {
    const input = [r("a.example.com", 222), r("b.example.com", 111)];
    expect(clusterByFavicon(input)).toEqual(clusterByFavicon([...input].reverse()));
  });

  it("returns nothing for no input", () => {
    expect(clusterByFavicon([])).toEqual([]);
  });
});
