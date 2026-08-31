import { describe, it, expect, vi } from "vitest";
import {
  encodeName,
  buildAxfrQuery,
  readName,
  parseAxfrResponse,
  checkZoneTransfer,
  buildZoneTransferFindings,
  type ZoneTransferResult,
} from "../../../server/scanner/zone-transfer";

const NOW = "2026-09-01T00:00:00.000Z";

/** Builds a DNS response message for tests. */
function response({
  rcode = 0,
  question = "example.com",
  answers = [] as string[],
}): Buffer {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x1234, 0);
  header.writeUInt16BE(0x8000 | rcode, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(answers.length, 6);

  const q = Buffer.concat([encodeName(question), Buffer.alloc(4)]);
  q.writeUInt16BE(252, q.length - 4);
  q.writeUInt16BE(1, q.length - 2);

  const rrs = answers.map((name) => {
    const n = encodeName(name);
    const fixed = Buffer.alloc(10);
    fixed.writeUInt16BE(1, 0); // TYPE A
    fixed.writeUInt16BE(1, 2); // CLASS IN
    fixed.writeUInt32BE(300, 4); // TTL
    fixed.writeUInt16BE(4, 8); // RDLENGTH
    return Buffer.concat([n, fixed, Buffer.from([1, 2, 3, 4])]);
  });

  return Buffer.concat([header, q, ...rrs]);
}

describe("encodeName", () => {
  it("length-prefixes each label and terminates with a zero byte", () => {
    expect([...encodeName("a.bc")]).toEqual([1, 0x61, 2, 0x62, 0x63, 0]);
  });

  it("ignores a trailing dot", () => {
    expect(encodeName("example.com.")).toEqual(encodeName("example.com"));
  });

  it("rejects a label over the 63-byte protocol limit", () => {
    // The length is a single byte, so a longer label cannot be represented and
    // would silently corrupt the query.
    expect(() => encodeName(`${"a".repeat(64)}.com`)).toThrow(/label too long/i);
  });
});

describe("buildAxfrQuery", () => {
  it("asks for AXFR in class IN", () => {
    const q = buildAxfrQuery("example.com");
    expect(q.readUInt16BE(q.length - 4)).toBe(252);
    expect(q.readUInt16BE(q.length - 2)).toBe(1);
  });

  it("declares exactly one question", () => {
    expect(buildAxfrQuery("example.com").readUInt16BE(4)).toBe(1);
  });

  it("does not request recursion", () => {
    // AXFR is answered by the authoritative server itself; asking for recursion
    // is meaningless and some servers reject the query outright.
    expect(buildAxfrQuery("example.com").readUInt16BE(2) & 0x0100).toBe(0);
  });
});

describe("readName", () => {
  it("reads an uncompressed name", () => {
    const buf = encodeName("www.example.com");
    expect(readName(buf, 0).name).toBe("www.example.com");
  });

  it("follows a backward compression pointer", () => {
    const base = encodeName("example.com");
    const buf = Buffer.concat([base, Buffer.from([0xc0, 0x00])]);
    const r = readName(buf, base.length);
    expect(r.name).toBe("example.com");
    // The cursor advances past the two pointer bytes, not to where it pointed.
    expect(r.next).toBe(base.length + 2);
  });

  it("refuses a pointer that does not move backwards", () => {
    // A self-referencing pointer is how a hostile response turns a name parser
    // into an infinite loop. It must terminate, not hang.
    const buf = Buffer.from([0xc0, 0x00]);
    expect(() => readName(buf, 0)).not.toThrow();
    expect(readName(buf, 0).next).toBe(2);
  });

  it("stops at the end of a truncated buffer", () => {
    // Claims a 9-byte label with only 3 bytes present.
    const buf = Buffer.from([9, 0x61, 0x62]);
    expect(() => readName(buf, 0)).not.toThrow();
  });
});

describe("parseAxfrResponse", () => {
  it("reads the rcode of a refusal", () => {
    const r = parseAxfrResponse(response({ rcode: 5 }));
    expect(r.rcode).toBe(5);
    expect(r.answers).toBe(0);
  });

  it("extracts record names from a successful transfer", () => {
    const r = parseAxfrResponse(
      response({ answers: ["example.com", "www.example.com", "vpn.example.com"] }),
    );
    expect(r.rcode).toBe(0);
    expect(r.answers).toBe(3);
    expect(r.names).toEqual(["example.com", "www.example.com", "vpn.example.com"]);
  });

  it("returns an empty result for a runt message rather than throwing", () => {
    expect(parseAxfrResponse(Buffer.from([1, 2, 3]))).toEqual({ rcode: -1, answers: 0, names: [] });
  });

  it("stops cleanly when the record count overstates the data present", () => {
    // A hostile or truncated response can claim 500 answers and send two.
    const buf = response({ answers: ["a.example.com"] });
    buf.writeUInt16BE(500, 6);
    expect(() => parseAxfrResponse(buf)).not.toThrow();
    expect(parseAxfrResponse(buf).names).toEqual(["a.example.com"]);
  });
});

describe("checkZoneTransfer", () => {
  it("tries every distinct nameserver", async () => {
    const attempt = vi.fn(async (_d: string, ns: string) => ({
      nameserver: ns, transferred: false, records: [], recordCount: 0, detail: "refused",
    }));
    await checkZoneTransfer("example.com", ["ns1.example.com", "ns2.example.com"], attempt);
    expect(attempt).toHaveBeenCalledTimes(2);
  });

  it("normalises the trailing dot NS records carry and dedups", async () => {
    // resolveNs returns "ns1.example.com." — treating that as a different host
    // would double every attempt.
    const seen: string[] = [];
    const attempt = vi.fn(async (_d: string, ns: string) => {
      seen.push(ns);
      return { nameserver: ns, transferred: false, records: [], recordCount: 0, detail: "refused" };
    });
    await checkZoneTransfer("example.com", ["ns1.example.com.", "ns1.example.com"], attempt);
    expect(seen).toEqual(["ns1.example.com"]);
  });

  it("caps the number of servers contacted", async () => {
    const attempt = vi.fn(async (_d: string, ns: string) => ({
      nameserver: ns, transferred: false, records: [], recordCount: 0, detail: "refused",
    }));
    const many = Array.from({ length: 20 }, (_, i) => `ns${i}.example.com`);
    await checkZoneTransfer("example.com", many, attempt);
    expect(attempt.mock.calls.length).toBeLessThanOrEqual(8);
  });
});

describe("buildZoneTransferFindings", () => {
  const refused = (ns: string): ZoneTransferResult => ({
    nameserver: ns, transferred: false, records: [], recordCount: 0, detail: "DNS rcode 5 (REFUSED)",
  });
  const open = (ns: string): ZoneTransferResult => ({
    nameserver: ns,
    transferred: true,
    records: ["example.com", "vpn.example.com", "staging.example.com"],
    recordCount: 3,
    detail: "Server transferred the zone: 3 record(s) in the first message",
  });

  it("reports nothing when every nameserver refuses", () => {
    expect(buildZoneTransferFindings("example.com", [refused("ns1"), refused("ns2")], NOW)).toEqual([]);
  });

  it("reports nothing when no nameserver was reachable", () => {
    expect(buildZoneTransferFindings("example.com", [], NOW)).toEqual([]);
  });

  it("raises one high-severity finding, not one per server", () => {
    // The zone is exposed once. Two findings for the same exposed zone is noise
    // that makes the report look padded.
    const f = buildZoneTransferFindings("example.com", [open("ns1"), open("ns2"), refused("ns3")], NOW);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("high");
    expect(f[0].category).toBe("dns_misconfiguration");
  });

  it("names which servers were permissive and how many were not", () => {
    const f = buildZoneTransferFindings("example.com", [open("ns1"), refused("ns2")], NOW);
    expect(f[0].description).toMatch(/1 of 2 authoritative nameserver/);
    expect(f[0].description).toContain("ns1");
  });

  it("includes recovered names as proof", () => {
    const f = buildZoneTransferFindings("example.com", [open("ns1")], NOW);
    expect(f[0].evidence?.[0].snippet).toMatch(/vpn\.example\.com/);
    expect(f[0].evidence?.[0].snippet).toMatch(/staging\.example\.com/);
  });

  it("gives a remediation naming the actual setting to change", () => {
    const f = buildZoneTransferFindings("example.com", [open("ns1")], NOW);
    expect(f[0].remediation).toMatch(/allow-transfer/);
    expect(f[0].remediation).toContain("ns1");
  });

  it("explains why this matters rather than just naming the misconfiguration", () => {
    const f = buildZoneTransferFindings("example.com", [open("ns1")], NOW);
    expect(f[0].description).toMatch(/removes the reconnaissance step/i);
  });
});
