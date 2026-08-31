/**
 * DNS zone transfer (AXFR) check.
 *
 * A nameserver that answers AXFR to anyone hands over the entire zone in one
 * request: every hostname, every internal service, every staging and admin
 * record the organisation has. It is the single highest-yield DNS
 * misconfiguration there is, it needs no credentials, and the engine had no
 * check for it — subdomain enumeration was left to guess at names that a
 * misconfigured server would simply have listed.
 *
 * Node's resolver cannot ask for AXFR, so this speaks DNS on the wire: AXFR is
 * TCP-only (RFC 5936), with a two-byte length prefix ahead of each message.
 *
 * ── Scope ───────────────────────────────────────────────────────────────────
 * This sends one standard, read-only DNS query per nameserver. It changes
 * nothing, and a correctly configured server answers REFUSED in a few bytes.
 * The response is capped and the socket is closed as soon as the question is
 * answered — proving the transfer is allowed needs the first records, not the
 * whole zone, and downloading a large zone would be rude as well as pointless.
 */

import net from "node:net";
import type { VerifiedFinding } from "./constants.js";

const TYPE_AXFR = 252;
const CLASS_IN = 1;

/** Stop reading once we have enough to answer the question. */
const MAX_RESPONSE_BYTES = 64 * 1024;
// 5s: long enough for a distant authoritative server, short enough that a
// handful of silently-dropped connections does not dominate the scan.
const DEFAULT_TIMEOUT_MS = 5000;

export interface ZoneTransferResult {
  nameserver: string;
  /** The server answered with zone data. */
  transferred: boolean;
  /** Record owner names recovered from the response. */
  records: string[];
  /** Total records the response claimed, which may exceed `records.length`. */
  recordCount: number;
  /** Why the attempt ended, for evidence. */
  detail: string;
}

/** Encodes a domain as DNS labels. */
export function encodeName(domain: string): Buffer {
  const parts: Buffer[] = [];
  for (const label of domain.split(".").filter(Boolean)) {
    const bytes = Buffer.from(label, "ascii");
    // A label is length-prefixed with a single byte, so 63 is the hard ceiling.
    if (bytes.length > 63) throw new Error(`DNS label too long: ${label}`);
    parts.push(Buffer.from([bytes.length]), bytes);
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

/** Builds an AXFR query message (without the TCP length prefix). */
export function buildAxfrQuery(domain: string, id = 0x1234): Buffer {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  // Flags: standard query, recursion NOT desired — AXFR is answered by the
  // authoritative server itself and asking for recursion is meaningless.
  header.writeUInt16BE(0x0000, 2);
  header.writeUInt16BE(1, 4); // QDCOUNT
  const question = Buffer.concat([encodeName(domain), Buffer.alloc(4)]);
  question.writeUInt16BE(TYPE_AXFR, question.length - 4);
  question.writeUInt16BE(CLASS_IN, question.length - 2);
  return Buffer.concat([header, question]);
}

/**
 * Reads a (possibly compressed) DNS name.
 *
 * Returns the name and the offset just past it. A compression pointer is
 * followed for the name's value but never advances the cursor past the two
 * pointer bytes — and a pointer that does not move strictly backwards is
 * rejected, because a self- or forward-referencing pointer is how a malicious
 * response turns a parser into an infinite loop.
 */
export function readName(buf: Buffer, offset: number): { name: string; next: number } {
  const labels: string[] = [];
  let cursor = offset;
  let next = -1;
  let hops = 0;

  while (cursor < buf.length) {
    const len = buf[cursor];
    if (len === 0) {
      cursor += 1;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      if (cursor + 1 >= buf.length) break;
      const pointer = ((len & 0x3f) << 8) | buf[cursor + 1];
      if (next === -1) next = cursor + 2;
      // Must point backwards, and a bounded number of times.
      if (pointer >= cursor || ++hops > 32) break;
      cursor = pointer;
      continue;
    }
    if (cursor + 1 + len > buf.length) break;
    labels.push(buf.toString("ascii", cursor + 1, cursor + 1 + len));
    cursor += 1 + len;
  }

  return { name: labels.join("."), next: next === -1 ? cursor : next };
}

/**
 * Parses record owner names out of an AXFR response.
 *
 * Only the names are extracted. The value of this check is "the zone is
 * readable, and here is proof" — reproducing every RDATA type would be a DNS
 * library, not a security check.
 */
export function parseAxfrResponse(buf: Buffer): { rcode: number; answers: number; names: string[] } {
  if (buf.length < 12) return { rcode: -1, answers: 0, names: [] };

  const rcode = buf.readUInt16BE(2) & 0x0f;
  const qdcount = buf.readUInt16BE(4);
  const ancount = buf.readUInt16BE(6);

  let offset = 12;
  for (let i = 0; i < qdcount && offset < buf.length; i += 1) {
    offset = readName(buf, offset).next + 4; // + QTYPE + QCLASS
  }

  const names: string[] = [];
  for (let i = 0; i < ancount && offset < buf.length; i += 1) {
    const { name, next } = readName(buf, offset);
    offset = next;
    if (offset + 10 > buf.length) break;
    const rdlength = buf.readUInt16BE(offset + 8);
    offset += 10 + rdlength;
    if (name) names.push(name);
  }

  return { rcode, answers: ancount, names };
}

/** Attempts a zone transfer from one nameserver. */
export function attemptZoneTransfer(
  domain: string,
  nameserver: string,
  timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<ZoneTransferResult> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;

    const finish = (result: Omit<ZoneTransferResult, "nameserver">) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ nameserver, ...result });
    };

    const socket = net.createConnection({ host: nameserver, port: 53 });
    socket.setTimeout(timeoutMs);

    socket.on("connect", () => {
      const query = buildAxfrQuery(domain);
      const framed = Buffer.alloc(2 + query.length);
      framed.writeUInt16BE(query.length, 0);
      query.copy(framed, 2);
      socket.write(framed);
    });

    socket.on("data", (chunk) => {
      chunks.push(chunk);
      total += chunk.length;

      const buf = Buffer.concat(chunks);
      // Wait for a complete first message before parsing.
      if (buf.length < 2) return;
      const declared = buf.readUInt16BE(0);
      if (buf.length < 2 + declared && total < MAX_RESPONSE_BYTES) return;

      const message = buf.subarray(2, Math.min(2 + declared, buf.length));
      const { rcode, answers, names } = parseAxfrResponse(message);

      if (rcode !== 0) {
        // 5 = REFUSED, 9 = NOTAUTH. Both are a correctly configured server.
        finish({
          transferred: false,
          records: [],
          recordCount: 0,
          detail: `Server responded with DNS rcode ${rcode}${rcode === 5 ? " (REFUSED)" : rcode === 9 ? " (NOTAUTH)" : ""}`,
        });
        return;
      }

      // A single answer is the SOA that opens a transfer and, on its own, is
      // not proof the zone followed. More than one record means it did.
      if (answers > 1) {
        finish({
          transferred: true,
          records: Array.from(new Set(names)).slice(0, 200),
          recordCount: answers,
          detail: `Server transferred the zone: ${answers} record(s) in the first message`,
        });
        return;
      }

      if (total >= MAX_RESPONSE_BYTES) {
        finish({
          transferred: true,
          records: Array.from(new Set(names)).slice(0, 200),
          recordCount: answers,
          detail: "Server began transferring the zone (response truncated by the scanner)",
        });
      }
    });

    socket.on("timeout", () =>
      finish({ transferred: false, records: [], recordCount: 0, detail: "Connection timed out" }),
    );
    socket.on("error", (err) =>
      finish({ transferred: false, records: [], recordCount: 0, detail: `Connection failed: ${err.message}` }),
    );
    socket.on("end", () => {
      const buf = Buffer.concat(chunks);
      if (buf.length < 3) {
        finish({ transferred: false, records: [], recordCount: 0, detail: "Server closed the connection without answering" });
        return;
      }
      const message = buf.subarray(2, 2 + buf.readUInt16BE(0));
      const { rcode, answers, names } = parseAxfrResponse(message);
      finish({
        transferred: rcode === 0 && answers > 1,
        records: Array.from(new Set(names)).slice(0, 200),
        recordCount: answers,
        detail: rcode === 0 ? `Transfer closed after ${answers} record(s)` : `DNS rcode ${rcode}`,
      });
    });
  });
}

/** Tries every nameserver; one permissive server is enough to expose the zone. */
export async function checkZoneTransfer(
  domain: string,
  nameservers: string[],
  attempt = attemptZoneTransfer,
): Promise<ZoneTransferResult[]> {
  const unique = Array.from(new Set(nameservers.map((n) => n.replace(/\.$/, "")))).filter(Boolean);
  const targets = unique.slice(0, 8);

  // Every nameserver is tried, not just the first: the classic form of this
  // misconfiguration is one secondary that was set up differently from the
  // rest, and stopping at the first refusal would miss exactly that.
  //
  // Three at a time. Fully sequential measured 12.6s against google.com alone,
  // because a server that silently drops the connection costs the whole
  // timeout; firing all eight at once at someone's authoritative servers reads
  // as an attack rather than an assessment.
  const results: ZoneTransferResult[] = [];
  for (let i = 0; i < targets.length; i += 3) {
    results.push(...(await Promise.all(targets.slice(i, i + 3).map((ns) => attempt(domain, ns)))));
  }
  return results;
}

/** One finding per permissive nameserver's zone, not per nameserver. */
export function buildZoneTransferFindings(
  domain: string,
  results: ZoneTransferResult[],
  now: string,
): VerifiedFinding[] {
  const open = results.filter((r) => r.transferred);
  if (open.length === 0) return [];

  const names = Array.from(new Set(open.flatMap((r) => r.records)));
  const servers = open.map((r) => r.nameserver);

  return [
    {
      title: `DNS zone transfer allowed for ${domain}`,
      description:
        `${servers.length} of ${results.length} authoritative nameserver(s) for ${domain} answered an AXFR request from ` +
        `an unauthorised client: ${servers.join(", ")}. A zone transfer returns the complete contents of the DNS zone, so ` +
        `every hostname the organisation has published internally — staging environments, admin interfaces, VPN endpoints, ` +
        `internal tooling — is handed over in a single request, with no credentials and nothing to brute-force. This ` +
        `removes the reconnaissance step from an attack entirely.` +
        (names.length ? ` ${names.length} record name(s) were recovered as proof.` : ""),
      severity: "high",
      category: "dns_misconfiguration",
      affectedAsset: domain,
      cvssScore: "7.5",
      remediation:
        `Restrict AXFR on ${servers.join(", ")} to the secondary nameservers that legitimately need it. In BIND use ` +
        `allow-transfer with an explicit ACL (and TSIG keys where possible); most managed DNS providers disable zone ` +
        `transfer by default and expose it as a per-zone setting.`,
      evidence: [
        {
          type: "dns",
          description: "AXFR request accepted by an authoritative nameserver",
          snippet:
            open
              .map((r) => `${r.nameserver}: ${r.detail}`)
              .join("\n") +
            (names.length ? `\n\nRecovered names (first ${Math.min(names.length, 25)}):\n${names.slice(0, 25).join("\n")}` : ""),
          source: "DNS AXFR (TCP/53)",
          verifiedAt: now,
        },
      ],
    },
  ];
}
