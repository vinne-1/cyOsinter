/**
 * Favicon hashing (MurmurHash3), for grouping an estate and for pivoting.
 *
 * ## What this is for here
 *
 * The famous use of a favicon hash is pivoting in Shodan or FOFA: given a hash,
 * ask "every IP on the internet serving this icon". That needs an API key, so it
 * is not what this module does. Two things it CAN do with no key at all:
 *
 *  - **Group the estate.** Ninety discovered subdomains are rarely ninety
 *    applications. Hosts sharing a favicon are almost always the same app behind
 *    different names, and the host whose icon matches nothing else is the one
 *    worth opening first. That is triage information the inventory did not have.
 *  - **Hand the operator a pivot they can use.** The hash is emitted in the
 *    Shodan-compatible form, so an operator with a Shodan account can paste
 *    `http.favicon.hash:<n>` and find infrastructure this scan never touched.
 *    Computing it costs one request; withholding it because we cannot do the
 *    pivot ourselves would be withholding the cheap half of a useful technique.
 *
 * **No product is named from a hash.** There are public lists mapping favicon
 * hashes to products, but this module does not embed one: asserting "this is a
 * Jenkins instance" from an unverified table is exactly the kind of claim the
 * body-signature gates exist to prevent. The hash is reported as an identifier,
 * which is what it is.
 *
 * ## The detail that is easy to get wrong
 *
 * Shodan hashes the **base64 encoding** of the icon, not its bytes — and
 * specifically Python's `base64.encodebytes`, which inserts a newline every 76
 * characters and appends a trailing newline. Hashing the raw bytes, or a
 * newline-free base64, produces a number that matches nothing anywhere. That
 * single detail is the difference between a usable pivot and a plausible-looking
 * dead end.
 */

import { createLogger } from "../logger.js";
import { httpGetBuffer } from "./http.js";

const log = createLogger("favicon");

/** Icons larger than this are not favicons; refuse rather than hash a page. */
const MAX_FAVICON_BYTES = 1024 * 1024;

/**
 * MurmurHash3 x86 32-bit, returned SIGNED.
 *
 * Signed because that is how Shodan reports and indexes it: `http.favicon.hash`
 * is frequently negative, and returning the unsigned form would produce a value
 * that never matches a real query.
 */
export function murmur3_32(data: Buffer, seed = 0): number {
  const c1 = 0xcc9e2d51;
  const c2 = 0x1b873593;
  const len = data.length;
  const nblocks = len >>> 2;

  let h1 = seed | 0;

  // Math.imul is required: `*` on two 32-bit values overflows into a float and
  // silently loses the low bits, which is the classic way this hash is written
  // wrong in JavaScript.
  const rotl = (x: number, r: number) => (x << r) | (x >>> (32 - r));

  for (let i = 0; i < nblocks; i++) {
    let k1 = data.readInt32LE(i * 4);
    k1 = Math.imul(k1, c1);
    k1 = rotl(k1, 15);
    k1 = Math.imul(k1, c2);

    h1 ^= k1;
    h1 = rotl(h1, 13);
    h1 = (Math.imul(h1, 5) + 0xe6546b64) | 0;
  }

  // Tail: the 0–3 bytes that did not fill a block.
  let k1 = 0;
  const tail = nblocks * 4;
  switch (len & 3) {
    case 3:
      k1 ^= data[tail + 2] << 16;
    // falls through
    case 2:
      k1 ^= data[tail + 1] << 8;
    // falls through
    case 1:
      k1 ^= data[tail];
      k1 = Math.imul(k1, c1);
      k1 = rotl(k1, 15);
      k1 = Math.imul(k1, c2);
      h1 ^= k1;
  }

  // Finalisation mix.
  h1 ^= len;
  h1 ^= h1 >>> 16;
  h1 = Math.imul(h1, 0x85ebca6b);
  h1 ^= h1 >>> 13;
  h1 = Math.imul(h1, 0xc2b2ae35);
  h1 ^= h1 >>> 16;

  return h1 | 0;
}

/**
 * Base64 in the form Shodan hashes: MIME-style, 76-character lines, trailing
 * newline. This mirrors Python's `base64.encodebytes`, which is what Shodan's
 * own tooling uses.
 */
export function shodanBase64(data: Buffer): string {
  const b64 = data.toString("base64");
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 76) lines.push(b64.slice(i, i + 76));
  return lines.join("\n") + "\n";
}

/** The Shodan-compatible `http.favicon.hash` value for an icon's bytes. */
export function faviconHash(data: Buffer): number {
  return murmur3_32(Buffer.from(shodanBase64(data), "utf8"));
}

export interface FaviconResult {
  host: string;
  url: string;
  hash: number;
  bytes: number;
}

/**
 * Fetches a host's favicon and hashes it. Null when there is no usable icon.
 *
 * Only `/favicon.ico` is tried. Parsing `<link rel="icon">` would find more, but
 * it costs a page fetch per host and the pivot value comes from the conventional
 * path that scanning engines index anyway.
 */
export async function fetchFaviconHash(host: string): Promise<FaviconResult | null> {
  const url = `https://${host}/favicon.ico`;
  try {
    const res = await httpGetBuffer(url);
    if (!res || res.status !== 200 || res.body.length === 0) return null;
    if (res.body.length > MAX_FAVICON_BYTES) return null;

    // A soft-404 commonly answers this path with the HTML app shell. An icon is
    // not markup, so this is a cheap, decisive check — the same "is it actually
    // the artefact?" rule the body signatures apply.
    const head = res.body.subarray(0, 512).toString("latin1").trimStart().toLowerCase();
    if (head.startsWith("<!doctype") || head.startsWith("<html") || head.startsWith("<?xml")) return null;

    return { host, url, hash: faviconHash(res.body), bytes: res.body.length };
  } catch (err) {
    log.debug({ err, host }, "favicon fetch failed");
    return null;
  }
}

export interface FaviconCluster {
  hash: number;
  hosts: string[];
}

/**
 * Groups hosts by the icon they serve.
 *
 * Sorted with the largest group first, and singletons last: a host whose icon
 * nothing else shares is the interesting one, and putting the big homogeneous
 * cluster first makes that visible at a glance rather than buried.
 */
export function clusterByFavicon(results: FaviconResult[]): FaviconCluster[] {
  const byHash = new Map<number, string[]>();
  for (const r of results) {
    const list = byHash.get(r.hash) ?? [];
    list.push(r.host);
    byHash.set(r.hash, list);
  }
  return Array.from(byHash.entries())
    .map(([hash, hosts]) => ({ hash, hosts: hosts.sort() }))
    .sort((a, b) => b.hosts.length - a.hosts.length || a.hash - b.hash);
}
