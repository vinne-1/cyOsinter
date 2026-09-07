import dns from "dns/promises";

/**
 * SSRF prevention for outbound requests to user-supplied or user-influenced URLs.
 *
 * ## Why resolution, not string matching
 *
 * There were two guards in this codebase and they disagreed. This one resolves
 * the hostname and inspects the ADDRESS; the other (`isSafeExternalUrl`, now
 * removed) pattern-matched the hostname text, which fails against everything
 * that matters:
 *
 *  - `evil.com` that simply resolves to `127.0.0.1` — no string check can see it
 *  - decimal, octal and hex literals: `http://2130706433/`, `http://0x7f000001/`,
 *    `http://017700000001/` are all 127.0.0.1
 *  - `127.0.0.2`, `127.1` — loopback without matching a `127.0.0.1` literal
 *  - IPv6 spellings of loopback and IPv4-mapped addresses
 *
 * Resolution collapses all of those into the same question: what address will
 * the socket actually connect to?
 *
 * ## Fail-closed
 *
 * A hostname that cannot be resolved is treated as private. A guard that lets a
 * request through when it could not check is not a guard.
 */

/** True when an IPv4 address is in a range that must never be fetched. */
export function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return true;
  const [a, b] = parts as [number, number, number, number];
  return (
    a === 0 ||                        // "this network"
    a === 127 ||                      // loopback
    a === 10 ||                       // RFC1918
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||       // link-local, incl. cloud metadata 169.254.169.254
    (a === 100 && b >= 64 && b <= 127) || // RFC6598 carrier NAT — Alibaba metadata lives at 100.100.100.200
    (a === 192 && b === 0) ||         // IETF protocol assignments
    (a === 198 && (b === 18 || b === 19)) || // benchmarking
    a >= 224                          // multicast and reserved
  );
}

/** True when an IPv6 address is loopback, link-local, unique-local, or maps to a private v4. */
export function isPrivateIpv6(ip: string): boolean {
  const addr = ip.toLowerCase().replace(/^\[|\]$/g, "").split("%")[0];
  if (addr === "::1" || addr === "::" ) return true;
  if (/^f[cd]/.test(addr)) return true;         // fc00::/7 unique-local
  if (/^fe[89ab]/.test(addr)) return true;      // fe80::/10 link-local
  if (addr.startsWith("fd00:ec2:")) return true; // AWS IMDS over IPv6
  // IPv4-mapped / IPv4-compatible: ::ffff:127.0.0.1 and friends.
  const mapped = addr.match(/(?:^|:)((?:\d{1,3}\.){3}\d{1,3})$/);
  if (mapped) return isPrivateIpv4(mapped[1]);
  return false;
}

/**
 * Returns true if the hostname resolves to a private, loopback, link-local or
 * otherwise non-routable address — i.e. the request must NOT be made.
 *
 * Both A and AAAA records are considered: a host with a public A record and a
 * loopback AAAA record would otherwise slip through whenever the runtime
 * preferred IPv6.
 */
export async function isPrivateHost(hostname: string): Promise<boolean> {
  const host = hostname.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (!host) return true;

  // A bare address needs no resolution, and resolving one would fail and be
  // treated as private — which is the right verdict for a private literal but
  // the wrong one for a public literal like 8.8.8.8.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return isPrivateIpv4(host);
  if (host.includes(":")) return isPrivateIpv6(host);

  // A non-dotted numeric host is a packed IPv4 literal — `http://2130706433/`
  // is 127.0.0.1. Node's resolver will not accept it, so it would otherwise be
  // rejected by the fail-closed path; decode it so the verdict is deliberate.
  if (/^(0x[0-9a-f]+|0[0-7]+|\d+)$/i.test(host)) {
    const n = host.startsWith("0x") ? Number.parseInt(host, 16)
      : /^0[0-7]+$/.test(host) ? Number.parseInt(host, 8)
        : Number(host);
    if (!Number.isFinite(n) || n < 0 || n > 0xffffffff) return true;
    const dotted = [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
    return isPrivateIpv4(dotted);
  }

  try {
    const [v4, v6] = await Promise.allSettled([dns.resolve4(host), dns.resolve6(host)]);
    const addrs4 = v4.status === "fulfilled" ? v4.value : [];
    const addrs6 = v6.status === "fulfilled" ? v6.value : [];
    // Nothing resolved at all — cannot verify, so refuse.
    if (addrs4.length === 0 && addrs6.length === 0) return true;
    return addrs4.some(isPrivateIpv4) || addrs6.some(isPrivateIpv6);
  } catch {
    return true; // fail-closed: if resolution fails, treat as private
  }
}

/**
 * Whether a full URL is safe to fetch: scheme is http(s), and the host does not
 * resolve anywhere private.
 *
 * Callers that follow redirects must re-check every hop — the guard applies to
 * the address a socket connects to, and a 302 chooses a new one.
 */
export async function isSafeOutboundUrl(raw: string): Promise<boolean> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return false;
  return !(await isPrivateHost(url.hostname));
}
