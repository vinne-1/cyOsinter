import dns from "dns/promises";

/**
 * Returns true if the hostname resolves to a private/loopback IP address.
 * Used as SSRF prevention before making outbound HTTP requests to user-supplied URLs.
 * Fail-closed: if DNS resolution fails for any reason, the host is treated as private.
 */
export async function isPrivateHost(hostname: string): Promise<boolean> {
  try {
    const addrs = await dns.resolve4(hostname);
    return addrs.some((ip) => {
      const parts = ip.split(".").map(Number);
      return (
        parts[0] === 127 ||
        parts[0] === 10 ||
        (parts[0] === 172 && parts[1]! >= 16 && parts[1]! <= 31) ||
        (parts[0] === 192 && parts[1] === 168) ||
        (parts[0] === 169 && parts[1] === 254) ||
        parts[0] === 0
      );
    });
  } catch {
    return true; // fail-closed: if DNS resolution fails, treat as private
  }
}
