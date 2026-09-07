import tls from "tls";

/**
 * Hostnames a certificate vouches for, restricted to the domain being scanned.
 *
 * A certificate's SAN list is the organisation's OWN statement about which names
 * it serves — stronger evidence than a wordlist guess and more current than a CT
 * index, because it is read from the live handshake rather than from a log of
 * what was once issued. The names were already being extracted and were used
 * only for display; feeding them back into discovery costs no extra traffic.
 *
 * Two filters matter:
 *  - **Wildcards are dropped.** `*.example.com` is not a host; resolving it is
 *    meaningless and adding it to an inventory asserts an asset that does not
 *    exist. What a wildcard tells you is that unknown siblings exist — which is
 *    what the permutation stage is for.
 *  - **Out-of-scope names are dropped.** A shared or multi-domain certificate
 *    routinely covers unrelated domains, and attributing somebody else's
 *    hostname to this target is the same attribution error `asn-expansion`
 *    refuses by default.
 */
export function inScopeSans(altNames: string[], domain: string): string[] {
  const apex = domain.trim().toLowerCase().replace(/\.$/, "");
  const out = new Set<string>();

  for (const raw of altNames) {
    const name = raw.trim().toLowerCase().replace(/^dns:/, "").replace(/\.$/, "");
    if (!name || name.includes("*")) continue;
    if (name !== apex && !name.endsWith(`.${apex}`)) continue;
    // Must still look like a hostname: a malformed SAN is not an asset.
    if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(name)) continue;
    out.add(name);
  }

  return Array.from(out).sort();
}

export async function getCertificateInfo(hostname: string, port = 443): Promise<{
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  serialNumber: string;
  altNames: string[];
  protocol: string;
} | null> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => { resolve(null); }, 8000);
    try {
      const socket = tls.connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false }, () => {
        try {
          const cert = socket.getPeerCertificate();
          const protocol = socket.getProtocol() || "unknown";
          if (!cert || !cert.valid_from) {
            socket.destroy();
            clearTimeout(timer);
            resolve(null);
            return;
          }
          const validTo = new Date(cert.valid_to);
          const now = new Date();
          const daysRemaining = Math.floor((validTo.getTime() - now.getTime()) / 86400000);
          const altNames = cert.subjectaltname
            ? cert.subjectaltname.split(", ").map((s: string) => s.replace("DNS:", ""))
            : [];
          socket.destroy();
          clearTimeout(timer);
          resolve({
            subject: typeof cert.subject === "object" ? (cert.subject as any).CN || JSON.stringify(cert.subject) : String(cert.subject),
            issuer: typeof cert.issuer === "object" ? ((cert.issuer as any).O || (cert.issuer as any).CN || JSON.stringify(cert.issuer)) : String(cert.issuer),
            validFrom: cert.valid_from,
            validTo: cert.valid_to,
            daysRemaining,
            serialNumber: cert.serialNumber || "",
            altNames,
            protocol,
          });
        } catch {
          socket.destroy();
          clearTimeout(timer);
          resolve(null);
        }
      });
      socket.on("error", () => { clearTimeout(timer); resolve(null); });
    } catch {
      clearTimeout(timer);
      resolve(null);
    }
  });
}
