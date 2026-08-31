/**
 * SRV service discovery.
 *
 * The engine enumerated A, AAAA, CNAME, NS, MX, CAA, TXT and SOA — every record
 * type that describes the domain itself — and no SRV records, which are the
 * ones that describe its SERVICES. That is a real blind spot, because an SRV
 * record is a voluntary, public statement of "this internal service exists, and
 * here is the host and port it runs on".
 *
 * The Active Directory names are the reason this matters most. A publicly
 * resolvable `_ldap._tcp.dc._msdcs.<domain>` hands an attacker the hostname of
 * a domain controller, which is the single most useful starting point for an
 * internal compromise. These records belong on internal DNS; when they answer
 * from the public resolvers it is nearly always a split-horizon DNS mistake
 * rather than a decision anyone made.
 *
 * Every name here is one DNS query. No key, no account, no rate limit.
 */

import type { VerifiedFinding } from "./constants.js";

export interface SrvRecord {
  /** The queried name, e.g. `_sip._tls.example.com`. */
  name: string;
  /** The service label, e.g. `_sip._tls`. */
  service: string;
  priority: number;
  weight: number;
  port: number;
  /** Target host. */
  target: string;
}

export interface SrvService {
  /** Service label to probe, without the domain. */
  label: string;
  /** What the service is, for the report. */
  description: string;
  /**
   * `internal` services should never resolve publicly — their presence is a
   * finding in itself. `public` services are normal to publish and are recorded
   * as inventory.
   */
  exposure: "internal" | "public";
}

/**
 * Services worth probing, chosen for what their presence reveals rather than
 * for list length. Every `internal` entry describes infrastructure that an
 * attacker would otherwise have to guess at.
 */
export const SRV_SERVICES: readonly SrvService[] = [
  // ── Active Directory / Windows domain infrastructure ──────────────────────
  { label: "_ldap._tcp.dc._msdcs", description: "Active Directory domain controller (LDAP)", exposure: "internal" },
  { label: "_kerberos._tcp.dc._msdcs", description: "Active Directory Kerberos KDC", exposure: "internal" },
  // Bare _ldap._tcp is NOT on its own evidence of Active Directory: Google
  // publishes ldap.google.com deliberately, and calling that a leaked domain
  // controller is the kind of false positive that gets a scanner ignored. It is
  // escalated only when a genuinely AD-specific record appears alongside it.
  { label: "_ldap._tcp", description: "LDAP directory service", exposure: "public" },
  { label: "_kerberos._tcp", description: "Kerberos key distribution centre", exposure: "internal" },
  { label: "_kpasswd._tcp", description: "Kerberos password change service", exposure: "internal" },
  { label: "_gc._tcp", description: "Active Directory global catalogue", exposure: "internal" },
  { label: "_kerberos._udp", description: "Kerberos KDC (UDP)", exposure: "internal" },

  // ── Collaboration / real-time services ────────────────────────────────────
  { label: "_sip._tls", description: "SIP over TLS (VoIP signalling)", exposure: "public" },
  { label: "_sip._tcp", description: "SIP over TCP (VoIP signalling)", exposure: "public" },
  { label: "_sip._udp", description: "SIP over UDP (VoIP signalling)", exposure: "public" },
  { label: "_sipfederationtls._tcp", description: "Skype for Business / Lync federation", exposure: "public" },
  { label: "_xmpp-server._tcp", description: "XMPP server-to-server", exposure: "public" },
  { label: "_xmpp-client._tcp", description: "XMPP client connection", exposure: "public" },
  { label: "_matrix._tcp", description: "Matrix homeserver", exposure: "public" },

  // ── Mail and calendaring autodiscovery ────────────────────────────────────
  { label: "_autodiscover._tcp", description: "Exchange/Outlook autodiscover", exposure: "public" },
  { label: "_caldavs._tcp", description: "CalDAV calendar service", exposure: "public" },
  { label: "_carddavs._tcp", description: "CardDAV contacts service", exposure: "public" },
  { label: "_imaps._tcp", description: "IMAP over TLS", exposure: "public" },
  { label: "_submission._tcp", description: "SMTP mail submission", exposure: "public" },
  { label: "_pop3s._tcp", description: "POP3 over TLS", exposure: "public" },

  // ── Other infrastructure worth knowing about ──────────────────────────────
  { label: "_vpn._tcp", description: "VPN endpoint", exposure: "internal" },
  { label: "_ntp._udp", description: "Network time service", exposure: "public" },
  { label: "_ftp._tcp", description: "FTP service", exposure: "public" },
  { label: "_ssh._tcp", description: "SSH service", exposure: "internal" },
  { label: "_minecraft._tcp", description: "Minecraft server", exposure: "public" },
];

/** Resolver shape, injected so this module is testable without DNS. */
export type SrvResolver = (
  name: string,
) => Promise<Array<{ priority: number; weight: number; port: number; name: string }>>;

/**
 * Probes the known service labels against a domain.
 *
 * Queries run in bounded batches: 25 labels fired at once is enough to trip a
 * resolver's rate limit and get the whole batch dropped, which would look
 * exactly like "this domain publishes no SRV records".
 */
export async function discoverSrvRecords(
  domain: string,
  resolveSrv: SrvResolver,
  services: readonly SrvService[] = SRV_SERVICES,
  batchSize = 6,
): Promise<SrvRecord[]> {
  const found: SrvRecord[] = [];

  for (let i = 0; i < services.length; i += batchSize) {
    const batch = services.slice(i, i + batchSize);
    const results = await Promise.all(
      batch.map(async (svc) => {
        const name = `${svc.label}.${domain}`;
        try {
          const records = await resolveSrv(name);
          return { svc, name, records: Array.isArray(records) ? records : [] };
        } catch {
          // NXDOMAIN is the expected answer for most labels; it is not an error.
          return { svc, name, records: [] };
        }
      }),
    );
    for (const { svc, name, records } of results) {
      for (const r of records) {
        // A single "." target is the RFC 2782 way of saying "this service is
        // explicitly NOT available here". Recording it as a live service would
        // invent infrastructure that does not exist.
        if (!r.name || r.name === ".") continue;
        found.push({
          name,
          service: svc.label,
          priority: r.priority,
          weight: r.weight,
          port: r.port,
          target: r.name,
        });
      }
    }
  }
  return found;
}

/** Looks up the service definition for a discovered record. */
function serviceFor(label: string, services: readonly SrvService[]): SrvService | undefined {
  return services.find((s) => s.label === label);
}

/**
 * Labels that only an Active Directory deployment publishes. `_ldap._tcp` is
 * deliberately absent: a public LDAP directory is a legitimate thing to run.
 */
const AD_SPECIFIC = /_msdcs|_kerberos|_gc\._tcp|_kpasswd/;

/**
 * Findings for internal infrastructure that answers on public DNS.
 *
 * Public services (SIP, XMPP, autodiscover) are inventory, not findings — they
 * are meant to be published, and reporting them as issues would bury the
 * records that genuinely should not be there.
 */
export function buildSrvFindings(
  domain: string,
  records: SrvRecord[],
  now: string,
  services: readonly SrvService[] = SRV_SERVICES,
): VerifiedFinding[] {
  const internal = records.filter((r) => serviceFor(r.service, services)?.exposure === "internal");

  // A bare _ldap._tcp record becomes evidence of an exposed domain controller
  // only when something AD-specific corroborates it. On its own it is a public
  // directory service and belongs in inventory, not in the findings list.
  const adCorroborated = records.some((r) => AD_SPECIFIC.test(r.service));
  if (adCorroborated) {
    internal.push(...records.filter((r) => r.service === "_ldap._tcp"));
  }
  if (internal.length === 0) return [];

  // Directory-service records are the ones that name a domain controller, so
  // they are separated from the general internal set and graded higher.
  // A corroborated _ldap._tcp belongs with the directory records, not in the
  // generic internal bucket — it is naming the same domain controller.
  const directory = internal.filter((r) => AD_SPECIFIC.test(r.service) || r.service === "_ldap._tcp");
  const findings: VerifiedFinding[] = [];

  if (directory.length > 0) {
    const hosts = Array.from(new Set(directory.map((r) => r.target)));
    findings.push({
      title: `Active Directory service records exposed in public DNS for ${domain}`,
      description:
        `Public DNS for ${domain} answers queries for ${directory.length} directory-service SRV record(s), naming ` +
        `${hosts.length} internal host(s): ${hosts.join(", ")}. These records exist so that domain-joined machines can ` +
        `locate domain controllers, and they are meant to be served only by internal DNS. Answering them publicly hands ` +
        `an attacker the hostnames and ports of the domain's authentication infrastructure, which is the usual starting ` +
        `point for credential attacks such as Kerberoasting or AS-REP roasting — no access to the network is needed to ` +
        `collect it.`,
      severity: "medium",
      category: "information_disclosure",
      affectedAsset: domain,
      cvssScore: "5.3",
      remediation:
        `Serve these records from internal DNS only. If the public and internal zones are the same, split them ` +
        `(split-horizon DNS) and remove the _msdcs, _ldap, _kerberos, _gc and _kpasswd SRV records from the public zone.`,
      evidence: [
        {
          type: "dns",
          description: "SRV records answered by public resolvers",
          snippet: directory
            .map((r) => `${r.name} -> ${r.target}:${r.port} (priority ${r.priority}, weight ${r.weight})`)
            .join("\n"),
          source: "DNS",
          verifiedAt: now,
        },
      ],
    });
  }

  const other = internal.filter((r) => !directory.includes(r));
  if (other.length > 0) {
    const hosts = Array.from(new Set(other.map((r) => r.target)));
    findings.push({
      title: `Internal service records exposed in public DNS for ${domain}`,
      description:
        `Public DNS for ${domain} names ${hosts.length} host(s) running services that are normally internal: ` +
        `${other.map((r) => `${serviceFor(r.service, services)?.description ?? r.service} at ${r.target}:${r.port}`).join("; ")}. ` +
        `Each record removes guesswork from an attacker's reconnaissance by confirming both the hostname and the port.`,
      severity: "low",
      category: "information_disclosure",
      affectedAsset: domain,
      cvssScore: "3.1",
      remediation: "Remove SRV records for internal-only services from the public DNS zone.",
      evidence: [
        {
          type: "dns",
          description: "SRV records answered by public resolvers",
          snippet: other.map((r) => `${r.name} -> ${r.target}:${r.port}`).join("\n"),
          source: "DNS",
          verifiedAt: now,
        },
      ],
    });
  }

  return findings;
}

/**
 * Groups discovered records for the recon view: what services this domain
 * publishes, and which hosts they point at.
 */
export function summariseSrv(
  records: SrvRecord[],
  services: readonly SrvService[] = SRV_SERVICES,
): Array<{ service: string; description: string; exposure: string; targets: string[] }> {
  const byService = new Map<string, SrvRecord[]>();
  for (const r of records) {
    const list = byService.get(r.service) ?? [];
    list.push(r);
    byService.set(r.service, list);
  }
  return Array.from(byService.entries()).map(([service, rs]) => ({
    service,
    description: serviceFor(service, services)?.description ?? service,
    exposure: serviceFor(service, services)?.exposure ?? "public",
    targets: Array.from(new Set(rs.map((r) => `${r.target}:${r.port}`))),
  }));
}
