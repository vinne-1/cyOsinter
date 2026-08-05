import type { VerifiedFinding } from "./types.js";

/**
 * Turns open-port + banner data into report-grade findings that generic port
 * enumeration does not: Internet-exposed database services (elevated to HIGH)
 * and outdated-software advisories parsed from service banners. Pure function —
 * no network — so it is deterministic and unit-testable.
 */

export interface OpenPortInfo {
  port: number;
  service?: string;
  banner?: string;
}

/** Database / data-store ports that should never be Internet-facing. */
const DB_PORTS: Record<number, string> = {
  1433: "Microsoft SQL Server",
  1521: "Oracle DB",
  3306: "MySQL/MariaDB",
  5432: "PostgreSQL",
  5984: "CouchDB",
  6379: "Redis",
  9042: "Cassandra",
  9200: "Elasticsearch",
  11211: "Memcached",
  27017: "MongoDB",
};

export function assessServiceExposure(ip: string, ports: OpenPortInfo[]): VerifiedFinding[] {
  const findings: VerifiedFinding[] = [];
  const now = new Date().toISOString();

  for (const p of ports) {
    const svc = DB_PORTS[p.port];
    if (!svc) continue;
    const banner = (p.banner ?? "").trim();
    const hasBanner = banner.length > 0;
    findings.push({
      title: `Internet-Exposed Database Service: ${svc} (port ${p.port}) on ${ip}`,
      description:
        `TCP port ${p.port} (${svc}) is reachable from the public Internet` +
        (hasBanner ? ` and returns a service banner: "${banner.slice(0, 120)}"` : "") +
        `. Database and data-store services must never be Internet-facing; they should be bound to localhost or the private ` +
        `application network. Direct exposure invites remote authentication brute-force, protocol-level exploits, and data theft.`,
      severity: "high",
      category: "network_exposure",
      affectedAsset: `${ip}:${p.port}`,
      cvssScore: "7.5",
      remediation:
        `Bind ${svc} to 127.0.0.1 or the private network and firewall port ${p.port} from the Internet. If remote access is genuinely ` +
        `required, restrict it to specific source IPs over TLS/VPN, and ensure no other tenant on shared hosting can reach the instance.`,
      evidence: [{
        type: "db_exposure",
        description: "Internet-exposed database/data-store port",
        snippet: `${ip}:${p.port} ${svc}${hasBanner ? ` — ${banner.slice(0, 160)}` : ""}`,
        source: "TCP port scan + banner grab",
        verifiedAt: now,
      }],
    });
  }

  // Outdated-software advisories from banners.
  for (const p of ports) {
    const banner = p.banner ?? "";
    const ssh = banner.match(/OpenSSH[_ ]([0-9]+)\.([0-9]+)/i);
    if (ssh) {
      const major = Number(ssh[1]);
      const minor = Number(ssh[2]);
      if (major < 8) {
        findings.push({
          title: `Outdated SSH Server (OpenSSH ${ssh[1]}.${ssh[2]}) on ${ip}`,
          description:
            `The SSH service on port ${p.port} reports OpenSSH ${ssh[1]}.${ssh[2]}, an outdated release (pre-8.0) affected by multiple ` +
            `known CVEs, including username enumeration. Outdated remote-access software is a favoured target for attackers.`,
          severity: "medium",
          category: "outdated_software",
          affectedAsset: `${ip}:${p.port}`,
          cvssScore: "5.3",
          remediation:
            "Upgrade OpenSSH to a current, supported version; disable password authentication in favour of keys; restrict SSH to trusted IPs.",
          evidence: [{
            type: "banner",
            description: "SSH version banner",
            snippet: banner.slice(0, 120),
            source: "TCP port scan + banner grab",
            verifiedAt: now,
          }],
        });
      }
    }
  }

  return findings;
}
