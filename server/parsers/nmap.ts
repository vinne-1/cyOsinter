/**
 * Nmap output parser for -oN (normal/text) and -oX (XML) formats.
 */

import { XMLParser } from "fast-xml-parser";

export interface ParsedHost {
  address: string;
  hostname?: string;
  ports: Array<{
    port: number;
    protocol: string;
    state: string;
    service?: string;
    version?: string;
  }>;
}

export interface ParsedNmap {
  hosts: ParsedHost[];
  rawSummary?: string;
}

function parseNmapNormal(text: string): ParsedNmap {
  const hosts: ParsedHost[] = [];
  const lines = text.split(/\r?\n/);
  let currentHost: ParsedHost | null = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const reportMatch = line.match(/Nmap scan report for (?:([^(]+)\s+\()?([^)\s]+)\)?/);
    if (reportMatch) {
      if (currentHost && currentHost.ports.length > 0) {
        hosts.push(currentHost);
      }
      const hostname = reportMatch[1]?.trim();
      const address = reportMatch[2].trim();
      currentHost = { address, hostname, ports: [] };
      continue;
    }

    const portMatch = line.match(/^(\d+)\/(tcp|udp)\s+(\w+)\s*(.*)?$/);
    if (portMatch && currentHost) {
      const [, portStr, protocol, state, rest] = portMatch;
      const port = parseInt(portStr!, 10);
      if (port < 1 || port > 65535) continue; // skip invalid port numbers
      const servicePart = (rest ?? "").trim();
      const service = servicePart || undefined;
      currentHost.ports.push({ port, protocol, state, service });
      continue;
    }

    if (line.match(/^PORT\s+STATE\s+SERVICE/) && currentHost) {
      continue;
    }
  }

  if (currentHost && (currentHost.ports.length > 0 || currentHost.address)) {
    hosts.push(currentHost);
  }

  return { hosts };
}

function parseNmapXml(text: string): ParsedNmap {
  const parser = new XMLParser({ ignoreAttributes: false, parseAttributeValue: false });
  let parsed: Record<string, unknown>;
  try {
    parsed = parser.parse(text) as Record<string, unknown>;
  } catch {
    return { hosts: [] };
  }

  const nmapRun = parsed.nmaprun as Record<string, unknown> | undefined;
  if (!nmapRun) return { hosts: [] };

  const hostEl = nmapRun.host;
  const hostArray = Array.isArray(hostEl) ? hostEl : hostEl ? [hostEl] : [];
  const hosts: ParsedHost[] = [];

  for (const h of hostArray) {
    const hostObj = h as Record<string, unknown>;
    const addresses = hostObj.address as Record<string, unknown> | Record<string, unknown>[] | undefined;
    const addrList = Array.isArray(addresses) ? addresses : addresses ? [addresses] : [];
    const ipv4 = addrList.find((a: Record<string, unknown>) => a["@_addrtype"] === "ipv4") as Record<string, unknown> | undefined;
    const addr = (ipv4?.["@_addr"] as string) ?? "";

    const hostnamesEl = hostObj.hostnames as Record<string, unknown> | undefined;
    const hostnameEntry = hostnamesEl?.hostname as Record<string, unknown> | Record<string, unknown>[] | undefined;
    const hnList = Array.isArray(hostnameEntry) ? hostnameEntry : hostnameEntry ? [hostnameEntry] : [];
    const primaryHostname = hnList.find((x: Record<string, unknown>) => x["@_type"] === "user") as Record<string, unknown> | undefined;
    const hostname = primaryHostname?.["@_name"] as string | undefined;

    const portsEl = hostObj.ports as Record<string, unknown> | undefined;
    const portEl = portsEl?.port as Record<string, unknown> | Record<string, unknown>[] | undefined;
    const portList = Array.isArray(portEl) ? portEl : portEl ? [portEl] : [];
    const ports: ParsedHost["ports"] = [];

    for (const p of portList) {
      const portObj = p as Record<string, unknown>;
      const portId = parseInt(String(portObj["@_portid"] ?? 0), 10);
      const protocol = String(portObj["@_protocol"] ?? "tcp");
      const stateEl = portObj.state as Record<string, unknown> | undefined;
      const state = (stateEl?.["@_state"] as string) ?? "unknown";
      const serviceEl = portObj.service as Record<string, unknown> | undefined;
      const service = serviceEl?.["@_name"] as string | undefined;
      const version = serviceEl?.["@_product"] as string | undefined;
      ports.push({ port: portId, protocol, state, service, version });
    }

    if (addr || hostname || ports.length > 0) {
      hosts.push({ address: addr || hostname || "unknown", hostname, ports });
    }
  }

  return { hosts };
}

export function parseNmap(rawContent: string, fileType: "nmap" | "nikto" | "generic"): ParsedNmap {
  // Guard against oversized files (10 MB max)
  if (rawContent.length > 10 * 1024 * 1024) {
    throw new Error("Scan file too large (max 10 MB)");
  }

  if (fileType !== "nmap") {
    return { hosts: [], rawSummary: rawContent.slice(0, 5000) };
  }

  const trimmed = rawContent.trim();
  if (trimmed.startsWith("<?xml") || trimmed.startsWith("<nmaprun")) {
    return parseNmapXml(trimmed);
  }
  return parseNmapNormal(trimmed);
}

export function nmapToTextSummary(parsed: ParsedNmap): string {
  const lines: string[] = [];
  for (const host of parsed.hosts) {
    lines.push(`Host: ${host.hostname ?? host.address} (${host.address})`);
    for (const p of host.ports) {
      const svc = p.service ? ` ${p.service}` : "";
      const ver = p.version ? ` ${p.version}` : "";
      lines.push(`  ${p.port}/${p.protocol} ${p.state}${svc}${ver}`);
    }
  }
  if (parsed.rawSummary) {
    lines.push("--- Raw content ---");
    lines.push(parsed.rawSummary);
  }
  return lines.join("\n");
}
