/**
 * SIEM egress — getting security events out of the platform and into the
 * customer's own detection stack.
 *
 * ## Why this is not "just another webhook"
 *
 * Webhooks already exist, are per-workspace, and carry a bespoke JSON shape a
 * human wired up. A SIEM is a different consumer with different requirements:
 * it is deployment-wide rather than per-workspace, it needs a STANDARD event
 * schema its parsers already understand, and it is usually reached over syslog
 * on an internal network rather than over HTTPS on the internet. Handing a SIEM
 * a bespoke JSON blob means somebody writes and maintains a custom parser, which
 * is the thing standard formats exist to avoid.
 *
 * Two formats cover essentially the whole market:
 *
 *  - **ECS** (Elastic Common Schema) — Elastic, OpenSearch, and anything that
 *    ingests structured JSON.
 *  - **CEF** (ArcSight Common Event Format) — ArcSight, QRadar, Splunk,
 *    Microsoft Sentinel, and most commercial SIEMs, all of which ship CEF
 *    parsers out of the box.
 *
 * ## SSRF: why this endpoint is deliberately NOT guarded
 *
 * Every other outbound URL in this codebase passes `isPrivateHost()` because it
 * came from USER input — a webhook a workspace member typed, a Jira base URL, a
 * sitemap `<loc>`. The SIEM endpoint is OPERATOR configuration, set in the
 * deployment's environment by whoever runs the server, and a SIEM is very
 * normally on a private network (`10.x`, `syslog://siem.internal:514`).
 * Applying the SSRF guard here would block the correct configuration and
 * protect against nothing: an operator who can set environment variables can
 * already reach anything the process can.
 *
 * That distinction is the whole reason this is a separate module rather than
 * another provider in the webhook dispatcher.
 *
 * ## Failure policy
 *
 * Fail-soft and non-blocking. A SIEM outage must never fail a scan, delay a
 * finding being stored, or throw into a caller. Delivery failures are logged and
 * counted; they are not retried in-process, because a queue that grows during an
 * outage is how a monitoring integration takes down the thing it monitors.
 */

import dgram from "dgram";
import net from "net";
import { createLogger } from "./logger.js";

const log = createLogger("siem-export");

export type SiemFormat = "ecs" | "cef";

export interface SiemEvent {
  /** Stable event kind, e.g. `new_critical_finding`, `scan_completed`. */
  type: string;
  title: string;
  message: string;
  severity: string;
  workspaceId: string;
  timestamp?: Date;
  findingId?: string;
  scanId?: string;
  category?: string;
  affectedAsset?: string;
  metadata?: Record<string, unknown>;
}

export interface SiemConfig {
  endpoint: string;
  format: SiemFormat;
  /** Bearer token or Splunk HEC token, when the endpoint is HTTP(S). */
  token?: string;
  enabled: boolean;
}

/** CEF severity is 0–10; map the platform's bands onto it. */
const CEF_SEVERITY: Record<string, number> = {
  critical: 10, high: 8, medium: 5, low: 3, info: 1,
};

/** Syslog severity (RFC 5424) for the platform's bands. */
const SYSLOG_SEVERITY: Record<string, number> = {
  critical: 2, high: 3, medium: 4, low: 5, info: 6,
};

/** ECS `event.severity` is an integer; higher is worse. */
const ECS_SEVERITY: Record<string, number> = {
  critical: 99, high: 73, medium: 47, low: 21, info: 1,
};

/**
 * Read the deployment's SIEM configuration.
 *
 * Absent configuration disables egress silently — this is an opt-in integration,
 * and a deployment that has not configured a SIEM is not misconfigured.
 */
export function readSiemConfig(env: NodeJS.ProcessEnv = process.env): SiemConfig {
  const endpoint = (env.SIEM_ENDPOINT ?? "").trim();
  const rawFormat = (env.SIEM_FORMAT ?? "ecs").trim().toLowerCase();
  const format: SiemFormat = rawFormat === "cef" ? "cef" : "ecs";
  return {
    endpoint,
    format,
    token: env.SIEM_TOKEN?.trim() || undefined,
    enabled: endpoint.length > 0,
  };
}

// ── formatting ──────────────────────────────────────────────────────────────

/**
 * CEF escaping.
 *
 * The header is pipe-delimited and the extension is `key=value` space-separated,
 * so a pipe, backslash, equals or newline in a finding title would otherwise
 * split the event into fields that do not exist — a log-injection bug as much as
 * a formatting one.
 */
export function escapeCefHeader(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

export function escapeCefExtension(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/=/g, "\\=").replace(/\r?\n/g, " ");
}

/** Elastic Common Schema representation. */
export function toEcs(event: SiemEvent, vendorProduct = "Cyshield"): Record<string, unknown> {
  const ts = (event.timestamp ?? new Date()).toISOString();
  return {
    "@timestamp": ts,
    message: event.message,
    event: {
      kind: "alert",
      category: ["host", "web"],
      action: event.type,
      severity: ECS_SEVERITY[event.severity] ?? 1,
      module: "cyshield",
      dataset: "cyshield.finding",
      provider: vendorProduct,
    },
    rule: { name: event.title, category: event.category },
    observer: { vendor: "Cyshield", product: vendorProduct, type: "easm" },
    vulnerability: event.category ? { category: event.category, severity: event.severity } : undefined,
    host: event.affectedAsset ? { name: event.affectedAsset } : undefined,
    cyshield: {
      workspace_id: event.workspaceId,
      finding_id: event.findingId,
      scan_id: event.scanId,
      severity: event.severity,
      ...(event.metadata ?? {}),
    },
  };
}

/** ArcSight CEF representation, consumed by most commercial SIEMs. */
export function toCef(event: SiemEvent, vendorProduct = "Cyshield", version = "1.0"): string {
  const header = [
    "CEF:0",
    "Cyshield",
    escapeCefHeader(vendorProduct),
    escapeCefHeader(version),
    escapeCefHeader(event.type),
    escapeCefHeader(event.title),
    String(CEF_SEVERITY[event.severity] ?? 1),
  ].join("|");

  const ext: Record<string, string | undefined> = {
    rt: String((event.timestamp ?? new Date()).getTime()),
    msg: escapeCefExtension(event.message),
    cat: event.category ? escapeCefExtension(event.category) : undefined,
    dhost: event.affectedAsset ? escapeCefExtension(event.affectedAsset) : undefined,
    cs1Label: "workspaceId",
    cs1: escapeCefExtension(event.workspaceId),
    cs2Label: event.findingId ? "findingId" : undefined,
    cs2: event.findingId ? escapeCefExtension(event.findingId) : undefined,
    cs3Label: event.scanId ? "scanId" : undefined,
    cs3: event.scanId ? escapeCefExtension(event.scanId) : undefined,
    cs4Label: "severity",
    cs4: escapeCefExtension(event.severity),
  };

  const pairs = Object.entries(ext)
    .filter(([, v]) => v !== undefined && v !== "")
    .map(([k, v]) => `${k}=${v}`)
    .join(" ");
  return `${header}|${pairs}`;
}

/**
 * RFC 5424 syslog framing.
 *
 * Facility 13 (log audit) — this is a security audit stream, and the facility is
 * what lets a receiver route it without parsing the payload.
 */
export function toSyslogRfc5424(payload: string, severity: string, host: string, appName = "cyshield"): string {
  const facility = 13;
  const sev = SYSLOG_SEVERITY[severity] ?? 6;
  const pri = facility * 8 + sev;
  const ts = new Date().toISOString();
  return `<${pri}>1 ${ts} ${host} ${appName} - - - ${payload}`;
}

/** Render an event in the configured format. */
export function formatEvent(event: SiemEvent, format: SiemFormat): string {
  return format === "cef" ? toCef(event) : JSON.stringify(toEcs(event));
}

// ── delivery ────────────────────────────────────────────────────────────────

interface Transport {
  kind: "http" | "udp" | "tcp";
  host?: string;
  port?: number;
  url?: string;
}

/**
 * Parse the endpoint into a transport.
 *
 * Supports `https://…` / `http://…` for HTTP collectors (Splunk HEC, Sentinel,
 * Elastic), and `syslog+udp://host:port` / `syslog+tcp://host:port` for classic
 * syslog receivers. Returns null for anything unrecognised, so a typo disables
 * egress loudly in the log rather than silently sending nowhere.
 */
export function parseEndpoint(endpoint: string): Transport | null {
  try {
    const u = new URL(endpoint);
    if (u.protocol === "http:" || u.protocol === "https:") return { kind: "http", url: endpoint };
    if (u.protocol === "syslog+udp:" || u.protocol === "udp:") {
      return { kind: "udp", host: u.hostname, port: Number(u.port) || 514 };
    }
    if (u.protocol === "syslog+tcp:" || u.protocol === "tcp:") {
      return { kind: "tcp", host: u.hostname, port: Number(u.port) || 514 };
    }
    return null;
  } catch {
    return null;
  }
}

async function sendHttp(url: string, body: string, format: SiemFormat, token?: string): Promise<void> {
  const headers: Record<string, string> = {
    "content-type": format === "cef" ? "text/plain" : "application/json",
  };
  // Splunk HEC uses `Authorization: Splunk <token>`; everything else takes a
  // bearer. Accepting a pre-formed scheme lets an operator target either.
  if (token) headers.authorization = /^(?:Splunk|Bearer|Basic)\s/i.test(token) ? token : `Bearer ${token}`;

  const res = await fetch(url, {
    method: "POST",
    headers,
    body,
    signal: AbortSignal.timeout(8000),
  });
  if (!res.ok) throw new Error(`SIEM collector returned ${res.status}`);
}

function sendUdp(host: string, port: number, line: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket("udp4");
    socket.send(Buffer.from(line), port, host, (err) => {
      socket.close();
      if (err) reject(err); else resolve();
    });
  });
}

function sendTcp(host: string, port: number, line: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port, timeout: 8000 });
    let settled = false;
    const done = (err?: Error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (err) reject(err); else resolve();
    };
    socket.on("connect", () => socket.write(`${line}\n`, () => done()));
    socket.on("error", done);
    socket.on("timeout", () => done(new Error("SIEM TCP connect timed out")));
  });
}

let deliveredCount = 0;
let failedCount = 0;

/** Counters for the admin status endpoint. */
export function siemStats(): { delivered: number; failed: number } {
  return { delivered: deliveredCount, failed: failedCount };
}

/** Reset counters (tests). */
export function resetSiemStats(): void {
  deliveredCount = 0;
  failedCount = 0;
}

/**
 * Deliver one event. Never throws.
 *
 * Returns whether the event was delivered, so callers that care (a test, a
 * "send test event" endpoint) can tell — but no production caller is expected
 * to branch on it.
 */
export async function sendToSiem(
  event: SiemEvent,
  config: SiemConfig = readSiemConfig(),
): Promise<boolean> {
  if (!config.enabled) return false;

  const transport = parseEndpoint(config.endpoint);
  if (!transport) {
    log.warn({ endpoint: config.endpoint }, "SIEM_ENDPOINT is not a recognised URL — egress disabled");
    return false;
  }

  try {
    const payload = formatEvent(event, config.format);
    if (transport.kind === "http") {
      await sendHttp(transport.url!, payload, config.format, config.token);
    } else {
      const line = toSyslogRfc5424(payload, event.severity, event.workspaceId.slice(0, 32) || "cyshield");
      if (transport.kind === "udp") await sendUdp(transport.host!, transport.port!, line);
      else await sendTcp(transport.host!, transport.port!, line);
    }
    deliveredCount++;
    return true;
  } catch (err) {
    // Fail-soft by design: a SIEM outage must not fail the scan that produced
    // the event, and must not throw into the emitter that called us.
    failedCount++;
    log.warn({ err, type: event.type }, "SIEM delivery failed (non-fatal)");
    return false;
  }
}
