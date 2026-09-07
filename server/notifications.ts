import { WebSocketServer, WebSocket } from "ws";
import type { Server } from "http";
import { createLogger } from "./logger";
import { storage } from "./storage";
import { validateSession } from "./auth";
import { sendToSiem } from "./siem-export.js";
import { dispatchWebhookEvent } from "./routes/webhooks.js";
import type { Alert, Finding, Scan } from "@shared/schema";

const log = createLogger("notifications");

interface WsClient {
  ws: WebSocket;
  workspaceId: string | null;
  userId: string | null;
}

let wss: WebSocketServer | null = null;
const clients: Set<WsClient> = new Set();

/**
 * How long a socket may stay connected without a successful subscribe.
 *
 * An unauthenticated socket costs memory and a file descriptor and can do
 * nothing useful, so it is not allowed to linger.
 */
const AUTH_GRACE_MS = 15_000;

/** Ceiling on concurrent sockets, so an anonymous caller cannot exhaust them. */
const MAX_WS_CLIENTS = 2_000;

/** Initialize WebSocket server on the existing HTTP server */
export function initNotifications(httpServer: Server): void {
  wss = new WebSocketServer({ server: httpServer, path: "/ws" });

  wss.on("connection", (ws) => {
    // The socket carried NO authentication and `subscribe` set `workspaceId`
    // straight from the client's own message. Any unauthenticated caller who
    // knew or guessed a workspace id received that tenant's live findings —
    // titles, descriptions, affected assets — because `broadcast` matches only
    // on the value the client supplied. Both gates were missing: who are you,
    // and are you a member of what you are asking for.
    if (clients.size >= MAX_WS_CLIENTS) {
      ws.close(1013, "Server busy");
      return;
    }

    const client: WsClient = { ws, workspaceId: null, userId: null };
    clients.add(client);

    // A socket that never authenticates is closed rather than left open.
    const graceTimer = setTimeout(() => {
      if (!client.userId) {
        try { ws.close(4401, "Authentication required"); } catch { /* already gone */ }
      }
    }, AUTH_GRACE_MS);

    const drop = () => {
      clearTimeout(graceTimer);
      clients.delete(client);
    };

    ws.on("message", (raw) => {
      void (async () => {
        try {
          const str = String(raw);
          // Reject oversized messages to prevent JSON.parse DoS
          if (str.length > 4096) return;
          const msg = JSON.parse(str);
          if (msg.type !== "subscribe") return;
          if (typeof msg.workspaceId !== "string" || typeof msg.token !== "string") {
            ws.send(JSON.stringify({ type: "error", code: "unauthorized" }));
            return;
          }

          const session = await validateSession(msg.token);
          if (!session) {
            ws.send(JSON.stringify({ type: "error", code: "unauthorized" }));
            ws.close(4401, "Authentication required");
            return;
          }

          // Superadmins may observe any workspace, matching how
          // `requireWorkspaceRole` treats them.
          if (session.user.role !== "superadmin") {
            const member = await storage.getWorkspaceMember(msg.workspaceId, session.user.id);
            if (!member) {
              // Same reasoning as the 404 convention on HTTP routes: a distinct
              // "forbidden" would confirm the workspace exists.
              ws.send(JSON.stringify({ type: "error", code: "not_found" }));
              return;
            }
          }

          client.userId = session.user.id;
          client.workspaceId = msg.workspaceId;
          clearTimeout(graceTimer);
          ws.send(JSON.stringify({ type: "subscribed", workspaceId: msg.workspaceId }));
        } catch {
          // ignore malformed messages
        }
      })();
    });

    ws.on("close", drop);
    ws.on("error", drop);
  });

  log.info("WebSocket notification server initialized on /ws");
}

/** Broadcast a message to all clients subscribed to a workspace */
function broadcast(workspaceId: string, payload: Record<string, unknown>): void {
  const message = JSON.stringify(payload);
  Array.from(clients).forEach((client) => {
    // `userId` is only set after a verified session AND a membership check, so
    // requiring it here means an unauthenticated socket can never be a
    // recipient even if some future path sets `workspaceId` alone.
    if (client.userId && client.workspaceId === workspaceId && client.ws.readyState === WebSocket.OPEN) {
      client.ws.send(message);
    }
  });
}

/** Create an alert and broadcast it via WebSocket */
/**
 * Alert type → the webhook event an operator can actually subscribe to.
 *
 * Explicit rather than passing `params.type` straight through, because the two
 * vocabularies genuinely differ: the config UI offers three coarse events
 * (`scan_completed`, `critical_finding`, `sla_breach`) while alerts are
 * finer-grained (`new_critical_finding` vs `new_high_finding`). Mapping by hand
 * means a new alert type cannot silently start firing webhooks nobody
 * subscribed to, and an operator who ticked a box receives what the box says.
 *
 * `new_high_finding` is deliberately absent: the UI offers "Critical Finding",
 * and quietly including highs would send more than was asked for.
 */
const WEBHOOK_EVENT_BY_ALERT_TYPE: Record<string, string> = {
  scan_completed: "scan_completed",
  new_critical_finding: "critical_finding",
  sla_breached: "sla_breach",
};

export async function emitAlert(params: {
  workspaceId: string;
  type: string;
  title: string;
  message: string;
  severity: string;
  scanId?: string;
  findingId?: string;
  metadata?: Record<string, unknown>;
}): Promise<Alert> {
  const alert = await storage.createAlert({
    workspaceId: params.workspaceId,
    type: params.type,
    title: params.title,
    message: params.message,
    severity: params.severity,
    scanId: params.scanId ?? null,
    findingId: params.findingId ?? null,
    read: false,
    metadata: params.metadata ?? null,
  });

  broadcast(params.workspaceId, {
    type: "alert",
    alert,
  });

  // SIEM egress hangs off the same choke point as the in-app alert, for the
  // reason `auditMutations` is mounted once at `/api`: a new event type is
  // exported the moment it is emitted, without the author remembering to
  // instrument it. Deliberately not awaited — a SIEM round trip must not sit in
  // the path of storing a finding, and `sendToSiem` never throws.
  void sendToSiem({
    type: params.type,
    title: params.title,
    message: params.message,
    severity: params.severity,
    workspaceId: params.workspaceId,
    timestamp: alert.createdAt ?? new Date(),
    findingId: params.findingId,
    scanId: params.scanId,
    category: typeof params.metadata?.category === "string" ? params.metadata.category : undefined,
    affectedAsset: typeof params.metadata?.affectedAsset === "string" ? params.metadata.affectedAsset : undefined,
    metadata: params.metadata,
  }).catch(() => { /* sendToSiem swallows its own errors; this is belt and braces */ });

  /*
   * Outbound webhooks hang off the SAME choke point, and for the same reason.
   *
   * `dispatchWebhookEvent` was a complete implementation — matching enabled
   * endpoints, HMAC signing, retries, failCount tracking — with **no caller
   * anywhere**. The table existed, the config page existed, the event
   * subscription checkboxes existed, and an operator who ticked "Critical
   * Finding" received nothing, ever. That is the same dead-feature pattern as
   * `logAudit`, `enqueueScan`, `checkSLABreaches`, `api_keys.scope` and
   * `retention_policies`.
   *
   * Not awaited: a customer's endpoint being slow or down must not sit in the
   * path of storing a finding.
   */
  const webhookEvent = WEBHOOK_EVENT_BY_ALERT_TYPE[params.type];
  if (webhookEvent) {
    void dispatchWebhookEvent(params.workspaceId, webhookEvent, {
      alertType: params.type,
      title: params.title,
      message: params.message,
      severity: params.severity,
      scanId: params.scanId ?? null,
      findingId: params.findingId ?? null,
      workspaceId: params.workspaceId,
      timestamp: (alert.createdAt ?? new Date()).toISOString(),
      metadata: params.metadata ?? null,
    }).catch((err) => log.warn({ err, event: webhookEvent }, "Webhook dispatch failed"));
  }

  return alert;
}

/** Emit alerts for a completed scan */
export async function emitScanCompleted(scan: Scan, findingsCreated: number): Promise<void> {
  const criticalCount = (scan.summary as Record<string, unknown>)?.criticalCount as number | undefined;
  const highCount = (scan.summary as Record<string, unknown>)?.highCount as number | undefined;

  await emitAlert({
    workspaceId: scan.workspaceId,
    type: "scan_completed",
    title: `Scan completed: ${scan.target}`,
    message: `${scan.type.toUpperCase()} scan finished with ${findingsCreated} findings${criticalCount ? ` (${criticalCount} critical)` : ""}.`,
    severity: criticalCount ? "critical" : highCount ? "high" : "info",
    scanId: scan.id,
    metadata: { findingsCreated, criticalCount, highCount },
  });
}

/** Emit alert for a failed scan */
export async function emitScanFailed(scan: Scan, errorMessage: string): Promise<void> {
  await emitAlert({
    workspaceId: scan.workspaceId,
    type: "scan_failed",
    title: `Scan failed: ${scan.target}`,
    message: errorMessage.slice(0, 500),
    severity: "high",
    scanId: scan.id,
  });
}

/** Emit alert for a new critical/high finding */
export async function emitNewCriticalFinding(finding: Finding): Promise<void> {
  if (finding.severity !== "critical" && finding.severity !== "high") return;

  await emitAlert({
    workspaceId: finding.workspaceId,
    type: finding.severity === "critical" ? "new_critical_finding" : "new_high_finding",
    title: `New ${finding.severity} finding: ${finding.title}`,
    message: (finding.description ?? "").slice(0, 300),
    severity: finding.severity,
    findingId: finding.id,
    metadata: { category: finding.category, affectedAsset: finding.affectedAsset },
  });
}

/** Emit alert when a scheduled scan triggers */
export async function emitScheduledScanTriggered(workspaceId: string, target: string, scanId: string): Promise<void> {
  await emitAlert({
    workspaceId,
    type: "scheduled_scan_triggered",
    title: `Scheduled scan started: ${target}`,
    message: `An automated scan has been triggered for ${target}.`,
    severity: "info",
    scanId,
  });
}
