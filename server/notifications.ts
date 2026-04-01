import { WebSocketServer, WebSocket } from "ws";
import type { Server } from "http";
import { createLogger } from "./logger";
import { storage } from "./storage";
import type { Alert, Finding, Scan } from "@shared/schema";

const log = createLogger("notifications");

interface WsClient {
  ws: WebSocket;
  workspaceId: string | null;
}

let wss: WebSocketServer | null = null;
const clients: Set<WsClient> = new Set();

/** Initialize WebSocket server on the existing HTTP server */
export function initNotifications(httpServer: Server): void {
  wss = new WebSocketServer({ server: httpServer, path: "/ws" });

  wss.on("connection", (ws, req) => {
    const client: WsClient = { ws, workspaceId: null };
    clients.add(client);

    ws.on("message", (raw) => {
      try {
        const msg = JSON.parse(String(raw));
        if (msg.type === "subscribe" && typeof msg.workspaceId === "string") {
          client.workspaceId = msg.workspaceId;
        }
      } catch {
        // ignore malformed messages
      }
    });

    ws.on("close", () => {
      clients.delete(client);
    });

    ws.on("error", () => {
      clients.delete(client);
    });
  });

  log.info("WebSocket notification server initialized on /ws");
}

/** Broadcast a message to all clients subscribed to a workspace */
function broadcast(workspaceId: string, payload: Record<string, unknown>): void {
  const message = JSON.stringify(payload);
  Array.from(clients).forEach((client) => {
    if (client.workspaceId === workspaceId && client.ws.readyState === WebSocket.OPEN) {
      client.ws.send(message);
    }
  });
}

/** Create an alert and broadcast it via WebSocket */
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
