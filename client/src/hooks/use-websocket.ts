import { useEffect, useRef, useCallback } from "react";
import { queryClient } from "@/lib/queryClient";

type WsMessage = {
  type: string;
  [key: string]: unknown;
};

type MessageHandler = (msg: WsMessage) => void;

const handlers = new Set<MessageHandler>();
let ws: WebSocket | null = null;
let currentWorkspaceId: string | null = null;
let reconnectTimeout: ReturnType<typeof setTimeout> | null = null;

function getWsUrl(): string {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/ws`;
}

function connect(workspaceId: string): void {
  if (ws && ws.readyState <= WebSocket.OPEN) {
    if (currentWorkspaceId === workspaceId) return;
    ws.close();
  }

  currentWorkspaceId = workspaceId;
  ws = new WebSocket(getWsUrl());

  ws.onopen = () => {
    ws?.send(JSON.stringify({ type: "subscribe", workspaceId }));
  };

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data) as WsMessage;
      Array.from(handlers).forEach((handler) => {
        handler(msg);
      });
    } catch {
      // ignore parse errors
    }
  };

  ws.onclose = () => {
    // Reconnect after 3 seconds
    if (reconnectTimeout) clearTimeout(reconnectTimeout);
    reconnectTimeout = setTimeout(() => {
      if (currentWorkspaceId) connect(currentWorkspaceId);
    }, 3000);
  };

  ws.onerror = () => {
    ws?.close();
  };
}

/**
 * Hook that connects to the WebSocket for real-time notifications.
 * Automatically invalidates alert queries when new alerts arrive.
 */
export function useWebSocket(workspaceId: string | null): void {
  useEffect(() => {
    if (!workspaceId) return;
    connect(workspaceId);

    const handler: MessageHandler = (msg) => {
      if (msg.type === "alert") {
        // Invalidate alert-related queries so the UI refreshes
        queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceId}/alerts`] });
        queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceId}/alerts/unread-count`] });

        // Also refresh scans/findings if a scan completed/failed
        const alertType = (msg.alert as Record<string, unknown>)?.type;
        if (alertType === "scan_completed" || alertType === "scan_failed") {
          queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceId}/scans`] });
          queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceId}/findings`] });
        }
      }
    };

    handlers.add(handler);
    return () => {
      handlers.delete(handler);
    };
  }, [workspaceId]);
}
