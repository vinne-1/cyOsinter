/**
 * WebSocket subscription authorization.
 *
 * The `/ws` endpoint accepted connections with NO authentication, and its
 * `subscribe` handler set `client.workspaceId` straight from the client's own
 * message with no membership check. `broadcast` then matched on exactly that
 * value — so any unauthenticated caller who knew or guessed a workspace id
 * received that tenant's live findings: titles, descriptions, affected assets,
 * pushed as they were discovered.
 *
 * Both gates were missing at once: *who are you*, and *are you a member of what
 * you are asking for*. These tests pin both, plus the belt-and-braces check in
 * `broadcast` itself.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { EventEmitter } from "events";

const validateSession = vi.fn();
const getWorkspaceMember = vi.fn();
const createAlert = vi.fn();

vi.mock("../../../server/auth", () => ({ validateSession: (...a: unknown[]) => validateSession(...a) }));
vi.mock("../../../server/storage", () => ({
  storage: {
    getWorkspaceMember: (...a: unknown[]) => getWorkspaceMember(...a),
    createAlert: (...a: unknown[]) => createAlert(...a),
  },
}));
vi.mock("../../../server/logger", () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));
vi.mock("../../../server/siem-export.js", () => ({ sendToSiem: vi.fn().mockResolvedValue(false) }));
// Outbound webhooks hang off emitAlert alongside SIEM export, so they are stubbed
// for the same reason: this file tests WebSocket authorization, and neither
// egress path is part of that. Without the stub the real module pulls in express,
// auth middleware and a live database connection.
vi.mock("../../../server/routes/webhooks.js", () => ({ dispatchWebhookEvent: vi.fn().mockResolvedValue(undefined) }));

/** A fake `ws` socket that records what the server sends and how it closes. */
class FakeSocket extends EventEmitter {
  readyState = 1; // WebSocket.OPEN
  sent: string[] = [];
  closed: { code?: number; reason?: string } | null = null;
  send(data: string) { this.sent.push(data); }
  close(code?: number, reason?: string) { this.closed = { code, reason }; this.readyState = 3; }
  frames() { return this.sent.map((s) => JSON.parse(s)); }
}

const connections: Array<(ws: FakeSocket) => void> = [];
vi.mock("ws", () => ({
  WebSocketServer: class {
    on(event: string, cb: (ws: FakeSocket) => void) { if (event === "connection") connections.push(cb); }
  },
  WebSocket: { OPEN: 1 },
}));

let notifications: typeof import("../../../server/notifications");

/** Connect a fresh fake socket to the initialised server. */
async function connect(): Promise<FakeSocket> {
  const ws = new FakeSocket();
  connections[connections.length - 1]!(ws);
  return ws;
}

/** Send a subscribe frame and let the async handler settle. */
async function subscribe(ws: FakeSocket, msg: Record<string, unknown>): Promise<void> {
  ws.emit("message", JSON.stringify(msg));
  for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));
}

beforeEach(async () => {
  vi.resetModules();
  vi.clearAllMocks();
  connections.length = 0;
  createAlert.mockImplementation(async (a: Record<string, unknown>) => ({ ...a, id: "alert-1", createdAt: new Date() }));
  notifications = await import("../../../server/notifications");
  notifications.initNotifications({} as never);
});

describe("subscribe authorization", () => {
  it("refuses a subscribe with no token — the unauthenticated case", async () => {
    const ws = await connect();
    await subscribe(ws, { type: "subscribe", workspaceId: "ws-1" });

    expect(ws.frames()).toEqual([{ type: "error", code: "unauthorized" }]);
    expect(validateSession).not.toHaveBeenCalled();
  });

  it("refuses and closes on an invalid session token", async () => {
    validateSession.mockResolvedValue(null);
    const ws = await connect();
    await subscribe(ws, { type: "subscribe", workspaceId: "ws-1", token: "forged" });

    expect(ws.frames()[0]).toEqual({ type: "error", code: "unauthorized" });
    expect(ws.closed?.code).toBe(4401);
  });

  /**
   * The cross-tenant case: a genuine user of workspace A asking for workspace B.
   */
  it("refuses a valid session that is not a member of the workspace", async () => {
    validateSession.mockResolvedValue({ user: { id: "u1", role: "analyst" } });
    getWorkspaceMember.mockResolvedValue(undefined);

    const ws = await connect();
    await subscribe(ws, { type: "subscribe", workspaceId: "someone-elses-ws", token: "good" });

    // "not_found" rather than "forbidden", for the same reason the HTTP routes
    // answer 404: a distinct refusal confirms the workspace exists.
    expect(ws.frames()[0]).toEqual({ type: "error", code: "not_found" });
  });

  it("admits a member and confirms the subscription", async () => {
    validateSession.mockResolvedValue({ user: { id: "u1", role: "analyst" } });
    getWorkspaceMember.mockResolvedValue({ workspaceId: "ws-1", userId: "u1", role: "analyst" });

    const ws = await connect();
    await subscribe(ws, { type: "subscribe", workspaceId: "ws-1", token: "good" });

    expect(ws.frames()[0]).toEqual({ type: "subscribed", workspaceId: "ws-1" });
  });

  it("admits a superadmin without a membership row", async () => {
    validateSession.mockResolvedValue({ user: { id: "root", role: "superadmin" } });
    const ws = await connect();
    await subscribe(ws, { type: "subscribe", workspaceId: "any-ws", token: "good" });

    expect(ws.frames()[0]).toEqual({ type: "subscribed", workspaceId: "any-ws" });
    expect(getWorkspaceMember).not.toHaveBeenCalled();
  });

  it("ignores oversized frames without parsing them", async () => {
    const ws = await connect();
    await subscribe(ws, { type: "subscribe", workspaceId: "x".repeat(5000), token: "t" });
    expect(ws.sent).toEqual([]);
  });
});

describe("broadcast delivery", () => {
  const emitTo = async (workspaceId: string) => {
    await notifications.emitAlert({
      workspaceId, type: "new_critical_finding",
      title: "Exposed .env", message: "secret material", severity: "critical",
    });
    for (let i = 0; i < 3; i++) await new Promise((r) => setImmediate(r));
  };

  it("delivers to an authorized subscriber", async () => {
    validateSession.mockResolvedValue({ user: { id: "u1", role: "analyst" } });
    getWorkspaceMember.mockResolvedValue({ role: "analyst" });
    const ws = await connect();
    await subscribe(ws, { type: "subscribe", workspaceId: "ws-1", token: "good" });

    await emitTo("ws-1");
    expect(ws.frames().some((f) => f.type === "alert")).toBe(true);
  });

  /** The leak itself: an unauthenticated socket must receive nothing. */
  it("delivers NOTHING to a socket that never authenticated", async () => {
    const ws = await connect();
    await subscribe(ws, { type: "subscribe", workspaceId: "ws-1" }); // no token

    await emitTo("ws-1");
    expect(ws.frames().some((f) => f.type === "alert")).toBe(false);
  });

  it("delivers nothing to a rejected non-member", async () => {
    validateSession.mockResolvedValue({ user: { id: "u1", role: "analyst" } });
    getWorkspaceMember.mockResolvedValue(undefined);
    const ws = await connect();
    await subscribe(ws, { type: "subscribe", workspaceId: "ws-1", token: "good" });

    await emitTo("ws-1");
    expect(ws.frames().some((f) => f.type === "alert")).toBe(false);
  });

  it("does not deliver another workspace's alerts to an authorized subscriber", async () => {
    validateSession.mockResolvedValue({ user: { id: "u1", role: "analyst" } });
    getWorkspaceMember.mockResolvedValue({ role: "analyst" });
    const ws = await connect();
    await subscribe(ws, { type: "subscribe", workspaceId: "ws-1", token: "good" });

    await emitTo("ws-2");
    expect(ws.frames().some((f) => f.type === "alert")).toBe(false);
  });
});
