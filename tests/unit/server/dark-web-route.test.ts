import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import express from "express";
import http from "node:http";

/**
 * Route-level tests for the dark web monitoring endpoints.
 *
 * Uses a real Express app so middleware dispatch works correctly.
 */

const { mockModules, mockFindings } = vi.hoisted(() => ({
  mockModules: [] as unknown[],
  mockFindings: [] as unknown[],
}));

vi.mock("../../../server/logger", () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));

vi.mock("../../../server/db", () => ({
  db: { select: vi.fn(), insert: vi.fn(), update: vi.fn(), delete: vi.fn() },
}));

vi.mock("../../../server/storage", () => ({
  storage: {
    getWorkspace: vi.fn(async (id: string) => {
      if (id === "ws-missing") return null;
      return { id, name: "test", domain: "example.com", status: "active" };
    }),
    getReconModulesByType: vi.fn(async () => mockModules),
    createReconModule: vi.fn(async (data: unknown) => {
      const mod = { id: `mod-${Date.now()}`, generatedAt: new Date().toISOString(), ...(data as Record<string, unknown>) };
      mockModules.push(mod);
      return mod;
    }),
    createFinding: vi.fn(async (data: unknown) => {
      const finding = { id: `f-${Date.now()}`, ...(data as Record<string, unknown>) };
      mockFindings.push(finding);
      return finding;
    }),
  },
}));

vi.mock("../../../server/scanner/tor-fetch", () => ({
  isTorAvailable: vi.fn(async () => false),
}));

const mockMonitorResult = {
  target: "example.com",
  mentions: [] as unknown[],
  leakDumps: [] as unknown[],
  forumMentions: [] as unknown[],
  counts: { confirmedMentions: 0, possibleMentions: 0, leakDumps: 0, forumMentions: 0 },
  sourcesChecked: ["ahmia"],
  sourcesFailed: [] as string[],
  torAvailable: false,
  scannedAt: new Date().toISOString(),
};

vi.mock("../../../server/scanner/dark-web-monitor", () => ({
  monitorDarkWeb: vi.fn(async () => ({ ...mockMonitorResult })),
}));

vi.mock("../../../server/routes/auth-middleware", () => ({
  requireWorkspaceRole: (..._roles: string[]) => {
    return (req: any, _res: any, next: any) => next();
  },
  requireRole: (..._roles: string[]) => {
    return (req: any, _res: any, next: any) => next();
  },
}));

import { darkWebRouter } from "../../../server/routes/dark-web";
import { monitorDarkWeb } from "../../../server/scanner/dark-web-monitor";

function request(
  method: string,
  path: string,
  body?: unknown,
): Promise<{ status: number; body: unknown }> {
  return new Promise((resolve, reject) => {
    const app = express();
    app.use(express.json());
    app.use("/api", darkWebRouter);
    const server = app.listen(0, () => {
      const addr = server.address() as any;
      const req = http.request(
        { hostname: "127.0.0.1", port: addr.port, method, path: `/api${path}` },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => {
            server.close();
            const raw = Buffer.concat(chunks).toString();
            let parsed: unknown = null;
            try { parsed = JSON.parse(raw); } catch { parsed = raw; }
            resolve({ status: res.statusCode ?? 0, body: parsed });
          });
        },
      );
      req.on("error", (err) => { server.close(); reject(err); });
      if (body !== undefined) req.write(JSON.stringify(body));
      req.end();
    });
  });
}

beforeEach(() => {
  mockModules.length = 0;
  mockFindings.length = 0;
  vi.mocked(monitorDarkWeb).mockClear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("GET /api/workspaces/:workspaceId/dark-web", () => {
  it("returns null when no scan has run", async () => {
    const res = await request("GET", "/workspaces/ws-1/dark-web");
    expect(res.status).toBe(200);
    expect(res.body).toBeNull();
  });

  it("returns the most recent module", async () => {
    mockModules.push(
      { id: "old", moduleType: "dark_web_monitoring", generatedAt: "2026-01-01T00:00:00Z" },
      { id: "new", moduleType: "dark_web_monitoring", generatedAt: "2026-06-01T00:00:00Z" },
    );
    const res = await request("GET", "/workspaces/ws-1/dark-web");
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ id: "new" });
  });
});

describe("POST /api/workspaces/:workspaceId/dark-web", () => {
  it("returns 404 for a missing workspace", async () => {
    const res = await request("POST", "/workspaces/ws-missing/dark-web", {});
    expect(res.status).toBe(404);
  });

  it("returns 503 when all sources fail", async () => {
    vi.mocked(monitorDarkWeb).mockResolvedValueOnce({
      ...mockMonitorResult,
      sourcesChecked: [],
      sourcesFailed: ["ahmia", "onion_live"],
    } as any);
    const res = await request("POST", "/workspaces/ws-1/dark-web", {});
    expect(res.status).toBe(503);
  });

  it("creates a recon module and returns 201", async () => {
    vi.mocked(monitorDarkWeb).mockResolvedValueOnce({
      ...mockMonitorResult,
      sourcesChecked: ["ahmia"],
    } as any);
    const res = await request("POST", "/workspaces/ws-1/dark-web", {});
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ moduleType: "dark_web_monitoring" });
  });

  it("creates findings for confirmed mentions", async () => {
    vi.mocked(monitorDarkWeb).mockResolvedValueOnce({
      ...mockMonitorResult,
      mentions: [
        {
          source: "ahmia",
          title: "Leaked credentials",
          url: "http://abc.onion/leak",
          snippet: "password dump for example.com",
          publishedAt: null,
          matchedTerm: "example.com",
          confidence: "confirmed",
          reason: 'Domain "example.com" appears in listing',
        },
      ],
      counts: { confirmedMentions: 1, possibleMentions: 0, leakDumps: 0, forumMentions: 0 },
      sourcesChecked: ["ahmia"],
    } as any);
    const res = await request("POST", "/workspaces/ws-1/dark-web", {});
    expect(res.status).toBe(201);
    expect(mockFindings).toHaveLength(1);
    expect(mockFindings[0]).toMatchObject({
      category: "dark_web",
      severity: "high",
      kind: "security",
    });
  });

  it("creates critical findings for confirmed credential dumps", async () => {
    vi.mocked(monitorDarkWeb).mockResolvedValueOnce({
      ...mockMonitorResult,
      leakDumps: [
        {
          source: "IntelX",
          recordCount: 5000,
          dataTypes: ["emails", "passwords"],
          publishedAt: null,
          url: null,
          confirmed: true,
          matchedTerm: "example.com",
          reason: 'Credential dump contains data for "example.com"',
        },
      ],
      counts: { confirmedMentions: 0, possibleMentions: 0, leakDumps: 1, forumMentions: 0 },
      sourcesChecked: ["ahmia"],
    } as any);
    const res = await request("POST", "/workspaces/ws-1/dark-web", {});
    expect(res.status).toBe(201);
    expect(mockFindings).toHaveLength(1);
    expect(mockFindings[0]).toMatchObject({
      category: "dark_web",
      severity: "critical",
      kind: "security",
    });
  });

  it("does not create findings for possible-only mentions", async () => {
    vi.mocked(monitorDarkWeb).mockResolvedValueOnce({
      ...mockMonitorResult,
      mentions: [
        {
          source: "ahmia",
          title: "Some mention",
          url: null,
          snippet: null,
          publishedAt: null,
          matchedTerm: "Acme Corp",
          confidence: "possible",
          reason: "Name match",
        },
      ],
      counts: { confirmedMentions: 0, possibleMentions: 1, leakDumps: 0, forumMentions: 0 },
      sourcesChecked: ["ahmia"],
    } as any);
    const res = await request("POST", "/workspaces/ws-1/dark-web", {});
    expect(res.status).toBe(201);
    expect(mockFindings).toHaveLength(0);
  });
});
