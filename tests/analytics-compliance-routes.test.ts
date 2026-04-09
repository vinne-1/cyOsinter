import express from "express";
import type { Server } from "http";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "@shared/schema";

const mockGetFindings = vi.fn();

vi.mock("../server/storage", () => ({
  storage: {
    getFindings: mockGetFindings,
  },
}));

vi.mock("../server/logger", () => ({
  createLogger: () => ({
    error: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
  }),
}));

vi.mock("../server/routes/auth-middleware", () => ({
  requireWorkspaceRole: () => (req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (req.headers["x-workspace-access"] === "viewer") {
      return next();
    }
    return res.status(403).json({
      success: false,
      error: "Insufficient workspace permissions",
      statusCode: 403,
    });
  },
}));

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-route-1",
    workspaceId: "workspace-1",
    scanId: null,
    title: "Route test finding",
    description: "Route test finding description",
    severity: "medium",
    status: "open",
    category: "security_headers",
    checkId: "security_headers",
    resourceType: "web_application",
    resourceId: "https://example.com",
    provider: null,
    complianceTags: [],
    affectedAsset: "https://example.com",
    evidence: [],
    cvssScore: null,
    remediation: null,
    assignee: null,
    assigneeId: null,
    priority: null,
    dueDate: null,
    slaBreached: false,
    workflowState: "open",
    groupId: null,
    verificationScanId: null,
    discoveredAt: new Date("2026-04-03T00:00:00.000Z"),
    resolvedAt: null,
    tags: [],
    aiEnrichment: null,
    ...overrides,
  };
}

describe("analytics compliance routes", () => {
  let server: Server;
  let baseUrl: string;

  beforeEach(async () => {
    vi.resetModules();
    mockGetFindings.mockReset();
    const { analyticsRouter } = await import("../server/routes/analytics");
    const app = express();
    app.use(express.json());
    app.use(analyticsRouter);
    server = app.listen(0);
    await new Promise<void>((resolve) => server.once("listening", () => resolve()));
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("Failed to resolve test server address");
    }
    baseUrl = `http://127.0.0.1:${address.port}`;
  });

  afterEach(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  it("blocks users without workspace membership", async () => {
    mockGetFindings.mockResolvedValue({ data: [] });

    const response = await fetch(`${baseUrl}/workspaces/workspace-1/compliance`);

    expect(response.status).toBe(403);
    expect(mockGetFindings).not.toHaveBeenCalled();
  });

  it("allows viewer access to workspace compliance reports", async () => {
    mockGetFindings.mockResolvedValue({ data: [] });

    const response = await fetch(`${baseUrl}/workspaces/workspace-1/compliance`, {
      headers: { "x-workspace-access": "viewer" },
    });
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(mockGetFindings).toHaveBeenCalledWith("workspace-1");
    expect(body.owasp.score).toBe(0);
    expect(body.owasp.assessedControls).toBe(0);
    expect(body.owasp.hasAssessmentData).toBe(false);
  });

  it("allows viewer access to framework-specific compliance reports", async () => {
    mockGetFindings.mockResolvedValue({ data: [makeFinding()] });

    const response = await fetch(`${baseUrl}/workspaces/workspace-1/compliance/owasp`, {
      headers: { "x-workspace-access": "viewer" },
    });
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body.framework).toBe("OWASP Top 10");
    expect(body.hasAssessmentData).toBe(true);
    expect(body.assessedControls).toBe(1);
  });

  it("supports new framework keys such as hipaa", async () => {
    mockGetFindings.mockResolvedValue({ data: [makeFinding()] });

    const response = await fetch(`${baseUrl}/workspaces/workspace-1/compliance/hipaa`, {
      headers: { "x-workspace-access": "viewer" },
    });
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body.framework).toBe("HIPAA Security Rule");
  });
});
