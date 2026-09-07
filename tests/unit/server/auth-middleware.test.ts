/**
 * Unit tests for server/routes/auth-middleware.ts — pure-logic paths.
 *
 * Tests: requireRole (fully synchronous), requireWorkspaceRole no-user / superadmin
 * bypass / missing-workspaceId paths — no DB calls involved.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { Request, Response, NextFunction } from "express";

// Mock heavy dependencies so the module loads without a real DB
vi.mock("../../../server/db", () => ({ db: {} }));
vi.mock("../../../server/auth", () => ({ validateSession: vi.fn() }));
vi.mock("../../../server/logger", () => ({
  createLogger: () => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }),
}));
vi.mock("@shared/schema", () => ({
  apiKeys: {},
  workspaceMembers: {},
  users: {},
}));

// Drizzle chain mock — used by requireWorkspaceRole
vi.mock("drizzle-orm", () => ({
  eq: vi.fn(),
  and: vi.fn(),
  isNull: vi.fn(),
}));

import { requireRole, requireWorkspaceRole } from "../../../server/routes/auth-middleware";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function mockRes(): Response {
  const res: Partial<Response> = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
    end: vi.fn().mockReturnThis(),
  };
  return res as Response;
}

function mockNext(): NextFunction {
  return vi.fn() as unknown as NextFunction;
}

function mockUser(overrides: Record<string, unknown> = {}) {
  return {
    id: "user-1",
    username: "alice",
    role: "user",
    passwordHash: "hash",
    createdAt: new Date(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// requireRole
// ---------------------------------------------------------------------------
describe("requireRole", () => {
  it("calls next() when user has required role", () => {
    const req = { user: mockUser({ role: "admin" }) } as unknown as Request;
    const res = mockRes();
    const next = mockNext();

    requireRole("admin", "superadmin")(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it("returns 401 when req.user is not set", () => {
    const req = {} as Request;
    const res = mockRes();
    const next = mockNext();

    requireRole("admin")(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it("returns 403 when user has insufficient role", () => {
    const req = { user: mockUser({ role: "user" }) } as unknown as Request;
    const res = mockRes();
    const next = mockNext();

    requireRole("admin", "superadmin")(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  it("accepts any role in the allowed list", () => {
    for (const role of ["owner", "admin", "analyst", "viewer"]) {
      const req = { user: mockUser({ role }) } as unknown as Request;
      const res = mockRes();
      const next = mockNext();
      requireRole("owner", "admin", "analyst", "viewer")(req, res, next);
      expect(next).toHaveBeenCalled();
    }
  });

  it("rejects role not in the list", () => {
    const req = { user: mockUser({ role: "viewer" }) } as unknown as Request;
    const res = mockRes();
    const next = mockNext();

    requireRole("owner", "admin")(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
  });
});

// ---------------------------------------------------------------------------
// requireWorkspaceRole — no-DB paths
// ---------------------------------------------------------------------------
describe("requireWorkspaceRole — no-DB paths", () => {
  it("returns 401 when req.user is not set", async () => {
    const req = { params: {}, query: {}, body: {} } as unknown as Request;
    const res = mockRes();
    const next = mockNext();

    await requireWorkspaceRole("owner", "admin")(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it("calls next() immediately for superadmin (bypasses DB check)", async () => {
    const req = {
      user: mockUser({ role: "superadmin" }),
      params: {},
      query: {},
      body: {},
    } as unknown as Request;
    const res = mockRes();
    const next = mockNext();

    await requireWorkspaceRole("owner")(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it("returns 400 when workspaceId is missing for non-superadmin", async () => {
    const req = {
      user: mockUser({ role: "admin" }),
      params: {},
      query: {},
      body: {},
    } as unknown as Request;
    const res = mockRes();
    const next = mockNext();

    // The function will try to call DB since workspaceId is missing — mock db.select chain
    const { db } = await import("../../../server/db");
    (db as Record<string, unknown>).select = vi.fn().mockReturnValue({
      from: vi.fn().mockReturnValue({
        where: vi.fn().mockReturnValue({
          limit: vi.fn().mockResolvedValue([]),
        }),
      }),
    });

    await requireWorkspaceRole("owner", "admin")(req, res, next);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(next).not.toHaveBeenCalled();
  });
});

/**
 * Membership and role are different answers.
 *
 * Collapsing both into 403 leaks exactly what the codebase's 404 convention
 * exists to hide: a 403 confirms "this workspace exists and you may not touch
 * it", so iterating workspace ids turns the middleware into a tenant oracle.
 * The bare-ID routes already returned 404 for a non-member, so the same
 * resource leaked or did not depending on which route reached it.
 */
describe("requireWorkspaceRole — membership must not leak existence", () => {
  const mockDbReturning = async (rows: unknown[]) => {
    const { db } = await import("../../../server/db");
    (db as Record<string, unknown>).select = vi.fn().mockReturnValue({
      from: vi.fn().mockReturnValue({
        where: vi.fn().mockReturnValue({ limit: vi.fn().mockResolvedValue(rows) }),
      }),
    });
  };

  const reqFor = (role = "admin") => ({
    user: mockUser({ role }),
    params: { workspaceId: "ws-1" },
    query: {},
    body: {},
  } as unknown as Request);

  it("returns 404 — not 403 — for a user who is not a member", async () => {
    await mockDbReturning([]); // no membership row
    const res = mockRes();
    const next = mockNext();

    await requireWorkspaceRole("owner", "admin")(reqFor(), res, next);

    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.status).not.toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  /**
   * A member with the wrong role already knows the workspace exists, so 404
   * would be a lie and 403 is the honest, actionable answer.
   */
  it("returns 403 for a member whose role is insufficient", async () => {
    await mockDbReturning([{ workspaceId: "ws-1", userId: "u1", role: "viewer" }]);
    const res = mockRes();
    const next = mockNext();

    await requireWorkspaceRole("owner", "admin")(reqFor(), res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  it("admits a member whose role is allowed", async () => {
    await mockDbReturning([{ workspaceId: "ws-1", userId: "u1", role: "admin" }]);
    const res = mockRes();
    const next = mockNext();

    await requireWorkspaceRole("owner", "admin")(reqFor(), res, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });
});
