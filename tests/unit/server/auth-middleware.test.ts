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
