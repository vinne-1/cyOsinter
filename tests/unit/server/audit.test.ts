import { describe, it, expect, vi, beforeEach } from "vitest";
import type { Request, Response, NextFunction } from "express";

const insertValues = vi.fn().mockResolvedValue(undefined);
vi.mock("../../../server/db", () => ({
  db: { insert: () => ({ values: insertValues }) },
  pool: { query: vi.fn() },
}));

const { describeMutation, auditMutations, logAudit, clientIp } = await import("../../../server/audit");

/** Minimal Express doubles — enough to drive the middleware's `finish` hook. */
function makeReq(overrides: Partial<Request> = {}): Request {
  return {
    method: "POST",
    path: "/workspaces/abc/scans",
    ip: "203.0.113.9",
    headers: {},
    socket: { remoteAddress: "203.0.113.9" },
    ...overrides,
  } as unknown as Request;
}

function makeRes(statusCode = 201) {
  const handlers: Record<string, Array<() => void>> = {};
  const res = {
    statusCode,
    on(event: string, fn: () => void) {
      (handlers[event] ??= []).push(fn);
      return res;
    },
    finish() {
      for (const fn of handlers.finish ?? []) fn();
    },
  };
  return res as unknown as Response & { finish: () => void };
}

beforeEach(() => {
  insertValues.mockClear();
});

describe("describeMutation", () => {
  it("names the action from the resource and the HTTP verb", () => {
    expect(describeMutation("POST", "/api/workspaces/x/reports")).toMatchObject({
      action: "report_created",
      resourceType: "report",
    });
    expect(describeMutation("DELETE", "/api/scans/abc")).toMatchObject({
      action: "scan_deleted",
      resourceType: "scan",
    });
    expect(describeMutation("PATCH", "/api/findings/abc")).toMatchObject({
      action: "finding_updated",
      resourceType: "finding",
    });
    expect(describeMutation("PUT", "/api/webhooks/abc")).toMatchObject({
      action: "webhook_updated",
      resourceType: "webhook",
    });
  });

  it("extracts a uuid path segment as the resource id", () => {
    const id = "1f6ba6e4-e21a-4391-867d-3786afbaa4b7";
    expect(describeMutation("DELETE", `/api/scans/${id}`).resourceId).toBe(id);
  });

  it("ignores structural segments when naming the resource", () => {
    // "workspaces" is a container here, not the thing being created.
    expect(describeMutation("POST", "/api/workspaces/abc/assets").resourceType).toBe("asset");
  });

  it("treats a bare collection as its own resource", () => {
    expect(describeMutation("POST", "/api/workspaces")).toMatchObject({
      action: "workspace_created",
      resourceType: "workspace",
      resourceId: null,
    });
  });

  it("uses position, not segment shape, so a non-uuid id is still an id", () => {
    // A uuid sniff would read "abc" as the resource and emit "abc_deleted".
    expect(describeMutation("DELETE", "/api/scans/abc")).toMatchObject({
      action: "scan_deleted",
      resourceType: "scan",
      resourceId: "abc",
    });
  });

  it("picks the innermost collection and its id when nested", () => {
    expect(describeMutation("PATCH", "/api/workspaces/w1/findings/f2")).toMatchObject({
      action: "finding_updated",
      resourceType: "finding",
      resourceId: "f2",
    });
  });

  it("does not over-singularise short or double-s nouns", () => {
    expect(describeMutation("POST", "/api/dns").resourceType).toBe("dns");
    expect(describeMutation("POST", "/api/access").resourceType).toBe("access");
  });

  it("normalises hyphenated resources to snake_case", () => {
    expect(describeMutation("POST", "/api/scan-profiles").resourceType).toBe("scan_profile");
  });

  it("falls back for a path with nothing nameable", () => {
    expect(describeMutation("POST", "/api")).toMatchObject({ action: "resource_changed" });
  });
});

describe("auditMutations middleware", () => {
  it("records a successful mutation once the response finishes", () => {
    const req = makeReq();
    (req as unknown as { user: { id: string } }).user = { id: "user-1" };
    const res = makeRes(201);
    const next = vi.fn() as NextFunction;

    auditMutations(req, res, next);
    expect(next).toHaveBeenCalledOnce();
    // Nothing is written until the response actually succeeds.
    expect(insertValues).not.toHaveBeenCalled();

    res.finish();
    expect(insertValues).toHaveBeenCalledOnce();
    expect(insertValues.mock.calls[0]![0]).toMatchObject({
      userId: "user-1",
      action: "scan_created",
      resourceType: "scan",
      ipAddress: "203.0.113.9",
    });
  });

  it("ignores reads", () => {
    for (const method of ["GET", "HEAD", "OPTIONS"]) {
      const res = makeRes(200);
      auditMutations(makeReq({ method }), res, vi.fn() as NextFunction);
      res.finish();
    }
    expect(insertValues).not.toHaveBeenCalled();
  });

  it("ignores failed mutations", () => {
    for (const status of [400, 401, 403, 404, 409, 500]) {
      const res = makeRes(status);
      auditMutations(makeReq(), res, vi.fn() as NextFunction);
      res.finish();
    }
    expect(insertValues).not.toHaveBeenCalled();
  });

  it("skips auth routes, which are audited explicitly with their outcome", () => {
    for (const path of ["/auth/login", "/auth/logout", "/auth/register", "/auth/refresh"]) {
      const res = makeRes(200);
      auditMutations(makeReq({ path }), res, vi.fn() as NextFunction);
      res.finish();
    }
    expect(insertValues).not.toHaveBeenCalled();
  });

  it("records an unauthenticated mutation with a null actor rather than dropping it", () => {
    const res = makeRes(204);
    auditMutations(makeReq({ method: "DELETE" }), res, vi.fn() as NextFunction);
    res.finish();
    expect(insertValues.mock.calls[0]![0]).toMatchObject({ userId: null, action: "scan_deleted" });
  });
});

describe("logAudit", () => {
  it("never throws when the insert fails, so it cannot break the caller", async () => {
    insertValues.mockRejectedValueOnce(new Error("db down"));
    await expect(
      logAudit({ userId: "u1", action: "login" }),
    ).resolves.toBeUndefined();
  });

  it("normalises absent optional fields to null", async () => {
    await logAudit({ userId: null, action: "login" });
    expect(insertValues.mock.calls[0]![0]).toEqual({
      userId: null,
      action: "login",
      resourceType: null,
      resourceId: null,
      metadata: null,
      ipAddress: null,
    });
  });
});

describe("clientIp", () => {
  it("prefers req.ip, which already reflects the trust-proxy policy", () => {
    const req = makeReq({ headers: { "x-forwarded-for": "198.51.100.1" } });
    expect(clientIp(req)).toBe("203.0.113.9");
  });

  it("falls back to the first forwarded hop when req.ip is unset", () => {
    const req = makeReq({ ip: undefined, headers: { "x-forwarded-for": "198.51.100.1, 10.0.0.1" } });
    expect(clientIp(req)).toBe("198.51.100.1");
  });

  it("falls back to the socket address when there is no header", () => {
    expect(clientIp(makeReq({ ip: undefined }))).toBe("203.0.113.9");
  });
});
