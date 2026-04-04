/**
 * Unit tests for server/routes/response.ts — API response helpers.
 *
 * Tests: sendError, sendNotFound, sendValidationError, sendConflict, errorHandler.
 */

import { describe, it, expect, vi } from "vitest";
import { ZodError, ZodIssueCode } from "zod";

// Mock logger
vi.mock("../../../server/logger", () => ({
  createLogger: () => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }),
}));

import {
  sendError,
  sendNotFound,
  sendValidationError,
  sendConflict,
  errorHandler,
} from "../../../server/routes/response";

function createMockRes() {
  const res: any = {
    statusCode: 200,
    body: null,
    status(code: number) {
      res.statusCode = code;
      return res;
    },
    json(data: unknown) {
      res.body = data;
      return res;
    },
  };
  return res;
}

function createMockReq(overrides: Partial<{ method: string; url: string }> = {}) {
  return {
    method: overrides.method ?? "GET",
    url: overrides.url ?? "/api/test",
  } as any;
}

// ---------------------------------------------------------------------------
// sendError
// ---------------------------------------------------------------------------
describe("sendError", () => {
  it("sets status code and returns error envelope", () => {
    const res = createMockRes();
    sendError(res, 403, "Forbidden");
    expect(res.statusCode).toBe(403);
    expect(res.body).toEqual({
      success: false,
      error: "Forbidden",
      statusCode: 403,
    });
  });

  it("works with 500 status", () => {
    const res = createMockRes();
    sendError(res, 500, "Internal Server Error");
    expect(res.statusCode).toBe(500);
    expect(res.body.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// sendNotFound
// ---------------------------------------------------------------------------
describe("sendNotFound", () => {
  it("returns 404 with default resource name", () => {
    const res = createMockRes();
    sendNotFound(res);
    expect(res.statusCode).toBe(404);
    expect(res.body.error).toBe("Resource not found");
  });

  it("returns 404 with custom resource name", () => {
    const res = createMockRes();
    sendNotFound(res, "Workspace");
    expect(res.statusCode).toBe(404);
    expect(res.body.error).toBe("Workspace not found");
  });
});

// ---------------------------------------------------------------------------
// sendValidationError
// ---------------------------------------------------------------------------
describe("sendValidationError", () => {
  it("returns 400 with message", () => {
    const res = createMockRes();
    sendValidationError(res, "Invalid email format");
    expect(res.statusCode).toBe(400);
    expect(res.body.error).toBe("Invalid email format");
    expect(res.body.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// sendConflict
// ---------------------------------------------------------------------------
describe("sendConflict", () => {
  it("returns 409 with message", () => {
    const res = createMockRes();
    sendConflict(res, "Duplicate entry");
    expect(res.statusCode).toBe(409);
    expect(res.body.error).toBe("Duplicate entry");
    expect(res.body.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// errorHandler
// ---------------------------------------------------------------------------
describe("errorHandler", () => {
  it("handles ZodError with 400 and first message", () => {
    const res = createMockRes();
    const zodErr = new ZodError([
      { code: ZodIssueCode.custom, message: "Field is required", path: ["email"] },
    ]);
    errorHandler(zodErr, createMockReq(), res, vi.fn());
    expect(res.statusCode).toBe(400);
    expect(res.body.error).toBe("Field is required");
  });

  it("handles generic Error with 500", () => {
    const res = createMockRes();
    errorHandler(new Error("Something broke"), createMockReq(), res, vi.fn());
    expect(res.statusCode).toBe(500);
    expect(res.body.error).toBe("Something broke");
  });

  it("handles non-Error unknown with 500 and generic message", () => {
    const res = createMockRes();
    errorHandler("string error", createMockReq(), res, vi.fn());
    expect(res.statusCode).toBe(500);
    expect(res.body.error).toBe("Internal server error");
  });

  it("handles ZodError with empty errors array", () => {
    const res = createMockRes();
    const zodErr = new ZodError([]);
    errorHandler(zodErr, createMockReq(), res, vi.fn());
    expect(res.statusCode).toBe(400);
    expect(res.body.error).toBe("Validation error");
  });
});
