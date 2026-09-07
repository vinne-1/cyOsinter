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
  parsePagination,
  parsePageParams,
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

  it("handles generic Error with 500 and generic message (no leakage)", () => {
    const res = createMockRes();
    errorHandler(new Error("Something broke"), createMockReq(), res, vi.fn());
    expect(res.statusCode).toBe(500);
    expect(res.body.error).toBe("Internal server error");
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

/**
 * Pagination clamping.
 *
 * Eleven routes open-coded `Math.min(parseInt(x) || 500, 5000)`, which has no
 * lower bound, and three bugs followed — all reachable by typing a URL.
 */
describe("parsePagination", () => {
  it("uses the defaults when nothing is supplied", () => {
    expect(parsePagination(undefined)).toEqual({ limit: 500, offset: 0 });
    expect(parsePagination({})).toEqual({ limit: 500, offset: 0 });
    expect(parsePagination({ limit: "", offset: "" })).toEqual({ limit: 500, offset: 0 });
  });

  it("honours a valid request", () => {
    expect(parsePagination({ limit: "25", offset: "50" })).toEqual({ limit: 25, offset: 50 });
  });

  /**
   * The headline bug: -5 is truthy, so `|| 500` never fired and `Math.min`
   * returned it — a negative SQL LIMIT, and a 500 for the caller.
   */
  it("clamps a negative limit instead of passing it to SQL", () => {
    expect(parsePagination({ limit: "-5" }).limit).toBe(1);
    expect(parsePagination({ limit: "0" }).limit).toBe(1);
  });

  it("clamps a negative offset to zero", () => {
    expect(parsePagination({ offset: "-100" }).offset).toBe(0);
  });

  /** `parseInt("1e9")` stops at the "e" and yields 1 — a silent wrong answer. */
  it("reads exponent notation as the number it is, then caps it", () => {
    expect(parsePagination({ limit: "1e9" }).limit).toBe(5000);
  });

  /** Past Postgres's bigint the query errors instead of returning an empty page. */
  it("caps an absurd offset rather than overflowing the column", () => {
    expect(parsePagination({ offset: "9999999999999999999" }).offset).toBe(10_000_000);
  });

  it("falls back for values that are not numbers at all", () => {
    for (const bad of ["abc", "NaN", "Infinity", "-Infinity", {}, [], null, true]) {
      expect(parsePagination({ limit: bad as never }).limit, `limit=${String(bad)}`).toBe(500);
    }
  });

  it("truncates a fractional request rather than handing SQL a float", () => {
    expect(parsePagination({ limit: "10.9" }).limit).toBe(10);
  });

  it("respects per-route caps", () => {
    expect(parsePagination({ limit: "999" }, { defaultLimit: 30, maxLimit: 100 }).limit).toBe(100);
    expect(parsePagination({}, { defaultLimit: 30, maxLimit: 100 }).limit).toBe(30);
  });
});

/**
 * `page` / `pageSize` clamping.
 *
 * The open-coded version was `Math.max(1, parseInt(String(page ?? "1"), 10))`,
 * and `Math.max(1, NaN)` is NaN — so `?page=abc` sliced NaN..NaN and returned
 * an EMPTY findings inbox with a 200 and a correct-looking total. An analyst
 * would read that as "no findings" rather than "malformed request".
 */
describe("parsePageParams", () => {
  it("does not page when no pageSize is asked for", () => {
    expect(parsePageParams({}).paged).toBe(false);
    expect(parsePageParams({ page: "3" }).paged).toBe(false);
    expect(parsePageParams({ pageSize: "" }).paged).toBe(false);
  });

  it("pages when a usable pageSize is given", () => {
    expect(parsePageParams({ pageSize: "25" })).toMatchObject({ paged: true, pageSize: 25, page: 1 });
  });

  /** The bug: a malformed page silently emptied the inbox. */
  it("falls back to page 1 for a non-numeric page instead of yielding NaN", () => {
    const p = parsePageParams({ page: "abc", pageSize: "10" });
    expect(Number.isNaN(p.page)).toBe(false);
    expect(p.page).toBe(1);
  });

  it("clamps a zero or negative page", () => {
    expect(parsePageParams({ page: "0", pageSize: "10" }).page).toBe(1);
    expect(parsePageParams({ page: "-4", pageSize: "10" }).page).toBe(1);
  });

  it("caps pageSize and refuses a zero-size page", () => {
    expect(parsePageParams({ pageSize: "9999" }).pageSize).toBe(200);
    expect(parsePageParams({ pageSize: "0" }).paged).toBe(false);
  });

  it("treats a non-numeric pageSize as no paging rather than an empty page", () => {
    expect(parsePageParams({ pageSize: "abc" }).paged).toBe(false);
  });
});
