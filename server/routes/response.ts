/**
 * Standardized API response helpers.
 *
 * Success responses preserve existing shapes for backward compatibility.
 * Error responses use a consistent envelope: { success: false, error: string, statusCode: number }
 */

import type { Response, Request, NextFunction } from "express";
import { ZodError } from "zod";
import { createLogger } from "../logger";

const log = createLogger("api-error");

export interface ApiError {
  success: false;
  error: string;
  statusCode: number;
}

export function sendError(res: Response, statusCode: number, message: string): void {
  res.status(statusCode).json({
    success: false,
    error: message,
    statusCode,
  } satisfies ApiError);
}

export function sendNotFound(res: Response, resource = "Resource"): void {
  sendError(res, 404, `${resource} not found`);
}

export function sendValidationError(res: Response, message: string): void {
  sendError(res, 400, message);
}

export function sendConflict(res: Response, message: string): void {
  sendError(res, 409, message);
}

/**
 * Express error-handling middleware.
 * Catches unhandled errors and Zod validation errors, returning a consistent envelope.
 */
export function errorHandler(err: unknown, req: Request, res: Response, _next: NextFunction): void {
  if (err instanceof ZodError) {
    sendValidationError(res, err.errors[0]?.message ?? "Validation error");
    return;
  }

  log.error({ err, method: req.method, url: req.url }, "Unhandled API error");
  sendError(res, 500, "Internal server error");
}

/**
 * Pagination parsed from a query string, clamped into a range SQL will accept.
 *
 * Eleven routes open-coded `Math.min(parseInt(x) || 500, 5000)`, which has no
 * LOWER bound on the limit. Three distinct bugs followed from that, all
 * reachable by anyone who can type a URL:
 *
 *  - `?limit=-5` produced **-5**. `-5` is truthy so the `|| 500` fallback never
 *    fired and `Math.min` happily returned it, giving Postgres a negative LIMIT
 *    and the caller a 500.
 *  - `?limit=1e9` produced **1**: `parseInt` stops at the `e`, so an obviously
 *    over-large request quietly returned a single row instead of being capped.
 *  - `?offset=9999999999999999999` produced 1e19, past the bigint Postgres can
 *    hold, so the query errored rather than returning an empty page.
 *
 * Clamping is the right response to all three rather than rejecting: a caller
 * asking for more than the cap wants as much as they can have, and a page far
 * beyond the end of the data is legitimately empty, not an error.
 */
export interface Pagination {
  limit: number;
  offset: number;
}

/** Largest offset worth honouring; beyond this the page is empty regardless. */
const MAX_OFFSET = 10_000_000;

function clampInt(raw: unknown, fallback: number, min: number, max: number): number {
  // `Number` rather than `parseInt` so "1e9" and "12abc" are handled honestly:
  // the first is a real number to be capped, the second is not a number at all.
  const n = typeof raw === "string" || typeof raw === "number" ? Number(raw) : Number.NaN;
  if (!Number.isFinite(n)) return fallback;
  return Math.min(Math.max(Math.trunc(n), min), max);
}

export function parsePagination(
  query: Record<string, unknown> | undefined,
  opts: { defaultLimit?: number; maxLimit?: number } = {},
): Pagination {
  const defaultLimit = opts.defaultLimit ?? 500;
  const maxLimit = opts.maxLimit ?? 5000;
  const rawLimit = query?.limit;
  const rawOffset = query?.offset;
  return {
    // A limit of 0 returns nothing and is never what a caller meant, so the
    // floor is 1.
    limit: rawLimit === undefined || rawLimit === "" ? defaultLimit : clampInt(rawLimit, defaultLimit, 1, maxLimit),
    offset: rawOffset === undefined || rawOffset === "" ? 0 : clampInt(rawOffset, 0, 0, MAX_OFFSET),
  };
}

/**
 * `page` / `pageSize` pagination, for routes that page in memory after
 * filtering rather than in SQL.
 *
 * Same clamping discipline as {@link parsePagination}, and the same reason: the
 * open-coded version was `Math.max(1, parseInt(String(page ?? "1"), 10))`, and
 * `Math.max(1, NaN)` is **NaN**. `?page=abc` therefore produced
 * `slice(NaN, NaN)` — an empty page returned with a 200 and a correct-looking
 * `total`, so an analyst filtering their inbox saw "no findings" and had no
 * reason to suspect the request rather than the data.
 */
export interface PageParams {
  page: number;
  pageSize: number;
  /** False when the caller asked for no paging at all. */
  paged: boolean;
}

export function parsePageParams(
  query: Record<string, unknown> | undefined,
  opts: { maxPageSize?: number } = {},
): PageParams {
  const maxPageSize = opts.maxPageSize ?? 200;
  const rawSize = query?.pageSize;
  const rawPage = query?.page;

  // An absent, unparseable, or non-positive pageSize means "give me
  // everything" — the behaviour every existing caller relies on. The original
  // code guarded on `ps === 0` for exactly this, but clamped to a floor of 1
  // first, so the guard could never fire and `?pageSize=0` returned a
  // single-row page instead.
  const requested = rawSize === undefined || rawSize === "" ? Number.NaN : Number(rawSize);
  const paged = Number.isFinite(requested) && requested >= 1;

  return {
    page: clampInt(rawPage, 1, 1, Number.MAX_SAFE_INTEGER),
    pageSize: paged ? clampInt(requested, 1, 1, maxPageSize) : 0,
    paged,
  };
}
