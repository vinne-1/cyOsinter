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
