/**
 * Audit trail.
 *
 * Two complementary paths write here:
 *
 *  1. `auditMutations` — Express middleware that records every successful
 *     state-changing /api request (POST/PATCH/PUT/DELETE). This gives blanket
 *     coverage so a new route is audited the moment it is mounted, rather than
 *     depending on the author remembering to instrument it.
 *  2. `logAudit` — explicit calls for events the middleware cannot see, most
 *     importantly authentication outcomes (a failed login is a 401, which the
 *     middleware deliberately ignores) and background/scheduled work.
 *
 * Writes never throw and never block the response: audit failure must not turn
 * a successful user action into an error.
 */

import type { Request, Response, NextFunction } from "express";
import { db } from "./db";
import { auditLogs } from "@shared/schema";
import { createLogger } from "./logger";

const log = createLogger("audit");

/** Canonical audit action names. Kept as a union so typos fail the build. */
export type AuditAction =
  // authentication
  | "login"
  | "login_failed"
  | "logout"
  | "user_registered"
  | "token_refreshed"
  | "mfa_challenge_failed"
  // resources (emitted by the mutation middleware)
  | "workspace_created"
  | "workspace_updated"
  | "workspace_deleted"
  | "scan_triggered"
  | "scan_deleted"
  | "finding_updated"
  | "finding_deleted"
  | "report_created"
  | "report_deleted"
  | "asset_created"
  | "asset_deleted"
  | "api_key_created"
  | "api_key_revoked"
  | "webhook_created"
  | "webhook_deleted"
  | "settings_updated"
  | "retention_purge"
  | "data_exported"
  | "resource_changed";

export interface AuditEntry {
  userId: string | null;
  action: AuditAction | string;
  resourceType?: string | null;
  resourceId?: string | null;
  metadata?: Record<string, unknown> | null;
  ipAddress?: string | null;
}

/**
 * Records an audit entry. Never throws — a failed audit write is logged and
 * swallowed so it cannot break the request it describes.
 */
export async function logAudit(entry: AuditEntry): Promise<void> {
  try {
    await db.insert(auditLogs).values({
      userId: entry.userId ?? null,
      action: entry.action,
      resourceType: entry.resourceType ?? null,
      resourceId: entry.resourceId ?? null,
      metadata: entry.metadata ?? null,
      ipAddress: entry.ipAddress ?? null,
    });
  } catch (err) {
    log.error({ err, action: entry.action, userId: entry.userId }, "Failed to write audit log");
  }
}

/** Fire-and-forget variant for hot paths where the caller must not await. */
export function logAuditAsync(entry: AuditEntry): void {
  void logAudit(entry);
}

/**
 * Best-effort client IP. Trusts `X-Forwarded-For` only when Express itself is
 * configured to trust the proxy (`app.set("trust proxy", …)`), because
 * `req.ip` already applies that policy; the header is read only as a fallback
 * for the un-proxied case where `req.ip` is undefined.
 */
export function clientIp(req: Request): string | null {
  if (req.ip) return req.ip;
  const fwd = req.headers["x-forwarded-for"];
  if (typeof fwd === "string") return fwd.split(",")[0]!.trim();
  return req.socket?.remoteAddress ?? null;
}

/** Prefix segments that are routing scaffolding, not part of the resource path. */
const PREFIX_SEGMENTS = new Set(["api", "v1", "v2"]);

const VERB_BY_METHOD: Record<string, string> = {
  POST: "created",
  PUT: "updated",
  PATCH: "updated",
  DELETE: "deleted",
};

/**
 * Derives `{ action, resourceType, resourceId }` from a request path.
 *
 * REST paths alternate collection/id/collection/id, so position — not the shape
 * of the segment — tells us which is which. Sniffing for a uuid would mis-name
 * any route whose id is short or non-hex: `DELETE /api/scans/abc` would read
 * "abc" as the resource and emit `abc_deleted`.
 *
 * `POST /api/workspaces/:id/reports` → `report_created`, resource `report`.
 */
export function describeMutation(
  method: string,
  path: string,
): { action: string; resourceType: string | null; resourceId: string | null } {
  const segments = path.split("/").filter(Boolean).filter((s) => !PREFIX_SEGMENTS.has(s));
  const verb = VERB_BY_METHOD[method.toUpperCase()] ?? "changed";

  // Even positions are collections, odd positions are the id within the
  // preceding collection.
  const collections = segments.filter((_, i) => i % 2 === 0);
  const ids = segments.filter((_, i) => i % 2 === 1);

  const noun = collections[collections.length - 1];
  if (!noun) {
    return { action: "resource_changed", resourceType: null, resourceId: ids[ids.length - 1] ?? null };
  }

  // "reports" → "report"; leave short and double-s words ("dns", "access") alone.
  const singular = noun.length > 3 && noun.endsWith("s") && !noun.endsWith("ss") ? noun.slice(0, -1) : noun;
  const resourceType = singular.replace(/-/g, "_");

  return {
    action: `${resourceType}_${verb}`,
    resourceType,
    resourceId: ids[ids.length - 1] ?? null,
  };
}

/** Routes the middleware must not audit — noisy, or audited explicitly elsewhere. */
const SKIP_PATHS = [
  "/auth/login",
  "/auth/logout",
  "/auth/register",
  "/auth/refresh",
];

/**
 * Records every successful state-changing /api request. Mount after `requireAuth`
 * so `req.user` is populated, and before the resource routers.
 */
export function auditMutations(req: Request, res: Response, next: NextFunction): void {
  const method = req.method.toUpperCase();
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") return next();
  if (SKIP_PATHS.some((p) => req.path.startsWith(p))) return next();

  const ip = clientIp(req);

  res.on("finish", () => {
    // Only successful mutations are auditable events; failures are covered by
    // application logs and would otherwise let anyone flood the trail with 4xx.
    if (res.statusCode < 200 || res.statusCode >= 300) return;

    const { action, resourceType, resourceId } = describeMutation(method, req.path);
    logAuditAsync({
      userId: req.user?.id ?? null,
      action,
      resourceType,
      resourceId,
      metadata: { method, path: req.path, status: res.statusCode },
      ipAddress: ip,
    });
  });

  next();
}
