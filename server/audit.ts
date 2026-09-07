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
/**
 * The caller's address, as far as the deployment can honestly determine it.
 *
 * `req.ip` is the only value worth consulting: Express already derives it from
 * `X-Forwarded-For` when `trust proxy` is configured, and deliberately ignores
 * that header when it is not — because an unproxied deployment lets the client
 * set it to anything. Reading the header here as a fallback (as this used to)
 * was both dead code, since `req.ip` is always set, and the wrong instinct: it
 * would have re-introduced the spoofable value that Express's setting exists to
 * gate. See TRUST_PROXY in server/index.ts.
 */
export function clientIp(req: Request): string | null {
  return req.ip ?? req.socket?.remoteAddress ?? null;
}

/** Prefix segments that are routing scaffolding, not part of the resource path. */
const PREFIX_SEGMENTS = new Set(["api", "v1", "v2"]);

/**
 * Whether a path segment is an identifier rather than a collection name.
 *
 * Used only to reject a bad NAME (see describeMutation), never to decide which
 * segments are ids — that stays positional, because a short or non-hex id such
 * as `/scans/abc` would fool any shape test.
 */
function looksLikeId(segment: string): boolean {
  return (
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(segment) || // uuid
    /^\d+$/.test(segment) ||                                                          // numeric id
    /^[0-9a-f]{24,}$/i.test(segment)                                                  // long hex blob
  );
}

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

  // Walk back to the last segment that actually names a collection. On a
  // well-formed REST path that is simply the last one; the loop only matters
  // when the path does not alternate, in which case an id would otherwise
  // become the resource type and produce an action like
  // `c7de255b_7ff9_4e2e_aa41_0dd77591f071_deleted` — unbounded garbage that
  // lands in the audit viewer's action facet list, one entry per record ever
  // touched.
  //
  // This does NOT contradict the position rule above. Position still decides
  // which segments are ids; this is only a last-step sanity check on the name
  // we are about to publish, so a route that does not follow the convention
  // degrades to the generic action instead of inventing a new one.
  const noun = [...collections].reverse().find((c) => !looksLikeId(c));
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

  /*
   * Resolve the path NOW, not inside the `finish` handler.
   *
   * `req.path` derives from `req.url`, which Express REWRITES as it descends
   * into a mounted sub-router — and `finish` fires after the handler has already
   * sent the response, while that rewrite is still in effect. Reading it late
   * therefore recorded the path relative to whichever router answered:
   *
   *   POST   /api/workspaces      →  "/"                 → `resource_changed`, no resourceType
   *   DELETE /api/workspaces/:id  →  "/<uuid>"           → `<uuid>_deleted`, a junk action name
   *   POST   /api/workspaces/:id/assets → "/<uuid>/assets" → the uuid read as the collection
   *
   * That was 501 of ~1200 audit rows — every workspace create, and the answer to
   * "who deleted this workspace" was an unnamed row with a NULL resource type.
   * Only `app.use("/api", ...)` routers escaped it, because their prefix matches
   * the one this middleware is mounted at and nothing further is stripped.
   *
   * `req.originalUrl` is the one value Express never rewrites, so it is the only
   * safe source here. Capturing synchronously also means a later rewrite by any
   * middleware cannot affect what we record.
   */
  // `|| req.path` only for exotic callers that construct a bare request
  // object; Express itself always sets originalUrl.
  const auditPath = (req.originalUrl || req.path || "").split("?")[0] || req.path;
  const described = describeMutation(method, auditPath);

  res.on("finish", () => {
    // Only successful mutations are auditable events; failures are covered by
    // application logs and would otherwise let anyone flood the trail with 4xx.
    if (res.statusCode < 200 || res.statusCode >= 300) return;

    logAuditAsync({
      userId: req.user?.id ?? null,
      action: described.action,
      resourceType: described.resourceType,
      resourceId: described.resourceId,
      metadata: { method, path: auditPath, status: res.statusCode },
      ipAddress: ip,
    });
  });

  next();
}
