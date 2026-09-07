import type { Request, Response, NextFunction } from "express";
import crypto from "crypto";
import { eq, and, isNull } from "drizzle-orm";
import { db } from "../db";
import { apiKeys, workspaceMembers } from "@shared/schema";
import type { User, Session } from "@shared/schema";
import { validateSession } from "../auth";
import { sendError, sendNotFound } from "./response";
import { createLogger } from "../logger";

const log = createLogger("auth-middleware");

declare global {
  namespace Express {
    interface Request {
      user?: User;
      session?: Session;
      /**
       * Set only when the caller authenticated with an API key. Absent for
       * session auth, which carries the user's full authority. Read by
       * `enforceApiKeyScope` to narrow what the key may do.
       */
      apiKeyScope?: string;
    }
  }
}

function extractBearerToken(req: Request): string | null {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) return null;
  return header.slice(7);
}

/**
 * Resolves an API key to its owner AND the scope recorded on the key.
 *
 * The scope has to travel with the user: `requireAuth` used to return only the
 * user, so the caller's authority was indistinguishable from a full session and
 * `api_keys.scope` had no way to be enforced downstream.
 */
async function authenticateApiKey(
  key: string,
): Promise<{ user: User; scope: string } | null> {
  const keyHash = crypto.createHash("sha256").update(key).digest("hex");

  const [record] = await db
    .select()
    .from(apiKeys)
    .where(and(eq(apiKeys.keyHash, keyHash), isNull(apiKeys.revokedAt)))
    .limit(1);

  if (!record) return null;

  // Check expiry
  if (record.expiresAt && new Date(record.expiresAt) < new Date()) return null;

  // Update lastUsedAt
  await db
    .update(apiKeys)
    .set({ lastUsedAt: new Date() })
    .where(eq(apiKeys.id, record.id));

  // Load the user
  const { users } = await import("@shared/schema");
  const [user] = await db
    .select()
    .from(users)
    .where(eq(users.id, record.userId))
    .limit(1);

  if (!user) return null;
  return { user, scope: record.scope };
}

/**
 * Requires a valid session or API key. Sets req.user and req.session.
 */
export async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    const token = extractBearerToken(req);
    if (!token) {
      sendError(res, 401, "Authorization header required");
      return;
    }

    // API key auth (keys prefixed with csk_)
    if (token.startsWith("csk_")) {
      const authed = await authenticateApiKey(token);
      if (!authed) {
        sendError(res, 401, "Invalid or expired API key");
        return;
      }
      req.user = authed.user;
      // `enforceApiKeyScope` narrows the request from here; without this the
      // key would carry the owner's full authority regardless of its scope.
      req.apiKeyScope = authed.scope;
      return next();
    }

    // Session-based auth
    const result = await validateSession(token);
    if (!result) {
      sendError(res, 401, "Invalid or expired session");
      return;
    }

    req.user = result.user;
    req.session = result.session as any;
    next();
  } catch (err) {
    log.error({ err }, "Auth middleware error");
    // Distinguish database/infrastructure errors from authentication failures
    // so callers get an accurate signal about what went wrong.
    const isDbError = err instanceof Error &&
      (err.message.includes("relation") || err.message.includes("column") ||
       err.message.includes("ECONNREFUSED") || err.message.includes("connect"));
    sendError(res, 500, isDbError ? "Internal server error" : "Authentication error");
  }
}

/**
 * Same as requireAuth but does not fail if no token is provided.
 */
export async function optionalAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    const token = extractBearerToken(req);
    if (!token) return next();

    if (token.startsWith("csk_")) {
      const authed = await authenticateApiKey(token);
      if (authed) {
        req.user = authed.user;
        // Carry the scope here too, so a route behind optionalAuth cannot be
        // used to sidestep the narrowing that requireAuth's path applies.
        req.apiKeyScope = authed.scope;
      }
      return next();
    }

    const result = await validateSession(token);
    if (result) {
      req.user = result.user;
      req.session = result.session as any;
    }
    next();
  } catch (err) {
    log.error({ err }, "Optional auth middleware error");
    next();
  }
}

/**
 * Returns middleware that checks the user has one of the specified roles.
 */
export function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      sendError(res, 401, "Authentication required");
      return;
    }
    if (!roles.includes(req.user.role)) {
      sendError(res, 403, "Insufficient permissions");
      return;
    }
    next();
  };
}

/**
 * Returns middleware that checks the user has one of the specified roles
 * within the workspace identified by req.params.workspaceId.
 */
export function requireWorkspaceRole(...roles: string[]) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.user) {
        sendError(res, 401, "Authentication required");
        return;
      }

      // Superadmins bypass workspace role checks
      if (req.user.role === "superadmin") return next();

      const workspaceId = (req.params.workspaceId as string)
        || (req.query.workspaceId as string)
        || (req.body?.workspaceId as string | undefined);
      if (!workspaceId) {
        sendError(res, 400, "Workspace ID is required");
        return;
      }

      const [member] = await db
        .select()
        .from(workspaceMembers)
        .where(
          and(
            eq(workspaceMembers.workspaceId, workspaceId),
            eq(workspaceMembers.userId, req.user.id),
          ),
        )
        .limit(1);

      // Non-membership and insufficient role are DIFFERENT answers, and
      // collapsing them into one 403 leaks exactly what the 404 convention
      // exists to hide.
      //
      // A 403 tells the caller "this workspace exists and you may not touch
      // it", which is a membership oracle: iterate workspace ids, and every 403
      // is a confirmed tenant. The bare-ID routes already return 404 for a
      // non-member for this reason; this middleware did not, so the same
      // resource leaked or did not depending on which route reached it.
      //
      // A member with the wrong role is a different case: they already know the
      // workspace exists, so 404 would be a lie and 403 is the honest, useful
      // answer.
      if (!member) {
        sendNotFound(res, "Workspace");
        return;
      }
      if (!roles.includes(member.role)) {
        sendError(res, 403, "Insufficient workspace permissions");
        return;
      }

      next();
    } catch (err) {
      log.error({ err }, "Workspace role check failed");
      sendError(res, 500, "Authorization error");
    }
  };
}
