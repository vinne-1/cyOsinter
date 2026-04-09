import type { Request, Response, NextFunction } from "express";
import crypto from "crypto";
import { eq, and, isNull } from "drizzle-orm";
import { db } from "../db";
import { apiKeys, workspaceMembers } from "@shared/schema";
import type { User, Session } from "@shared/schema";
import { validateSession } from "../auth";
import { sendError } from "./response";
import { createLogger } from "../logger";

const log = createLogger("auth-middleware");

declare global {
  namespace Express {
    interface Request {
      user?: User;
      session?: Session;
    }
  }
}

function extractBearerToken(req: Request): string | null {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) return null;
  return header.slice(7);
}

async function authenticateApiKey(
  key: string,
): Promise<User | null> {
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

  return user ?? null;
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
      const user = await authenticateApiKey(token);
      if (!user) {
        sendError(res, 401, "Invalid or expired API key");
        return;
      }
      req.user = user;
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
      const user = await authenticateApiKey(token);
      if (user) req.user = user;
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

      if (!member) {
        sendError(res, 404, "Workspace not found");
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
