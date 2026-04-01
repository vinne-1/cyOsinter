import crypto from "crypto";
import { eq, and, lt } from "drizzle-orm";
import { db } from "./db";
import { users, sessions } from "@shared/schema";
import type { User, Session } from "@shared/schema";
import { createLogger } from "./logger";

const log = createLogger("auth");

const SCRYPT_KEY_LEN = 64;
const SALT_LEN = 16;
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(SALT_LEN).toString("hex");
  const hash = crypto.scryptSync(password, salt, SCRYPT_KEY_LEN).toString("hex");
  return `${salt}:${hash}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [salt, storedHash] = stored.split(":");
  if (!salt || !storedHash) return false;
  const hash = crypto.scryptSync(password, salt, SCRYPT_KEY_LEN).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(storedHash, "hex"));
}

export function generateToken(): string {
  return crypto.randomBytes(32).toString("hex");
}

export function generateRefreshToken(): string {
  return crypto.randomBytes(32).toString("hex");
}

export async function createSession(
  userId: string,
  ipAddress?: string,
  userAgent?: string,
): Promise<Session> {
  const token = generateToken();
  const refreshToken = generateRefreshToken();
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS);

  const [session] = await db
    .insert(sessions)
    .values({ userId, token, refreshToken, expiresAt, ipAddress: ipAddress ?? null, userAgent: userAgent ?? null })
    .returning();

  log.info({ userId, sessionId: session.id }, "Session created");
  return session;
}

export async function validateSession(
  token: string,
): Promise<{ user: User; session: Session } | null> {
  const [session] = await db
    .select()
    .from(sessions)
    .where(eq(sessions.token, token))
    .limit(1);

  if (!session) return null;
  if (new Date(session.expiresAt) < new Date()) {
    await db.delete(sessions).where(eq(sessions.id, session.id));
    return null;
  }

  const [user] = await db
    .select()
    .from(users)
    .where(eq(users.id, session.userId))
    .limit(1);

  if (!user) return null;
  return { user, session };
}

export async function refreshSession(
  refreshToken: string,
): Promise<{ token: string; refreshToken: string; expiresAt: Date } | null> {
  const [session] = await db
    .select()
    .from(sessions)
    .where(eq(sessions.refreshToken, refreshToken))
    .limit(1);

  if (!session) return null;

  const newToken = generateToken();
  const newRefreshToken = generateRefreshToken();
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS);

  await db
    .update(sessions)
    .set({ token: newToken, refreshToken: newRefreshToken, expiresAt })
    .where(eq(sessions.id, session.id));

  log.info({ sessionId: session.id }, "Session refreshed");
  return { token: newToken, refreshToken: newRefreshToken, expiresAt };
}

export async function deleteSession(token: string): Promise<void> {
  await db.delete(sessions).where(eq(sessions.token, token));
}

export async function deleteUserSessions(userId: string): Promise<void> {
  await db.delete(sessions).where(eq(sessions.userId, userId));
}

export async function cleanExpiredSessions(): Promise<number> {
  const now = new Date();
  const result = await db
    .delete(sessions)
    .where(lt(sessions.expiresAt, now))
    .returning();

  const deleted = result.length;
  if (deleted > 0) {
    log.info({ count: deleted }, "Cleaned expired sessions");
  }
  return deleted;
}
