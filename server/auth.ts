import crypto from "crypto";
import { eq, and, lt, isNotNull } from "drizzle-orm";
import { db } from "./db";
import { users, sessions } from "@shared/schema";
import type { User, Session } from "@shared/schema";
import { createLogger } from "./logger";

const log = createLogger("auth");

const SCRYPT_KEY_LEN = 64;
const SCRYPT_PARAMS = { N: 65536, r: 8, p: 1, maxmem: 128 * 1024 * 1024 }; // OWASP recommended minimum; maxmem=128MB
const SALT_LEN = 16;
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

/** Failed logins before an account is temporarily locked. */
export const MAX_FAILED_LOGINS = 5;
/** Base lockout, doubled for each failure past the threshold, up to the cap. */
export const LOCKOUT_BASE_MS = 60 * 1000;
export const LOCKOUT_MAX_MS = 60 * 60 * 1000;

/**
 * Hashes a bearer/refresh token for storage.
 *
 * SHA-256 rather than scrypt: the token is 256 bits of CSPRNG output, so there
 * is no guessable input to slow an attacker down on, and a KDF would add real
 * latency to every authenticated request. Password hashing is a different
 * problem and still uses scrypt above.
 */
export function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function scryptAsync(password: string, salt: string, keyLen: number, options: crypto.ScryptOptions): Promise<Buffer> {
  return new Promise((resolve, reject) =>
    crypto.scrypt(password, salt, keyLen, options, (err, key) => (err ? reject(err) : resolve(key))),
  );
}

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(SALT_LEN).toString("hex");
  const hash = (await scryptAsync(password, salt, SCRYPT_KEY_LEN, SCRYPT_PARAMS)).toString("hex");
  return `${salt}:${hash}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [salt, storedHash] = stored.split(":");
  if (!salt || !storedHash) return false;
  const hash = (await scryptAsync(password, salt, SCRYPT_KEY_LEN, SCRYPT_PARAMS)).toString("hex");
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
    .values({
      userId,
      // Only the hashes are persisted; the caller receives the plaintext once
      // and it is never recoverable from the database again.
      token: hashToken(token),
      refreshToken: hashToken(refreshToken),
      expiresAt,
      ipAddress: ipAddress ?? null,
      userAgent: userAgent ?? null,
    })
    .returning();

  // A fresh login starts its own family; rotations inherit this id.
  await db.update(sessions).set({ familyId: session.id }).where(eq(sessions.id, session.id));

  log.info({ userId, sessionId: session.id }, "Session created");
  // Hand back the plaintext tokens so the client can actually use them.
  return { ...session, token, refreshToken, familyId: session.id };
}

export async function validateSession(
  token: string,
): Promise<{ user: User; session: Session } | null> {
  const [session] = await db
    .select()
    .from(sessions)
    .where(eq(sessions.token, hashToken(token)))
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
    .where(eq(sessions.refreshToken, hashToken(refreshToken)))
    .limit(1);

  if (!session) return null;

  // ── Reuse detection ──
  // Refresh tokens are single-use. The spent row is kept (with its old hashes)
  // precisely so a replay lands here. If it does, the token leaked — and we
  // cannot tell whether the legitimate client or the attacker is presenting it,
  // so the entire family descended from that login is revoked.
  if (session.rotatedAt) {
    const family = session.familyId ?? session.id;
    log.warn(
      { sessionId: session.id, userId: session.userId, family },
      "Refresh token reuse detected — revoking session family",
    );
    await db.delete(sessions).where(eq(sessions.familyId, family));
    // Belt and braces: a pre-migration row may have no familyId of its own.
    await db.delete(sessions).where(eq(sessions.id, session.id));
    return null;
  }

  // Enforce refresh token TTL — reject if the family was created more than 30
  // days ago. Rotation must not extend a session indefinitely.
  const sessionAge = Date.now() - new Date(session.createdAt ?? Date.now()).getTime();
  if (sessionAge > REFRESH_TTL_MS) {
    await db.delete(sessions).where(eq(sessions.id, session.id));
    log.info({ sessionId: session.id }, "Refresh token expired (30-day limit)");
    return null;
  }

  const newToken = generateToken();
  const newRefreshToken = generateRefreshToken();
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
  const family = session.familyId ?? session.id;

  // Mark the old row spent rather than overwriting it, so the previous token
  // remains findable for the reuse check above.
  await db.update(sessions).set({ rotatedAt: new Date() }).where(eq(sessions.id, session.id));

  await db.insert(sessions).values({
    userId: session.userId,
    token: hashToken(newToken),
    refreshToken: hashToken(newRefreshToken),
    expiresAt,
    ipAddress: session.ipAddress,
    userAgent: session.userAgent,
    familyId: family,
    // Inherit the original login time so the 30-day family TTL keeps counting
    // from the real login, not from the most recent refresh.
    createdAt: session.createdAt,
  });

  log.info({ sessionId: session.id, family }, "Session refreshed");
  return { token: newToken, refreshToken: newRefreshToken, expiresAt };
}

export async function deleteSession(token: string): Promise<void> {
  await db.delete(sessions).where(eq(sessions.token, hashToken(token)));
}

export async function deleteUserSessions(userId: string): Promise<void> {
  await db.delete(sessions).where(eq(sessions.userId, userId));
}

/** True while the account is inside a lockout window. */
export function isLockedOut(user: { lockedUntil?: Date | null }): boolean {
  return !!user.lockedUntil && new Date(user.lockedUntil) > new Date();
}

/** Seconds remaining on a lockout, for the client-facing message. */
export function lockoutSecondsRemaining(user: { lockedUntil?: Date | null }): number {
  if (!user.lockedUntil) return 0;
  return Math.max(0, Math.ceil((new Date(user.lockedUntil).getTime() - Date.now()) / 1000));
}

/**
 * Lockout duration after `attempts` consecutive failures.
 *
 * Doubles per failure past the threshold and is capped, so a legitimate user who
 * mistypes a few times is inconvenienced for a minute while a sustained
 * guessing run is throttled to a handful of attempts per hour.
 */
export function lockoutDurationMs(attempts: number): number {
  if (attempts < MAX_FAILED_LOGINS) return 0;
  const over = attempts - MAX_FAILED_LOGINS;
  return Math.min(LOCKOUT_BASE_MS * 2 ** over, LOCKOUT_MAX_MS);
}

/**
 * Records a failed login and locks the account once the threshold is crossed.
 * Returns the new attempt count and lockout expiry, if any.
 */
export async function recordFailedLogin(
  userId: string,
): Promise<{ attempts: number; lockedUntil: Date | null }> {
  const [user] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
  if (!user) return { attempts: 0, lockedUntil: null };

  const attempts = (user.failedLoginAttempts ?? 0) + 1;
  const duration = lockoutDurationMs(attempts);
  const lockedUntil = duration > 0 ? new Date(Date.now() + duration) : null;

  await db
    .update(users)
    .set({ failedLoginAttempts: attempts, lockedUntil })
    .where(eq(users.id, userId));

  if (lockedUntil) {
    log.warn({ userId, attempts, lockedUntil }, "Account locked after repeated failed logins");
  }
  return { attempts, lockedUntil };
}

/** Clears the failure counter after a successful authentication. */
export async function clearFailedLogins(userId: string): Promise<void> {
  await db
    .update(users)
    .set({ failedLoginAttempts: 0, lockedUntil: null, lastLoginAt: new Date() })
    .where(eq(users.id, userId));
}

export async function cleanExpiredSessions(): Promise<number> {
  const now = new Date();
  const result = await db
    .delete(sessions)
    .where(lt(sessions.expiresAt, now))
    .returning();

  // Rotation keeps spent rows so reuse stays detectable, but they only need to
  // outlive the window in which a stolen token could plausibly be replayed.
  const spent = await db
    .delete(sessions)
    .where(and(isNotNull(sessions.rotatedAt), lt(sessions.rotatedAt, new Date(Date.now() - REFRESH_TTL_MS))))
    .returning();

  const deleted = result.length + spent.length;
  if (deleted > 0) {
    log.info({ count: deleted, expired: result.length, spent: spent.length }, "Cleaned expired sessions");
  }
  return deleted;
}
