import { Router } from "express";
import { z } from "zod";
import { eq } from "drizzle-orm";
import { db } from "../db";
import { users } from "@shared/schema";
import {
  hashPassword,
  verifyPassword,
  createSession,
  deleteSession,
  deleteUserSessions,
  refreshSession,
  isLockedOut,
  lockoutSecondsRemaining,
  recordFailedLogin,
  clearFailedLogins,
} from "../auth";
import { requireAuth } from "./auth-middleware";
import { sendError, sendValidationError } from "./response";
import { createLogger } from "../logger";
import { logAuditAsync, clientIp } from "../audit";
import { verifyTotp } from "../totp";
import { checkPassword, PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH } from "../password-policy";

const log = createLogger("auth-routes");

export const authRouter = Router();

const registerSchema = z.object({
  email: z.string().email("Invalid email address"),
  // Length is checked here so Zod can report it with the other field errors;
  // the full policy (common-password screening, ASVS V6.2.4) runs in the handler
  // where the email and name are available to compare against.
  password: z.string().min(PASSWORD_MIN_LENGTH, `Password must be at least ${PASSWORD_MIN_LENGTH} characters`)
    .max(PASSWORD_MAX_LENGTH, `Password must be at most ${PASSWORD_MAX_LENGTH} characters`),
  name: z.string().min(1, "Name is required").optional(),
});

const changePasswordSchema = z.object({
  // ASVS V6.2.3: the current password is required, so possession of a live
  // session is not on its own enough to take the account over.
  currentPassword: z.string().min(1, "Current password is required"),
  newPassword: z.string().min(PASSWORD_MIN_LENGTH, `Password must be at least ${PASSWORD_MIN_LENGTH} characters`)
    .max(PASSWORD_MAX_LENGTH, `Password must be at most ${PASSWORD_MAX_LENGTH} characters`),
});

const loginSchema = z.object({
  email: z.string().email("Invalid email address"),
  password: z.string().min(1, "Password is required"),
  totpCode: z.string().optional(),
});

const refreshSchema = z.object({
  refreshToken: z.string().min(1, "Refresh token is required"),
});

// POST /auth/register
authRouter.post("/auth/register", async (req, res) => {
  try {
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) {
      return sendValidationError(res, parsed.error.errors[0]?.message ?? "Validation error");
    }
    const { email, password, name } = parsed.data;

    const policy = checkPassword(password, [email, name]);
    if (!policy.ok) {
      return sendValidationError(res, policy.reason ?? "Password is not acceptable");
    }

    const [existing] = await db
      .select()
      .from(users)
      .where(eq(users.email, email.toLowerCase()))
      .limit(1);

    if (existing) {
      return sendError(res, 409, "A user with this email already exists");
    }

    const passwordHash = await hashPassword(password);

    const [user] = await db
      .insert(users)
      .values({
        email: email.toLowerCase(),
        passwordHash,
        name: name ?? null,
      })
      .returning();

    const session = await createSession(
      user.id,
      req.ip ?? undefined,
      req.headers["user-agent"],
    );

    log.info({ userId: user.id }, "User registered");
    logAuditAsync({
      userId: user.id,
      action: "user_registered",
      resourceType: "user",
      resourceId: user.id,
      metadata: { email: user.email },
      ipAddress: clientIp(req),
    });

    res.status(201).json({
      user: { id: user.id, email: user.email, name: user.name, role: user.role },
      token: session.token,
      refreshToken: session.refreshToken,
      expiresAt: session.expiresAt,
    });
  } catch (err) {
    log.error({ err }, "Registration failed");
    sendError(res, 500, "Registration failed");
  }
});

// POST /auth/login
authRouter.post("/auth/login", async (req, res) => {
  try {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      return sendValidationError(res, parsed.error.errors[0]?.message ?? "Validation error");
    }
    const { email, password, totpCode } = parsed.data;

    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.email, email.toLowerCase()))
      .limit(1);

    if (!user) {
      // No userId to attribute: the account does not exist. The attempted
      // address is recorded so credential-stuffing sweeps are still visible.
      logAuditAsync({
        userId: null,
        action: "login_failed",
        resourceType: "user",
        metadata: { email: email.toLowerCase(), reason: "unknown_account" },
        ipAddress: clientIp(req),
      });
      return sendError(res, 401, "Invalid email or password");
    }

    // Checked before the password so a locked account cannot be used as an
    // oracle: every attempt costs the same regardless of whether the guess was
    // right, and a correct password during lockout still fails.
    if (isLockedOut(user)) {
      const seconds = lockoutSecondsRemaining(user);
      logAuditAsync({
        userId: user.id,
        action: "login_failed",
        resourceType: "user",
        resourceId: user.id,
        metadata: { email: user.email, reason: "account_locked", secondsRemaining: seconds },
        ipAddress: clientIp(req),
      });
      return sendError(
        res,
        429,
        `Too many failed sign-in attempts. Try again in ${Math.ceil(seconds / 60)} minute(s).`,
      );
    }

    const valid = await verifyPassword(password, user.passwordHash);
    if (!valid) {
      const { attempts, lockedUntil } = await recordFailedLogin(user.id);
      logAuditAsync({
        userId: user.id,
        action: "login_failed",
        resourceType: "user",
        resourceId: user.id,
        metadata: { email: user.email, reason: "bad_password", attempts, locked: !!lockedUntil },
        ipAddress: clientIp(req),
      });
      // The response is identical whether or not the lockout just triggered, so
      // it does not reveal which addresses correspond to real accounts.
      return sendError(res, 401, "Invalid email or password");
    }

    // TOTP verification when MFA is enabled. See server/totp.ts — this is
    // RFC 6238, so codes interoperate with standard authenticator apps.
    if (user.totpEnabled && user.totpSecret) {
      if (!totpCode) {
        logAuditAsync({
          userId: user.id, action: "mfa_challenge_failed", resourceType: "user",
          resourceId: user.id, metadata: { reason: "code_missing" }, ipAddress: clientIp(req),
        });
        return sendError(res, 401, "TOTP code is required for this account");
      }
      if (!verifyTotp(user.totpSecret, totpCode)) {
        // Otherwise an attacker holding a valid password could brute-force the
        // 6-digit code without limit.
        await recordFailedLogin(user.id);
        logAuditAsync({
          userId: user.id, action: "mfa_challenge_failed", resourceType: "user",
          resourceId: user.id, metadata: { reason: "bad_code" }, ipAddress: clientIp(req),
        });
        return sendError(res, 401, "Invalid TOTP code");
      }
    }

    // Clears the failure counter and any lockout, and stamps lastLoginAt.
    await clearFailedLogins(user.id);

    const session = await createSession(
      user.id,
      req.ip ?? undefined,
      req.headers["user-agent"],
    );

    log.info({ userId: user.id }, "User logged in");
    logAuditAsync({
      userId: user.id,
      action: "login",
      resourceType: "user",
      resourceId: user.id,
      metadata: { email: user.email },
      ipAddress: clientIp(req),
    });

    res.json({
      user: { id: user.id, email: user.email, name: user.name, role: user.role },
      token: session.token,
      refreshToken: session.refreshToken,
      expiresAt: session.expiresAt,
    });
  } catch (err) {
    log.error({ err }, "Login failed");
    sendError(res, 500, "Login failed");
  }
});

// POST /auth/logout
authRouter.post("/auth/logout", requireAuth, async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.replace("Bearer ", "") ?? "";
    await deleteSession(token);
    logAuditAsync({
      userId: req.user?.id ?? null,
      action: "logout",
      resourceType: "user",
      resourceId: req.user?.id ?? null,
      ipAddress: clientIp(req),
    });
    res.json({ success: true });
  } catch (err) {
    log.error({ err }, "Logout failed");
    sendError(res, 500, "Logout failed");
  }
});

// POST /auth/refresh
authRouter.post("/auth/refresh", async (req, res) => {
  try {
    const parsed = refreshSchema.safeParse(req.body);
    if (!parsed.success) {
      return sendValidationError(res, parsed.error.errors[0]?.message ?? "Validation error");
    }

    const result = await refreshSession(parsed.data.refreshToken);
    if (!result) {
      return sendError(res, 401, "Invalid or expired refresh token");
    }

    res.json({
      token: result.token,
      refreshToken: result.refreshToken,
      expiresAt: result.expiresAt,
    });
  } catch (err) {
    log.error({ err }, "Token refresh failed");
    sendError(res, 500, "Token refresh failed");
  }
});

// GET /auth/me
authRouter.get("/auth/me", requireAuth, async (req, res) => {
  try {
    const user = req.user!;
    res.json({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      totpEnabled: user.totpEnabled,
      lastLoginAt: user.lastLoginAt,
      createdAt: user.createdAt,
    });
  } catch (err) {
    log.error({ err }, "Failed to get user info");
    sendError(res, 500, "Failed to get user info");
  }
});

/**
 * POST /auth/change-password
 *
 * There was no way to change a password at all. That is ASVS 5.0 V6.2.2 ("verify
 * that users can change their password"), but the practical point is worse than
 * the checklist one: a user who learns their password is compromised had no way
 * to rotate it, and an administrator had no way to tell them to.
 *
 * Three properties are deliberate:
 *
 *  - **The current password is required** (V6.2.3), so a stolen session token is
 *    not sufficient to seize the account permanently. Without it, anyone with a
 *    borrowed laptop or an XSS-lifted token could lock the real owner out.
 *  - **The new password goes through the full policy**, including the
 *    common-password screen — a change flow that skips the checks the
 *    registration flow applies is just a slower way to set a weak password.
 *  - **Every other session is terminated** and a fresh token is issued. Changing
 *    a password is the action people take when they believe someone else has
 *    access; leaving that someone else logged in makes it ceremonial. The caller
 *    gets a new token so their own session survives the revocation.
 */
authRouter.post("/auth/change-password", requireAuth, async (req, res) => {
  try {
    const parsed = changePasswordSchema.safeParse(req.body);
    if (!parsed.success) {
      return sendValidationError(res, parsed.error.errors[0]?.message ?? "Validation error");
    }
    const { currentPassword, newPassword } = parsed.data;

    // `requireAuth` guarantees this, but re-reading the row means the hash is
    // current rather than whatever was loaded when the session was minted.
    const userId = req.user?.id;
    if (!userId) return sendError(res, 401, "Authentication required");

    const [user] = await db.select().from(users).where(eq(users.id, userId)).limit(1);
    if (!user) return sendError(res, 401, "Authentication required");

    const valid = await verifyPassword(currentPassword, user.passwordHash);
    if (!valid) {
      logAuditAsync({
        userId: user.id,
        action: "password_change_failed",
        resourceType: "user",
        resourceId: user.id,
        ipAddress: clientIp(req),
      });
      // Deliberately not 401: the session is fine, the supplied password is not,
      // and a 401 would make the client discard a valid token and log the user out.
      return sendError(res, 400, "Current password is incorrect");
    }

    const policy = checkPassword(newPassword, [user.email, user.name]);
    if (!policy.ok) {
      return sendValidationError(res, policy.reason ?? "Password is not acceptable");
    }

    // Compared by hash, not by string: the old plaintext is never stored, and
    // this also catches a "change" that only altered surrounding whitespace.
    if (await verifyPassword(newPassword, user.passwordHash)) {
      return sendValidationError(res, "New password must be different from the current password");
    }

    const passwordHash = await hashPassword(newPassword);
    await db.update(users)
      .set({ passwordHash, updatedAt: new Date(), failedLoginAttempts: 0, lockedUntil: null })
      .where(eq(users.id, user.id));

    // Terminate everything, including this caller's own session, then re-issue.
    // Revoking first means there is no window in which the old tokens and the
    // new password are both valid.
    await deleteUserSessions(user.id);
    const session = await createSession(user.id, req.ip ?? undefined, req.headers["user-agent"]);

    logAuditAsync({
      userId: user.id,
      action: "password_changed",
      resourceType: "user",
      resourceId: user.id,
      ipAddress: clientIp(req),
    });
    log.info({ userId: user.id }, "Password changed; all sessions revoked");

    res.json({
      success: true,
      token: session.token,
      refreshToken: session.refreshToken,
      expiresAt: session.expiresAt,
    });
  } catch (err) {
    log.error({ err }, "Change password error");
    sendError(res, 500, "Failed to change password");
  }
});
