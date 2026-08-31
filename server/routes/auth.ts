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

const log = createLogger("auth-routes");

export const authRouter = Router();

const registerSchema = z.object({
  email: z.string().email("Invalid email address"),
  password: z.string().min(12, "Password must be at least 12 characters"),
  name: z.string().min(1, "Name is required").optional(),
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
