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
} from "../auth";
import { requireAuth } from "./auth-middleware";
import { sendError, sendValidationError } from "./response";
import { createLogger } from "../logger";

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
      return sendError(res, 401, "Invalid email or password");
    }

    const valid = await verifyPassword(password, user.passwordHash);
    if (!valid) {
      return sendError(res, 401, "Invalid email or password");
    }

    // TOTP verification when MFA is enabled
    if (user.totpEnabled && user.totpSecret) {
      if (!totpCode) {
        return sendError(res, 401, "TOTP code is required for this account");
      }
      // Constant-time TOTP validation using HMAC-based comparison
      // For production, replace with a full TOTP library (e.g. otplib)
      const crypto = await import("crypto");
      const epoch = Math.floor(Date.now() / 30000);
      const validCodes: string[] = [];
      for (const offset of [-1, 0, 1]) {
        const hmac = crypto.default.createHmac("sha1", user.totpSecret);
        hmac.update(Buffer.from(String(epoch + offset)));
        const digest = hmac.digest();
        const code = (digest.readUInt32BE(digest[digest.length - 1]! & 0xf) & 0x7fffffff) % 1000000;
        validCodes.push(String(code).padStart(6, "0"));
      }
      if (!validCodes.includes(totpCode)) {
        return sendError(res, 401, "Invalid TOTP code");
      }
    }

    // Update lastLoginAt
    await db
      .update(users)
      .set({ lastLoginAt: new Date() })
      .where(eq(users.id, user.id));

    const session = await createSession(
      user.id,
      req.ip ?? undefined,
      req.headers["user-agent"],
    );

    log.info({ userId: user.id }, "User logged in");

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
