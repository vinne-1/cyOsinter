import { Router } from "express";
import { z } from "zod";
import crypto from "crypto";
import { eq, and, isNull } from "drizzle-orm";
import { db } from "../db";
import { apiKeys } from "@shared/schema";
import { requireAuth } from "./auth-middleware";
import { sendError, sendValidationError, sendNotFound } from "./response";
import { createLogger } from "../logger";

const log = createLogger("api-keys");

export const apiKeysRouter = Router();

const createKeySchema = z.object({
  name: z.string().min(1, "Name is required"),
  scope: z.enum(["read", "scan", "full"]).default("read"),
  expiresAt: z.preprocess(
    (val) => (val === null || val === "" ? undefined : val),
    z.coerce.date().optional()
  ),
});

function generateApiKey(): string {
  const random = crypto.randomBytes(24).toString("hex");
  return `csk_${random}`;
}

function hashKey(key: string): string {
  return crypto.createHash("sha256").update(key).digest("hex");
}

// GET /api-keys — list user's API keys (key is masked)
apiKeysRouter.get(
  "/api-keys",
  requireAuth,
  async (req, res) => {
    try {
      const rows = await db
        .select({
          id: apiKeys.id,
          name: apiKeys.name,
          keyPrefix: apiKeys.keyPrefix,
          scope: apiKeys.scope,
          expiresAt: apiKeys.expiresAt,
          lastUsedAt: apiKeys.lastUsedAt,
          createdAt: apiKeys.createdAt,
          revokedAt: apiKeys.revokedAt,
        })
        .from(apiKeys)
        .where(eq(apiKeys.userId, req.user!.id));

      res.json(rows);
    } catch (err) {
      log.error({ err }, "Failed to list API keys");
      sendError(res, 500, "Failed to list API keys");
    }
  },
);

// POST /api-keys — create a new API key (returns full key once)
apiKeysRouter.post(
  "/api-keys",
  requireAuth,
  async (req, res) => {
    try {
      const parsed = createKeySchema.safeParse(req.body);
      if (!parsed.success) {
        return sendValidationError(res, parsed.error.errors[0]?.message ?? "Validation error");
      }

      const rawKey = generateApiKey();
      const keyHash = hashKey(rawKey);
      const keyPrefix = rawKey.slice(0, 8);

      const [record] = await db
        .insert(apiKeys)
        .values({
          userId: req.user!.id,
          name: parsed.data.name,
          keyHash,
          keyPrefix,
          scope: parsed.data.scope,
          expiresAt: parsed.data.expiresAt ?? null,
        })
        .returning();

      log.info({ keyId: record.id, userId: req.user!.id }, "API key created");

      res.status(201).json({
        id: record.id,
        name: record.name,
        key: rawKey, // returned only once
        keyPrefix: record.keyPrefix,
        scope: record.scope,
        expiresAt: record.expiresAt,
        createdAt: record.createdAt,
      });
    } catch (err) {
      log.error({ err }, "Failed to create API key");
      sendError(res, 500, "Failed to create API key");
    }
  },
);

// DELETE /api-keys/:id — revoke an API key
apiKeysRouter.delete(
  "/api-keys/:id",
  requireAuth,
  async (req, res) => {
    try {
      const [existing] = await db
        .select()
        .from(apiKeys)
        .where(
          and(
            eq(apiKeys.id, req.params.id as string),
            eq(apiKeys.userId, req.user!.id),
          ),
        )
        .limit(1);

      if (!existing) {
        return sendNotFound(res, "API key");
      }

      if (existing.revokedAt) {
        return sendError(res, 400, "API key is already revoked");
      }

      await db
        .update(apiKeys)
        .set({ revokedAt: new Date() })
        .where(eq(apiKeys.id, req.params.id as string));

      log.info({ keyId: req.params.id }, "API key revoked");
      res.json({ success: true });
    } catch (err) {
      log.error({ err }, "Failed to revoke API key");
      sendError(res, 500, "Failed to revoke API key");
    }
  },
);
