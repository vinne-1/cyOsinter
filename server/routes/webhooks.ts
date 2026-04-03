import { Router } from "express";
import { z } from "zod";
import crypto from "crypto";
import dns from "dns/promises";
import { eq, and } from "drizzle-orm";
import { db } from "../db";
import { webhookEndpoints } from "@shared/schema";
import { requireAuth, requireWorkspaceRole } from "./auth-middleware";
import { sendError, sendValidationError, sendNotFound } from "./response";
import { encrypt, decrypt } from "../crypto";
import { createLogger } from "../logger";

/** Check if a hostname resolves to a private/loopback IP (SSRF prevention) */
async function isPrivateHost(hostname: string): Promise<boolean> {
  try {
    const addrs = await dns.resolve4(hostname);
    return addrs.some((ip) => {
      const parts = ip.split(".").map(Number);
      return (
        parts[0] === 127 ||
        parts[0] === 10 ||
        (parts[0] === 172 && parts[1]! >= 16 && parts[1]! <= 31) ||
        (parts[0] === 192 && parts[1] === 168) ||
        (parts[0] === 169 && parts[1] === 254) ||
        parts[0] === 0
      );
    });
  } catch {
    return true; // fail-closed: if DNS resolution fails, treat as private
  }
}

/** Omit the secret from a webhook row for API responses */
function sanitizeWebhook(row: typeof webhookEndpoints.$inferSelect) {
  const { secret: _secret, ...rest } = row;
  return { ...rest, hasSecret: !!_secret };
}

const log = createLogger("webhooks");

export const webhooksRouter = Router();

const WEBHOOK_TIMEOUT_MS = 10_000;
const MAX_RETRIES = 3;

const createWebhookSchema = z.object({
  name: z.string().min(1, "Name is required"),
  url: z.string().url("Must be a valid URL").refine(
    (u) => { try { return new URL(u).protocol === "https:"; } catch { return false; } },
    "Webhook URL must use HTTPS",
  ),
  secret: z.string().optional(),
  events: z.array(z.string()).min(1, "At least one event is required"),
  provider: z.enum(["generic", "slack", "teams", "pagerduty"]).default("generic"),
});

const updateWebhookSchema = z.object({
  name: z.string().min(1).optional(),
  url: z.string().url().refine(
    (u) => { try { return new URL(u).protocol === "https:"; } catch { return false; } },
    "Webhook URL must use HTTPS",
  ).optional(),
  secret: z.string().nullable().optional(),
  events: z.array(z.string()).min(1).optional(),
  provider: z.enum(["generic", "slack", "teams", "pagerduty"]).optional(),
  enabled: z.boolean().optional(),
});

// GET /workspaces/:workspaceId/webhooks
webhooksRouter.get(
  "/workspaces/:workspaceId/webhooks",
  requireAuth,
  requireWorkspaceRole("owner", "admin", "analyst"),
  async (req, res) => {
    try {
      const rows = await db
        .select()
        .from(webhookEndpoints)
        .where(eq(webhookEndpoints.workspaceId, req.params.workspaceId as string));

      res.json(rows.map(sanitizeWebhook));
    } catch (err) {
      log.error({ err }, "Failed to list webhooks");
      sendError(res, 500, "Failed to list webhooks");
    }
  },
);

// POST /workspaces/:workspaceId/webhooks
webhooksRouter.post(
  "/workspaces/:workspaceId/webhooks",
  requireAuth,
  requireWorkspaceRole("owner", "admin"),
  async (req, res) => {
    try {
      const parsed = createWebhookSchema.safeParse(req.body);
      if (!parsed.success) {
        return sendValidationError(res, parsed.error.errors[0]?.message ?? "Validation error");
      }

      // SSRF protection: reject private/loopback webhook URLs
      const webhookHost = new URL(parsed.data.url).hostname;
      if (await isPrivateHost(webhookHost)) {
        return sendError(res, 400, "Webhook URL must not target private or internal networks");
      }

      const encryptedSecret = parsed.data.secret ? encrypt(parsed.data.secret) : null;

      const [webhook] = await db
        .insert(webhookEndpoints)
        .values({
          workspaceId: req.params.workspaceId as string,
          name: parsed.data.name,
          url: parsed.data.url,
          secret: encryptedSecret,
          events: parsed.data.events,
          provider: parsed.data.provider,
        })
        .returning();

      res.status(201).json(sanitizeWebhook(webhook));
    } catch (err) {
      log.error({ err }, "Failed to create webhook");
      sendError(res, 500, "Failed to create webhook");
    }
  },
);

// PATCH /webhooks/:id
webhooksRouter.patch(
  "/webhooks/:id",
  requireAuth,
  async (req, res) => {
    try {
      const parsed = updateWebhookSchema.safeParse(req.body);
      if (!parsed.success) {
        return sendValidationError(res, parsed.error.errors[0]?.message ?? "Validation error");
      }

      const [existing] = await db
        .select()
        .from(webhookEndpoints)
        .where(eq(webhookEndpoints.id, req.params.id as string))
        .limit(1);

      if (!existing) {
        return sendNotFound(res, "Webhook");
      }

      // Verify caller has admin+ role in the webhook's workspace
      const { workspaceMembers } = await import("@shared/schema");
      const [member] = await db
        .select()
        .from(workspaceMembers)
        .where(and(eq(workspaceMembers.workspaceId, existing.workspaceId), eq(workspaceMembers.userId, req.user!.id)))
        .limit(1);
      if (!member || !["owner", "admin"].includes(member.role)) {
        return sendError(res, 403, "Forbidden");
      }

      // SSRF protection on URL update
      if (parsed.data.url) {
        const webhookHost = new URL(parsed.data.url).hostname;
        if (await isPrivateHost(webhookHost)) {
          return sendError(res, 400, "Webhook URL must not target private or internal networks");
        }
      }

      const updates = { ...parsed.data } as Record<string, unknown>;
      if (parsed.data.secret !== undefined) {
        updates.secret = parsed.data.secret ? encrypt(parsed.data.secret) : null;
      }

      const [updated] = await db
        .update(webhookEndpoints)
        .set(updates)
        .where(eq(webhookEndpoints.id, req.params.id as string))
        .returning();

      res.json(sanitizeWebhook(updated));
    } catch (err) {
      log.error({ err }, "Failed to update webhook");
      sendError(res, 500, "Failed to update webhook");
    }
  },
);

// DELETE /webhooks/:id
webhooksRouter.delete(
  "/webhooks/:id",
  requireAuth,
  async (req, res) => {
    try {
      const [existing] = await db
        .select()
        .from(webhookEndpoints)
        .where(eq(webhookEndpoints.id, req.params.id as string))
        .limit(1);

      if (!existing) {
        return sendNotFound(res, "Webhook");
      }

      // Verify workspace ownership
      const { workspaceMembers } = await import("@shared/schema");
      const [member] = await db
        .select()
        .from(workspaceMembers)
        .where(and(eq(workspaceMembers.workspaceId, existing.workspaceId), eq(workspaceMembers.userId, req.user!.id)))
        .limit(1);
      if (!member || !["owner", "admin"].includes(member.role)) {
        return sendError(res, 403, "Forbidden");
      }

      await db.delete(webhookEndpoints).where(eq(webhookEndpoints.id, req.params.id as string));
      res.json({ success: true });
    } catch (err) {
      log.error({ err }, "Failed to delete webhook");
      sendError(res, 500, "Failed to delete webhook");
    }
  },
);

// POST /webhooks/:id/test
webhooksRouter.post(
  "/webhooks/:id/test",
  requireAuth,
  async (req, res) => {
    try {
      const [webhook] = await db
        .select()
        .from(webhookEndpoints)
        .where(eq(webhookEndpoints.id, req.params.id as string))
        .limit(1);

      if (!webhook) {
        return sendNotFound(res, "Webhook");
      }

      const testPayload = {
        event: "test",
        timestamp: new Date().toISOString(),
        data: { message: "This is a test webhook delivery from Cyber Shield Pro" },
      };

      const result = await deliverWebhook(webhook, testPayload);
      res.json({ success: result.ok, statusCode: result.statusCode, error: result.error });
    } catch (err) {
      log.error({ err }, "Webhook test failed");
      sendError(res, 500, "Webhook test failed");
    }
  },
);

// ── Webhook Dispatch ──

interface DeliveryResult {
  ok: boolean;
  statusCode?: number;
  error?: string;
}

function signPayload(body: string, secret: string): string {
  return crypto.createHmac("sha256", secret).update(body).digest("hex");
}

function formatSlackPayload(event: string, payload: Record<string, unknown>): Record<string, unknown> {
  return {
    blocks: [
      {
        type: "header",
        text: { type: "plain_text", text: `Cyber Shield Pro: ${event}` },
      },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `*Event:* \`${event}\`\n*Time:* ${new Date().toISOString()}`,
        },
      },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `\`\`\`${JSON.stringify(payload, null, 2).slice(0, 2900)}\`\`\``,
        },
      },
    ],
  };
}

function formatTeamsPayload(event: string, payload: Record<string, unknown>): Record<string, unknown> {
  return {
    type: "message",
    attachments: [
      {
        contentType: "application/vnd.microsoft.card.adaptive",
        content: {
          $schema: "http://adaptivecards.io/schemas/adaptive-card.json",
          type: "AdaptiveCard",
          version: "1.4",
          body: [
            {
              type: "TextBlock",
              text: `Cyber Shield Pro: ${event}`,
              weight: "Bolder",
              size: "Medium",
            },
            {
              type: "TextBlock",
              text: JSON.stringify(payload, null, 2).slice(0, 2900),
              wrap: true,
              fontType: "Monospace",
            },
          ],
        },
      },
    ],
  };
}

function formatPagerDutyPayload(event: string, payload: Record<string, unknown>): Record<string, unknown> {
  return {
    routing_key: "", // will be overridden by webhook secret as integration key
    event_action: "trigger",
    payload: {
      summary: `Cyber Shield Pro: ${event}`,
      source: "cyber-shield-pro",
      severity: "warning",
      custom_details: payload,
    },
  };
}

async function deliverWebhook(
  webhook: typeof webhookEndpoints.$inferSelect,
  payload: Record<string, unknown>,
): Promise<DeliveryResult> {
  const provider = webhook.provider ?? "generic";
  let body: string;
  const headers: Record<string, string> = { "Content-Type": "application/json" };

  // Decrypt the stored secret for use in signing/routing
  let plainSecret: string | null = null;
  if (webhook.secret) {
    try { plainSecret = decrypt(webhook.secret); } catch { plainSecret = webhook.secret; /* legacy unencrypted */ }
  }

  switch (provider) {
    case "slack":
      body = JSON.stringify(formatSlackPayload(String(payload.event ?? "unknown"), payload));
      break;
    case "teams":
      body = JSON.stringify(formatTeamsPayload(String(payload.event ?? "unknown"), payload));
      break;
    case "pagerduty": {
      const pdPayload = formatPagerDutyPayload(String(payload.event ?? "unknown"), payload);
      if (plainSecret) {
        (pdPayload as Record<string, unknown>).routing_key = plainSecret;
      }
      body = JSON.stringify(pdPayload);
      break;
    }
    default:
      body = JSON.stringify(payload);
      if (plainSecret) {
        headers["X-Webhook-Signature"] = signPayload(body, plainSecret);
      }
      break;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), WEBHOOK_TIMEOUT_MS);

  try {
    const response = await fetch(webhook.url, {
      method: "POST",
      headers,
      body,
      signal: controller.signal,
    });
    clearTimeout(timeout);

    return { ok: response.ok, statusCode: response.status };
  } catch (err) {
    clearTimeout(timeout);
    const message = err instanceof Error ? err.message : "Unknown error";
    return { ok: false, error: message };
  }
}

/**
 * Dispatches a webhook event to all matching enabled endpoints for a workspace.
 * Retries up to MAX_RETRIES on failure and updates failCount.
 */
export async function dispatchWebhookEvent(
  workspaceId: string,
  event: string,
  payload: Record<string, unknown>,
): Promise<void> {
  try {
    const endpoints = await db
      .select()
      .from(webhookEndpoints)
      .where(
        and(
          eq(webhookEndpoints.workspaceId, workspaceId),
          eq(webhookEndpoints.enabled, true),
        ),
      );

    const matching = endpoints.filter(
      (ep) => ep.events && ep.events.includes(event),
    );

    const fullPayload = { event, timestamp: new Date().toISOString(), ...payload };

    const deliveries = matching.map(async (endpoint) => {
      let result: DeliveryResult = { ok: false };

      for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
        result = await deliverWebhook(endpoint, fullPayload);
        if (result.ok) break;
        log.warn(
          { webhookId: endpoint.id, attempt: attempt + 1, error: result.error },
          "Webhook delivery failed, retrying",
        );
      }

      if (result.ok) {
        await db
          .update(webhookEndpoints)
          .set({ lastTriggeredAt: new Date(), failCount: 0 })
          .where(eq(webhookEndpoints.id, endpoint.id));
      } else {
        await db
          .update(webhookEndpoints)
          .set({
            lastTriggeredAt: new Date(),
            failCount: (endpoint.failCount ?? 0) + 1,
          })
          .where(eq(webhookEndpoints.id, endpoint.id));
        log.error(
          { webhookId: endpoint.id, event, error: result.error },
          "Webhook delivery failed after retries",
        );
      }
    });

    await Promise.allSettled(deliveries);
  } catch (err) {
    log.error({ err, workspaceId, event }, "Webhook dispatch error");
  }
}
