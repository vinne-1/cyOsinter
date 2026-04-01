import { Router } from "express";
import { z } from "zod";
import crypto from "crypto";
import { eq, and } from "drizzle-orm";
import { db } from "../db";
import { webhookEndpoints } from "@shared/schema";
import { requireAuth, requireWorkspaceRole } from "./auth-middleware";
import { sendError, sendValidationError, sendNotFound } from "./response";
import { createLogger } from "../logger";

const log = createLogger("webhooks");

export const webhooksRouter = Router();

const WEBHOOK_TIMEOUT_MS = 10_000;
const MAX_RETRIES = 3;

const createWebhookSchema = z.object({
  name: z.string().min(1, "Name is required"),
  url: z.string().url("Must be a valid URL"),
  secret: z.string().optional(),
  events: z.array(z.string()).min(1, "At least one event is required"),
  provider: z.enum(["generic", "slack", "teams", "pagerduty"]).default("generic"),
});

const updateWebhookSchema = z.object({
  name: z.string().min(1).optional(),
  url: z.string().url().optional(),
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

      res.json(rows);
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

      const [webhook] = await db
        .insert(webhookEndpoints)
        .values({
          workspaceId: req.params.workspaceId as string,
          name: parsed.data.name,
          url: parsed.data.url,
          secret: parsed.data.secret ?? null,
          events: parsed.data.events,
          provider: parsed.data.provider,
        })
        .returning();

      res.status(201).json(webhook);
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

      const [updated] = await db
        .update(webhookEndpoints)
        .set(parsed.data)
        .where(eq(webhookEndpoints.id, req.params.id as string))
        .returning();

      res.json(updated);
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

  switch (provider) {
    case "slack":
      body = JSON.stringify(formatSlackPayload(String(payload.event ?? "unknown"), payload));
      break;
    case "teams":
      body = JSON.stringify(formatTeamsPayload(String(payload.event ?? "unknown"), payload));
      break;
    case "pagerduty": {
      const pdPayload = formatPagerDutyPayload(String(payload.event ?? "unknown"), payload);
      if (webhook.secret) {
        (pdPayload as Record<string, unknown>).routing_key = webhook.secret;
      }
      body = JSON.stringify(pdPayload);
      break;
    }
    default:
      body = JSON.stringify(payload);
      if (webhook.secret) {
        headers["X-Webhook-Signature"] = signPayload(body, webhook.secret);
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
