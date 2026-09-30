/**
 * The in-app assistant chat route. See server/ai-chat.ts for the grounding
 * and prompt-injection defenses — this file is just auth, validation, and
 * error shaping.
 */
import { Router } from "express";
import { sendError, sendNotFound } from "./response";
import { createLogger } from "../logger";
import { requireWorkspaceRole } from "./auth-middleware";
import { assistantChatSchema } from "./schemas";
import { assistantReply } from "../ai-chat.js";

const log = createLogger("assistant-routes");

export const assistantRouter = Router();

const wsAuth = requireWorkspaceRole("owner", "admin", "analyst", "viewer");

// POST /api/workspaces/:workspaceId/assistant/chat
assistantRouter.post("/workspaces/:workspaceId/assistant/chat", wsAuth, async (req, res) => {
  const parsed = assistantChatSchema.safeParse(req.body);
  if (!parsed.success) {
    return sendError(res, 400, parsed.error.issues[0]?.message ?? "Invalid request");
  }
  try {
    const reply = await assistantReply({
      workspaceId: req.params.workspaceId as string,
      message: parsed.data.message,
      history: parsed.data.history,
      page: parsed.data.page,
    });
    res.json({ reply });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    log.warn({ err: message }, "Assistant chat failed");
    if (message === "Workspace not found") return sendNotFound(res, "Workspace");
    if (message.includes("not configured")) return sendError(res, 503, message);
    sendError(res, 500, "The assistant could not answer that. Try again.");
  }
});
