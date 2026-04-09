import { Router } from "express";
import { z } from "zod";
import { createLogger } from "../logger";
import { storage } from "../storage";
import { requireWorkspaceRole } from "./auth-middleware";
import { runSecurityBaselineQuestionnaire } from "../compliance-workflows";

const log = createLogger("routes:questionnaires");

export const questionnairesRouter = Router();

const runQuestionnaireSchema = z.object({
  type: z.string().optional().default("security_baseline"),
});

questionnairesRouter.get(
  "/workspaces/:workspaceId/questionnaires",
  requireWorkspaceRole("owner", "admin", "analyst", "viewer"),
  async (req, res) => {
    try {
      const runs = await storage.getQuestionnaireRuns(String(req.params.workspaceId));
      res.json(runs);
    } catch (err) {
      log.error({ err }, "List questionnaires failed");
      res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" });
    }
  },
);

questionnairesRouter.get(
  "/questionnaires/:id",
  requireWorkspaceRole("owner", "admin", "analyst", "viewer"),
  async (req, res) => {
    try {
      const run = await storage.getQuestionnaireRun(String(req.params.id));
      if (!run) return res.status(404).json({ message: "Questionnaire run not found" });
      const workspaceId = String(req.query.workspaceId ?? "");
      if (!workspaceId || run.workspaceId !== workspaceId) {
        return res.status(403).json({ message: "Workspace mismatch for questionnaire run" });
      }
      res.json(run);
    } catch (err) {
      log.error({ err }, "Get questionnaire run failed");
      res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" });
    }
  },
);

questionnairesRouter.post(
  "/workspaces/:workspaceId/questionnaires",
  requireWorkspaceRole("owner", "admin", "analyst"),
  async (req, res) => {
    try {
      const workspaceId = String(req.params.workspaceId);
      const parsed = runQuestionnaireSchema.parse(req.body);
      if (parsed.type !== "security_baseline") {
        return res.status(400).json({ message: "Only security_baseline is supported in phase 1" });
      }
      const payload = await runSecurityBaselineQuestionnaire(workspaceId, req.user?.id);
      const created = await storage.createQuestionnaireRun(payload);
      res.status(201).json(created);
    } catch (err) {
      if (err instanceof z.ZodError) {
        return res.status(400).json({ message: err.errors[0]?.message ?? "Validation error" });
      }
      log.error({ err }, "Run questionnaire failed");
      res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" });
    }
  },
);

