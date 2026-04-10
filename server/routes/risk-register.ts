import { Router } from "express";
import { z } from "zod";
import { storage } from "../storage";
import { createLogger } from "../logger";
import { applyRiskItemUpdate, autoSeedRiskRegister } from "../compliance-workflows";
import { requireWorkspaceRole } from "./auth-middleware";

const log = createLogger("routes:risk-register");

export const riskRegisterRouter = Router();

const createRiskItemSchema = z.object({
  title: z.string().min(1),
  description: z.string().min(1),
  category: z.string().default("technical"),
  likelihood: z.enum(["low", "medium", "high"]).default("medium"),
  impact: z.enum(["low", "medium", "high"]).default("medium"),
  owner: z.string().nullable().optional(),
  treatment: z.enum(["mitigate", "accept", "transfer", "avoid"]).default("mitigate"),
  treatmentPlan: z.string().nullable().optional(),
  status: z.enum(["open", "in_progress", "accepted", "resolved"]).default("open"),
  reviewCadenceDays: z.number().int().min(1).max(365).default(90),
  reviewNotes: z.string().nullable().optional(),
  relatedFindingId: z.string().nullable().optional(),
});

const updateRiskItemSchema = createRiskItemSchema.partial();

riskRegisterRouter.get(
  "/workspaces/:workspaceId/risk-register",
  requireWorkspaceRole("owner", "admin", "analyst", "viewer"),
  async (req, res) => {
    try {
      const workspaceId = String(req.params.workspaceId);
      const items = await storage.getRiskItems(workspaceId);
      res.json(items);
    } catch (err) {
      log.error({ err }, "Get risk register failed");
      res.status(500).json({ message: "Internal error" });
    }
  },
);

riskRegisterRouter.post(
  "/workspaces/:workspaceId/risk-register/seed",
  requireWorkspaceRole("owner", "admin", "analyst"),
  async (req, res) => {
    try {
      const workspaceId = String(req.params.workspaceId);
      const result = await autoSeedRiskRegister(workspaceId);
      const items = await storage.getRiskItems(workspaceId);
      res.json({ ...result, total: items.length, items });
    } catch (err) {
      log.error({ err }, "Auto-seed risk register failed");
      res.status(500).json({ message: "Internal error" });
    }
  },
);

riskRegisterRouter.post(
  "/workspaces/:workspaceId/risk-register",
  requireWorkspaceRole("owner", "admin", "analyst"),
  async (req, res) => {
    try {
      const workspaceId = String(req.params.workspaceId);
      const parsed = createRiskItemSchema.parse(req.body);
      const fingerprint = `${workspaceId}:${Date.now()}:${Math.random().toString(36).slice(2, 8)}`;
      const created = await storage.createRiskItem({
        workspaceId,
        fingerprint,
        title: parsed.title,
        description: parsed.description,
        category: parsed.category,
        likelihood: parsed.likelihood,
        impact: parsed.impact,
        riskScore: 0,
        riskLevel: "low",
        owner: parsed.owner ?? null,
        treatment: parsed.treatment,
        treatmentPlan: parsed.treatmentPlan ?? null,
        status: parsed.status,
        reviewCadenceDays: parsed.reviewCadenceDays,
        reviewNotes: parsed.reviewNotes ?? null,
        relatedFindingId: parsed.relatedFindingId ?? null,
        lastReviewedAt: null,
      });
      const updated = await applyRiskItemUpdate(created.id, {
        likelihood: parsed.likelihood,
        impact: parsed.impact,
      });
      res.status(201).json(updated ?? created);
    } catch (err) {
      if (err instanceof z.ZodError) {
        return res.status(400).json({ message: err.errors[0]?.message ?? "Validation error" });
      }
      log.error({ err }, "Create risk item failed");
      res.status(500).json({ message: "Internal error" });
    }
  },
);

riskRegisterRouter.patch(
  "/risk-register/:id",
  requireWorkspaceRole("owner", "admin", "analyst"),
  async (req, res) => {
    try {
      const parsed = updateRiskItemSchema.parse(req.body);
      const existing = await storage.getRiskItem(String(req.params.id));
      if (!existing) return res.status(404).json({ message: "Risk item not found" });
      const workspaceId = String(req.query.workspaceId ?? "");
      if (!workspaceId || existing.workspaceId !== workspaceId) {
        return res.status(403).json({ message: "Workspace mismatch for risk item update" });
      }
      const updated = await applyRiskItemUpdate(existing.id, {
        ...parsed,
        owner: parsed.owner ?? undefined,
        treatmentPlan: parsed.treatmentPlan ?? undefined,
        reviewNotes: parsed.reviewNotes ?? undefined,
        relatedFindingId: parsed.relatedFindingId ?? undefined,
      });
      res.json(updated);
    } catch (err) {
      if (err instanceof z.ZodError) {
        return res.status(400).json({ message: err.errors[0]?.message ?? "Validation error" });
      }
      log.error({ err }, "Update risk item failed");
      res.status(500).json({ message: "Internal error" });
    }
  },
);

riskRegisterRouter.delete(
  "/risk-register/:id",
  requireWorkspaceRole("owner", "admin", "analyst"),
  async (req, res) => {
    try {
      const existing = await storage.getRiskItem(String(req.params.id));
      if (!existing) return res.status(404).json({ message: "Risk item not found" });
      const workspaceId = String(req.query.workspaceId ?? "");
      if (!workspaceId || existing.workspaceId !== workspaceId) {
        return res.status(403).json({ message: "Workspace mismatch for risk item delete" });
      }
      await storage.deleteRiskItem(existing.id);
      res.status(204).send();
    } catch (err) {
      log.error({ err }, "Delete risk item failed");
      res.status(500).json({ message: "Internal error" });
    }
  },
);

riskRegisterRouter.get(
  "/workspaces/:workspaceId/risk-register/export",
  requireWorkspaceRole("owner", "admin", "analyst", "viewer"),
  async (req, res) => {
    try {
      const workspaceId = String(req.params.workspaceId);
      const format = String(req.query.format ?? "json").toLowerCase();
      const items = await storage.getRiskItems(workspaceId);
      if (format === "csv") {
        const lines = [
          "id,title,category,likelihood,impact,riskScore,riskLevel,status,treatment,owner",
          ...items.map((r) => [
            r.id,
            JSON.stringify(r.title),
            r.category,
            r.likelihood,
            r.impact,
            String(r.riskScore),
            r.riskLevel,
            r.status,
            r.treatment,
            JSON.stringify(r.owner ?? ""),
          ].join(",")),
        ];
        res.setHeader("Content-Type", "text/csv; charset=utf-8");
        return res.send(lines.join("\n"));
      }
      res.json(items);
    } catch (err) {
      log.error({ err }, "Export risk register failed");
      res.status(500).json({ message: "Internal error" });
    }
  },
);
