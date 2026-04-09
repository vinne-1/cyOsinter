import { Router } from "express";
import { z } from "zod";
import { createLogger } from "../logger";
import { storage } from "../storage";
import { requireWorkspaceRole } from "./auth-middleware";
import { upsertPolicyDocument } from "../compliance-workflows";

const log = createLogger("routes:policies");

export const policiesRouter = Router();

const policyTypeSchema = z.enum([
  "access_control",
  "change_management",
  "incident_response",
  "risk_assessment",
  "vendor_management",
  "data_classification",
  "acceptable_use",
  "business_continuity",
]);

const generatePolicySchema = z.object({
  policyType: policyTypeSchema,
});

policiesRouter.get(
  "/workspaces/:workspaceId/policies",
  requireWorkspaceRole("owner", "admin", "analyst", "viewer"),
  async (req, res) => {
    try {
      const rows = await storage.getPolicyDocuments(String(req.params.workspaceId));
      res.json(rows);
    } catch (err) {
      log.error({ err }, "List policies failed");
      res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" });
    }
  },
);

policiesRouter.post(
  "/workspaces/:workspaceId/policies",
  requireWorkspaceRole("owner", "admin", "analyst"),
  async (req, res) => {
    try {
      const workspaceId = String(req.params.workspaceId);
      const parsed = generatePolicySchema.parse(req.body);
      const { data: findings } = await storage.getFindings(workspaceId, { limit: 500, offset: 0 });
      await upsertPolicyDocument(workspaceId, parsed.policyType, req.user?.id, findings);
      const updated = await storage.getPolicyDocumentByType(workspaceId, parsed.policyType);
      res.status(201).json(updated);
    } catch (err) {
      if (err instanceof z.ZodError) {
        return res.status(400).json({ message: err.errors[0]?.message ?? "Validation error" });
      }
      log.error({ err }, "Generate policy failed");
      res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" });
    }
  },
);

policiesRouter.delete(
  "/policies/:id",
  requireWorkspaceRole("owner", "admin"),
  async (req, res) => {
    try {
      const row = await storage.getPolicyDocument(String(req.params.id));
      if (!row) return res.status(404).json({ message: "Policy not found" });
      const workspaceId = String(req.query.workspaceId ?? "");
      if (!workspaceId || row.workspaceId !== workspaceId) {
        return res.status(403).json({ message: "Workspace mismatch for policy delete" });
      }
      await storage.deletePolicyDocument(row.id);
      res.status(204).send();
    } catch (err) {
      log.error({ err }, "Delete policy failed");
      res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" });
    }
  },
);

policiesRouter.get(
  "/workspaces/:workspaceId/policies/export",
  requireWorkspaceRole("owner", "admin", "analyst", "viewer"),
  async (req, res) => {
    try {
      const workspaceId = String(req.params.workspaceId);
      const docs = await storage.getPolicyDocuments(workspaceId);
      res.json(docs.map((d) => ({
        id: d.id,
        policyType: d.policyType,
        title: d.title,
        version: d.version,
        effectiveDate: d.effectiveDate,
        content: d.content,
      })));
    } catch (err) {
      log.error({ err }, "Export policies failed");
      res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" });
    }
  },
);

