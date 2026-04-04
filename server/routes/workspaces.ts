import { Router } from "express";
import { z } from "zod";
import { storage } from "../storage";
import { createLogger } from "../logger";
import { createWorkspaceSchema, updateWorkspaceSchema, createAssetSchema } from "./schemas";
import { requireWorkspaceRole } from "./auth-middleware";

const routeLog = createLogger("routes");

export const workspacesRouter = Router();

workspacesRouter.get("/", async (req, res) => {
  try {
    const ws = await storage.getWorkspacesByUserId(req.user!.id);
    res.json(ws);
  } catch (err) {
    routeLog.error({ err }, "Get workspaces error");
    res.status(500).json({ message: "Internal server error" });
  }
});

workspacesRouter.post("/:workspaceId/purge", requireWorkspaceRole("owner"), async (req, res) => {
  try {
    const workspaceId = req.params.workspaceId as string;
    const ws = await storage.getWorkspace(workspaceId);
    if (!ws) return res.status(404).json({ message: "Workspace not found" });
    await storage.purgeWorkspaceData(workspaceId);
    res.status(200).set("Content-Type", "application/json").json({ purged: true, workspaceId });
  } catch (err) {
    routeLog.error({ err }, "Purge workspace error");
    res.status(500).json({ message: "Failed to purge workspace" });
  }
});

workspacesRouter.get("/:id", async (req, res) => {
  try {
    const ws = await storage.getWorkspace(req.params.id);
    if (!ws) return res.status(404).json({ message: "Workspace not found" });
    // Verify caller is a member of this workspace
    const membership = await storage.getWorkspaceMember(ws.id, req.user!.id);
    if (!membership) return res.status(404).json({ message: "Workspace not found" });
    res.json(ws);
  } catch (err) { res.status(500).json({ message: "Internal server error" }); }
});

workspacesRouter.post("/", async (req, res) => {
  try {
    const parsed = createWorkspaceSchema.parse(req.body);
    const existing = await storage.getWorkspaceByName(parsed.name);
    if (existing) {
      return res.status(409).json({ message: "A workspace with this domain already exists", workspace: existing });
    }
    const ws = await storage.createWorkspace({ name: parsed.name, description: parsed.description || null, status: "active" });
    res.status(201).json(ws);
  } catch (error: unknown) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: error.errors[0]?.message || "Validation error" });
    }
    res.status(400).json({ message: "Bad request" });
  }
});

workspacesRouter.patch("/:id", async (req, res) => {
  try {
    const ws = await storage.getWorkspace(req.params.id);
    if (!ws) return res.status(404).json({ message: "Workspace not found" });
    // Only owner/admin can update workspace settings
    const membership = await storage.getWorkspaceMember(ws.id, req.user!.id);
    if (!membership || !["owner", "admin"].includes(membership.role)) {
      return res.status(403).json({ message: "Forbidden" });
    }
    const parsed = updateWorkspaceSchema.parse(req.body);
    const updated = await storage.updateWorkspace(req.params.id, parsed);
    if (!updated) return res.status(404).json({ message: "Workspace not found" });
    res.json(updated);
  } catch (error: unknown) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: error.errors[0]?.message || "Validation error" });
    }
    res.status(400).json({ message: "Bad request" });
  }
});

workspacesRouter.delete("/:id", async (req, res) => {
  try {
    const ws = await storage.getWorkspace(req.params.id);
    if (!ws) return res.status(404).json({ message: "Workspace not found" });
    // Only owner can delete a workspace
    const membership = await storage.getWorkspaceMember(ws.id, req.user!.id);
    if (!membership || membership.role !== "owner") {
      return res.status(403).json({ message: "Forbidden" });
    }
    await storage.deleteWorkspace(req.params.id);
    res.status(204).send();
  } catch (err) {
    routeLog.error({ err }, "Delete workspace error");
    res.status(500).json({ message: "Internal server error" });
  }
});

const wsAuth = requireWorkspaceRole("owner", "admin", "analyst", "viewer");
const wsWrite = requireWorkspaceRole("owner", "admin", "analyst");

workspacesRouter.get("/:workspaceId/assets", wsAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(String(req.query.limit ?? "500"), 10) || 500, 5000);
    const offset = Math.max(parseInt(String(req.query.offset ?? "0"), 10) || 0, 0);
    const result = await storage.getAssets(req.params.workspaceId as string, { limit, offset });
    res.json(result);
  } catch (err) {
    routeLog.error({ err }, "Get assets error");
    res.status(500).json({ message: "Internal server error" });
  }
});

workspacesRouter.post("/:workspaceId/assets", wsWrite, async (req, res) => {
  try {
    const parsed = createAssetSchema.parse({ ...req.body, workspaceId: req.params.workspaceId });
    const asset = await storage.createAsset(parsed);
    res.status(201).json(asset);
  } catch (error: unknown) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: error.errors[0]?.message || "Validation error" });
    }
    res.status(400).json({ message: "Bad request" });
  }
});
