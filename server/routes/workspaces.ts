import { Router } from "express";
import { parsePagination } from "./response";
import { z } from "zod";
import { storage } from "../storage";
import { createLogger } from "../logger";
import { createWorkspaceSchema, updateWorkspaceSchema, createAssetSchema } from "./schemas";
import { requireWorkspaceRole } from "./auth-middleware";

const routeLog = createLogger("routes");

export const workspacesRouter = Router();

workspacesRouter.get("/", async (req, res) => {
  try {
    // Superadmins can see all workspaces; regular users only see their own
    const ws = req.user!.role === "superadmin"
      ? await storage.getWorkspaces()
      : await storage.getWorkspacesByUserId(req.user!.id);
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
      return res.status(409).json({ message: "A workspace with this name already exists" });
    }
    const ws = await storage.createWorkspace({ name: parsed.name, domain: parsed.domain || null, description: parsed.description || null, status: "active" });
    // Add the creating user as the workspace owner
    await storage.addWorkspaceMember(ws.id, req.user!.id, "owner");
    res.status(201).json(ws);
  } catch (error: unknown) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: error.errors[0]?.message || "Validation error" });
    }
    routeLog.error({ error }, "Create workspace error");
    res.status(500).json({ message: "Internal server error" });
  }
});

workspacesRouter.patch("/:id", async (req, res) => {
  try {
    const ws = await storage.getWorkspace(req.params.id);
    if (!ws) return res.status(404).json({ message: "Workspace not found" });
    // Only owner/admin can update workspace settings
    // 404 for a non-member, 403 only for a member with the wrong role — the same
    // split `requireWorkspaceRole` makes. Collapsing both into 403 turns this
    // route into a membership oracle: iterate workspace ids and every 403 is a
    // confirmed tenant. A member with an insufficient role already knows the
    // workspace exists, so 403 is the honest answer there.
    const membership = await storage.getWorkspaceMember(ws.id, req.user!.id);
    if (!membership) return res.status(404).json({ message: "Workspace not found" });
    if (!["owner", "admin"].includes(membership.role)) {
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
    routeLog.error({ error }, "Update workspace error");
    res.status(500).json({ message: "Internal server error" });
  }
});

workspacesRouter.delete("/:id", async (req, res) => {
  try {
    const ws = await storage.getWorkspace(req.params.id);
    if (!ws) return res.status(404).json({ message: "Workspace not found" });
    // Only owner can delete a workspace
    // Same split as PATCH above: non-member ⇒ 404, wrong role ⇒ 403.
    const membership = await storage.getWorkspaceMember(ws.id, req.user!.id);
    if (!membership) return res.status(404).json({ message: "Workspace not found" });
    if (membership.role !== "owner") {
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
    const { limit, offset } = parsePagination(req.query, { defaultLimit: 500, maxLimit: 5000 });
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
