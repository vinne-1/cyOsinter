import { Router } from "express";
import { z } from "zod";
import { storage } from "../storage";
import { createLogger } from "../logger";
import type { ScanProfileConfig } from "@shared/schema";

const log = createLogger("scan-profiles");

const scanProfileConfigSchema = z.object({
  enableTakeoverCheck: z.boolean().optional(),
  enableApiDiscovery: z.boolean().optional(),
  enableSecretScan: z.boolean().optional(),
  enableNuclei: z.boolean().optional(),
  subdomainWordlistCap: z.number().int().min(0).max(100000).optional(),
  directoryWordlistCap: z.number().int().min(0).max(100000).optional(),
  portScanEnabled: z.boolean().optional(),
  customPorts: z.array(z.number().int().min(1).max(65535)).optional(),
  excludePaths: z.array(z.string()).optional(),
  maxConcurrency: z.number().int().min(1).max(50).optional(),
  timeoutMinutes: z.number().int().min(1).max(1440).optional(),
});

const createProfileSchema = z.object({
  workspaceId: z.string().min(1),
  name: z.string().min(1, "Profile name is required"),
  description: z.string().optional(),
  scanType: z.enum(["easm", "osint", "full"]).default("full"),
  mode: z.enum(["standard", "gold"]).default("standard"),
  config: scanProfileConfigSchema,
  isDefault: z.boolean().default(false),
});

const updateProfileSchema = z.object({
  name: z.string().min(1).optional(),
  description: z.string().nullable().optional(),
  scanType: z.enum(["easm", "osint", "full"]).optional(),
  mode: z.enum(["standard", "gold"]).optional(),
  config: scanProfileConfigSchema.optional(),
  isDefault: z.boolean().optional(),
});

export const scanProfilesRouter = Router();

// GET /api/scan-profiles?workspaceId=...
scanProfilesRouter.get("/scan-profiles", async (req, res) => {
  try {
    const workspaceId = req.query.workspaceId as string;
    if (!workspaceId) return res.status(400).json({ message: "workspaceId required" });
    const profiles = await storage.getScanProfiles(workspaceId);
    res.json(profiles);
  } catch (err) {
    log.error({ err }, "Failed to list scan profiles");
    res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" });
  }
});

// GET /api/scan-profiles/:id
scanProfilesRouter.get("/scan-profiles/:id", async (req, res) => {
  try {
    const profile = await storage.getScanProfile(req.params.id);
    if (!profile) return res.status(404).json({ message: "Profile not found" });
    res.json(profile);
  } catch (err) {
    log.error({ err }, "Failed to get scan profile");
    res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" });
  }
});

// POST /api/scan-profiles
scanProfilesRouter.post("/scan-profiles", async (req, res) => {
  try {
    const parsed = createProfileSchema.parse(req.body);
    const profile = await storage.createScanProfile({
      ...parsed,
      config: parsed.config as ScanProfileConfig,
    });
    res.status(201).json(profile);
  } catch (err) {
    if (err instanceof z.ZodError) return res.status(400).json({ message: err.errors[0]?.message });
    log.error({ err }, "Failed to create scan profile");
    res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" });
  }
});

// PATCH /api/scan-profiles/:id
scanProfilesRouter.patch("/scan-profiles/:id", async (req, res) => {
  try {
    const parsed = updateProfileSchema.parse(req.body);
    const updated = await storage.updateScanProfile(req.params.id, {
      ...parsed,
      config: parsed.config as ScanProfileConfig | undefined,
    });
    if (!updated) return res.status(404).json({ message: "Profile not found" });
    res.json(updated);
  } catch (err) {
    if (err instanceof z.ZodError) return res.status(400).json({ message: err.errors[0]?.message });
    log.error({ err }, "Failed to update scan profile");
    res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" });
  }
});

// DELETE /api/scan-profiles/:id
scanProfilesRouter.delete("/scan-profiles/:id", async (req, res) => {
  try {
    await storage.deleteScanProfile(req.params.id);
    res.status(204).send();
  } catch (err) {
    log.error({ err }, "Failed to delete scan profile");
    res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" });
  }
});
