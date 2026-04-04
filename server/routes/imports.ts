import { Router } from "express";
import multer from "multer";
import { storage } from "../storage";
import { createLogger } from "../logger";
import { parseNmap, nmapToTextSummary } from "../parsers/nmap";
import { consolidateScanResults } from "../ai-service";
import { requireWorkspaceRole } from "./auth-middleware";
import { validSeverities } from "./schemas";

const routeLog = createLogger("routes");
const wsWrite = requireWorkspaceRole("owner", "admin", "analyst");

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = [
      "text/plain", "text/xml", "application/xml",
      "application/json", "application/octet-stream",
    ];
    cb(null, allowed.includes(file.mimetype));
  },
});

export const importsRouter = Router();

importsRouter.get("/workspaces/:workspaceId/imports", wsWrite, async (req, res) => {
  try {
    const workspaceId = req.params.workspaceId as string;
    const ws = await storage.getWorkspace(workspaceId);
    if (!ws) return res.status(404).json({ message: "Workspace not found" });
    const scans = await storage.getUploadedScans(workspaceId);
    res.json(scans);
  } catch (err) {
    routeLog.error({ err }, "List imports error");
    res.status(500).json({ message: "Failed to list imports" });
  }
});

importsRouter.post("/workspaces/:workspaceId/imports", wsWrite, upload.single("file"), async (req, res) => {
  try {
    const workspaceId = req.params.workspaceId as string;
    const ws = await storage.getWorkspace(workspaceId);
    if (!ws) return res.status(404).json({ message: "Workspace not found" });
    const file = req.file as Express.Multer.File | undefined;
    if (!file || !file.buffer) return res.status(400).json({ message: "No file uploaded" });
    const fileType = (req.body?.fileType as string) || "nmap";
    const validTypes = ["nmap", "nikto", "generic"];
    const type = validTypes.includes(fileType) ? fileType : "generic";
    const rawContent = file.buffer.toString("utf-8");
    const parsed = parseNmap(rawContent, type as "nmap" | "nikto" | "generic");
    const scan = await storage.createUploadedScan({
      workspaceId,
      filename: file.originalname,
      fileType: type,
      rawContent,
      parsedData: { hosts: parsed.hosts, rawSummary: parsed.rawSummary } as Record<string, unknown>,
    });
    res.status(201).json(scan);
  } catch (err) {
    routeLog.error({ err }, "Upload import error");
    res.status(500).json({ message: "Failed to upload" });
  }
});

importsRouter.post("/workspaces/:workspaceId/imports/:id/consolidate", wsWrite, async (req, res) => {
  try {
    const workspaceId = req.params.workspaceId as string;
    const id = req.params.id as string;
    const ws = await storage.getWorkspace(workspaceId);
    if (!ws) return res.status(404).json({ message: "Workspace not found" });
    const scan = await storage.getUploadedScan(id);
    if (!scan || scan.workspaceId !== workspaceId) return res.status(404).json({ message: "Import not found" });
    const { data: existingFindings } = await storage.getFindings(workspaceId);
    const parsedData = scan.parsedData as { hosts?: Array<{ address: string; hostname?: string; ports: Array<{ port: number; protocol: string; state: string; service?: string; version?: string }> }>; rawSummary?: string } | null;
    const textForAI = parsedData?.hosts?.length
      ? nmapToTextSummary({ hosts: parsedData.hosts, rawSummary: parsedData.rawSummary })
      : scan.rawContent.slice(0, 12000);
    const result = await consolidateScanResults(textForAI, existingFindings, ws.name);
    for (const nf of result.newFindings) {
      // Validate AI-provided severity against known values
      if (!validSeverities.includes(nf.severity as typeof validSeverities[number])) continue;
      await storage.createFinding({
        workspaceId,
        title: nf.title,
        description: nf.description,
        severity: nf.severity,
        category: nf.category,
        affectedAsset: nf.affectedAsset,
        remediation: nf.remediation,
      });
    }
    for (const mu of result.mergedUpdates) {
      // Verify the finding belongs to the current workspace before updating
      const existing = await storage.getFinding(mu.findingId);
      if (!existing || existing.workspaceId !== workspaceId) continue;
      // Only allow safe fields from AI
      const safeUpdates: Record<string, unknown> = {};
      if (mu.updates.description) safeUpdates.description = mu.updates.description;
      if (mu.updates.evidence) safeUpdates.evidence = mu.updates.evidence;
      if (mu.updates.remediation) safeUpdates.remediation = mu.updates.remediation;
      await storage.updateFinding(mu.findingId, safeUpdates);
    }
    res.json({ newCount: result.newFindings.length, mergedCount: result.mergedUpdates.length });
  } catch (err) {
    routeLog.error({ err }, "Consolidate error");
    res.status(500).json({ message: "Consolidation failed" });
  }
});

importsRouter.delete("/workspaces/:workspaceId/imports/:id", wsWrite, async (req, res) => {
  try {
    const workspaceId = req.params.workspaceId as string;
    const id = req.params.id as string;
    const scan = await storage.getUploadedScan(id);
    if (!scan || scan.workspaceId !== workspaceId) return res.status(404).json({ message: "Import not found" });
    await storage.deleteUploadedScan(id);
    res.status(200).json({ deleted: true });
  } catch (err) {
    routeLog.error({ err }, "Delete import error");
    res.status(500).json({ message: "Failed to delete" });
  }
});
