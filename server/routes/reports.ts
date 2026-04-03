import { Router } from "express";
import { z } from "zod";
import { storage } from "../storage";
import { createLogger } from "../logger";
import { requireWorkspaceRole } from "./auth-middleware";
import { createReportSchema } from "./schemas";
import { buildReportContent } from "./report-helpers";

const routeLog = createLogger("routes");

export const reportsRouter = Router();

const wsAuth = requireWorkspaceRole("owner", "admin", "analyst", "viewer");
const wsWrite = requireWorkspaceRole("owner", "admin", "analyst");

reportsRouter.get("/workspaces/:workspaceId/reports", wsAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(String(req.query.limit ?? "500"), 10) || 500, 5000);
    const offset = Math.max(parseInt(String(req.query.offset ?? "0"), 10) || 0, 0);
    const result = await storage.getReports(req.params.workspaceId as string, { limit, offset });
    res.json(result);
  } catch (err) { res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" }); }
});

reportsRouter.get("/reports/:id", async (req, res) => {
  try {
    const report = await storage.getReport(req.params.id);
    if (!report) return res.status(404).json({ message: "Report not found" });
    res.json(report);
  } catch (err) { res.status(500).json({ message: err instanceof Error ? err.message : "Internal error" }); }
});

reportsRouter.post("/workspaces/:workspaceId/reports", wsWrite, async (req, res) => {
  try {
    const workspaceId = req.params.workspaceId as string;
    const parsed = createReportSchema.parse({ ...req.body, workspaceId });
    const report = await storage.createReport(parsed);

    setTimeout(async () => {
      try {
        await storage.updateReport(report.id, { status: "generating" });
        const { content, summary } = await buildReportContent(workspaceId, report.findingIds ?? undefined, report.type);
        await storage.updateReport(report.id, {
          status: "completed",
          content,
          summary,
          generatedAt: new Date(),
        });
      } catch (err) {
        routeLog.error({ err }, "Report generation error");
        await storage.updateReport(report.id, { status: "draft" });
      }
    }, 2000);

    res.status(201).json(report);
  } catch (error: unknown) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: error.errors[0]?.message || "Validation error" });
    }
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(400).json({ message });
  }
});

reportsRouter.get("/workspaces/:workspaceId/reports/:reportId/export", wsAuth, async (req, res) => {
  try {
    const workspaceId = req.params.workspaceId as string;
    const reportId = req.params.reportId as string;
    const report = await storage.getReport(reportId);
    if (!report) return res.status(404).json({ message: "Report not found" });
    if (report.workspaceId !== workspaceId) return res.status(404).json({ message: "Report not found" });
    if (report.status !== "completed") return res.status(400).json({ message: "Report not yet completed" });

    const { data: allFindings } = await storage.getFindings(workspaceId);
    const reportFindings = allFindings
      .filter((f) => (report.findingIds || []).includes(f.id))
      .map((f) => ({
        id: f.id,
        title: f.title,
        severity: f.severity,
        status: f.status,
        category: f.category,
        affectedAsset: f.affectedAsset,
        description: f.description,
      }));

    const exportInput = {
      title: report.title,
      summary: report.summary ?? "",
      generatedAt: report.generatedAt?.toISOString?.() ?? (report.generatedAt as string | null),
      content: report.content as Record<string, unknown> | null,
      findings: reportFindings,
    };

    const format = (req.query.format as string) || "pdf";
    const safeTitle = (report.title || "security-report").replace(/[^a-zA-Z0-9-_]/g, "-").replace(/-+/g, "-").toLowerCase();

    if (format === "csv") {
      const { generateReportCsv } = await import("../report-export.js");
      const csv = generateReportCsv(exportInput);
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", `attachment; filename="${safeTitle}.csv"`);
      res.send(csv);
      return;
    }

    if (format === "xlsx" || format === "excel") {
      const { generateReportExcel } = await import("../report-export.js");
      const xlsxBuffer = await generateReportExcel(exportInput);
      res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
      res.setHeader("Content-Disposition", `attachment; filename="${safeTitle}.xlsx"`);
      res.send(xlsxBuffer);
      return;
    }

    const { generateReportPdfBuffer } = await import("../report-pdf.js");
    const pdfBuffer = generateReportPdfBuffer({
      ...exportInput,
      findings: reportFindings.map((f) => ({ id: f.id, title: f.title, severity: f.severity, affectedAsset: f.affectedAsset })),
    });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${safeTitle}.pdf"`);
    res.send(pdfBuffer);
  } catch (err) {
    routeLog.error({ err }, "Report export error");
    res.status(500).json({ message: err instanceof Error ? err.message : "Export failed" });
  }
});

reportsRouter.delete("/workspaces/:workspaceId/reports/:reportId", wsWrite, async (req, res) => {
  try {
    const workspaceId = req.params.workspaceId as string;
    const reportId = req.params.reportId as string;
    const report = await storage.getReport(reportId);
    if (!report) return res.status(404).json({ message: "Report not found" });
    if (report.workspaceId !== workspaceId) return res.status(404).json({ message: "Report not found" });
    await storage.deleteReport(reportId);
    res.status(204).send();
  } catch (err) {
    routeLog.error({ err }, "Delete report error");
    res.status(500).json({ message: err instanceof Error ? err.message : "Failed to delete report" });
  }
});
