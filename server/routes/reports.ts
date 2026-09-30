import { Router } from "express";
import { selectReportFindings } from "../report-scope";
import { parsePagination } from "./response";
import { z } from "zod";
import { storage, FULL_SET_LIMIT } from "../storage";
import { createLogger } from "../logger";
import { requireWorkspaceRole } from "./auth-middleware";
import { createReportSchema } from "./schemas";
import { buildReportContent } from "./report-helpers";
import { buildAiFollowUpReport } from "../ai-follow-up";
import { getGlmConfig } from "../ai-service";
import type { ReportDocxInput } from "../report-docx.js";

const routeLog = createLogger("routes");

export const reportsRouter = Router();

const wsAuth = requireWorkspaceRole("owner", "admin", "analyst", "viewer");
const wsWrite = requireWorkspaceRole("owner", "admin", "analyst");

/**
 * Generation has no natural upper bound of its own: `buildReportContent` makes
 * one GLM call, `buildAiFollowUpReport` makes two plus up to four live checks,
 * and any one of those can retry. Measured on real data: a normal run
 * completes in 30–90s. Observed once in testing: a run that made no further
 * network calls and logged no error sat in "generating" for over ten minutes
 * with nothing to show the operator and no way to retry. A report that never
 * reaches a terminal state is the same failure this file documents for scans
 * (`POST /scans/:id/cancel`) — this is that same escape hatch for reports.
 *
 * Sized above the legitimate worst case, not the common case: each GLM call
 * can retry 3 attempts at `AI_REQUEST_TIMEOUT_MS` (120s) plus backoff — up to
 * ~371s — and `buildAiFollowUpReport` makes TWO such calls plus up to four
 * 25s live checks, so a fully-retried follow-up report can legitimately take
 * ~14 minutes. A shorter timeout would fire on a report that was still
 * correctly working through GLM rate-limiting, not stuck.
 */
const REPORT_GENERATION_TIMEOUT_MS = 15 * 60 * 1000;

reportsRouter.get("/workspaces/:workspaceId/reports", wsAuth, async (req, res) => {
  try {
    const { limit, offset } = parsePagination(req.query, { defaultLimit: 500, maxLimit: 5000 });
    const result = await storage.getReports(req.params.workspaceId as string, { limit, offset });
    res.json(result);
  } catch (err) { res.status(500).json({ message: "Internal server error" }); }
});

reportsRouter.get("/reports/:id", async (req, res) => {
  try {
    const report = await storage.getReport(req.params.id);
    if (!report) return res.status(404).json({ message: "Report not found" });
    // Verify caller is a member of the report's workspace
    const membership = await storage.getWorkspaceMember(report.workspaceId, req.user!.id);
    if (!membership) return res.status(404).json({ message: "Report not found" });
    res.json(report);
  } catch (err) { res.status(500).json({ message: "Internal server error" }); }
});

/**
 * POST /api/reports/:id/qa-review — a proofreading pass BEFORE the operator
 * shares this report, checking the written summary against the report's own
 * stated counts and the finding titles it actually lists. Not a second
 * opinion on severity and not persisted: it is a pre-send check over a
 * snapshot, and a report can be re-checked after every edit for free.
 */
reportsRouter.post("/reports/:id/qa-review", async (req, res) => {
  try {
    const report = await storage.getReport(req.params.id);
    if (!report) return res.status(404).json({ message: "Report not found" });
    const membership = await storage.getWorkspaceMember(report.workspaceId, req.user!.id);
    if (!membership) return res.status(404).json({ message: "Report not found" });
    if (report.status !== "completed") return res.status(400).json({ message: "Report is not yet completed" });

    const content = (report.content as Record<string, unknown> | null) ?? {};
    const { data: allFindings } = await storage.getFindings(report.workspaceId, { limit: FULL_SET_LIMIT });
    const reportFindings = selectReportFindings(allFindings, report.findingIds ?? undefined);

    const { reviewReportForQA } = await import("../ai-service.js");
    const result = await reviewReportForQA({
      title: report.title,
      reportType: report.type,
      summary: report.summary ?? "",
      totalFindings: (content.totalFindings as number) ?? reportFindings.length,
      criticalCount: (content.criticalCount as number) ?? reportFindings.filter((f) => f.severity === "critical").length,
      highCount: (content.highCount as number) ?? reportFindings.filter((f) => f.severity === "high").length,
      findingTitles: reportFindings.map((f) => f.title),
    });
    res.json(result);
  } catch (err) {
    routeLog.warn({ err }, "Report QA review failed");
    res.status(500).json({ message: "GLM did not answer. Try again." });
  }
});

reportsRouter.post("/workspaces/:workspaceId/reports", wsWrite, async (req, res) => {
  try {
    const workspaceId = req.params.workspaceId as string;
    const parsed = createReportSchema.parse({ ...req.body, workspaceId });
    const report = await storage.createReport(parsed);

    setTimeout(async () => {
      // `buildReportContent`/`buildAiFollowUpReport` take no AbortSignal, so
      // the timeout branch below cannot actually CANCEL a run past its
      // deadline — only stop waiting on it. Without this flag, a run that
      // finally finishes after the timeout already marked the report
      // "failed" would silently overwrite that with "completed", which is
      // worse than the original bug: the operator was already told it
      // failed, then it quietly un-fails behind their back.
      let timedOut = false;

      const generate = async () => {
        await storage.updateReport(report.id, { status: "generating" });
        const { content, summary } = await buildReportContent(workspaceId, report.findingIds ?? undefined, report.type);
        let finalSummary = summary;
        if (report.type === "ai_follow_up") {
          const workspace = await storage.getWorkspace(workspaceId);
          const { data: allFindings } = await storage.getFindings(workspaceId, { limit: FULL_SET_LIMIT });
          const scoped = selectReportFindings(allFindings, report.findingIds ?? undefined);
          const explicit = (report.findingIds ?? []).length > 0;
          const findings = explicit ? scoped : scoped.filter((f) => f.status === "open" || f.status === "in_review");
          const segment = await buildAiFollowUpReport({
            workspaceName: workspace?.name ?? "",
            domain: (workspace?.domain || workspace?.name || "").trim(),
            findings,
            model: getGlmConfig().model,
          });
          content.aiFollowUp = segment;
          if (segment.narrative) finalSummary = segment.narrative;
          // `buildReportContent` above counted from `scoped` (no status
          // filter, same as every other report type), but the themes this
          // section just built came from `findings` (open/in_review only
          // when there was no explicit selection) — so "Total Findings: 20"
          // in the overview could sit above a follow-up section that only
          // consolidated 15. Re-derive the overview counts from the SAME set
          // the AI section actually covers, so the two halves of one report
          // cannot disagree about how many findings there are.
          if (!explicit) {
            content.totalFindings = findings.length;
            content.criticalCount = findings.filter((f) => f.severity === "critical").length;
            content.highCount = findings.filter((f) => f.severity === "high").length;
            content.categories = Array.from(new Set(findings.map((f) => f.category)));
          }
        }
        if (timedOut) {
          routeLog.warn({ reportId: report.id }, "Report generation finished after its own timeout; discarding (already marked failed)");
          return;
        }
        await storage.updateReport(report.id, {
          status: "completed",
          content,
          summary: finalSummary,
          generatedAt: new Date(),
        });
      };

      let timer: NodeJS.Timeout | undefined;
      const timeout = new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          timedOut = true;
          reject(new Error(`Report generation timed out after ${REPORT_GENERATION_TIMEOUT_MS / 1000}s`));
        }, REPORT_GENERATION_TIMEOUT_MS);
      });

      try {
        await Promise.race([generate(), timeout]);
      } catch (err) {
        routeLog.error({ err, reportId: report.id, reportType: report.type }, "Report generation error");
        // A report that stays "generating" forever is worse than one marked
        // failed: the operator has no signal and no way to retry. "draft" used
        // to be written here, which looked identical to a report nobody had
        // generated yet. The client gets a generic message — `err` can be a
        // raw DB/network error, and this codebase never forwards `err.message`
        // to a caller (see routes/response.ts and every catch block in this
        // file); the real error is in the server log line above.
        await storage.updateReport(report.id, {
          status: "failed",
          summary: "Report generation failed. Check the server log for details, or try again.",
        }).catch((updateErr) => {
          routeLog.error({ err: updateErr, reportId: report.id }, "Failed to record report generation failure");
        });
      } finally {
        clearTimeout(timer);
      }
    }, 2000);

    res.status(201).json(report);
  } catch (error: unknown) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: error.errors[0]?.message || "Validation error" });
    }
    res.status(400).json({ message: "Bad request" });
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

    const { data: allFindings } = await storage.getFindings(workspaceId, { limit: FULL_SET_LIMIT });
    // An empty/absent findingIds means "all findings" — this mirrors
    // buildReportContent(). Filtering against an empty list here produced an
    // empty findings table in exports while the summary still counted them all.
    const reportFindings = selectReportFindings(allFindings, report.findingIds)
      .map((f) => ({
        id: f.id,
        title: f.title,
        severity: f.severity,
        status: f.status,
        category: f.category,
        affectedAsset: f.affectedAsset,
        description: f.description,
        cvssScore: f.cvssScore,
        remediation: f.remediation,
        evidence: f.evidence as Array<Record<string, unknown>> | null,
        tags: f.tags,
        assignee: f.assignee,
        dueDate: f.dueDate,
        priority: f.priority,
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

    if (format === "docx" || format === "word") {
      const { buildDocxInput } = await import("../report-docx-input.js");
      const { generateReportDocx } = await import("../report-docx.js");
      const withEvidence = req.query.evidence === "1" || req.query.evidence === "true";
      const docxInput = await buildDocxInput(workspaceId, {
        findingIds: report.findingIds ?? undefined,
        scanMode: (report.content as Record<string, unknown> | null)?.scanMode as string | undefined,
        captureEvidence: withEvidence,
        // The stored AI Follow-up segment, verbatim — see its doc comment on
        // ReportDocxInput. Absent for every report type except `ai_follow_up`.
        aiFollowUp: (report.content as Record<string, unknown> | null)?.aiFollowUp as ReportDocxInput["aiFollowUp"],
      });
      const docxBuffer = await generateReportDocx(docxInput);
      res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
      res.setHeader("Content-Disposition", `attachment; filename="${safeTitle}.docx"`);
      res.send(docxBuffer);
      return;
    }

    const { generateReportPdfBuffer } = await import("../report-pdf.js");
    const { summarizeEvidence } = await import("../report-export.js");
    const pdfBuffer = generateReportPdfBuffer({
      ...exportInput,
      findings: reportFindings.map((f) => ({
        id: f.id,
        title: f.title,
        severity: f.severity,
        affectedAsset: f.affectedAsset,
        category: f.category,
        description: f.description,
        remediation: f.remediation,
        cvssScore: f.cvssScore,
        evidenceSummary: summarizeEvidence(f.evidence, 220),
      })),
    });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${safeTitle}.pdf"`);
    res.send(pdfBuffer);
  } catch (err) {
    routeLog.error({ err }, "Report export error");
    res.status(500).json({ message: "Export failed" });
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
    res.status(500).json({ message: "Failed to delete report" });
  }
});
