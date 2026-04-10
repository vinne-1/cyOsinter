import { Router } from "express";
import { storage } from "../storage";
import { createLogger } from "../logger";
import { generateComplianceReport, generateAllComplianceReports } from "../compliance-mapper";
import { requireWorkspaceRole } from "./auth-middleware";

const log = createLogger("routes:analytics");

export const analyticsRouter = Router();

// ── Compliance Mapping ──

// GET /api/workspaces/:workspaceId/compliance
analyticsRouter.get("/workspaces/:workspaceId/compliance", requireWorkspaceRole("owner", "admin", "analyst", "viewer"), async (req, res) => {
  try {
    const workspaceId = String(req.params.workspaceId);
    const { data: findings } = await storage.getFindings(workspaceId);
    const reports = generateAllComplianceReports(findings);
    res.json(reports);
  } catch (err) {
    log.error({ err }, "Compliance report error");
    res.status(500).json({ message: "Internal error" });
  }
});

// GET /api/workspaces/:workspaceId/compliance/:framework
analyticsRouter.get("/workspaces/:workspaceId/compliance/:framework", requireWorkspaceRole("owner", "admin", "analyst", "viewer"), async (req, res) => {
  try {
    const workspaceId = String(req.params.workspaceId);
    const framework = req.params.framework as "owasp" | "cis" | "nist" | "soc2" | "iso27001" | "hipaa";
    if (!["owasp", "cis", "nist", "soc2", "iso27001", "hipaa"].includes(framework)) {
      return res.status(400).json({ message: "Invalid framework. Use: owasp, cis, nist, soc2, iso27001, hipaa" });
    }
    const { data: findings } = await storage.getFindings(workspaceId);
    const report = generateComplianceReport(findings, framework);
    res.json(report);
  } catch (err) {
    log.error({ err }, "Compliance report error");
    res.status(500).json({ message: "Internal error" });
  }
});

// ── Vulnerability Trend Analytics ──

// GET /api/workspaces/:workspaceId/trends/severity
analyticsRouter.get("/workspaces/:workspaceId/trends/severity", async (req, res) => {
  try {
    const limit = Math.min(parseInt(String(req.query.limit) || "30", 10) || 30, 100);
    const snapshots = await storage.getPostureHistory(req.params.workspaceId, limit);

    // Return chronological order (oldest first for charts)
    const trend = snapshots.reverse().map((s) => ({
      date: s.snapshotAt,
      securityScore: s.securityScore,
      findingsCount: s.findingsCount,
      criticalCount: s.criticalCount,
      highCount: s.highCount,
      surfaceRiskScore: s.surfaceRiskScore,
      tlsGrade: s.tlsGrade,
      openPortsCount: s.openPortsCount,
      wafCoverage: s.wafCoverage,
    }));

    res.json(trend);
  } catch (err) {
    log.error({ err }, "Severity trend error");
    res.status(500).json({ message: "Internal error" });
  }
});

// GET /api/workspaces/:workspaceId/trends/findings
analyticsRouter.get("/workspaces/:workspaceId/trends/findings", async (req, res) => {
  try {
    const { data: findings } = await storage.getFindings(req.params.workspaceId);

    // Group findings by discovery date (day resolution)
    const byDay = new Map<string, { total: number; critical: number; high: number; medium: number; low: number; info: number }>();
    for (const f of findings) {
      const day = f.discoveredAt ? new Date(f.discoveredAt).toISOString().slice(0, 10) : "unknown";
      const existing = byDay.get(day) ?? { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      existing.total++;
      const sev = f.severity as keyof typeof existing;
      if (sev in existing && sev !== "total") {
        (existing as Record<string, number>)[sev]++;
      }
      byDay.set(day, existing);
    }

    // Sort chronologically
    const trend = Array.from(byDay.entries())
      .filter(([day]) => day !== "unknown")
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([date, counts]) => ({ date, ...counts }));

    res.json(trend);
  } catch (err) {
    log.error({ err }, "Findings trend error");
    res.status(500).json({ message: "Internal error" });
  }
});

// GET /api/workspaces/:workspaceId/trends/categories
analyticsRouter.get("/workspaces/:workspaceId/trends/categories", async (req, res) => {
  try {
    const { data: findings } = await storage.getFindings(req.params.workspaceId);

    const byCategory = new Map<string, { total: number; open: number; resolved: number; critical: number; high: number }>();
    for (const f of findings) {
      const cat = f.category;
      const existing = byCategory.get(cat) ?? { total: 0, open: 0, resolved: 0, critical: 0, high: 0 };
      existing.total++;
      if (f.status === "open") existing.open++;
      if (f.status === "resolved") existing.resolved++;
      if (f.severity === "critical") existing.critical++;
      if (f.severity === "high") existing.high++;
      byCategory.set(cat, existing);
    }

    const categories = Array.from(byCategory.entries())
      .sort(([, a], [, b]) => b.total - a.total)
      .map(([category, counts]) => ({ category, ...counts }));

    res.json(categories);
  } catch (err) {
    log.error({ err }, "Category trend error");
    res.status(500).json({ message: "Internal error" });
  }
});

// GET /api/workspaces/:workspaceId/trends/mttr  (Mean Time to Resolve)
analyticsRouter.get("/workspaces/:workspaceId/trends/mttr", async (req, res) => {
  try {
    const { data: findings } = await storage.getFindings(req.params.workspaceId);
    const resolved = findings.filter((f) => f.status === "resolved" && f.resolvedAt && f.discoveredAt);

    const bySeverity: Record<string, { count: number; totalHours: number }> = {};
    for (const f of resolved) {
      const hours = (new Date(f.resolvedAt!).getTime() - new Date(f.discoveredAt!).getTime()) / 3_600_000;
      if (hours < 0) continue; // data anomaly
      const sev = f.severity;
      if (!bySeverity[sev]) bySeverity[sev] = { count: 0, totalHours: 0 };
      bySeverity[sev].count++;
      bySeverity[sev].totalHours += hours;
    }

    const mttr = Object.entries(bySeverity).map(([severity, data]) => ({
      severity,
      count: data.count,
      avgHours: Math.round(data.totalHours / data.count * 10) / 10,
    }));

    res.json({
      totalResolved: resolved.length,
      bySeverity: mttr,
      overallAvgHours: resolved.length > 0
        ? Math.round(mttr.reduce((sum, m) => sum + m.avgHours * m.count, 0) / resolved.length * 10) / 10
        : null,
    });
  } catch (err) {
    log.error({ err }, "MTTR trend error");
    res.status(500).json({ message: "Internal error" });
  }
});
