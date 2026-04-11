import { eq, desc, and, sql, lt, asc, count, inArray } from "drizzle-orm";
import { db } from "./db";
import {
  workspaces,
  assets,
  scans,
  findings,
  reports,
  reconModules,
  continuousMonitoring,
  uploadedScans,
  postureSnapshots,
  alerts,
  scheduledScans,
  scanProfiles,
  riskItems,
  policyDocuments,
  questionnaireRuns,
  workspaceMembers,
  tlsCertificates,
  techInventory,
  epssScores,
  findingPriority,
  postureAnomalies,
} from "@shared/schema";
import type {
  Workspace,
  InsertWorkspace,
  WorkspaceMember,
  Asset,
  InsertAsset,
  Scan,
  InsertScan,
  Finding,
  InsertFinding,
  Report,
  InsertReport,
  ReconModule,
  InsertReconModule,
  ContinuousMonitoring,
  InsertContinuousMonitoring,
  UploadedScan,
  InsertUploadedScan,
  PostureSnapshot,
  InsertPostureSnapshot,
  Alert,
  InsertAlert,
  ScheduledScan,
  InsertScheduledScan,
  ScanProfile,
  InsertScanProfile,
  RiskItem,
  InsertRiskItem,
  PolicyDocument,
  InsertPolicyDocument,
  QuestionnaireRun,
  InsertQuestionnaireRun,
  TlsCertificate,
  InsertTlsCertificate,
  TechInventoryItem,
  InsertTechInventoryItem,
  EpssScore,
  InsertEpssScore,
  FindingPriority,
  InsertFindingPriority,
  PostureAnomaly,
  InsertPostureAnomaly,
} from "@shared/schema";

export interface PaginationOpts {
  limit?: number;
  offset?: number;
}

export interface PaginatedResult<T> {
  data: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface IStorage {
  getWorkspaces(): Promise<Workspace[]>;
  getWorkspace(id: string): Promise<Workspace | undefined>;
  getWorkspaceByName(name: string): Promise<Workspace | undefined>;
  createWorkspace(ws: InsertWorkspace): Promise<Workspace>;
  updateWorkspace(id: string, data: Partial<Workspace>): Promise<Workspace | undefined>;
  deleteWorkspace(id: string): Promise<void>;
  purgeWorkspaceData(id: string): Promise<void>;

  getAssets(workspaceId: string, opts?: PaginationOpts): Promise<PaginatedResult<Asset>>;
  getAsset(id: string): Promise<Asset | undefined>;
  assetExists(workspaceId: string, type: string, value: string): Promise<boolean>;
  createAsset(asset: InsertAsset): Promise<Asset>;
  deleteAsset(id: string): Promise<void>;

  getScans(workspaceId: string, opts?: PaginationOpts): Promise<PaginatedResult<Scan>>;
  getScan(id: string): Promise<Scan | undefined>;
  createScan(scan: InsertScan): Promise<Scan>;
  updateScan(id: string, data: Partial<Scan>): Promise<Scan | undefined>;
  deleteScan(id: string): Promise<void>;

  getFindings(workspaceId: string, opts?: PaginationOpts): Promise<PaginatedResult<Finding>>;
  getAllFindings(): Promise<Finding[]>;
  getFinding(id: string): Promise<Finding | undefined>;
  findingExists(workspaceId: string, title: string, affectedAsset: string, category: string): Promise<boolean>;
  createFinding(finding: InsertFinding): Promise<Finding>;
  updateFinding(id: string, data: Partial<Finding>): Promise<Finding | undefined>;

  getReports(workspaceId: string, opts?: PaginationOpts): Promise<PaginatedResult<Report>>;
  getReport(id: string): Promise<Report | undefined>;
  createReport(report: InsertReport): Promise<Report>;
  updateReport(id: string, data: Partial<Report>): Promise<Report | undefined>;
  deleteReport(id: string): Promise<void>;

  getReconModules(workspaceId: string, opts?: PaginationOpts): Promise<PaginatedResult<ReconModule>>;
  getReconModule(id: string): Promise<ReconModule | undefined>;
  getReconModulesByType(workspaceId: string, moduleType: string): Promise<ReconModule[]>;
  createReconModule(mod: InsertReconModule): Promise<ReconModule>;
  updateReconModule(id: string, data: Partial<ReconModule>): Promise<ReconModule | undefined>;

  getContinuousMonitoringByWorkspace(workspaceId: string): Promise<ContinuousMonitoring | undefined>;
  createContinuousMonitoring(mod: InsertContinuousMonitoring): Promise<ContinuousMonitoring>;
  updateContinuousMonitoring(id: string, data: Partial<ContinuousMonitoring>): Promise<ContinuousMonitoring | undefined>;

  getUploadedScans(workspaceId: string): Promise<UploadedScan[]>;
  getUploadedScan(id: string): Promise<UploadedScan | undefined>;
  createUploadedScan(scan: InsertUploadedScan): Promise<UploadedScan>;
  deleteUploadedScan(id: string): Promise<void>;

  getPostureHistory(workspaceId: string, limit?: number): Promise<PostureSnapshot[]>;
  createPostureSnapshot(snapshot: InsertPostureSnapshot): Promise<PostureSnapshot>;
  getStuckScans(maxAgeMs: number): Promise<Scan[]>;

  // Workspace Members
  getWorkspaceMember(workspaceId: string, userId: string): Promise<WorkspaceMember | undefined>;
  addWorkspaceMember(workspaceId: string, userId: string, role: string): Promise<WorkspaceMember>;
  getWorkspacesByUserId(userId: string): Promise<Workspace[]>;

  // Alerts
  getAlert(id: string): Promise<Alert | undefined>;
  getAlerts(workspaceId: string, limit?: number): Promise<Alert[]>;
  getUnreadAlertCount(workspaceId: string): Promise<number>;
  createAlert(alert: InsertAlert): Promise<Alert>;
  markAlertRead(id: string): Promise<Alert | undefined>;
  markAllAlertsRead(workspaceId: string): Promise<void>;
  deleteAlert(id: string): Promise<void>;

  // Scheduled Scans
  getScheduledScans(workspaceId: string): Promise<ScheduledScan[]>;
  getScheduledScan(id: string): Promise<ScheduledScan | undefined>;
  getDueScheduledScans(): Promise<ScheduledScan[]>;
  createScheduledScan(scan: InsertScheduledScan): Promise<ScheduledScan>;
  updateScheduledScan(id: string, data: Partial<ScheduledScan>): Promise<ScheduledScan | undefined>;
  deleteScheduledScan(id: string): Promise<void>;

  // Scan Profiles
  getScanProfiles(workspaceId: string): Promise<ScanProfile[]>;
  getScanProfile(id: string): Promise<ScanProfile | undefined>;
  createScanProfile(profile: InsertScanProfile): Promise<ScanProfile>;
  updateScanProfile(id: string, data: Partial<ScanProfile>): Promise<ScanProfile | undefined>;
  deleteScanProfile(id: string): Promise<void>;

  // Risk register
  getRiskItems(workspaceId: string): Promise<RiskItem[]>;
  getRiskItem(id: string): Promise<RiskItem | undefined>;
  getRiskItemByFingerprint(workspaceId: string, fingerprint: string): Promise<RiskItem | undefined>;
  createRiskItem(item: InsertRiskItem): Promise<RiskItem>;
  updateRiskItem(id: string, data: Partial<RiskItem>): Promise<RiskItem | undefined>;
  deleteRiskItem(id: string): Promise<void>;

  // Policies
  getPolicyDocuments(workspaceId: string): Promise<PolicyDocument[]>;
  getPolicyDocument(id: string): Promise<PolicyDocument | undefined>;
  getPolicyDocumentByType(workspaceId: string, policyType: string): Promise<PolicyDocument | undefined>;
  createPolicyDocument(doc: InsertPolicyDocument): Promise<PolicyDocument>;
  updatePolicyDocument(id: string, data: Partial<PolicyDocument>): Promise<PolicyDocument | undefined>;
  deletePolicyDocument(id: string): Promise<void>;

  // Questionnaires
  getQuestionnaireRuns(workspaceId: string): Promise<QuestionnaireRun[]>;
  getQuestionnaireRun(id: string): Promise<QuestionnaireRun | undefined>;
  createQuestionnaireRun(run: InsertQuestionnaireRun): Promise<QuestionnaireRun>;

  // ── Enrichment: Certificate Inventory ──
  getCertificates(workspaceId: string, opts?: { expiringWithinDays?: number }): Promise<TlsCertificate[]>;
  upsertCertificate(cert: Omit<InsertTlsCertificate, "id">): Promise<void>;

  // ── Enrichment: Tech Inventory ──
  getTechInventory(workspaceId: string): Promise<TechInventoryItem[]>;
  upsertTechInventory(item: Omit<InsertTechInventoryItem, "id">): Promise<void>;

  // ── Enrichment: EPSS Scores ──
  getEpssScore(cveId: string): Promise<EpssScore | undefined>;
  upsertEpssScore(score: InsertEpssScore): Promise<void>;

  // ── Enrichment: Finding Priority ──
  getFindingPriorities(workspaceId: string, limit?: number): Promise<Array<FindingPriority & { finding: Finding }>>;
  upsertFindingPriority(priority: InsertFindingPriority): Promise<void>;

  // ── Enrichment: Posture Anomalies ──
  getPostureAnomalies(workspaceId: string, limit?: number): Promise<PostureAnomaly[]>;
  createPostureAnomaly(anomaly: InsertPostureAnomaly): Promise<PostureAnomaly>;
  acknowledgePostureAnomaly(id: string): Promise<void>;

  // ── Evidence Search ──
  searchEvidence(workspaceId: string, query: string, limit?: number): Promise<Array<{ type: "finding" | "recon"; id: string; title: string; snippet: string; host: string | null }>>;
}

const DEFAULT_LIMIT = 500;

export class DatabaseStorage implements IStorage {
  async getWorkspaces(): Promise<Workspace[]> {
    return db.select().from(workspaces).orderBy(desc(workspaces.createdAt));
  }

  async getWorkspace(id: string): Promise<Workspace | undefined> {
    const [ws] = await db.select().from(workspaces).where(eq(workspaces.id, id));
    return ws;
  }

  async getWorkspaceByName(name: string): Promise<Workspace | undefined> {
    const [ws] = await db.select().from(workspaces).where(eq(workspaces.name, name));
    return ws;
  }

  async createWorkspace(ws: InsertWorkspace): Promise<Workspace> {
    const [created] = await db.insert(workspaces).values(ws).returning();
    return created;
  }

  async updateWorkspace(id: string, data: Partial<Workspace>): Promise<Workspace | undefined> {
    const [updated] = await db.update(workspaces).set(data).where(eq(workspaces.id, id)).returning();
    return updated;
  }

  async deleteWorkspace(id: string): Promise<void> {
    // Foreign keys with ON DELETE CASCADE handle child table cleanup
    await db.delete(workspaces).where(eq(workspaces.id, id));
  }

  async purgeWorkspaceData(id: string): Promise<void> {
    // Delete child tables that reference scans first (due to FK ordering)
    const childTables = [
      scanProfiles, alerts, scheduledScans, reconModules,
      postureSnapshots, findings, assets, reports,
      continuousMonitoring, uploadedScans, riskItems, policyDocuments, questionnaireRuns,
    ] as const;
    for (const table of childTables) {
      await db.delete(table).where(eq(table.workspaceId, id));
    }
    // Delete scans last (other tables reference it)
    await db.delete(scans).where(eq(scans.workspaceId, id));
  }

  async getPostureHistory(workspaceId: string, limit = 30): Promise<PostureSnapshot[]> {
    return db.select().from(postureSnapshots)
      .where(eq(postureSnapshots.workspaceId, workspaceId))
      .orderBy(desc(postureSnapshots.snapshotAt))
      .limit(limit);
  }

  async createPostureSnapshot(snapshot: InsertPostureSnapshot): Promise<PostureSnapshot> {
    const [created] = await db.insert(postureSnapshots).values(snapshot).returning();
    if (!created) throw new Error("Posture snapshot insert did not return row");
    return created;
  }

  async getAssets(workspaceId: string, opts?: PaginationOpts): Promise<PaginatedResult<Asset>> {
    const limit = opts?.limit ?? DEFAULT_LIMIT;
    const offset = opts?.offset ?? 0;
    const where = eq(assets.workspaceId, workspaceId);
    const [data, [{ total }]] = await Promise.all([
      db.select().from(assets).where(where).orderBy(desc(assets.firstSeen)).limit(limit).offset(offset),
      db.select({ total: count() }).from(assets).where(where),
    ]);
    return { data, total, limit, offset };
  }

  async getAsset(id: string): Promise<Asset | undefined> {
    const [asset] = await db.select().from(assets).where(eq(assets.id, id));
    return asset;
  }

  async assetExists(workspaceId: string, type: string, value: string): Promise<boolean> {
    const [asset] = await db.select().from(assets).where(
      and(eq(assets.workspaceId, workspaceId), eq(assets.type, type), eq(assets.value, value))
    );
    return !!asset;
  }

  async createAsset(asset: InsertAsset): Promise<Asset> {
    const [created] = await db.insert(assets).values(asset)
      .onConflictDoNothing({ target: [assets.workspaceId, assets.type, assets.value] })
      .returning();
    if (created) return created;
    // Asset already exists (race condition); return the existing record
    const [existing] = await db.select().from(assets).where(
      and(eq(assets.workspaceId, asset.workspaceId), eq(assets.type, asset.type), eq(assets.value, asset.value))
    );
    return existing;
  }

  async deleteAsset(id: string): Promise<void> {
    await db.delete(assets).where(eq(assets.id, id));
  }

  async getScans(workspaceId: string, opts?: PaginationOpts): Promise<PaginatedResult<Scan>> {
    const limit = opts?.limit ?? DEFAULT_LIMIT;
    const offset = opts?.offset ?? 0;
    const where = eq(scans.workspaceId, workspaceId);
    const [data, [{ total }]] = await Promise.all([
      db.select().from(scans).where(where).orderBy(desc(scans.startedAt)).limit(limit).offset(offset),
      db.select({ total: count() }).from(scans).where(where),
    ]);
    return { data, total, limit, offset };
  }

  async getStuckScans(maxAgeMs: number): Promise<Scan[]> {
    const cutoff = new Date(Date.now() - maxAgeMs);
    return db.select().from(scans)
      .where(and(eq(scans.status, "running"), lt(scans.startedAt, cutoff)));
  }

  async getScan(id: string): Promise<Scan | undefined> {
    const [scan] = await db.select().from(scans).where(eq(scans.id, id));
    return scan;
  }

  async createScan(scan: InsertScan): Promise<Scan> {
    const [created] = await db.insert(scans).values({
      ...scan,
      startedAt: new Date(),
    }).returning();
    return created;
  }

  async updateScan(id: string, data: Partial<Scan>): Promise<Scan | undefined> {
    const [updated] = await db.update(scans).set(data).where(eq(scans.id, id)).returning();
    return updated;
  }

  async deleteScan(id: string): Promise<void> {
    await db.delete(scans).where(eq(scans.id, id));
  }

  async getFindings(workspaceId: string, opts?: PaginationOpts): Promise<PaginatedResult<Finding>> {
    const limit = opts?.limit ?? DEFAULT_LIMIT;
    const offset = opts?.offset ?? 0;
    const where = eq(findings.workspaceId, workspaceId);
    const [data, [{ total }]] = await Promise.all([
      db.select().from(findings).where(where).orderBy(desc(findings.discoveredAt)).limit(limit).offset(offset),
      db.select({ total: count() }).from(findings).where(where),
    ]);
    return { data, total, limit, offset };
  }

  async getAllFindings(): Promise<Finding[]> {
    return db.select().from(findings).orderBy(desc(findings.discoveredAt));
  }

  async getFinding(id: string): Promise<Finding | undefined> {
    const [finding] = await db.select().from(findings).where(eq(findings.id, id));
    return finding;
  }

  async findingExists(workspaceId: string, title: string, affectedAsset: string, category: string): Promise<boolean> {
    const aff = affectedAsset || "";
    const [finding] = await db.select().from(findings).where(
      and(
        eq(findings.workspaceId, workspaceId),
        eq(findings.title, title),
        sql`COALESCE(${findings.affectedAsset}, '') = ${aff}`,
        eq(findings.category, category)
      )
    );
    return !!finding;
  }

  async createFinding(finding: InsertFinding): Promise<Finding> {
    const [created] = await db.insert(findings).values(finding).returning();
    return created;
  }

  async updateFinding(id: string, data: Partial<Finding>): Promise<Finding | undefined> {
    const updateData: Partial<Finding> = { ...data };
    if (data.status === "resolved") {
      updateData.resolvedAt = new Date();
    }
    const [updated] = await db.update(findings).set(updateData).where(eq(findings.id, id)).returning();
    return updated;
  }

  async getReports(workspaceId: string, opts?: PaginationOpts): Promise<PaginatedResult<Report>> {
    const limit = opts?.limit ?? DEFAULT_LIMIT;
    const offset = opts?.offset ?? 0;
    const where = eq(reports.workspaceId, workspaceId);
    const [data, [{ total }]] = await Promise.all([
      db.select().from(reports).where(where).orderBy(desc(reports.generatedAt)).limit(limit).offset(offset),
      db.select({ total: count() }).from(reports).where(where),
    ]);
    return { data, total, limit, offset };
  }

  async getReport(id: string): Promise<Report | undefined> {
    const [report] = await db.select().from(reports).where(eq(reports.id, id));
    return report;
  }

  async createReport(report: InsertReport): Promise<Report> {
    const [created] = await db.insert(reports).values({
      ...report,
      generatedAt: new Date(),
    }).returning();
    return created;
  }

  async updateReport(id: string, data: Partial<Report>): Promise<Report | undefined> {
    const [updated] = await db.update(reports).set(data).where(eq(reports.id, id)).returning();
    return updated;
  }

  async deleteReport(id: string): Promise<void> {
    await db.delete(reports).where(eq(reports.id, id));
  }

  async getReconModules(workspaceId: string, opts?: PaginationOpts): Promise<PaginatedResult<ReconModule>> {
    const limit = opts?.limit ?? DEFAULT_LIMIT;
    const offset = opts?.offset ?? 0;
    const where = eq(reconModules.workspaceId, workspaceId);
    const [data, [{ total }]] = await Promise.all([
      db.select().from(reconModules).where(where).orderBy(desc(reconModules.generatedAt)).limit(limit).offset(offset),
      db.select({ total: count() }).from(reconModules).where(where),
    ]);
    return { data, total, limit, offset };
  }

  async getReconModule(id: string): Promise<ReconModule | undefined> {
    const [mod] = await db.select().from(reconModules).where(eq(reconModules.id, id));
    return mod;
  }

  async getReconModulesByType(workspaceId: string, moduleType: string): Promise<ReconModule[]> {
    return db.select().from(reconModules)
      .where(and(eq(reconModules.workspaceId, workspaceId), eq(reconModules.moduleType, moduleType)))
      .orderBy(desc(reconModules.generatedAt));
  }

  async createReconModule(mod: InsertReconModule): Promise<ReconModule> {
    const [created] = await db.insert(reconModules).values(mod).returning();
    return created;
  }

  async updateReconModule(id: string, data: Partial<ReconModule>): Promise<ReconModule | undefined> {
    const [updated] = await db.update(reconModules).set(data).where(eq(reconModules.id, id)).returning();
    return updated;
  }

  async getContinuousMonitoringByWorkspace(workspaceId: string): Promise<ContinuousMonitoring | undefined> {
    const rows = await db.select().from(continuousMonitoring).where(eq(continuousMonitoring.workspaceId, workspaceId)).orderBy(desc(continuousMonitoring.createdAt)).limit(1);
    return rows[0];
  }

  async createContinuousMonitoring(mod: InsertContinuousMonitoring): Promise<ContinuousMonitoring> {
    const [created] = await db.insert(continuousMonitoring).values(mod).returning();
    return created;
  }

  async updateContinuousMonitoring(id: string, data: Partial<ContinuousMonitoring>): Promise<ContinuousMonitoring | undefined> {
    const [updated] = await db.update(continuousMonitoring).set(data).where(eq(continuousMonitoring.id, id)).returning();
    return updated;
  }

  async getUploadedScans(workspaceId: string): Promise<UploadedScan[]> {
    return db.select().from(uploadedScans).where(eq(uploadedScans.workspaceId, workspaceId)).orderBy(desc(uploadedScans.createdAt));
  }

  async getUploadedScan(id: string): Promise<UploadedScan | undefined> {
    const [scan] = await db.select().from(uploadedScans).where(eq(uploadedScans.id, id));
    return scan;
  }

  async createUploadedScan(scan: InsertUploadedScan): Promise<UploadedScan> {
    const [created] = await db.insert(uploadedScans).values(scan).returning();
    return created;
  }

  async deleteUploadedScan(id: string): Promise<void> {
    await db.delete(uploadedScans).where(eq(uploadedScans.id, id));
  }

  // ── Workspace Members ──

  async getWorkspaceMember(workspaceId: string, userId: string): Promise<WorkspaceMember | undefined> {
    const [member] = await db.select().from(workspaceMembers)
      .where(and(eq(workspaceMembers.workspaceId, workspaceId), eq(workspaceMembers.userId, userId)))
      .limit(1);
    return member;
  }

  async addWorkspaceMember(workspaceId: string, userId: string, role: string): Promise<WorkspaceMember> {
    const [member] = await db.insert(workspaceMembers)
      .values({ workspaceId, userId, role })
      .returning();
    return member;
  }

  async getWorkspacesByUserId(userId: string): Promise<Workspace[]> {
    const members = await db.select({ workspaceId: workspaceMembers.workspaceId })
      .from(workspaceMembers)
      .where(eq(workspaceMembers.userId, userId));
    if (members.length === 0) return [];
    const wsIds = members.map(m => m.workspaceId);
    return db.select().from(workspaces).where(inArray(workspaces.id, wsIds));
  }

  // ── Alerts ──

  async getAlert(id: string): Promise<Alert | undefined> {
    const [alert] = await db.select().from(alerts).where(eq(alerts.id, id)).limit(1);
    return alert;
  }

  async getAlerts(workspaceId: string, limit = 50): Promise<Alert[]> {
    return db.select().from(alerts)
      .where(eq(alerts.workspaceId, workspaceId))
      .orderBy(desc(alerts.createdAt))
      .limit(limit);
  }

  async getUnreadAlertCount(workspaceId: string): Promise<number> {
    const [row] = await db.select({ count: sql<number>`count(*)::int` })
      .from(alerts)
      .where(and(eq(alerts.workspaceId, workspaceId), eq(alerts.read, false)));
    return row?.count ?? 0;
  }

  async createAlert(alert: InsertAlert): Promise<Alert> {
    const [created] = await db.insert(alerts).values(alert).returning();
    return created;
  }

  async markAlertRead(id: string): Promise<Alert | undefined> {
    const [updated] = await db.update(alerts).set({ read: true }).where(eq(alerts.id, id)).returning();
    return updated;
  }

  async markAllAlertsRead(workspaceId: string): Promise<void> {
    await db.update(alerts).set({ read: true }).where(and(eq(alerts.workspaceId, workspaceId), eq(alerts.read, false)));
  }

  async deleteAlert(id: string): Promise<void> {
    await db.delete(alerts).where(eq(alerts.id, id));
  }

  // ── Scheduled Scans ──

  async getScheduledScans(workspaceId: string): Promise<ScheduledScan[]> {
    return db.select().from(scheduledScans)
      .where(eq(scheduledScans.workspaceId, workspaceId))
      .orderBy(desc(scheduledScans.createdAt));
  }

  async getScheduledScan(id: string): Promise<ScheduledScan | undefined> {
    const [row] = await db.select().from(scheduledScans).where(eq(scheduledScans.id, id));
    return row;
  }

  async getDueScheduledScans(): Promise<ScheduledScan[]> {
    return db.select().from(scheduledScans)
      .where(and(
        eq(scheduledScans.enabled, true),
        sql`${scheduledScans.nextRunAt} <= NOW()`,
      ))
      .orderBy(asc(scheduledScans.nextRunAt));
  }

  async createScheduledScan(scan: InsertScheduledScan): Promise<ScheduledScan> {
    const [created] = await db.insert(scheduledScans).values(scan).returning();
    return created;
  }

  async updateScheduledScan(id: string, data: Partial<ScheduledScan>): Promise<ScheduledScan | undefined> {
    const [updated] = await db.update(scheduledScans).set(data).where(eq(scheduledScans.id, id)).returning();
    return updated;
  }

  async deleteScheduledScan(id: string): Promise<void> {
    await db.delete(scheduledScans).where(eq(scheduledScans.id, id));
  }

  // ── Scan Profiles ──

  async getScanProfiles(workspaceId: string): Promise<ScanProfile[]> {
    return db.select().from(scanProfiles)
      .where(eq(scanProfiles.workspaceId, workspaceId))
      .orderBy(desc(scanProfiles.createdAt));
  }

  async getScanProfile(id: string): Promise<ScanProfile | undefined> {
    const [row] = await db.select().from(scanProfiles).where(eq(scanProfiles.id, id));
    return row;
  }

  async createScanProfile(profile: InsertScanProfile): Promise<ScanProfile> {
    const [created] = await db.insert(scanProfiles).values(profile).returning();
    return created;
  }

  async updateScanProfile(id: string, data: Partial<ScanProfile>): Promise<ScanProfile | undefined> {
    const [updated] = await db.update(scanProfiles)
      .set({ ...data, updatedAt: new Date() })
      .where(eq(scanProfiles.id, id))
      .returning();
    return updated;
  }

  async deleteScanProfile(id: string): Promise<void> {
    await db.delete(scanProfiles).where(eq(scanProfiles.id, id));
  }

  // ── Risk Register ──

  async getRiskItems(workspaceId: string): Promise<RiskItem[]> {
    return db.select().from(riskItems)
      .where(eq(riskItems.workspaceId, workspaceId))
      .orderBy(desc(riskItems.riskScore), desc(riskItems.createdAt));
  }

  async getRiskItem(id: string): Promise<RiskItem | undefined> {
    const [row] = await db.select().from(riskItems).where(eq(riskItems.id, id));
    return row;
  }

  async getRiskItemByFingerprint(workspaceId: string, fingerprint: string): Promise<RiskItem | undefined> {
    const [row] = await db.select().from(riskItems)
      .where(and(eq(riskItems.workspaceId, workspaceId), eq(riskItems.fingerprint, fingerprint)));
    return row;
  }

  async createRiskItem(item: InsertRiskItem): Promise<RiskItem> {
    const [created] = await db.insert(riskItems).values(item).returning();
    return created;
  }

  async updateRiskItem(id: string, data: Partial<RiskItem>): Promise<RiskItem | undefined> {
    const [updated] = await db.update(riskItems)
      .set({ ...data, updatedAt: new Date() })
      .where(eq(riskItems.id, id))
      .returning();
    return updated;
  }

  async deleteRiskItem(id: string): Promise<void> {
    await db.delete(riskItems).where(eq(riskItems.id, id));
  }

  // ── Policy Documents ──

  async getPolicyDocuments(workspaceId: string): Promise<PolicyDocument[]> {
    return db.select().from(policyDocuments)
      .where(eq(policyDocuments.workspaceId, workspaceId))
      .orderBy(asc(policyDocuments.policyType));
  }

  async getPolicyDocument(id: string): Promise<PolicyDocument | undefined> {
    const [row] = await db.select().from(policyDocuments).where(eq(policyDocuments.id, id));
    return row;
  }

  async getPolicyDocumentByType(workspaceId: string, policyType: string): Promise<PolicyDocument | undefined> {
    const [row] = await db.select().from(policyDocuments)
      .where(and(eq(policyDocuments.workspaceId, workspaceId), eq(policyDocuments.policyType, policyType)));
    return row;
  }

  async createPolicyDocument(doc: InsertPolicyDocument): Promise<PolicyDocument> {
    const [created] = await db.insert(policyDocuments).values(doc).returning();
    return created;
  }

  async updatePolicyDocument(id: string, data: Partial<PolicyDocument>): Promise<PolicyDocument | undefined> {
    const [updated] = await db.update(policyDocuments)
      .set({ ...data, updatedAt: new Date() })
      .where(eq(policyDocuments.id, id))
      .returning();
    return updated;
  }

  async deletePolicyDocument(id: string): Promise<void> {
    await db.delete(policyDocuments).where(eq(policyDocuments.id, id));
  }

  // ── Questionnaire Runs ──

  async getQuestionnaireRuns(workspaceId: string): Promise<QuestionnaireRun[]> {
    return db.select().from(questionnaireRuns)
      .where(eq(questionnaireRuns.workspaceId, workspaceId))
      .orderBy(desc(questionnaireRuns.createdAt));
  }

  async getQuestionnaireRun(id: string): Promise<QuestionnaireRun | undefined> {
    const [row] = await db.select().from(questionnaireRuns).where(eq(questionnaireRuns.id, id));
    return row;
  }

  async createQuestionnaireRun(run: InsertQuestionnaireRun): Promise<QuestionnaireRun> {
    const [created] = await db.insert(questionnaireRuns).values(run).returning();
    return created;
  }

  // ── Enrichment: Certificate Inventory ──

  async getCertificates(workspaceId: string, opts?: { expiringWithinDays?: number }): Promise<TlsCertificate[]> {
    const conditions = [eq(tlsCertificates.workspaceId, workspaceId)];
    if (opts?.expiringWithinDays != null) {
      const cutoff = new Date(Date.now() + opts.expiringWithinDays * 86_400_000);
      conditions.push(lt(tlsCertificates.validTo, cutoff));
    }
    return db.select().from(tlsCertificates)
      .where(and(...conditions))
      .orderBy(asc(tlsCertificates.validTo));
  }

  async upsertCertificate(cert: Omit<InsertTlsCertificate, "id">): Promise<void> {
    await db.insert(tlsCertificates)
      .values({ ...cert, lastSeen: new Date() })
      .onConflictDoUpdate({
        target: [tlsCertificates.workspaceId, tlsCertificates.host, tlsCertificates.fingerprint],
        set: {
          subject: cert.subject,
          issuer: cert.issuer,
          validFrom: cert.validFrom,
          validTo: cert.validTo,
          daysRemaining: cert.daysRemaining,
          protocol: cert.protocol,
          san: cert.san,
          signatureAlgorithm: cert.signatureAlgorithm,
          isWildcard: cert.isWildcard,
          lastSeen: new Date(),
        },
      });
  }

  // ── Enrichment: Tech Inventory ──

  async getTechInventory(workspaceId: string): Promise<TechInventoryItem[]> {
    return db.select().from(techInventory)
      .where(eq(techInventory.workspaceId, workspaceId))
      .orderBy(asc(techInventory.product), asc(techInventory.version));
  }

  async upsertTechInventory(item: Omit<InsertTechInventoryItem, "id">): Promise<void> {
    await db.insert(techInventory)
      .values({ ...item, lastSeen: new Date() })
      .onConflictDoUpdate({
        target: [techInventory.workspaceId, techInventory.host, techInventory.product, techInventory.version],
        set: {
          source: item.source,
          confidence: item.confidence,
          eol: item.eol,
          lastSeen: new Date(),
        },
      });
  }

  // ── Enrichment: EPSS Scores ──

  async getEpssScore(cveId: string): Promise<EpssScore | undefined> {
    const [row] = await db.select().from(epssScores).where(eq(epssScores.cveId, cveId));
    return row;
  }

  async upsertEpssScore(score: InsertEpssScore): Promise<void> {
    await db.insert(epssScores)
      .values({ ...score, updatedAt: new Date() })
      .onConflictDoUpdate({
        target: epssScores.cveId,
        set: { epss: score.epss, percentile: score.percentile, updatedAt: new Date() },
      });
  }

  // ── Enrichment: Finding Priority ──

  async getFindingPriorities(workspaceId: string, limit = 50): Promise<Array<FindingPriority & { finding: Finding }>> {
    const rows = await db
      .select()
      .from(findingPriority)
      .innerJoin(findings, eq(findingPriority.findingId, findings.id))
      .where(eq(findings.workspaceId, workspaceId))
      .orderBy(desc(findingPriority.compositeScore))
      .limit(limit);

    return rows.map((r) => ({ ...r.finding_priority, finding: r.findings }));
  }

  async upsertFindingPriority(priority: InsertFindingPriority): Promise<void> {
    await db.insert(findingPriority)
      .values({ ...priority, computedAt: new Date() })
      .onConflictDoUpdate({
        target: findingPriority.findingId,
        set: {
          cvssComponent: priority.cvssComponent,
          epssComponent: priority.epssComponent,
          kevComponent: priority.kevComponent,
          exposureComponent: priority.exposureComponent,
          ageComponent: priority.ageComponent,
          compositeScore: priority.compositeScore,
          rank: priority.rank,
          computedAt: new Date(),
        },
      });
  }

  // ── Enrichment: Posture Anomalies ──

  async getPostureAnomalies(workspaceId: string, limit = 20): Promise<PostureAnomaly[]> {
    return db.select().from(postureAnomalies)
      .where(eq(postureAnomalies.workspaceId, workspaceId))
      .orderBy(desc(postureAnomalies.detectedAt))
      .limit(limit);
  }

  async createPostureAnomaly(anomaly: InsertPostureAnomaly): Promise<PostureAnomaly> {
    const [created] = await db.insert(postureAnomalies).values(anomaly).returning();
    return created;
  }

  async acknowledgePostureAnomaly(id: string): Promise<void> {
    await db.update(postureAnomalies)
      .set({ acknowledged: true })
      .where(eq(postureAnomalies.id, id));
  }

  // ── Evidence Search ──

  async searchEvidence(
    workspaceId: string,
    query: string,
    limit = 50,
  ): Promise<Array<{ type: "finding" | "recon"; id: string; title: string; snippet: string; host: string | null }>> {
    const safeLimit = Math.min(limit, 100);

    // Search findings
    const findingRows = await db
      .select({
        id: findings.id,
        title: findings.title,
        description: findings.description,
        affectedAsset: findings.affectedAsset,
      })
      .from(findings)
      .where(
        and(
          eq(findings.workspaceId, workspaceId),
          sql`(to_tsvector('english', ${findings.title} || ' ' || coalesce(${findings.description}, ''))
               @@ plainto_tsquery('english', ${query}))`,
        ),
      )
      .limit(safeLimit);

    const findingResults = findingRows.map((r) => ({
      type: "finding" as const,
      id: r.id,
      title: r.title,
      snippet: (r.description ?? "").slice(0, 200),
      host: r.affectedAsset,
    }));

    // Search recon modules (target field + moduleType)
    const reconRows = await db
      .select({
        id: reconModules.id,
        target: reconModules.target,
        moduleType: reconModules.moduleType,
      })
      .from(reconModules)
      .where(
        and(
          eq(reconModules.workspaceId, workspaceId),
          sql`(to_tsvector('english', ${reconModules.target} || ' ' || ${reconModules.moduleType})
               @@ plainto_tsquery('english', ${query}))`,
        ),
      )
      .limit(safeLimit);

    const reconResults = reconRows.map((r) => ({
      type: "recon" as const,
      id: r.id,
      title: `${r.moduleType}: ${r.target}`,
      snippet: `Recon module data for ${r.target}`,
      host: r.target,
    }));

    return [...findingResults, ...reconResults].slice(0, safeLimit);
  }
}

export const storage = new DatabaseStorage();
