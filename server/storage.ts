import { eq, desc, and, sql, lt } from "drizzle-orm";
import { db } from "./db";
import { workspaces, assets, scans, findings, reports, reconModules, continuousMonitoring, uploadedScans, postureSnapshots } from "@shared/schema";
import type { Workspace, InsertWorkspace, Asset, InsertAsset, Scan, InsertScan, Finding, InsertFinding, Report, InsertReport, ReconModule, InsertReconModule, ContinuousMonitoring, InsertContinuousMonitoring, UploadedScan, InsertUploadedScan, PostureSnapshot, InsertPostureSnapshot } from "@shared/schema";

export interface IStorage {
  getWorkspaces(): Promise<Workspace[]>;
  getWorkspace(id: string): Promise<Workspace | undefined>;
  getWorkspaceByName(name: string): Promise<Workspace | undefined>;
  createWorkspace(ws: InsertWorkspace): Promise<Workspace>;
  updateWorkspace(id: string, data: Partial<Workspace>): Promise<Workspace | undefined>;
  deleteWorkspace(id: string): Promise<void>;
  purgeWorkspaceData(id: string): Promise<void>;

  getAssets(workspaceId: string): Promise<Asset[]>;
  getAsset(id: string): Promise<Asset | undefined>;
  assetExists(workspaceId: string, type: string, value: string): Promise<boolean>;
  createAsset(asset: InsertAsset): Promise<Asset>;
  deleteAsset(id: string): Promise<void>;

  getScans(workspaceId: string): Promise<Scan[]>;
  getScan(id: string): Promise<Scan | undefined>;
  createScan(scan: InsertScan): Promise<Scan>;
  updateScan(id: string, data: Partial<Scan>): Promise<Scan | undefined>;
  deleteScan(id: string): Promise<void>;

  getFindings(workspaceId: string): Promise<Finding[]>;
  getAllFindings(): Promise<Finding[]>;
  getFinding(id: string): Promise<Finding | undefined>;
  findingExists(workspaceId: string, title: string, affectedAsset: string, category: string): Promise<boolean>;
  createFinding(finding: InsertFinding): Promise<Finding>;
  updateFinding(id: string, data: Partial<Finding>): Promise<Finding | undefined>;

  getReports(workspaceId: string): Promise<Report[]>;
  getReport(id: string): Promise<Report | undefined>;
  createReport(report: InsertReport): Promise<Report>;
  updateReport(id: string, data: Partial<Report>): Promise<Report | undefined>;
  deleteReport(id: string): Promise<void>;

  getReconModules(workspaceId: string): Promise<ReconModule[]>;
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
}

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
    await db.delete(assets).where(eq(assets.workspaceId, id));
    await db.delete(findings).where(eq(findings.workspaceId, id));
    await db.delete(scans).where(eq(scans.workspaceId, id));
    await db.delete(reports).where(eq(reports.workspaceId, id));
    await db.delete(reconModules).where(eq(reconModules.workspaceId, id));
    await db.delete(continuousMonitoring).where(eq(continuousMonitoring.workspaceId, id));
    await db.delete(uploadedScans).where(eq(uploadedScans.workspaceId, id));
    await db.delete(postureSnapshots).where(eq(postureSnapshots.workspaceId, id));
    await db.delete(workspaces).where(eq(workspaces.id, id));
  }

  async purgeWorkspaceData(id: string): Promise<void> {
    await db.delete(assets).where(eq(assets.workspaceId, id));
    await db.delete(findings).where(eq(findings.workspaceId, id));
    await db.delete(scans).where(eq(scans.workspaceId, id));
    await db.delete(reports).where(eq(reports.workspaceId, id));
    await db.delete(reconModules).where(eq(reconModules.workspaceId, id));
    await db.delete(continuousMonitoring).where(eq(continuousMonitoring.workspaceId, id));
    await db.delete(uploadedScans).where(eq(uploadedScans.workspaceId, id));
    await db.delete(postureSnapshots).where(eq(postureSnapshots.workspaceId, id));
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

  async getAssets(workspaceId: string): Promise<Asset[]> {
    return db.select().from(assets).where(eq(assets.workspaceId, workspaceId)).orderBy(desc(assets.firstSeen));
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

  async getScans(workspaceId: string): Promise<Scan[]> {
    return db.select().from(scans).where(eq(scans.workspaceId, workspaceId)).orderBy(desc(scans.startedAt));
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

  async getFindings(workspaceId: string): Promise<Finding[]> {
    return db.select().from(findings).where(eq(findings.workspaceId, workspaceId)).orderBy(desc(findings.discoveredAt));
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

  async getReports(workspaceId: string): Promise<Report[]> {
    return db.select().from(reports).where(eq(reports.workspaceId, workspaceId)).orderBy(desc(reports.generatedAt));
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

  async getReconModules(workspaceId: string): Promise<ReconModule[]> {
    return db.select().from(reconModules).where(eq(reconModules.workspaceId, workspaceId)).orderBy(desc(reconModules.generatedAt));
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
}

export const storage = new DatabaseStorage();
