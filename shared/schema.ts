import { sql } from "drizzle-orm";
import { pgTable, text, varchar, integer, timestamp, jsonb, boolean, index, unique } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const workspaces = pgTable("workspaces", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull().unique(),
  description: text("description"),
  status: text("status").notNull().default("active"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const assets = pgTable("assets", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  workspaceId: varchar("workspace_id").notNull(),
  type: text("type").notNull(),
  value: text("value").notNull(),
  status: text("status").notNull().default("active"),
  firstSeen: timestamp("first_seen").defaultNow(),
  lastSeen: timestamp("last_seen").defaultNow(),
  metadata: jsonb("metadata").$type<Record<string, unknown>>(),
  tags: text("tags").array().default(sql`'{}'::text[]`),
}, (t) => [
  index("assets_workspace_id_idx").on(t.workspaceId),
  unique("assets_workspace_type_value_unique").on(t.workspaceId, t.type, t.value),
]);

export const scans = pgTable("scans", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  workspaceId: varchar("workspace_id").notNull(),
  type: text("type").notNull(),
  target: text("target").notNull(),
  status: text("status").notNull().default("pending"),
  startedAt: timestamp("started_at"),
  completedAt: timestamp("completed_at"),
  findingsCount: integer("findings_count").default(0),
  summary: jsonb("summary").$type<Record<string, unknown>>(),
  errorMessage: text("error_message"),
  progressMessage: text("progress_message"),
  progressPercent: integer("progress_percent"),
  currentStep: text("current_step"),
  estimatedSecondsRemaining: integer("estimated_seconds_remaining"),
}, (t) => [
  index("scans_workspace_id_idx").on(t.workspaceId),
  index("scans_status_idx").on(t.status),
]);

export const findings = pgTable("findings", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  workspaceId: varchar("workspace_id").notNull(),
  scanId: varchar("scan_id"),
  title: text("title").notNull(),
  description: text("description").notNull(),
  severity: text("severity").notNull(),
  status: text("status").notNull().default("open"),
  category: text("category").notNull(),
  affectedAsset: text("affected_asset"),
  evidence: jsonb("evidence").$type<Record<string, unknown>[]>(),
  cvssScore: text("cvss_score"),
  remediation: text("remediation"),
  assignee: text("assignee"),
  discoveredAt: timestamp("discovered_at").defaultNow(),
  resolvedAt: timestamp("resolved_at"),
  tags: text("tags").array().default(sql`'{}'::text[]`),
  aiEnrichment: jsonb("ai_enrichment").$type<Record<string, unknown>>(),
}, (t) => [
  index("findings_workspace_id_idx").on(t.workspaceId),
  index("findings_scan_id_idx").on(t.scanId),
]);

export const uploadedScans = pgTable("uploaded_scans", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  workspaceId: varchar("workspace_id").notNull(),
  filename: text("filename").notNull(),
  fileType: text("file_type").notNull(),
  rawContent: text("raw_content").notNull(),
  parsedData: jsonb("parsed_data").$type<Record<string, unknown>>(),
  createdAt: timestamp("created_at").defaultNow(),
});

export const reports = pgTable("reports", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  workspaceId: varchar("workspace_id").notNull(),
  title: text("title").notNull(),
  type: text("type").notNull(),
  status: text("status").notNull().default("draft"),
  findingIds: text("finding_ids").array().default(sql`'{}'::text[]`),
  generatedAt: timestamp("generated_at"),
  content: jsonb("content").$type<Record<string, unknown>>(),
  summary: text("summary"),
}, (t) => [
  index("reports_workspace_id_idx").on(t.workspaceId),
]);

export const continuousMonitoring = pgTable("continuous_monitoring", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  workspaceId: varchar("workspace_id").notNull(),
  target: text("target").notNull(),
  status: text("status").notNull().default("running"),
  iterationCount: integer("iteration_count").default(0),
  progressPercent: integer("progress_percent"),
  progressMessage: text("progress_message"),
  currentStep: text("current_step"),
  lastIterationAt: timestamp("last_iteration_at"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const postureSnapshots = pgTable("posture_snapshots", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  workspaceId: varchar("workspace_id").notNull(),
  scanId: varchar("scan_id"),
  target: text("target").notNull(),
  snapshotAt: timestamp("snapshot_at").notNull().defaultNow(),
  surfaceRiskScore: integer("surface_risk_score"),
  tlsGrade: text("tls_grade"),
  securityScore: integer("security_score"),
  findingsCount: integer("findings_count").default(0),
  criticalCount: integer("critical_count").default(0),
  highCount: integer("high_count").default(0),
  openPortsCount: integer("open_ports_count").default(0),
  wafCoverage: integer("waf_coverage"),
  metadata: jsonb("metadata").$type<Record<string, unknown>>(),
}, (t) => [
  index("posture_snapshots_workspace_id_idx").on(t.workspaceId),
  index("posture_snapshots_snapshot_at_idx").on(t.snapshotAt),
]);

export const reconModules = pgTable("recon_modules", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  workspaceId: varchar("workspace_id").notNull(),
  scanId: varchar("scan_id"),
  target: text("target").notNull(),
  moduleType: text("module_type").notNull(),
  data: jsonb("data").$type<Record<string, unknown>>().notNull(),
  confidence: integer("confidence").default(0),
  generatedAt: timestamp("generated_at").defaultNow(),
}, (t) => [
  index("recon_modules_workspace_id_idx").on(t.workspaceId),
]);

export const insertWorkspaceSchema = createInsertSchema(workspaces).omit({ id: true, createdAt: true });
export const insertAssetSchema = createInsertSchema(assets).omit({ id: true, firstSeen: true, lastSeen: true });
export const insertScanSchema = createInsertSchema(scans).omit({ id: true, startedAt: true, completedAt: true, findingsCount: true, summary: true });
export const insertFindingSchema = createInsertSchema(findings).omit({ id: true, discoveredAt: true, resolvedAt: true });
export const insertReportSchema = createInsertSchema(reports).omit({ id: true, generatedAt: true, content: true });
export const insertPostureSnapshotSchema = createInsertSchema(postureSnapshots).omit({ id: true });
export const insertReconModuleSchema = createInsertSchema(reconModules).omit({ id: true, generatedAt: true });
export const insertContinuousMonitoringSchema = createInsertSchema(continuousMonitoring).omit({ id: true, createdAt: true });
export const insertUploadedScanSchema = createInsertSchema(uploadedScans).omit({ id: true, createdAt: true });

export type Workspace = typeof workspaces.$inferSelect;
export type InsertWorkspace = z.infer<typeof insertWorkspaceSchema>;
export type Asset = typeof assets.$inferSelect;
export type InsertAsset = z.infer<typeof insertAssetSchema>;
export type Scan = typeof scans.$inferSelect;
export type InsertScan = z.infer<typeof insertScanSchema>;
export type Finding = typeof findings.$inferSelect;
export type InsertFinding = z.infer<typeof insertFindingSchema>;
export type Report = typeof reports.$inferSelect;
export type InsertReport = z.infer<typeof insertReportSchema>;
export type PostureSnapshot = typeof postureSnapshots.$inferSelect;
export type InsertPostureSnapshot = z.infer<typeof insertPostureSnapshotSchema>;
export type ReconModule = typeof reconModules.$inferSelect;
export type InsertReconModule = z.infer<typeof insertReconModuleSchema>;
export type ContinuousMonitoring = typeof continuousMonitoring.$inferSelect;
export type InsertContinuousMonitoring = z.infer<typeof insertContinuousMonitoringSchema>;
export type UploadedScan = typeof uploadedScans.$inferSelect;
export type InsertUploadedScan = z.infer<typeof insertUploadedScanSchema>;
