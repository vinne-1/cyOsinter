import { sql } from "drizzle-orm";
import { pgTable, text, varchar, integer, timestamp, jsonb, boolean, index, unique, foreignKey } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

/** Domain validation regex — shared between server and client */
export const DOMAIN_REGEX = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

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
  foreignKey({ columns: [t.workspaceId], foreignColumns: [workspaces.id], name: "assets_workspace_fk" }).onDelete("cascade"),
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
  foreignKey({ columns: [t.workspaceId], foreignColumns: [workspaces.id], name: "scans_workspace_fk" }).onDelete("cascade"),
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
  assigneeId: varchar("assignee_id"),
  priority: integer("priority"), // 1=critical, 2=high, 3=medium, 4=low
  dueDate: timestamp("due_date"),
  slaBreached: boolean("sla_breached").default(false),
  workflowState: text("workflow_state").notNull().default("open"), // open, triaged, in_progress, remediated, verified, closed
  groupId: varchar("group_id"),
  verificationScanId: varchar("verification_scan_id"),
  discoveredAt: timestamp("discovered_at").defaultNow(),
  resolvedAt: timestamp("resolved_at"),
  tags: text("tags").array().default(sql`'{}'::text[]`),
  aiEnrichment: jsonb("ai_enrichment").$type<Record<string, unknown>>(),
}, (t) => [
  index("findings_workspace_id_idx").on(t.workspaceId),
  index("findings_scan_id_idx").on(t.scanId),
  foreignKey({ columns: [t.workspaceId], foreignColumns: [workspaces.id], name: "findings_workspace_fk" }).onDelete("cascade"),
  foreignKey({ columns: [t.scanId], foreignColumns: [scans.id], name: "findings_scan_fk" }).onDelete("set null"),
]);

export const uploadedScans = pgTable("uploaded_scans", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  workspaceId: varchar("workspace_id").notNull(),
  filename: text("filename").notNull(),
  fileType: text("file_type").notNull(),
  rawContent: text("raw_content").notNull(),
  parsedData: jsonb("parsed_data").$type<Record<string, unknown>>(),
  createdAt: timestamp("created_at").defaultNow(),
}, (t) => [
  index("uploaded_scans_workspace_id_idx").on(t.workspaceId),
  foreignKey({ columns: [t.workspaceId], foreignColumns: [workspaces.id], name: "uploaded_scans_workspace_fk" }).onDelete("cascade"),
]);

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
  foreignKey({ columns: [t.workspaceId], foreignColumns: [workspaces.id], name: "reports_workspace_fk" }).onDelete("cascade"),
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
}, (t) => [
  index("continuous_monitoring_workspace_id_idx").on(t.workspaceId),
  foreignKey({ columns: [t.workspaceId], foreignColumns: [workspaces.id], name: "continuous_monitoring_workspace_fk" }).onDelete("cascade"),
]);

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
  foreignKey({ columns: [t.workspaceId], foreignColumns: [workspaces.id], name: "posture_snapshots_workspace_fk" }).onDelete("cascade"),
  foreignKey({ columns: [t.scanId], foreignColumns: [scans.id], name: "posture_snapshots_scan_fk" }).onDelete("set null"),
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
  foreignKey({ columns: [t.workspaceId], foreignColumns: [workspaces.id], name: "recon_modules_workspace_fk" }).onDelete("cascade"),
  foreignKey({ columns: [t.scanId], foreignColumns: [scans.id], name: "recon_modules_scan_fk" }).onDelete("set null"),
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

// ── Phase 1: Alerts & Scheduled Scans ──

export const alerts = pgTable("alerts", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  workspaceId: varchar("workspace_id").notNull(),
  scanId: varchar("scan_id"),
  findingId: varchar("finding_id"),
  type: text("type").notNull(), // scan_completed, scan_failed, new_critical_finding, new_high_finding, scheduled_scan_triggered
  title: text("title").notNull(),
  message: text("message").notNull(),
  severity: text("severity").notNull().default("info"), // critical, high, medium, low, info
  read: boolean("read").notNull().default(false),
  metadata: jsonb("metadata").$type<Record<string, unknown>>(),
  createdAt: timestamp("created_at").defaultNow(),
}, (t) => [
  index("alerts_workspace_id_idx").on(t.workspaceId),
  index("alerts_read_idx").on(t.read),
  foreignKey({ columns: [t.workspaceId], foreignColumns: [workspaces.id], name: "alerts_workspace_fk" }).onDelete("cascade"),
  foreignKey({ columns: [t.scanId], foreignColumns: [scans.id], name: "alerts_scan_fk" }).onDelete("set null"),
  foreignKey({ columns: [t.findingId], foreignColumns: [findings.id], name: "alerts_finding_fk" }).onDelete("set null"),
]);

export const scheduledScans = pgTable("scheduled_scans", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  workspaceId: varchar("workspace_id").notNull(),
  target: text("target").notNull(),
  scanType: text("scan_type").notNull().default("full"), // easm, osint, full
  cronExpression: text("cron_expression").notNull(), // e.g. "0 2 * * 1" (Mon 2am)
  enabled: boolean("enabled").notNull().default(true),
  lastRunAt: timestamp("last_run_at"),
  nextRunAt: timestamp("next_run_at"),
  lastScanId: varchar("last_scan_id"),
  mode: text("mode").notNull().default("standard"), // standard, gold
  createdAt: timestamp("created_at").defaultNow(),
}, (t) => [
  index("scheduled_scans_workspace_id_idx").on(t.workspaceId),
  index("scheduled_scans_enabled_idx").on(t.enabled),
  foreignKey({ columns: [t.workspaceId], foreignColumns: [workspaces.id], name: "scheduled_scans_workspace_fk" }).onDelete("cascade"),
  foreignKey({ columns: [t.lastScanId], foreignColumns: [scans.id], name: "scheduled_scans_last_scan_fk" }).onDelete("set null"),
]);

export const insertAlertSchema = createInsertSchema(alerts).omit({ id: true, createdAt: true });
export const insertScheduledScanSchema = createInsertSchema(scheduledScans).omit({ id: true, createdAt: true });

// ── Phase 4: Scan Profiles & Integrations ──

export const scanProfiles = pgTable("scan_profiles", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  workspaceId: varchar("workspace_id").notNull(),
  name: text("name").notNull(),
  description: text("description"),
  scanType: text("scan_type").notNull().default("full"),
  mode: text("mode").notNull().default("standard"),
  config: jsonb("config").$type<ScanProfileConfig>().notNull(),
  isDefault: boolean("is_default").notNull().default(false),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (t) => [
  index("scan_profiles_workspace_id_idx").on(t.workspaceId),
  foreignKey({ columns: [t.workspaceId], foreignColumns: [workspaces.id], name: "scan_profiles_workspace_fk" }).onDelete("cascade"),
]);

export interface ScanProfileConfig {
  enableTakeoverCheck?: boolean;
  enableApiDiscovery?: boolean;
  enableSecretScan?: boolean;
  enableNuclei?: boolean;
  subdomainWordlistCap?: number;
  directoryWordlistCap?: number;
  portScanEnabled?: boolean;
  customPorts?: number[];
  excludePaths?: string[];
  maxConcurrency?: number;
  timeoutMinutes?: number;
}

export const insertScanProfileSchema = createInsertSchema(scanProfiles).omit({ id: true, createdAt: true, updatedAt: true });

// ── Phase 1: Auth, RBAC & Audit ──

export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  email: text("email").notNull().unique(),
  passwordHash: text("password_hash").notNull(),
  name: text("name"),
  role: text("role").notNull().default("analyst"), // superadmin, admin, analyst, viewer
  totpSecret: text("totp_secret"),
  totpEnabled: boolean("totp_enabled").notNull().default(false),
  lastLoginAt: timestamp("last_login_at"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (t) => [
  index("users_email_idx").on(t.email),
]);

export const sessions = pgTable("sessions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull(),
  token: text("token").notNull().unique(),
  refreshToken: text("refresh_token").unique(),
  expiresAt: timestamp("expires_at").notNull(),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  createdAt: timestamp("created_at").defaultNow(),
}, (t) => [
  index("sessions_user_id_idx").on(t.userId),
  index("sessions_token_idx").on(t.token),
  foreignKey({ columns: [t.userId], foreignColumns: [users.id], name: "sessions_user_fk" }).onDelete("cascade"),
]);

export const workspaceMembers = pgTable("workspace_members", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  workspaceId: varchar("workspace_id").notNull(),
  userId: varchar("user_id").notNull(),
  role: text("role").notNull().default("analyst"), // owner, admin, analyst, viewer
  joinedAt: timestamp("joined_at").defaultNow(),
}, (t) => [
  index("workspace_members_workspace_id_idx").on(t.workspaceId),
  index("workspace_members_user_id_idx").on(t.userId),
  unique("workspace_members_unique").on(t.workspaceId, t.userId),
  foreignKey({ columns: [t.workspaceId], foreignColumns: [workspaces.id], name: "workspace_members_workspace_fk" }).onDelete("cascade"),
  foreignKey({ columns: [t.userId], foreignColumns: [users.id], name: "workspace_members_user_fk" }).onDelete("cascade"),
]);

export const auditLogs = pgTable("audit_logs", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id"),
  action: text("action").notNull(), // login, scan_triggered, finding_updated, workspace_created, etc.
  resourceType: text("resource_type"), // workspace, scan, finding, report, etc.
  resourceId: varchar("resource_id"),
  metadata: jsonb("metadata").$type<Record<string, unknown>>(),
  ipAddress: text("ip_address"),
  timestamp: timestamp("timestamp").notNull().defaultNow(),
}, (t) => [
  index("audit_logs_user_id_idx").on(t.userId),
  index("audit_logs_action_idx").on(t.action),
  index("audit_logs_timestamp_idx").on(t.timestamp),
  foreignKey({ columns: [t.userId], foreignColumns: [users.id], name: "audit_logs_user_fk" }).onDelete("set null"),
]);

// ── Phase 2: Finding Groups ──

export const findingGroups = pgTable("finding_groups", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  workspaceId: varchar("workspace_id").notNull(),
  title: text("title").notNull(),
  category: text("category").notNull(),
  severity: text("severity").notNull(),
  findingIds: text("finding_ids").array().default(sql`'{}'::text[]`),
  instanceCount: integer("instance_count").default(0),
  status: text("status").notNull().default("open"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (t) => [
  index("finding_groups_workspace_id_idx").on(t.workspaceId),
  foreignKey({ columns: [t.workspaceId], foreignColumns: [workspaces.id], name: "finding_groups_workspace_fk" }).onDelete("cascade"),
]);

// ── Phase 5: Webhooks, API Keys, Retention ──

export const webhookEndpoints = pgTable("webhook_endpoints", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  workspaceId: varchar("workspace_id").notNull(),
  name: text("name").notNull(),
  url: text("url").notNull(),
  secret: text("secret"),
  events: text("events").array().default(sql`'{}'::text[]`), // scan_completed, critical_finding, sla_breach
  provider: text("provider").notNull().default("generic"), // generic, slack, teams, pagerduty
  enabled: boolean("enabled").notNull().default(true),
  lastTriggeredAt: timestamp("last_triggered_at"),
  failCount: integer("fail_count").default(0),
  createdAt: timestamp("created_at").defaultNow(),
}, (t) => [
  index("webhook_endpoints_workspace_id_idx").on(t.workspaceId),
  foreignKey({ columns: [t.workspaceId], foreignColumns: [workspaces.id], name: "webhook_endpoints_workspace_fk" }).onDelete("cascade"),
]);

export const apiKeys = pgTable("api_keys", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull(),
  name: text("name").notNull(),
  keyHash: text("key_hash").notNull(),
  keyPrefix: text("key_prefix").notNull(), // first 8 chars for identification
  scope: text("scope").notNull().default("read"), // read, scan, full
  expiresAt: timestamp("expires_at"),
  lastUsedAt: timestamp("last_used_at"),
  createdAt: timestamp("created_at").defaultNow(),
  revokedAt: timestamp("revoked_at"),
}, (t) => [
  index("api_keys_user_id_idx").on(t.userId),
  index("api_keys_key_hash_idx").on(t.keyHash),
  foreignKey({ columns: [t.userId], foreignColumns: [users.id], name: "api_keys_user_fk" }).onDelete("cascade"),
]);

export const retentionPolicies = pgTable("retention_policies", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  workspaceId: varchar("workspace_id").notNull().unique(),
  scanRetentionDays: integer("scan_retention_days").default(365),
  findingRetentionDays: integer("finding_retention_days").default(730),
  snapshotRetentionDays: integer("snapshot_retention_days").default(365),
  archiveEnabled: boolean("archive_enabled").notNull().default(false),
  lastCleanupAt: timestamp("last_cleanup_at"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
}, (t) => [
  foreignKey({ columns: [t.workspaceId], foreignColumns: [workspaces.id], name: "retention_policies_workspace_fk" }).onDelete("cascade"),
]);

export const insertUserSchema = createInsertSchema(users).omit({ id: true, createdAt: true, updatedAt: true, lastLoginAt: true });
export const insertSessionSchema = createInsertSchema(sessions).omit({ id: true, createdAt: true });
export const insertWorkspaceMemberSchema = createInsertSchema(workspaceMembers).omit({ id: true, joinedAt: true });
export const insertAuditLogSchema = createInsertSchema(auditLogs).omit({ id: true, timestamp: true });
export const insertFindingGroupSchema = createInsertSchema(findingGroups).omit({ id: true, createdAt: true, updatedAt: true });
export const insertWebhookEndpointSchema = createInsertSchema(webhookEndpoints).omit({ id: true, createdAt: true, lastTriggeredAt: true, failCount: true }).extend({
  url: z.string().url().refine((u) => {
    try { return ["http:", "https:"].includes(new URL(u).protocol); } catch { return false; }
  }, "Webhook URL must use http or https"),
});
export const insertApiKeySchema = createInsertSchema(apiKeys).omit({ id: true, createdAt: true, lastUsedAt: true, revokedAt: true });
export const insertRetentionPolicySchema = createInsertSchema(retentionPolicies).omit({ id: true, createdAt: true, updatedAt: true, lastCleanupAt: true });

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
export type Alert = typeof alerts.$inferSelect;
export type InsertAlert = z.infer<typeof insertAlertSchema>;
export type ScheduledScan = typeof scheduledScans.$inferSelect;
export type InsertScheduledScan = z.infer<typeof insertScheduledScanSchema>;
export type ScanProfile = typeof scanProfiles.$inferSelect;
export type InsertScanProfile = z.infer<typeof insertScanProfileSchema>;
export type User = typeof users.$inferSelect;
export type InsertUser = z.infer<typeof insertUserSchema>;
export type Session = typeof sessions.$inferSelect;
export type InsertSession = z.infer<typeof insertSessionSchema>;
export type WorkspaceMember = typeof workspaceMembers.$inferSelect;
export type InsertWorkspaceMember = z.infer<typeof insertWorkspaceMemberSchema>;
export type AuditLog = typeof auditLogs.$inferSelect;
export type InsertAuditLog = z.infer<typeof insertAuditLogSchema>;
export type FindingGroup = typeof findingGroups.$inferSelect;
export type InsertFindingGroup = z.infer<typeof insertFindingGroupSchema>;
export type WebhookEndpoint = typeof webhookEndpoints.$inferSelect;
export type InsertWebhookEndpoint = z.infer<typeof insertWebhookEndpointSchema>;
export type ApiKey = typeof apiKeys.$inferSelect;
export type InsertApiKey = z.infer<typeof insertApiKeySchema>;
export type RetentionPolicy = typeof retentionPolicies.$inferSelect;
export type InsertRetentionPolicy = z.infer<typeof insertRetentionPolicySchema>;
