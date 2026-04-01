import { z } from "zod";
import { insertAssetSchema, DOMAIN_REGEX } from "@shared/schema";

export const validSeverities = ["critical", "high", "medium", "low", "info"] as const;
export const validStatuses = ["open", "in_review", "resolved", "false_positive", "accepted_risk"] as const;

export const updateFindingSchema = z.object({
  status: z.enum(validStatuses).optional(),
  assignee: z.string().nullable().optional(),
});

export const createAssetSchema = insertAssetSchema.extend({
  value: z.string().min(1, "Value is required"),
  type: z.enum(["domain", "subdomain", "ip", "service", "certificate"]),
  status: z.enum(["active", "inactive", "unknown"]).default("active"),
});

export const createScanSchema = z.object({
  target: z.string().min(1, "Target is required").refine(
    (val) => DOMAIN_REGEX.test(val.trim()),
    { message: "Target must be a valid domain name (e.g. example.com)" }
  ),
  type: z.enum(["easm", "osint", "full", "dast"]),
  status: z.enum(["pending", "running", "completed", "failed"]).default("pending"),
  workspaceId: z.string().optional(),
  autoGenerateReport: z.boolean().optional(),
  mode: z.enum(["standard", "gold"]).optional(),
  profileId: z.string().optional(),
});

export const createReportSchema = z.object({
  title: z.string().min(1, "Title is required"),
  type: z.enum(["executive_summary", "full_report", "evidence_pack"]),
  workspaceId: z.string(),
  status: z.enum(["draft", "generating", "completed"]).default("draft"),
  findingIds: z.array(z.string()).optional(),
});

export const createWorkspaceSchema = z.object({
  name: z.string().min(1, "Domain name is required"),
  description: z.string().optional(),
});

export const updateWorkspaceSchema = z.object({
  name: z.string().min(1).optional(),
  description: z.string().nullable().optional(),
  status: z.enum(["active", "inactive"]).optional(),
});

export const startContinuousMonitoringSchema = z.object({
  target: z.string().min(1, "Target is required").refine(
    (val) => DOMAIN_REGEX.test(val.trim()),
    { message: "Target must be a valid domain name (e.g. example.com)" }
  ),
  workspaceId: z.string().optional(),
});

export const stopContinuousMonitoringSchema = z.object({
  workspaceId: z.string().min(1, "Workspace ID is required"),
});

export const createScheduledScanSchema = z.object({
  target: z.string().min(1, "Target is required").refine(
    (val) => DOMAIN_REGEX.test(val.trim()),
    { message: "Target must be a valid domain name (e.g. example.com)" }
  ),
  scanType: z.enum(["easm", "osint", "full", "dast"]).default("full"),
  cronExpression: z.string().min(1, "Cron expression is required").refine(
    (val) => val.trim().split(/\s+/).length === 5,
    { message: "Cron expression must have exactly 5 fields (min hour dom mon dow)" }
  ),
  mode: z.enum(["standard", "gold"]).default("standard"),
  enabled: z.boolean().default(true),
});

export const updateScheduledScanSchema = z.object({
  cronExpression: z.string().min(1).refine(
    (val) => val.trim().split(/\s+/).length === 5,
    { message: "Cron expression must have exactly 5 fields" }
  ).optional(),
  scanType: z.enum(["easm", "osint", "full", "dast"]).optional(),
  mode: z.enum(["standard", "gold"]).optional(),
  enabled: z.boolean().optional(),
});
