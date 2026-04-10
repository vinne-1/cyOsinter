/**
 * Unit tests for server/routes/schemas.ts — Zod validation schemas.
 *
 * Tests: createScanSchema, createScheduledScanSchema, updateFindingSchema,
 *        createWorkspaceSchema, updateWorkspaceSchema.
 */

import { describe, it, expect, vi } from "vitest";

// Mock database
vi.mock("../../../server/db", () => ({ db: {} }));

import {
  createScanSchema,
  createScheduledScanSchema,
  updateFindingSchema,
  createWorkspaceSchema,
  updateWorkspaceSchema,
  createReportSchema,
  validSeverities,
  validStatuses,
} from "../../../server/routes/schemas";

// ---------------------------------------------------------------------------
// createScanSchema
// ---------------------------------------------------------------------------
describe("createScanSchema", () => {
  it("accepts a valid scan", () => {
    const result = createScanSchema.safeParse({
      target: "example.com",
      type: "easm",
    });
    expect(result.success).toBe(true);
  });

  it("accepts all valid scan types", () => {
    for (const type of ["easm", "osint", "full", "dast"]) {
      const result = createScanSchema.safeParse({ target: "example.com", type });
      expect(result.success).toBe(true);
    }
  });

  it("rejects invalid scan type", () => {
    const result = createScanSchema.safeParse({
      target: "example.com",
      type: "invalid",
    });
    expect(result.success).toBe(false);
  });

  it("rejects empty target", () => {
    const result = createScanSchema.safeParse({ target: "", type: "easm" });
    expect(result.success).toBe(false);
  });

  it("rejects non-domain target", () => {
    const result = createScanSchema.safeParse({
      target: "not a domain!!",
      type: "easm",
    });
    expect(result.success).toBe(false);
  });

  it("accepts target with subdomains", () => {
    const result = createScanSchema.safeParse({
      target: "sub.example.com",
      type: "full",
    });
    expect(result.success).toBe(true);
  });

  it("defaults status to pending", () => {
    const result = createScanSchema.parse({
      target: "example.com",
      type: "easm",
    });
    expect(result.status).toBe("pending");
  });

  it("accepts optional mode field", () => {
    const result = createScanSchema.safeParse({
      target: "example.com",
      type: "full",
      mode: "gold",
    });
    expect(result.success).toBe(true);
    if (result.success) expect(result.data.mode).toBe("gold");
  });

  it("rejects invalid mode", () => {
    const result = createScanSchema.safeParse({
      target: "example.com",
      type: "full",
      mode: "platinum",
    });
    expect(result.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// createScheduledScanSchema
// ---------------------------------------------------------------------------
describe("createScheduledScanSchema", () => {
  it("accepts valid scheduled scan", () => {
    const result = createScheduledScanSchema.safeParse({
      target: "example.com",
      cronExpression: "0 2 * * *",
    });
    expect(result.success).toBe(true);
  });

  it("rejects cron with wrong number of fields", () => {
    const result = createScheduledScanSchema.safeParse({
      target: "example.com",
      cronExpression: "0 2 * *", // 4 fields
    });
    expect(result.success).toBe(false);
  });

  it("rejects empty cron expression", () => {
    const result = createScheduledScanSchema.safeParse({
      target: "example.com",
      cronExpression: "",
    });
    expect(result.success).toBe(false);
  });

  it("defaults scanType to full", () => {
    const result = createScheduledScanSchema.parse({
      target: "example.com",
      cronExpression: "0 2 * * *",
    });
    expect(result.scanType).toBe("full");
  });

  it("defaults mode to standard", () => {
    const result = createScheduledScanSchema.parse({
      target: "example.com",
      cronExpression: "0 2 * * *",
    });
    expect(result.mode).toBe("standard");
  });

  it("defaults enabled to true", () => {
    const result = createScheduledScanSchema.parse({
      target: "example.com",
      cronExpression: "0 2 * * *",
    });
    expect(result.enabled).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// updateFindingSchema
// ---------------------------------------------------------------------------
describe("updateFindingSchema", () => {
  it("accepts valid status update", () => {
    const result = updateFindingSchema.safeParse({ status: "resolved" });
    expect(result.success).toBe(true);
  });

  it("accepts all valid statuses", () => {
    for (const status of validStatuses) {
      expect(updateFindingSchema.safeParse({ status }).success).toBe(true);
    }
  });

  it("rejects invalid status", () => {
    const result = updateFindingSchema.safeParse({ status: "deleted" });
    expect(result.success).toBe(false);
  });

  it("accepts assignee as string or null", () => {
    expect(updateFindingSchema.safeParse({ assignee: "user-123" }).success).toBe(true);
    expect(updateFindingSchema.safeParse({ assignee: null }).success).toBe(true);
  });

  it("accepts empty object (all fields optional)", () => {
    expect(updateFindingSchema.safeParse({}).success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// createWorkspaceSchema
// ---------------------------------------------------------------------------
describe("createWorkspaceSchema", () => {
  it("accepts valid workspace", () => {
    const result = createWorkspaceSchema.safeParse({ name: "example.com" });
    expect(result.success).toBe(true);
  });

  it("rejects empty name", () => {
    const result = createWorkspaceSchema.safeParse({ name: "" });
    expect(result.success).toBe(false);
  });

  it("rejects non-domain name", () => {
    const result = createWorkspaceSchema.safeParse({ name: "My Workspace" });
    expect(result.success).toBe(false);
  });

  it("accepts optional description", () => {
    const result = createWorkspaceSchema.safeParse({
      name: "test.example.com",
      description: "A workspace for testing",
    });
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// updateWorkspaceSchema
// ---------------------------------------------------------------------------
describe("updateWorkspaceSchema", () => {
  it("accepts partial updates", () => {
    expect(updateWorkspaceSchema.safeParse({ name: "updated.example.com" }).success).toBe(true);
    expect(updateWorkspaceSchema.safeParse({ status: "inactive" }).success).toBe(true);
    expect(updateWorkspaceSchema.safeParse({ description: null }).success).toBe(true);
  });

  it("rejects non-domain name update", () => {
    expect(updateWorkspaceSchema.safeParse({ name: "New name" }).success).toBe(false);
  });

  it("rejects invalid status", () => {
    expect(updateWorkspaceSchema.safeParse({ status: "deleted" }).success).toBe(false);
  });

  it("accepts empty object", () => {
    expect(updateWorkspaceSchema.safeParse({}).success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// createReportSchema
// ---------------------------------------------------------------------------
describe("createReportSchema", () => {
  it("accepts valid report", () => {
    const result = createReportSchema.safeParse({
      title: "Q4 Security Report",
      type: "full_report",
      workspaceId: "ws-123",
    });
    expect(result.success).toBe(true);
  });

  it("rejects empty title", () => {
    const result = createReportSchema.safeParse({
      title: "",
      type: "full_report",
      workspaceId: "ws-123",
    });
    expect(result.success).toBe(false);
  });

  it("accepts valid report types", () => {
    for (const type of ["executive_summary", "full_report", "evidence_pack"]) {
      const result = createReportSchema.safeParse({
        title: "Report",
        type,
        workspaceId: "ws-1",
      });
      expect(result.success).toBe(true);
    }
  });

  it("defaults status to draft", () => {
    const result = createReportSchema.parse({
      title: "Report",
      type: "full_report",
      workspaceId: "ws-1",
    });
    expect(result.status).toBe("draft");
  });
});

// ---------------------------------------------------------------------------
// startContinuousMonitoringSchema
// ---------------------------------------------------------------------------
import { startContinuousMonitoringSchema, stopContinuousMonitoringSchema, updateScheduledScanSchema } from "../../../server/routes/schemas";

describe("startContinuousMonitoringSchema", () => {
  it("accepts valid domain target", () => {
    expect(startContinuousMonitoringSchema.safeParse({ target: "example.com" }).success).toBe(true);
  });

  it("accepts optional workspaceId", () => {
    expect(startContinuousMonitoringSchema.safeParse({ target: "example.com", workspaceId: "ws-1" }).success).toBe(true);
  });

  it("rejects invalid domain", () => {
    expect(startContinuousMonitoringSchema.safeParse({ target: "not a domain" }).success).toBe(false);
  });

  it("rejects empty target", () => {
    expect(startContinuousMonitoringSchema.safeParse({ target: "" }).success).toBe(false);
  });
});

describe("stopContinuousMonitoringSchema", () => {
  it("accepts valid workspaceId", () => {
    expect(stopContinuousMonitoringSchema.safeParse({ workspaceId: "ws-123" }).success).toBe(true);
  });

  it("rejects empty workspaceId", () => {
    expect(stopContinuousMonitoringSchema.safeParse({ workspaceId: "" }).success).toBe(false);
  });

  it("rejects missing workspaceId", () => {
    expect(stopContinuousMonitoringSchema.safeParse({}).success).toBe(false);
  });
});

describe("updateScheduledScanSchema", () => {
  it("accepts empty object (all optional)", () => {
    expect(updateScheduledScanSchema.safeParse({}).success).toBe(true);
  });

  it("accepts valid cron update", () => {
    expect(updateScheduledScanSchema.safeParse({ cronExpression: "0 3 * * *" }).success).toBe(true);
  });

  it("rejects invalid cron (4 fields)", () => {
    expect(updateScheduledScanSchema.safeParse({ cronExpression: "0 3 * *" }).success).toBe(false);
  });

  it("accepts valid scanType update", () => {
    expect(updateScheduledScanSchema.safeParse({ scanType: "osint" }).success).toBe(true);
  });

  it("accepts enabled toggle", () => {
    expect(updateScheduledScanSchema.safeParse({ enabled: false }).success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
describe("constants", () => {
  it("validSeverities contains expected values", () => {
    expect(validSeverities).toEqual(["critical", "high", "medium", "low", "info"]);
  });

  it("validStatuses contains expected values", () => {
    expect(validStatuses).toContain("open");
    expect(validStatuses).toContain("resolved");
    expect(validStatuses).toContain("false_positive");
    expect(validStatuses).toHaveLength(5);
  });
});
