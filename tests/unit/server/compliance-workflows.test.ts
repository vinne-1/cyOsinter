import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "@shared/schema";

const { storageMock } = vi.hoisted(() => ({
  storageMock: {
    getFindings: vi.fn(),
    getRiskItemByFingerprint: vi.fn(),
    createRiskItem: vi.fn(),
    getPolicyDocuments: vi.fn(),
    getWorkspace: vi.fn(),
    getScans: vi.fn(),
  },
}));

vi.mock("../../../server/storage", () => ({
  storage: storageMock,
}));

import { autoSeedRiskRegister, runSecurityBaselineQuestionnaire } from "../../../server/compliance-workflows";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: `finding-${Math.random().toString(36).slice(2)}`,
    workspaceId: "ws-1",
    scanId: "scan-1",
    title: "Test finding",
    description: "desc",
    severity: "high",
    status: "open",
    category: "security_headers",
    checkId: "security_headers",
    resourceType: "web",
    resourceId: "example.com",
    provider: null,
    complianceTags: [],
    affectedAsset: "example.com",
    evidence: [],
    cvssScore: null,
    remediation: "fix",
    assignee: null,
    assigneeId: null,
    priority: null,
    dueDate: null,
    slaBreached: false,
    workflowState: "open",
    groupId: null,
    verificationScanId: null,
    discoveredAt: new Date(),
    resolvedAt: null,
    tags: [],
    aiEnrichment: null,
    ...overrides,
  };
}

describe("compliance-workflows", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("auto-seeds risks only from unresolved findings and skips duplicates", async () => {
    storageMock.getFindings.mockResolvedValue({
      data: [
        makeFinding({ id: "f-open", status: "open" }),
        makeFinding({ id: "f-resolved", status: "resolved" }),
      ],
    });
    storageMock.getRiskItemByFingerprint.mockResolvedValueOnce(undefined).mockResolvedValueOnce(undefined);
    storageMock.createRiskItem.mockResolvedValue({});

    const result = await autoSeedRiskRegister("ws-1");

    expect(storageMock.createRiskItem).toHaveBeenCalledTimes(1);
    expect(result.created).toBe(1);
    expect(result.existing).toBe(0);
  });

  it("generates questionnaire payload with manual items when no mapped findings are present", async () => {
    storageMock.getFindings.mockResolvedValue({ data: [makeFinding({ checkId: "unmapped-check" })] });
    storageMock.getPolicyDocuments.mockResolvedValue([]);

    const run = await runSecurityBaselineQuestionnaire("ws-1", "user-1");

    expect(run.workspaceId).toBe("ws-1");
    expect(run.totalQuestions).toBeGreaterThan(0);
    expect(run.manualRequired).toBeGreaterThan(0);
    expect(Array.isArray(run.answers)).toBe(true);
  });
});
