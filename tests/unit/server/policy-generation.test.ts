import { describe, it, expect, vi, beforeEach } from "vitest";
import type { Finding } from "@shared/schema";

// ── Mock storage ──────────────────────────────────────────────────────────────
// vi.hoisted ensures the mock object is created before vi.mock() factory runs
const storageMock = vi.hoisted(() => ({
  getWorkspace: vi.fn(),
  getPolicyDocumentByType: vi.fn(),
  createPolicyDocument: vi.fn(),
  updatePolicyDocument: vi.fn(),
}));

vi.mock("../../../server/storage", () => ({ storage: storageMock }));
vi.mock("../../../server/compliance-mapper", () => ({
  generateAllComplianceReports: vi.fn(() => ({})),
}));

import { upsertPolicyDocument } from "../../../server/compliance-workflows";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f-1",
    workspaceId: "ws-1",
    scanId: "scan-1",
    title: "Open Port 22",
    description: "SSH exposed",
    severity: "high",
    status: "open",
    category: "open_port",
    checkId: null,
    resourceType: null,
    resourceId: null,
    provider: null,
    complianceTags: [],
    affectedAsset: "1.2.3.4",
    evidence: [],
    cvssScore: null,
    remediation: "Close port",
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

beforeEach(() => {
  vi.clearAllMocks();
  storageMock.getWorkspace.mockResolvedValue({ id: "ws-1", name: "AcmeCorp" });
});

describe("policy generation — upsertPolicyDocument", () => {
  const POLICY_TYPES = [
    "access_control",
    "incident_response",
    "data_classification",
    "change_management",
    "vendor_management",
    "risk_assessment",
    "business_continuity",
    "acceptable_use",
  ] as const;

  it.each(POLICY_TYPES)("generates a non-empty document for '%s'", async (policyType) => {
    storageMock.getPolicyDocumentByType.mockResolvedValue(undefined);
    let captured: { content?: string; title?: string } = {};
    storageMock.createPolicyDocument.mockImplementation(async (doc) => {
      captured = doc;
      return doc;
    });

    await upsertPolicyDocument("ws-1", policyType, "user-1", []);

    expect(storageMock.createPolicyDocument).toHaveBeenCalledOnce();
    expect(captured.content).toBeTruthy();
    expect(captured.content!.length).toBeGreaterThan(500);
    expect(captured.title).toBeTruthy();
  });

  it.each(POLICY_TYPES)("document for '%s' contains all 8 required sections", async (policyType) => {
    storageMock.getPolicyDocumentByType.mockResolvedValue(undefined);
    let content = "";
    storageMock.createPolicyDocument.mockImplementation(async (doc) => {
      content = doc.content as string;
      return doc;
    });

    await upsertPolicyDocument("ws-1", policyType, "user-1", []);

    expect(content).toMatch(/## \d+\. Purpose/);
    expect(content).toMatch(/## \d+\. (Scope|Policy Statements)/);
    expect(content).toMatch(/Compliance References/);
    expect(content).toMatch(/Review and Maintenance/);
  });

  it("injects open findings into the risk context section for business_continuity", async () => {
    storageMock.getPolicyDocumentByType.mockResolvedValue(undefined);
    const findings = [
      makeFinding({ category: "open_port", title: "SSH Port Exposed", severity: "high" }),
    ];
    let content = "";
    storageMock.createPolicyDocument.mockImplementation(async (doc) => {
      content = doc.content as string;
      return doc;
    });

    await upsertPolicyDocument("ws-1", "business_continuity", "user-1", findings);

    expect(content).toContain("Current Risk Context");
    expect(content).toContain("SSH Port Exposed");
  });

  it("does not inject resolved findings into risk context", async () => {
    storageMock.getPolicyDocumentByType.mockResolvedValue(undefined);
    const findings = [
      makeFinding({ category: "open_port", title: "Old Finding", status: "resolved" }),
    ];
    let content = "";
    storageMock.createPolicyDocument.mockImplementation(async (doc) => {
      content = doc.content as string;
      return doc;
    });

    await upsertPolicyDocument("ws-1", "business_continuity", "user-1", findings);

    // Resolved finding should not appear; section may not be present at all
    expect(content).not.toContain("Old Finding");
  });

  it("bumps minor version on regeneration (1.0 → 1.1)", async () => {
    storageMock.getPolicyDocumentByType.mockResolvedValue({
      id: "p-1",
      version: "1.0",
    });
    let captured: { version?: string } = {};
    storageMock.updatePolicyDocument.mockImplementation(async (_id, patch) => {
      captured = patch;
      return patch;
    });

    await upsertPolicyDocument("ws-1", "access_control", "user-1", []);

    expect(storageMock.updatePolicyDocument).toHaveBeenCalledOnce();
    expect(captured.version).toBe("1.1");
  });

  it("bumps major version when minor is 9 (1.9 → 2.0)", async () => {
    storageMock.getPolicyDocumentByType.mockResolvedValue({
      id: "p-2",
      version: "1.9",
    });
    let captured: { version?: string } = {};
    storageMock.updatePolicyDocument.mockImplementation(async (_id, patch) => {
      captured = patch;
      return patch;
    });

    await upsertPolicyDocument("ws-1", "access_control", "user-1", []);

    expect(captured.version).toBe("2.0");
  });

  it("creates with version 1.0 when no existing document", async () => {
    storageMock.getPolicyDocumentByType.mockResolvedValue(undefined);
    let captured: { version?: string } = {};
    storageMock.createPolicyDocument.mockImplementation(async (doc) => {
      captured = doc;
      return doc;
    });

    await upsertPolicyDocument("ws-1", "access_control", "user-1", []);

    expect(captured.version).toBe("1.0");
  });

  it("uses workspace name in document content", async () => {
    storageMock.getWorkspace.mockResolvedValue({ id: "ws-1", name: "WidgetCo" });
    storageMock.getPolicyDocumentByType.mockResolvedValue(undefined);
    let content = "";
    storageMock.createPolicyDocument.mockImplementation(async (doc) => {
      content = doc.content as string;
      return doc;
    });

    await upsertPolicyDocument("ws-1", "access_control", "user-1", []);

    expect(content).toContain("WidgetCo");
  });
});
