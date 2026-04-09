import crypto from "crypto";
import { storage } from "./storage";
import { generateAllComplianceReports } from "./compliance-mapper";
import type { Finding, InsertPolicyDocument, InsertQuestionnaireRun, InsertRiskItem, RiskItem } from "@shared/schema";

type RiskLevel = "low" | "medium" | "high";
type RiskTreatment = "mitigate" | "accept" | "transfer" | "avoid";
type RiskStatus = "open" | "in_progress" | "accepted" | "resolved";

const LIKELIHOOD_VALUES: Record<RiskLevel, number> = { low: 1, medium: 2, high: 3 };
const IMPACT_VALUES: Record<RiskLevel, number> = { low: 1, medium: 2, high: 3 };

export interface DriftFinding {
  id: string;
  title: string;
  severity: string;
  category: string;
  affectedAsset: string | null;
  changeType: "new" | "resolved" | "unchanged";
}

export interface ComplianceDriftReport {
  workspaceId: string;
  currentScanId: string | null;
  previousScanId: string | null;
  currentScore: number | null;
  previousScore: number | null;
  scoreDelta: number | null;
  trend: "improving" | "degrading" | "stable" | "initial";
  newFindings: DriftFinding[];
  resolvedFindings: DriftFinding[];
  unchangedFailingFindings: number;
  generatedAt: string;
}

export interface QuestionDefinition {
  id: string;
  text: string;
  category: string;
  checkIds: string[];
  policyType?: string;
}

export interface QuestionnaireAnswer {
  questionId: string;
  question: string;
  answer: "yes" | "no" | "partial" | "manual_review_required";
  confidence: "high" | "medium" | "manual";
  evidenceRefs: string[];
  notes: string;
}

const SECURITY_BASELINE_QUESTIONS: QuestionDefinition[] = [
  {
    id: "SEC-AC-01",
    text: "Is MFA enforced for privileged and console access?",
    category: "Access Control",
    checkIds: ["iam-root-mfa", "iam-user-mfa"],
    policyType: "access_control",
  },
  {
    id: "SEC-AC-02",
    text: "Are passwords and account access controls managed securely?",
    category: "Access Control",
    checkIds: ["iam-password-policy", "iam-no-direct-policies", "iam-overprivileged-user"],
    policyType: "access_control",
  },
  {
    id: "SEC-NW-01",
    text: "Are internet-exposed services and ingress rules restricted?",
    category: "Network Security",
    checkIds: ["sg-no-unrestricted-ingress", "vpc-flow-logs-enabled"],
  },
  {
    id: "SEC-DP-01",
    text: "Is sensitive data protected at rest and in transit?",
    category: "Data Protection",
    checkIds: ["s3-encryption-at-rest", "s3-public-access-block"],
    policyType: "data_classification",
  },
  {
    id: "SEC-MON-01",
    text: "Are audit logging and threat monitoring controls active?",
    category: "Monitoring",
    checkIds: ["cloudtrail-enabled", "guardduty-enabled", "config-enabled"],
    policyType: "incident_response",
  },
];

function isOpenFinding(status: string): boolean {
  return status === "open" || status === "in_review" || status === "in_progress";
}

function findingFingerprint(finding: Finding): string {
  const checkId = String((finding as Finding & { checkId?: string | null }).checkId ?? "").trim().toLowerCase();
  const resourceId = String((finding as Finding & { resourceId?: string | null }).resourceId ?? finding.affectedAsset ?? "").trim().toLowerCase();
  const raw = [finding.workspaceId, checkId || finding.category, resourceId, finding.title.trim().toLowerCase()].join("|");
  return crypto.createHash("sha256").update(raw).digest("hex");
}

function computeRisk(likelihood: RiskLevel, impact: RiskLevel): { riskScore: number; riskLevel: RiskLevel } {
  const riskScore = LIKELIHOOD_VALUES[likelihood] * IMPACT_VALUES[impact];
  if (riskScore >= 6) return { riskScore, riskLevel: "high" };
  if (riskScore >= 3) return { riskScore, riskLevel: "medium" };
  return { riskScore, riskLevel: "low" };
}

function riskFromFinding(finding: Finding): InsertRiskItem {
  const severity = String(finding.severity).toLowerCase();
  const likelihood: RiskLevel = severity === "critical" ? "high" : severity === "high" ? "high" : severity === "medium" ? "medium" : "low";
  const impact: RiskLevel = severity === "critical" || severity === "high" ? "high" : severity === "medium" ? "medium" : "low";
  const { riskScore, riskLevel } = computeRisk(likelihood, impact);

  return {
    workspaceId: finding.workspaceId,
    relatedFindingId: finding.id,
    fingerprint: findingFingerprint(finding),
    title: finding.title,
    description: finding.description,
    category: "technical",
    likelihood,
    impact,
    riskScore,
    riskLevel,
    owner: null,
    treatment: "mitigate" as RiskTreatment,
    treatmentPlan: finding.remediation ?? "Review and remediate this finding based on business impact.",
    status: "open" as RiskStatus,
    reviewCadenceDays: 90,
    reviewNotes: null,
    lastReviewedAt: null,
  };
}

function compactScanScore(findings: Finding[]): number | null {
  const reports = generateAllComplianceReports(findings);
  const scores = Object.values(reports).map((r) => r.score).filter((s): s is number => s !== null);
  if (scores.length === 0) return null;
  return Math.round(scores.reduce((sum, score) => sum + score, 0) / scores.length);
}

function findPolicyTypeExists(policyTypes: Set<string>, policyType?: string): boolean {
  if (!policyType) return false;
  return policyTypes.has(policyType);
}

function createAnswer(
  question: QuestionDefinition,
  findings: Finding[],
  existingPolicyTypes: Set<string>,
): QuestionnaireAnswer {
  const mappedFindings = findings.filter((f) => {
    const checkId = String((f as Finding & { checkId?: string | null }).checkId ?? "").toLowerCase().trim();
    return question.checkIds.includes(checkId);
  });

  const policyExists = findPolicyTypeExists(existingPolicyTypes, question.policyType);
  const passed = mappedFindings.filter((f) => !isOpenFinding(f.status));
  const failed = mappedFindings.filter((f) => isOpenFinding(f.status));

  if (mappedFindings.length === 0 && !question.policyType) {
    return {
      questionId: question.id,
      question: question.text,
      answer: "manual_review_required",
      confidence: "manual",
      evidenceRefs: [],
      notes: "No mapped check evidence was found for this question.",
    };
  }

  if (mappedFindings.length === 0 && question.policyType) {
    return {
      questionId: question.id,
      question: question.text,
      answer: policyExists ? "yes" : "manual_review_required",
      confidence: policyExists ? "medium" : "manual",
      evidenceRefs: policyExists ? [`policy:${question.policyType}`] : [],
      notes: policyExists
        ? `Policy '${question.policyType}' exists and supports this answer.`
        : `Policy '${question.policyType}' is missing and no mapped findings were available.`,
    };
  }

  let answer: QuestionnaireAnswer["answer"] = "manual_review_required";
  let confidence: QuestionnaireAnswer["confidence"] = "manual";
  let notes = "Mapped evidence is inconclusive.";

  if (failed.length === 0 && passed.length > 0) {
    answer = "yes";
    confidence = "high";
    notes = `All mapped resources (${passed.length}) are compliant.`;
  } else if (failed.length > 0 && passed.length === 0) {
    answer = "no";
    confidence = "high";
    notes = `All mapped resources (${failed.length}) are currently non-compliant.`;
  } else if (failed.length > 0 && passed.length > 0) {
    answer = "partial";
    confidence = "medium";
    notes = `Mixed evidence (${passed.length} pass, ${failed.length} fail).`;
  }

  const evidenceRefs = mappedFindings.map((f) => f.id);
  if (question.policyType && policyExists) {
    evidenceRefs.push(`policy:${question.policyType}`);
  }
  if (question.policyType && !policyExists && answer === "yes") {
    answer = "partial";
    confidence = "medium";
    notes += ` Policy '${question.policyType}' was not found.`;
  }

  return {
    questionId: question.id,
    question: question.text,
    answer,
    confidence,
    evidenceRefs,
    notes,
  };
}

function policyContent(policyType: string, workspaceName: string, effectiveDate: string): string {
  const titleByType: Record<string, string> = {
    access_control: "Access Control Policy",
    change_management: "Change Management Policy",
    incident_response: "Incident Response Plan",
    risk_assessment: "Risk Assessment Policy",
    vendor_management: "Vendor Management Policy",
    data_classification: "Data Classification Policy",
    acceptable_use: "Acceptable Use Policy",
    business_continuity: "Business Continuity Policy",
  };
  const title = titleByType[policyType] ?? "Security Policy";
  return `# ${title}

**Version:** 1.0
**Effective Date:** ${effectiveDate}
**Owner:** ${workspaceName} Security Team

## Purpose
This policy defines minimum governance and security requirements for ${workspaceName}.

## Scope
This policy applies to all employees, contractors, systems, and data assets under ${workspaceName}'s control.

## Policy Statements
- Security responsibilities are documented and assigned.
- Access and changes to production systems require authorization and auditability.
- Security incidents are detected, triaged, and remediated with documented evidence.
- Risks are tracked in the risk register and reviewed on a recurring cadence.
- Controls and policies are reviewed at least annually.

## Governance and Review
- Policy exceptions must be documented, approved, and time-bounded.
- This policy is reviewed annually or after material operational/security changes.
`;
}

export async function autoSeedRiskRegister(workspaceId: string): Promise<{ created: number; existing: number }> {
  const { data: findings } = await storage.getFindings(workspaceId, { limit: 5000, offset: 0 });
  const openFindings = findings.filter((f) => isOpenFinding(f.status));
  let created = 0;
  let existing = 0;

  for (const finding of openFindings) {
    const item = riskFromFinding(finding);
    const current = await storage.getRiskItemByFingerprint(workspaceId, item.fingerprint);
    if (current) {
      existing++;
      continue;
    }
    await storage.createRiskItem(item);
    created++;
  }

  return { created, existing };
}

export async function getComplianceDrift(workspaceId: string): Promise<ComplianceDriftReport> {
  const scans = await storage.getScans(workspaceId, { limit: 100, offset: 0 });
  const completed = scans.data
    .filter((s) => s.status === "completed")
    .sort((a, b) => (new Date(b.completedAt ?? b.startedAt ?? 0).getTime() - new Date(a.completedAt ?? a.startedAt ?? 0).getTime()));

  const current = completed[0];
  const previous = completed[1];

  if (!current) {
    return {
      workspaceId,
      currentScanId: null,
      previousScanId: null,
      currentScore: null,
      previousScore: null,
      scoreDelta: null,
      trend: "initial",
      newFindings: [],
      resolvedFindings: [],
      unchangedFailingFindings: 0,
      generatedAt: new Date().toISOString(),
    };
  }

  const { data: allFindings } = await storage.getFindings(workspaceId, { limit: 5000, offset: 0 });
  const currentFindings = allFindings.filter((f) => f.scanId === current.id);
  const previousFindings = previous ? allFindings.filter((f) => f.scanId === previous.id) : [];

  const currentOpen = new Map<string, Finding>();
  const previousOpen = new Map<string, Finding>();
  for (const finding of currentFindings) {
    if (isOpenFinding(finding.status)) currentOpen.set(findingFingerprint(finding), finding);
  }
  for (const finding of previousFindings) {
    if (isOpenFinding(finding.status)) previousOpen.set(findingFingerprint(finding), finding);
  }

  const newFindings: DriftFinding[] = [];
  const resolvedFindings: DriftFinding[] = [];
  let unchangedFailingFindings = 0;

  for (const [fp, finding] of Array.from(currentOpen.entries())) {
    if (!previousOpen.has(fp)) {
      newFindings.push({
        id: finding.id,
        title: finding.title,
        severity: finding.severity,
        category: finding.category,
        affectedAsset: finding.affectedAsset,
        changeType: "new",
      });
    } else {
      unchangedFailingFindings++;
    }
  }

  for (const [fp, finding] of Array.from(previousOpen.entries())) {
    if (!currentOpen.has(fp)) {
      resolvedFindings.push({
        id: finding.id,
        title: finding.title,
        severity: finding.severity,
        category: finding.category,
        affectedAsset: finding.affectedAsset,
        changeType: "resolved",
      });
    }
  }

  const currentScore = compactScanScore(currentFindings);
  const previousScore = compactScanScore(previousFindings);
  const scoreDelta = currentScore === null || previousScore === null ? null : currentScore - previousScore;

  let trend: ComplianceDriftReport["trend"] = "initial";
  if (previous) {
    if (scoreDelta === null) trend = "stable";
    else if (scoreDelta > 2) trend = "improving";
    else if (scoreDelta < -2) trend = "degrading";
    else trend = "stable";
  }

  return {
    workspaceId,
    currentScanId: current.id,
    previousScanId: previous?.id ?? null,
    currentScore,
    previousScore,
    scoreDelta,
    trend,
    newFindings,
    resolvedFindings,
    unchangedFailingFindings,
    generatedAt: new Date().toISOString(),
  };
}

export async function runSecurityBaselineQuestionnaire(
  workspaceId: string,
  createdBy: string | undefined,
): Promise<InsertQuestionnaireRun> {
  const [findingsResult, existingPolicies] = await Promise.all([
    storage.getFindings(workspaceId, { limit: 5000, offset: 0 }),
    storage.getPolicyDocuments(workspaceId),
  ]);
  const findings = findingsResult.data;
  const policyTypes = new Set(existingPolicies.map((p) => p.policyType));

  const answers = SECURITY_BASELINE_QUESTIONS.map((q) => createAnswer(q, findings, policyTypes));
  const autoAnswered = answers.filter((a) => a.confidence !== "manual").length;
  const totalQuestions = SECURITY_BASELINE_QUESTIONS.length;
  const manualRequired = totalQuestions - autoAnswered;
  const coveragePct = totalQuestions > 0 ? Math.round((autoAnswered / totalQuestions) * 100) : 0;

  return {
    workspaceId,
    questionnaireType: "security_baseline",
    totalQuestions,
    autoAnswered,
    manualRequired,
    coveragePct,
    answers: answers as unknown as Array<Record<string, unknown>>,
    createdBy: createdBy ?? null,
  };
}

export async function upsertPolicyDocument(
  workspaceId: string,
  policyType: string,
  createdBy: string | undefined,
): Promise<void> {
  const workspace = await storage.getWorkspace(workspaceId);
  const effectiveDate = new Date().toISOString().slice(0, 10);
  const content = policyContent(policyType, workspace?.name ?? "Organization", effectiveDate);
  const title = content.split("\n")[0]?.replace(/^#\s*/, "") || "Security Policy";

  const existing = await storage.getPolicyDocumentByType(workspaceId, policyType);
  const payload: InsertPolicyDocument = {
    workspaceId,
    policyType,
    title,
    version: "1.0",
    effectiveDate: new Date(),
    content,
    createdBy: createdBy ?? null,
  };

  if (existing) {
    await storage.updatePolicyDocument(existing.id, {
      title: payload.title,
      content: payload.content,
      effectiveDate: payload.effectiveDate,
      createdBy: payload.createdBy,
    });
    return;
  }
  await storage.createPolicyDocument(payload);
}

export async function applyRiskItemUpdate(id: string, patch: Partial<RiskItem>): Promise<RiskItem | undefined> {
  const likelihood = patch.likelihood as RiskLevel | undefined;
  const impact = patch.impact as RiskLevel | undefined;
  if (likelihood && impact) {
    const { riskScore, riskLevel } = computeRisk(likelihood, impact);
    return storage.updateRiskItem(id, { ...patch, riskScore, riskLevel });
  }
  if (likelihood || impact) {
    const current = await storage.getRiskItem(id);
    if (!current) return undefined;
    const nextLikelihood = (likelihood ?? current.likelihood) as RiskLevel;
    const nextImpact = (impact ?? current.impact) as RiskLevel;
    const { riskScore, riskLevel } = computeRisk(nextLikelihood, nextImpact);
    return storage.updateRiskItem(id, { ...patch, riskScore, riskLevel });
  }
  return storage.updateRiskItem(id, patch);
}
