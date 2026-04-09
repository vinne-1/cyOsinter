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

// ── Policy-type → relevant finding categories ──────────────────────────────
const POLICY_FINDING_CATEGORIES: Record<string, string[]> = {
  access_control:      ["exposed_credentials", "leaked_credential", "api_exposure", "cors_misconfiguration"],
  incident_response:   ["threat_intelligence", "nuclei_finding", "vulnerability"],
  data_classification: ["data_leak", "secret_exposure", "ssl_issue"],
  change_management:   ["vulnerability", "infrastructure_disclosure"],
  vendor_management:   ["osint_exposure"],
  business_continuity: ["open_port", "cloud_exposure", "dns_misconfiguration"],
  acceptable_use:      ["osint_exposure", "security_headers"],
  risk_assessment:     [], // uses all findings
};

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

function relevantFindings(policyType: string, findings: Finding[]): Finding[] {
  const cats = POLICY_FINDING_CATEGORIES[policyType] ?? [];
  const isOpen = (f: Finding) => ["open", "in_review", "in_progress"].includes(f.status);
  const pool = cats.length === 0
    ? findings.filter(isOpen)
    : findings.filter(f => isOpen(f) && cats.includes(f.category));
  return pool
    .slice()
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99))
    .slice(0, 5);
}

function riskContextSection(topFindings: Finding[]): string {
  if (topFindings.length === 0) return "";
  const lines = topFindings.map(
    (f, i) =>
      `  ${i + 1}. **[${f.severity.toUpperCase()}]** ${f.title}${f.affectedAsset ? ` — ${f.affectedAsset}` : ""}`,
  );
  return `\n## Current Risk Context\n\nThe following open findings were detected during the most recent security assessment and are addressed by this policy:\n\n${lines.join("\n")}\n\nThese items are tracked in the Risk Register and must be remediated according to the SLA timelines defined in Section 3.\n`;
}

function bumpVersion(current: string): string {
  const [major, minor] = current.split(".").map(Number);
  if (isNaN(major) || isNaN(minor)) return "1.1";
  if ((minor ?? 0) >= 9) return `${(major ?? 1) + 1}.0`;
  return `${major ?? 1}.${(minor ?? 0) + 1}`;
}

function policyContent(
  policyType: string,
  workspaceName: string,
  effectiveDate: string,
  version: string,
  contextFindings: Finding[],
): string {
  const top = relevantFindings(policyType, contextFindings);
  const riskCtx = riskContextSection(top);

  const header = (title: string) =>
    `# ${title}\n\n**Organization:** ${workspaceName}  \n**Version:** ${version}  \n**Effective Date:** ${effectiveDate}  \n**Classification:** Internal — Confidential  \n**Owner:** Information Security Team  \n`;

  switch (policyType) {
    case "access_control":
      return `${header("Access Control Policy")}
## 1. Purpose

This policy establishes requirements for managing logical access to ${workspaceName} systems, applications, networks, and data. It ensures that access is granted on a least-privilege basis, authenticated appropriately, and reviewed regularly to prevent unauthorised disclosure, modification, or destruction of information assets.
${riskCtx}
## 2. Scope

This policy applies to all employees, contractors, consultants, temporary workers, and other personnel who have access to ${workspaceName} information systems. It covers all systems, applications, cloud environments, and network resources regardless of hosting location.

## 3. Policy Statements

3.1 **Least Privilege** — Access rights must be restricted to the minimum permissions required to perform authorised job functions. Privileged access must be separate from standard user accounts.

3.2 **Multi-Factor Authentication (MFA)** — MFA is mandatory for all remote access, privileged accounts, cloud console access, and access to systems classified as Confidential or above.

3.3 **Access Provisioning** — All access requests must be formally approved by the resource owner and documented in the access management system prior to provisioning.

3.4 **Password Standards** — Passwords must be at least 14 characters, unique per system, and managed through an approved password manager. Shared credentials are prohibited.

3.5 **Privileged Access Management** — All privileged (admin/root) accounts must use dedicated credentials, be recorded in a PAM system, and subject to session recording where technically feasible.

3.6 **Access Reviews** — User access rights must be reviewed quarterly for privileged accounts and annually for standard accounts. Terminated employee access must be revoked within 24 hours.

3.7 **Service Accounts** — Non-human service accounts must be documented, have minimal required permissions, rotate credentials automatically, and never be used for interactive login.

3.8 **API Keys & Tokens** — API keys must have defined scopes, expiry dates, and be stored in secrets management systems. Hardcoded credentials in source code are prohibited.

3.9 **Remote Access** — All remote access must traverse a VPN or zero-trust access gateway. Direct RDP/SSH exposure to the internet is prohibited.

3.10 **Segregation of Duties** — Critical operations (e.g., code deployment, financial transactions) must require approval from a second authorised individual.

## 4. Roles and Responsibilities

| Role | Responsibility |
|---|---|
| CISO / Security Lead | Own and maintain this policy; approve exceptions |
| IT Operations | Implement access controls; execute provisioning/de-provisioning |
| HR | Notify IT of employee changes within 4 hours |
| All Staff | Protect their credentials; report suspected compromise immediately |
| Resource Owners | Approve and review access to their systems |

## 5. Compliance References

- **NIST CSF 2.0:** PR.AA (Identity Management and Access Control)
- **ISO 27001:2022:** A.5.15, A.5.16, A.5.18, A.8.2, A.8.3
- **SOC 2 Type II:** CC6.1, CC6.2, CC6.3
- **CIS Controls v8:** Control 5 (Account Management), Control 6 (Access Control Management)

## 6. Exceptions

Exceptions to this policy must be submitted to the CISO with business justification, compensating controls, and a defined time boundary. Exceptions are reviewed quarterly and must be reapproved annually.

## 7. Policy Violations

Violations of this policy may result in disciplinary action up to and including termination, and may constitute grounds for legal action. Security incidents resulting from policy violations must be reported immediately.

## 8. Review and Maintenance

This policy is reviewed annually or following a material security incident, significant organisational change, or relevant regulatory update. The next scheduled review is ${new Date(new Date(effectiveDate).setFullYear(new Date(effectiveDate).getFullYear() + 1)).toISOString().slice(0, 10)}.
`;

    case "incident_response":
      return `${header("Incident Response Plan")}
## 1. Purpose

This plan establishes a structured approach for detecting, responding to, and recovering from information security incidents affecting ${workspaceName}. The objective is to contain incidents rapidly, minimise impact, preserve evidence, and restore normal operations while meeting regulatory notification obligations.
${riskCtx}
## 2. Scope

This plan applies to all information security incidents affecting ${workspaceName} systems, data, personnel, and third-party services. It covers all incident types including data breaches, malware infections, denial of service, insider threats, and supply chain compromises.

## 3. Incident Classification

| Severity | Criteria | Initial Response Time |
|---|---|---|
| P1 – Critical | Data breach, ransomware, service outage affecting revenue | 1 hour |
| P2 – High | Malware detected, credential compromise, external exploitation | 4 hours |
| P3 – Medium | Policy violation, phishing attempt, failed intrusion | 24 hours |
| P4 – Low | Suspicious activity, anomaly alerts | 72 hours |

## 4. Policy Statements

4.1 **Incident Response Team (IRT)** — A designated IRT must be established with defined roles (Incident Commander, Technical Lead, Communications Lead, Legal Liaison).

4.2 **Detection and Reporting** — All personnel must report suspected incidents to security@${workspaceName.toLowerCase().replace(/[^a-z0-9]/g, "")}.com or the security helpdesk within 1 hour of discovery.

4.3 **Evidence Preservation** — Affected systems must not be powered off or wiped without approval from the Incident Commander. Forensic images must be taken before remediation.

4.4 **Containment** — Network isolation, credential revocation, and traffic blocking must be performed within the timeframes defined in Section 3.

4.5 **Regulatory Notification** — Incidents involving personal data must be assessed for GDPR/breach notification obligations within 24 hours. Regulators must be notified within 72 hours where required.

4.6 **Post-Incident Review** — A post-mortem must be completed within 5 business days of incident closure, with action items tracked to completion.

4.7 **Runbooks** — Technical runbooks for the most common incident types must be maintained and tested annually via tabletop exercises.

4.8 **Threat Intelligence Integration** — Indicators of compromise (IoCs) from incidents must be shared with threat intelligence feeds and used to update detection rules.

## 5. Incident Response Phases

1. **Preparation** — Maintain IRT roster, tooling, playbooks, and communication channels
2. **Detection & Analysis** — Identify, validate, and classify the incident
3. **Containment** — Short-term (isolate) and long-term (patch/harden) containment
4. **Eradication** — Remove threat actor persistence and malicious artefacts
5. **Recovery** — Restore systems from clean backups; validate integrity
6. **Post-Incident Activity** — Lessons learned, root cause analysis, control improvements

## 6. Roles and Responsibilities

| Role | Responsibility |
|---|---|
| Incident Commander | Coordinate response; authorise containment actions; communicate to leadership |
| Technical Lead | Lead forensic investigation and remediation |
| Communications Lead | Manage internal and external communications |
| Legal / Compliance | Assess notification obligations; preserve privilege |

## 7. Compliance References

- **NIST CSF 2.0:** RS.MA, RS.CO, RC.RP
- **ISO 27001:2022:** A.5.24, A.5.25, A.5.26, A.5.27, A.5.28
- **SOC 2 Type II:** CC7.3, CC7.4, CC7.5
- **CIS Controls v8:** Control 17 (Incident Response Management)

## 8. Review and Maintenance

This plan is reviewed annually, after each P1/P2 incident, and following material changes to the IT environment. Tabletop exercises must be conducted at least annually. Next review: ${new Date(new Date(effectiveDate).setFullYear(new Date(effectiveDate).getFullYear() + 1)).toISOString().slice(0, 10)}.
`;

    case "data_classification":
      return `${header("Data Classification Policy")}
## 1. Purpose

This policy establishes a framework for classifying, handling, and protecting ${workspaceName}'s information assets based on their sensitivity, business value, and regulatory obligations. Proper classification ensures that appropriate security controls are applied throughout the data lifecycle.
${riskCtx}
## 2. Scope

This policy applies to all data created, collected, processed, stored, or transmitted by ${workspaceName} personnel, systems, and third parties acting on ${workspaceName}'s behalf, regardless of format (digital, physical, verbal).

## 3. Data Classification Tiers

| Classification | Definition | Examples |
|---|---|---|
| **Public** | Approved for public release | Marketing materials, public docs |
| **Internal** | For employees only; limited business impact if disclosed | Internal memos, project plans |
| **Confidential** | Sensitive business data; significant impact if disclosed | Customer data, financials, contracts |
| **Restricted** | Highest sensitivity; regulatory or legal obligations | PII, PHI, PCI data, credentials, keys |

## 4. Policy Statements

4.1 **Classification Requirement** — All data assets must be classified at creation or acquisition. Default classification is Confidential if not explicitly labelled.

4.2 **Encryption at Rest** — Restricted and Confidential data must be encrypted at rest using AES-256 or equivalent. Encryption keys must be managed separately from encrypted data.

4.3 **Encryption in Transit** — All data classified Confidential or above must be transmitted over encrypted channels (TLS 1.2 minimum; TLS 1.3 preferred). Unencrypted protocols (HTTP, FTP, Telnet) are prohibited for sensitive data.

4.4 **Data Minimisation** — Only the minimum data necessary for the stated business purpose should be collected and retained.

4.5 **Retention and Disposal** — Data must be retained according to the Retention Policy and securely destroyed at end-of-life using NIST 800-88 media sanitisation standards.

4.6 **Access to Restricted Data** — Access to Restricted data requires explicit approval from the data owner and is subject to quarterly access reviews.

4.7 **Secrets and Credentials** — Credentials, API keys, and cryptographic material are classified as Restricted. They must never appear in source code, logs, or tickets.

4.8 **Data Loss Prevention** — Technical DLP controls must be implemented for Restricted and Confidential data egress via email, cloud storage, and removable media.

## 5. Roles and Responsibilities

| Role | Responsibility |
|---|---|
| Data Owners | Classify data assets; approve access to Restricted data |
| Data Custodians | Implement technical controls; manage storage and backups |
| All Staff | Apply correct classification labels; handle data per this policy |
| Legal / Compliance | Maintain regulatory mapping; advise on retention obligations |

## 6. Compliance References

- **NIST CSF 2.0:** ID.AM, PR.DS
- **ISO 27001:2022:** A.5.9, A.5.10, A.5.12, A.5.33, A.8.10, A.8.24
- **SOC 2 Type II:** CC6.1, CC6.7, CC9.1
- **CIS Controls v8:** Control 3 (Data Protection)

## 7. Review and Maintenance

This policy is reviewed annually or following a data breach, significant regulatory change, or new data type acquisition. Next review: ${new Date(new Date(effectiveDate).setFullYear(new Date(effectiveDate).getFullYear() + 1)).toISOString().slice(0, 10)}.
`;

    case "change_management":
      return `${header("Change Management Policy")}
## 1. Purpose

This policy governs the process for requesting, evaluating, approving, implementing, and reviewing changes to ${workspaceName}'s IT systems, infrastructure, and applications. It ensures that changes are made in a controlled manner that minimises security risk and operational disruption.
${riskCtx}
## 2. Scope

This policy applies to all changes to production systems including infrastructure, applications, network configuration, security controls, cloud resources, and third-party integrations.

## 3. Change Categories

| Category | Description | Approval Required |
|---|---|---|
| Standard | Pre-approved, low-risk, routine changes | CAB pre-approval (standing) |
| Normal | Non-emergency changes assessed through full CAB process | CAB + Change Owner |
| Emergency | Urgent changes required to restore service or prevent breach | CISO + CTO (retrospective CAB) |

## 4. Policy Statements

4.1 **Change Request** — All non-emergency changes must be submitted via the change management system with: description, scope, risk assessment, rollback plan, and testing evidence.

4.2 **Security Review** — Changes that modify authentication, authorisation, network exposure, or data handling must undergo a security review before approval.

4.3 **Separation of Duties** — Developers must not deploy their own changes to production. A second approver is required for all Normal and Emergency changes.

4.4 **Testing** — All changes must be tested in a non-production environment before production deployment. Automated test results must be attached to the change record.

4.5 **Rollback Plan** — Every change must include a documented and tested rollback procedure that can be executed within the agreed Recovery Time Objective (RTO).

4.6 **Emergency Changes** — Emergency changes must be documented within 24 hours of implementation and reviewed at the next CAB meeting.

4.7 **Audit Trail** — All change records must be retained for a minimum of 3 years. Change records must include who approved, who implemented, timestamps, and outcome.

4.8 **Vulnerability Remediation** — Security patches rated Critical must be applied within 7 days; High within 30 days; Medium within 90 days.

## 5. Roles and Responsibilities

| Role | Responsibility |
|---|---|
| Change Requester | Submit complete change request; own implementation and rollback |
| Change Advisory Board (CAB) | Review and approve Normal changes weekly |
| CISO | Approve emergency changes; own security review criteria |
| IT Operations | Implement approved changes; maintain the CMDB |

## 6. Compliance References

- **NIST CSF 2.0:** PR.PS, ID.RA
- **ISO 27001:2022:** A.8.32, A.8.8
- **SOC 2 Type II:** CC8.1
- **CIS Controls v8:** Control 4 (Secure Configuration), Control 7 (Vulnerability Management)

## 7. Review and Maintenance

This policy is reviewed annually or following a major incident attributable to an uncontrolled change. Next review: ${new Date(new Date(effectiveDate).setFullYear(new Date(effectiveDate).getFullYear() + 1)).toISOString().slice(0, 10)}.
`;

    case "vendor_management":
      return `${header("Vendor Management Policy")}
## 1. Purpose

This policy establishes requirements for assessing, onboarding, monitoring, and offboarding third-party vendors and service providers who access, process, store, or transmit ${workspaceName} data or who provide services that affect the security posture of ${workspaceName}.
${riskCtx}
## 2. Scope

This policy applies to all third-party relationships including SaaS providers, managed service providers, contractors, consultants, data processors, and any entity with access to ${workspaceName} systems or data.

## 3. Policy Statements

3.1 **Risk Tiering** — Vendors must be classified into tiers (Critical, High, Medium, Low) based on data access, system integration depth, and regulatory impact. Critical and High vendors require annual security assessments.

3.2 **Security Questionnaire** — All new vendors accessing Confidential or Restricted data must complete a security questionnaire and provide evidence of controls (e.g., SOC 2 report, ISO 27001 certificate, penetration test results) before onboarding.

3.3 **Contractual Requirements** — All vendor contracts must include: data processing agreements (DPA), security requirements, breach notification obligations (≤24 hours to ${workspaceName}), and right-to-audit clauses.

3.4 **Minimum Security Baseline** — Vendors must demonstrate: encryption in transit and at rest, MFA for privileged access, vulnerability management programme, and incident response capability.

3.5 **Continuous Monitoring** — Critical and High vendors must be monitored continuously via external attack surface scanning. Material security changes (breaches, certifications lapsing) must be communicated to ${workspaceName} within 48 hours.

3.6 **Fourth-Party Risk** — Critical vendors must disclose material subprocessors and notify ${workspaceName} of any changes to their supply chain that could affect data security.

3.7 **Offboarding** — Upon vendor relationship termination, all ${workspaceName} data must be returned or destroyed (with certificate of destruction) within 30 days.

3.8 **Access Revocation** — All vendor access (credentials, VPN, API keys) must be revoked within 4 hours of relationship termination.

## 4. Roles and Responsibilities

| Role | Responsibility |
|---|---|
| Procurement / Legal | Ensure DPA and security clauses in all vendor contracts |
| CISO | Define security assessment criteria; approve Critical vendor onboarding |
| Business Owner | Identify vendor tier; maintain vendor register entry |
| IT Operations | Provision and revoke vendor access; maintain audit trail |

## 5. Compliance References

- **NIST CSF 2.0:** GV.SC (Cybersecurity Supply Chain Risk Management)
- **ISO 27001:2022:** A.5.19, A.5.20, A.5.21, A.5.22
- **SOC 2 Type II:** CC9.2
- **CIS Controls v8:** Control 15 (Service Provider Management)

## 6. Review and Maintenance

This policy is reviewed annually or following a vendor-related security incident. The vendor register must be reviewed and updated quarterly. Next review: ${new Date(new Date(effectiveDate).setFullYear(new Date(effectiveDate).getFullYear() + 1)).toISOString().slice(0, 10)}.
`;

    case "risk_assessment":
      return `${header("Risk Assessment Policy")}
## 1. Purpose

This policy establishes a systematic approach to identifying, analysing, evaluating, and treating information security risks facing ${workspaceName}. It ensures that risks are understood, prioritised, and managed in alignment with ${workspaceName}'s risk appetite and business objectives.
${riskCtx}
## 2. Scope

This policy applies to all information assets, processes, systems, and third-party relationships within ${workspaceName}'s risk boundary, regardless of whether they are hosted on-premise or in the cloud.

## 3. Policy Statements

3.1 **Risk Assessment Cadence** — A formal risk assessment must be conducted at least annually and whenever significant changes occur (new systems, M&A activity, material security incidents, regulatory changes).

3.2 **Risk Identification** — Risks must be identified across threat categories including technical vulnerabilities, operational failures, third-party dependencies, insider threats, and regulatory non-compliance.

3.3 **Risk Scoring** — Risks are scored using Likelihood × Impact (each rated 1–3: Low/Medium/High), producing a 1–9 scale. Scores ≥6 are High risk; 3–5 are Medium; 1–2 are Low.

3.4 **Risk Register** — All identified risks must be recorded in the Risk Register with: description, category, owner, likelihood, impact, score, treatment, and review date.

3.5 **Risk Treatment** — Each risk must have a documented treatment decision: Mitigate (implement controls), Accept (documented with CISO approval), Transfer (insurance/vendor), or Avoid (cease the activity).

3.6 **High Risk Escalation** — Risks scored ≥8 must be reported to the Board/Executive Team within 5 business days and reviewed monthly until remediated or formally accepted.

3.7 **Risk Acceptance** — Risk acceptance must be formally documented, approved by the CISO, and reviewed quarterly. Accepted risks cannot exceed a defined aggregate threshold.

3.8 **Residual Risk** — After treatment, residual risk must be assessed and accepted by the appropriate authority before the risk is closed.

## 4. Risk Categories

- Technical: Vulnerabilities, misconfigurations, unpatched systems
- Operational: Process failures, human error, business continuity
- Third-Party: Vendor breaches, supply chain compromise
- Regulatory: Non-compliance with GDPR, PCI DSS, SOC 2, ISO 27001
- Strategic: Reputational damage, M&A integration risks

## 5. Roles and Responsibilities

| Role | Responsibility |
|---|---|
| CISO | Own the risk management programme; approve risk acceptance |
| Risk Owners | Identify risks in their domain; implement treatments; update register |
| Internal Audit | Independently validate risk register completeness and accuracy |
| Executive Team | Review High risks; set risk appetite |

## 6. Compliance References

- **NIST CSF 2.0:** GV.RM, ID.RA
- **ISO 27001:2022:** Clause 6.1, A.5.7
- **SOC 2 Type II:** CC3.1, CC3.2, CC3.3, CC3.4
- **CIS Controls v8:** Control 18 (Penetration Testing)

## 7. Review and Maintenance

This policy is reviewed annually or following a material risk event. The risk register is reviewed monthly for High risks and quarterly for all others. Next review: ${new Date(new Date(effectiveDate).setFullYear(new Date(effectiveDate).getFullYear() + 1)).toISOString().slice(0, 10)}.
`;

    case "business_continuity":
      return `${header("Business Continuity Policy")}
## 1. Purpose

This policy establishes ${workspaceName}'s commitment to maintaining critical business operations during and after disruptive events. It defines requirements for business continuity planning (BCP), disaster recovery (DR), and resilience to ensure that ${workspaceName} can continue to serve its customers and meet its obligations under adverse conditions.
${riskCtx}
## 2. Scope

This policy applies to all critical business processes, IT systems, personnel, and facilities that support ${workspaceName}'s key services. It encompasses natural disasters, cyber incidents, infrastructure failures, pandemic events, and supply chain disruptions.

## 3. Policy Statements

3.1 **BCP Development** — A Business Continuity Plan must be developed for each critical business function, defining Maximum Tolerable Downtime (MTD), Recovery Time Objective (RTO), and Recovery Point Objective (RPO).

3.2 **Recovery Objectives** — Tier 1 (revenue-critical) systems must have RTO ≤4 hours and RPO ≤1 hour. Tier 2 systems must have RTO ≤24 hours and RPO ≤4 hours.

3.3 **Backup Requirements** — Critical data must be backed up daily (minimum), with backups tested monthly. Backups must follow the 3-2-1 rule (3 copies, 2 different media, 1 offsite/cloud).

3.4 **Backup Testing** — Backup restoration must be tested at least quarterly. Test results must be documented and retained.

3.5 **Disaster Recovery** — A Disaster Recovery Plan (DRP) must be maintained for all Tier 1 systems, with documented runbooks and designated recovery teams.

3.6 **DR Testing** — Tabletop exercises must be conducted annually; full DR failover tests must be performed for Tier 1 systems at least every 18 months.

3.7 **Redundancy** — Critical systems must be deployed across multiple availability zones or data centres to eliminate single points of failure.

3.8 **Communication Plan** — A crisis communication plan must exist for notifying customers, regulators, staff, and media during a disruptive event, with pre-approved message templates.

3.9 **Supply Chain Resilience** — Alternative suppliers must be identified for all single-source critical dependencies. Vendor SLAs must include BCP requirements.

## 4. Roles and Responsibilities

| Role | Responsibility |
|---|---|
| BCP Coordinator | Maintain and test the BCP; coordinate exercises |
| IT Operations | Implement DR infrastructure; execute recovery runbooks |
| Business Unit Leads | Define critical processes and acceptable downtimes |
| Executive Team | Invoke BCP during a declared disaster; communicate to stakeholders |

## 5. Compliance References

- **NIST CSF 2.0:** RC.RP, RC.CO
- **ISO 27001:2022:** A.5.29, A.5.30, A.8.13, A.8.14
- **SOC 2 Type II:** A1.1, A1.2, A1.3
- **CIS Controls v8:** Control 11 (Data Recovery)

## 6. Review and Maintenance

This policy is reviewed annually and following any activation of the BCP or major IT infrastructure change. Next review: ${new Date(new Date(effectiveDate).setFullYear(new Date(effectiveDate).getFullYear() + 1)).toISOString().slice(0, 10)}.
`;

    case "acceptable_use":
      return `${header("Acceptable Use Policy")}
## 1. Purpose

This policy defines acceptable and prohibited uses of ${workspaceName}'s information systems, network infrastructure, data, and technology resources. It protects ${workspaceName}'s assets, maintains a productive work environment, and ensures compliance with legal and regulatory obligations.
${riskCtx}
## 2. Scope

This policy applies to all employees, contractors, consultants, and third parties who are granted access to ${workspaceName} systems, networks, or data, whether on-premise or remote.

## 3. Policy Statements

3.1 **Authorised Use** — ${workspaceName} systems and resources are provided for legitimate business purposes. Incidental personal use is permitted provided it does not consume excessive resources or violate any provisions of this policy.

3.2 **Prohibited Activities** — The following are strictly prohibited:
- Accessing, downloading, or distributing illegal content
- Bypassing security controls, firewalls, or content filters
- Installing unauthorised software or browser extensions
- Using ${workspaceName} resources to conduct personal business or freelance work
- Sharing credentials or allowing others to use your account
- Connecting unauthorised devices (personal USB drives, shadow IT) to corporate systems
- Conducting port scans, vulnerability assessments, or exploit attempts against systems not explicitly authorised

3.3 **Internet and Email Use** — Internet and email access must not be used for phishing, spam, harassment, or the transmission of confidential data to unauthorised parties.

3.4 **Social Media** — Employees must not share confidential ${workspaceName} information, client data, or internal system details on social media platforms.

3.5 **Remote Work** — Remote workers must use ${workspaceName}-approved devices, connect via the approved VPN, and ensure their home networks use WPA3 or WPA2 encryption.

3.6 **Physical Security** — Workstations must be locked when unattended (screen lock ≤5 minutes). Sensitive documents must be stored securely and shredded when no longer needed.

3.7 **Software Licensing** — Only legally licensed software approved by IT must be used on ${workspaceName} systems. Employees must not circumvent licensing controls.

3.8 **Monitoring** — ${workspaceName} reserves the right to monitor all activity on its systems and networks. Users have no expectation of privacy on corporate devices or networks.

## 4. Roles and Responsibilities

| Role | Responsibility |
|---|---|
| IT Operations | Enforce technical controls; maintain approved software list |
| HR | Communicate policy to new hires; enforce disciplinary process |
| All Staff | Comply with this policy; report suspected violations |
| Security Team | Monitor for policy violations; investigate incidents |

## 5. Compliance References

- **NIST CSF 2.0:** PR.AT (Awareness and Training)
- **ISO 27001:2022:** A.5.10, A.6.3, A.8.1
- **SOC 2 Type II:** CC1.4
- **CIS Controls v8:** Control 14 (Security Awareness Training)

## 6. Review and Maintenance

This policy is reviewed annually and communicated to all staff at onboarding and upon each major revision. Next review: ${new Date(new Date(effectiveDate).setFullYear(new Date(effectiveDate).getFullYear() + 1)).toISOString().slice(0, 10)}.
`;

    default: // change_management fallback / unknown types
      return `${header("Security Policy")}
## 1. Purpose

This policy defines minimum governance and security requirements for ${workspaceName}.
${riskCtx}
## 2. Scope

This policy applies to all employees, contractors, systems, and data assets under ${workspaceName}'s control.

## 3. Policy Statements

- Security responsibilities are documented and assigned.
- Access and changes to production systems require authorization and auditability.
- Security incidents are detected, triaged, and remediated with documented evidence.
- Risks are tracked in the risk register and reviewed on a recurring cadence.
- Controls and policies are reviewed at least annually.

## 4. Compliance References

- **NIST CSF 2.0:** GV, ID, PR, DE, RS, RC
- **ISO 27001:2022:** Clause 6, Annex A
- **SOC 2 Type II:** Common Criteria

## 5. Review and Maintenance

This policy is reviewed annually or after material operational or security changes. Next review: ${new Date(new Date(effectiveDate).setFullYear(new Date(effectiveDate).getFullYear() + 1)).toISOString().slice(0, 10)}.
`;
  }
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
  contextFindings: Finding[] = [],
): Promise<void> {
  const workspace = await storage.getWorkspace(workspaceId);
  const effectiveDate = new Date().toISOString().slice(0, 10);

  const existing = await storage.getPolicyDocumentByType(workspaceId, policyType);
  const version = existing ? bumpVersion(existing.version) : "1.0";

  const content = policyContent(policyType, workspace?.name ?? "Organization", effectiveDate, version, contextFindings);
  const title = content.split("\n")[0]?.replace(/^#\s*/, "") || "Security Policy";

  const payload: InsertPolicyDocument = {
    workspaceId,
    policyType,
    title,
    version,
    effectiveDate: new Date(),
    content,
    createdBy: createdBy ?? null,
  };

  if (existing) {
    await storage.updatePolicyDocument(existing.id, {
      title: payload.title,
      version: payload.version,
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
