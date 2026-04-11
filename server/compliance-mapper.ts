/**
 * Compliance Mapping Service
 *
 * Framework support:
 * - OWASP Top 10 (2021)
 * - CIS Controls v8 (high-level)
 * - NIST CSF 2.0 (high-level categories)
 * - SOC 2 (selected Trust Services Criteria controls)
 * - ISO 27001 (selected Annex A controls)
 * - HIPAA Security Rule (selected safeguard controls)
 */

import type { Finding } from "@shared/schema";

export type FrameworkKey = "owasp" | "cis" | "nist" | "soc2" | "iso27001" | "hipaa";

type MappingStatus = "pass" | "fail" | "partial" | "unknown";

interface FrameworkMeta {
  name: string;
  version: string;
  controls: ComplianceControl[];
}

interface FindingIndex {
  checkId: string;
  category: string;
  severity: string;
}

export interface ComplianceControl {
  id: string;
  title: string;
  description: string;
  framework: FrameworkKey;
  requiresPolicy?: boolean;
  guidance?: string;
}

export interface ComplianceMapping {
  control: ComplianceControl;
  findingIds: string[];
  status: MappingStatus;
  overallStatus: MappingStatus;
  passCount: number;
  failCount: number;
  partialCount: number;
  severity: "critical" | "high" | "medium" | "low" | "info";
  requiresPolicy: boolean;
  guidance: string;
}

export interface ComplianceReport {
  framework: string;
  frameworkVersion: string;
  totalControls: number;
  assessedControls: number;
  hasAssessmentData: boolean;
  policyRequiredControls: number;
  policyRequiredAssessedControls: number;
  policyRequiredFailingControls: number;
  passCount: number;
  failCount: number;
  partialCount: number;
  unknownCount: number;
  score: number;
  mappings: ComplianceMapping[];
  generatedAt: string;
}

const OWASP_CONTROLS: ComplianceControl[] = [
  { id: "A01", title: "Broken Access Control", description: "Restrictions on authenticated users are not properly enforced.", framework: "owasp" },
  { id: "A02", title: "Cryptographic Failures", description: "Failures related to cryptography that can lead to data exposure.", framework: "owasp" },
  { id: "A03", title: "Injection", description: "User-supplied data is not validated or sanitized by the application.", framework: "owasp" },
  { id: "A04", title: "Insecure Design", description: "Missing or ineffective control design.", framework: "owasp" },
  { id: "A05", title: "Security Misconfiguration", description: "Missing appropriate hardening across the application stack.", framework: "owasp" },
  { id: "A06", title: "Vulnerable and Outdated Components", description: "Using components with known vulnerabilities.", framework: "owasp" },
  { id: "A07", title: "Identification and Authentication Failures", description: "Authentication and session management weaknesses.", framework: "owasp" },
  { id: "A08", title: "Software and Data Integrity Failures", description: "Code and infrastructure that do not protect integrity.", framework: "owasp" },
  { id: "A09", title: "Security Logging and Monitoring Failures", description: "Insufficient logging, detection, and response.", framework: "owasp" },
  { id: "A10", title: "Server-Side Request Forgery", description: "Server fetches remote resources without strict validation.", framework: "owasp" },
];

const CIS_CONTROLS: ComplianceControl[] = [
  { id: "CIS-01", title: "Inventory and Control of Enterprise Assets", description: "Actively manage all assets connected to the infrastructure.", framework: "cis" },
  { id: "CIS-02", title: "Inventory and Control of Software Assets", description: "Actively manage all software on the network.", framework: "cis" },
  { id: "CIS-03", title: "Data Protection", description: "Identify, classify, and protect data.", framework: "cis" },
  { id: "CIS-04", title: "Secure Configuration of Enterprise Assets", description: "Establish and maintain secure configurations.", framework: "cis" },
  { id: "CIS-05", title: "Account Management", description: "Use processes and tools to assign and manage credentials.", framework: "cis" },
  { id: "CIS-06", title: "Access Control Management", description: "Create, assign, manage, and revoke access credentials.", framework: "cis" },
  { id: "CIS-07", title: "Continuous Vulnerability Management", description: "Continuously assess and remediate vulnerabilities.", framework: "cis" },
  { id: "CIS-08", title: "Audit Log Management", description: "Collect, review, and retain audit logs.", framework: "cis" },
  { id: "CIS-09", title: "Email and Web Browser Protections", description: "Improve protections for email and web browsers.", framework: "cis" },
  { id: "CIS-10", title: "Malware Defenses", description: "Control installation and execution of malicious code.", framework: "cis" },
  { id: "CIS-11", title: "Data Recovery", description: "Establish and maintain data recovery practices.", framework: "cis" },
  { id: "CIS-12", title: "Network Infrastructure Management", description: "Establish and maintain secure network infrastructure.", framework: "cis" },
  { id: "CIS-13", title: "Network Monitoring and Defense", description: "Maintain comprehensive network monitoring.", framework: "cis" },
  { id: "CIS-14", title: "Security Awareness and Skills Training", description: "Establish and maintain security awareness program.", framework: "cis" },
  { id: "CIS-15", title: "Service Provider Management", description: "Develop a process to evaluate service providers.", framework: "cis" },
  { id: "CIS-16", title: "Application Software Security", description: "Manage software security throughout the lifecycle.", framework: "cis" },
  { id: "CIS-17", title: "Incident Response Management", description: "Maintain incident response capability.", framework: "cis" },
  { id: "CIS-18", title: "Penetration Testing", description: "Test resiliency of enterprise assets.", framework: "cis" },
];

const NIST_CONTROLS: ComplianceControl[] = [
  { id: "GV", title: "Govern", description: "Risk management strategy, expectations, and policy.", framework: "nist" },
  { id: "ID.AM", title: "Asset Management", description: "Assets and facilities are identified and managed.", framework: "nist" },
  { id: "ID.RA", title: "Risk Assessment", description: "Understand cybersecurity risk to operations and assets.", framework: "nist" },
  { id: "PR.AA", title: "Identity Management and Access Control", description: "Access is limited to authorized users and devices.", framework: "nist" },
  { id: "PR.DS", title: "Data Security", description: "Information is managed consistent with risk strategy.", framework: "nist" },
  { id: "PR.PS", title: "Platform Security", description: "Platform security is managed and maintained.", framework: "nist" },
  { id: "PR.IR", title: "Infrastructure Resilience", description: "Security architecture protects CIA goals.", framework: "nist" },
  { id: "DE.CM", title: "Continuous Monitoring", description: "Assets are monitored for anomalies and compromise.", framework: "nist" },
  { id: "DE.AE", title: "Adverse Event Analysis", description: "Potentially adverse events are analyzed.", framework: "nist" },
  { id: "RS.MA", title: "Incident Management", description: "Responses to incidents are managed.", framework: "nist" },
  { id: "RS.MI", title: "Incident Mitigation", description: "Activities mitigate detected events.", framework: "nist" },
  { id: "RC.RP", title: "Incident Recovery Plan Execution", description: "Restoration activities ensure availability.", framework: "nist" },
];

const SOC2_CONTROLS: ComplianceControl[] = [
  { id: "CC1.1", title: "Control Environment", description: "Commitment to integrity and ethical values.", framework: "soc2", requiresPolicy: true, guidance: "Maintain acceptable use and security awareness policies." },
  { id: "CC2.1", title: "Information and Communication", description: "Relevant information supports internal control.", framework: "soc2", requiresPolicy: true, guidance: "Document incident communication and training processes." },
  { id: "CC3.1", title: "Risk Assessment", description: "Risk identification and assessment process is defined.", framework: "soc2", requiresPolicy: true, guidance: "Maintain and review a living risk register." },
  { id: "CC6.1", title: "Logical Access Security", description: "Logical access controls protect information assets.", framework: "soc2" },
  { id: "CC6.2", title: "Access Provisioning", description: "User access is authorized and provisioned correctly.", framework: "soc2" },
  { id: "CC6.3", title: "Access Removal", description: "Access is removed in a timely manner.", framework: "soc2" },
  { id: "CC7.1", title: "Detection and Monitoring", description: "Monitoring detects vulnerabilities and configuration changes.", framework: "soc2" },
  { id: "CC8.1", title: "Change Management", description: "Changes are controlled and tested before deployment.", framework: "soc2", requiresPolicy: true, guidance: "Enforce reviewed change management workflow." },
  { id: "CC9.1", title: "Risk Mitigation", description: "Risk mitigation activities exist for business disruption.", framework: "soc2", requiresPolicy: true, guidance: "Vendor management and BCP/DR policies should be documented." },
];

const ISO27001_CONTROLS: ComplianceControl[] = [
  { id: "A.5.1", title: "Policies for Information Security", description: "Information security policy framework exists and is reviewed.", framework: "iso27001", requiresPolicy: true, guidance: "Maintain and version security policy documents." },
  { id: "A.5.15", title: "Access Control", description: "Access control rules are established and enforced.", framework: "iso27001" },
  { id: "A.5.16", title: "Identity Management", description: "Identity lifecycle is controlled.", framework: "iso27001" },
  { id: "A.8.24", title: "Use of Cryptography", description: "Cryptographic controls protect confidentiality and integrity.", framework: "iso27001" },
  { id: "A.8.20", title: "Network Security", description: "Networks are secured and monitored.", framework: "iso27001" },
  { id: "A.8.28", title: "Secure Coding", description: "Secure coding principles are applied to development.", framework: "iso27001" },
  { id: "A.8.7", title: "Protection Against Malware", description: "Controls detect and prevent malware.", framework: "iso27001" },
  { id: "A.8.16", title: "Monitoring Activities", description: "Systems and events are monitored.", framework: "iso27001" },
  { id: "A.5.30", title: "ICT Readiness for Business Continuity", description: "Continuity requirements are planned and tested.", framework: "iso27001", requiresPolicy: true, guidance: "Maintain business continuity and disaster recovery policy." },
];

const HIPAA_CONTROLS: ComplianceControl[] = [
  { id: "164.308(a)(1)", title: "Security Management Process", description: "Risk analysis and risk management process exists.", framework: "hipaa", requiresPolicy: true, guidance: "Maintain risk assessment policy and risk register." },
  { id: "164.308(a)(3)", title: "Workforce Security", description: "Workforce access is authorized and supervised.", framework: "hipaa" },
  { id: "164.308(a)(4)", title: "Information Access Management", description: "Access to ePHI is limited appropriately.", framework: "hipaa" },
  { id: "164.308(a)(5)", title: "Security Awareness and Training", description: "Security awareness and training is performed.", framework: "hipaa", requiresPolicy: true, guidance: "Track annual awareness training coverage." },
  { id: "164.312(a)(1)", title: "Access Control (Technical Safeguards)", description: "Technical controls enforce access restrictions.", framework: "hipaa" },
  { id: "164.312(c)(1)", title: "Integrity", description: "ePHI integrity is protected from improper alteration.", framework: "hipaa" },
  { id: "164.312(e)(1)", title: "Transmission Security", description: "ePHI transmission is protected in transit.", framework: "hipaa" },
  { id: "164.308(a)(1)(ii)(D)", title: "Information System Activity Review", description: "Audit logs and activity reports are reviewed.", framework: "hipaa" },
];

const FRAMEWORKS: Record<FrameworkKey, FrameworkMeta> = {
  owasp: { name: "OWASP Top 10", version: "2021", controls: OWASP_CONTROLS },
  cis: { name: "CIS Controls", version: "v8", controls: CIS_CONTROLS },
  nist: { name: "NIST CSF", version: "2.0", controls: NIST_CONTROLS },
  soc2: { name: "SOC 2", version: "TSC 2017", controls: SOC2_CONTROLS },
  iso27001: { name: "ISO 27001", version: "2022", controls: ISO27001_CONTROLS },
  hipaa: { name: "HIPAA Security Rule", version: "45 CFR 164", controls: HIPAA_CONTROLS },
};

const CATEGORY_MAP: Record<string, Partial<Record<FrameworkKey, string[]>>> = {
  subdomain_takeover: { owasp: ["A05"], cis: ["CIS-12"], nist: ["PR.PS"], soc2: ["CC6.1"], iso27001: ["A.8.20"], hipaa: ["164.312(a)(1)"] },
  ssl_issue: { owasp: ["A02"], cis: ["CIS-03"], nist: ["PR.DS"], soc2: ["CC6.1"], iso27001: ["A.8.24"], hipaa: ["164.312(e)(1)"] },
  security_headers: { owasp: ["A05"], cis: ["CIS-04"], nist: ["PR.PS"], soc2: ["CC8.1"], iso27001: ["A.8.28"] },
  threat_intelligence: { owasp: ["A09"], cis: ["CIS-13"], nist: ["DE.CM", "DE.AE"], soc2: ["CC7.1"], iso27001: ["A.8.16"], hipaa: ["164.308(a)(1)(ii)(D)"] },
  dns_misconfiguration: { owasp: ["A05"], cis: ["CIS-12"], nist: ["PR.IR"], soc2: ["CC6.1"], iso27001: ["A.8.20"] },
  exposed_credentials: { owasp: ["A07"], cis: ["CIS-03", "CIS-05"], nist: ["PR.AA"], soc2: ["CC6.1", "CC6.2"], iso27001: ["A.5.15", "A.5.16"], hipaa: ["164.308(a)(4)", "164.312(a)(1)"] },
  infrastructure_disclosure: { owasp: ["A05"], cis: ["CIS-04"], nist: ["PR.PS"], soc2: ["CC8.1"], iso27001: ["A.8.20"] },
  api_exposure: { owasp: ["A01", "A05"], cis: ["CIS-06", "CIS-16"], nist: ["PR.AA", "PR.PS"], soc2: ["CC6.2", "CC8.1"], iso27001: ["A.5.15", "A.8.28"], hipaa: ["164.308(a)(4)", "164.312(a)(1)"] },
  secret_exposure: { owasp: ["A02", "A07"], cis: ["CIS-03", "CIS-05"], nist: ["PR.AA", "PR.DS"], soc2: ["CC6.1", "CC6.3"], iso27001: ["A.5.16", "A.8.24"], hipaa: ["164.312(c)(1)", "164.312(e)(1)"] },
  open_port: { owasp: ["A05"], cis: ["CIS-12"], nist: ["PR.PS"], soc2: ["CC6.1"], iso27001: ["A.8.20"], hipaa: ["164.312(a)(1)"] },
  nuclei_finding: { owasp: ["A06"], cis: ["CIS-07"], nist: ["ID.RA"], soc2: ["CC7.1"], iso27001: ["A.8.7"], hipaa: ["164.308(a)(1)"] },
  leaked_credential: { owasp: ["A07"], cis: ["CIS-05"], nist: ["PR.AA"], soc2: ["CC6.1"], iso27001: ["A.5.16"], hipaa: ["164.312(a)(1)"] },
  data_leak: { owasp: ["A02"], cis: ["CIS-03"], nist: ["PR.DS"], soc2: ["CC9.1"], iso27001: ["A.8.24"], hipaa: ["164.312(c)(1)", "164.312(e)(1)"] },
  osint_exposure: { owasp: ["A05"], cis: ["CIS-04"], nist: ["ID.RA"], soc2: ["CC7.1"], iso27001: ["A.8.16"] },
  vulnerability: { owasp: ["A06"], cis: ["CIS-07"], nist: ["ID.RA"], soc2: ["CC7.1"], iso27001: ["A.8.7"], hipaa: ["164.308(a)(1)"] },
  clickjacking: { owasp: ["A05"], cis: ["CIS-16"], nist: ["PR.PS"], soc2: ["CC8.1"], iso27001: ["A.8.28"] },
  cors_misconfiguration: { owasp: ["A01", "A05"], cis: ["CIS-06"], nist: ["PR.AA"], soc2: ["CC6.2"], iso27001: ["A.5.15"], hipaa: ["164.312(a)(1)"] },
  xss: { owasp: ["A03"], cis: ["CIS-16", "CIS-18"], nist: ["PR.PS"], soc2: ["CC8.1"], iso27001: ["A.8.28"] },
  waf_bypass: { owasp: ["A05"], cis: ["CIS-13"], nist: ["DE.CM"], soc2: ["CC7.1"], iso27001: ["A.8.16"] },
  cloud_exposure: { owasp: ["A05"], cis: ["CIS-12"], nist: ["PR.PS"], soc2: ["CC6.1"], iso27001: ["A.8.20"], hipaa: ["164.312(a)(1)"] },
};

const CHECK_ID_MAP: Record<string, Partial<Record<FrameworkKey, string[]>>> = {
  "iam-root-mfa": { soc2: ["CC6.1"], iso27001: ["A.5.16"], hipaa: ["164.312(a)(1)"] },
  "iam-user-mfa": { soc2: ["CC6.1"], iso27001: ["A.5.16"], hipaa: ["164.312(a)(1)"] },
  "iam-password-policy": { soc2: ["CC6.1"], iso27001: ["A.5.15"], hipaa: ["164.312(a)(1)"] },
  "iam-no-direct-policies": { soc2: ["CC6.2"], iso27001: ["A.5.15"], hipaa: ["164.308(a)(4)"] },
  "iam-overprivileged-user": { soc2: ["CC6.2"], iso27001: ["A.5.15"], hipaa: ["164.308(a)(4)"] },
  "iam-access-key-rotation": { soc2: ["CC6.3"], iso27001: ["A.5.16"], hipaa: ["164.312(a)(1)"] },
  "cloudtrail-enabled": { soc2: ["CC7.1", "CC8.1"], iso27001: ["A.8.16"], hipaa: ["164.308(a)(1)(ii)(D)"] },
  "guardduty-enabled": { soc2: ["CC7.1"], iso27001: ["A.8.7", "A.8.16"], hipaa: ["164.308(a)(1)"] },
  "config-enabled": { soc2: ["CC7.1", "CC8.1"], iso27001: ["A.8.16"], hipaa: ["164.308(a)(1)(ii)(D)"] },
  "s3-encryption-at-rest": { soc2: ["CC6.1"], iso27001: ["A.8.24"], hipaa: ["164.312(c)(1)"] },
  "s3-public-access-block": { soc2: ["CC6.2"], iso27001: ["A.5.15"], hipaa: ["164.308(a)(4)"] },
  "vpc-flow-logs-enabled": { soc2: ["CC7.1"], iso27001: ["A.8.16"], hipaa: ["164.308(a)(1)(ii)(D)"] },
  "sg-no-unrestricted-ingress": { soc2: ["CC6.1"], iso27001: ["A.8.20"], hipaa: ["164.312(a)(1)"] },
};

const SEVERITY_FALLBACK_MAP: Record<FrameworkKey, Record<"critical" | "high" | "medium" | "low" | "info", string[]>> = {
  owasp: { critical: ["A05"], high: ["A06"], medium: ["A09"], low: ["A04"], info: ["A09"] },
  cis: { critical: ["CIS-07"], high: ["CIS-12"], medium: ["CIS-04"], low: ["CIS-08"], info: ["CIS-08"] },
  nist: { critical: ["PR.PS"], high: ["ID.RA"], medium: ["DE.CM"], low: ["GV"], info: ["GV"] },
  soc2: { critical: ["CC7.1"], high: ["CC6.1"], medium: ["CC8.1"], low: ["CC2.1"], info: ["CC2.1"] },
  iso27001: { critical: ["A.8.7"], high: ["A.8.20"], medium: ["A.8.16"], low: ["A.5.1"], info: ["A.5.1"] },
  hipaa: { critical: ["164.312(a)(1)"], high: ["164.308(a)(1)"], medium: ["164.308(a)(1)(ii)(D)"], low: ["164.308(a)(5)"], info: ["164.308(a)(5)"] },
};

function isResolvedFinding(status: string): boolean {
  return status === "resolved" || status === "closed" || status === "verified";
}

function normalizeSeverity(severity: string | null | undefined): "critical" | "high" | "medium" | "low" | "info" {
  const raw = String(severity ?? "").toLowerCase();
  if (raw === "critical" || raw === "high" || raw === "medium" || raw === "low") return raw;
  return "info";
}

function getHighestSeverity(findings: Finding[]): ComplianceMapping["severity"] {
  const order: ComplianceMapping["severity"][] = ["critical", "high", "medium", "low", "info"];
  for (const s of order) {
    if (findings.some((f) => normalizeSeverity(f.severity) === s && !isResolvedFinding(f.status))) return s;
  }
  return "info";
}

function getMappingControlIds(finding: FindingIndex, framework: FrameworkKey): string[] {
  const checkMappings = CHECK_ID_MAP[finding.checkId]?.[framework] ?? [];
  if (checkMappings.length > 0) return checkMappings;

  const categoryMappings = CATEGORY_MAP[finding.category]?.[framework] ?? [];
  if (categoryMappings.length > 0) return categoryMappings;

  return SEVERITY_FALLBACK_MAP[framework][normalizeSeverity(finding.severity)];
}

function computeControlCounts(controlFindings: Finding[]): Pick<ComplianceMapping, "passCount" | "failCount" | "partialCount" | "status" | "overallStatus"> {
  if (controlFindings.length === 0) {
    return { passCount: 0, failCount: 0, partialCount: 0, status: "unknown", overallStatus: "unknown" };
  }

  let passCount = 0;
  let failCount = 0;
  let partialCount = 0;

  for (const f of controlFindings) {
    if (isResolvedFinding(f.status)) {
      passCount++;
    } else if (f.status === "in_review" || f.status === "in_progress") {
      partialCount++;
    } else {
      failCount++;
    }
  }

  let status: MappingStatus = "unknown";
  if (failCount > 0 && passCount > 0) status = "partial";
  else if (failCount > 0 && partialCount > 0) status = "partial";
  else if (failCount > 0) status = "fail";
  else if (partialCount > 0) status = "partial";
  else if (passCount > 0) status = "pass";

  return { passCount, failCount, partialCount, status, overallStatus: status };
}

function mapFindingsToControls(
  findings: Finding[],
  controls: ComplianceControl[],
  framework: FrameworkKey,
): ComplianceMapping[] {
  const findingsByControl = new Map<string, Finding[]>();

  for (const control of controls) {
    findingsByControl.set(control.id, []);
  }

  for (const finding of findings) {
    const index: FindingIndex = {
      checkId: String((finding as Finding & { checkId?: string | null }).checkId ?? "").toLowerCase().trim(),
      category: String(finding.category ?? "").toLowerCase().trim(),
      severity: String(finding.severity ?? "").toLowerCase().trim(),
    };

    const controlIds = getMappingControlIds(index, framework);
    for (const controlId of controlIds) {
      const existing = findingsByControl.get(controlId);
      if (existing) existing.push(finding);
    }
  }

  return controls.map((control) => {
    const matchedFindings = findingsByControl.get(control.id) ?? [];
    const counts = computeControlCounts(matchedFindings);

    return {
      control,
      findingIds: matchedFindings.map((f) => f.id),
      status: counts.status,
      overallStatus: counts.overallStatus,
      passCount: counts.passCount,
      failCount: counts.failCount,
      partialCount: counts.partialCount,
      severity: matchedFindings.length > 0 ? getHighestSeverity(matchedFindings) : "info",
      requiresPolicy: !!control.requiresPolicy,
      guidance: control.guidance ?? "",
    };
  });
}

/**
 * Weight applied to "partial" controls when computing the compliance score.
 * A partial control satisfies some (but not all) requirements, so it contributes
 * half-credit toward the passing count.
 */
const PARTIAL_WEIGHT = 0.5;

/**
 * Compute a compliance score (0–100) for a set of control mappings.
 *
 * Formula: round((passing + partial × PARTIAL_WEIGHT) / assessedControls × 100)
 * "unknown" controls (no evidence for or against) are excluded from the denominator.
 * Returns 0 when no controls have been assessed.
 */
function computeScore(mappings: ComplianceMapping[]): number {
  const assessed = mappings.filter((m) => m.overallStatus !== "unknown");
  if (assessed.length === 0) return 0;
  const passing = assessed.filter((m) => m.overallStatus === "pass").length;
  const partial = assessed.filter((m) => m.overallStatus === "partial").length;
  return Math.round(((passing + partial * PARTIAL_WEIGHT) / assessed.length) * 100);
}

export function generateComplianceReport(
  findings: Finding[],
  framework: FrameworkKey,
): ComplianceReport {
  const fw = FRAMEWORKS[framework];
  const mappings = mapFindingsToControls(findings, fw.controls, framework);

  const passCount = mappings.filter((m) => m.overallStatus === "pass").length;
  const failCount = mappings.filter((m) => m.overallStatus === "fail").length;
  const partialCount = mappings.filter((m) => m.overallStatus === "partial").length;
  const unknownCount = mappings.filter((m) => m.overallStatus === "unknown").length;
  const assessedControls = mappings.length - unknownCount;
  const policyRequiredControls = mappings.filter((m) => m.requiresPolicy).length;
  const policyRequiredAssessedControls = mappings.filter((m) => m.requiresPolicy && m.overallStatus !== "unknown").length;
  const policyRequiredFailingControls = mappings.filter((m) => m.requiresPolicy && m.overallStatus === "fail").length;
  const score = computeScore(mappings);

  return {
    framework: fw.name,
    frameworkVersion: fw.version,
    totalControls: fw.controls.length,
    assessedControls,
    hasAssessmentData: assessedControls > 0,
    policyRequiredControls,
    policyRequiredAssessedControls,
    policyRequiredFailingControls,
    passCount,
    failCount,
    partialCount,
    unknownCount,
    score,
    mappings,
    generatedAt: new Date().toISOString(),
  };
}

export function generateAllComplianceReports(findings: Finding[]): Record<string, ComplianceReport> {
  return {
    owasp: generateComplianceReport(findings, "owasp"),
    cis: generateComplianceReport(findings, "cis"),
    nist: generateComplianceReport(findings, "nist"),
    soc2: generateComplianceReport(findings, "soc2"),
    iso27001: generateComplianceReport(findings, "iso27001"),
    hipaa: generateComplianceReport(findings, "hipaa"),
  };
}
