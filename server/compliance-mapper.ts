/**
 * Compliance Mapping Service
 *
 * Maps security findings to standard compliance frameworks:
 * - OWASP Top 10 (2021)
 * - CIS Controls v8
 * - NIST CSF 2.0
 */

import type { Finding } from "@shared/schema";

export interface ComplianceControl {
  id: string;
  title: string;
  description: string;
  framework: "owasp" | "cis" | "nist";
}

export interface ComplianceMapping {
  control: ComplianceControl;
  findingIds: string[];
  status: "pass" | "fail" | "partial" | "unknown";
  severity: "critical" | "high" | "medium" | "low" | "info";
}

export interface ComplianceReport {
  framework: string;
  frameworkVersion: string;
  totalControls: number;
  passCount: number;
  failCount: number;
  partialCount: number;
  unknownCount: number;
  score: number; // 0-100
  mappings: ComplianceMapping[];
  generatedAt: string;
}

// ── OWASP Top 10 (2021) ──

const OWASP_CONTROLS: ComplianceControl[] = [
  { id: "A01", title: "Broken Access Control", description: "Restrictions on authenticated users are not properly enforced.", framework: "owasp" },
  { id: "A02", title: "Cryptographic Failures", description: "Failures related to cryptography which often lead to sensitive data exposure.", framework: "owasp" },
  { id: "A03", title: "Injection", description: "User-supplied data is not validated, filtered, or sanitized by the application.", framework: "owasp" },
  { id: "A04", title: "Insecure Design", description: "Missing or ineffective control design.", framework: "owasp" },
  { id: "A05", title: "Security Misconfiguration", description: "Missing appropriate security hardening across any part of the application stack.", framework: "owasp" },
  { id: "A06", title: "Vulnerable and Outdated Components", description: "Using components with known vulnerabilities.", framework: "owasp" },
  { id: "A07", title: "Identification and Authentication Failures", description: "Confirmation of identity, authentication, and session management weaknesses.", framework: "owasp" },
  { id: "A08", title: "Software and Data Integrity Failures", description: "Code and infrastructure that does not protect against integrity violations.", framework: "owasp" },
  { id: "A09", title: "Security Logging and Monitoring Failures", description: "Insufficient logging, detection, monitoring, and active response.", framework: "owasp" },
  { id: "A10", title: "Server-Side Request Forgery", description: "Web application fetches a remote resource without validating the user-supplied URL.", framework: "owasp" },
];

// ── CIS Controls v8 (top-level) ──

const CIS_CONTROLS: ComplianceControl[] = [
  { id: "CIS-01", title: "Inventory and Control of Enterprise Assets", description: "Actively manage all enterprise assets connected to the infrastructure.", framework: "cis" },
  { id: "CIS-02", title: "Inventory and Control of Software Assets", description: "Actively manage all software on the network.", framework: "cis" },
  { id: "CIS-03", title: "Data Protection", description: "Develop processes and technical controls to identify, classify, and protect data.", framework: "cis" },
  { id: "CIS-04", title: "Secure Configuration of Enterprise Assets", description: "Establish and maintain secure configuration of enterprise assets.", framework: "cis" },
  { id: "CIS-05", title: "Account Management", description: "Use processes and tools to assign and manage credentials.", framework: "cis" },
  { id: "CIS-06", title: "Access Control Management", description: "Use processes and tools to create, assign, manage, and revoke access credentials.", framework: "cis" },
  { id: "CIS-07", title: "Continuous Vulnerability Management", description: "Continuously assess and remediate vulnerabilities.", framework: "cis" },
  { id: "CIS-08", title: "Audit Log Management", description: "Collect, alert, review, and retain audit logs.", framework: "cis" },
  { id: "CIS-09", title: "Email and Web Browser Protections", description: "Improve protections and detections of threats from email and web vectors.", framework: "cis" },
  { id: "CIS-10", title: "Malware Defenses", description: "Prevent or control the installation and execution of malicious applications.", framework: "cis" },
  { id: "CIS-11", title: "Data Recovery", description: "Establish and maintain data recovery practices.", framework: "cis" },
  { id: "CIS-12", title: "Network Infrastructure Management", description: "Establish and maintain the management and security of network infrastructure.", framework: "cis" },
  { id: "CIS-13", title: "Network Monitoring and Defense", description: "Operate processes and tools to establish and maintain comprehensive network monitoring.", framework: "cis" },
  { id: "CIS-14", title: "Security Awareness and Skills Training", description: "Establish and maintain a security awareness program.", framework: "cis" },
  { id: "CIS-15", title: "Service Provider Management", description: "Develop and maintain a process to evaluate service providers.", framework: "cis" },
  { id: "CIS-16", title: "Application Software Security", description: "Manage the security life cycle of in-house developed, hosted, or acquired software.", framework: "cis" },
  { id: "CIS-17", title: "Incident Response Management", description: "Establish a program to develop and maintain an incident response capability.", framework: "cis" },
  { id: "CIS-18", title: "Penetration Testing", description: "Test the effectiveness and resiliency of enterprise assets.", framework: "cis" },
];

// ── NIST CSF 2.0 Categories ──

const NIST_CONTROLS: ComplianceControl[] = [
  { id: "GV", title: "Govern", description: "Organizational cybersecurity risk management strategy, expectations, and policy.", framework: "nist" },
  { id: "ID.AM", title: "Asset Management", description: "The data, personnel, devices, systems, and facilities are identified and managed.", framework: "nist" },
  { id: "ID.RA", title: "Risk Assessment", description: "The organization understands the cybersecurity risk to operations, assets, and individuals.", framework: "nist" },
  { id: "PR.AA", title: "Identity Management and Access Control", description: "Access to assets and facilities is limited to authorized users, processes, and devices.", framework: "nist" },
  { id: "PR.DS", title: "Data Security", description: "Information and records are managed consistent with the organization's risk strategy.", framework: "nist" },
  { id: "PR.PS", title: "Platform Security", description: "The hardware, software, and services of physical and virtual platforms are managed.", framework: "nist" },
  { id: "PR.IR", title: "Technology Infrastructure Resilience", description: "Security architectures are managed to protect asset confidentiality, integrity, and availability.", framework: "nist" },
  { id: "DE.CM", title: "Continuous Monitoring", description: "Assets are monitored to find anomalies, indicators of compromise, and other potentially adverse events.", framework: "nist" },
  { id: "DE.AE", title: "Adverse Event Analysis", description: "Anomalies, indicators of compromise, and other potentially adverse events are analyzed.", framework: "nist" },
  { id: "RS.MA", title: "Incident Management", description: "Responses to detected cybersecurity incidents are managed.", framework: "nist" },
  { id: "RS.MI", title: "Incident Mitigation", description: "Activities are performed to prevent expansion of an event and mitigate its effects.", framework: "nist" },
  { id: "RC.RP", title: "Incident Recovery Plan Execution", description: "Restoration activities are performed to ensure operational availability.", framework: "nist" },
];

// ── Category-to-Control Mapping ──

type FrameworkKey = "owasp" | "cis" | "nist";

const CATEGORY_MAP: Record<string, Record<FrameworkKey, string[]>> = {
  subdomain_takeover: {
    owasp: ["A05"],
    cis: ["CIS-01", "CIS-12"],
    nist: ["ID.AM", "PR.PS"],
  },
  ssl_issue: {
    owasp: ["A02"],
    cis: ["CIS-03", "CIS-12"],
    nist: ["PR.DS", "PR.PS"],
  },
  security_headers: {
    owasp: ["A05"],
    cis: ["CIS-04", "CIS-16"],
    nist: ["PR.PS"],
  },
  threat_intelligence: {
    owasp: ["A09"],
    cis: ["CIS-13"],
    nist: ["DE.CM", "DE.AE"],
  },
  dns_misconfiguration: {
    owasp: ["A05"],
    cis: ["CIS-04", "CIS-09", "CIS-12"],
    nist: ["PR.PS", "PR.IR"],
  },
  exposed_credentials: {
    owasp: ["A02", "A07"],
    cis: ["CIS-03", "CIS-05"],
    nist: ["PR.AA", "PR.DS"],
  },
  exposed_infrastructure: {
    owasp: ["A05"],
    cis: ["CIS-04", "CIS-12"],
    nist: ["PR.PS"],
  },
  exposed_document: {
    owasp: ["A01", "A05"],
    cis: ["CIS-03"],
    nist: ["PR.DS"],
  },
  information_disclosure: {
    owasp: ["A05"],
    cis: ["CIS-04"],
    nist: ["PR.PS"],
  },
  api_exposure: {
    owasp: ["A01", "A04", "A05"],
    cis: ["CIS-04", "CIS-06", "CIS-16"],
    nist: ["PR.AA", "PR.PS"],
  },
  secret_exposure: {
    owasp: ["A02", "A07"],
    cis: ["CIS-03", "CIS-05"],
    nist: ["PR.DS", "PR.AA"],
  },
  open_port: {
    owasp: ["A05"],
    cis: ["CIS-04", "CIS-12"],
    nist: ["PR.PS", "DE.CM"],
  },
  nuclei_finding: {
    owasp: ["A06"],
    cis: ["CIS-07", "CIS-16"],
    nist: ["ID.RA", "PR.PS"],
  },
  data_breach: {
    owasp: ["A02"],
    cis: ["CIS-03"],
    nist: ["PR.DS", "RS.MI"],
  },
  email_security: {
    owasp: ["A05"],
    cis: ["CIS-09"],
    nist: ["PR.DS", "PR.IR"],
  },
  s3_exposure: {
    owasp: ["A01", "A05"],
    cis: ["CIS-03", "CIS-06"],
    nist: ["PR.AA", "PR.DS"],
  },
};

function getHighestSeverity(findings: Finding[]): ComplianceMapping["severity"] {
  const order: ComplianceMapping["severity"][] = ["critical", "high", "medium", "low", "info"];
  for (const s of order) {
    if (findings.some((f) => f.severity === s && f.status === "open")) return s;
  }
  return "info";
}

function mapFindingsToControls(
  findings: Finding[],
  controls: ComplianceControl[],
  framework: FrameworkKey,
): ComplianceMapping[] {
  return controls.map((control) => {
    const matchedFindings = findings.filter((f) => {
      const mapping = CATEGORY_MAP[f.category];
      if (!mapping) return false;
      return mapping[framework]?.includes(control.id) ?? false;
    });

    const openFindings = matchedFindings.filter((f) => f.status === "open");
    const resolvedFindings = matchedFindings.filter((f) => f.status === "resolved");

    let status: ComplianceMapping["status"];
    if (matchedFindings.length === 0) {
      status = "unknown"; // no data to assess
    } else if (openFindings.length === 0) {
      status = "pass"; // all findings resolved
    } else if (resolvedFindings.length > 0) {
      status = "partial"; // some resolved, some open
    } else {
      status = "fail"; // all open
    }

    return {
      control,
      findingIds: matchedFindings.map((f) => f.id),
      status,
      severity: matchedFindings.length > 0 ? getHighestSeverity(matchedFindings) : "info",
    };
  });
}

function computeScore(mappings: ComplianceMapping[]): number {
  const assessed = mappings.filter((m) => m.status !== "unknown");
  if (assessed.length === 0) return 0;
  const passing = assessed.filter((m) => m.status === "pass").length;
  const partial = assessed.filter((m) => m.status === "partial").length;
  return Math.round(((passing + partial * 0.5) / assessed.length) * 100);
}

export function generateComplianceReport(
  findings: Finding[],
  framework: FrameworkKey,
): ComplianceReport {
  const controlSets: Record<FrameworkKey, { controls: ComplianceControl[]; version: string; name: string }> = {
    owasp: { controls: OWASP_CONTROLS, version: "2021", name: "OWASP Top 10" },
    cis: { controls: CIS_CONTROLS, version: "v8", name: "CIS Controls" },
    nist: { controls: NIST_CONTROLS, version: "2.0", name: "NIST CSF" },
  };

  const { controls, version, name } = controlSets[framework];
  const mappings = mapFindingsToControls(findings, controls, framework);

  const passCount = mappings.filter((m) => m.status === "pass").length;
  const failCount = mappings.filter((m) => m.status === "fail").length;
  const partialCount = mappings.filter((m) => m.status === "partial").length;
  const unknownCount = mappings.filter((m) => m.status === "unknown").length;

  return {
    framework: name,
    frameworkVersion: version,
    totalControls: controls.length,
    passCount,
    failCount,
    partialCount,
    unknownCount,
    score: computeScore(mappings),
    mappings,
    generatedAt: new Date().toISOString(),
  };
}

export function generateAllComplianceReports(findings: Finding[]): Record<string, ComplianceReport> {
  return {
    owasp: generateComplianceReport(findings, "owasp"),
    cis: generateComplianceReport(findings, "cis"),
    nist: generateComplianceReport(findings, "nist"),
  };
}
