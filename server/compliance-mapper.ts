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
  framework: "owasp" | "cis" | "nist" | "certin" | "dpdp";
  /**
   * False when an EXTERNAL scan structurally cannot assess this control —
   * consent records, grievance handling, retention practice. Such a control has
   * no findings by definition, and without this flag it renders as "No Data",
   * which a reader takes as "probably fine". Saying "not externally assessable"
   * is the honest answer and keeps the framework from claiming coverage it does
   * not have.
   */
  externallyAssessable?: boolean;
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

/**
 * CERT-In Directions 2022, Annexure I — the incident types that must be
 * reported to CERT-In **within six hours** of being noticed.
 *
 * This is not a hardening checklist like CIS. It is the list of things an
 * Indian body corporate is legally obliged to report, and the mapping answers a
 * question no other framework here does: *if this finding were exploited, which
 * reporting obligation would it trigger, and how much warning do I have?*
 *
 * The six-hour clock is the whole reason an external attack-surface monitor
 * matters in India — you cannot report what you never saw, and the Directions
 * explicitly list "targeted scanning" and "probing of critical networks" among
 * the reportable events. Applies to every body corporate regardless of size.
 */
const CERTIN_CONTROLS: ComplianceControl[] = [
  { id: "CERTIN-01", title: "Targeted scanning and probing", description: "Targeted scanning or probing of critical networks and systems — Annexure I(i).", framework: "certin", externallyAssessable: true },
  { id: "CERTIN-02", title: "Unauthorised access to systems or data", description: "Unauthorised access to IT systems or data — Annexure I(iii).", framework: "certin", externallyAssessable: true },
  { id: "CERTIN-03", title: "Website defacement or intrusion", description: "Defacement of a website, or intrusion and unauthorised changes such as inserting malicious code — Annexure I(iv).", framework: "certin", externallyAssessable: true },
  { id: "CERTIN-04", title: "Identity theft, spoofing and phishing", description: "Identity theft, spoofing and phishing attacks against the organisation or its customers — Annexure I(vi).", framework: "certin", externallyAssessable: true },
  { id: "CERTIN-05", title: "Data breach or data leak", description: "Data breach or data leak — Annexure I(xi)/(xii).", framework: "certin", externallyAssessable: true },
  { id: "CERTIN-06", title: "Attacks on servers and network devices", description: "Attacks on servers such as database, mail and DNS, and on network devices including routers — Annexure I(viii).", framework: "certin", externallyAssessable: true },
  { id: "CERTIN-07", title: "Attacks on applications", description: "Attacks on applications such as e-governance, e-commerce and web applications — Annexure I(ix).", framework: "certin", externallyAssessable: true },
  { id: "CERTIN-08", title: "Attacks on cloud and IoT systems", description: "Attacks or incidents affecting cloud computing systems and IoT devices — Annexure I(xv)/(xvi).", framework: "certin", externallyAssessable: true },
  { id: "CERTIN-09", title: "Malicious code and ransomware", description: "Malicious code attacks including ransomware — Annexure I(vii).", framework: "certin", externallyAssessable: true },
  { id: "CERTIN-10", title: "Supply chain compromise", description: "Attacks reaching the organisation through a third party or software supply chain — Annexure I(xix).", framework: "certin", externallyAssessable: true },
];

/**
 * Digital Personal Data Protection Act 2023, with the Rules notified in
 * November 2025.
 *
 * Only the technical-safeguard duties under s.8(4) and the breach-detection
 * half of s.8(5) are visible from outside. **Most of the DPDP Act is not** —
 * consent, purpose limitation, grievance redressal and erasure are process
 * obligations that no external scan can observe, and they are marked
 * `externallyAssessable: false` rather than left to render as "No Data".
 *
 * Shipping DPDP as though a surface scan could certify it would be exactly the
 * overclaim `compliance-guidance.ts` is deliberately left unwired to avoid.
 */
const DPDP_CONTROLS: ComplianceControl[] = [
  { id: "DPDP-8.4-TECH", title: "Reasonable security safeguards — technical", description: "s.8(4): technical measures to prevent a personal data breach. An external scan evidences the internet-facing half.", framework: "dpdp", externallyAssessable: true },
  { id: "DPDP-8.4-ACCESS", title: "Access control over personal data", description: "s.8(4): controls preventing unauthorised access to systems processing personal data.", framework: "dpdp", externallyAssessable: true },
  { id: "DPDP-8.4-CRYPTO", title: "Protection of data in transit", description: "s.8(4): encryption and transport protection for personal data in transit.", framework: "dpdp", externallyAssessable: true },
  { id: "DPDP-8.5-DETECT", title: "Breach detection readiness", description: "s.8(5): the detection capability that makes notification to the Board and Data Principals possible within the prescribed window.", framework: "dpdp", externallyAssessable: true },
  { id: "DPDP-8.7-RETAIN", title: "Storage limitation and erasure", description: "s.8(7): erasure once the purpose is served. A process obligation — not observable from outside.", framework: "dpdp", externallyAssessable: false },
  { id: "DPDP-6-CONSENT", title: "Consent and notice", description: "s.5-6: notice and consent records. A process obligation — not observable from outside.", framework: "dpdp", externallyAssessable: false },
  { id: "DPDP-13-GRIEV", title: "Grievance redressal", description: "s.13: a grievance mechanism for Data Principals. A process obligation — not observable from outside.", framework: "dpdp", externallyAssessable: false },
  { id: "DPDP-10-SDF", title: "Significant Data Fiduciary duties", description: "s.10: DPIA, independent audit and a resident Data Protection Officer. A process obligation — not observable from outside.", framework: "dpdp", externallyAssessable: false },
];

type FrameworkKey = "owasp" | "cis" | "nist" | "certin" | "dpdp";

/**
 * Finding category -> the controls it bears on, per framework.
 *
 * ## This map must cover every category the engine emits
 *
 * A category absent from here matches no control, so `mapFindingsToControls`
 * classes that control `unknown` and the UI renders **"No Data"** — which reads
 * as "not assessed" and invites the reader to assume the control passes. A live
 * workspace showed nine of ten OWASP controls as No Data while holding 31 open
 * findings, because 27 of them were `cookie_security` and the map had no such
 * key. Several other keys below the old set (`open_port`, `exposed_document`,
 * `s3_exposure`, `nuclei_finding`) named categories no detector has ever
 * emitted, so they matched nothing at all.
 *
 * `compliance-mapper.test.ts` asserts that every entry in
 * `SECURITY_CATEGORIES` appears here, so adding a detector category without a
 * mapping fails the build rather than silently blanking a control.
 *
 * Legacy keys are retained at the bottom: stored findings from earlier scans
 * still carry them, and dropping the keys would blank the history.
 */
const CATEGORY_MAP: Record<string, Record<FrameworkKey, string[]>> = {
  // ── Configuration and hardening ──
  security_headers: { owasp: ["A05"], cis: ["CIS-04", "CIS-16"], nist: ["PR.PS"], certin: ["CERTIN-07"], dpdp: ["DPDP-8.4-TECH"] },
  clickjacking: { owasp: ["A05"], cis: ["CIS-04", "CIS-16"], nist: ["PR.PS"], certin: ["CERTIN-07"], dpdp: ["DPDP-8.4-TECH"] },
  http_methods: { owasp: ["A05"], cis: ["CIS-04", "CIS-16"], nist: ["PR.PS"], certin: ["CERTIN-07"], dpdp: ["DPDP-8.4-TECH"] },
  dns_misconfiguration: { owasp: ["A05"], cis: ["CIS-04", "CIS-09", "CIS-12"], nist: ["PR.PS", "PR.IR"], certin: ["CERTIN-04"], dpdp: ["DPDP-8.4-TECH"] },
  email_security: { owasp: ["A05"], cis: ["CIS-09"], nist: ["PR.DS", "PR.IR"], certin: ["CERTIN-04"], dpdp: ["DPDP-8.4-TECH"] },
  // CAA governs which CAs may issue for the domain. Absent, anyone who can
  // fool any CA can obtain a valid certificate — a cryptographic-failure
  // (A02) and identity-management concern, not merely a misconfiguration.
  certificate_authority: { owasp: ["A02", "A05"], cis: ["CIS-09", "CIS-12"], nist: ["PR.DS", "PR.IR"], certin: ["CERTIN-04"], dpdp: ["DPDP-8.4-CRYPTO"] },
  waf_bypass: { owasp: ["A05"], cis: ["CIS-13"], nist: ["PR.IR", "DE.CM"], certin: ["CERTIN-01", "CERTIN-07"], dpdp: ["DPDP-8.4-TECH"] },
  // An application interface left enabled that need not be (XML-RPC and the
  // like): hardening, not a flaw in code.
  web_application: { owasp: ["A05"], cis: ["CIS-04", "CIS-16"], nist: ["PR.PS", "PR.IR"], certin: ["CERTIN-07"], dpdp: ["DPDP-8.4-TECH"] },

  // ── Session and access control ──
  // A cookie missing Secure/HttpOnly is both a misconfiguration and a session
  // management weakness, which is why it carries A05 and A07.
  cookie_security: { owasp: ["A05", "A07"], cis: ["CIS-04", "CIS-16"], nist: ["PR.AA", "PR.PS"], certin: ["CERTIN-02"], dpdp: ["DPDP-8.4-ACCESS"] },
  cors_misconfiguration: { owasp: ["A01", "A05"], cis: ["CIS-04", "CIS-16"], nist: ["PR.AA", "PR.PS"], certin: ["CERTIN-02", "CERTIN-07"], dpdp: ["DPDP-8.4-ACCESS"] },
  authentication: { owasp: ["A07"], cis: ["CIS-05", "CIS-06"], nist: ["PR.AA"], certin: ["CERTIN-02"], dpdp: ["DPDP-8.4-ACCESS"] },
  open_redirect: { owasp: ["A01"], cis: ["CIS-16"], nist: ["PR.PS"], certin: ["CERTIN-04"], dpdp: ["DPDP-8.4-TECH"] },

  // ── Cryptography and transport ──
  ssl_issue: { owasp: ["A02"], cis: ["CIS-03", "CIS-12"], nist: ["PR.DS", "PR.PS"], certin: ["CERTIN-06"], dpdp: ["DPDP-8.4-CRYPTO"] },
  transport_security: { owasp: ["A02"], cis: ["CIS-03", "CIS-12"], nist: ["PR.DS"], certin: ["CERTIN-06"], dpdp: ["DPDP-8.4-CRYPTO"] },

  // ── Injection and application flaws ──
  injection: { owasp: ["A03"], cis: ["CIS-16"], nist: ["PR.PS"], certin: ["CERTIN-07"], dpdp: ["DPDP-8.4-TECH"] },
  xss: { owasp: ["A03"], cis: ["CIS-16"], nist: ["PR.PS"], certin: ["CERTIN-07"], dpdp: ["DPDP-8.4-TECH"] },

  // ── Secrets and data exposure ──
  secret_exposure: { owasp: ["A02", "A07"], cis: ["CIS-03", "CIS-05"], nist: ["PR.DS", "PR.AA"], certin: ["CERTIN-05", "CERTIN-02"], dpdp: ["DPDP-8.5-DETECT", "DPDP-8.4-ACCESS"] },
  leaked_credential: { owasp: ["A02", "A07"], cis: ["CIS-03", "CIS-05"], nist: ["PR.AA", "PR.DS"], certin: ["CERTIN-05", "CERTIN-02"], dpdp: ["DPDP-8.5-DETECT"] },
  data_leak: { owasp: ["A01", "A02"], cis: ["CIS-03"], nist: ["PR.DS"], certin: ["CERTIN-05"], dpdp: ["DPDP-8.5-DETECT"] },
  information_disclosure: { owasp: ["A05"], cis: ["CIS-04"], nist: ["PR.PS"], certin: ["CERTIN-05"], dpdp: ["DPDP-8.4-TECH"] },
  infrastructure_disclosure: { owasp: ["A05"], cis: ["CIS-04", "CIS-12"], nist: ["PR.PS"], certin: ["CERTIN-01"], dpdp: ["DPDP-8.4-TECH"] },
  // Exposed employee identities and email formats are the raw material for
  // phishing, which is why this maps to security awareness rather than to a
  // technical hardening control.
  osint_exposure: { owasp: ["A05"], cis: ["CIS-14"], nist: ["ID.AM", "PR.AA"], certin: ["CERTIN-04"], dpdp: ["DPDP-8.4-TECH"] },

  // ── Attack surface and infrastructure ──
  subdomain_takeover: { owasp: ["A05"], cis: ["CIS-01", "CIS-12"], nist: ["ID.AM", "PR.PS"], certin: ["CERTIN-03", "CERTIN-02"], dpdp: ["DPDP-8.4-TECH"] },
  exposed_service: { owasp: ["A05"], cis: ["CIS-04", "CIS-12"], nist: ["PR.PS", "DE.CM"], certin: ["CERTIN-06", "CERTIN-01"], dpdp: ["DPDP-8.4-ACCESS"] },
  network_exposure: { owasp: ["A05"], cis: ["CIS-04", "CIS-12", "CIS-13"], nist: ["PR.IR", "DE.CM"], certin: ["CERTIN-06", "CERTIN-01"], dpdp: ["DPDP-8.4-ACCESS"] },
  cloud_exposure: { owasp: ["A01", "A05"], cis: ["CIS-03", "CIS-06"], nist: ["PR.AA", "PR.DS"], certin: ["CERTIN-08", "CERTIN-02"], dpdp: ["DPDP-8.4-ACCESS"] },
  container_exposure: { owasp: ["A05"], cis: ["CIS-04", "CIS-12"], nist: ["PR.PS", "PR.IR"], certin: ["CERTIN-08", "CERTIN-06"], dpdp: ["DPDP-8.4-ACCESS"] },
  api_exposure: { owasp: ["A01", "A04", "A05"], cis: ["CIS-04", "CIS-06", "CIS-16"], nist: ["PR.AA", "PR.PS"], certin: ["CERTIN-07", "CERTIN-02"], dpdp: ["DPDP-8.4-ACCESS"] },

  // ── Components and supply chain ──
  vulnerability: { owasp: ["A06"], cis: ["CIS-07", "CIS-16"], nist: ["ID.RA", "PR.PS"], certin: ["CERTIN-07", "CERTIN-06"], dpdp: ["DPDP-8.4-TECH"] },
  outdated_software: { owasp: ["A06"], cis: ["CIS-02", "CIS-07"], nist: ["ID.RA", "PR.PS"], certin: ["CERTIN-07", "CERTIN-10"], dpdp: ["DPDP-8.4-TECH"] },
  supply_chain: { owasp: ["A08"], cis: ["CIS-02", "CIS-15", "CIS-16"], nist: ["ID.AM", "PR.PS"], certin: ["CERTIN-10"], dpdp: ["DPDP-8.4-TECH"] },

  // ── Monitoring ──
  threat_intelligence: { owasp: ["A09"], cis: ["CIS-13"], nist: ["DE.CM", "DE.AE"], certin: ["CERTIN-09"], dpdp: ["DPDP-8.5-DETECT"] },
  // Brand abuse — lookalike domains, apps published under your name. There is no
  // honest OWASP Top 10 control for it: the Top 10 describes flaws in YOUR
  // application, and an attacker registering your brand elsewhere is not one.
  // It maps to identification and detection instead, which is what it actually
  // is. Inventing an application-security control to fill the OWASP column would
  // be the "No Data reads as a pass" problem in reverse — a made-up pass.
  brand_threat: { owasp: [], cis: ["CIS-13"], nist: ["ID.RA", "DE.CM"], certin: ["CERTIN-04"], dpdp: [] },
  // Dark web mentions and credential dumps — the external confirmation that
  // data has been exfiltrated. Maps to detection and response, not to a
  // preventive control, because the data is already outside the perimeter.
  dark_web: { owasp: ["A09"], cis: ["CIS-13"], nist: ["DE.CM", "DE.AE", "RS.AN"], certin: ["CERTIN-05"], dpdp: ["DPDP-8.5-DETECT"] },

  // ── Legacy keys ──
  // Categories used by earlier scans and still present on stored findings.
  // Dropping them would blank historical compliance history.
  exposed_credentials: { owasp: ["A02", "A07"], cis: ["CIS-03", "CIS-05"], nist: ["PR.AA", "PR.DS"], certin: ["CERTIN-05", "CERTIN-02"], dpdp: ["DPDP-8.5-DETECT"] },
  exposed_infrastructure: { owasp: ["A05"], cis: ["CIS-04", "CIS-12"], nist: ["PR.PS"], certin: ["CERTIN-01"], dpdp: ["DPDP-8.4-TECH"] },
  exposed_document: { owasp: ["A01", "A05"], cis: ["CIS-03"], nist: ["PR.DS"], certin: ["CERTIN-05"], dpdp: ["DPDP-8.5-DETECT"] },
  open_port: { owasp: ["A05"], cis: ["CIS-04", "CIS-12"], nist: ["PR.PS", "DE.CM"], certin: ["CERTIN-06", "CERTIN-01"], dpdp: ["DPDP-8.4-ACCESS"] },
  nuclei_finding: { owasp: ["A06"], cis: ["CIS-07", "CIS-16"], nist: ["ID.RA", "PR.PS"], certin: ["CERTIN-07"], dpdp: ["DPDP-8.4-TECH"] },
  data_breach: { owasp: ["A02"], cis: ["CIS-03"], nist: ["PR.DS", "RS.MI"], certin: ["CERTIN-05"], dpdp: ["DPDP-8.5-DETECT"] },
  s3_exposure: { owasp: ["A01", "A05"], cis: ["CIS-03", "CIS-06"], nist: ["PR.AA", "PR.DS"], certin: ["CERTIN-08", "CERTIN-02"], dpdp: ["DPDP-8.4-ACCESS"] },
};

/** Exposed so the coverage test can assert the vocabulary is fully mapped. */
export const MAPPED_CATEGORIES: readonly string[] = Object.keys(CATEGORY_MAP);

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
    certin: { controls: CERTIN_CONTROLS, version: "Directions 2022", name: "CERT-In Directions (6-hour reporting)" },
    dpdp: { controls: DPDP_CONTROLS, version: "Act 2023 / Rules 2025", name: "DPDP Act (technical safeguards)" },
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
    certin: generateComplianceReport(findings, "certin"),
    dpdp: generateComplianceReport(findings, "dpdp"),
  };
}
