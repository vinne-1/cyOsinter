import type { ReconModule } from "@shared/schema";

export function deriveTlsGradeForOverview(d: Record<string, unknown> | undefined): string {
  if (!d) return "N/A";
  const grade = (d.tlsPosture as { grade?: string } | undefined)?.grade;
  if (grade) return grade;
  const ssl = d.ssl as { daysRemaining?: number; protocol?: string } | undefined;
  if (!ssl || ssl.daysRemaining == null) return "N/A";
  if (ssl.daysRemaining <= 0) return "F";
  const proto = (ssl.protocol || "").toLowerCase();
  if ((proto === "tlsv1.2" || proto === "tlsv1.3") && ssl.daysRemaining > 30) return "A";
  if (proto === "tlsv1.2" || proto === "tlsv1.3") return "B";
  return "C";
}

export function deriveCloudGradeForOverview(d: Record<string, unknown> | undefined): string {
  if (!d) return "N/A";
  const grades = d.grades as { overall?: string; spf?: string; dmarc?: string } | undefined;
  if (grades?.overall) return grades.overall;
  const email = d.emailSecurity as Record<string, { found?: boolean; record?: string; issues?: string[]; status?: string }> | undefined;
  const spf = email?.spf;
  const dmarc = email?.dmarc;
  const spfGrade = spf?.found ? ((spf.issues?.length ?? 0) === 0 ? "A" : "B") : "F";
  const dmarcGrade = dmarc?.found ? ((dmarc.issues?.length ?? 0) === 0 ? "A" : "C") : "F";
  const n = ({ A: 4, B: 3, C: 2, D: 1, F: 0 }[spfGrade] ?? 0) + ({ A: 4, B: 3, C: 2, D: 1, F: 0 }[dmarcGrade] ?? 0);
  const overall = n >= 7 ? "A" : n >= 5 ? "B" : n >= 3 ? "C" : n >= 1 ? "D" : "F";
  return overall;
}

export const SEVERITY_SLICES = [
  { key: "critical", label: "Critical", color: "#ef4444" },
  { key: "high",     label: "High",     color: "#f97316" },
  { key: "medium",   label: "Medium",   color: "#eab308" },
  { key: "low",      label: "Low",      color: "#3b82f6" },
  { key: "info",     label: "Info",     color: "#64748b" },
] as const;

export interface ContinuousMonitoringStatus {
  running: boolean;
  iteration: number;
  progressPercent: number;
  progressMessage: string;
  currentStep: string;
}

export const scanTypes = [
  { id: "full", label: "Full Scan (EASM + OSINT)", description: "Complete scan: subdomains, attack surface, email security, exposed content, and all recon modules" },
  { id: "easm", label: "Attack Surface (EASM)", description: "Discover subdomains, services, certificates, and exposed infrastructure" },
  { id: "osint", label: "OSINT Discovery", description: "Find leaked credentials, exposed documents, and public mentions" },
];
