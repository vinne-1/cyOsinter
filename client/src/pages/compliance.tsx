import { useQuery } from "@tanstack/react-query";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { CheckCircle2, XCircle, AlertTriangle, HelpCircle, ShieldCheck, Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useDomain } from "@/lib/domain-context";
import type { Scan } from "@shared/schema";

function exportComplianceCSV(reports: Record<string, ComplianceReport>) {
  const esc = (v: string) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const headers = ["Framework", "Version", "Control ID", "Control Title", "Status", "Findings Count", "Description"];
  const rows: string[] = [];

  for (const report of Object.values(reports)) {
    for (const mapping of report.mappings) {
      rows.push([
        esc(report.framework),
        esc(report.frameworkVersion),
        esc(mapping.control.id),
        esc(mapping.control.title),
        esc(mapping.overallStatus ?? mapping.status),
        String(mapping.findingIds.length),
        esc(mapping.control.description),
      ].join(","));
    }
  }

  const csv = [headers.join(","), ...rows].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `compliance-report-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

interface ComplianceControl {
  id: string;
  title: string;
  description: string;
  framework: string;
}

interface ComplianceMapping {
  control: ComplianceControl;
  findingIds: string[];
  status: "pass" | "fail" | "partial" | "unknown";
  overallStatus?: "pass" | "fail" | "partial" | "unknown";
  passCount?: number;
  failCount?: number;
  partialCount?: number;
  requiresPolicy?: boolean;
  guidance?: string;
  severity: string;
}

interface ComplianceReport {
  framework: string;
  frameworkVersion: string;
  totalControls: number;
  assessedControls: number;
  hasAssessmentData: boolean;
  passCount: number;
  failCount: number;
  partialCount: number;
  unknownCount: number;
  score: number | null;
  mappings: ComplianceMapping[];
  generatedAt: string;
}

const statusConfig = {
  pass: { icon: CheckCircle2, color: "text-green-500", bg: "bg-green-500/10", label: "Pass" },
  fail: { icon: XCircle, color: "text-red-500", bg: "bg-red-500/10", label: "Fail" },
  partial: { icon: AlertTriangle, color: "text-yellow-500", bg: "bg-yellow-500/10", label: "Partial" },
  unknown: { icon: HelpCircle, color: "text-muted-foreground", bg: "bg-muted", label: "No Data" },
};

function ScoreRing({ score, label }: { score: number | null; label: string }) {
  if (score === null) {
    return (
      <div className="text-center">
        <div className="text-lg font-semibold text-muted-foreground">Not assessed</div>
        <p className="text-xs text-muted-foreground mt-1">{label}</p>
      </div>
    );
  }

  const color = score >= 80 ? "text-green-500" : score >= 60 ? "text-yellow-500" : score >= 40 ? "text-orange-500" : "text-red-500";
  return (
    <div className="text-center">
      <div className={`text-4xl font-bold ${color}`}>{score}</div>
      <p className="text-xs text-muted-foreground mt-1">{label}</p>
    </div>
  );
}

function FrameworkCard({ report }: { report: ComplianceReport }) {
  if (!report.hasAssessmentData) {
    return (
      <Card>
        <CardContent className="py-12 text-center">
          <ShieldCheck className="w-10 h-10 text-muted-foreground/40 mx-auto mb-3" />
          <p className="text-sm text-muted-foreground">No assessed controls for {report.framework}</p>
          <p className="text-xs text-muted-foreground mt-1">
            Run a scan to generate findings and compliance mappings
          </p>
        </CardContent>
      </Card>
    );
  }

  const scoreColor =
    report.score !== null && report.score >= 80 ? "text-green-500"
    : report.score !== null && report.score >= 60 ? "text-yellow-500"
    : report.score !== null && report.score >= 40 ? "text-orange-500"
    : "text-red-500";

  return (
    <div className="space-y-4">
      {/* Summary */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card>
          <CardContent className="p-3 text-center">
            <p className={`text-2xl font-bold ${scoreColor}`}>{report.score}%</p>
            <p className="text-[10px] text-muted-foreground">Compliance Score</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 text-center">
            <p className="text-2xl font-bold text-green-500">{report.passCount}</p>
            <p className="text-[10px] text-muted-foreground">Passing</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 text-center">
            <p className="text-2xl font-bold text-red-500">{report.failCount}</p>
            <p className="text-[10px] text-muted-foreground">Failing</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 text-center">
            <p className="text-2xl font-bold text-yellow-500">{report.partialCount}</p>
            <p className="text-[10px] text-muted-foreground">Partial</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 text-center">
            <p className="text-2xl font-bold text-muted-foreground">{report.unknownCount}</p>
            <p className="text-[10px] text-muted-foreground">No Data</p>
          </CardContent>
        </Card>
      </div>

      {/* Progress bar */}
      <div className="space-y-1">
        <div className="flex justify-between text-xs text-muted-foreground">
          <span>{report.framework} {report.frameworkVersion}</span>
          <span>{report.assessedControls}/{report.totalControls} assessed</span>
        </div>
        <Progress value={report.score ?? 0} className="h-2" />
      </div>

      {/* Controls list */}
      <div className="space-y-2">
        {report.mappings.map((mapping) => {
          const status = mapping.overallStatus ?? mapping.status;
          const config = statusConfig[status];
          const Icon = config.icon;
          return (
            <Card key={mapping.control.id} data-testid={`card-control-${mapping.control.id}`}>
              <CardContent className="p-3">
                <div className="flex items-start gap-3">
                  <div className={`flex items-center justify-center w-8 h-8 rounded-md flex-shrink-0 ${config.bg}`}>
                    <Icon className={`w-4 h-4 ${config.color}`} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-mono text-muted-foreground">{mapping.control.id}</span>
                      <p className="text-sm font-medium">{mapping.control.title}</p>
                      <Badge variant="outline" className={`text-[10px] ${config.color}`}>
                        {config.label}
                      </Badge>
                      {mapping.requiresPolicy ? (
                        <Badge variant="secondary" className="text-[10px]">Policy Required</Badge>
                      ) : null}
                      {mapping.findingIds.length > 0 && (
                        <span className="text-[10px] text-muted-foreground">
                          {mapping.findingIds.length} finding{mapping.findingIds.length > 1 ? "s" : ""}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground mt-0.5">{mapping.control.description}</p>
                    {mapping.guidance ? <p className="text-xs text-muted-foreground mt-1">Guidance: {mapping.guidance}</p> : null}
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

export default function Compliance() {
  const { selectedWorkspaceId } = useDomain();

  const { data: scans = [] } = useQuery<Scan[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/scans`],
    enabled: !!selectedWorkspaceId,
    refetchInterval: (query) => {
      const data = query.state.data as Scan[] | undefined;
      return data?.some((scan) => scan.status === "running" || scan.status === "pending") ? 2000 : false;
    },
  });

  const hasRunningScans = scans.some((scan) => scan.status === "running" || scan.status === "pending");

  const { data: reports, isLoading } = useQuery<Record<string, ComplianceReport>>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/compliance`],
    enabled: !!selectedWorkspaceId,
    refetchInterval: hasRunningScans ? 4000 : false,
  });

  if (isLoading) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-8 w-64" />
        <div className="grid grid-cols-3 gap-4">
          {Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-32" />)}
        </div>
        {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-16" />)}
      </div>
    );
  }

  const frameworkTabs = [
    { key: "owasp", label: "OWASP Top 10" },
    { key: "cis", label: "CIS Controls" },
    { key: "nist", label: "NIST CSF" },
    { key: "soc2", label: "SOC 2" },
    { key: "iso27001", label: "ISO 27001" },
    { key: "hipaa", label: "HIPAA" },
  ] as const;
  const hasAssessmentData = reports ? Object.values(reports).some((report) => report.hasAssessmentData) : false;

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight" data-testid="text-compliance-title">
            Compliance
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Map security findings to industry compliance frameworks
          </p>
        </div>
        {reports && hasAssessmentData && (
          <Button variant="outline" size="sm" onClick={() => exportComplianceCSV(reports)}>
            <Download className="w-4 h-4 mr-2" />
            Export CSV
          </Button>
        )}
      </div>

      {!reports || !selectedWorkspaceId ? (
        <Card>
          <CardContent className="py-12 text-center">
            <ShieldCheck className="w-10 h-10 text-muted-foreground/40 mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">No compliance data available</p>
            <p className="text-xs text-muted-foreground mt-1">
              Select a workspace to view compliance mappings
            </p>
          </CardContent>
        </Card>
      ) : !hasAssessmentData ? (
        <Card>
          <CardContent className="py-12 text-center">
            <ShieldCheck className="w-10 h-10 text-muted-foreground/40 mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">No compliance assessment yet</p>
            <p className="text-xs text-muted-foreground mt-1">
              {hasRunningScans
                ? "A scan is in progress. Compliance mappings will populate automatically as findings are processed."
                : "Run a scan to generate findings and compliance mappings"}
            </p>
          </CardContent>
        </Card>
      ) : (
        <>
          {/* Overview scores */}
          <div className="grid grid-cols-1 md:grid-cols-3 xl:grid-cols-6 gap-4">
            {frameworkTabs.map((tab) => {
              const report = reports?.[tab.key];
              if (!report) return null;
              return (
                <Card key={tab.key}>
                  <CardContent className="p-4 text-center">
                    <ScoreRing score={report.score} label={tab.label} />
                    <p className="text-[10px] text-muted-foreground mt-2">
                      {report.passCount}/{report.assessedControls} assessed controls passing
                    </p>
                  </CardContent>
                </Card>
              );
            })}
          </div>

          <Tabs defaultValue="owasp">
            <TabsList>
              {frameworkTabs.map((tab) => (
                <TabsTrigger key={tab.key} value={tab.key}>{tab.label}</TabsTrigger>
              ))}
            </TabsList>
            {frameworkTabs.map((tab) => {
              const report = reports?.[tab.key];
              if (!report) return null;
              return <TabsContent key={tab.key} value={tab.key}><FrameworkCard report={report} /></TabsContent>;
            })}
          </Tabs>
        </>
      )}
    </div>
  );
}
