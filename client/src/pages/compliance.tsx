import { useQuery } from "@tanstack/react-query";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { CheckCircle2, XCircle, AlertTriangle, HelpCircle, ShieldCheck, Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useDomain } from "@/lib/domain-context";

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
        esc(mapping.status),
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
  severity: string;
}

interface ComplianceReport {
  framework: string;
  frameworkVersion: string;
  totalControls: number;
  passCount: number;
  failCount: number;
  partialCount: number;
  unknownCount: number;
  score: number;
  mappings: ComplianceMapping[];
  generatedAt: string;
}

const statusConfig = {
  pass: { icon: CheckCircle2, color: "text-green-500", bg: "bg-green-500/10", label: "Pass" },
  fail: { icon: XCircle, color: "text-red-500", bg: "bg-red-500/10", label: "Fail" },
  partial: { icon: AlertTriangle, color: "text-yellow-500", bg: "bg-yellow-500/10", label: "Partial" },
  unknown: { icon: HelpCircle, color: "text-muted-foreground", bg: "bg-muted", label: "No Data" },
};

function ScoreRing({ score, label }: { score: number; label: string }) {
  const color = score >= 80 ? "text-green-500" : score >= 60 ? "text-yellow-500" : score >= 40 ? "text-orange-500" : "text-red-500";
  return (
    <div className="text-center">
      <div className={`text-4xl font-bold ${color}`}>{score}</div>
      <p className="text-xs text-muted-foreground mt-1">{label}</p>
    </div>
  );
}

function FrameworkCard({ report }: { report: ComplianceReport }) {
  const scoreColor = report.score >= 80 ? "text-green-500" : report.score >= 60 ? "text-yellow-500" : report.score >= 40 ? "text-orange-500" : "text-red-500";

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
          <span>{report.totalControls} controls</span>
        </div>
        <Progress value={report.score} className="h-2" />
      </div>

      {/* Controls list */}
      <div className="space-y-2">
        {report.mappings.map((mapping) => {
          const config = statusConfig[mapping.status];
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
                      {mapping.findingIds.length > 0 && (
                        <span className="text-[10px] text-muted-foreground">
                          {mapping.findingIds.length} finding{mapping.findingIds.length > 1 ? "s" : ""}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground mt-0.5">{mapping.control.description}</p>
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

  const { data: reports, isLoading } = useQuery<Record<string, ComplianceReport>>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/compliance`],
    enabled: !!selectedWorkspaceId,
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

  const owasp = reports?.owasp;
  const cis = reports?.cis;
  const nist = reports?.nist;

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
        {reports && (
          <Button variant="outline" size="sm" onClick={() => exportComplianceCSV(reports)}>
            <Download className="w-4 h-4 mr-2" />
            Export CSV
          </Button>
        )}
      </div>

      {!reports ? (
        <Card>
          <CardContent className="py-12 text-center">
            <ShieldCheck className="w-10 h-10 text-muted-foreground/40 mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">No compliance data available</p>
            <p className="text-xs text-muted-foreground mt-1">
              Run a scan first to generate compliance mappings
            </p>
          </CardContent>
        </Card>
      ) : (
        <>
          {/* Overview scores */}
          <div className="grid grid-cols-3 gap-4">
            {owasp && (
              <Card>
                <CardContent className="p-4 text-center">
                  <ScoreRing score={owasp.score} label="OWASP Top 10" />
                  <p className="text-[10px] text-muted-foreground mt-2">
                    {owasp.passCount}/{owasp.totalControls} controls passing
                  </p>
                </CardContent>
              </Card>
            )}
            {cis && (
              <Card>
                <CardContent className="p-4 text-center">
                  <ScoreRing score={cis.score} label="CIS Controls v8" />
                  <p className="text-[10px] text-muted-foreground mt-2">
                    {cis.passCount}/{cis.totalControls} controls passing
                  </p>
                </CardContent>
              </Card>
            )}
            {nist && (
              <Card>
                <CardContent className="p-4 text-center">
                  <ScoreRing score={nist.score} label="NIST CSF 2.0" />
                  <p className="text-[10px] text-muted-foreground mt-2">
                    {nist.passCount}/{nist.totalControls} controls passing
                  </p>
                </CardContent>
              </Card>
            )}
          </div>

          <Tabs defaultValue="owasp">
            <TabsList>
              <TabsTrigger value="owasp">OWASP Top 10</TabsTrigger>
              <TabsTrigger value="cis">CIS Controls</TabsTrigger>
              <TabsTrigger value="nist">NIST CSF</TabsTrigger>
            </TabsList>
            {owasp && <TabsContent value="owasp"><FrameworkCard report={owasp} /></TabsContent>}
            {cis && <TabsContent value="cis"><FrameworkCard report={cis} /></TabsContent>}
            {nist && <TabsContent value="nist"><FrameworkCard report={nist} /></TabsContent>}
          </Tabs>
        </>
      )}
    </div>
  );
}
