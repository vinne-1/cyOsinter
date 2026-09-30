import { useQuery, useMutation } from "@tanstack/react-query";
import { useState, useId, useMemo } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { CheckCircle2, XCircle, AlertTriangle, HelpCircle, ShieldCheck, Download, ChevronRight, Sparkles, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useDomain } from "@/lib/domain-context";
import { FindingDrilldown, type DrilldownFinding } from "@/components/finding-drilldown";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { Finding } from "@shared/schema";

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

/**
 * One compliance control, openable to the findings that decided its status.
 *
 * The mapping has always carried `findingIds` and the page has always rendered
 * only their COUNT — so "Security Misconfiguration · Fail · 14 findings" told a
 * reader that fourteen things were wrong and gave them no way to learn which
 * fourteen without going to the inbox and guessing at categories. The ids were
 * right there.
 */
function ControlRow({
  mapping,
  findingById,
}: {
  mapping: ComplianceMapping;
  findingById: Map<string, DrilldownFinding>;
}) {
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const config = statusConfig[mapping.status];
  const Icon = config.icon;

  // Resolve ids to findings. An id with no match is dropped rather than shown as
  // a placeholder: it means the finding was deleted or filtered since the report
  // was generated, and inventing a row for it would assert something we cannot
  // show.
  const resolved = mapping.findingIds
    .map((id) => findingById.get(id))
    .filter((f): f is DrilldownFinding => !!f);

  const expandable = resolved.length > 0;

  return (
    <Card data-testid={`card-control-${mapping.control.id}`}>
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
              {expandable && (
                <button
                  type="button"
                  onClick={() => setOpen((v) => !v)}
                  aria-expanded={open}
                  aria-controls={panelId}
                  className="flex items-center gap-0.5 text-[10px] text-muted-foreground underline-offset-2 hover:underline"
                  data-testid={`control-toggle-${mapping.control.id}`}
                >
                  <ChevronRight
                    className={`h-3 w-3 transition-transform ${open ? "rotate-90" : ""}`}
                    aria-hidden="true"
                  />
                  {resolved.length} finding{resolved.length > 1 ? "s" : ""}
                </button>
              )}
              {/* Ids that resolved to nothing are still counted, so the number
                  never silently shrinks below what the report recorded. */}
              {!expandable && mapping.findingIds.length > 0 && (
                <span className="text-[10px] text-muted-foreground">
                  {mapping.findingIds.length} finding{mapping.findingIds.length > 1 ? "s" : ""}
                </span>
              )}
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">{mapping.control.description}</p>
            {expandable && open && (
              <div id={panelId} className="mt-2 border-l-2 border-border pl-3">
                <FindingDrilldown findings={resolved} />
              </div>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

interface ComplianceNarrative {
  summary: string;
  topGaps: string[];
}

/**
 * The narrative explains and prioritizes gaps the mapper already computed —
 * it never re-grades a control. Ephemeral (not persisted): the report itself
 * is cheap to recompute from current findings, so there is no stable row to
 * cache the narrative against, same reasoning as the attack-path explanation.
 */
function AiComplianceSummary({ workspaceId, frameworkKey }: { workspaceId: string; frameworkKey: string }) {
  const { toast } = useToast();
  const [narrative, setNarrative] = useState<ComplianceNarrative | null>(null);

  const explainMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest(
        "POST",
        `/api/workspaces/${workspaceId}/compliance/${frameworkKey}/explain`,
        undefined,
        { timeoutMs: 120000 },
      );
      return res.json() as Promise<ComplianceNarrative>;
    },
    onSuccess: (data) => setNarrative(data),
    onError: (err: Error) => {
      toast({ title: "AI explanation failed", description: err.message, variant: "destructive" });
    },
  });

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">AI Summary</p>
        <Button
          variant="outline"
          size="sm"
          onClick={() => explainMutation.mutate()}
          disabled={explainMutation.isPending}
          data-testid={`button-explain-compliance-${frameworkKey}`}
        >
          {explainMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
          {explainMutation.isPending ? "Asking GLM..." : narrative ? "Re-explain" : "Explain with AI"}
        </Button>
      </div>
      {narrative && (
        <div className="rounded-lg border bg-muted/30 p-3 space-y-2" data-testid={`text-compliance-narrative-${frameworkKey}`}>
          <p className="text-sm leading-relaxed">{narrative.summary}</p>
          {narrative.topGaps.length > 0 && (
            <ul className="space-y-1">
              {narrative.topGaps.map((gap, i) => (
                <li key={i} className="flex items-start gap-2 text-xs">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-500 flex-shrink-0 mt-0.5" />
                  {gap}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

function FrameworkCard({
  report,
  findingById,
  workspaceId,
  frameworkKey,
}: {
  report: ComplianceReport;
  findingById: Map<string, DrilldownFinding>;
  workspaceId: string;
  frameworkKey: string;
}) {
  const scoreColor = report.score >= 80 ? "text-green-500" : report.score >= 60 ? "text-yellow-500" : report.score >= 40 ? "text-orange-500" : "text-red-500";

  return (
    <div className="space-y-4">
      <AiComplianceSummary workspaceId={workspaceId} frameworkKey={frameworkKey} />
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
        <Progress
          value={report.score}
          className="h-2"
          aria-label={`Compliance score: ${report.score} out of 100`}
        />
      </div>

      {/* Controls list */}
      <div className="space-y-2">
        {report.mappings.map((mapping) => {
          const config = statusConfig[mapping.status];
          const Icon = config.icon;
          return (
            <ControlRow
              key={mapping.control.id}
              mapping={mapping}
              findingById={findingById}
            />
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

  // The mappings carry finding IDs; the titles live on the findings themselves.
  // Fetched here rather than joined server-side so the compliance endpoint stays
  // a mapping and does not duplicate the finding payload per control — a
  // finding cited by four controls would otherwise be sent four times.
  const { data: findings = [] } = useQuery<Finding[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/findings`],
    enabled: !!selectedWorkspaceId,
  });

  const findingById = useMemo(() => {
    const m = new Map<string, DrilldownFinding>();
    for (const f of findings) {
      m.set(f.id, {
        id: f.id,
        title: f.title,
        severity: f.severity,
        status: f.status,
        affectedAsset: f.affectedAsset,
        category: f.category,
      });
    }
    return m;
  }, [findings]);

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
  // India-specific frameworks. CERT-In is the six-hour reporting obligation
  // every Indian body corporate carries; DPDP covers the technical safeguards
  // an external scan can actually evidence.
  const certin = reports?.certin;
  const dpdp = reports?.dpdp;

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
            {certin && (
              <Card>
                <CardContent className="p-4 text-center">
                  <ScoreRing score={certin.score} label="CERT-In" />
                  <p className="text-[10px] text-muted-foreground mt-2">
                    {certin.failCount}/{certin.totalControls} incident types implicated
                  </p>
                </CardContent>
              </Card>
            )}
            {dpdp && (
              <Card>
                <CardContent className="p-4 text-center">
                  <ScoreRing score={dpdp.score} label="DPDP Act" />
                  <p className="text-[10px] text-muted-foreground mt-2">
                    {dpdp.passCount}/{dpdp.totalControls} controls passing
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
              <TabsTrigger value="certin">CERT-In</TabsTrigger>
              <TabsTrigger value="dpdp">DPDP Act</TabsTrigger>
            </TabsList>
            {owasp && <TabsContent value="owasp"><FrameworkCard report={owasp} findingById={findingById} workspaceId={selectedWorkspaceId!} frameworkKey="owasp" /></TabsContent>}
            {cis && <TabsContent value="cis"><FrameworkCard report={cis} findingById={findingById} workspaceId={selectedWorkspaceId!} frameworkKey="cis" /></TabsContent>}
            {nist && <TabsContent value="nist"><FrameworkCard report={nist} findingById={findingById} workspaceId={selectedWorkspaceId!} frameworkKey="nist" /></TabsContent>}
            {certin && (
              <TabsContent value="certin">
                <p className="mb-3 text-xs text-muted-foreground">
                  The CERT-In Directions 2022 require an Indian body corporate to report a listed incident within
                  <strong> six hours</strong> of noticing it. These are the incident types your current external
                  exposure relates to — early warning, not a statement that an incident has occurred.
                </p>
                <FrameworkCard report={certin} findingById={findingById} workspaceId={selectedWorkspaceId!} frameworkKey="certin" />
              </TabsContent>
            )}
            {dpdp && (
              <TabsContent value="dpdp">
                <p className="mb-3 text-xs text-muted-foreground">
                  Only the technical safeguards under s.8(4) and breach-detection readiness under s.8(5) are visible
                  from outside. Consent, grievance handling, retention and Significant Data Fiduciary duties are
                  process obligations marked <strong>not externally assessable</strong> — an external scan cannot
                  certify them, and showing them blank would read as a pass.
                </p>
                <FrameworkCard report={dpdp} findingById={findingById} workspaceId={selectedWorkspaceId!} frameworkKey="dpdp" />
              </TabsContent>
            )}
          </Tabs>
        </>
      )}
    </div>
  );
}
