import { useState, useEffect, useMemo } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Shield,
  AlertTriangle,
  Globe,
  Search,
  TrendingUp,
  Activity,
  ArrowUpRight,
  Brain,
  ShieldAlert,
  Lock,
  Mail,
  Code2,
  Users,
  Radar,
  Loader2,
  Play,
  CheckCircle2,
  Clock,
  Square,
  Radio,
} from "lucide-react";
import type { Finding, Asset, Scan, ReconModule, PostureSnapshot } from "@shared/schema";
import { computeSecurityScore } from "@shared/scoring";
import { SeverityBadge, StatusBadge } from "@/components/severity-badge";
import { DeleteScanButton } from "@/components/delete-scan-button";
import { Link } from "wouter";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";

function StatCard({
  title,
  value,
  icon: Icon,
  description,
  trend,
  testId,
}: {
  title: string;
  value: string | number;
  icon: React.ElementType;
  description: string;
  trend?: string;
  testId: string;
}) {
  return (
    <Card data-testid={testId}>
      <CardContent className="p-5">
        <div className="flex items-start justify-between gap-2">
          <div className="space-y-2">
            <p className="text-sm text-muted-foreground">{title}</p>
            <p className="text-2xl font-semibold tracking-tight" data-testid={`${testId}-value`}>
              {typeof value === "number" ? value.toLocaleString() : value}
            </p>
            <p className="text-xs text-muted-foreground">{description}</p>
          </div>
          <div className="flex items-center justify-center w-10 h-10 rounded-md bg-primary/10">
            <Icon className="w-5 h-5 text-primary" />
          </div>
        </div>
        {trend && (
          <div className="flex items-center gap-1 mt-3 text-xs text-green-500">
            <TrendingUp className="w-3 h-3" />
            <span>{trend}</span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function SeverityChart({ findings }: { findings: Finding[] }) {
  const counts = {
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
  };
  const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1;

  const bars = [
    { key: "critical", label: "Critical", color: "bg-red-500", count: counts.critical },
    { key: "high", label: "High", color: "bg-orange-500", count: counts.high },
    { key: "medium", label: "Medium", color: "bg-yellow-500", count: counts.medium },
    { key: "low", label: "Low", color: "bg-blue-500", count: counts.low },
    { key: "info", label: "Info", color: "bg-slate-500", count: counts.info },
  ];

  return (
    <Card data-testid="card-severity-chart">
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="text-sm font-medium">Severity Distribution</CardTitle>
        <AlertTriangle className="w-4 h-4 text-muted-foreground" />
      </CardHeader>
      <CardContent className="space-y-3">
        {bars.map((bar) => (
          <div key={bar.key} className="space-y-1">
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground">{bar.label}</span>
              <span className="font-mono font-medium">{bar.count}</span>
            </div>
            <div className="h-2 rounded-md bg-muted overflow-hidden">
              <div
                className={`bar-fill h-full rounded-md ${bar.color} transition-all duration-500`}
                data-value={String(Math.min(100, Math.round(((bar.count / total) * 100) / 5) * 5))}
              />
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

const SEVERITY_SLICES = [
  { key: "critical", label: "Critical", color: "#ef4444" },
  { key: "high",     label: "High",     color: "#f97316" },
  { key: "medium",   label: "Medium",   color: "#eab308" },
  { key: "low",      label: "Low",      color: "#3b82f6" },
  { key: "info",     label: "Info",     color: "#64748b" },
] as const;

function FindingsSummaryCard({ findings }: { findings: Finding[] }) {
  const sliceData = useMemo(() => {
    return SEVERITY_SLICES.map((s) => ({
      ...s,
      count: findings.filter((f) => f.severity === s.key).length,
    })).filter((s) => s.count > 0);
  }, [findings]);

  const total = sliceData.reduce((acc, s) => acc + s.count, 0);

  return (
    <Card data-testid="card-findings-summary">
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="text-sm font-medium">Findings by Severity</CardTitle>
        <AlertTriangle className="w-4 h-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        {total === 0 ? (
          <p className="text-sm text-muted-foreground py-8 text-center">No findings yet. Run a scan to discover vulnerabilities.</p>
        ) : (
          <div className="flex flex-col sm:flex-row items-center gap-6">
            <div className="flex-shrink-0">
              <ResponsiveContainer width={160} height={160}>
                <PieChart>
                  <Pie
                    data={sliceData}
                    cx="50%"
                    cy="50%"
                    innerRadius={48}
                    outerRadius={72}
                    dataKey="count"
                    startAngle={90}
                    endAngle={-270}
                    strokeWidth={2}
                  >
                    {sliceData.map((entry) => (
                      <Cell key={entry.key} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    content={({ active, payload }) => {
                      if (!active || !payload?.length) return null;
                      const p = payload[0]?.payload as typeof sliceData[number];
                      return (
                        <div className="rounded-lg border bg-background px-3 py-2 text-xs shadow-md">
                          <p className="font-medium">{p.label}</p>
                          <p className="text-muted-foreground">{p.count} finding{p.count !== 1 ? "s" : ""}</p>
                        </div>
                      );
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="flex flex-col gap-2 flex-1 min-w-0">
              {SEVERITY_SLICES.map((s) => {
                const count = sliceData.find((d) => d.key === s.key)?.count ?? 0;
                return (
                  <div key={s.key} className="flex items-center justify-between gap-3 text-xs">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ backgroundColor: s.color }} />
                      <span className="text-muted-foreground">{s.label}</span>
                    </div>
                    <span className="font-mono font-semibold tabular-nums">{count}</span>
                  </div>
                );
              })}
              <div className="border-t pt-2 mt-1 flex items-center justify-between text-xs">
                <span className="text-muted-foreground">Total</span>
                <span className="font-mono font-semibold tabular-nums">{total}</span>
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function RecentFindings({ findings }: { findings: Finding[] }) {
  const recent = findings.slice(0, 5);

  return (
    <Card data-testid="card-recent-findings">
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="text-sm font-medium">Recent Findings</CardTitle>
        <Link href="/findings">
          <Badge variant="outline" className="text-xs cursor-pointer" data-testid="link-view-all-findings">
            View All
            <ArrowUpRight className="w-3 h-3 ml-1" />
          </Badge>
        </Link>
      </CardHeader>
      <CardContent>
        {recent.length === 0 ? (
          <p className="text-sm text-muted-foreground py-8 text-center">No findings yet. Run a scan to discover vulnerabilities.</p>
        ) : (
          <div className="space-y-3">
            {recent.map((finding) => (
              <div
                key={finding.id}
                className="flex items-start justify-between gap-3 p-3 rounded-md bg-muted/40"
                data-testid={`finding-row-${finding.id}`}
              >
                <div className="space-y-1 min-w-0 flex-1">
                  <p className="text-sm font-medium truncate">{finding.title}</p>
                  <p className="text-xs text-muted-foreground truncate">{finding.affectedAsset}</p>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0 flex-wrap">
                  <SeverityBadge severity={finding.severity} />
                  <StatusBadge status={finding.status} />
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function deriveTlsGradeForOverview(d: Record<string, unknown> | undefined): string {
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

function deriveCloudGradeForOverview(d: Record<string, unknown> | undefined): string {
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

function IntelligenceOverview({ modules }: { modules: ReconModule[] }) {
  const modulesByType = modules.reduce((acc, mod) => {
    if (!(mod.moduleType in acc)) acc[mod.moduleType] = mod;
    return acc;
  }, {} as Record<string, ReconModule>);

  const attackSurface = modulesByType["attack_surface"]?.data as any;
  const cloud = modulesByType["cloud_footprint"]?.data as any;
  const webPresence = modulesByType["web_presence"]?.data as any;
  const people = modulesByType["linkedin_people"]?.data as any;
  const avgConfidence = modules.length > 0
    ? Math.round(modules.reduce((sum, m) => sum + (m.confidence || 0), 0) / modules.length)
    : 0;

  const tlsGrade = deriveTlsGradeForOverview(attackSurface);
  const cloudGrade = deriveCloudGradeForOverview(cloud);
  const totalSubdomains = webPresence?.totalSubdomains ?? webPresence?.totalSubdomainsEnumerated ?? 0;
  const assetInventory = (attackSurface?.assetInventory || []) as Array<{ riskScore: number; waf: string }>;
  const totalHosts = assetInventory.length || 0;
  const highRiskHosts = assetInventory.filter((a) => a.riskScore >= 60).length;
  const wafCoverage = totalHosts > 0 ? Math.round((assetInventory.filter((a) => a.waf).length / totalHosts) * 100) : 0;

  const highlights = [
    { icon: ShieldAlert, label: "Surface Risk", value: attackSurface?.surfaceRiskScore != null ? `${attackSurface.surfaceRiskScore}/100` : "N/A", color: attackSurface?.surfaceRiskScore >= 70 ? "text-red-400" : attackSurface?.surfaceRiskScore != null ? "text-yellow-400" : "text-muted-foreground" },
    { icon: Globe, label: "Hosts", value: totalHosts || totalSubdomains, color: "text-primary" },
    { icon: AlertTriangle, label: "High Risk", value: highRiskHosts, color: highRiskHosts > 0 ? "text-orange-400" : "text-muted-foreground" },
    { icon: Shield, label: "WAF Coverage", value: totalHosts > 0 ? `${wafCoverage}%` : "N/A", color: "text-primary" },
    { icon: Lock, label: "TLS Grade", value: tlsGrade, color: "text-green-400" },
    { icon: Mail, label: "Email Security", value: cloudGrade, color: "text-blue-400" },
    { icon: Users, label: "Employees", value: people?.totalEmployees ?? 0, color: "text-primary" },
    { icon: Brain, label: "Intel Modules", value: `${modules.length} (${avgConfidence}%)`, color: "text-primary" },
  ];

  return (
    <Card data-testid="card-intelligence-overview">
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="text-sm font-medium">Intelligence Overview</CardTitle>
        <Link href="/intelligence">
          <Badge variant="outline" className="text-xs cursor-pointer" data-testid="link-view-intelligence">
            Explore
            <ArrowUpRight className="w-3 h-3 ml-1" />
          </Badge>
        </Link>
      </CardHeader>
      <CardContent>
        {modules.length === 0 ? (
          <p className="text-sm text-muted-foreground py-8 text-center">No intelligence data yet. Run a scan to begin.</p>
        ) : (
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            {highlights.map((h) => (
              <div key={h.label} className="flex items-center gap-3 p-3 rounded-md bg-muted/40" data-testid={`intel-stat-${h.label.toLowerCase().replace(/\s/g, "-")}`}>
                <div className="flex items-center justify-center w-8 h-8 rounded-md bg-muted/60 flex-shrink-0">
                  <h.icon className={`w-4 h-4 ${h.color}`} />
                </div>
                <div>
                  <p className={`text-sm font-semibold ${h.color}`}>{h.value}</p>
                  <p className="text-xs text-muted-foreground">{h.label}</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function PostureHistoryCard({ workspaceId }: { workspaceId: string | null }) {
  const { toast } = useToast();
  const { data: snapshots = [], isLoading } = useQuery<PostureSnapshot[]>({
    queryKey: [`/api/workspaces/${workspaceId}/posture-history`],
    enabled: !!workspaceId,
  });

  const backfillMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/workspaces/${workspaceId}/posture-history/backfill`, {});
      return res as unknown as { created: number; snapshots: PostureSnapshot[] };
    },
    onSuccess: (data) => {
      queryClient.setQueryData([`/api/workspaces/${workspaceId}/posture-history`], data.snapshots);
      if (data.created > 0) {
        toast({ title: "Synced", description: `Created ${data.created} posture snapshot(s) from completed scans.` });
      }
    },
    onError: () => {
      toast({ title: "Sync failed", description: "Could not backfill posture history.", variant: "destructive" });
    },
  });

  const chartData = [...snapshots].reverse().map((s) => ({
    date: s.snapshotAt ? new Date(s.snapshotAt).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "2-digit" }) : "",
    surfaceRisk: s.surfaceRiskScore ?? null,
    securityScore: s.securityScore ?? null,
    target: s.target,
    scanId: s.scanId,
  }));

  if (!workspaceId) return null;

  return (
    <Card data-testid="card-posture-history">
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="text-sm font-medium">Posture History</CardTitle>
        <Link href="/reports">
          <Badge variant="outline" className="text-xs cursor-pointer" data-testid="link-view-reports">
            Reports
            <ArrowUpRight className="w-3 h-3 ml-1" />
          </Badge>
        </Link>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-48 w-full" />
        ) : snapshots.length === 0 ? (
          <div className="py-8 text-center space-y-3">
            <p className="text-sm text-muted-foreground">No posture history yet. Complete scans to track trends.</p>
            <Button
              variant="outline"
              size="sm"
              disabled={backfillMutation.isPending}
              onClick={() => backfillMutation.mutate()}
            >
              {backfillMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Activity className="w-4 h-4" />}
              {backfillMutation.isPending ? " Syncing…" : " Sync from completed scans"}
            </Button>
          </div>
        ) : (
          <>
            <div className="h-48 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={chartData} margin={{ top: 5, right: 5, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                  <XAxis dataKey="date" tick={{ fontSize: 10 }} />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 10 }} />
                  <Tooltip
                    content={({ active, payload }) => {
                      if (!active || !payload?.length) return null;
                      const p = payload[0]?.payload;
                      return (
                        <div className="rounded-lg border bg-background px-3 py-2 text-xs shadow-md">
                          <p className="font-medium">{p?.date}</p>
                          <p className="text-muted-foreground">{p?.target}</p>
                          {p?.surfaceRisk != null && <p>Surface Risk: {p.surfaceRisk}/100</p>}
                          {p?.securityScore != null && <p>Security Score: {p.securityScore}/100</p>}
                        </div>
                      );
                    }}
                  />
                  {chartData.some((d) => d.surfaceRisk != null) && (
                    <Line type="monotone" dataKey="surfaceRisk" stroke="#f87171" strokeWidth={2} dot={{ r: 3 }} name="Surface Risk" />
                  )}
                  {chartData.some((d) => d.securityScore != null) && (
                    <Line type="monotone" dataKey="securityScore" stroke="#22c55e" strokeWidth={2} dot={{ r: 3 }} name="Security Score" />
                  )}
                </LineChart>
              </ResponsiveContainer>
            </div>
            <div className="mt-3 space-y-2 max-h-32 overflow-y-auto">
              {snapshots.slice(0, 5).map((s) => (
                <div key={s.id} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/40 text-xs">
                  <Link href="/easm">
                    <span className="truncate cursor-pointer hover:underline text-primary">{s.target}</span>
                  </Link>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    {s.surfaceRiskScore != null && (
                      <Badge variant="outline" className="text-[10px] border-0 font-mono">
                        Risk {s.surfaceRiskScore}
                      </Badge>
                    )}
                    {s.securityScore != null && (
                      <Badge variant="outline" className="text-[10px] border-0 font-mono bg-green-600/15 text-green-400">
                        {s.securityScore}
                      </Badge>
                    )}
                    <Link href="/reports">
                      <span className="text-muted-foreground cursor-pointer hover:underline">
                        {s.snapshotAt ? new Date(s.snapshotAt).toLocaleDateString() : ""}
                      </span>
                    </Link>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

function RecentScans({ scans, workspaceId }: { scans: Scan[]; workspaceId: string | null }) {
  const recent = scans.slice(0, 4);

  return (
    <Card data-testid="card-recent-scans">
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="text-sm font-medium">Recent Scans</CardTitle>
        <Activity className="w-4 h-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        {recent.length === 0 ? (
          <p className="text-sm text-muted-foreground py-8 text-center">No scans yet. Start scanning your attack surface.</p>
        ) : (
          <div className="space-y-3">
            {recent.map((scan) => {
              const s = scan as Scan & { progressMessage?: string | null; progressPercent?: number | null; estimatedSecondsRemaining?: number | null };
              const isRunning = scan.status === "running" || scan.status === "pending";
              return (
                <div
                  key={scan.id}
                  className="flex flex-col gap-1 p-3 rounded-md bg-muted/40"
                  data-testid={`scan-row-${scan.id}`}
                >
                  <div className="flex items-center justify-between gap-3 min-w-0">
                    <div className="flex items-center gap-3 min-w-0 flex-1">
                      <div className={`w-2 h-2 rounded-full flex-shrink-0 ${
                        scan.status === "completed" ? "bg-green-500" :
                        scan.status === "running" ? "bg-blue-500 animate-pulse" :
                        scan.status === "failed" ? "bg-red-500" :
                        "bg-slate-500"
                      }`} />
                      <div className="min-w-0">
                        <p className="text-sm font-medium truncate">{scan.target}</p>
                        <p className="text-xs text-muted-foreground font-mono uppercase">{scan.type}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      {(scan as any).summary?.assetsDiscovered != null && (
                        <p className="text-sm font-mono">{(scan as any).summary.assetsDiscovered} assets</p>
                      )}
                      <p className="text-sm font-mono">{scan.findingsCount ?? 0} findings</p>
                      <p className="text-xs text-muted-foreground">
                        {scan.completedAt ? new Date(scan.completedAt).toLocaleDateString() : isRunning ? "In progress" : "Pending"}
                      </p>
                      {workspaceId && (
                        <DeleteScanButton scan={scan} workspaceId={workspaceId} />
                      )}
                    </div>
                  </div>
                  {isRunning && (s.progressMessage || (s.progressPercent ?? 0) > 0) && (
                    <div className="mt-2 space-y-1">
                      <Progress value={s.progressPercent ?? 0} className="h-1.5" />
                      <p className="text-xs text-muted-foreground truncate">{s.progressMessage}</p>
                      {s.estimatedSecondsRemaining != null && s.estimatedSecondsRemaining > 0 && (
                        <p className="text-xs text-muted-foreground flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          ~{Math.ceil(s.estimatedSecondsRemaining / 60)} min remaining
                        </p>
                      )}
                    </div>
                  )}
                  {scan.status === "failed" && (scan as any).errorMessage && (
                    <p className="text-xs text-red-400 mt-1" title={(scan as any).errorMessage}>
                      {(scan as any).errorMessage}
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

interface ContinuousMonitoringStatus {
  running: boolean;
  iteration: number;
  progressPercent: number;
  progressMessage: string;
  currentStep: string;
}

function ContinuousMonitoringCard({ workspaceId, onStop }: { workspaceId: string; onStop: () => void }) {
  const { toast } = useToast();
  const { data: status, isLoading } = useQuery<ContinuousMonitoringStatus>({
    queryKey: [`/api/continuous-monitoring/status/${workspaceId}`],
    enabled: !!workspaceId,
    refetchInterval: 2000,
  });

  const stopMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/continuous-monitoring/stop", { workspaceId });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/continuous-monitoring/status/${workspaceId}`] });
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceId}/scans`] });
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceId}/assets`] });
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceId}/findings`] });
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceId}/recon-modules`] });
      onStop();
    },
    onError: (err: Error) => {
      toast({ title: "Failed to stop monitoring", description: err.message, variant: "destructive" });
    },
  });

  if ((!status?.running && !isLoading) || (!status && !isLoading)) return null;

  return (
    <Card data-testid="card-continuous-monitoring" className="border-primary/30">
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <Radio className="w-4 h-4 text-primary animate-pulse" />
          Continuous Monitoring Active
        </CardTitle>
        <Button
          variant="destructive"
          size="sm"
          onClick={() => stopMutation.mutate()}
          disabled={stopMutation.isPending}
          data-testid="button-stop-continuous-monitoring"
        >
          <Square className="w-4 h-4 mr-1" />
          Stop
        </Button>
      </CardHeader>
      <CardContent className="space-y-3">
        <Progress value={status?.progressPercent ?? 0} className="h-2" data-testid="progress-continuous-monitoring" />
        <p className="text-sm text-muted-foreground">Iteration {status?.iteration ?? 0}</p>
        <p className="text-xs text-muted-foreground truncate">{status?.progressMessage ?? "Loading..."}</p>
      </CardContent>
    </Card>
  );
}

function StartContinuousMonitoringDialog({ workspaces, setSelectedWorkspace, onStarted }: {
  workspaces: { id: string; name: string; [key: string]: unknown }[];
  setSelectedWorkspace: (ws: { id: string; name: string; [key: string]: unknown } | null) => void;
  onStarted: (workspaceId: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [target, setTarget] = useState("");
  const { toast } = useToast();

  const mutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/continuous-monitoring/start", { target: target.trim() });
      return res.json();
    },
    onSuccess: (data: { workspaceId: string }) => {
      const ws = workspaces.find((w) => w.id === data.workspaceId);
      if (ws) setSelectedWorkspace(ws);
      onStarted(data.workspaceId);
      setOpen(false);
      setTarget("");
      toast({ title: "Continuous monitoring started", description: "Full scans will run every 5 minutes. Only new findings will be added." });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to start", description: error.message, variant: "destructive" });
    },
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" data-testid="button-start-continuous-monitoring">
          <Radio className="w-4 h-4 mr-2" />
          Start Continuous Monitoring
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Continuous Monitoring</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground">
            Runs a full EASM + OSINT scan every 5 minutes. Only new assets and findings are added. Use Stop to end.
          </p>
          <div>
            <label className="text-sm font-medium">Target domain</label>
            <Input
              placeholder="example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="mt-2"
              data-testid="input-continuous-monitoring-target"
            />
          </div>
          <Button
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending || !target.trim()}
            className="w-full"
          >
            {mutation.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : null}
            Start
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

const scanTypes = [
  { id: "full", label: "Full Scan (EASM + OSINT)", description: "Complete scan: subdomains, attack surface, email security, exposed content, and all recon modules" },
  { id: "easm", label: "Attack Surface (EASM)", description: "Discover subdomains, services, certificates, and exposed infrastructure" },
  { id: "osint", label: "OSINT Discovery", description: "Find leaked credentials, exposed documents, and public mentions" },
];

function ScanLauncher() {
  const { toast } = useToast();
  const { selectedWorkspaceId, selectedWorkspace } = useDomain();
  const [target, setTarget] = useState("");
  const [selectedTypes, setSelectedTypes] = useState<string[]>(["full"]);
  const [launchedScans, setLaunchedScans] = useState<Record<string, "pending" | "launched">>({});
  const [autoGenerateReport, setAutoGenerateReport] = useState(false);

  useEffect(() => {
    if (selectedWorkspace?.name && !target.trim()) {
      setTarget(selectedWorkspace.name);
    }
    setLaunchedScans({});
  }, [selectedWorkspace?.name]);

  const effectiveTarget = target.trim() || selectedWorkspace?.name || "";
  const DOMAIN_REGEX = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  const domainError = effectiveTarget && !DOMAIN_REGEX.test(effectiveTarget)
    ? "Please enter a valid domain (e.g. example.com)"
    : null;

  const mutation = useMutation({
    mutationFn: async ({ scanType, autoGen }: { scanType: string; autoGen?: boolean }) => {
      const res = await apiRequest("POST", "/api/scans", {
        target: effectiveTarget,
        type: scanType,
        status: "pending",
        workspaceId: selectedWorkspaceId || undefined,
        autoGenerateReport: autoGen ?? false,
        mode: "gold",
      });
      return res.json();
    },
    onSuccess: (data: { workspaceId?: string }, variables) => {
      setLaunchedScans((prev) => ({ ...prev, [variables.scanType]: "launched" }));
      const workspaceIdToInvalidate = selectedWorkspaceId || data?.workspaceId;
      if (workspaceIdToInvalidate) {
        queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceIdToInvalidate}/scans`] });
        queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceIdToInvalidate}/findings`] });
        queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceIdToInvalidate}/assets`] });
        queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceIdToInvalidate}/recon-modules`] });
        queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceIdToInvalidate}/reports`] });
        queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceIdToInvalidate}/posture-history`] });
      }
      queryClient.invalidateQueries({ queryKey: ["/api/workspaces"] });
    },
    onError: (error: Error) => {
      toast({ title: "Scan failed to launch", description: error.message, variant: "destructive" });
    },
  });

  const allLaunched = selectedTypes.length > 0 && selectedTypes.every((t) => launchedScans[t] === "launched");

  const handleLaunchAll = () => {
    if (!effectiveTarget) {
      toast({ title: "Target required", description: "Enter a domain or select a workspace", variant: "destructive" });
      return;
    }
    if (domainError) {
      toast({ title: "Invalid domain", description: domainError, variant: "destructive" });
      return;
    }
    if (selectedTypes.length === 0) {
      toast({ title: "No scan types selected", description: "Select at least one scan type", variant: "destructive" });
      return;
    }
    const pending: Record<string, "pending"> = {};
    for (const t of selectedTypes) {
      pending[t] = "pending";
    }
    setLaunchedScans(pending);
    if (selectedTypes.includes("full")) {
      mutation.mutate({ scanType: "full", autoGen: autoGenerateReport });
      toast({ title: "Full scan started", description: `EASM + OSINT scan initiated against ${effectiveTarget}${autoGenerateReport ? " (report will be auto-generated)" : ""}` });
    } else {
      for (const scanType of selectedTypes) {
        mutation.mutate({ scanType, autoGen: autoGenerateReport });
      }
      toast({ title: "Scans launched", description: `${selectedTypes.length} scan(s) initiated against ${effectiveTarget}${autoGenerateReport ? " (report will be auto-generated)" : ""}` });
    }
  };

  const toggleType = (id: string) => {
    setSelectedTypes((prev) => {
      if (prev.includes(id)) return prev.filter((t) => t !== id);
      if (id === "full") return ["full"];
      return [...prev.filter((t) => t !== "full"), id];
    });
  };

  return (
    <Card data-testid="card-scan-launcher">
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="text-sm font-medium">Launch Scans</CardTitle>
        <Radar className="w-4 h-4 text-muted-foreground" />
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="flex-1 space-y-1">
            <Input
              placeholder="Enter target domain (e.g. example.com)"
              value={target}
              onChange={(e) => {
                setTarget(e.target.value);
                setLaunchedScans({});
              }}
              className={domainError ? "border-red-500 focus-visible:ring-red-500" : ""}
              data-testid="input-scan-target"
            />
            {domainError && (
              <p className="text-xs text-red-500">{domainError}</p>
            )}
          </div>
          <Button
            onClick={handleLaunchAll}
            disabled={mutation.isPending || allLaunched || !effectiveTarget || !!domainError}
            data-testid="button-launch-all-scans"
          >
            {mutation.isPending ? (
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
            ) : allLaunched ? (
              <CheckCircle2 className="w-4 h-4 mr-2" />
            ) : (
              <Play className="w-4 h-4 mr-2" />
            )}
            {mutation.isPending ? "Launching..." : allLaunched ? "All Launched" : "Launch All Scans"}
          </Button>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {scanTypes.map((scan) => {
            const status = launchedScans[scan.id];
            return (
              <div
                key={scan.id}
                className={`flex items-start gap-3 p-3 rounded-md cursor-pointer hover-elevate ${
                  selectedTypes.includes(scan.id) ? "bg-primary/5 ring-1 ring-primary/20" : "bg-muted/40"
                }`}
                onClick={() => { if (!status) toggleType(scan.id); }}
                data-testid={`scan-type-${scan.id}`}
              >
                <Checkbox
                  checked={selectedTypes.includes(scan.id)}
                  onCheckedChange={() => { if (!status) toggleType(scan.id); }}
                  disabled={!!status}
                  className="mt-0.5"
                  data-testid={`checkbox-scan-${scan.id}`}
                />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm font-medium">{scan.label}</span>
                    {status === "launched" && (
                      <Badge variant="outline" className="text-xs bg-green-600/15 text-green-400 border-0 no-default-hover-elevate no-default-active-elevate">
                        <CheckCircle2 className="w-3 h-3 mr-1" />
                        Running
                      </Badge>
                    )}
                    {status === "pending" && (
                      <Badge variant="outline" className="text-xs bg-blue-600/15 text-blue-400 border-0 no-default-hover-elevate no-default-active-elevate">
                        <Loader2 className="w-3 h-3 mr-1 animate-spin" />
                        Starting
                      </Badge>
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground mt-0.5">{scan.description}</p>
                </div>
              </div>
            );
          })}
        </div>
        <div className="flex items-center gap-2 pt-2 border-t">
          <Checkbox
            id="auto-generate-report"
            checked={autoGenerateReport}
            onCheckedChange={(checked) => setAutoGenerateReport(checked === true)}
            disabled={!!Object.keys(launchedScans).length}
            data-testid="checkbox-auto-generate-report"
          />
          <label htmlFor="auto-generate-report" className="text-sm cursor-pointer select-none">
            Auto-generate report when scan completes
          </label>
        </div>
      </CardContent>
    </Card>
  );
}

export default function Dashboard() {
  const { selectedWorkspaceId, workspaces, setSelectedWorkspace } = useDomain();
  const [monitoringWorkspaceId, setMonitoringWorkspaceId] = useState<string | null>(null);

  const { data: cmStatus } = useQuery<ContinuousMonitoringStatus>({
    queryKey: [`/api/continuous-monitoring/status/${selectedWorkspaceId}`],
    enabled: !!selectedWorkspaceId,
    refetchInterval: 2000,
  });
  const isMonitoringActive = cmStatus?.running ?? false;
  useEffect(() => {
    if (isMonitoringActive && selectedWorkspaceId) setMonitoringWorkspaceId(selectedWorkspaceId);
  }, [isMonitoringActive, selectedWorkspaceId]);

  const { data: scans = [], isLoading: loadingScans } = useQuery<Scan[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/scans`],
    enabled: !!selectedWorkspaceId,
    refetchInterval: (query) => {
      const data = query.state.data as Scan[] | undefined;
      const hasRunning = data?.some((s) => s.status === "running" || s.status === "pending");
      return hasRunning || isMonitoringActive ? 2000 : false;
    },
  });
  const hasRunningScans = scans.some((s) => s.status === "running" || s.status === "pending");
  const shouldPollData = hasRunningScans || isMonitoringActive;

  const { data: findings = [], isLoading: loadingFindings } = useQuery<Finding[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/findings`],
    enabled: !!selectedWorkspaceId,
    refetchInterval: shouldPollData ? 4000 : false,
  });

  const { data: assets = [], isLoading: loadingAssets } = useQuery<Asset[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/assets`],
    enabled: !!selectedWorkspaceId,
    refetchInterval: shouldPollData ? 4000 : false,
  });

  const { data: modules = [], isLoading: loadingModules } = useQuery<ReconModule[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/recon-modules`],
    enabled: !!selectedWorkspaceId,
    refetchInterval: shouldPollData ? 4000 : false,
  });

  const isLoading = loadingFindings || loadingAssets || loadingScans || loadingModules;

  const openFindings = findings.filter((f) => f.status === "open");
  const criticalCount = findings.filter((f) => f.severity === "critical" && f.status === "open").length;

  if (isLoading) {
    return (
      <div className="space-y-6 p-6">
        <div>
          <Skeleton className="h-8 w-48 mb-2" />
          <Skeleton className="h-4 w-72" />
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-36" />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <Skeleton className="h-80" />
          <Skeleton className="h-80" />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight" data-testid="text-dashboard-title">Security Overview</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Monitor your organization's security posture at a glance
        </p>
      </div>

      {!selectedWorkspaceId ? (
        <Card>
          <CardContent className="py-16 text-center">
            <Radar className="w-12 h-12 text-muted-foreground/40 mx-auto mb-4" />
            <p className="text-base font-medium text-muted-foreground">No workspace selected</p>
            <p className="text-sm text-muted-foreground mt-1 mb-6">
              Select a workspace from the sidebar or create one to get started
            </p>
            <ScanLauncher />
          </CardContent>
        </Card>
      ) : (
      <>
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row gap-4 items-stretch sm:items-start">
          <div className="flex-1 min-w-0">
            <ScanLauncher />
          </div>
          <div className="flex items-center">
            <StartContinuousMonitoringDialog
              workspaces={workspaces}
              setSelectedWorkspace={(ws) => setSelectedWorkspace(ws as Parameters<typeof setSelectedWorkspace>[0])}
              onStarted={(id) => setMonitoringWorkspaceId(id)}
            />
          </div>
        </div>
      </div>

      {monitoringWorkspaceId && (
        <ContinuousMonitoringCard
          workspaceId={monitoringWorkspaceId}
          onStop={() => setMonitoringWorkspaceId(null)}
        />
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Assets"
          value={assets.length}
          icon={Globe}
          description="Monitored assets"
          testId="stat-total-assets"
        />
        <StatCard
          title="Open Findings"
          value={openFindings.length}
          icon={AlertTriangle}
          description={`${criticalCount} critical`}
          testId="stat-open-findings"
        />
        <StatCard
          title="Scans Run"
          value={scans.length}
          icon={Search}
          description={(() => {
            const last = scans.find((s) => s.status === "completed");
            if (!last?.completedAt) return "No completed scans";
            const ago = Date.now() - new Date(last.completedAt).getTime();
            if (ago < 60_000) return "Last: just now";
            if (ago < 3_600_000) return `Last: ${Math.round(ago / 60_000)}m ago`;
            if (ago < 86_400_000) return `Last: ${Math.round(ago / 3_600_000)}h ago`;
            return `Last: ${Math.round(ago / 86_400_000)}d ago`;
          })()}
          testId="stat-scans-run"
        />
        <StatCard
          title="Security Score"
          value={findings.length === 0 ? "N/A" : `${computeSecurityScore(findings)}/100`}
          icon={Shield}
          description="Based on open findings"
          testId="stat-security-score"
        />
      </div>

      <IntelligenceOverview modules={modules} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <SeverityChart findings={findings} />
        <RecentScans scans={scans} workspaceId={selectedWorkspaceId ?? null} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <PostureHistoryCard workspaceId={selectedWorkspaceId ?? null} />
        <FindingsSummaryCard findings={findings} />
      </div>

      <RecentFindings findings={findings} />
      </>
      )}
    </div>
  );
}
