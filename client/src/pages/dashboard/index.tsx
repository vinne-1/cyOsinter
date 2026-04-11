import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Shield,
  AlertTriangle,
  Globe,
  Search,
  Radar,
  ScanLine,
  Route,
} from "lucide-react";
import type { Finding, Asset, Scan, ReconModule } from "@shared/schema";
import { computeSecurityScore } from "@shared/scoring";
import { StatCard, SeverityChart, FindingsSummaryCard, RecentFindings } from "./stat-cards";
import { IntelligenceOverview } from "./intelligence-overview";
import { RecentScans, ContinuousMonitoringCard, StartContinuousMonitoringDialog, ScanLauncher } from "./scan-sections";
import { PostureHistoryCard } from "./posture-history-card";
import { type ContinuousMonitoringStatus } from "./helpers";

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
          value={`${computeSecurityScore(findings)}/100`}
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

      {/* DAST + Attack Paths Summary Row */}
      {(() => {
        const dastModule = modules.find((m) => m.moduleType === "dast_lite");
        const dastData = dastModule?.data as { testsRun?: number; testsPassed?: number; findings?: unknown[] } | undefined;
        const openFinds = findings.filter((f) => f.status === "open" || f.status === "in_review");
        const attackCategories = new Set(openFinds.map((f) => f.category));
        const hasAttackPaths = attackCategories.has("xss") || attackCategories.has("cors_misconfiguration") ||
          attackCategories.has("subdomain_takeover") || attackCategories.has("transport_security") ||
          attackCategories.has("api_exposure") || attackCategories.has("open_redirect");
        const chainCount = [
          attackCategories.has("xss") || attackCategories.has("cors_misconfiguration") || attackCategories.has("open_redirect"),
          attackCategories.has("subdomain_takeover"),
          attackCategories.has("transport_security") || attackCategories.has("ssl_tls"),
          attackCategories.has("api_exposure"),
        ].filter(Boolean).length;

        return (dastData || hasAttackPaths) ? (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {dastData && (
              <Card>
                <CardContent className="p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <ScanLine className="w-4 h-4 text-primary" />
                    <span className="font-semibold text-sm">DAST-Lite Results</span>
                  </div>
                  <div className="grid grid-cols-3 gap-3 text-center">
                    <div>
                      <div className="text-2xl font-bold">{dastData.testsRun ?? 0}</div>
                      <div className="text-xs text-muted-foreground">Tests Run</div>
                    </div>
                    <div>
                      <div className="text-2xl font-bold text-green-500">{dastData.testsPassed ?? 0}</div>
                      <div className="text-xs text-muted-foreground">Passed</div>
                    </div>
                    <div>
                      <div className="text-2xl font-bold text-red-500">{(dastData.findings ?? []).length}</div>
                      <div className="text-xs text-muted-foreground">Issues</div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}
            {hasAttackPaths && (
              <Card>
                <CardContent className="p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <Route className="w-4 h-4 text-primary" />
                    <span className="font-semibold text-sm">Attack Paths</span>
                  </div>
                  <div className="grid grid-cols-2 gap-3 text-center">
                    <div>
                      <div className="text-2xl font-bold">{chainCount}</div>
                      <div className="text-xs text-muted-foreground">Active Chains</div>
                    </div>
                    <div>
                      <div className="text-2xl font-bold text-red-500">{openFinds.filter((f) => f.severity === "critical" || f.severity === "high").length}</div>
                      <div className="text-xs text-muted-foreground">Critical/High</div>
                    </div>
                  </div>
                  <p className="text-xs text-muted-foreground mt-2">View full attack path analysis on the Attack Paths page</p>
                </CardContent>
              </Card>
            )}
          </div>
        ) : null;
      })()}

      <RecentFindings findings={findings} />
      </>
      )}
    </div>
  );
}
