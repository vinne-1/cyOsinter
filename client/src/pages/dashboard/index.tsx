import { useState, useEffect, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { useListQuery } from "@/hooks/use-list-query";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  AlertTriangle,
  Globe,
  Radar,
  ScanLine,
  Route,
  ChevronDown,
  Play,
  Layers,
  Activity,
  Timer,
} from "lucide-react";
import type { Finding, Asset, Scan, ReconModule, PostureSnapshot } from "@shared/schema";
import { computeSecurityScore } from "@shared/scoring";
import { countBySeverity } from "@/lib/severity";
import { MetricTile } from "@/components/metric-tile";
import { PostureHero } from "@/components/posture-hero";
import { BentoGrid, BentoTile, LiveIndicator } from "@/components/bento";
import { SeverityChart, FindingsSummaryCard, RecentFindings } from "./stat-cards";
import { IntelligenceOverview } from "./intelligence-overview";
import { RecentScans, ContinuousMonitoringCard, StartContinuousMonitoringDialog, ScanLauncher } from "./scan-sections";
import { PostureHistoryCard } from "./posture-history-card";
import { type ContinuousMonitoringStatus } from "./helpers";

/** Humanises a timestamp into "just now" / "12m ago" / "3d ago". */
function relativeTime(at: string | Date | null | undefined): string | null {
  if (!at) return null;
  const ago = Date.now() - new Date(at).getTime();
  if (ago < 60_000) return "just now";
  if (ago < 3_600_000) return `${Math.round(ago / 60_000)}m ago`;
  if (ago < 86_400_000) return `${Math.round(ago / 3_600_000)}h ago`;
  return `${Math.round(ago / 86_400_000)}d ago`;
}

export default function Dashboard() {
  const { selectedWorkspaceId, selectedWorkspace, workspaces, setSelectedWorkspace } = useDomain();
  const [monitoringWorkspaceId, setMonitoringWorkspaceId] = useState<string | null>(null);
  const [launcherOpen, setLauncherOpen] = useState(false);

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

  // Assets are counted, not listed, on this page — so the server's `total` is
  // what matters. `useListQuery` keeps it; the default query fn would unwrap the
  // envelope and leave only the first page, under-reporting large workspaces.
  const { total: assetTotal, isLoading: loadingAssets } = useListQuery<Asset>(
    selectedWorkspaceId ? `/api/workspaces/${selectedWorkspaceId}/assets` : null,
    { refetchInterval: shouldPollData ? 4000 : false },
  );

  const { data: modules = [], isLoading: loadingModules } = useQuery<ReconModule[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/recon-modules`],
    enabled: !!selectedWorkspaceId,
    refetchInterval: shouldPollData ? 4000 : false,
  });

  // Remediation-deadline posture. Counts come from the server so they cover the
  // whole workspace, not the current page of findings.
  const { data: sla } = useQuery<{ open: number; breached: number; dueSoon: number; onTrack: number }>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/sla-summary`],
    enabled: !!selectedWorkspaceId,
    refetchInterval: shouldPollData ? 10000 : false,
  });

  const { data: snapshots = [] } = useQuery<PostureSnapshot[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/posture-history`],
    enabled: !!selectedWorkspaceId,
  });

  const isLoading = loadingFindings || loadingAssets || loadingScans || loadingModules;

  const openFindings = useMemo(() => findings.filter((f) => f.status === "open"), [findings]);
  const counts = useMemo(() => countBySeverity(openFindings), [openFindings]);
  const score = findings.length === 0 ? null : computeSecurityScore(findings);

  // Snapshots arrive newest-first; sparklines and deltas read oldest → newest.
  const history = useMemo(() => [...snapshots].reverse(), [snapshots]);
  const scoreSeries = history.map((s) => s.securityScore).filter((n): n is number => typeof n === "number");
  const findingSeries = history.map((s) => s.findingsCount).filter((n): n is number => typeof n === "number");
  const scoreDelta =
    scoreSeries.length >= 2 && typeof score === "number"
      ? score - scoreSeries[scoreSeries.length - 2]!
      : null;
  const findingsDelta =
    findingSeries.length >= 2
      ? openFindings.length - findingSeries[findingSeries.length - 2]!
      : undefined;

  const lastCompleted = scans.find((s) => s.status === "completed");
  const lastScanLabel = relativeTime(lastCompleted?.completedAt);
  const target = selectedWorkspace?.domain || selectedWorkspace?.name || null;

  if (isLoading) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-9 w-56" />
        <Skeleton className="h-64 rounded-2xl" />
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-32 rounded-xl" />
          ))}
        </div>
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Skeleton className="h-80 rounded-xl" />
          <Skeleton className="h-80 rounded-xl" />
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-[1600px] space-y-6 p-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-semibold tracking-tight" data-testid="text-dashboard-title">
              Security Overview
            </h1>
            {/* A monitoring dashboard should say whether what you are reading is
                current. Without this the page looks identical whether the data
                arrived a second or a month ago. */}
            {shouldPollData && <LiveIndicator label={hasRunningScans ? "Scanning" : "Monitoring"} />}
          </div>
          <p className="mt-1 text-sm text-muted-foreground">
            Monitor your organization's security posture at a glance
          </p>
        </div>
        {selectedWorkspaceId && (
          <div className="flex items-center gap-2">
            <StartContinuousMonitoringDialog
              workspaces={workspaces}
              setSelectedWorkspace={(ws) => setSelectedWorkspace(ws as Parameters<typeof setSelectedWorkspace>[0])}
              onStarted={(id) => setMonitoringWorkspaceId(id)}
            />
          </div>
        )}
      </div>

      {!selectedWorkspaceId ? (
        <Card>
          <CardContent className="py-16 text-center">
            <Radar className="mx-auto mb-4 h-12 w-12 text-muted-foreground/40" aria-hidden="true" />
            <p className="text-base font-medium text-muted-foreground">No workspace selected</p>
            <p className="mb-6 mt-1 text-sm text-muted-foreground">
              Select a workspace from the header or start a scan to create one
            </p>
            <div className="mx-auto max-w-3xl text-left">
              <ScanLauncher />
            </div>
          </CardContent>
        </Card>
      ) : (
        <>
          {/*
            Bento grid: tile SIZE carries the hierarchy. Posture is the hero at
            2x2; open findings — the number an analyst acts on — gets a wide
            tile; the supporting counts sit in single cells. A uniform row of
            five equal cards, which is what this was, tells the reader nothing
            about what to look at first.
          */}
          <BentoGrid className="animate-fade-up">
            <BentoTile span={2} rows={2} bare>
              <PostureHero
                score={score}
                counts={counts}
                delta={scoreDelta}
                target={target}
                totalAssets={assetTotal}
                lastScanLabel={lastScanLabel}
                className="h-full"
              />
            </BentoTile>

            <BentoTile span={2} accent="hsl(var(--sev-high))">
              <MetricTile
                label="Open findings"
                value={openFindings.length}
                hint={`${counts.critical} critical · ${counts.high} high`}
                icon={AlertTriangle}
                delta={findingsDelta}
                deltaGoodDirection="down"
                series={findingSeries}
                accent="hsl(var(--sev-high))"
                emphasis
                testId="stat-open-findings"
                className="border-0 bg-transparent p-0"
              />
            </BentoTile>

            <BentoTile>
              <MetricTile
                label="Attack surface"
                value={assetTotal}
                hint="Assets discovered"
                icon={Globe}
                testId="stat-total-assets"
                className="border-0 bg-transparent p-0"
              />
            </BentoTile>

            <BentoTile
              accent={(sla?.breached ?? 0) > 0 ? "hsl(var(--sev-critical))" : undefined}
              emphasis={(sla?.breached ?? 0) > 0}
            >
              <MetricTile
                label="SLA breached"
                value={sla?.breached ?? 0}
                hint={sla ? `${sla.dueSoon} due in 24h` : "Deadlines"}
                icon={Timer}
                accent={(sla?.breached ?? 0) > 0 ? "hsl(var(--sev-critical))" : "hsl(var(--sev-ok))"}
                testId="stat-sla-breached"
                className="border-0 bg-transparent p-0"
              />
            </BentoTile>

            <BentoTile span={2}>
              <MetricTile
                label="Scans run"
                value={scans.length}
                hint={lastScanLabel ? `Last ${lastScanLabel}` : "None completed"}
                icon={ScanLine}
                testId="stat-scans-run"
                className="border-0 bg-transparent p-0"
              />
            </BentoTile>

            <BentoTile span={2}>
              <MetricTile
                label="Security score"
                value={score === null ? "N/A" : `${score}`}
                hint="From open findings"
                icon={Activity}
                delta={scoreDelta ?? undefined}
                deltaGoodDirection="up"
                series={scoreSeries}
                accent="hsl(var(--sev-ok))"
                testId="stat-security-score"
                className="border-0 bg-transparent p-0"
              />
            </BentoTile>
          </BentoGrid>

          <Collapsible open={launcherOpen} onOpenChange={setLauncherOpen}>
            <CollapsibleTrigger asChild>
              <Button
                variant="outline"
                className="h-11 w-full justify-between border-hairline bg-surface-2 px-4"
                data-testid="button-toggle-launcher"
              >
                <span className="flex items-center gap-2 text-sm font-medium">
                  <Play className="h-4 w-4 text-primary" aria-hidden="true" />
                  Run a scan
                  {target && <span className="font-mono text-xs text-muted-foreground">{target}</span>}
                </span>
                <ChevronDown
                  className={`h-4 w-4 text-muted-foreground transition-transform duration-200 ${launcherOpen ? "rotate-180" : ""}`}
                  aria-hidden="true"
                />
              </Button>
            </CollapsibleTrigger>
            <CollapsibleContent className="pt-3">
              <ScanLauncher />
            </CollapsibleContent>
          </Collapsible>

          {monitoringWorkspaceId && (
            <ContinuousMonitoringCard
              workspaceId={monitoringWorkspaceId}
              onStop={() => setMonitoringWorkspaceId(null)}
            />
          )}

          <IntelligenceOverview modules={modules} />

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <SeverityChart findings={findings} />
            <RecentScans scans={scans} workspaceId={selectedWorkspaceId ?? null} />
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <PostureHistoryCard workspaceId={selectedWorkspaceId ?? null} />
            <FindingsSummaryCard findings={findings} />
          </div>

          <DastAndAttackPaths modules={modules} findings={findings} />

          <RecentFindings findings={findings} />
        </>
      )}
    </div>
  );
}

/**
 * DAST + attack-path summary. Rendered only when at least one of the two has
 * something to say, so an unscanned workspace does not show empty scaffolding.
 */
function DastAndAttackPaths({ modules, findings }: { modules: ReconModule[]; findings: Finding[] }) {
  const dastModule = modules.find((m) => m.moduleType === "dast_lite");
  const dastData = dastModule?.data as
    | { testsRun?: number; testsPassed?: number; findings?: unknown[] }
    | undefined;

  const openFinds = findings.filter((f) => f.status === "open" || f.status === "in_review");
  const categories = new Set(openFinds.map((f) => f.category));
  const chains = [
    categories.has("xss") || categories.has("cors_misconfiguration") || categories.has("open_redirect"),
    categories.has("subdomain_takeover"),
    categories.has("transport_security") || categories.has("ssl_tls"),
    categories.has("api_exposure"),
  ].filter(Boolean).length;

  if (!dastData && chains === 0) return null;

  const criticalHigh = openFinds.filter((f) => f.severity === "critical" || f.severity === "high").length;

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      {dastData && (
        <div className="rounded-xl border border-hairline bg-surface-2 p-4">
          <div className="mb-4 flex items-center gap-2">
            <ScanLine className="h-4 w-4 text-primary" aria-hidden="true" />
            <span className="text-sm font-semibold">DAST-Lite results</span>
          </div>
          <div className="grid grid-cols-3 gap-3">
            {[
              { label: "Tests run", value: dastData.testsRun ?? 0, tone: "text-foreground" },
              { label: "Passed", value: dastData.testsPassed ?? 0, tone: "text-severity-ok" },
              { label: "Issues", value: (dastData.findings ?? []).length, tone: "text-severity-critical" },
            ].map((s) => (
              <div key={s.label} className="rounded-lg bg-surface-inset p-3 text-center">
                <div className={`text-display-sm font-semibold tabular-nums ${s.tone}`}>{s.value}</div>
                <div className="mt-1 text-xs text-muted-foreground">{s.label}</div>
              </div>
            ))}
          </div>
        </div>
      )}
      {chains > 0 && (
        <div className="rounded-xl border border-hairline bg-surface-2 p-4">
          <div className="mb-4 flex items-center gap-2">
            <Route className="h-4 w-4 text-primary" aria-hidden="true" />
            <span className="text-sm font-semibold">Attack paths</span>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-lg bg-surface-inset p-3 text-center">
              <div className="text-display-sm font-semibold tabular-nums">{chains}</div>
              <div className="mt-1 text-xs text-muted-foreground">Active chains</div>
            </div>
            <div className="rounded-lg bg-surface-inset p-3 text-center">
              <div className="text-display-sm font-semibold tabular-nums text-severity-critical">{criticalHigh}</div>
              <div className="mt-1 text-xs text-muted-foreground">Critical / high</div>
            </div>
          </div>
          <p className="mt-3 flex items-center gap-1.5 text-xs text-muted-foreground">
            <Layers className="h-3 w-3" aria-hidden="true" />
            Full chain analysis on the Attack Paths page
          </p>
        </div>
      )}
    </div>
  );
}
