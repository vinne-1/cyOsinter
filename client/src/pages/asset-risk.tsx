import React, { useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { usePagedList, ListPager } from "@/components/list-pager";
import { useToast } from "@/hooks/use-toast";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Shield,
  TrendingUp,
  TrendingDown,
  Minus,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  Server,
  BarChart3,
  Sparkles,
  Loader2,
} from "lucide-react";

interface AssetRiskNarrative {
  summary: string;
  drivers: string[];
}

interface RiskFactor {
  name: string;
  score: number;
  weight: number;
  details: string;
}

interface AssetRisk {
  assetId: string;
  hostname: string;
  overallScore: number;
  /**
   * Scorable findings behind the score. A 0 reached from no findings is not
   * the same claim as a 0 reached from findings that all scored low, and the
   * table must not render them identically — a green "0" with a green bar for
   * a host nothing was ever found against reads as an assurance we never made.
   */
  findingCount: number;
  trend: "improving" | "stable" | "degrading" | "unknown";
  factors: RiskFactor[];
  lastUpdated: string;
}

type SortField = "hostname" | "overallScore";
type SortDir = "asc" | "desc";

function scoreColor(score: number): string {
  if (score >= 80) return "text-red-600";
  if (score >= 60) return "text-orange-600";
  if (score >= 40) return "text-yellow-600";
  return "text-green-600";
}

function progressBarColor(score: number): string {
  if (score >= 80) return "bg-red-500";
  if (score >= 60) return "bg-orange-500";
  if (score >= 40) return "bg-yellow-500";
  return "bg-green-500";
}

/**
 * The icon column had no text at all, so a red rising arrow was the whole
 * claim — and `unknown` has to be legible as "we cannot say", not as neutral.
 * The icon is decorative; the accessible name comes from the label beside it.
 */
function TrendIcon({ trend }: { trend: string }) {
  const { Icon, cls, label } =
    trend === "degrading"
      ? { Icon: TrendingUp, cls: "text-red-500", label: "Degrading" }
      : trend === "improving"
        ? { Icon: TrendingDown, cls: "text-green-500", label: "Improving" }
        : trend === "stable"
          ? { Icon: Minus, cls: "text-muted-foreground", label: "Stable" }
          : { Icon: Minus, cls: "text-muted-foreground", label: "No history" };

  return (
    <span className="flex items-center gap-1.5">
      <Icon className={`w-4 h-4 ${cls}`} aria-hidden="true" />
      <span className="text-xs text-muted-foreground">{label}</span>
    </span>
  );
}

function sortAssets(assets: AssetRisk[], field: SortField, dir: SortDir): AssetRisk[] {
  return [...assets].sort((a, b) => {
    const aVal = field === "hostname" ? a.hostname.toLowerCase() : a.overallScore;
    const bVal = field === "hostname" ? b.hostname.toLowerCase() : b.overallScore;
    if (aVal < bVal) return dir === "asc" ? -1 : 1;
    if (aVal > bVal) return dir === "asc" ? 1 : -1;
    return 0;
  });
}

function topRiskFactor(factors: RiskFactor[]): string {
  if (!factors || factors.length === 0) return "N/A";
  const sorted = [...factors].sort((a, b) => b.score * b.weight - a.score * a.weight);
  return sorted[0]?.name ?? "N/A";
}

export default function AssetRiskPage() {
  const { selectedWorkspaceId } = useDomain();
  const { toast } = useToast();
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [sortField, setSortField] = useState<SortField>("overallScore");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [narrative, setNarrative] = useState<AssetRiskNarrative | null>(null);

  const { data: assets, isLoading, isError, error } = useQuery<AssetRisk[]>({
    queryKey: ["/api/asset-risk", selectedWorkspaceId],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/asset-risk?workspaceId=${selectedWorkspaceId}`);
      return res.json();
    },
    enabled: !!selectedWorkspaceId,
  });

  const explainMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/asset-risk/explain?workspaceId=${selectedWorkspaceId}`, undefined, { timeoutMs: 120000 });
      return res.json() as Promise<AssetRiskNarrative>;
    },
    onSuccess: (data) => setNarrative(data),
    onError: (err: Error) => {
      toast({ title: "AI explanation failed", description: err.message, variant: "destructive" });
    },
  });
  // Every hook before any early return (see the note below on `assetList`) —
  // this page already carries a documented crash from getting that wrong once.
  useEffect(() => {
    setNarrative(null);
  }, [selectedWorkspaceId]);

  function handleSort(field: SortField) {
    if (sortField === field) {
      setSortDir(sortDir === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortDir("desc");
    }
  }

  /*
   * Derived above the early returns, because `usePagedList` is a HOOK.
   *
   * It was originally placed after the `isLoading` / `isError` guards, so it
   * ran on a loaded render and not on a loading one — React counted a different
   * number of hooks between renders, threw "Rendered more hooks than during the
   * previous render", and tore the page down. The symptom was not an error
   * message on screen: the table simply never appeared, and a scan measuring
   * "largest rendered list" read the crash as a successful reduction.
   *
   * `assets` is undefined while loading, which the Array.isArray guard already
   * handles, so running this early costs nothing.
   */
  const assetList = Array.isArray(assets) ? assets : [];
  const totalAssets = assetList.length;
  const criticalRiskCount = assetList.filter((a) => a.overallScore >= 80).length;
  /*
   * Average over the assets that actually have findings.
   *
   * Averaging the whole estate divides by every host nothing was found against
   * — on a live workspace that is 654 of 743 — so the headline collapsed
   * towards zero and reported a clean posture no matter what the findings said.
   * The denominator is shown beside it so the number cannot be read as an
   * estate-wide claim.
   */
  const scoredAssets = assetList.filter((a) => a.findingCount > 0);
  const averageScore = scoredAssets.length > 0
    ? scoredAssets.reduce((sum, a) => sum + a.overallScore, 0) / scoredAssets.length
    : 0;

  const sorted = sortAssets(assetList, sortField, sortDir);
  // Sorting covers the whole estate; only the window is paged, so "highest risk
  // first" still means highest in the estate. Re-sorting returns to page 1 —
  // the row the reader was looking at has moved.
  const pagedAssets = usePagedList(sorted, `${sortField}|${sortDir}`);

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-48" />
        <div className="grid gap-4 md:grid-cols-3">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="p-6">
        <Card>
          <CardContent className="py-8 text-center">
            <p className="text-destructive">
              Failed to load asset risk data:{" "}
              {error instanceof Error ? error.message : "Unknown error"}
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-3">
          <Shield className="w-6 h-6 text-primary" />
          <div>
            <h1 className="text-2xl font-bold">Asset Risk Scoring</h1>
            <p className="text-sm text-muted-foreground">
              View risk scores and contributing factors for each asset
            </p>
          </div>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => explainMutation.mutate()}
          disabled={explainMutation.isPending || assetList.length === 0}
          data-testid="button-explain-asset-risk"
        >
          {explainMutation.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Sparkles className="w-4 h-4 mr-2" />}
          {explainMutation.isPending ? "Asking GLM..." : narrative ? "Re-explain" : "Explain with AI"}
        </Button>
      </div>

      {narrative && (
        <Card data-testid="card-asset-risk-narrative">
          <CardContent className="p-4 space-y-2">
            <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
              AI Summary — correlates risk factors across the whole estate, from aggregate counts only
            </p>
            <p className="text-sm leading-relaxed">{narrative.summary}</p>
            {narrative.drivers.length > 0 && (
              <ul className="space-y-1">
                {narrative.drivers.map((d, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-500 flex-shrink-0 mt-0.5" />
                    {d}
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      )}

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground flex items-center gap-2">
              <Server className="w-4 h-4" />
              Total Assets
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">{totalAssets}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" />
              Critical Risk
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold text-red-600">{criticalRiskCount}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground flex items-center gap-2">
              <BarChart3 className="w-4 h-4" />
              Average Score
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className={`text-2xl font-bold ${scoreColor(averageScore)}`}>
              {scoredAssets.length > 0 ? averageScore.toFixed(1) : "—"}
            </p>
            <p className="text-xs text-muted-foreground mt-1">
              {scoredAssets.length > 0
                ? `across ${scoredAssets.length} of ${totalAssets} assets with findings`
                : "no assets have findings yet"}
            </p>
          </CardContent>
        </Card>
      </div>

      {assetList.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-16">
            <Shield className="w-12 h-12 text-muted-foreground mb-4" />
            <p className="text-muted-foreground">No asset risk data available</p>
            <p className="text-sm text-muted-foreground mt-1">
              Risk scores are computed after scans complete
            </p>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>Asset Risk Details</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead
                    className="cursor-pointer select-none"
                    onClick={() => handleSort("hostname")}
                  >
                    Hostname{" "}
                    {sortField === "hostname" && (sortDir === "asc" ? "^" : "v")}
                  </TableHead>
                  <TableHead
                    className="cursor-pointer select-none"
                    onClick={() => handleSort("overallScore")}
                  >
                    Risk Score{" "}
                    {sortField === "overallScore" && (sortDir === "asc" ? "^" : "v")}
                  </TableHead>
                  <TableHead>Trend</TableHead>
                  <TableHead>Top Risk Factor</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pagedAssets.items.map((asset) => (
                  <React.Fragment key={asset.assetId}>
                    <TableRow
                      className="cursor-pointer"
                      onClick={() =>
                        setExpandedId(expandedId === asset.assetId ? null : asset.assetId)
                      }
                    >
                      <TableCell className="font-medium">{asset.hostname}</TableCell>
                      <TableCell>
                        {asset.findingCount === 0 ? (
                          // Nothing was found against this host. Rendering a
                          // green 0 here would assert it was assessed clean.
                          <span className="text-muted-foreground text-sm">
                            No findings
                          </span>
                        ) : (
                          <div className="flex items-center gap-3">
                            <span className={`font-bold ${scoreColor(asset.overallScore)}`}>
                              {asset.overallScore}
                            </span>
                            <div className="w-24 h-2 bg-muted rounded-full overflow-hidden">
                              <div
                                className={`h-full rounded-full ${progressBarColor(asset.overallScore)}`}
                                style={{ width: `${asset.overallScore}%` }}
                              />
                            </div>
                            <span className="text-xs text-muted-foreground">
                              {asset.findingCount} finding{asset.findingCount === 1 ? "" : "s"}
                            </span>
                          </div>
                        )}
                      </TableCell>
                      <TableCell>
                        <TrendIcon trend={asset.trend} />
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">{topRiskFactor(asset.factors)}</Badge>
                      </TableCell>
                      <TableCell>
                        {expandedId === asset.assetId ? (
                          <ChevronUp className="w-4 h-4 text-muted-foreground" />
                        ) : (
                          <ChevronDown className="w-4 h-4 text-muted-foreground" />
                        )}
                      </TableCell>
                    </TableRow>
                    {expandedId === asset.assetId && (
                      <TableRow key={`${asset.assetId}-factors`}>
                        <TableCell colSpan={5} className="bg-muted/50">
                          <div className="py-2 space-y-2">
                            <p className="text-sm font-medium mb-2">Risk Factor Breakdown</p>
                            {(asset.factors ?? []).map((factor, idx) => (
                              <div
                                key={`${factor.name}-${idx}`}
                                className="flex items-center justify-between p-3 rounded-md border bg-background"
                              >
                                <div className="flex-1">
                                  <p className="text-sm font-medium">{factor.name}</p>
                                  <p className="text-xs text-muted-foreground">
                                    {factor.details}
                                  </p>
                                </div>
                                <div className="flex items-center gap-4 text-sm">
                                  <span>
                                    Score:{" "}
                                    <span className={`font-bold ${scoreColor(factor.score)}`}>
                                      {factor.score}
                                    </span>
                                  </span>
                                  <span className="text-muted-foreground">
                                    Weight: {factor.weight}x
                                  </span>
                                </div>
                              </div>
                            ))}
                          </div>
                        </TableCell>
                      </TableRow>
                    )}
                  </React.Fragment>
                ))}
              </TableBody>
            </Table>
            <ListPager paged={pagedAssets} label="assets" />
          </CardContent>
        </Card>
      )}
    </div>
  );
}
