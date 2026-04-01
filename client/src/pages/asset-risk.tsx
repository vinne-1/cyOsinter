import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
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
} from "lucide-react";

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
  trend: "improving" | "stable" | "degrading";
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

function TrendIcon({ trend }: { trend: string }) {
  switch (trend) {
    case "degrading":
      return <TrendingUp className="w-4 h-4 text-red-500" />;
    case "improving":
      return <TrendingDown className="w-4 h-4 text-green-500" />;
    default:
      return <Minus className="w-4 h-4 text-muted-foreground" />;
  }
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
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [sortField, setSortField] = useState<SortField>("overallScore");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const { data: assets, isLoading, isError, error } = useQuery<AssetRisk[]>({
    queryKey: ["/api/asset-risk", selectedWorkspaceId],
    queryFn: async () => {
      const res = await apiRequest("GET", `/api/asset-risk?workspaceId=${selectedWorkspaceId}`);
      return res.json();
    },
    enabled: !!selectedWorkspaceId,
  });

  function handleSort(field: SortField) {
    if (sortField === field) {
      setSortDir(sortDir === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortDir("desc");
    }
  }

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

  const assetList = Array.isArray(assets) ? assets : [];
  const totalAssets = assetList.length;
  const criticalRiskCount = assetList.filter((a) => a.overallScore >= 80).length;
  const averageScore = totalAssets > 0
    ? assetList.reduce((sum, a) => sum + a.overallScore, 0) / totalAssets
    : 0;

  const sorted = sortAssets(assetList, sortField, sortDir);

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-3">
        <Shield className="w-6 h-6 text-primary" />
        <div>
          <h1 className="text-2xl font-bold">Asset Risk Scoring</h1>
          <p className="text-sm text-muted-foreground">
            View risk scores and contributing factors for each asset
          </p>
        </div>
      </div>

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
              {averageScore.toFixed(1)}
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
                {sorted.map((asset) => (
                  <React.Fragment key={asset.assetId}>
                    <TableRow
                      className="cursor-pointer"
                      onClick={() =>
                        setExpandedId(expandedId === asset.assetId ? null : asset.assetId)
                      }
                    >
                      <TableCell className="font-medium">{asset.hostname}</TableCell>
                      <TableCell>
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
                        </div>
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
          </CardContent>
        </Card>
      )}
    </div>
  );
}
