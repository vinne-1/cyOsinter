import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
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
import { ShieldAlert, Search, Zap } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface Indicator {
  type: string;
  value: string;
  pulseCount: number;
  reputationScore: number;
  tags: string[];
}

interface ThreatIntelResult {
  riskLevel: string;
  indicatorCount: number;
  summary: string;
  indicators: Indicator[];
}

const riskColors: Record<string, string> = {
  critical: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300",
  high: "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300",
  medium: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300",
  low: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300",
  none: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300",
};

function reputationColor(score: number): string {
  if (score >= 80) return "text-red-600";
  if (score >= 50) return "text-orange-600";
  if (score >= 20) return "text-yellow-600";
  return "text-green-600";
}

export default function ThreatIntel() {
  const { selectedWorkspaceId } = useDomain();
  const [target, setTarget] = useState("");
  const [submittedTarget, setSubmittedTarget] = useState("");
  const { toast } = useToast();

  const {
    data: result,
    isLoading,
    isError,
    error,
  } = useQuery<ThreatIntelResult>({
    queryKey: ["/api/threat-intel/lookup", submittedTarget],
    queryFn: async () => {
      const res = await apiRequest("POST", "/api/threat-intel/lookup", {
        target: submittedTarget,
      });
      return res.json();
    },
    enabled: !!submittedTarget,
  });

  const enrichMutation = useMutation({
    mutationFn: () => {
      if (!selectedWorkspaceId) throw new Error("No workspace selected");
      return apiRequest("POST", `/api/threat-intel/enrich?workspaceId=${selectedWorkspaceId}`);
    },
    onSuccess: () => {
      toast({ title: "Enrichment complete", description: "All findings have been enriched with threat intelligence" });
    },
    onError: (err: Error) => {
      toast({ title: "Enrichment failed", description: err.message, variant: "destructive" });
    },
  });

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = target.trim();
    if (trimmed) {
      setSubmittedTarget(trimmed);
    }
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ShieldAlert className="w-6 h-6 text-primary" />
          <div>
            <h1 className="text-2xl font-bold">Threat Intelligence</h1>
            <p className="text-sm text-muted-foreground">
              Look up IP addresses and domains for threat indicators
            </p>
          </div>
        </div>
        <Button
          onClick={() => enrichMutation.mutate()}
          disabled={enrichMutation.isPending}
          variant="outline"
        >
          <Zap className={`w-4 h-4 mr-2 ${enrichMutation.isPending ? "animate-spin" : ""}`} />
          {enrichMutation.isPending ? "Enriching..." : "Enrich All Findings"}
        </Button>
      </div>

      <Card>
        <CardContent className="py-4">
          <form onSubmit={handleSearch} className="flex gap-3">
            <Input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="Enter IP address or domain (e.g. 8.8.8.8 or example.com)"
              className="flex-1"
            />
            <Button type="submit" disabled={!target.trim() || isLoading}>
              <Search className="w-4 h-4 mr-2" />
              {isLoading ? "Looking up..." : "Lookup"}
            </Button>
          </form>
        </CardContent>
      </Card>

      {!submittedTarget && (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-16">
            <ShieldAlert className="w-12 h-12 text-muted-foreground mb-4" />
            <p className="text-muted-foreground">Enter an IP or domain to look up threat intelligence</p>
          </CardContent>
        </Card>
      )}

      {isLoading && (
        <div className="space-y-4">
          <Skeleton className="h-24 w-full" />
          <Skeleton className="h-64 w-full" />
        </div>
      )}

      {isError && (
        <Card>
          <CardContent className="py-8 text-center">
            <p className="text-destructive">
              Lookup failed: {error instanceof Error ? error.message : "Unknown error"}
            </p>
          </CardContent>
        </Card>
      )}

      {result && !isLoading && (
        <>
          <div className="grid gap-4 md:grid-cols-3">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm text-muted-foreground">Risk Level</CardTitle>
              </CardHeader>
              <CardContent>
                <Badge
                  className={`text-base px-3 py-1 ${riskColors[result.riskLevel] || ""}`}
                  variant="secondary"
                >
                  {result.riskLevel}
                </Badge>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm text-muted-foreground">Indicators Found</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-bold">{result.indicatorCount}</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm text-muted-foreground">Summary</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm">{result.summary}</p>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Indicators</CardTitle>
            </CardHeader>
            <CardContent>
              {result.indicators.length === 0 ? (
                <p className="text-sm text-muted-foreground text-center py-8">
                  No indicators found for this target
                </p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Type</TableHead>
                      <TableHead>Value</TableHead>
                      <TableHead>Pulse Count</TableHead>
                      <TableHead>Reputation</TableHead>
                      <TableHead>Tags</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {result.indicators.map((ind, idx) => (
                      <TableRow key={`${ind.type}-${ind.value}-${idx}`}>
                        <TableCell>
                          <Badge variant="outline">{ind.type}</Badge>
                        </TableCell>
                        <TableCell className="font-mono text-sm">{ind.value}</TableCell>
                        <TableCell>{ind.pulseCount}</TableCell>
                        <TableCell>
                          <span className={`font-semibold ${reputationColor(ind.reputationScore)}`}>
                            {ind.reputationScore}
                          </span>
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {ind.tags.map((tag) => (
                              <Badge key={tag} variant="secondary" className="text-xs">
                                {tag}
                              </Badge>
                            ))}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
