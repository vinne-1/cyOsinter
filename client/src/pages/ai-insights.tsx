import { useState } from "react";
import { Link } from "wouter";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Sparkles,
  Loader2,
  AlertTriangle,
  ExternalLink,
  ShieldAlert,
  ChevronRight,
  Inbox,
} from "lucide-react";
import type { Finding, ReconModule } from "@shared/schema";
import { SeverityBadge } from "@/components/severity-badge";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface WorkspaceInsightsData {
  findings: Finding[];
  modules: ReconModule[];
  workspaceName: string;
}

interface WorkspaceInsightsResult {
  summary: string;
  keyRisks: string[];
  threatLandscape: string;
  /** true = AI-generated, false = fallback (rule-based, no LLM) */
  isAIGenerated?: boolean;
  /** When fallback: why AI was not used */
  fallbackReason?: "ollama_disabled" | "ollama_timeout" | "ollama_error";
  /** When fallback: actual error message for debugging */
  fallbackErrorDetail?: string;
}

export default function AIInsights() {
  const { selectedWorkspaceId } = useDomain();
  const { toast } = useToast();
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);

  const { data: insightsData, isLoading } = useQuery<WorkspaceInsightsData>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId ?? ""}/ai-insights`],
    enabled: !!selectedWorkspaceId,
  });

  const summaryMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/workspaces/${selectedWorkspaceId}/ai-insights/summary`, undefined, {
        timeoutMs: 1800000, // 30 min for CVE fetch + Tavily + Ollama inference
      });
      return res.json() as Promise<WorkspaceInsightsResult>;
    },
    onSuccess: (data) => {
      setSummary(data);
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/ai-insights`] });
      const fallbackDesc = data.isAIGenerated
        ? undefined
        : data.fallbackErrorDetail
          ? data.fallbackErrorDetail.slice(0, 80) + (data.fallbackErrorDetail.length > 80 ? "…" : "")
          : "Ollama was unavailable; showing rule-based summary.";
      toast({
        title: data.isAIGenerated ? "AI insights generated" : "Summary generated (fallback)",
        description: fallbackDesc,
      });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to generate insights", description: err.message, variant: "destructive" });
    },
  });

  const [summary, setSummary] = useState<WorkspaceInsightsResult | null>(null);

  if (!selectedWorkspaceId) {
    return (
      <div className="p-6">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-16">
            <Inbox className="w-12 h-12 text-muted-foreground mb-4" />
            <p className="text-muted-foreground">Select a workspace to view AI insights</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-48 w-full" />
        <Skeleton className="h-96 w-full" />
      </div>
    );
  }

  const findings = insightsData?.findings ?? [];
  const workspaceName = insightsData?.workspaceName ?? "Workspace";

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold flex items-center gap-2">
          <Sparkles className="w-6 h-6 text-primary" />
          AI Insights
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          AI-powered synthesis of intelligence for {workspaceName}
        </p>
      </div>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2">
          <CardTitle className="text-base">Executive Summary</CardTitle>
          <Button
            variant="outline"
            size="sm"
            onClick={() => summaryMutation.mutate()}
            disabled={summaryMutation.isPending}
          >
            {summaryMutation.isPending ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Sparkles className="w-4 h-4" />
            )}
            {summaryMutation.isPending ? "Generating..." : "Generate"}
          </Button>
        </CardHeader>
        <CardContent className="space-y-4">
          {summary ? (
            <>
              <div className="flex items-center gap-2 mb-2">
                <Badge
                  variant="outline"
                  className={
                    summary.isAIGenerated
                      ? "bg-emerald-600/15 text-emerald-400 border-emerald-500/30"
                      : "bg-amber-600/15 text-amber-400 border-amber-500/30"
                  }
                >
                  {summary.isAIGenerated ? (
                    <>
                      <Sparkles className="w-3 h-3 mr-1" />
                      AI-generated
                    </>
                  ) : (
                    <>Fallback summary (not AI-generated)</>
                  )}
                </Badge>
              </div>
              <div
                className={
                  summary.isAIGenerated === false
                    ? "rounded-lg border border-amber-500/20 bg-amber-500/5 p-4 space-y-4"
                    : "space-y-4"
                }
              >
                {summary.isAIGenerated === false && (
                  <div className="space-y-2">
                    <p className="text-xs text-muted-foreground">
                      {summary.fallbackReason === "ollama_disabled"
                        ? "Turn on Enable AI in Integrations and click Save to use AI-generated insights."
                        : summary.fallbackReason === "ollama_timeout"
                          ? "Request timed out. Try a smaller model (smollm2:135m or tinyllama) or free up CPU/memory."
                          : "Ollama error. Check Integrations—ensure Ollama is running and the model is pulled."}{" "}
                      <Link href="/integrations" className="text-primary hover:underline">Integrations</Link>
                    </p>
                    {summary.fallbackErrorDetail && (
                      <div className="rounded border border-amber-500/30 bg-amber-500/5 p-2">
                        <p className="text-xs font-medium text-amber-600 dark:text-amber-500 mb-1">Error details (copy for debugging):</p>
                        <pre
                          className="text-xs font-mono text-muted-foreground overflow-x-auto whitespace-pre-wrap break-words cursor-text select-all"
                          onClick={(e) => {
                            const target = e.currentTarget;
                            navigator.clipboard.writeText(target.textContent ?? "");
                            toast({ title: "Copied to clipboard" });
                          }}
                          title="Click to copy"
                        >
                          {summary.fallbackErrorDetail}
                        </pre>
                      </div>
                    )}
                  </div>
                )}
                <p className="text-sm leading-relaxed">{summary.summary}</p>
                {summary.keyRisks.length > 0 && (
                  <div>
                    <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2">Key Risks</h4>
                    <ul className="space-y-1">
                      {summary.keyRisks.map((risk, i) => (
                        <li key={i} className="flex items-start gap-2 text-sm">
                          <AlertTriangle className="w-4 h-4 text-amber-500 flex-shrink-0 mt-0.5" />
                          {risk}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {summary.threatLandscape && (
                  <div>
                    <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2">Threat Landscape</h4>
                    <p className="text-sm leading-relaxed">{summary.threatLandscape}</p>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="py-8 text-center">
              <Sparkles className="w-10 h-10 text-muted-foreground/50 mx-auto mb-3" />
              <p className="text-sm text-muted-foreground">Click Generate to create AI insights from findings and intelligence data</p>
              <p className="text-xs text-muted-foreground mt-1">
                Enable Ollama in <Link href="/integrations" className="text-primary hover:underline">Integrations</Link> for AI-generated insights, or use the summary below
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Findings with CVE Context</CardTitle>
          <p className="text-xs text-muted-foreground mt-1">
            {findings.length} findings. Use CVE lookup and Detailed Analysis in the Findings page.
          </p>
        </CardHeader>
        <CardContent>
          {findings.length === 0 ? (
            <p className="text-sm text-muted-foreground py-8 text-center">No findings yet. Run a scan to discover issues.</p>
          ) : (
            <div className="space-y-3">
              {findings.slice(0, 20).map((f) => {
                const cveData = f.aiEnrichment as { cveData?: { cveIds?: string[]; records?: Array<{ cveId: string; cvssScore?: number; url: string }> } } | null | undefined;
                const cveRecords = cveData?.cveData?.records ?? [];
                const hasCve = cveRecords.length > 0;
                const detailedAnalysis = f.aiEnrichment as { detailedAnalysis?: { analysis?: string; recommendations?: string[] } } | null | undefined;
                const hasAnalysis = !!detailedAnalysis?.detailedAnalysis?.analysis;

                return (
                  <div
                    key={f.id}
                    className="rounded-lg border bg-card overflow-hidden"
                  >
                    <div
                      className="flex items-center justify-between gap-4 p-3 hover:bg-muted/30 transition-colors cursor-pointer"
                      onClick={() => setExpandedFindingId(expandedFindingId === f.id ? null : f.id)}
                    >
                      <div className="flex items-center gap-3 min-w-0 flex-1">
                        <ShieldAlert className="w-5 h-5 text-muted-foreground flex-shrink-0" />
                        <div className="min-w-0">
                          <p className="font-medium truncate">{f.title}</p>
                          <div className="flex items-center gap-2 flex-wrap mt-1">
                            <SeverityBadge severity={f.severity} />
                            {hasCve && (
                              <div className="flex gap-1 flex-wrap">
                                {cveRecords.slice(0, 3).map((c) => (
                                  <a
                                    key={c.cveId}
                                    href={c.url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    onClick={(e) => e.stopPropagation()}
                                    className="inline-flex items-center gap-1 text-xs"
                                  >
                                    <Badge variant="outline" className="text-[10px] font-mono no-default-hover-elevate no-default-active-elevate">
                                      {c.cveId}
                                      {c.cvssScore != null ? ` (${c.cvssScore})` : ""}
                                    </Badge>
                                    <ExternalLink className="w-3 h-3" />
                                  </a>
                                ))}
                              </div>
                            )}
                            {hasAnalysis && (
                              <Badge variant="outline" className="text-[10px] bg-green-600/15 text-green-400 border-0 no-default-hover-elevate no-default-active-elevate">
                                Analyzed
                              </Badge>
                            )}
                          </div>
                        </div>
                      </div>
                      <ChevronRight className={`w-4 h-4 transition-transform flex-shrink-0 ${expandedFindingId === f.id ? "rotate-90" : ""}`} />
                    </div>
                    {expandedFindingId === f.id && hasAnalysis && (
                      <div className="border-t bg-muted/20 p-4 space-y-3">
                        <p className="text-sm leading-relaxed">{detailedAnalysis?.detailedAnalysis?.analysis}</p>
                        {(detailedAnalysis?.detailedAnalysis?.recommendations?.length ?? 0) > 0 && (
                          <div>
                            <h5 className="text-xs font-medium text-muted-foreground mb-2">Recommendations</h5>
                            <ul className="list-disc list-inside space-y-1 text-sm">
                              {detailedAnalysis?.detailedAnalysis?.recommendations?.map((r, i) => (
                                <li key={i}>{r}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
              {findings.length > 20 && (
                <p className="text-xs text-muted-foreground text-center py-2">+ {findings.length - 20} more findings</p>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
