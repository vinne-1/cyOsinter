/**
 * AI Insights, surfaced inside Intelligence rather than only on its own page.
 *
 * This is the same persisted synthesis `/ai-insights` page reads and writes —
 * one source of truth (`ai_insights_snapshots`, one row per workspace) shown
 * in two places, not a second implementation that could drift from the first.
 *
 * Like `ip_reputation`, this tab has no backing `recon_modules` row (writing
 * one would feed the AI's own past output back into its next prompt as
 * "recon intelligence"), so it is special-cased into `availableModules` in
 * `index.tsx` rather than keyed off `modulesByType`.
 */
import { Link } from "wouter";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Sparkles, Loader2, AlertTriangle, Radar, ArrowUpRight } from "lucide-react";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface VerificationCheck {
  id: string;
  label: string;
  status: string;
  summary: string;
}

interface WorkspaceInsightsResult {
  summary: string;
  keyRisks: string[];
  threatLandscape: string;
  isAIGenerated?: boolean;
  verification?: VerificationCheck[];
}

interface AiInsightsData {
  workspaceName: string;
  lastSummary: (WorkspaceInsightsResult & { generatedAt: string }) | null;
}

export function AiInsightsPanel() {
  const { selectedWorkspaceId } = useDomain();
  const { toast } = useToast();

  const { data, isLoading } = useQuery<AiInsightsData>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/ai-insights`],
    enabled: !!selectedWorkspaceId,
  });

  const generateMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/workspaces/${selectedWorkspaceId}/ai-insights/summary`, undefined, {
        timeoutMs: 1800000,
      });
      return res.json() as Promise<WorkspaceInsightsResult>;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/ai-insights`] });
      toast({ title: "AI insights generated" });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to generate insights", description: err.message, variant: "destructive" });
    },
  });

  const snapshot = data?.lastSummary ?? null;

  return (
    <div className="space-y-4" data-testid="panel-ai-insights">
      <div className="flex items-center justify-between gap-3 mb-2 flex-wrap">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-9 h-9 rounded-md bg-primary/10 flex-shrink-0">
            <Sparkles className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h3 className="text-base font-semibold">AI Insights</h3>
            {snapshot && (
              <p className="text-[10px] text-muted-foreground">
                {new Date(snapshot.generatedAt).toLocaleString()}
              </p>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => generateMutation.mutate()}
            disabled={generateMutation.isPending}
            data-testid="button-generate-insights-panel"
          >
            {generateMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
            {generateMutation.isPending ? "Generating..." : snapshot ? "Regenerate" : "Generate"}
          </Button>
          <Link href="/ai-insights">
            <Button variant="ghost" size="sm" data-testid="link-full-ai-insights">
              Full page <ArrowUpRight className="w-3.5 h-3.5 ml-1" />
            </Button>
          </Link>
        </div>
      </div>

      {isLoading ? (
        <p className="text-sm text-muted-foreground py-8 text-center">Loading…</p>
      ) : !snapshot ? (
        <Card>
          <CardContent className="py-10 text-center">
            <Sparkles className="w-10 h-10 text-muted-foreground/50 mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">No AI synthesis yet for this workspace.</p>
            <p className="text-xs text-muted-foreground mt-1">
              Click Generate to have GLM correlate findings, recon data and CVEs, and verify the result against the
              workspace's live hosts.
            </p>
          </CardContent>
        </Card>
      ) : (
        <>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                Executive Summary
                <Badge
                  variant="outline"
                  className={`text-xs border-0 no-default-hover-elevate no-default-active-elevate ${
                    snapshot.isAIGenerated ? "bg-emerald-600/15 text-emerald-400" : "bg-amber-600/15 text-amber-400"
                  }`}
                >
                  {snapshot.isAIGenerated ? "AI-generated" : "Fallback"}
                </Badge>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-sm leading-relaxed">{snapshot.summary}</p>
              {snapshot.keyRisks.length > 0 && (
                <ul className="space-y-1">
                  {snapshot.keyRisks.slice(0, 4).map((risk, i) => (
                    <li key={i} className="flex items-start gap-2 text-xs">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-500 flex-shrink-0 mt-0.5" />
                      {risk}
                    </li>
                  ))}
                  {snapshot.keyRisks.length > 4 && (
                    <li className="text-xs text-muted-foreground pl-5">+ {snapshot.keyRisks.length - 4} more on the full page</li>
                  )}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Radar className="w-4 h-4" /> Live Verification
              </CardTitle>
            </CardHeader>
            <CardContent>
              {snapshot.verification === undefined ? (
                <p className="text-xs text-muted-foreground py-2">Not run for this summary — regenerate to include it.</p>
              ) : snapshot.verification.length === 0 ? (
                <p className="text-xs text-muted-foreground py-2">No usable domain to verify for this workspace.</p>
              ) : (
                <div className="space-y-1.5">
                  {snapshot.verification.map((check) => (
                    <div key={check.id} className="flex items-start gap-2 text-xs">
                      <Badge variant="outline" className="text-[10px] border-0 no-default-hover-elevate no-default-active-elevate flex-shrink-0">
                        {check.status}
                      </Badge>
                      <span>
                        <span className="font-medium">{check.label}:</span> {check.summary}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
