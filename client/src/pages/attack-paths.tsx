/**
 * Attack Path Visualization — backed by the SAME playbook engine the
 * Playbooks page uses (`attack-simulation.ts`: 6 MITRE-mapped chains, tested,
 * normalized category matching), not a separate hand-rolled heuristic.
 *
 * The previous version built its own attack-chain buckets from a hardcoded
 * category list that had drifted from the real taxonomy — `dns_security` and
 * `ssl_tls` do not exist as finding categories (the real ones are
 * `dns_misconfiguration` and `ssl_issue`), so the DNS half of the
 * reconnaissance node and the entire "Transport Security Attack Chain" could
 * never fire no matter what a workspace held. That is the same
 * category-vocabulary-drift bug this codebase has already found and fixed in
 * `compliance-mapper.ts` and `risk-factors.ts`.
 */
import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Shield, ArrowRight, Sparkles, Loader2, AlertTriangle } from "lucide-react";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface Finding {
  id: string;
  title: string;
  severity: string;
  category: string;
  affectedAsset: string | null;
}

interface PlaybookStep {
  order: number;
  action: string;
  description: string;
  severity: string;
}

interface Playbook {
  id: string;
  name: string;
  description: string;
  category: string;
  mitreTactics: string[];
  steps: PlaybookStep[];
}

interface SimulationResult {
  playbook: Playbook;
  exploitable: boolean;
  matchedSteps: Array<{ step: PlaybookStep; matchingFindings: Finding[] }>;
  riskScore: number;
  recommendations: string[];
  /** Same finding cited as evidence for 2+ different steps — reused evidence
   *  rather than distinct proof of progress along the chain. */
  lowConfidence: boolean;
}

interface VerificationCheck {
  label: string;
  status: string;
  summary: string;
}

interface AttackChainNarrative {
  narrative: string;
  priorityAction: string;
  lowConfidence?: boolean;
  verification?: VerificationCheck[];
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/15 border-red-500/40 text-red-700 dark:text-red-400",
  high: "bg-orange-500/15 border-orange-500/40 text-orange-700 dark:text-orange-400",
  medium: "bg-yellow-500/15 border-yellow-500/40 text-yellow-700 dark:text-yellow-400",
  low: "bg-blue-500/15 border-blue-500/40 text-blue-700 dark:text-blue-400",
  info: "bg-gray-500/15 border-gray-500/40 text-gray-700 dark:text-gray-400",
};

function StepCard({ step, findings }: { step: PlaybookStep; findings: Finding[] }) {
  const colorClass = SEVERITY_COLORS[step.severity] ?? SEVERITY_COLORS.info;
  return (
    <div className={`rounded-lg border-2 p-3 min-w-[180px] ${colorClass}`}>
      <div className="flex items-center gap-2 mb-1">
        <span className="font-semibold text-sm">{step.order}. {step.action}</span>
      </div>
      <p className="text-xs opacity-80 mb-1">{step.description}</p>
      <div className="text-xs opacity-80">
        {findings.length} matching finding{findings.length !== 1 ? "s" : ""}
      </div>
      <div className="mt-2 space-y-1 max-h-24 overflow-y-auto">
        {findings.slice(0, 3).map((f) => (
          <div key={f.id} className="truncate text-xs" title={f.title}>
            {f.title}
          </div>
        ))}
        {findings.length > 3 && (
          <div className="text-xs opacity-50">+{findings.length - 3} more</div>
        )}
      </div>
    </div>
  );
}

function AttackPathCard({ result, workspaceId }: { result: SimulationResult; workspaceId: string }) {
  const { toast } = useToast();
  const [narrative, setNarrative] = useState<AttackChainNarrative | null>(null);

  const explainMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest(
        "POST",
        `/api/workspaces/${workspaceId}/attack-paths/${result.playbook.id}/explain`,
        undefined,
        { timeoutMs: 120000 },
      );
      return res.json() as Promise<AttackChainNarrative>;
    },
    onSuccess: (data) => setNarrative(data),
    onError: (err: Error) => {
      toast({ title: "AI explanation failed", description: err.message, variant: "destructive" });
    },
  });

  return (
    <Card data-testid={`card-attack-path-${result.playbook.id}`}>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <CardTitle className="text-lg">{result.playbook.name}</CardTitle>
          <div className="flex items-center gap-2 flex-wrap">
            {result.playbook.mitreTactics.map((t) => (
              <Badge key={t} variant="outline" className="text-[10px] font-mono no-default-hover-elevate no-default-active-elevate">
                {t}
              </Badge>
            ))}
            <Badge variant={result.riskScore >= 50 ? "destructive" : result.riskScore >= 25 ? "default" : "secondary"}>
              Risk: {result.riskScore}
            </Badge>
            {result.lowConfidence && (
              <Badge
                variant="outline"
                className="gap-1 border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-400 no-default-hover-elevate no-default-active-elevate"
                data-testid={`badge-low-confidence-${result.playbook.id}`}
              >
                <AlertTriangle className="w-3 h-3" aria-hidden="true" />
                Low confidence
              </Badge>
            )}
          </div>
        </div>
        <p className="text-xs text-muted-foreground">{result.playbook.description}</p>
        {result.lowConfidence && (
          <p className="text-xs text-amber-700 dark:text-amber-400">
            The same finding is cited as evidence for more than one step below — this reads as a stretch, not a
            demonstrated chain.
          </p>
        )}
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex items-center gap-2 overflow-x-auto pb-2">
          {result.matchedSteps.map(({ step, matchingFindings }, idx) => (
            <div key={step.order} className="flex items-center gap-2 shrink-0">
              <StepCard step={step} findings={matchingFindings} />
              {idx < result.matchedSteps.length - 1 && (
                <ArrowRight className="w-5 h-5 text-muted-foreground shrink-0" aria-hidden="true" />
              )}
            </div>
          ))}
        </div>

        <div className="flex items-center justify-between gap-2 pt-2 border-t">
          <p className="text-xs text-muted-foreground">
            {result.exploitable ? "Majority of the chain is viable" : "Partial chain coverage"}
          </p>
          <Button
            variant="outline"
            size="sm"
            onClick={() => explainMutation.mutate()}
            disabled={explainMutation.isPending}
            data-testid={`button-explain-${result.playbook.id}`}
          >
            {explainMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
            {explainMutation.isPending ? "Asking GLM..." : narrative ? "Re-explain" : "Explain with AI"}
          </Button>
        </div>

        {narrative && (
          <div className="rounded-lg border bg-muted/30 p-3 space-y-2" data-testid={`text-narrative-${result.playbook.id}`}>
            <p className="text-sm leading-relaxed">{narrative.narrative}</p>
            {narrative.priorityAction && (
              <p className="text-xs">
                <span className="font-medium text-primary">Break the chain:</span> {narrative.priorityAction}
              </p>
            )}
            {narrative.verification && narrative.verification.length > 0 && (
              <div className="pt-2 border-t space-y-1">
                <p className="text-xs font-medium text-muted-foreground">Live verification (checked just now)</p>
                {narrative.verification.map((v, i) => (
                  <p key={i} className="text-xs text-muted-foreground">
                    <span className="font-medium">{v.label}</span> ({v.status}): {v.summary}
                  </p>
                ))}
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

interface AttackPathsResponse {
  chains: SimulationResult[];
  /** Chains that had matching findings but scored below the confidence floor
   *  — kept visible as a count so "nothing matched" and "something matched
   *  but wasn't confident enough to show" never look like the same state. */
  suppressedCount: number;
  /** Whether this workspace has any open security findings at all. False
   *  means there is genuinely nothing to build a chain from yet. */
  hasFindings: boolean;
}

function AttackPathsPage() {
  const { selectedWorkspace: workspace } = useDomain();

  const { data, isLoading } = useQuery<AttackPathsResponse>({
    queryKey: [`/api/workspaces/${workspace?.id}/attack-paths`],
    enabled: !!workspace,
  });
  const attackPaths = data?.chains ?? [];
  const suppressedCount = data?.suppressedCount ?? 0;
  const hasFindings = data?.hasFindings ?? false;

  if (!workspace) {
    return (
      <div className="p-6">
        <p className="text-muted-foreground">Select a workspace to view attack paths.</p>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Attack Path Visualization</h1>
        <p className="text-muted-foreground">
          MITRE ATT&CK-mapped chains matched against this workspace's open findings. Each chain can be explained by
          GLM, grounded strictly in the findings already matched below — it narrates and prioritizes, it does not
          invent steps.
        </p>
      </div>

      {isLoading ? (
        <p className="text-muted-foreground">Analyzing attack paths...</p>
      ) : attackPaths.length === 0 ? (
        <Card>
          <CardContent className="p-8 text-center">
            <Shield className="w-12 h-12 mx-auto mb-4 text-green-500/40" />
            {!hasFindings ? (
              <p className="text-muted-foreground">
                No open security findings in this workspace yet. Run a scan to discover potential vulnerability
                chains.
              </p>
            ) : suppressedCount > 0 ? (
              <div className="space-y-1">
                <p className="text-muted-foreground">
                  No attack chain currently meets the confidence threshold to display.
                </p>
                <p className="text-xs text-muted-foreground">
                  {suppressedCount} partial match{suppressedCount !== 1 ? "es were" : " was"} found but scored too low
                  to show — usually one weak, generic finding stretched across steps it doesn't really evidence,
                  rather than a demonstrated chain. This is expected and not a sign anything is broken.
                </p>
              </div>
            ) : (
              <p className="text-muted-foreground">
                No attack chain matches this workspace's current findings.
              </p>
            )}
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-3 gap-4">
            <Card>
              <CardContent className="p-4 text-center">
                <div className="text-3xl font-bold">{attackPaths.length}</div>
                <div className="text-sm text-muted-foreground">Attack Chains</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4 text-center">
                <div className="text-3xl font-bold text-red-500">
                  {attackPaths.filter((p) => p.riskScore >= 50).length}
                </div>
                <div className="text-sm text-muted-foreground">High Risk Paths</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4 text-center">
                <div className="text-3xl font-bold">
                  {attackPaths.reduce((max, p) => Math.max(max, p.riskScore), 0)}
                </div>
                <div className="text-sm text-muted-foreground">Max Risk Score</div>
              </CardContent>
            </Card>
          </div>

          <div className="space-y-4">
            {attackPaths.map((result) => (
              <AttackPathCard key={result.playbook.id} result={result} workspaceId={workspace.id} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}

export default AttackPathsPage;
