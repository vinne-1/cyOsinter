import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Zap, RefreshCw, AlertTriangle } from "lucide-react";
import { buildUrl } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface PriorityEntry {
  findingId: string;
  rank: number;
  compositeScore: number;
  components: {
    cvss: number;
    epss: number;
    kev: number;
    exposure: number;
    age: number;
  };
  computedAt: string;
  finding: {
    id: string;
    title: string;
    severity: string;
    category: string;
    affectedAsset: string | null;
    status: string;
    cvssScore: string | null;
    discoveredAt: string;
  };
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/15 text-red-600 border-red-500/30",
  high: "bg-orange-500/15 text-orange-600 border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-600 border-yellow-500/30",
  low: "bg-blue-500/15 text-blue-600 border-blue-500/30",
  info: "bg-gray-500/15 text-gray-600 border-gray-500/30",
};

function ScoreBar({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="w-16 text-muted-foreground shrink-0">{label}</span>
      <Progress value={Math.round(value * 100)} className={`h-1.5 flex-1 ${color}`} />
      <span className="w-8 text-right font-mono">{Math.round(value * 100)}%</span>
    </div>
  );
}

function PriorityCard({ entry }: { entry: PriorityEntry }) {
  const { finding, components, compositeScore, rank } = entry;
  const sevColor = SEVERITY_COLORS[finding.severity?.toLowerCase() ?? "info"] ?? SEVERITY_COLORS.info;

  return (
    <Card>
      <CardContent className="p-4 space-y-3">
        <div className="flex items-start gap-3">
          <div className="shrink-0 w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center text-sm font-bold">
            {rank}
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-medium text-sm truncate">{finding.title}</span>
              <Badge variant="outline" className={`text-xs ${sevColor}`}>{finding.severity}</Badge>
              {components.kev === 1 && (
                <Badge variant="destructive" className="text-[10px] px-1">KEV</Badge>
              )}
            </div>
            {finding.affectedAsset && (
              <p className="text-xs text-muted-foreground mt-0.5 font-mono truncate">{finding.affectedAsset}</p>
            )}
          </div>
          <div className="shrink-0 text-right">
            <div className="text-lg font-bold">{compositeScore.toFixed(1)}</div>
            <div className="text-xs text-muted-foreground">score</div>
          </div>
        </div>

        <div className="space-y-1">
          <ScoreBar label="CVSS" value={components.cvss} color="" />
          <ScoreBar label="EPSS" value={components.epss} color="" />
          <ScoreBar label="Exposure" value={components.exposure} color="" />
          <ScoreBar label="Age" value={components.age} color="" />
        </div>
      </CardContent>
    </Card>
  );
}

export default function SmartPriorityPage() {
  const { selectedWorkspace: ws } = useDomain();
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data: priorities = [], isLoading } = useQuery<PriorityEntry[]>({
    queryKey: [`/api/workspaces/${ws?.id}/priorities`],
    enabled: !!ws,
  });

  const { mutate: refresh, isPending: refreshing } = useMutation({
    mutationFn: () =>
      fetch(buildUrl(`/api/workspaces/${ws!.id}/priorities/refresh`), { method: "POST" }).then((r) => r.json()),
    onSuccess: () => {
      toast({ title: "Priority computation started" });
      setTimeout(() => qc.invalidateQueries({ queryKey: [`/api/workspaces/${ws?.id}/priorities`] }), 5000);
    },
  });

  if (!ws) return <div className="p-6 text-muted-foreground">Select a workspace.</div>;

  const kevCount = priorities.filter((p) => p.components.kev === 1).length;
  const topScore = priorities[0]?.compositeScore ?? 0;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Zap className="w-6 h-6 text-yellow-500" />
            Fix This First
          </h1>
          <p className="text-muted-foreground">
            Findings ranked by composite risk: CVSS × EPSS exploitability × KEV presence × exposure × age.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refresh()} disabled={refreshing}>
          <RefreshCw className={`w-4 h-4 mr-2 ${refreshing ? "animate-spin" : ""}`} />
          Recompute
        </Button>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-3xl font-bold">{priorities.length}</div>
            <div className="text-sm text-muted-foreground">Ranked Findings</div>
          </CardContent>
        </Card>
        <Card className={kevCount > 0 ? "border-red-500/40" : ""}>
          <CardContent className="p-4 text-center">
            <div className={`text-3xl font-bold ${kevCount > 0 ? "text-red-500" : ""}`}>{kevCount}</div>
            <div className="text-sm text-muted-foreground">CISA KEV Findings</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-3xl font-bold">{topScore.toFixed(1)}</div>
            <div className="text-sm text-muted-foreground">Highest Risk Score</div>
          </CardContent>
        </Card>
      </div>

      {isLoading ? (
        <p className="text-muted-foreground">Computing priorities...</p>
      ) : priorities.length === 0 ? (
        <Card><CardContent className="p-8 text-center">
          <AlertTriangle className="w-12 h-12 mx-auto mb-4 text-muted-foreground/40" />
          <p className="text-muted-foreground">No priority data. Run a scan and click Recompute.</p>
        </CardContent></Card>
      ) : (
        <div className="space-y-3">
          {priorities.map((p) => <PriorityCard key={p.findingId} entry={p} />)}
        </div>
      )}
    </div>
  );
}
