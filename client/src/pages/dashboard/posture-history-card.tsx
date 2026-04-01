import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import {
  Activity,
  ArrowUpRight,
  Loader2,
} from "lucide-react";
import type { PostureSnapshot } from "@shared/schema";
import { Link } from "wouter";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

export function PostureHistoryCard({ workspaceId }: { workspaceId: string | null }) {
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
              {backfillMutation.isPending ? " Syncing..." : " Sync from completed scans"}
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
