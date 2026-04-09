import { useQuery } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

interface DriftFinding {
  id: string;
  title: string;
  severity: string;
  category: string;
  affectedAsset: string | null;
  changeType: "new" | "resolved" | "unchanged";
}

interface ComplianceDriftReport {
  currentScanId: string | null;
  previousScanId: string | null;
  currentScore: number | null;
  previousScore: number | null;
  scoreDelta: number | null;
  trend: "improving" | "degrading" | "stable" | "initial";
  newFindings: DriftFinding[];
  resolvedFindings: DriftFinding[];
  unchangedFailingFindings: number;
  generatedAt: string;
}

export default function ComplianceDriftPage() {
  const { selectedWorkspaceId } = useDomain();

  const { data, isLoading } = useQuery<ComplianceDriftReport>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/compliance-drift`],
    enabled: !!selectedWorkspaceId,
  });

  if (!selectedWorkspaceId) {
    return (
      <div className="space-y-4 p-6">
        <h1 className="text-2xl font-semibold tracking-tight">Compliance Drift</h1>
        <p className="text-sm text-muted-foreground">Select a workspace to inspect scan-to-scan drift.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Compliance Drift</h1>
        <p className="text-sm text-muted-foreground">Compare latest completed scan with the previous baseline.</p>
      </div>

      {isLoading ? <p className="text-sm text-muted-foreground">Loading drift report...</p> : null}

      {data ? (
        <>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card><CardContent className="p-4"><p className="text-xs text-muted-foreground">Current Score</p><p className="text-2xl font-semibold">{data.currentScore ?? "Not assessed"}</p></CardContent></Card>
            <Card><CardContent className="p-4"><p className="text-xs text-muted-foreground">Previous Score</p><p className="text-2xl font-semibold">{data.previousScore ?? "Not assessed"}</p></CardContent></Card>
            <Card><CardContent className="p-4"><p className="text-xs text-muted-foreground">Delta</p><p className="text-2xl font-semibold">{data.scoreDelta === null ? "N/A" : `${data.scoreDelta > 0 ? "+" : ""}${data.scoreDelta}`}</p></CardContent></Card>
            <Card><CardContent className="p-4"><p className="text-xs text-muted-foreground">Trend</p><p className="text-2xl font-semibold capitalize">{data.trend}</p></CardContent></Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Drift Summary</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <p>New findings: <strong>{data.newFindings.length}</strong></p>
              <p>Resolved findings: <strong>{data.resolvedFindings.length}</strong></p>
              <p>Unchanged failing findings: <strong>{data.unchangedFailingFindings}</strong></p>
            </CardContent>
          </Card>

          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader><CardTitle className="text-base">New Findings</CardTitle></CardHeader>
              <CardContent className="space-y-2">
                {data.newFindings.length === 0 ? <p className="text-sm text-muted-foreground">No new failing findings.</p> : data.newFindings.map((f) => (
                  <div key={f.id} className="rounded-md border p-3">
                    <div className="flex items-center gap-2">
                      <p className="font-medium text-sm">{f.title}</p>
                      <Badge variant="outline">{f.severity}</Badge>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">{f.category}{f.affectedAsset ? ` • ${f.affectedAsset}` : ""}</p>
                  </div>
                ))}
              </CardContent>
            </Card>

            <Card>
              <CardHeader><CardTitle className="text-base">Resolved Findings</CardTitle></CardHeader>
              <CardContent className="space-y-2">
                {data.resolvedFindings.length === 0 ? <p className="text-sm text-muted-foreground">No findings resolved since previous scan.</p> : data.resolvedFindings.map((f) => (
                  <div key={f.id} className="rounded-md border p-3">
                    <div className="flex items-center gap-2">
                      <p className="font-medium text-sm">{f.title}</p>
                      <Badge variant="outline">{f.severity}</Badge>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">{f.category}{f.affectedAsset ? ` • ${f.affectedAsset}` : ""}</p>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        </>
      ) : null}
    </div>
  );
}

