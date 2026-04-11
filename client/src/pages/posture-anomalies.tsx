import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ActivitySquare, TrendingUp, TrendingDown, CheckCircle } from "lucide-react";
import { buildUrl } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface PostureAnomaly {
  id: string;
  workspaceId: string;
  metric: string;
  detectedAt: string;
  baselineValue: string | null;
  currentValue: string | null;
  deviationSigma: string | null;
  direction: "improvement" | "regression";
  severity: "info" | "warning" | "critical";
  acknowledged: boolean;
}

interface ForecastPoint { day: number; value: number }
interface ForecastResponse { metric: string; daysAhead: number; forecast: ForecastPoint[] }

const SEVERITY_CLASSES: Record<string, string> = {
  critical: "border-red-500/40 bg-red-500/5",
  warning: "border-yellow-500/40 bg-yellow-500/5",
  info: "border-blue-500/40 bg-blue-500/5",
};

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-500/15 text-red-600 border-red-500/30",
  warning: "bg-yellow-500/15 text-yellow-600 border-yellow-500/30",
  info: "bg-blue-500/15 text-blue-600 border-blue-500/30",
};

const METRIC_LABELS: Record<string, string> = {
  securityScore: "Security Score",
  criticalCount: "Critical Findings",
  openPortsCount: "Open Ports",
  wafCoverage: "WAF Coverage",
};

function AnomalyCard({ anomaly, onAcknowledge }: { anomaly: PostureAnomaly; onAcknowledge: (id: string) => void }) {
  const sevClass = SEVERITY_CLASSES[anomaly.severity] ?? SEVERITY_CLASSES.warning;
  const badgeClass = SEVERITY_BADGE[anomaly.severity] ?? SEVERITY_BADGE.warning;
  const isRegression = anomaly.direction === "regression";

  return (
    <div className={`border rounded-lg p-4 space-y-2 ${sevClass} ${anomaly.acknowledged ? "opacity-50" : ""}`}>
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          {isRegression
            ? <TrendingDown className="w-4 h-4 text-red-500 shrink-0" />
            : <TrendingUp className="w-4 h-4 text-green-500 shrink-0" />}
          <div>
            <p className="font-medium text-sm">{METRIC_LABELS[anomaly.metric] ?? anomaly.metric}</p>
            <p className="text-xs text-muted-foreground">
              {new Date(anomaly.detectedAt).toLocaleString()}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Badge variant="outline" className={`text-xs capitalize ${badgeClass}`}>
            {anomaly.severity}
          </Badge>
          {!anomaly.acknowledged && (
            <Button
              variant="ghost"
              size="sm"
              className="h-7 px-2 text-xs"
              onClick={() => onAcknowledge(anomaly.id)}
            >
              <CheckCircle className="w-3.5 h-3.5 mr-1" />
              Ack
            </Button>
          )}
          {anomaly.acknowledged && (
            <Badge variant="secondary" className="text-xs">Acknowledged</Badge>
          )}
        </div>
      </div>

      <div className="grid grid-cols-3 gap-3 text-xs">
        <div>
          <p className="text-muted-foreground">Baseline</p>
          <p className="font-mono font-medium">
            {anomaly.baselineValue != null ? Number(anomaly.baselineValue).toFixed(1) : "—"}
          </p>
        </div>
        <div>
          <p className="text-muted-foreground">Current</p>
          <p className={`font-mono font-medium ${isRegression ? "text-red-500" : "text-green-500"}`}>
            {anomaly.currentValue != null ? Number(anomaly.currentValue).toFixed(1) : "—"}
          </p>
        </div>
        <div>
          <p className="text-muted-foreground">Deviation</p>
          <p className="font-mono font-medium">
            {anomaly.deviationSigma != null ? `${Number(anomaly.deviationSigma).toFixed(2)}σ` : "—"}
          </p>
        </div>
      </div>
    </div>
  );
}

function ForecastChart({ forecast, metric }: { forecast: ForecastPoint[]; metric: string }) {
  if (forecast.length === 0) return null;
  const values = forecast.map((p) => p.value);
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min || 1;

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-base">
          {METRIC_LABELS[metric] ?? metric} — 30-Day Forecast
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex items-end gap-0.5 h-20">
          {forecast.map((p) => {
            const heightPct = ((p.value - min) / range) * 100;
            return (
              <div
                key={p.day}
                className="flex-1 bg-primary/40 rounded-sm min-h-[2px]"
                style={{ height: `${Math.max(heightPct, 4)}%` }}
                title={`Day ${p.day}: ${p.value.toFixed(1)}`}
              />
            );
          })}
        </div>
        <div className="flex justify-between text-xs text-muted-foreground mt-1">
          <span>Today</span>
          <span>+30 days</span>
        </div>
        <div className="flex justify-between text-xs text-muted-foreground">
          <span className="font-mono">{forecast[0]?.value.toFixed(1)}</span>
          <span className="font-mono">{forecast[forecast.length - 1]?.value.toFixed(1)}</span>
        </div>
      </CardContent>
    </Card>
  );
}

export default function PostureAnomaliesPage() {
  const { selectedWorkspace: ws } = useDomain();
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data: anomalies = [], isLoading } = useQuery<PostureAnomaly[]>({
    queryKey: [`/api/workspaces/${ws?.id}/anomalies`],
    enabled: !!ws,
  });

  const { data: forecast } = useQuery<ForecastResponse>({
    queryKey: [`/api/workspaces/${ws?.id}/forecast`, "securityScore"],
    queryFn: () =>
      fetch(buildUrl(`/api/workspaces/${ws!.id}/forecast?metric=securityScore&days=30`), {
        headers: { Authorization: `Bearer ${localStorage.getItem("auth_token")}` },
      }).then((r) => r.json()),
    enabled: !!ws,
  });

  const { mutate: acknowledge } = useMutation({
    mutationFn: (id: string) =>
      fetch(buildUrl(`/api/workspaces/${ws!.id}/anomalies/${id}/acknowledge`), {
        method: "POST",
        headers: { Authorization: `Bearer ${localStorage.getItem("auth_token")}` },
      }).then((r) => r.json()),
    onSuccess: () => {
      toast({ title: "Anomaly acknowledged" });
      qc.invalidateQueries({ queryKey: [`/api/workspaces/${ws?.id}/anomalies`] });
    },
  });

  if (!ws) return <div className="p-6 text-muted-foreground">Select a workspace.</div>;

  const unacked = anomalies.filter((a) => !a.acknowledged);
  const regressions = anomalies.filter((a) => a.direction === "regression" && !a.acknowledged);
  const criticalCount = anomalies.filter((a) => a.severity === "critical" && !a.acknowledged).length;

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <ActivitySquare className="w-6 h-6 text-primary" />
          Posture Anomalies
        </h1>
        <p className="text-muted-foreground">
          Statistical anomaly detection on security posture metrics using rolling z-score analysis.
        </p>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <Card className={criticalCount > 0 ? "border-red-500/40" : ""}>
          <CardContent className="p-4 text-center">
            <div className={`text-3xl font-bold ${criticalCount > 0 ? "text-red-500" : ""}`}>
              {criticalCount}
            </div>
            <div className="text-sm text-muted-foreground">Critical Anomalies</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-3xl font-bold text-orange-500">{regressions.length}</div>
            <div className="text-sm text-muted-foreground">Active Regressions</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <div className="text-3xl font-bold">{unacked.length}</div>
            <div className="text-sm text-muted-foreground">Unacknowledged</div>
          </CardContent>
        </Card>
      </div>

      {forecast && forecast.forecast.length > 0 && (
        <ForecastChart forecast={forecast.forecast} metric={forecast.metric} />
      )}

      {isLoading ? (
        <p className="text-muted-foreground">Loading anomalies...</p>
      ) : anomalies.length === 0 ? (
        <Card><CardContent className="p-8 text-center">
          <ActivitySquare className="w-12 h-12 mx-auto mb-4 text-muted-foreground/40" />
          <p className="text-muted-foreground">No anomalies detected. Run scans to build posture history.</p>
        </CardContent></Card>
      ) : (
        <div className="space-y-3">
          {anomalies.map((a) => (
            <AnomalyCard key={a.id} anomaly={a} onAcknowledge={acknowledge} />
          ))}
        </div>
      )}
    </div>
  );
}
