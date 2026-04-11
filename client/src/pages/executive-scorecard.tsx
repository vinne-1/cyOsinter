import { useQuery } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, TrendingUp, TrendingDown, Minus, AlertTriangle, CheckCircle, Clock } from "lucide-react";

interface ComplianceSummary { framework: string; score: number; delta: number | null }
interface TopAsset { hostname: string; riskScore: number; criticalFindings: number }
interface SuggestedFix { title: string; impact: string; effort: "low" | "medium" | "high"; affectedAssets: number }
interface Scorecard {
  generatedAt: string;
  target: string;
  securityScore: number;
  securityScoreDelta: number | null;
  totalOpenFindings: number;
  criticalOpen: number;
  highOpen: number;
  avgMttrHours: number | null;
  slaBreach: number;
  compliance: ComplianceSummary[];
  topRiskyAssets: TopAsset[];
  suggestedFixes: SuggestedFix[];
  trend: "improving" | "stable" | "degrading";
}

const EFFORT_COLORS: Record<string, string> = {
  low: "bg-green-500/15 text-green-600 border-green-500/30",
  medium: "bg-yellow-500/15 text-yellow-600 border-yellow-500/30",
  high: "bg-red-500/15 text-red-600 border-red-500/30",
};

function TrendIcon({ trend }: { trend: Scorecard["trend"] }) {
  if (trend === "improving") return <TrendingUp className="w-5 h-5 text-green-500" />;
  if (trend === "degrading") return <TrendingDown className="w-5 h-5 text-red-500" />;
  return <Minus className="w-5 h-5 text-muted-foreground" />;
}

function DeltaBadge({ delta }: { delta: number | null }) {
  if (delta == null) return null;
  const color = delta > 0 ? "text-green-600" : delta < 0 ? "text-red-600" : "text-muted-foreground";
  return <span className={`text-sm font-medium ${color}`}>{delta > 0 ? "+" : ""}{delta} pts</span>;
}

export default function ExecutiveScorecardPage() {
  const { selectedWorkspace: ws } = useDomain();

  const { data: sc, isLoading } = useQuery<Scorecard>({
    queryKey: [`/api/workspaces/${ws?.id}/scorecard`],
    enabled: !!ws,
  });

  if (!ws) return <div className="p-6 text-muted-foreground">Select a workspace.</div>;

  if (isLoading) return <div className="p-6 text-muted-foreground">Building scorecard...</div>;
  if (!sc) return <div className="p-6 text-muted-foreground">No scorecard data available.</div>;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Executive Risk Scorecard</h1>
          <p className="text-muted-foreground">{sc.target} · Generated {new Date(sc.generatedAt).toLocaleString()}</p>
        </div>
        <div className="flex items-center gap-2">
          <TrendIcon trend={sc.trend} />
          <span className="text-sm text-muted-foreground capitalize">{sc.trend}</span>
        </div>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-end justify-between">
              <div>
                <div className="text-3xl font-bold">{sc.securityScore}</div>
                <div className="text-xs text-muted-foreground">Security Score / 100</div>
              </div>
              <div className="flex flex-col items-end gap-1">
                <DeltaBadge delta={sc.securityScoreDelta} />
                <Shield className="w-5 h-5 text-muted-foreground" />
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className={sc.criticalOpen > 0 ? "border-red-500/40" : ""}>
          <CardContent className="p-4">
            <div className="text-3xl font-bold text-red-500">{sc.criticalOpen}</div>
            <div className="text-xs text-muted-foreground">Critical Open</div>
            <div className="text-xs text-muted-foreground mt-1">{sc.highOpen} high</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-3xl font-bold">
              {sc.avgMttrHours != null ? `${sc.avgMttrHours}h` : "—"}
            </div>
            <div className="text-xs text-muted-foreground">Avg MTTR</div>
          </CardContent>
        </Card>
        <Card className={sc.slaBreach > 0 ? "border-orange-500/40" : ""}>
          <CardContent className="p-4">
            <div className={`text-3xl font-bold ${sc.slaBreach > 0 ? "text-orange-500" : ""}`}>{sc.slaBreach}</div>
            <div className="text-xs text-muted-foreground">SLA Breaches</div>
          </CardContent>
        </Card>
      </div>

      <div className="grid md:grid-cols-2 gap-6">
        {/* Compliance */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <CheckCircle className="w-4 h-4" /> Compliance
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {sc.compliance.map((c) => (
              <div key={c.framework} className="flex items-center justify-between">
                <span className="text-sm">{c.framework}</span>
                <div className="flex items-center gap-2">
                  <div className="w-24 h-2 bg-muted rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full ${c.score >= 70 ? "bg-green-500" : c.score >= 40 ? "bg-yellow-500" : "bg-red-500"}`}
                      style={{ width: `${c.score}%` }}
                    />
                  </div>
                  <span className="text-sm font-mono w-12 text-right">{c.score}%</span>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Top risky assets */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" /> Top Risky Assets
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {sc.topRiskyAssets.length === 0 ? (
              <p className="text-sm text-muted-foreground">No assets with open findings.</p>
            ) : sc.topRiskyAssets.map((a, i) => (
              <div key={a.hostname} className="flex items-center gap-3 text-sm">
                <span className="text-muted-foreground w-4">{i + 1}</span>
                <span className="font-mono truncate flex-1">{a.hostname}</span>
                <Badge variant="outline" className="text-xs">Risk {a.riskScore}</Badge>
                {a.criticalFindings > 0 && (
                  <Badge variant="destructive" className="text-xs">{a.criticalFindings} crit</Badge>
                )}
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Suggested fixes */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center gap-2">
            <Clock className="w-4 h-4" /> Recommended Actions
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {sc.suggestedFixes.length === 0 ? (
            <p className="text-sm text-muted-foreground">No open findings requiring action.</p>
          ) : sc.suggestedFixes.map((fix, i) => (
            <div key={i} className="border rounded-lg p-3 space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-medium text-sm capitalize">{fix.title}</span>
                <Badge variant="outline" className={`text-xs ${EFFORT_COLORS[fix.effort]}`}>
                  {fix.effort} effort
                </Badge>
              </div>
              <p className="text-xs text-muted-foreground">{fix.impact} · {fix.affectedAssets} asset{fix.affectedAssets !== 1 ? "s" : ""} affected</p>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
