import { useQuery } from "@tanstack/react-query";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { TrendingUp, TrendingDown, Clock, BarChart3, Target } from "lucide-react";
import { useDomain } from "@/lib/domain-context";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
} from "recharts";

interface SeverityTrend {
  date: string;
  securityScore: number | null;
  findingsCount: number | null;
  criticalCount: number | null;
  highCount: number | null;
  surfaceRiskScore: number | null;
}

interface FindingTrend {
  date: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface CategoryData {
  category: string;
  total: number;
  open: number;
  resolved: number;
  critical: number;
  high: number;
}

interface MttrData {
  totalResolved: number;
  bySeverity: Array<{ severity: string; count: number; avgHours: number }>;
  overallAvgHours: number | null;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#6b7280",
};

const CATEGORY_COLORS = ["#6366f1", "#8b5cf6", "#a855f7", "#c084fc", "#d8b4fe", "#818cf8", "#93c5fd", "#60a5fa", "#38bdf8"];

function formatCategoryName(cat: string): string {
  return cat.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function formatDate(dateStr: string): string {
  const d = new Date(dateStr);
  return `${d.getMonth() + 1}/${d.getDate()}`;
}

function formatHours(hours: number): string {
  if (hours < 1) return `${Math.round(hours * 60)}m`;
  if (hours < 24) return `${Math.round(hours)}h`;
  return `${Math.round(hours / 24)}d`;
}

export default function Trends() {
  const { selectedWorkspaceId } = useDomain();

  const { data: severityTrend = [], isLoading: loadingSeverity } = useQuery<SeverityTrend[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/trends/severity`],
    enabled: !!selectedWorkspaceId,
  });

  const { data: findingTrend = [], isLoading: loadingFindings } = useQuery<FindingTrend[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/trends/findings`],
    enabled: !!selectedWorkspaceId,
  });

  const { data: categories = [], isLoading: loadingCategories } = useQuery<CategoryData[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/trends/categories`],
    enabled: !!selectedWorkspaceId,
  });

  const { data: mttr, isLoading: loadingMttr } = useQuery<MttrData>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/trends/mttr`],
    enabled: !!selectedWorkspaceId,
  });

  const isLoading = loadingSeverity || loadingFindings || loadingCategories || loadingMttr;

  // Compute trend direction
  const latestScore = severityTrend.length > 0 ? severityTrend[severityTrend.length - 1].securityScore : null;
  const prevScore = severityTrend.length > 1 ? severityTrend[severityTrend.length - 2].securityScore : null;
  const scoreDirection = latestScore != null && prevScore != null ? (latestScore >= prevScore ? "up" : "down") : null;

  if (isLoading) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-8 w-64" />
        <div className="grid grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-24" />)}
        </div>
        <Skeleton className="h-64" />
        <Skeleton className="h-64" />
      </div>
    );
  }

  const totalFindings = categories.reduce((sum, c) => sum + c.total, 0);
  const openFindings = categories.reduce((sum, c) => sum + c.open, 0);

  // Prepare pie data for categories
  const pieData = categories.slice(0, 8).map((c, i) => ({
    name: formatCategoryName(c.category),
    value: c.total,
    color: CATEGORY_COLORS[i % CATEGORY_COLORS.length],
  }));

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight" data-testid="text-trends-title">
          Vulnerability Trends
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          Track security posture over time and identify patterns
        </p>
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-2xl font-bold">{latestScore ?? "—"}</p>
                <p className="text-xs text-muted-foreground">Security Score</p>
              </div>
              {scoreDirection && (
                scoreDirection === "up" ?
                  <TrendingUp className="w-5 h-5 text-green-500" /> :
                  <TrendingDown className="w-5 h-5 text-red-500" />
              )}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-2xl font-bold">{totalFindings}</p>
            <p className="text-xs text-muted-foreground">Total Findings</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-2xl font-bold text-orange-500">{openFindings}</p>
            <p className="text-xs text-muted-foreground">Open Findings</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-2">
              <Clock className="w-4 h-4 text-muted-foreground" />
              <div>
                <p className="text-2xl font-bold">{mttr?.overallAvgHours != null ? formatHours(mttr.overallAvgHours) : "—"}</p>
                <p className="text-xs text-muted-foreground">Avg Time to Resolve</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Security Score Trend */}
      {severityTrend.length > 0 && (
        <Card>
          <CardContent className="p-4">
            <h3 className="text-sm font-medium mb-4">Security Score Over Time</h3>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={severityTrend}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis dataKey="date" tickFormatter={formatDate} tick={{ fontSize: 11 }} stroke="hsl(var(--muted-foreground))" />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} stroke="hsl(var(--muted-foreground))" />
                  <Tooltip
                    contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }}
                    labelFormatter={(v) => new Date(v).toLocaleDateString()}
                  />
                  <Line type="monotone" dataKey="securityScore" name="Security Score" stroke="#22c55e" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="surfaceRiskScore" name="Risk Score" stroke="#ef4444" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Finding severity trend */}
        {findingTrend.length > 0 && (
          <Card>
            <CardContent className="p-4">
              <h3 className="text-sm font-medium mb-4">Findings by Severity</h3>
              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={findingTrend}>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                    <XAxis dataKey="date" tickFormatter={formatDate} tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" />
                    <YAxis tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" />
                    <Tooltip
                      contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }}
                    />
                    <Bar dataKey="critical" stackId="a" fill={SEVERITY_COLORS.critical} />
                    <Bar dataKey="high" stackId="a" fill={SEVERITY_COLORS.high} />
                    <Bar dataKey="medium" stackId="a" fill={SEVERITY_COLORS.medium} />
                    <Bar dataKey="low" stackId="a" fill={SEVERITY_COLORS.low} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Category distribution */}
        {pieData.length > 0 && (
          <Card>
            <CardContent className="p-4">
              <h3 className="text-sm font-medium mb-4">Finding Categories</h3>
              <div className="h-56 flex items-center">
                <div className="w-1/2 h-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={pieData} dataKey="value" cx="50%" cy="50%" innerRadius={40} outerRadius={70} paddingAngle={2}>
                        {pieData.map((entry, index) => (
                          <Cell key={index} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="w-1/2 space-y-1 pl-2">
                  {pieData.map((entry, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs">
                      <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: entry.color }} />
                      <span className="truncate">{entry.name}</span>
                      <span className="text-muted-foreground ml-auto">{entry.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        )}
      </div>

      {/* MTTR by severity */}
      {mttr && mttr.bySeverity.length > 0 && (
        <Card>
          <CardContent className="p-4">
            <h3 className="text-sm font-medium mb-4">Mean Time to Resolve (MTTR) by Severity</h3>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
              {["critical", "high", "medium", "low", "info"].map((sev) => {
                const data = mttr.bySeverity.find((m) => m.severity === sev);
                return (
                  <div key={sev} className="p-3 rounded-md bg-muted/30 text-center">
                    <div className="w-3 h-3 rounded-full mx-auto mb-2" style={{ backgroundColor: SEVERITY_COLORS[sev] }} />
                    <p className="text-lg font-semibold">{data ? formatHours(data.avgHours) : "—"}</p>
                    <p className="text-[10px] text-muted-foreground capitalize">{sev}</p>
                    {data && <p className="text-[10px] text-muted-foreground">{data.count} resolved</p>}
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Categories table */}
      {categories.length > 0 && (
        <Card>
          <CardContent className="p-4">
            <h3 className="text-sm font-medium mb-4">Finding Categories Detail</h3>
            <div className="space-y-2">
              {categories.map((cat) => (
                <div key={cat.category} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/20">
                  <div className="flex items-center gap-2 min-w-0">
                    <Target className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />
                    <span className="text-sm truncate">{formatCategoryName(cat.category)}</span>
                  </div>
                  <div className="flex items-center gap-3 flex-shrink-0">
                    {cat.critical > 0 && <Badge variant="destructive" className="text-[10px] h-5">{cat.critical} crit</Badge>}
                    {cat.high > 0 && <Badge className="text-[10px] h-5 bg-orange-500">{cat.high} high</Badge>}
                    <span className="text-xs text-muted-foreground">{cat.open} open / {cat.total} total</span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
