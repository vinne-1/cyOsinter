import React, { useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  AlertTriangle,
  TrendingUp,
  ArrowUpRight,
} from "lucide-react";
import type { Finding } from "@shared/schema";
import { SeverityBadge, StatusBadge } from "@/components/severity-badge";
import { Link } from "wouter";
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from "recharts";
import { SEVERITY_SLICES } from "./helpers";

export function StatCard({
  title,
  value,
  icon: Icon,
  description,
  trend,
  testId,
}: {
  title: string;
  value: string | number;
  icon: React.ElementType;
  description: string;
  trend?: string;
  testId: string;
}) {
  return (
    <Card data-testid={testId}>
      <CardContent className="p-5">
        <div className="flex items-start justify-between gap-2">
          <div className="space-y-2">
            <p className="text-sm text-muted-foreground">{title}</p>
            <p className="text-2xl font-semibold tracking-tight" data-testid={`${testId}-value`}>
              {typeof value === "number" ? value.toLocaleString() : value}
            </p>
            <p className="text-xs text-muted-foreground">{description}</p>
          </div>
          <div className="flex items-center justify-center w-10 h-10 rounded-md bg-primary/10">
            <Icon className="w-5 h-5 text-primary" />
          </div>
        </div>
        {trend && (
          <div className="flex items-center gap-1 mt-3 text-xs text-green-500">
            <TrendingUp className="w-3 h-3" />
            <span>{trend}</span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function SeverityChart({ findings }: { findings: Finding[] }) {
  const counts = {
    critical: findings.filter((f) => f.severity === "critical").length,
    high: findings.filter((f) => f.severity === "high").length,
    medium: findings.filter((f) => f.severity === "medium").length,
    low: findings.filter((f) => f.severity === "low").length,
    info: findings.filter((f) => f.severity === "info").length,
  };
  const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1;

  const bars = [
    { key: "critical", label: "Critical", color: "bg-red-500", count: counts.critical },
    { key: "high", label: "High", color: "bg-orange-500", count: counts.high },
    { key: "medium", label: "Medium", color: "bg-yellow-500", count: counts.medium },
    { key: "low", label: "Low", color: "bg-blue-500", count: counts.low },
    { key: "info", label: "Info", color: "bg-slate-500", count: counts.info },
  ];

  return (
    <Card data-testid="card-severity-chart">
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="text-sm font-medium">Severity Distribution</CardTitle>
        <AlertTriangle className="w-4 h-4 text-muted-foreground" />
      </CardHeader>
      <CardContent className="space-y-3">
        {bars.map((bar) => (
          <div key={bar.key} className="space-y-1">
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground">{bar.label}</span>
              <span className="font-mono font-medium">{bar.count}</span>
            </div>
            <div className="h-2 rounded-md bg-muted overflow-hidden">
              <div
                className={`bar-fill h-full rounded-md ${bar.color} transition-all duration-500`}
                data-value={String(Math.min(100, Math.round(((bar.count / total) * 100) / 5) * 5))}
              />
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

export function FindingsSummaryCard({ findings }: { findings: Finding[] }) {
  const sliceData = useMemo(() => {
    return SEVERITY_SLICES.map((s) => ({
      ...s,
      count: findings.filter((f) => f.severity === s.key).length,
    })).filter((s) => s.count > 0);
  }, [findings]);

  const total = sliceData.reduce((acc, s) => acc + s.count, 0);

  return (
    <Card data-testid="card-findings-summary">
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="text-sm font-medium">Findings by Severity</CardTitle>
        <AlertTriangle className="w-4 h-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        {total === 0 ? (
          <p className="text-sm text-muted-foreground py-8 text-center">No findings yet. Run a scan to discover vulnerabilities.</p>
        ) : (
          <div className="flex flex-col sm:flex-row items-center gap-6">
            <div className="flex-shrink-0">
              <ResponsiveContainer width={160} height={160}>
                <PieChart>
                  <Pie
                    data={sliceData}
                    cx="50%"
                    cy="50%"
                    innerRadius={48}
                    outerRadius={72}
                    dataKey="count"
                    startAngle={90}
                    endAngle={-270}
                    strokeWidth={2}
                  >
                    {sliceData.map((entry) => (
                      <Cell key={entry.key} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    content={({ active, payload }) => {
                      if (!active || !payload?.length) return null;
                      const p = payload[0]?.payload as typeof sliceData[number];
                      return (
                        <div className="rounded-lg border bg-background px-3 py-2 text-xs shadow-md">
                          <p className="font-medium">{p.label}</p>
                          <p className="text-muted-foreground">{p.count} finding{p.count !== 1 ? "s" : ""}</p>
                        </div>
                      );
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="flex flex-col gap-2 flex-1 min-w-0">
              {SEVERITY_SLICES.map((s) => {
                const count = sliceData.find((d) => d.key === s.key)?.count ?? 0;
                return (
                  <div key={s.key} className="flex items-center justify-between gap-3 text-xs">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ backgroundColor: s.color }} />
                      <span className="text-muted-foreground">{s.label}</span>
                    </div>
                    <span className="font-mono font-semibold tabular-nums">{count}</span>
                  </div>
                );
              })}
              <div className="border-t pt-2 mt-1 flex items-center justify-between text-xs">
                <span className="text-muted-foreground">Total</span>
                <span className="font-mono font-semibold tabular-nums">{total}</span>
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function RecentFindings({ findings }: { findings: Finding[] }) {
  const recent = findings.slice(0, 5);

  return (
    <Card data-testid="card-recent-findings">
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="text-sm font-medium">Recent Findings</CardTitle>
        <Link href="/findings">
          <Badge variant="outline" className="text-xs cursor-pointer" data-testid="link-view-all-findings">
            View All
            <ArrowUpRight className="w-3 h-3 ml-1" />
          </Badge>
        </Link>
      </CardHeader>
      <CardContent>
        {recent.length === 0 ? (
          <p className="text-sm text-muted-foreground py-8 text-center">No findings yet. Run a scan to discover vulnerabilities.</p>
        ) : (
          <div className="space-y-3">
            {recent.map((finding) => (
              <div
                key={finding.id}
                className="flex items-start justify-between gap-3 p-3 rounded-md bg-muted/40"
                data-testid={`finding-row-${finding.id}`}
              >
                <div className="space-y-1 min-w-0 flex-1">
                  <p className="text-sm font-medium truncate">{finding.title}</p>
                  <p className="text-xs text-muted-foreground truncate">{finding.affectedAsset}</p>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0 flex-wrap">
                  <SeverityBadge severity={finding.severity} />
                  <StatusBadge status={finding.status} />
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
