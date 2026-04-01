import React, { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  ShieldAlert,
  Download,
  ChevronDown,
  ChevronRight,
} from "lucide-react";
import type { ReconModule } from "@shared/schema";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ModuleHeader, GradeBadge, StatusIcon } from "./shared";

// Derive TLS grade from ssl when backend did not send tlsPosture (e.g. old payload)
function deriveTlsGrade(d: Record<string, unknown>): string {
  const grade = (d.tlsPosture as { grade?: string } | undefined)?.grade;
  if (grade) return grade;
  const ssl = d.ssl as { daysRemaining?: number; protocol?: string } | undefined;
  if (!ssl || ssl.daysRemaining == null) return "N/A";
  if (ssl.daysRemaining <= 0) return "F";
  const proto = (ssl.protocol || "").toLowerCase();
  if ((proto === "tlsv1.2" || proto === "tlsv1.3") && ssl.daysRemaining > 30) return "A";
  if (proto === "tlsv1.2" || proto === "tlsv1.3") return "B";
  return "C";
}

export function AttackSurfacePanel({ mod }: { mod: ReconModule }) {
  const { selectedWorkspaceId } = useDomain();
  const [sortBy, setSortBy] = useState<"host" | "riskScore" | "tlsGrade" | "waf">("riskScore");
  const [sortDesc, setSortDesc] = useState(true);
  const [expandedHost, setExpandedHost] = useState<string | null>(null);
  const d = mod.data as Record<string, any>;
  const headers = d.securityHeaders || {};
  const tlsGrade = deriveTlsGrade(d);
  const publicIPs = (d.publicIPs || []) as Array<{ ip: string; banner?: string; services?: string[] }>;
  const ips = publicIPs.map((p) => p.ip).filter(Boolean);
  const assetInventory = (d.assetInventory || []) as Array<{ host: string; ip: string; category: string; riskScore: number; tlsGrade: string; waf: string; cdn: string }>;

  const rawPerAssetHeaders = d.perAssetHeaders || {};
  const rawPerAssetTls = d.perAssetTls || {};
  const rawPerAssetLeaks = d.perAssetLeaks || {};

  const perAssetHeaders = useMemo(() => {
    if (Array.isArray(rawPerAssetHeaders)) return rawPerAssetHeaders as Array<{ host: string; headers: Record<string, { present: boolean; value?: string }>; missingCount: number }>;
    return Object.entries(rawPerAssetHeaders).map(([host, headers]) => ({
      host,
      headers: headers as Record<string, { present: boolean; value?: string | null }>,
      missingCount: Object.values(headers as Record<string, { present: boolean }>).filter((h) => !h.present).length,
    }));
  }, [rawPerAssetHeaders]);

  const perAssetTls = useMemo(() => {
    if (Array.isArray(rawPerAssetTls)) return rawPerAssetTls as Array<{ host: string; grade: string; daysRemaining: number; issuer: string }>;
    return Object.entries(rawPerAssetTls).map(([host, tls]) => {
      const t = tls as { daysRemaining?: number; protocol?: string; issuer?: string; subject?: string } | null;
      if (!t) return { host, grade: "N/A", daysRemaining: -1, issuer: "Unknown" };
      const proto = (t.protocol || "").toLowerCase();
      let grade = "F";
      if (t.daysRemaining != null && t.daysRemaining > 0) {
        if ((proto === "tlsv1.2" || proto === "tlsv1.3") && t.daysRemaining > 30) grade = "A";
        else if (proto === "tlsv1.2" || proto === "tlsv1.3") grade = "B";
        else grade = "C";
      }
      return { host, grade, daysRemaining: t.daysRemaining ?? -1, issuer: t.issuer || "Unknown" };
    });
  }, [rawPerAssetTls]);

  const perAssetLeaks = useMemo(() => {
    if (Array.isArray(rawPerAssetLeaks)) return rawPerAssetLeaks as Array<{ host: string; leaks: string[] }>;
    return Object.entries(rawPerAssetLeaks).map(([host, leaks]) => ({
      host,
      leaks: (leaks || []) as string[],
    }));
  }, [rawPerAssetLeaks]);

  const headersByHost = useMemo(() => new Map(perAssetHeaders.map((h) => [h.host, h])), [perAssetHeaders]);
  const tlsByHost = useMemo(() => new Map(perAssetTls.map((t) => [t.host, t])), [perAssetTls]);
  const leaksByHost = useMemo(() => new Map(perAssetLeaks.map((l) => [l.host, l])), [perAssetLeaks]);
  const sortedAssets = useMemo(() => {
    const arr = [...assetInventory];
    arr.sort((a, b) => {
      let cmp = 0;
      if (sortBy === "host") cmp = a.host.localeCompare(b.host);
      else if (sortBy === "riskScore") cmp = a.riskScore - b.riskScore;
      else if (sortBy === "tlsGrade") cmp = (a.tlsGrade || "Z").localeCompare(b.tlsGrade || "Z");
      else if (sortBy === "waf") cmp = (a.waf ? "1" : "0").localeCompare(b.waf ? "1" : "0");
      return sortDesc ? -cmp : cmp;
    });
    return arr;
  }, [assetInventory, sortBy, sortDesc]);
  const { data: ipEnrichment = {} } = useQuery<Record<string, { abuseipdb?: { abuseConfidenceScore?: number; totalReports?: number; countryCode?: string; isp?: string } | null; virustotal?: { malicious?: number; suspicious?: number } | null }>>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/ip-enrichment`],
    enabled: !!selectedWorkspaceId && ips.length > 0,
  });
  const exportAttackSurface = (format: "json" | "csv") => {
    const data = assetInventory.length > 0 ? assetInventory : [{ host: "-", ip: "-", category: "-", riskScore: d.surfaceRiskScore ?? 0, tlsGrade, waf: d.wafDetection?.provider || "", cdn: "None" }];
    if (format === "json") {
      const blob = new Blob([JSON.stringify({ attackSurface: data, surfaceRiskScore: d.surfaceRiskScore, wafDetection: d.wafDetection }, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "attack-surface.json";
      a.click();
      URL.revokeObjectURL(url);
    } else {
      const csv = ["host,ip,category,riskScore,tlsGrade,waf,cdn", ...data.map((r) => `${r.host},${r.ip},${r.category},${r.riskScore},${r.tlsGrade},${r.waf},${r.cdn}`)].join("\n");
      const blob = new Blob([csv], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "attack-surface.csv";
      a.click();
      URL.revokeObjectURL(url);
    }
  };
  const highRiskCount = assetInventory.filter((a) => a.riskScore >= 60).length;
  const wafCoverage = assetInventory.length > 0 ? Math.round((assetInventory.filter((a) => a.waf).length / assetInventory.length) * 100) : 0;
  return (
    <div className="space-y-4" data-testid="panel-attack-surface">
      <ModuleHeader title="External Attack Surface" icon={ShieldAlert} confidence={mod.confidence || 0} generatedAt={mod.generatedAt} />
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
        <Card>
          <CardContent className="p-3 text-center">
            <p className={`text-2xl font-semibold ${(d.surfaceRiskScore || 0) >= 80 ? 'text-green-400' : (d.surfaceRiskScore || 0) >= 60 ? 'text-yellow-500' : 'text-red-500'}`}>
              {d.surfaceRiskScore || 0}
            </p>
            <p className="text-xs text-muted-foreground">Surface Risk Score</p>
          </CardContent>
        </Card>
        <Card><CardContent className="p-3 text-center"><p className="text-lg font-semibold">{assetInventory.length || (d.publicIPs || []).length}</p><p className="text-xs text-muted-foreground">Hosts</p></CardContent></Card>
        <Card><CardContent className="p-3 text-center"><p className="text-lg font-semibold text-orange-400">{highRiskCount}</p><p className="text-xs text-muted-foreground">High Risk</p></CardContent></Card>
        <Card><CardContent className="p-3 text-center"><GradeBadge grade={tlsGrade} /><p className="text-xs text-muted-foreground mt-1">TLS Grade</p></CardContent></Card>
        <Card><CardContent className="p-3 text-center"><StatusIcon pass={d.wafDetection?.detected || false} /><p className="text-xs text-muted-foreground mt-1">WAF {d.wafDetection?.provider || ""}</p></CardContent></Card>
        <Card><CardContent className="p-3 text-center"><p className="text-lg font-semibold">{wafCoverage}%</p><p className="text-xs text-muted-foreground">WAF Coverage</p></CardContent></Card>
      </div>
      {(d.riskBreakdown || []).length > 0 && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Risk Breakdown</CardTitle></CardHeader>
          <CardContent className="space-y-3">
            {d.riskBreakdown.map((r: any, i: number) => (
              <div key={i} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">{r.category}</span>
                  <span className="font-mono font-medium">{r.score}/{r.maxScore}</span>
                </div>
                <div className="h-2 rounded-md bg-muted overflow-hidden">
                  <div className={`bar-fill h-full rounded-md transition-all ${r.score >= 80 ? 'bg-green-500' : r.score >= 60 ? 'bg-yellow-500' : 'bg-red-500'}`} data-value={String(Math.min(100, Math.round(((r.score / r.maxScore) * 100) / 5) * 5))} />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
      {sortedAssets.length > 0 && (
        <Card>
          <CardHeader className="pb-2 flex flex-row items-center justify-between">
            <CardTitle className="text-sm font-medium">Per-Asset Attack Surface</CardTitle>
            <div className="flex gap-2">
              <button onClick={() => exportAttackSurface("csv")} className="text-xs px-2 py-1 rounded border border-border hover:bg-muted/50 flex items-center gap-1">
                <Download className="w-3 h-3" /> CSV
              </button>
              <button onClick={() => exportAttackSurface("json")} className="text-xs px-2 py-1 rounded border border-border hover:bg-muted/50 flex items-center gap-1">
                <Download className="w-3 h-3" /> JSON
              </button>
            </div>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead></TableHead>
                  <TableHead><button className="font-medium hover:underline" onClick={() => { setSortBy("host"); setSortDesc(sortBy === "host" ? !sortDesc : false); }}>Host</button></TableHead>
                  <TableHead><button className="font-medium hover:underline" onClick={() => { setSortBy("riskScore"); setSortDesc(sortBy === "riskScore" ? !sortDesc : true); }}>Risk</button></TableHead>
                  <TableHead><button className="font-medium hover:underline" onClick={() => { setSortBy("tlsGrade"); setSortDesc(sortBy === "tlsGrade" ? !sortDesc : true); }}>TLS</button></TableHead>
                  <TableHead>Headers</TableHead>
                  <TableHead>WAF</TableHead>
                  <TableHead>CDN</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sortedAssets.map((a) => (
                  <React.Fragment key={a.host}>
                    <TableRow className="cursor-pointer hover:bg-muted/30" onClick={() => setExpandedHost(expandedHost === a.host ? null : a.host)}>
                      <TableCell className="w-8">{expandedHost === a.host ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}</TableCell>
                      <TableCell className="font-mono text-sm">{a.host}</TableCell>
                      <TableCell><Badge variant="outline" className={`text-xs border-0 no-default-hover-elevate no-default-active-elevate ${a.riskScore >= 60 ? "bg-red-600/15 text-red-400" : a.riskScore >= 40 ? "bg-yellow-600/15 text-yellow-400" : "bg-green-600/15 text-green-400"}`}>{a.riskScore}</Badge></TableCell>
                      <TableCell><GradeBadge grade={a.tlsGrade || "N/A"} /></TableCell>
                      <TableCell>{headersByHost.get(a.host)?.missingCount ?? 0} missing</TableCell>
                      <TableCell>{a.waf ? <Badge variant="outline" className="text-xs bg-green-600/15 text-green-400 border-0 no-default-hover-elevate no-default-active-elevate">{a.waf}</Badge> : <span className="text-xs text-muted-foreground">—</span>}</TableCell>
                      <TableCell>{a.cdn && a.cdn !== "None" ? <Badge variant="outline" className="text-xs no-default-hover-elevate no-default-active-elevate">{a.cdn}</Badge> : <span className="text-xs text-muted-foreground">—</span>}</TableCell>
                    </TableRow>
                    {expandedHost === a.host && (
                      <TableRow key={`${a.host}-exp`}>
                        <TableCell colSpan={7} className="bg-muted/20 p-4">
                          <div className="space-y-3 text-sm">
                            {(() => { const tls = tlsByHost.get(a.host); return tls ? (
                              <div>
                                <p className="font-medium text-muted-foreground mb-1">TLS Certificate</p>
                                <p className="font-mono text-xs">Issuer: {tls.issuer} · Days remaining: {tls.daysRemaining}</p>
                              </div>
                            ) : null; })()}
                            {headersByHost.get(a.host) && (
                              <div>
                                <p className="font-medium text-muted-foreground mb-1">Security Headers</p>
                                <div className="flex flex-wrap gap-2">
                                  {Object.entries(headersByHost.get(a.host)!.headers || {}).map(([k, v]) => (
                                    <Badge key={k} variant="outline" className={`text-xs no-default-hover-elevate no-default-active-elevate ${v.present ? "bg-green-600/15 text-green-400 border-0" : "bg-red-600/15 text-red-400 border-0"}`}>{k}: {v.present ? "\u2713" : "\u2717"}</Badge>
                                  ))}
                                </div>
                              </div>
                            )}
                            {leaksByHost.get(a.host)?.leaks?.length ? (
                              <div>
                                <p className="font-medium text-muted-foreground mb-1">Server Info Leaks</p>
                                <p className="font-mono text-xs">{leaksByHost.get(a.host)!.leaks.join("; ")}</p>
                              </div>
                            ) : null}
                          </div>
                        </TableCell>
                      </TableRow>
                    )}
                  </React.Fragment>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Public IPs & Services</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.publicIPs || []).map((ip: any, i: number) => {
              const enrichment = ipEnrichment[ip.ip];
              const abuse = enrichment?.abuseipdb;
              const vt = enrichment?.virustotal;
              const score = abuse?.abuseConfidenceScore ?? -1;
              const scoreColor = score < 0 ? "" : score < 25 ? "bg-green-600/15 text-green-400" : score <= 75 ? "bg-yellow-600/15 text-yellow-400" : "bg-red-600/15 text-red-400";
              return (
                <div key={i} className="p-2 rounded-md bg-muted/40 space-y-1">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <span className="text-sm font-mono font-medium">{ip.ip}</span>
                    <div className="flex items-center gap-2 flex-wrap">
                      {abuse && (
                        <Badge variant="outline" className={`text-xs border-0 font-mono no-default-hover-elevate no-default-active-elevate ${scoreColor}`}>
                          AbuseIPDB: {abuse.abuseConfidenceScore}%
                        </Badge>
                      )}
                      {vt && (vt.malicious !== undefined || vt.suspicious !== undefined) && (
                        <Badge variant="outline" className="text-xs border-0 no-default-hover-elevate no-default-active-elevate bg-slate-600/15">
                          VT: {vt.malicious ?? 0} mal / {vt.suspicious ?? 0} susp
                        </Badge>
                      )}
                      <span className="text-xs text-muted-foreground">{ip.banner}</span>
                    </div>
                  </div>
                  <div className="flex gap-1 flex-wrap">
                    {(ip.services || []).map((s: string, j: number) => (
                      <Badge key={j} variant="outline" className="text-xs font-mono no-default-hover-elevate no-default-active-elevate">{s}</Badge>
                    ))}
                  </div>
                </div>
              );
            })}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Security Headers</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {Object.entries(headers).map(([key, val]: [string, any]) => (
              <div key={key} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/40">
                <div className="flex items-center gap-2">
                  <StatusIcon pass={val.present} />
                  <span className="text-sm">{key.replace(/([A-Z])/g, ' $1').replace(/^./, (s: string) => s.toUpperCase())}</span>
                </div>
                <GradeBadge grade={val.grade ?? (val.present ? "A" : "N/A")} />
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
