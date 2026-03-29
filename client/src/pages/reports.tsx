import { useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Checkbox } from "@/components/ui/checkbox";
import { useDomain } from "@/lib/domain-context";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import {
  FileText,
  Plus,
  Download,
  FileBarChart,
  Clock,
  CheckCircle2,
  Loader2,
  Eye,
  Trash2,
  ChevronDown,
} from "lucide-react";
import type { Report, Finding, ReconModule } from "@shared/schema";
import { SeverityBadge } from "@/components/severity-badge";
import { downloadReportPdf } from "@/lib/reportPdf";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { apiRequest, buildUrl, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

const moduleLabels: Record<string, string> = {
  org_identity: "Org Identity",
  web_presence: "Web Presence",
  tech_stack: "Tech Stack",
  cloud_footprint: "Cloud & Email",
  exposed_content: "Exposures",
  attack_surface: "Attack Surface",
  brand_signals: "Brand",
  linkedin_company: "LinkedIn Org",
  linkedin_people: "People Intel",
  linkedin_hiring: "Hiring Signals",
  code_footprint: "Code Footprint",
  third_party_surface: "Third-Party",
};

function ReportDetailDialog({
  report,
  open,
  onOpenChange,
  onDeleted,
}: {
  report: Report | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onDeleted?: () => void;
}) {
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const { toast } = useToast();
  const { selectedWorkspaceId } = useDomain();
  const { data: findings = [] } = useQuery<Finding[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/findings`],
    enabled: !!selectedWorkspaceId,
  });
  const { data: modules = [] } = useQuery<ReconModule[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/recon-modules`],
    enabled: !!selectedWorkspaceId,
  });

  if (!report) return null;

  const reportFindings = findings.filter((f) =>
    (report.findingIds || []).includes(f.id)
  );

  const content = report.content as Record<string, unknown> | null;

  const contentAttackSurface = content?.attackSurface as Record<string, unknown> | null | undefined;
  const contentAttackSurfaceSummary = content?.attackSurfaceSummary as { totalHosts: number; highRiskCount: number; wafCoverage: number } | null | undefined;
  const contentAttackSurfaceAssets = content?.attackSurfaceAssets as Array<{ host: string; ip: string; category: string; riskScore: number; tlsGrade: string; waf: string; cdn: string }> | undefined;
  const contentCloudFootprint = content?.cloudFootprint as Record<string, unknown> | null | undefined;
  const contentReconModules = content?.reconModules as Array<{ moduleType: string; confidence: number }> | undefined;
  const contentOsintDiscovery = content?.osintDiscovery as {
    leakedCredentials?: Array<{ id: string; title: string; severity: string; affectedAsset?: string }>;
    exposedDocuments?: Array<{ id: string; title: string; severity: string; affectedAsset?: string }>;
    infrastructureDisclosure?: Array<{ id: string; title: string; severity: string; affectedAsset?: string }>;
    osintExposure?: Array<{ id: string; title: string; severity: string; affectedAsset?: string }>;
    summary?: { total: number; byCategory: Record<string, number> };
  } | undefined;

  const attackSurface = contentAttackSurface ?? modules.find(m => m.moduleType === "attack_surface")?.data as Record<string, unknown> | undefined;
  const cloud = contentCloudFootprint ?? modules.find(m => m.moduleType === "cloud_footprint")?.data as Record<string, unknown> | undefined;

  const deleteMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("DELETE", `/api/workspaces/${selectedWorkspaceId}/reports/${report.id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/reports`] });
      toast({ title: "Report deleted" });
      setDeleteDialogOpen(false);
      onOpenChange(false);
      onDeleted?.();
    },
    onError: (error: Error) => {
      toast({ title: "Error", description: error.message, variant: "destructive" });
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <div className="flex items-start gap-3">
            <div className="flex items-center justify-center w-10 h-10 rounded-md bg-primary/10 flex-shrink-0">
              <FileBarChart className="w-5 h-5 text-primary" />
            </div>
            <div className="space-y-1 min-w-0 flex-1">
              <DialogTitle className="text-base">{report.title}</DialogTitle>
              {report.status === "completed" && (
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="outline" size="sm" className="mt-2" data-testid="button-export">
                      <Download className="w-4 h-4 mr-2" />
                      Export
                      <ChevronDown className="w-4 h-4 ml-2" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="start">
                    <DropdownMenuItem
                      onClick={() =>
                        downloadReportPdf(
                          {
                            title: report.title,
                            summary: report.summary ?? "",
                            generatedAt: report.generatedAt ? new Date(report.generatedAt).toISOString() : null,
                            content,
                            findings: reportFindings,
                          },
                          `${(report.title || "security-report").replace(/[^a-zA-Z0-9-_]/g, "-").replace(/-+/g, "-").toLowerCase()}.pdf`
                        )
                      }
                      data-testid="button-export-pdf"
                    >
                      <FileText className="w-4 h-4 mr-2" />
                      PDF
                    </DropdownMenuItem>
                    <DropdownMenuItem
                      onClick={() => {
                        const safeTitle = (report.title || "security-report").replace(/[^a-zA-Z0-9-_]/g, "-").replace(/-+/g, "-").toLowerCase();
                        const a = document.createElement("a");
                        a.href = buildUrl(`/api/workspaces/${selectedWorkspaceId}/reports/${report.id}/export?format=csv`);
                        a.download = `${safeTitle}.csv`;
                        a.click();
                      }}
                      data-testid="button-export-csv"
                    >
                      CSV
                    </DropdownMenuItem>
                    <DropdownMenuItem
                      onClick={() => {
                        const safeTitle = (report.title || "security-report").replace(/[^a-zA-Z0-9-_]/g, "-").replace(/-+/g, "-").toLowerCase();
                        const a = document.createElement("a");
                        a.href = buildUrl(`/api/workspaces/${selectedWorkspaceId}/reports/${report.id}/export?format=xlsx`);
                        a.download = `${safeTitle}.xlsx`;
                        a.click();
                      }}
                      data-testid="button-export-excel"
                    >
                      Excel (.xlsx)
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              )}
              <Button
                variant="ghost"
                size="sm"
                className="mt-2 text-destructive hover:text-destructive hover:bg-destructive/10"
                onClick={() => setDeleteDialogOpen(true)}
                data-testid="button-delete-report"
              >
                <Trash2 className="w-4 h-4 mr-2" />
                Delete
              </Button>
              <div className="flex items-center gap-2 flex-wrap">
                <Badge variant="outline" className="text-xs capitalize no-default-hover-elevate no-default-active-elevate">
                  {report.type.replace(/_/g, " ")}
                </Badge>
                <Badge
                  variant="outline"
                  className={`text-xs no-default-hover-elevate no-default-active-elevate ${
                    report.status === "completed"
                      ? "bg-green-600/15 text-green-400 border-0"
                      : report.status === "generating"
                      ? "bg-blue-600/15 text-blue-400 border-0"
                      : "bg-slate-600/15 text-slate-400 border-0"
                  }`}
                >
                  {report.status === "generating" && <Loader2 className="w-3 h-3 mr-1 animate-spin" />}
                  {report.status.charAt(0).toUpperCase() + report.status.slice(1)}
                </Badge>
              </div>
            </div>
          </div>
        </DialogHeader>

        <div className="space-y-5 mt-2">
          {report.summary && (
            <div>
              <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2">
                Executive Summary
                {content?.aiNarrative != null && (
                  <span className="ml-2 text-[10px] font-normal normal-case text-muted-foreground/80">(AI-generated)</span>
                )}
              </h4>
              <p className="text-sm leading-relaxed">{report.summary}</p>
            </div>
          )}

          {content && (
            <div>
              <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2">Report Overview</h4>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {content.totalFindings !== undefined && (
                  <div className="bg-muted/50 p-3 rounded-md text-center">
                    <p className="text-lg font-semibold">{String(content.totalFindings)}</p>
                    <p className="text-xs text-muted-foreground">Total Findings</p>
                  </div>
                )}
                {content.criticalCount !== undefined && (
                  <div className="bg-red-500/10 p-3 rounded-md text-center">
                    <p className="text-lg font-semibold text-red-400">{String(content.criticalCount)}</p>
                    <p className="text-xs text-muted-foreground">Critical</p>
                  </div>
                )}
                {content.highCount !== undefined && (
                  <div className="bg-orange-500/10 p-3 rounded-md text-center">
                    <p className="text-lg font-semibold text-orange-400">{String(content.highCount)}</p>
                    <p className="text-xs text-muted-foreground">High</p>
                  </div>
                )}
                {content.resolvedCount !== undefined && (
                  <div className="bg-green-500/10 p-3 rounded-md text-center">
                    <p className="text-lg font-semibold text-green-400">{String(content.resolvedCount)}</p>
                    <p className="text-xs text-muted-foreground">Resolved</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {((contentReconModules?.length ?? 0) > 0 || modules.length > 0) && (
            <div>
              <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2">
                Intelligence Summary ({(contentReconModules?.length ?? modules.length)} modules)
              </h4>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                {(contentReconModules ?? modules).map((mod, i) => (
                  <div key={mod.moduleType + i} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/40" data-testid={`report-intel-${mod.moduleType}`}>
                    <span className="text-xs">{moduleLabels[mod.moduleType] || mod.moduleType}</span>
                    <Badge variant="outline" className={`text-xs border-0 no-default-hover-elevate no-default-active-elevate ${
                      (mod.confidence || 0) >= 90 ? "bg-green-600/15 text-green-400" :
                      (mod.confidence || 0) >= 70 ? "bg-yellow-600/15 text-yellow-400" :
                      "bg-orange-600/15 text-orange-400"
                    }`}>
                      {mod.confidence}%
                    </Badge>
                  </div>
                ))}
              </div>
              <div className="mt-3 space-y-2">
                {attackSurface && attackSurface.surfaceRiskScore != null && (
                  <div className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/40">
                    <span className="text-xs text-muted-foreground">Surface Risk Score</span>
                    <span className={`text-sm font-semibold font-mono ${(attackSurface.surfaceRiskScore as number) >= 70 ? 'text-yellow-500' : 'text-red-500'}`}>
                      {attackSurface.surfaceRiskScore as number}/100
                    </span>
                  </div>
                )}
                {contentAttackSurfaceSummary && (
                  <div className="grid grid-cols-3 gap-2 mt-2">
                    <div className="p-2 rounded-md bg-muted/40 text-center">
                      <p className="text-sm font-semibold">{contentAttackSurfaceSummary.totalHosts}</p>
                      <p className="text-xs text-muted-foreground">Hosts</p>
                    </div>
                    <div className="p-2 rounded-md bg-muted/40 text-center">
                      <p className="text-sm font-semibold text-orange-400">{contentAttackSurfaceSummary.highRiskCount}</p>
                      <p className="text-xs text-muted-foreground">High Risk</p>
                    </div>
                    <div className="p-2 rounded-md bg-muted/40 text-center">
                      <p className="text-sm font-semibold">{contentAttackSurfaceSummary.wafCoverage}%</p>
                      <p className="text-xs text-muted-foreground">WAF Coverage</p>
                    </div>
                  </div>
                )}
                {Array.isArray(content?.securityHeadersMatrix) && (content.securityHeadersMatrix as Array<{ header: string; present: boolean; grade: string }>).length > 0 && (
                  <div className="mt-3">
                    <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2">
                      Security Headers ({content?.securityHeadersCoverage ? `${(content.securityHeadersCoverage as { passing: number; total: number }).passing}/${(content.securityHeadersCoverage as { passing: number; total: number }).total} passing` : ""})
                    </h4>
                    <div className="rounded-md border overflow-x-auto">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead className="text-xs">Header</TableHead>
                            <TableHead className="text-xs">Status</TableHead>
                            <TableHead className="text-xs">Grade</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {(content.securityHeadersMatrix as Array<{ header: string; present: boolean; grade: string }>).map((h, i) => (
                            <TableRow key={i}>
                              <TableCell className="text-xs">{h.header}</TableCell>
                              <TableCell>
                                <Badge variant="outline" className={`text-xs border-0 no-default-hover-elevate no-default-active-elevate ${h.present ? "bg-green-600/15 text-green-400" : "bg-red-600/15 text-red-400"}`}>
                                  {h.present ? "Present" : "Missing"}
                                </Badge>
                              </TableCell>
                              <TableCell className="font-mono text-xs">{h.grade}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                  </div>
                )}
                {contentAttackSurfaceAssets && contentAttackSurfaceAssets.length > 0 && (
                  <div className="mt-3">
                    <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2">Per-Asset Attack Surface</h4>
                    <div className="rounded-md border overflow-x-auto">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead className="text-xs">Host</TableHead>
                            <TableHead className="text-xs">IP</TableHead>
                            <TableHead className="text-xs">Risk</TableHead>
                            <TableHead className="text-xs">TLS</TableHead>
                            <TableHead className="text-xs">WAF</TableHead>
                            <TableHead className="text-xs">CDN</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {contentAttackSurfaceAssets.slice(0, 20).map((a, i) => (
                            <TableRow key={i}>
                              <TableCell className="font-mono text-xs">{a.host}</TableCell>
                              <TableCell className="font-mono text-xs text-muted-foreground">{a.ip}</TableCell>
                              <TableCell><Badge variant="outline" className={`text-xs border-0 no-default-hover-elevate no-default-active-elevate ${a.riskScore >= 60 ? "bg-red-600/15 text-red-400" : a.riskScore >= 40 ? "bg-yellow-600/15 text-yellow-400" : "bg-green-600/15 text-green-400"}`}>{a.riskScore}</Badge></TableCell>
                              <TableCell className="font-mono text-xs">{a.tlsGrade}</TableCell>
                              <TableCell className="text-xs">{a.waf || "—"}</TableCell>
                              <TableCell className="text-xs">{a.cdn !== "None" ? a.cdn : "—"}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                      {contentAttackSurfaceAssets.length > 20 && <p className="text-xs text-muted-foreground p-2">... and {contentAttackSurfaceAssets.length - 20} more</p>}
                    </div>
                  </div>
                )}
                {(cloud?.grades != null || (cloud as Record<string, unknown>)?.grades != null) && (
                  <div className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/40">
                    <span className="text-xs text-muted-foreground">Email Security Grade</span>
                    <Badge variant="outline" className={`text-xs border-0 font-mono no-default-hover-elevate no-default-active-elevate ${
                      (cloud?.grades as Record<string, string>)?.overall?.startsWith("A") ? "bg-green-600/15 text-green-400" :
                      (cloud?.grades as Record<string, string>)?.overall?.startsWith("B") ? "bg-blue-600/15 text-blue-400" :
                      "bg-yellow-600/15 text-yellow-400"
                    }`}>
                      {(cloud?.grades as Record<string, string>)?.overall}
                    </Badge>
                  </div>
                )}
              </div>
            </div>
          )}

          {Array.isArray(content?.postureTrend) && (content.postureTrend as Array<{ snapshotAt: string; surfaceRiskScore: number | null; securityScore: number | null; findingsCount: number }>).length > 0 && (
            <div>
              <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2">Posture Trend</h4>
              <div className="rounded-md border overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="text-xs">Date</TableHead>
                      <TableHead className="text-xs">Surface Risk</TableHead>
                      <TableHead className="text-xs">Security Score</TableHead>
                      <TableHead className="text-xs">Findings</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(content.postureTrend as Array<{ snapshotAt: string; surfaceRiskScore: number | null; securityScore: number | null; findingsCount: number }>).map((p, i) => (
                      <TableRow key={i}>
                        <TableCell className="text-xs">{new Date(p.snapshotAt).toLocaleDateString()}</TableCell>
                        <TableCell className="font-mono text-xs">{p.surfaceRiskScore ?? "—"}</TableCell>
                        <TableCell className="font-mono text-xs">{p.securityScore ?? "—"}</TableCell>
                        <TableCell className="text-xs">{p.findingsCount ?? "—"}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </div>
          )}

          {content?.ipEnrichment != null && Object.keys(content.ipEnrichment as object).length > 0 && (
            <div>
              <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2">
                IP Reputation (AbuseIPDB / VirusTotal)
              </h4>
              <div className="space-y-2">
                {Object.entries(content.ipEnrichment as Record<string, { abuseipdb?: { abuseConfidenceScore?: number; totalReports?: number; countryCode?: string; isp?: string } | null; virustotal?: { malicious?: number; suspicious?: number; harmless?: number; as_owner?: string; country?: string } | null }>).map(([ip, data]) => {
                  const abuse = data?.abuseipdb;
                  const vt = data?.virustotal;
                  const score = abuse?.abuseConfidenceScore ?? -1;
                  const scoreColor = score < 0 ? "text-muted-foreground" : score < 25 ? "text-green-400" : score <= 75 ? "text-yellow-400" : "text-red-400";
                  return (
                    <div key={ip} className="p-3 rounded-md bg-muted/40 space-y-2">
                      <div className="flex items-center justify-between gap-2 flex-wrap">
                        <span className="text-sm font-mono font-medium">{ip}</span>
                        <div className="flex gap-2">
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
                        </div>
                      </div>
                      <div className="flex gap-4 text-xs text-muted-foreground flex-wrap">
                        {abuse?.countryCode && <span>Country: {abuse.countryCode}</span>}
                        {abuse?.isp && <span>ISP: {abuse.isp}</span>}
                        {vt?.as_owner && <span>AS: {vt.as_owner}</span>}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {contentOsintDiscovery && (contentOsintDiscovery.summary?.total ?? 0) > 0 && (
            <div>
              <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2">
                OSINT Discovery ({contentOsintDiscovery.summary?.total ?? 0} items)
              </h4>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-3">
                {contentOsintDiscovery.summary?.byCategory && Object.entries(contentOsintDiscovery.summary.byCategory).map(([cat, count]) =>
                  count > 0 ? (
                    <div key={cat} className="p-2 rounded-md bg-muted/40 text-center">
                      <p className="text-sm font-semibold">{count}</p>
                      <p className="text-xs text-muted-foreground capitalize">{cat.replace(/_/g, " ")}</p>
                    </div>
                  ) : null
                )}
              </div>
              <div className="space-y-2">
                {[
                  ...(contentOsintDiscovery.leakedCredentials ?? []),
                  ...(contentOsintDiscovery.exposedDocuments ?? []),
                  ...(contentOsintDiscovery.infrastructureDisclosure ?? []),
                  ...(contentOsintDiscovery.osintExposure ?? []),
                ].slice(0, 10).map((item) => (
                  <div key={item.id} className="flex items-center justify-between gap-3 p-2 rounded-md bg-muted/40">
                    <p className="text-sm truncate flex-1">{item.title}</p>
                    <SeverityBadge severity={item.severity} />
                  </div>
                ))}
                {[
                  ...(contentOsintDiscovery.leakedCredentials ?? []),
                  ...(contentOsintDiscovery.exposedDocuments ?? []),
                  ...(contentOsintDiscovery.infrastructureDisclosure ?? []),
                  ...(contentOsintDiscovery.osintExposure ?? []),
                ].length > 10 ? (
                  <p className="text-xs text-muted-foreground">... and more in included findings</p>
                ) : null}
              </div>
            </div>
          )}

          {reportFindings.length > 0 && (
            <div>
              <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2">
                Included Findings ({reportFindings.length})
              </h4>
              <div className="space-y-2">
                {reportFindings.map((f) => (
                  <div key={f.id} className="flex items-center justify-between gap-3 p-3 rounded-md bg-muted/40">
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium truncate">{f.title}</p>
                      <p className="text-xs text-muted-foreground font-mono truncate">{f.affectedAsset}</p>
                    </div>
                    <SeverityBadge severity={f.severity} />
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="flex items-center gap-2 text-xs text-muted-foreground pt-2 border-t">
            <Clock className="w-3 h-3" />
            Generated: {report.generatedAt ? new Date(report.generatedAt).toLocaleString() : "Not yet generated"}
          </div>
        </div>
      </DialogContent>
      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete report</AlertDialogTitle>
            <AlertDialogDescription>
              Permanently delete &quot;{report.title}&quot;? This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault();
                deleteMutation.mutate();
              }}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              disabled={deleteMutation.isPending}
            >
              {deleteMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : null}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Dialog>
  );
}

const reportFormSchema = z.object({
  title: z.string().min(1, "Report title is required"),
  type: z.enum(["executive_summary", "full_report", "evidence_pack"]),
});

function NewReportDialog() {
  const [open, setOpen] = useState(false);
  const [selectedFindings, setSelectedFindings] = useState<string[]>([]);
  const { toast } = useToast();
  const { selectedWorkspaceId } = useDomain();
  const form = useForm<z.infer<typeof reportFormSchema>>({
    resolver: zodResolver(reportFormSchema),
    defaultValues: { title: "", type: "full_report" },
  });

  const { data: findings = [] } = useQuery<Finding[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/findings`],
    enabled: !!selectedWorkspaceId,
  });

  const mutation = useMutation({
    mutationFn: async (data: { title: string; type: string }) => {
      const res = await apiRequest("POST", `/api/workspaces/${selectedWorkspaceId}/reports`, {
        title: data.title,
        type: data.type,
        status: "draft",
        findingIds: selectedFindings.length > 0 ? selectedFindings : findings.map((f) => f.id),
      });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/reports`] });
      toast({ title: "Report created" });
      setOpen(false);
      form.reset();
      setSelectedFindings([]);
    },
    onError: (error: Error) => {
      toast({ title: "Error", description: error.message, variant: "destructive" });
    },
  });

  const toggleFinding = (id: string) => {
    setSelectedFindings((prev) =>
      prev.includes(id) ? prev.filter((f) => f !== id) : [...prev, id]
    );
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button data-testid="button-new-report">
          <Plus className="w-4 h-4 mr-2" />
          New Report
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Generate Report</DialogTitle>
        </DialogHeader>
        <Form {...form}>
          <form onSubmit={form.handleSubmit((data) => mutation.mutate(data))} className="space-y-4">
            <FormField
              control={form.control}
              name="title"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Report Title</FormLabel>
                  <FormControl>
                    <Input placeholder="Q4 Security Assessment" data-testid="input-report-title" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="type"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Report Type</FormLabel>
                  <Select onValueChange={field.onChange} defaultValue={field.value}>
                    <FormControl>
                      <SelectTrigger data-testid="select-report-type">
                        <SelectValue />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="executive_summary">Executive Summary</SelectItem>
                      <SelectItem value="full_report">Full Report</SelectItem>
                      <SelectItem value="evidence_pack">Evidence Pack</SelectItem>
                    </SelectContent>
                  </Select>
                </FormItem>
              )}
            />

            {findings.length > 0 && (
              <div>
                <FormLabel>Include Findings</FormLabel>
                <p className="text-xs text-muted-foreground mb-2">
                  Select findings to include, or leave empty to include all
                </p>
                <div className="space-y-2 max-h-48 overflow-y-auto border rounded-md p-2">
                  {findings.map((f) => (
                    <div
                      key={f.id}
                      className="flex items-center gap-2 p-2 rounded-md hover-elevate cursor-pointer"
                      onClick={() => toggleFinding(f.id)}
                    >
                      <Checkbox
                        checked={selectedFindings.includes(f.id)}
                        onCheckedChange={() => toggleFinding(f.id)}
                        data-testid={`checkbox-finding-${f.id}`}
                      />
                      <span className="text-sm truncate flex-1">{f.title}</span>
                      <SeverityBadge severity={f.severity} />
                    </div>
                  ))}
                </div>
              </div>
            )}

            <Button type="submit" className="w-full" disabled={mutation.isPending} data-testid="button-generate-report">
              {mutation.isPending ? "Generating..." : "Generate Report"}
            </Button>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

export default function Reports() {
  const [selectedReport, setSelectedReport] = useState<Report | null>(null);
  const { selectedWorkspaceId } = useDomain();

  useEffect(() => {
    setSelectedReport(null);
  }, [selectedWorkspaceId]);

  const { data: reports = [], isLoading } = useQuery<Report[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/reports`],
    enabled: !!selectedWorkspaceId,
  });

  if (isLoading) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-8 w-48 mb-2" />
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-40" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight" data-testid="text-reports-title">Reports</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Generate deterministic security reports with full evidence packs
          </p>
        </div>
        <NewReportDialog />
      </div>

      {reports.length === 0 ? (
        <Card>
          <CardContent className="py-16 text-center">
            <FileText className="w-12 h-12 text-muted-foreground/40 mx-auto mb-4" />
            <p className="text-base font-medium text-muted-foreground">No reports generated yet</p>
            <p className="text-sm text-muted-foreground mt-1">
              Create a report to compile findings with evidence and scoring
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {reports.map((report) => (
            <Card
              key={report.id}
              className="cursor-pointer hover-elevate active-elevate-2"
              onClick={() => setSelectedReport(report)}
              data-testid={`card-report-${report.id}`}
            >
              <CardContent className="p-5 space-y-3">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center justify-center w-10 h-10 rounded-md bg-primary/10 flex-shrink-0">
                    <FileBarChart className="w-5 h-5 text-primary" />
                  </div>
                  <Badge
                    variant="outline"
                    className={`text-xs no-default-hover-elevate no-default-active-elevate ${
                      report.status === "completed"
                        ? "bg-green-600/15 text-green-400 border-0"
                        : report.status === "generating"
                        ? "bg-blue-600/15 text-blue-400 border-0"
                        : ""
                    }`}
                  >
                    {report.status === "generating" && <Loader2 className="w-3 h-3 mr-1 animate-spin" />}
                    {report.status.charAt(0).toUpperCase() + report.status.slice(1)}
                  </Badge>
                </div>

                <div>
                  <h3 className="text-sm font-medium">{report.title}</h3>
                  <p className="text-xs text-muted-foreground capitalize mt-0.5">
                    {report.type.replace(/_/g, " ")}
                  </p>
                </div>

                <div className="flex items-center justify-between gap-2 text-xs text-muted-foreground pt-2 border-t">
                  <span>{(report.findingIds || []).length} findings</span>
                  <span>
                    {report.generatedAt
                      ? new Date(report.generatedAt).toLocaleDateString()
                      : "Draft"}
                  </span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <ReportDetailDialog
        report={selectedReport}
        open={!!selectedReport}
        onOpenChange={(open) => {
          if (!open) setSelectedReport(null);
        }}
        onDeleted={() => setSelectedReport(null)}
      />
    </div>
  );
}
