import { useState, useEffect, useMemo } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Inbox,
  Search,
  Filter,
  AlertTriangle,
  ExternalLink,
  Clock,
  CheckCircle2,
  XCircle,
  Eye,
  ShieldAlert,
  ChevronRight,
  ChevronLeft,
  Sparkles,
  Loader2,
  Database,
  FileSearch,
  Download,
  TicketCheck,
} from "lucide-react";
import type { Finding, Scan } from "@shared/schema";
import { SeverityBadge, StatusBadge } from "@/components/severity-badge";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import { severityMeta } from "@/lib/severity";

/**
 * Remediation-deadline state for a finding.
 *
 * Findings carry `dueDate` and `slaBreached` and nothing rendered them, because
 * until the SLA clock was wired up they were always null/false. Now that they
 * hold real values, an overdue item has to be visible in the list — the whole
 * point of a deadline is that someone sees it before it passes.
 */
function SlaIndicator({ finding }: { finding: Finding }) {
  const closed = ["resolved", "false_positive", "accepted_risk"].includes(finding.status);
  if (closed || !finding.dueDate) return null;

  const due = new Date(finding.dueDate).getTime();
  const hoursLeft = (due - Date.now()) / 3_600_000;

  if (finding.slaBreached || hoursLeft <= 0) {
    const daysOver = Math.floor(-hoursLeft / 24);
    return (
      <span className="inline-flex items-center gap-1 rounded bg-severity-critical/12 px-1.5 py-0.5 text-[0.6875rem] font-medium text-severity-critical">
        <Clock className="h-3 w-3" aria-hidden="true" />
        Overdue{daysOver >= 1 ? ` ${daysOver}d` : ""}
      </span>
    );
  }
  // Only warn inside the last day; anything further out is just noise in a list.
  if (hoursLeft <= 24) {
    return (
      <span className="inline-flex items-center gap-1 rounded bg-severity-medium/12 px-1.5 py-0.5 text-[0.6875rem] font-medium text-severity-medium">
        <Clock className="h-3 w-3" aria-hidden="true" />
        Due in {Math.max(1, Math.round(hoursLeft))}h
      </span>
    );
  }
  return null;
}


function FindingDetail({
  finding,
  open,
  onOpenChange,
  onEnriched,
}: {
  finding: Finding | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onEnriched?: (finding: Finding) => void;
}) {
  const { toast } = useToast();

  const { selectedWorkspaceId } = useDomain();
  const statusMutation = useMutation({
    mutationFn: async ({ id, status }: { id: string; status: string }) => {
      const res = await apiRequest("PATCH", `/api/findings/${id}`, { status });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/findings`] });
      toast({ title: "Finding updated" });
    },
    onError: (err: Error) => {
      toast({ title: "Update failed", description: err.message, variant: "destructive" });
    },
  });

  const enrichMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/workspaces/${selectedWorkspaceId}/findings/${finding!.id}/enrich`, undefined, {
        timeoutMs: 1800000, // 30 min for Ollama
      });
      return res.json();
    },
    onSuccess: (data: Finding) => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/findings`] });
      toast({ title: "Finding enriched with AI" });
      onEnriched?.(data);
    },
    onError: (err: Error) => {
      toast({ title: "Enrichment failed", description: err.message, variant: "destructive" });
    },
  });

  const cveLookupMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/workspaces/${selectedWorkspaceId}/findings/${finding!.id}/cve-lookup`);
      return res.json();
    },
    onSuccess: (data: { finding: Finding; cveRecords?: unknown[] }) => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/findings`] });
      toast({ title: "CVE lookup complete", description: `${(data.cveRecords ?? []).length} CVE(s) found` });
      onEnriched?.(data.finding);
    },
    onError: (err: Error) => {
      toast({ title: "CVE lookup failed", description: err.message, variant: "destructive" });
    },
  });

  const analyzeMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/workspaces/${selectedWorkspaceId}/findings/${finding!.id}/analyze`, undefined, {
        timeoutMs: 1800000, // 30 min for Ollama
      });
      return res.json();
    },
    onSuccess: (data: { finding: Finding }) => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/findings`] });
      toast({ title: "Detailed analysis complete" });
      onEnriched?.(data.finding);
    },
    onError: (err: Error) => {
      toast({ title: "Analysis failed", description: err.message, variant: "destructive" });
    },
  });

  const { data: ticketingStatus } = useQuery<{
    jira: { configured: boolean };
    github: { configured: boolean };
  }>({
    queryKey: ["/api/integrations/ticketing"],
  });

  const ticketMutation = useMutation({
    mutationFn: async (provider: "jira" | "github") => {
      const res = await apiRequest("POST", "/api/integrations/ticketing/create", {
        findingId: finding!.id,
        provider,
      });
      return res.json() as Promise<{ ticketUrl: string }>;
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/findings`] });
      toast({ title: "Ticket created", description: data.ticketUrl });
    },
    onError: (err: Error) => {
      toast({ title: "Ticket creation failed", description: err.message, variant: "destructive" });
    },
  });

  if (!finding) return null;

  const evidence = Array.isArray(finding.evidence) ? finding.evidence : [];
  const aiEnrichment = finding.aiEnrichment as {
    enhancedDescription?: string;
    contextualRisks?: string;
    additionalRemediation?: string;
    enrichedAt?: string;
    cveData?: { records?: Array<{ cveId: string; description?: string; cvssScore?: number; cvssSeverity?: string; url: string }> };
    detailedAnalysis?: { analysis?: string; recommendations?: string[]; analyzedAt?: string };
    ticketUrl?: string;
    ticketProvider?: string;
  } | null | undefined;
  const cveRecords = aiEnrichment?.cveData?.records ?? [];
  const detailedAnalysis = aiEnrichment?.detailedAnalysis;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <div className="flex items-start gap-3">
            <div className="flex items-center justify-center w-10 h-10 rounded-md bg-primary/10 flex-shrink-0 mt-0.5">
              <ShieldAlert className="w-5 h-5 text-primary" />
            </div>
            <div className="space-y-1 min-w-0 flex-1">
              <DialogTitle className="text-base leading-snug">{finding.title}</DialogTitle>
              <div className="flex items-center gap-2 flex-wrap">
                <SeverityBadge severity={finding.severity} />
                <StatusBadge status={finding.status} />
                {finding.cvssScore && (
                  <Badge variant="outline" className="text-xs font-mono no-default-hover-elevate no-default-active-elevate">
                    CVSS {finding.cvssScore}
                  </Badge>
                )}
              </div>
            </div>
          </div>
        </DialogHeader>

        <div className="space-y-5 mt-2">
          <div className="flex items-start justify-between gap-2">
            <div className="flex-1 min-w-0">
              <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2">Description</h4>
              <p className="text-sm leading-relaxed">{aiEnrichment?.enhancedDescription ?? finding.description}</p>
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <Button
                variant="outline"
                size="sm"
                onClick={() => enrichMutation.mutate()}
                disabled={enrichMutation.isPending}
                data-testid="button-enrich-ai"
              >
                {enrichMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
                {enrichMutation.isPending ? "Enriching..." : "Enrich with AI"}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => cveLookupMutation.mutate()}
                disabled={cveLookupMutation.isPending}
                data-testid="button-cve-lookup"
              >
                {cveLookupMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Database className="w-4 h-4" />}
                {cveLookupMutation.isPending ? "Looking up..." : "Look up CVE"}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => analyzeMutation.mutate()}
                disabled={analyzeMutation.isPending}
                data-testid="button-analyze"
              >
                {analyzeMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileSearch className="w-4 h-4" />}
                {analyzeMutation.isPending ? "Analyzing..." : "Detailed Analysis"}
              </Button>
              {aiEnrichment?.ticketUrl ? (
                <a href={aiEnrichment.ticketUrl} target="_blank" rel="noopener noreferrer">
                  <Button variant="outline" size="sm">
                    <ExternalLink className="w-4 h-4" />
                    View {aiEnrichment.ticketProvider === "jira" ? "Jira" : "GitHub"} Ticket
                  </Button>
                </a>
              ) : (
                <>
                  {ticketingStatus?.jira?.configured && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => ticketMutation.mutate("jira")}
                      disabled={ticketMutation.isPending}
                    >
                      {ticketMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <TicketCheck className="w-4 h-4" />}
                      Jira Ticket
                    </Button>
                  )}
                  {ticketingStatus?.github?.configured && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => ticketMutation.mutate("github")}
                      disabled={ticketMutation.isPending}
                    >
                      {ticketMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <TicketCheck className="w-4 h-4" />}
                      GitHub Issue
                    </Button>
                  )}
                </>
              )}
            </div>
          </div>
          {aiEnrichment?.contextualRisks && (
            <div>
              <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2">Contextual Risks (AI)</h4>
              <p className="text-sm leading-relaxed">{aiEnrichment.contextualRisks}</p>
            </div>
          )}

          {cveRecords.length > 0 && (
            <div>
              <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2">Related CVEs</h4>
              <div className="flex flex-wrap gap-2">
                {cveRecords.map((c) => (
                  <a
                    key={c.cveId}
                    href={c.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1"
                  >
                    <Badge variant="outline" className="font-mono text-xs no-default-hover-elevate no-default-active-elevate">
                      {c.cveId}
                      {c.cvssScore != null ? ` CVSS ${c.cvssScore}` : ""}
                    </Badge>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                ))}
              </div>
            </div>
          )}

          {detailedAnalysis?.analysis && (
            <div>
              <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2">Detailed Analysis (AI)</h4>
              <p className="text-sm leading-relaxed">{detailedAnalysis.analysis}</p>
              {(detailedAnalysis.recommendations?.length ?? 0) > 0 && (
                <div className="mt-3">
                  <h5 className="text-xs font-medium text-muted-foreground mb-2">Recommendations</h5>
                  <ul className="list-disc list-inside space-y-1 text-sm">
                    {detailedAnalysis.recommendations?.map((r, i) => (
                      <li key={i}>{r}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {finding.affectedAsset && (
            <div>
              <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2">Affected Asset</h4>
              <p className="text-sm font-mono bg-muted/50 px-3 py-2 rounded-md">{finding.affectedAsset}</p>
            </div>
          )}

          {(finding.remediation || aiEnrichment?.additionalRemediation) && (
            <div>
              <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2">Remediation</h4>
              <p className="text-sm leading-relaxed">{finding.remediation}</p>
              {aiEnrichment?.additionalRemediation && (
                <p className="text-sm leading-relaxed mt-2 text-muted-foreground border-l-2 border-primary/50 pl-3">
                  <span className="text-xs font-medium text-primary">AI additional:</span> {aiEnrichment.additionalRemediation}
                </p>
              )}
            </div>
          )}

          {evidence.length > 0 && (
            <div>
              <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2">Evidence</h4>
              <div className="space-y-3">
                {evidence.map((rawEv: Record<string, unknown>, i: number) => {
                  const ev = {
                    type: rawEv.type ? String(rawEv.type) : "",
                    description: rawEv.description ? String(rawEv.description) : "",
                    url: rawEv.url ? String(rawEv.url) : "",
                    snippet: rawEv.snippet ? String(rawEv.snippet) : "",
                    source: rawEv.source ? String(rawEv.source) : "",
                    verifiedAt: rawEv.verifiedAt ? String(rawEv.verifiedAt) : "",
                  };
                  return (
                    <div key={i} className="bg-muted/50 rounded-md p-3 space-y-2" data-testid={`evidence-item-${i}`}>
                      <div className="flex items-center gap-2 flex-wrap">
                        {ev.type && <Badge variant="outline" className="text-xs no-default-hover-elevate no-default-active-elevate">{ev.type}</Badge>}
                        {ev.source && (
                          <span className="text-xs text-muted-foreground">
                            Source: {ev.source}
                          </span>
                        )}
                      </div>
                      {ev.description && <p className="text-sm">{ev.description}</p>}
                      {ev.url && (
                        <a
                          href={ev.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-xs text-primary inline-flex items-center gap-1"
                          data-testid={`link-evidence-${i}`}
                        >
                          <ExternalLink className="w-3 h-3" />
                          {ev.url}
                        </a>
                      )}
                      {ev.snippet && (
                        <pre className="text-xs font-mono bg-background p-2 rounded-md overflow-x-auto mt-1 whitespace-pre-wrap">{ev.snippet}</pre>
                      )}
                      {ev.verifiedAt && (
                        <div className="flex items-center gap-1 text-xs text-muted-foreground pt-1 border-t border-border/50">
                          <CheckCircle2 className="w-3 h-3 text-green-500" />
                          Verified: {new Date(ev.verifiedAt).toLocaleString()}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          <div>
            <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2">Lifecycle</h4>
            <div className="flex items-center gap-2 flex-wrap">
              {["open", "in_review", "resolved", "false_positive", "accepted_risk"].map((s) => (
                <Button
                  key={s}
                  variant={finding.status === s ? "default" : "outline"}
                  size="sm"
                  onClick={() => statusMutation.mutate({ id: finding.id, status: s })}
                  disabled={statusMutation.isPending}
                  data-testid={`button-status-${s}`}
                >
                  {s === "open" && <AlertTriangle className="w-3 h-3 mr-1" />}
                  {s === "in_review" && <Eye className="w-3 h-3 mr-1" />}
                  {s === "resolved" && <CheckCircle2 className="w-3 h-3 mr-1" />}
                  {s === "false_positive" && <XCircle className="w-3 h-3 mr-1" />}
                  {s === "accepted_risk" && <ShieldAlert className="w-3 h-3 mr-1" />}
                  {s.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase())}
                </Button>
              ))}
            </div>
          </div>

          <div className="flex items-center gap-4 text-xs text-muted-foreground pt-2 border-t flex-wrap">
            <div className="flex items-center gap-1">
              <Clock className="w-3 h-3" />
              Discovered: {finding.discoveredAt ? new Date(finding.discoveredAt).toLocaleString() : "Unknown"}
            </div>
            {finding.resolvedAt && (
              <div className="flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3" />
                Resolved: {new Date(finding.resolvedAt).toLocaleString()}
              </div>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

const PAGE_SIZE = 50;

function exportFindingsCSV(findings: Finding[]) {
  const esc = (v: string) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const headers = ["ID", "Title", "Severity", "Status", "Category", "Affected Asset", "CVSS Score", "Discovered At"];
  const rows = findings.map((f) =>
    [
      esc(f.id),
      esc(f.title ?? ""),
      esc(f.severity),
      esc(f.status),
      esc(f.category),
      esc(f.affectedAsset ?? ""),
      esc(String(f.cvssScore ?? "")),
      esc(f.discoveredAt ? new Date(f.discoveredAt).toISOString() : ""),
    ].join(",")
  );
  const csv = [headers.join(","), ...rows].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `findings-export-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function Findings() {
  const { selectedWorkspaceId } = useDomain();
  const { toast } = useToast();

  const { data: ticketingStatus } = useQuery<{
    jira: { configured: boolean };
    github: { configured: boolean };
  }>({
    queryKey: ["/api/integrations/ticketing"],
  });

  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [currentPage, setCurrentPage] = useState(1);

  useEffect(() => {
    setSelectedFinding(null);
    setSearchQuery("");
    setSeverityFilter("all");
    setStatusFilter("all");
    setCategoryFilter("all");
    setSelectedIds(new Set());
    setCurrentPage(1);
  }, [selectedWorkspaceId]);

  // Reset to page 1 when filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery, severityFilter, statusFilter, categoryFilter]);

  const { data: scans = [] } = useQuery<Scan[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/scans`],
    enabled: !!selectedWorkspaceId,
    refetchInterval: (q) =>
      (q.state.data as Scan[] | undefined)?.some((s) => s.status === "running" || s.status === "pending") ? 2000 : false,
  });
  const hasRunningScans = scans.some((s) => s.status === "running" || s.status === "pending");

  const { data: findings = [], isLoading } = useQuery<Finding[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/findings`],
    enabled: !!selectedWorkspaceId,
    refetchInterval: hasRunningScans ? 4000 : false,
  });

  // Derive filtered list BEFORE handlers that depend on it
  const filtered = findings.filter((f) => {
    const matchesSearch =
      f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (f.affectedAsset || "").toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSeverity = severityFilter === "all" || f.severity === severityFilter;
    const matchesStatus = statusFilter === "all" || f.status === statusFilter;
    const matchesCategory = categoryFilter === "all" || f.category === categoryFilter;
    return matchesSearch && matchesSeverity && matchesStatus && matchesCategory;
  });

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(currentPage, totalPages);
  const paginatedFindings = filtered.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  const bulkUpdateMutation = useMutation({
    mutationFn: async ({ ids, status }: { ids: string[]; status: string }) => {
      await Promise.all(ids.map((id) => apiRequest("PATCH", `/api/findings/${id}`, { status })));
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/findings`] });
      setSelectedIds(new Set());
      toast({ title: `${selectedIds.size} finding(s) updated` });
    },
    onError: (err: Error) => {
      toast({ title: "Bulk update failed", description: err.message, variant: "destructive" });
    },
  });

  const toggleSelect = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // Operates on all filtered findings (not just current page)
  const toggleSelectAll = () => {
    if (selectedIds.size === filtered.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filtered.map((f) => f.id)));
    }
  };

  const enrichAllMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/workspaces/${selectedWorkspaceId}/findings/enrich-all`, undefined, {
        timeoutMs: 3600000, // 60 min for batch
      });
      return res.json();
    },
    onSuccess: (data: { enriched: number; total: number }) => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/findings`] });
      toast({ title: "Enrichment complete", description: `Enriched ${data.enriched} of ${data.total} findings` });
    },
    onError: (err: Error) => {
      toast({ title: "Enrichment failed", description: err.message, variant: "destructive" });
    },
  });

  const countBySeverity = useMemo(() => ({
    critical: (findings ?? []).filter((f) => f.severity === "critical").length,
    high: (findings ?? []).filter((f) => f.severity === "high").length,
    medium: (findings ?? []).filter((f) => f.severity === "medium").length,
    low: (findings ?? []).filter((f) => f.severity === "low").length,
  }), [findings]);

  if (!selectedWorkspaceId) {
    return (
      <div className="p-6">
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-16">
            <Inbox className="w-12 h-12 text-muted-foreground mb-4" />
            <p className="text-muted-foreground">Select a workspace to view findings</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-8 w-48 mb-2" />
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-20" />
          ))}
        </div>
        <Skeleton className="h-96" />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-[1600px] space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight" data-testid="text-findings-title">Findings Inbox</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Triage, investigate, and manage security findings with full lifecycle tracking
        </p>
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {Object.entries(countBySeverity).map(([severity, count]) => {
          const meta = severityMeta(severity);
          const active = severityFilter === severity;
          return (
            <button
              key={severity}
              type="button"
              // A filter is a control, not a card: it must be reachable by
              // keyboard and announce its pressed state.
              aria-pressed={active}
              onClick={() => setSeverityFilter(active ? "all" : severity)}
              data-testid={`card-filter-${severity}`}
              className={cn(
                "group relative overflow-hidden rounded-xl border bg-surface-2 p-4 text-left transition-all",
                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                active ? "border-primary/50 shadow-lift" : "border-hairline hover:border-primary/30",
              )}
            >
              <span
                aria-hidden="true"
                className={cn("absolute inset-x-0 top-0 h-0.5 transition-opacity", meta.solid,
                  active ? "opacity-100" : "opacity-40 group-hover:opacity-70")}
              />
              <div className="flex items-center justify-between gap-2">
                <div>
                  <p className="text-display-sm font-semibold tabular-nums">{count}</p>
                  <p className="mt-0.5 text-xs capitalize text-muted-foreground">{meta.label}</p>
                </div>
                <span className={cn("h-2.5 w-2.5 rounded-full", meta.solid)} aria-hidden="true" />
              </div>
            </button>
          );
        })}
      </div>

      <Card data-testid="card-findings-table">
        <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2 flex-wrap">
          <CardTitle className="text-sm font-medium">
            Findings ({filtered.length.toLocaleString()})
          </CardTitle>
          <div className="flex items-center gap-2 flex-wrap">
            {selectedIds.size > 0 && (
              <>
                <span className="text-xs text-muted-foreground">{selectedIds.size} selected</span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => bulkUpdateMutation.mutate({ ids: Array.from(selectedIds), status: "resolved" })}
                  disabled={bulkUpdateMutation.isPending}
                >
                  {bulkUpdateMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <CheckCircle2 className="w-4 h-4" />}
                  Resolve
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => bulkUpdateMutation.mutate({ ids: Array.from(selectedIds), status: "in_review" })}
                  disabled={bulkUpdateMutation.isPending}
                >
                  <Eye className="w-4 h-4" />
                  In Review
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => bulkUpdateMutation.mutate({ ids: Array.from(selectedIds), status: "false_positive" })}
                  disabled={bulkUpdateMutation.isPending}
                >
                  <XCircle className="w-4 h-4" />
                  False Positive
                </Button>
                {(ticketingStatus?.jira?.configured || ticketingStatus?.github?.configured) && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={async () => {
                      const provider = ticketingStatus?.jira?.configured ? "jira" : "github";
                      try {
                        const res = await apiRequest("POST", "/api/integrations/ticketing/bulk-create", {
                          findingIds: Array.from(selectedIds),
                          provider,
                        });
                        const data = await res.json() as { results: Array<{ ticketUrl?: string; error?: string }> };
                        const created = data.results.filter((r) => r.ticketUrl).length;
                        queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/findings`] });
                        toast({ title: `${created} ticket(s) created` });
                      } catch (err) {
                        toast({ title: "Bulk ticket creation failed", description: err instanceof Error ? err.message : "Failed", variant: "destructive" });
                      }
                    }}
                  >
                    <TicketCheck className="w-4 h-4" />
                    Create Tickets
                  </Button>
                )}
              </>
            )}
            <Button
              variant="outline"
              size="sm"
              onClick={() => exportFindingsCSV(filtered)}
              disabled={filtered.length === 0}
              data-testid="button-export-csv"
            >
              <Download className="w-4 h-4" />
              Export CSV
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => enrichAllMutation.mutate()}
              disabled={enrichAllMutation.isPending || filtered.length === 0}
              data-testid="button-enrich-all"
            >
              {enrichAllMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
              {enrichAllMutation.isPending ? "Enriching..." : "Enrich all"}
            </Button>
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Search findings..."
                className="pl-9 h-9 w-48"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                data-testid="input-search-findings"
              />
            </div>
            <Select value={categoryFilter} onValueChange={setCategoryFilter}>
              <SelectTrigger className="h-9 w-40" aria-label="Filter by category">
                <SelectValue placeholder="Category" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Categories</SelectItem>
                <SelectItem value="ssl_issue">SSL Issue</SelectItem>
                <SelectItem value="security_headers">Security Headers</SelectItem>
                <SelectItem value="vulnerability">Vulnerability</SelectItem>
                <SelectItem value="dns_misconfiguration">DNS Misconfig</SelectItem>
                <SelectItem value="infrastructure_disclosure">Infrastructure</SelectItem>
                <SelectItem value="information_disclosure">Info Disclosure</SelectItem>
                <SelectItem value="leaked_credential">Leaked Credential</SelectItem>
                <SelectItem value="data_leak">Data Leak</SelectItem>
                <SelectItem value="osint_exposure">OSINT Exposure</SelectItem>
                <SelectItem value="cors_misconfiguration">CORS Misconfig</SelectItem>
                <SelectItem value="xss">XSS</SelectItem>
                <SelectItem value="clickjacking">Clickjacking</SelectItem>
                <SelectItem value="open_redirect">Open Redirect</SelectItem>
                <SelectItem value="cookie_security">Cookie Security</SelectItem>
                <SelectItem value="transport_security">Transport Security</SelectItem>
                <SelectItem value="http_methods">HTTP Methods</SelectItem>
                <SelectItem value="subdomain_takeover">Subdomain Takeover</SelectItem>
                <SelectItem value="api_exposure">API Exposure</SelectItem>
                <SelectItem value="exposed_credentials">Exposed Credentials</SelectItem>
              </SelectContent>
            </Select>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="h-9 w-36" aria-label="Filter by status" data-testid="select-status-filter">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="open">Open</SelectItem>
                <SelectItem value="in_review">In Review</SelectItem>
                <SelectItem value="resolved">Resolved</SelectItem>
                <SelectItem value="false_positive">False Positive</SelectItem>
                <SelectItem value="accepted_risk">Accepted Risk</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent>
          {filtered.length === 0 ? (
            <div className="text-center py-12">
              <Inbox className="w-10 h-10 text-muted-foreground/40 mx-auto mb-3" />
              <p className="text-sm text-muted-foreground">No findings match your filters</p>
              <p className="text-xs text-muted-foreground mt-1">
                {findings.length === 0
                  ? "Run a scan to discover vulnerabilities"
                  : "Try adjusting your search or filters"}
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              <div className="flex items-center gap-3 px-3 py-1">
                <Checkbox
                  checked={filtered.length > 0 && selectedIds.size === filtered.length}
                  onCheckedChange={toggleSelectAll}
                  aria-label="Select all findings"
                />
                <span className="text-xs text-muted-foreground">Select all</span>
              </div>
              {paginatedFindings.map((finding) => (
                <div
                  key={finding.id}
                  className="flex items-center justify-between gap-4 rounded-lg border border-transparent bg-surface-inset/60 p-3 transition-colors hover:border-hairline hover:bg-surface-3/50"
                  data-testid={`finding-item-${finding.id}`}
                >
                  <div className="flex items-center gap-3 min-w-0 flex-1">
                    <Checkbox
                      checked={selectedIds.has(finding.id)}
                      onCheckedChange={() => toggleSelect(finding.id)}
                      onClick={(e) => e.stopPropagation()}
                      aria-label={`Select ${finding.title}`}
                    />
                    <span
                      aria-hidden="true"
                      className={cn("h-8 w-1.5 flex-shrink-0 rounded-full", severityMeta(finding.severity).solid)}
                    />
                    <div
                      className="min-w-0 flex-1 cursor-pointer active-elevate-2"
                      onClick={() => setSelectedFinding(finding)}
                    >
                      <p className="text-sm font-medium truncate">{finding.title}</p>
                      <div className="mt-0.5 flex flex-wrap items-center gap-2">
                        <span className="truncate font-mono text-xs text-muted-foreground">{finding.affectedAsset}</span>
                        <span className="text-xs capitalize text-muted-foreground">
                          {finding.category.replace(/_/g, " ")}
                        </span>
                        <SlaIndicator finding={finding} />
                      </div>
                    </div>
                  </div>
                  <div
                    className="flex items-center gap-2 flex-shrink-0 flex-wrap cursor-pointer"
                    onClick={() => setSelectedFinding(finding)}
                  >
                    <SeverityBadge severity={finding.severity} />
                    <StatusBadge status={finding.status} />
                    {finding.cvssScore && (
                      <Badge variant="outline" className="text-xs font-mono no-default-hover-elevate no-default-active-elevate">
                        {finding.cvssScore}
                      </Badge>
                    )}
                    <ChevronRight className="w-4 h-4 text-muted-foreground" />
                  </div>
                </div>
              ))}
              {totalPages > 1 && (
                <div className="flex items-center justify-between pt-3 border-t border-border/50">
                  <span className="text-xs text-muted-foreground">
                    {(safePage - 1) * PAGE_SIZE + 1}–{Math.min(safePage * PAGE_SIZE, filtered.length)} of {filtered.length.toLocaleString()}
                  </span>
                  <div className="flex items-center gap-1">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                      disabled={safePage === 1}
                      className="h-7 px-2"
                    >
                      <ChevronLeft className="w-4 h-4" />
                    </Button>
                    <span className="text-xs text-muted-foreground px-2">
                      {safePage} / {totalPages}
                    </span>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                      disabled={safePage === totalPages}
                      className="h-7 px-2"
                    >
                      <ChevronRight className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      <FindingDetail
        finding={selectedFinding}
        open={!!selectedFinding}
        onOpenChange={(open) => {
          if (!open) setSelectedFinding(null);
        }}
        onEnriched={setSelectedFinding}
      />
    </div>
  );
}
