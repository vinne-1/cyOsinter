import { useQuery, useMutation } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  AlertTriangle,
  ExternalLink,
  Clock,
  CheckCircle2,
  XCircle,
  Eye,
  ShieldAlert,
  Sparkles,
  Loader2,
  Database,
  FileSearch,
  TicketCheck,
} from "lucide-react";
import type { Finding } from "@shared/schema";
import { SeverityBadge, StatusBadge } from "@/components/severity-badge";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

/**
 * The full finding detail dialog — description, AI enrichment/CVE lookup/
 * detailed analysis actions, evidence, ticketing, and lifecycle status
 * controls. Originally only reachable from the Findings inbox; every OTHER
 * page that lists findings (OSINT Discovery, and any future one) renders
 * finding titles too, so this is the one place that logic lives rather than
 * a second, divergent implementation per page.
 */
export function FindingDetailDialog({
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
