import DOMPurify from "dompurify";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { CheckCircle2, CircleDashed, Download, Loader2, RefreshCw, Trash2 } from "lucide-react";

interface PolicyDocument {
  id: string;
  policyType: string;
  title: string;
  version: string;
  effectiveDate: string;
  content: string;
}

const POLICY_TYPES: Array<{ value: string; label: string; description: string }> = [
  { value: "access_control",     label: "Access Control",     description: "Least-privilege, MFA, PAM, access reviews" },
  { value: "incident_response",  label: "Incident Response",  description: "Detection, containment, recovery, notification" },
  { value: "data_classification",label: "Data Classification",description: "Tiers, encryption, retention, disposal" },
  { value: "change_management",  label: "Change Management",  description: "CAB, separation of duties, patch cadence" },
  { value: "vendor_management",  label: "Vendor Management",  description: "Third-party risk, DPA, offboarding" },
  { value: "risk_assessment",    label: "Risk Assessment",    description: "Risk register, scoring, treatment, acceptance" },
  { value: "business_continuity",label: "Business Continuity",description: "BCP, DR, RTO/RPO, backup testing" },
  { value: "acceptable_use",     label: "Acceptable Use",     description: "Permitted use, prohibited activities, monitoring" },
];

function downloadMarkdown(filename: string, content: string) {
  const blob = new Blob([content], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function renderMarkdown(content: string): string {
  return content
    .replace(/^# (.+)$/gm, '<h1 class="text-xl font-bold mt-4 mb-2">$1</h1>')
    .replace(/^## (.+)$/gm, '<h2 class="text-base font-semibold mt-5 mb-2 border-b pb-1">$1</h2>')
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/^(\|.+\|)$/gm, (line) => {
      if (/^\|[-| ]+\|$/.test(line)) return "";
      const cells = line.split("|").filter((c) => c.trim() !== "");
      return `<tr>${cells.map((c) => `<td class="px-3 py-1 text-xs border border-muted/40">${c.trim()}</td>`).join("")}</tr>`;
    })
    .replace(/((?:<tr>.+<\/tr>\n?)+)/gm, (rows) =>
      `<table class="w-full border-collapse my-3 text-xs">${rows}</table>`,
    )
    .replace(/^[-*] (.+)$/gm, '<li class="ml-5 list-disc text-sm my-0.5">$1</li>')
    .replace(/^(\d+)\. (.+)$/gm, '<li class="ml-5 list-decimal text-sm my-0.5">$2</li>')
    .replace(/^(?!<[a-z])(.{1,})$/gm, '<p class="text-sm my-1">$1</p>')
    .replace(/^$/gm, "");
}

export default function PoliciesPage() {
  const { selectedWorkspaceId } = useDomain();
  const { toast } = useToast();
  const qc = useQueryClient();

  const queryKey = [`/api/workspaces/${selectedWorkspaceId}/policies`];
  const { data: policies = [], isLoading } = useQuery<PolicyDocument[]>({
    queryKey,
    enabled: !!selectedWorkspaceId,
  });

  const generatedTypes = new Set(policies.map((p) => p.policyType));
  const generatedCount = generatedTypes.size;
  const totalCount = POLICY_TYPES.length;

  const generateMutation = useMutation({
    mutationFn: async (policyType: string) => {
      const res = await apiRequest("POST", `/api/workspaces/${selectedWorkspaceId}/policies`, { policyType });
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Policy generated successfully" });
      qc.invalidateQueries({ queryKey });
    },
    onError: (err: Error) =>
      toast({ title: "Policy generation failed", description: err.message, variant: "destructive" }),
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/workspaces/${selectedWorkspaceId}/policies/${id}`);
    },
    onSuccess: () => {
      toast({ title: "Policy deleted" });
      qc.invalidateQueries({ queryKey });
    },
    onError: (err: Error) =>
      toast({ title: "Delete failed", description: err.message, variant: "destructive" }),
  });

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Policies</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Generate compliance policy documents from your scan findings. Open findings are injected as risk context automatically.
        </p>
      </div>

      {!selectedWorkspaceId ? (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted-foreground">
            Select a workspace to manage policy documents.
          </CardContent>
        </Card>
      ) : (
        <>
          {/* Coverage grid */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <p className="text-sm font-medium text-muted-foreground">
                Coverage — {generatedCount}/{totalCount} policies generated
              </p>
              <div className="h-2 w-40 rounded-full bg-muted overflow-hidden">
                <div
                  className="h-full bg-green-500 transition-all duration-500"
                  style={{ width: `${Math.round((generatedCount / totalCount) * 100)}%` }}
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {POLICY_TYPES.map((pt) => {
                const exists = generatedTypes.has(pt.value);
                const isGenerating =
                  generateMutation.isPending && generateMutation.variables === pt.value;
                return (
                  <Card
                    key={pt.value}
                    className={`transition-colors ${
                      exists
                        ? "border-green-500/40 bg-green-500/5 dark:bg-green-900/10"
                        : "border-dashed"
                    }`}
                  >
                    <CardContent className="p-4 space-y-2">
                      <div className="flex items-start justify-between gap-2">
                        <span className="text-sm font-medium leading-tight">{pt.label}</span>
                        {exists ? (
                          <CheckCircle2 className="w-4 h-4 text-green-500 shrink-0 mt-0.5" />
                        ) : (
                          <CircleDashed className="w-4 h-4 text-muted-foreground shrink-0 mt-0.5" />
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground leading-snug">{pt.description}</p>
                      <Button
                        size="sm"
                        variant={exists ? "outline" : "default"}
                        className="w-full"
                        disabled={!selectedWorkspaceId || isGenerating}
                        onClick={() => generateMutation.mutate(pt.value)}
                      >
                        {isGenerating ? (
                          <Loader2 className="w-3 h-3 mr-1 animate-spin" />
                        ) : exists ? (
                          <RefreshCw className="w-3 h-3 mr-1" />
                        ) : null}
                        {exists ? "Regenerate" : "Generate"}
                      </Button>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          </div>

          {/* Document list */}
          {isLoading ? (
            <p className="text-sm text-muted-foreground">Loading policy documents…</p>
          ) : policies.length === 0 ? (
            <Card>
              <CardContent className="py-10 text-center text-sm text-muted-foreground">
                No policy documents generated yet. Click "Generate" on any policy card above to create
                a context-aware compliance document.
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              {policies.map((policy) => (
                <Card key={policy.id}>
                  <CardHeader className="pb-2">
                    <div className="flex items-start justify-between gap-3">
                      <div className="space-y-1">
                        <CardTitle className="text-base">{policy.title}</CardTitle>
                        <div className="flex items-center gap-2 flex-wrap">
                          <Badge variant="outline" className="text-xs font-mono">
                            v{policy.version}
                          </Badge>
                          <Badge variant="secondary" className="text-xs">
                            {policy.policyType.replace(/_/g, " ")}
                          </Badge>
                          <span className="text-xs text-muted-foreground">
                            Effective {new Date(policy.effectiveDate).toLocaleDateString()}
                          </span>
                        </div>
                      </div>
                      <div className="flex items-center gap-1 shrink-0">
                        <Button
                          size="icon"
                          variant="ghost"
                          title="Download as Markdown"
                          aria-label="Download as Markdown"
                          onClick={() =>
                            downloadMarkdown(
                              `${policy.policyType}-v${policy.version}.md`,
                              policy.content,
                            )
                          }
                        >
                          <Download className="w-4 h-4" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          className="text-destructive hover:text-destructive"
                          title="Delete policy"
                          aria-label="Delete policy"
                          disabled={deleteMutation.isPending}
                          onClick={() => deleteMutation.mutate(policy.id)}
                        >
                          <Trash2 className="w-4 h-4" />
                        </Button>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div
                      className="max-h-96 overflow-auto rounded-md border bg-muted/10 p-4 text-sm leading-relaxed"
                      dangerouslySetInnerHTML={{
                        __html: DOMPurify.sanitize(renderMarkdown(policy.content)),
                      }}
                    />
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
