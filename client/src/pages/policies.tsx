import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { useState } from "react";
import { Loader2 } from "lucide-react";

interface PolicyDocument {
  id: string;
  policyType: string;
  title: string;
  version: string;
  effectiveDate: string;
  content: string;
}

const POLICY_TYPES = [
  { value: "access_control", label: "Access Control" },
  { value: "change_management", label: "Change Management" },
  { value: "incident_response", label: "Incident Response" },
  { value: "risk_assessment", label: "Risk Assessment" },
  { value: "vendor_management", label: "Vendor Management" },
  { value: "data_classification", label: "Data Classification" },
  { value: "acceptable_use", label: "Acceptable Use" },
  { value: "business_continuity", label: "Business Continuity" },
];

export default function PoliciesPage() {
  const { selectedWorkspaceId } = useDomain();
  const { toast } = useToast();
  const qc = useQueryClient();
  const [policyType, setPolicyType] = useState<string>("access_control");

  const queryKey = [`/api/workspaces/${selectedWorkspaceId}/policies`];
  const { data: policies = [], isLoading } = useQuery<PolicyDocument[]>({
    queryKey,
    enabled: !!selectedWorkspaceId,
  });

  const generateMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/workspaces/${selectedWorkspaceId}/policies`, { policyType });
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Policy generated" });
      qc.invalidateQueries({ queryKey });
    },
    onError: (err: Error) => toast({ title: "Policy generation failed", description: err.message, variant: "destructive" }),
  });

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Policies</h1>
          <p className="text-sm text-muted-foreground">Generate and manage compliance policy documents.</p>
        </div>
        <div className="flex items-center gap-2">
          <Select value={policyType} onValueChange={setPolicyType}>
            <SelectTrigger className="w-[220px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {POLICY_TYPES.map((type) => (
                <SelectItem key={type.value} value={type.value}>{type.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button onClick={() => generateMutation.mutate()} disabled={!selectedWorkspaceId || generateMutation.isPending}>
            {generateMutation.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : null}
            Generate
          </Button>
        </div>
      </div>

      {!selectedWorkspaceId ? (
        <Card><CardContent className="py-10 text-center text-sm text-muted-foreground">Select a workspace to manage policy documents.</CardContent></Card>
      ) : null}

      {isLoading ? <p className="text-sm text-muted-foreground">Loading policy documents...</p> : null}
      {selectedWorkspaceId && !isLoading && policies.length === 0 ? (
        <Card><CardContent className="py-10 text-center text-sm text-muted-foreground">No policy documents generated yet.</CardContent></Card>
      ) : null}

      <div className="space-y-4">
        {policies.map((policy) => (
          <Card key={policy.id}>
            <CardHeader>
              <CardTitle className="text-base">{policy.title}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <p className="text-xs text-muted-foreground">
                Type: {policy.policyType} • Version: {policy.version} • Effective: {new Date(policy.effectiveDate).toLocaleDateString()}
              </p>
              <pre className="max-h-64 overflow-auto rounded-md border bg-muted/20 p-3 text-xs whitespace-pre-wrap">
                {policy.content}
              </pre>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

