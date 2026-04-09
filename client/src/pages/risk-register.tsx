import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { Loader2 } from "lucide-react";

interface RiskItem {
  id: string;
  title: string;
  description: string;
  category: string;
  likelihood: "low" | "medium" | "high";
  impact: "low" | "medium" | "high";
  riskScore: number;
  riskLevel: "low" | "medium" | "high";
  owner: string | null;
  treatment: "mitigate" | "accept" | "transfer" | "avoid";
  status: "open" | "in_progress" | "accepted" | "resolved";
}

const riskLevelClass: Record<string, string> = {
  high: "bg-red-500/10 text-red-500",
  medium: "bg-yellow-500/10 text-yellow-500",
  low: "bg-emerald-500/10 text-emerald-500",
};

export default function RiskRegisterPage() {
  const { selectedWorkspaceId } = useDomain();
  const qc = useQueryClient();
  const { toast } = useToast();
  const [newTitle, setNewTitle] = useState("");
  const [newDesc, setNewDesc] = useState("");

  const queryKey = useMemo(() => [`/api/workspaces/${selectedWorkspaceId}/risk-register`], [selectedWorkspaceId]);

  const { data: items = [], isLoading } = useQuery<RiskItem[]>({
    queryKey,
    enabled: !!selectedWorkspaceId,
  });

  const refresh = () => qc.invalidateQueries({ queryKey });

  const seedMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/workspaces/${selectedWorkspaceId}/risk-register/seed`);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Risk register updated from findings" });
      refresh();
    },
    onError: (err: Error) => toast({ title: "Failed to seed risk register", description: err.message, variant: "destructive" }),
  });

  const createMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/workspaces/${selectedWorkspaceId}/risk-register`, {
        title: newTitle,
        description: newDesc,
      });
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Risk item created" });
      setNewTitle("");
      setNewDesc("");
      refresh();
    },
    onError: (err: Error) => toast({ title: "Failed to create risk item", description: err.message, variant: "destructive" }),
  });

  const updateStatusMutation = useMutation({
    mutationFn: async ({ id, status }: { id: string; status: RiskItem["status"] }) => {
      const res = await apiRequest("PATCH", `/api/risk-register/${id}?workspaceId=${selectedWorkspaceId}`, { status });
      return res.json();
    },
    onSuccess: () => refresh(),
    onError: (err: Error) => toast({ title: "Failed to update status", description: err.message, variant: "destructive" }),
  });

  if (!selectedWorkspaceId) {
    return (
      <div className="space-y-4 p-6">
        <h1 className="text-2xl font-semibold tracking-tight">Risk Register</h1>
        <p className="text-sm text-muted-foreground">Select a workspace to view and manage risk items.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Risk Register</h1>
          <p className="text-sm text-muted-foreground">Track and review technical/compliance risk items.</p>
        </div>
        <Button onClick={() => seedMutation.mutate()} disabled={seedMutation.isPending}>
          {seedMutation.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : null}
          Seed from findings
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Add Risk Item</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid gap-2">
            <Label htmlFor="risk-title">Title</Label>
            <Input id="risk-title" value={newTitle} onChange={(e) => setNewTitle(e.target.value)} placeholder="Risk title" />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="risk-description">Description</Label>
            <Input id="risk-description" value={newDesc} onChange={(e) => setNewDesc(e.target.value)} placeholder="Risk description" />
          </div>
          <Button onClick={() => createMutation.mutate()} disabled={createMutation.isPending || !newTitle.trim() || !newDesc.trim()}>
            {createMutation.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : null}
            Create
          </Button>
        </CardContent>
      </Card>

      <div className="space-y-3">
        {isLoading ? <p className="text-sm text-muted-foreground">Loading risk register...</p> : null}
        {!isLoading && items.length === 0 ? (
          <Card>
            <CardContent className="py-10 text-center text-sm text-muted-foreground">
              No risk items yet. Seed from findings or create one manually.
            </CardContent>
          </Card>
        ) : null}
        {items.map((item) => (
          <Card key={item.id}>
            <CardContent className="p-4 space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <p className="font-medium">{item.title}</p>
                  <Badge className={riskLevelClass[item.riskLevel] ?? riskLevelClass.medium}>
                    {item.riskLevel.toUpperCase()} ({item.riskScore})
                  </Badge>
                  <Badge variant="outline">{item.treatment}</Badge>
                </div>
                <Select
                  value={item.status}
                  onValueChange={(status: RiskItem["status"]) => updateStatusMutation.mutate({ id: item.id, status })}
                >
                  <SelectTrigger className="w-[170px]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="open">Open</SelectItem>
                    <SelectItem value="in_progress">In Progress</SelectItem>
                    <SelectItem value="accepted">Accepted</SelectItem>
                    <SelectItem value="resolved">Resolved</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <p className="text-sm text-muted-foreground">{item.description}</p>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

