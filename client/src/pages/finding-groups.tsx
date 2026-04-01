import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Layers, RefreshCw, ChevronDown, ChevronUp } from "lucide-react";
import { useDomain } from "@/lib/domain-context";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface FindingInstance {
  id: string;
  title: string;
  severity: string;
  target: string;
  status: string;
  discoveredAt: string;
}

interface FindingGroup {
  id: string;
  title: string;
  category: string;
  severity: string;
  status: string;
  instanceCount: number;
  findings: FindingInstance[];
}

const severityColors: Record<string, string> = {
  critical: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300",
  high: "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300",
  medium: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300",
  low: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300",
  info: "bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300",
};

function GroupCard({ group }: { group: FindingGroup }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <Card>
      <CardHeader
        className="cursor-pointer flex flex-row items-center justify-between"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="space-y-1">
          <CardTitle className="text-base">{group.title}</CardTitle>
          <div className="flex items-center gap-2">
            <Badge className={severityColors[group.severity] || ""} variant="secondary">
              {group.severity}
            </Badge>
            <Badge variant="outline">{group.category}</Badge>
            <Badge variant="secondary">{group.instanceCount} instances</Badge>
            <Badge variant={group.status === "open" ? "destructive" : "default"}>
              {group.status}
            </Badge>
          </div>
        </div>
        {expanded ? (
          <ChevronUp className="w-5 h-5 text-muted-foreground" />
        ) : (
          <ChevronDown className="w-5 h-5 text-muted-foreground" />
        )}
      </CardHeader>
      {expanded && (
        <CardContent>
          <div className="space-y-2">
            {group.findings.map((f) => (
              <div
                key={f.id}
                className="flex items-center justify-between p-3 rounded-md border bg-muted/50"
              >
                <div>
                  <p className="text-sm font-medium">{f.title}</p>
                  <p className="text-xs text-muted-foreground">{f.target}</p>
                </div>
                <div className="flex items-center gap-2">
                  <Badge className={severityColors[f.severity] || ""} variant="secondary">
                    {f.severity}
                  </Badge>
                  <span className="text-xs text-muted-foreground">
                    {new Date(f.discoveredAt).toLocaleDateString()}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      )}
    </Card>
  );
}

export default function FindingGroups() {
  const { selectedWorkspaceId } = useDomain();
  const { toast } = useToast();

  const { data: groups = [], isLoading } = useQuery<FindingGroup[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/finding-groups`],
    enabled: !!selectedWorkspaceId,
  });

  const compute = useMutation({
    mutationFn: () =>
      apiRequest("POST", `/api/workspaces/${selectedWorkspaceId}/finding-groups/compute`),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: [`/api/workspaces/${selectedWorkspaceId}/finding-groups`],
      });
      toast({ title: "Finding groups recomputed" });
    },
    onError: (err: Error) => {
      toast({ title: "Grouping failed", description: err.message, variant: "destructive" });
    },
  });

  const totalFindings = groups.reduce((sum, g) => sum + g.instanceCount, 0);

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-20 w-full" />
        <div className="space-y-3">
          {[1, 2, 3].map((i) => <Skeleton key={i} className="h-24" />)}
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Layers className="w-6 h-6 text-primary" />
          <h1 className="text-2xl font-bold">Finding Groups</h1>
        </div>
        <Button onClick={() => compute.mutate()} disabled={compute.isPending}>
          <RefreshCw className={`w-4 h-4 mr-2 ${compute.isPending ? "animate-spin" : ""}`} />
          {compute.isPending ? "Computing..." : "Recompute Groups"}
        </Button>
      </div>

      {groups.length > 0 && (
        <Card>
          <CardContent className="py-4">
            <p className="text-sm text-muted-foreground">
              <span className="font-semibold text-foreground">{totalFindings}</span> similar findings
              grouped into <span className="font-semibold text-foreground">{groups.length}</span> groups
            </p>
          </CardContent>
        </Card>
      )}

      {groups.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-16">
            <Layers className="w-12 h-12 text-muted-foreground mb-4" />
            <p className="text-muted-foreground">No finding groups yet</p>
            <p className="text-sm text-muted-foreground mt-1">
              Click "Recompute Groups" to analyze and group similar findings
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {groups.map((g) => (
            <GroupCard key={g.id} group={g} />
          ))}
        </div>
      )}
    </div>
  );
}
