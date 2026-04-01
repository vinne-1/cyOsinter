import { useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import { Database, Save, Trash2, Clock } from "lucide-react";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface RetentionPolicy {
  scanRetentionDays: number;
  findingRetentionDays: number;
  snapshotRetentionDays: number;
  archiveEnabled: boolean;
  lastCleanup?: string;
}

export default function RetentionConfig() {
  const { selectedWorkspaceId } = useDomain();
  const { toast } = useToast();

  const [scanDays, setScanDays] = useState(90);
  const [findingDays, setFindingDays] = useState(180);
  const [snapshotDays, setSnapshotDays] = useState(30);
  const [archiveEnabled, setArchiveEnabled] = useState(false);

  const { data: config, isLoading } = useQuery<RetentionPolicy>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/retention`],
    enabled: !!selectedWorkspaceId,
  });

  useEffect(() => {
    if (config) {
      setScanDays(config.scanRetentionDays);
      setFindingDays(config.findingRetentionDays);
      setSnapshotDays(config.snapshotRetentionDays);
      setArchiveEnabled(config.archiveEnabled);
    }
  }, [config]);

  const saveMutation = useMutation({
    mutationFn: () =>
      apiRequest("PUT", `/api/workspaces/${selectedWorkspaceId}/retention`, {
        scanRetentionDays: scanDays,
        findingRetentionDays: findingDays,
        snapshotRetentionDays: snapshotDays,
        archiveEnabled,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/retention`] });
      toast({ title: "Retention policy saved" });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to save", description: err.message, variant: "destructive" });
    },
  });

  const cleanupMutation = useMutation({
    mutationFn: () => apiRequest("POST", "/api/retention/cleanup"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/retention`] });
      toast({ title: "Cleanup completed", description: "Expired data has been removed" });
    },
    onError: (err: Error) => {
      toast({ title: "Cleanup failed", description: err.message, variant: "destructive" });
    },
  });

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-3">
        <Database className="w-6 h-6 text-primary" />
        <div>
          <h1 className="text-2xl font-bold">Data Retention</h1>
          <p className="text-sm text-muted-foreground">
            Configure how long scan data, findings, and snapshots are retained
          </p>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Retention Policy</CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="grid gap-6 md:grid-cols-3">
            <div className="space-y-2">
              <Label htmlFor="scan-days">Scan Retention (days)</Label>
              <Input
                id="scan-days"
                type="number"
                min={1}
                max={365}
                value={scanDays}
                onChange={(e) => setScanDays(Number(e.target.value))}
              />
              <p className="text-xs text-muted-foreground">
                Completed scans older than this will be removed
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="finding-days">Finding Retention (days)</Label>
              <Input
                id="finding-days"
                type="number"
                min={1}
                max={730}
                value={findingDays}
                onChange={(e) => setFindingDays(Number(e.target.value))}
              />
              <p className="text-xs text-muted-foreground">
                Resolved findings older than this will be removed
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="snapshot-days">Snapshot Retention (days)</Label>
              <Input
                id="snapshot-days"
                type="number"
                min={1}
                max={365}
                value={snapshotDays}
                onChange={(e) => setSnapshotDays(Number(e.target.value))}
              />
              <p className="text-xs text-muted-foreground">
                EASM snapshots older than this will be removed
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 p-4 rounded-md border">
            <Switch
              id="archive-toggle"
              checked={archiveEnabled}
              onCheckedChange={setArchiveEnabled}
            />
            <div>
              <Label htmlFor="archive-toggle" className="cursor-pointer">
                Archive data before deletion
              </Label>
              <p className="text-xs text-muted-foreground">
                Expired data will be archived for compliance before removal
              </p>
            </div>
          </div>

          <div className="flex items-center justify-between pt-2">
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Clock className="w-4 h-4" />
              {config?.lastCleanup ? (
                <span>Last cleanup: {new Date(config.lastCleanup).toLocaleString()}</span>
              ) : (
                <span>No cleanup has been run yet</span>
              )}
            </div>
            <div className="flex gap-2">
              <Button
                variant="outline"
                onClick={() => cleanupMutation.mutate()}
                disabled={cleanupMutation.isPending}
              >
                <Trash2 className="w-4 h-4 mr-2" />
                {cleanupMutation.isPending ? "Running..." : "Run Cleanup Now"}
              </Button>
              <Button onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending}>
                <Save className="w-4 h-4 mr-2" />
                {saveMutation.isPending ? "Saving..." : "Save Policy"}
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
