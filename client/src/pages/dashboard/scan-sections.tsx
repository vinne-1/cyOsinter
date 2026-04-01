import { useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Activity,
  Loader2,
  Play,
  CheckCircle2,
  Clock,
  Square,
  Radio,
  Radar,
} from "lucide-react";
import { DOMAIN_REGEX, type Scan } from "@shared/schema";
import { DeleteScanButton } from "@/components/delete-scan-button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { type ContinuousMonitoringStatus, scanTypes } from "./helpers";

export function RecentScans({ scans, workspaceId }: { scans: Scan[]; workspaceId: string | null }) {
  const recent = scans.slice(0, 4);

  return (
    <Card data-testid="card-recent-scans">
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="text-sm font-medium">Recent Scans</CardTitle>
        <Activity className="w-4 h-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        {recent.length === 0 ? (
          <p className="text-sm text-muted-foreground py-8 text-center">No scans yet. Start scanning your attack surface.</p>
        ) : (
          <div className="space-y-3">
            {recent.map((scan) => {
              const s = scan as Scan & { progressMessage?: string | null; progressPercent?: number | null; estimatedSecondsRemaining?: number | null };
              const isRunning = scan.status === "running" || scan.status === "pending";
              return (
                <div
                  key={scan.id}
                  className="flex flex-col gap-1 p-3 rounded-md bg-muted/40"
                  data-testid={`scan-row-${scan.id}`}
                >
                  <div className="flex items-center justify-between gap-3 min-w-0">
                    <div className="flex items-center gap-3 min-w-0 flex-1">
                      <div className={`w-2 h-2 rounded-full flex-shrink-0 ${
                        scan.status === "completed" ? "bg-green-500" :
                        scan.status === "running" ? "bg-blue-500 animate-pulse" :
                        scan.status === "failed" ? "bg-red-500" :
                        "bg-slate-500"
                      }`} />
                      <div className="min-w-0">
                        <p className="text-sm font-medium truncate">{scan.target}</p>
                        <p className="text-xs text-muted-foreground font-mono uppercase">{scan.type}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      {scan.summary?.assetsDiscovered != null && (
                        <p className="text-sm font-mono">{String(scan.summary.assetsDiscovered)} assets</p>
                      )}
                      <p className="text-sm font-mono">{scan.findingsCount ?? 0} findings</p>
                      <p className="text-xs text-muted-foreground">
                        {scan.completedAt ? new Date(scan.completedAt).toLocaleDateString() : isRunning ? "In progress" : "Pending"}
                      </p>
                      {workspaceId && (
                        <DeleteScanButton scan={scan} workspaceId={workspaceId} />
                      )}
                    </div>
                  </div>
                  {isRunning && (s.progressMessage || (s.progressPercent ?? 0) > 0) && (
                    <div className="mt-2 space-y-1">
                      <Progress value={s.progressPercent ?? 0} className="h-1.5" />
                      <p className="text-xs text-muted-foreground truncate">{s.progressMessage}</p>
                      {s.estimatedSecondsRemaining != null && s.estimatedSecondsRemaining > 0 && (
                        <p className="text-xs text-muted-foreground flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          ~{Math.ceil(s.estimatedSecondsRemaining / 60)} min remaining
                        </p>
                      )}
                    </div>
                  )}
                  {scan.status === "failed" && scan.errorMessage && (
                    <p className="text-xs text-red-400 mt-1" title={scan.errorMessage}>
                      {scan.errorMessage}
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export function ContinuousMonitoringCard({ workspaceId, onStop }: { workspaceId: string; onStop: () => void }) {
  const { toast } = useToast();
  const { data: status, isLoading } = useQuery<ContinuousMonitoringStatus>({
    queryKey: [`/api/continuous-monitoring/status/${workspaceId}`],
    enabled: !!workspaceId,
    refetchInterval: 2000,
  });

  const stopMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/continuous-monitoring/stop", { workspaceId });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/continuous-monitoring/status/${workspaceId}`] });
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceId}/scans`] });
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceId}/assets`] });
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceId}/findings`] });
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceId}/recon-modules`] });
      onStop();
    },
    onError: (err: Error) => {
      toast({ title: "Failed to stop monitoring", description: err.message, variant: "destructive" });
    },
  });

  if ((!status?.running && !isLoading) || (!status && !isLoading)) return null;

  return (
    <Card data-testid="card-continuous-monitoring" className="border-primary/30">
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <Radio className="w-4 h-4 text-primary animate-pulse" />
          Continuous Monitoring Active
        </CardTitle>
        <Button
          variant="destructive"
          size="sm"
          onClick={() => stopMutation.mutate()}
          disabled={stopMutation.isPending}
          data-testid="button-stop-continuous-monitoring"
        >
          <Square className="w-4 h-4 mr-1" />
          Stop
        </Button>
      </CardHeader>
      <CardContent className="space-y-3">
        <Progress value={status?.progressPercent ?? 0} className="h-2" data-testid="progress-continuous-monitoring" />
        <p className="text-sm text-muted-foreground">Iteration {status?.iteration ?? 0}</p>
        <p className="text-xs text-muted-foreground truncate">{status?.progressMessage ?? "Loading..."}</p>
      </CardContent>
    </Card>
  );
}

export function StartContinuousMonitoringDialog({ workspaces, setSelectedWorkspace, onStarted }: {
  workspaces: { id: string; name: string; [key: string]: unknown }[];
  setSelectedWorkspace: (ws: { id: string; name: string; [key: string]: unknown } | null) => void;
  onStarted: (workspaceId: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [target, setTarget] = useState("");
  const { toast } = useToast();

  const mutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/continuous-monitoring/start", { target: target.trim() });
      return res.json();
    },
    onSuccess: (data: { workspaceId: string }) => {
      const ws = workspaces.find((w) => w.id === data.workspaceId);
      if (ws) setSelectedWorkspace(ws);
      onStarted(data.workspaceId);
      setOpen(false);
      setTarget("");
      toast({ title: "Continuous monitoring started", description: "Full scans will run every 5 minutes. Only new findings will be added." });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to start", description: error.message, variant: "destructive" });
    },
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" data-testid="button-start-continuous-monitoring">
          <Radio className="w-4 h-4 mr-2" />
          Start Continuous Monitoring
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Continuous Monitoring</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground">
            Runs a full EASM + OSINT scan every 5 minutes. Only new assets and findings are added. Use Stop to end.
          </p>
          <div>
            <label className="text-sm font-medium">Target domain</label>
            <Input
              placeholder="example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="mt-2"
              data-testid="input-continuous-monitoring-target"
            />
          </div>
          <Button
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending || !target.trim()}
            className="w-full"
          >
            {mutation.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : null}
            Start
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export function ScanLauncher() {
  const { toast } = useToast();
  const { selectedWorkspaceId, selectedWorkspace } = useDomain();
  const [target, setTarget] = useState("");
  const [selectedTypes, setSelectedTypes] = useState<string[]>(["full"]);
  const [launchedScans, setLaunchedScans] = useState<Record<string, "pending" | "launched">>({});
  const [autoGenerateReport, setAutoGenerateReport] = useState(false);

  useEffect(() => {
    if (selectedWorkspace?.name && !target.trim()) {
      setTarget(selectedWorkspace.name);
    }
    setLaunchedScans({});
  }, [selectedWorkspace?.name, target]);

  const effectiveTarget = target.trim() || selectedWorkspace?.name || "";
  const domainError = effectiveTarget && !DOMAIN_REGEX.test(effectiveTarget)
    ? "Please enter a valid domain (e.g. example.com)"
    : null;

  const mutation = useMutation({
    mutationFn: async ({ scanType, autoGen }: { scanType: string; autoGen?: boolean }) => {
      const res = await apiRequest("POST", "/api/scans", {
        target: effectiveTarget,
        type: scanType,
        status: "pending",
        workspaceId: selectedWorkspaceId || undefined,
        autoGenerateReport: autoGen ?? false,
        mode: "gold",
      });
      return res.json();
    },
    onSuccess: (data: { workspaceId?: string }, variables) => {
      setLaunchedScans((prev) => ({ ...prev, [variables.scanType]: "launched" }));
      const workspaceIdToInvalidate = selectedWorkspaceId || data?.workspaceId;
      if (workspaceIdToInvalidate) {
        queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceIdToInvalidate}/scans`] });
        queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceIdToInvalidate}/findings`] });
        queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceIdToInvalidate}/assets`] });
        queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceIdToInvalidate}/recon-modules`] });
        queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceIdToInvalidate}/reports`] });
        queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceIdToInvalidate}/posture-history`] });
      }
      queryClient.invalidateQueries({ queryKey: ["/api/workspaces"] });
    },
    onError: (error: Error) => {
      toast({ title: "Scan failed to launch", description: error.message, variant: "destructive" });
    },
  });

  const allLaunched = selectedTypes.length > 0 && selectedTypes.every((t) => launchedScans[t] === "launched");

  const handleLaunchAll = () => {
    if (!effectiveTarget) {
      toast({ title: "Target required", description: "Enter a domain or select a workspace", variant: "destructive" });
      return;
    }
    if (domainError) {
      toast({ title: "Invalid domain", description: domainError, variant: "destructive" });
      return;
    }
    if (selectedTypes.length === 0) {
      toast({ title: "No scan types selected", description: "Select at least one scan type", variant: "destructive" });
      return;
    }
    const pending: Record<string, "pending"> = {};
    for (const t of selectedTypes) {
      pending[t] = "pending";
    }
    setLaunchedScans(pending);
    if (selectedTypes.includes("full")) {
      mutation.mutate({ scanType: "full", autoGen: autoGenerateReport });
      toast({ title: "Full scan started", description: `EASM + OSINT scan initiated against ${effectiveTarget}${autoGenerateReport ? " (report will be auto-generated)" : ""}` });
    } else {
      for (const scanType of selectedTypes) {
        mutation.mutate({ scanType, autoGen: autoGenerateReport });
      }
      toast({ title: "Scans launched", description: `${selectedTypes.length} scan(s) initiated against ${effectiveTarget}${autoGenerateReport ? " (report will be auto-generated)" : ""}` });
    }
  };

  const toggleType = (id: string) => {
    setSelectedTypes((prev) => {
      if (prev.includes(id)) return prev.filter((t) => t !== id);
      if (id === "full") return ["full"];
      return [...prev.filter((t) => t !== "full"), id];
    });
  };

  return (
    <Card data-testid="card-scan-launcher">
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="text-sm font-medium">Launch Scans</CardTitle>
        <Radar className="w-4 h-4 text-muted-foreground" />
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="flex-1 space-y-1">
            <Input
              placeholder="Enter target domain (e.g. example.com)"
              value={target}
              onChange={(e) => {
                setTarget(e.target.value);
                setLaunchedScans({});
              }}
              className={domainError ? "border-red-500 focus-visible:ring-red-500" : ""}
              data-testid="input-scan-target"
            />
            {domainError && (
              <p className="text-xs text-red-500">{domainError}</p>
            )}
          </div>
          <Button
            onClick={handleLaunchAll}
            disabled={mutation.isPending || allLaunched || !effectiveTarget || !!domainError}
            data-testid="button-launch-all-scans"
          >
            {mutation.isPending ? (
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
            ) : allLaunched ? (
              <CheckCircle2 className="w-4 h-4 mr-2" />
            ) : (
              <Play className="w-4 h-4 mr-2" />
            )}
            {mutation.isPending ? "Launching..." : allLaunched ? "All Launched" : "Launch All Scans"}
          </Button>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {scanTypes.map((scan) => {
            const status = launchedScans[scan.id];
            return (
              <div
                key={scan.id}
                className={`flex items-start gap-3 p-3 rounded-md cursor-pointer hover-elevate ${
                  selectedTypes.includes(scan.id) ? "bg-primary/5 ring-1 ring-primary/20" : "bg-muted/40"
                }`}
                onClick={() => { if (!status) toggleType(scan.id); }}
                data-testid={`scan-type-${scan.id}`}
              >
                <Checkbox
                  checked={selectedTypes.includes(scan.id)}
                  onCheckedChange={() => { if (!status) toggleType(scan.id); }}
                  disabled={!!status}
                  className="mt-0.5"
                  data-testid={`checkbox-scan-${scan.id}`}
                />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm font-medium">{scan.label}</span>
                    {status === "launched" && (
                      <Badge variant="outline" className="text-xs bg-green-600/15 text-green-400 border-0 no-default-hover-elevate no-default-active-elevate">
                        <CheckCircle2 className="w-3 h-3 mr-1" />
                        Running
                      </Badge>
                    )}
                    {status === "pending" && (
                      <Badge variant="outline" className="text-xs bg-blue-600/15 text-blue-400 border-0 no-default-hover-elevate no-default-active-elevate">
                        <Loader2 className="w-3 h-3 mr-1 animate-spin" />
                        Starting
                      </Badge>
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground mt-0.5">{scan.description}</p>
                </div>
              </div>
            );
          })}
        </div>
        <div className="flex items-center gap-2 pt-2 border-t">
          <Checkbox
            id="auto-generate-report"
            checked={autoGenerateReport}
            onCheckedChange={(checked) => setAutoGenerateReport(checked === true)}
            disabled={!!Object.keys(launchedScans).length}
            data-testid="checkbox-auto-generate-report"
          />
          <label htmlFor="auto-generate-report" className="text-sm cursor-pointer select-none">
            Auto-generate report when scan completes
          </label>
        </div>
      </CardContent>
    </Card>
  );
}
