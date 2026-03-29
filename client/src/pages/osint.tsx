import { useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
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
  Search,
  FileSearch,
  Eye,
  AlertCircle,
  ExternalLink,
  Database,
  Key,
  Mail,
  Shield,
  Clock,
} from "lucide-react";
import type { Scan, Finding } from "@shared/schema";
import { ScanStatusBadge, SeverityBadge } from "@/components/severity-badge";
import { DeleteScanButton } from "@/components/delete-scan-button";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useDomain } from "@/lib/domain-context";

const dorkCategories = [
  { id: "credentials", label: "Leaked Credentials", icon: Key, description: "Search for exposed passwords and API keys" },
  { id: "documents", label: "Exposed Documents", icon: FileSearch, description: "Find publicly accessible documents" },
  { id: "emails", label: "Email Harvesting", icon: Mail, description: "Discover exposed email addresses" },
  { id: "infrastructure", label: "Infrastructure", icon: Database, description: "Identify exposed infrastructure details" },
];

const DOMAIN_REGEX = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

const osintFormSchema = z.object({
  target: z.string().min(1, "Target is required").refine(
    (val) => DOMAIN_REGEX.test(val.trim()),
    { message: "Enter a valid domain (e.g. example.com)" }
  ),
});

function NewOSINTScanDialog() {
  const [open, setOpen] = useState(false);
  const [scanType, setScanType] = useState<"osint" | "full">("full");
  const { toast } = useToast();
  const { selectedWorkspaceId, selectedWorkspace } = useDomain();
  const form = useForm<z.infer<typeof osintFormSchema>>({
    resolver: zodResolver(osintFormSchema),
    defaultValues: { target: "" },
  });

  useEffect(() => {
    if (open && selectedWorkspace?.name) {
      form.setValue("target", selectedWorkspace.name);
    }
  }, [open, selectedWorkspace?.name]);

  const mutation = useMutation({
    mutationFn: async (data: { target: string }) => {
      const res = await apiRequest("POST", "/api/scans", { target: data.target, type: scanType, status: "pending", workspaceId: selectedWorkspaceId || undefined, mode: "gold" });
      return res.json();
    },
    onSuccess: () => {
      if (selectedWorkspaceId) {
        queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/scans`] });
        queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/findings`] });
        queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/recon-modules`] });
      }
      queryClient.invalidateQueries({ queryKey: ["/api/workspaces"] });
      toast({ title: "Scan started", description: scanType === "full" ? "Full scan (EASM + OSINT) has been initiated." : "OSINT scan has been initiated." });
      setOpen(false);
      form.reset();
    },
    onError: (error: Error) => {
      toast({ title: "Error", description: error.message, variant: "destructive" });
    },
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button data-testid="button-new-osint-scan">
          <Search className="w-4 h-4 mr-2" />
          New Scan
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Start Discovery</DialogTitle>
        </DialogHeader>
        <Form {...form}>
          <form onSubmit={form.handleSubmit((data) => mutation.mutate(data))} className="space-y-4">
            <FormField
              control={form.control}
              name="target"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Target (domain or organization)</FormLabel>
                  <FormControl>
                    <Input
                      placeholder="example.com or Company Inc."
                      data-testid="input-osint-target"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <div className="space-y-2">
              <FormLabel>Scan Type</FormLabel>
              <Select value={scanType} onValueChange={(v) => setScanType(v as "osint" | "full")}>
                <SelectTrigger data-testid="select-osint-scan-type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="full">Full Scan (EASM + OSINT)</SelectItem>
                  <SelectItem value="osint">OSINT Only</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {scanType === "full" ? "Complete scan with all recon modules" : "OSINT discovery only"}
              </p>
            </div>
            <Button type="submit" className="w-full" disabled={mutation.isPending} data-testid="button-start-osint-scan">
              {mutation.isPending ? "Starting..." : "Start Discovery"}
            </Button>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

export default function OSINT() {
  const { selectedWorkspaceId } = useDomain();

  const { data: scans = [], isLoading: loadingScans } = useQuery<Scan[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/scans`],
    enabled: !!selectedWorkspaceId,
    refetchInterval: (query) => {
      const data = query.state.data as Scan[] | undefined;
      const hasRunning = data?.some((s) => s.status === "running" || s.status === "pending");
      return hasRunning ? 2000 : false;
    },
  });

  const { data: findings = [], isLoading: loadingFindings } = useQuery<Finding[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/findings`],
    enabled: !!selectedWorkspaceId,
  });

  const osintScans = scans.filter((s) => s.type === "osint" || s.type === "full");
  const osintFindings = findings.filter((f) => f.category === "osint_exposure" || f.category === "data_leak" || f.category === "leaked_credential" || f.category === "infrastructure_disclosure");

  if (loadingScans || loadingFindings) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-8 w-64 mb-2" />
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-28" />
          ))}
        </div>
        <Skeleton className="h-96" />
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight" data-testid="text-osint-title">OSINT Discovery</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Discover exposed data through open-source intelligence and Google dorking
          </p>
        </div>
        <NewOSINTScanDialog />
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {dorkCategories.map((cat) => (
          <Card key={cat.id} data-testid={`card-dork-category-${cat.id}`}>
            <CardContent className="p-4">
              <div className="flex items-start gap-3">
                <div className="flex items-center justify-center w-9 h-9 rounded-md bg-primary/10 flex-shrink-0">
                  <cat.icon className="w-4 h-4 text-primary" />
                </div>
                <div className="min-w-0">
                  <p className="text-sm font-medium">{cat.label}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">{cat.description}</p>
                  {(() => {
                    const count = osintFindings.filter((f) => {
                      if (cat.id === "credentials") return f.category === "leaked_credential";
                      if (cat.id === "documents") return f.category === "data_leak";
                      if (cat.id === "emails") return f.category === "osint_exposure";
                      if (cat.id === "infrastructure") return f.category === "infrastructure_disclosure";
                      return false;
                    }).length;
                    return (
                      <>
                        <p className="text-lg font-semibold mt-2">{count}</p>
                        {count === 0 && osintScans.length > 0 && (
                          <p className="text-[10px] text-muted-foreground/60 leading-tight mt-0.5">No exposures found — target appears well-configured</p>
                        )}
                      </>
                    );
                  })()}
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Tabs defaultValue="scans" className="space-y-4">
        <TabsList data-testid="tabs-osint">
          <TabsTrigger value="scans" data-testid="tab-osint-scans">Scans</TabsTrigger>
          <TabsTrigger value="exposures" data-testid="tab-osint-exposures">Exposures</TabsTrigger>
        </TabsList>

        <TabsContent value="scans" className="space-y-4">
          {osintScans.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Search className="w-10 h-10 text-muted-foreground/40 mx-auto mb-3" />
                <p className="text-sm text-muted-foreground">No OSINT scans yet</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Start an OSINT scan to discover leaked data and public exposure signals
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-3">
              {osintScans.map((scan) => {
                const s = scan as Scan & { progressMessage?: string | null; progressPercent?: number | null; estimatedSecondsRemaining?: number | null };
                const isRunning = scan.status === "running" || scan.status === "pending";
                const scanFindings = findings.filter((f) => f.scanId === scan.id);
                return (
                  <Card key={scan.id} data-testid={`card-osint-scan-${scan.id}`}>
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between gap-4 flex-wrap">
                      <div className="flex flex-col gap-1 min-w-0 flex-1">
                        <div className="flex items-center gap-3 min-w-0">
                          <div className={`w-2 h-2 rounded-full flex-shrink-0 ${
                            scan.status === "completed" ? "bg-green-500" :
                            scan.status === "running" ? "bg-blue-500 animate-pulse" :
                            scan.status === "failed" ? "bg-red-500" :
                            "bg-slate-500"
                          }`} />
                          <div className="min-w-0">
                            <p className="text-sm font-medium truncate">{scan.target}</p>
                            <p className="text-xs text-muted-foreground">
                              {scan.completedAt ? `Completed ${new Date(scan.completedAt).toLocaleString()}` : isRunning ? "In progress" : "Pending"} · {scan.type}
                            </p>
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
                        {scan.status === "failed" && (scan as any).errorMessage && (
                          <p className="text-xs text-red-400 mt-1" title={(scan as any).errorMessage}>
                            {(scan as any).errorMessage}
                          </p>
                        )}
                      </div>
                        <div className="flex items-center gap-3 flex-wrap">
                          {(scan as any).summary?.assetsDiscovered != null && (
                            <span className="text-sm font-mono">{(scan as any).summary.assetsDiscovered} assets</span>
                          )}
                          <span className="text-sm font-mono">{scan.findingsCount ?? 0} findings</span>
                          <ScanStatusBadge status={scan.status} />
                          {selectedWorkspaceId && (
                            <DeleteScanButton scan={scan} workspaceId={selectedWorkspaceId} />
                          )}
                        </div>
                      </div>
                      {scanFindings.length > 0 && (
                        <div className="mt-3 pt-3 border-t border-border space-y-2">
                          <p className="text-xs font-medium text-muted-foreground">Findings</p>
                          <ul className="space-y-1.5">
                            {scanFindings.slice(0, 10).map((f) => (
                              <li key={f.id} className="flex items-center gap-2 flex-wrap text-sm">
                                <SeverityBadge severity={f.severity} />
                                <span className="min-w-0 truncate" title={f.title}>{f.title}</span>
                              </li>
                            ))}
                            {scanFindings.length > 10 && (
                              <li className="text-xs text-muted-foreground">+ {scanFindings.length - 10} more</li>
                            )}
                          </ul>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </TabsContent>

        <TabsContent value="exposures" className="space-y-4">
          {osintFindings.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Eye className="w-10 h-10 text-muted-foreground/40 mx-auto mb-3" />
                <p className="text-sm text-muted-foreground">No exposures discovered yet</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Run an OSINT scan to find data leaks and exposure signals
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-3">
              {osintFindings.map((finding) => (
                <Card key={finding.id} data-testid={`card-osint-finding-${finding.id}`}>
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between gap-4">
                      <div className="space-y-1 min-w-0 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <p className="text-sm font-medium">{finding.title}</p>
                          <SeverityBadge severity={finding.severity} />
                        </div>
                        <p className="text-xs text-muted-foreground line-clamp-2">{finding.description}</p>
                        {finding.affectedAsset && (
                          <p className="text-xs font-mono text-muted-foreground mt-1">{finding.affectedAsset}</p>
                        )}
                      </div>
                      <Badge variant="outline" className="text-xs flex-shrink-0 capitalize no-default-hover-elevate no-default-active-elevate">
                        {finding.category.replace(/_/g, " ")}
                      </Badge>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
