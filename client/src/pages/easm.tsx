import { useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { useDomain } from "@/lib/domain-context";
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import {
  Globe,
  Plus,
  Scan,
  Server,
  MonitorSmartphone,
  Lock,
  Search,
  Filter,
  Clock,
} from "lucide-react";
import type { Asset, Scan as ScanType } from "@shared/schema";
import { ScanStatusBadge } from "@/components/severity-badge";
import { DeleteScanButton } from "@/components/delete-scan-button";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

const DOMAIN_REGEX = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

const scanFormSchema = z.object({
  target: z.string().min(1, "Target domain is required").refine(
    (val) => DOMAIN_REGEX.test(val.trim()),
    { message: "Enter a valid domain (e.g. example.com)" }
  ),
});

const assetFormSchema = z.object({
  value: z.string().min(1, "Asset value is required"),
  type: z.enum(["domain", "subdomain", "ip", "service", "certificate"]),
  status: z.enum(["active", "inactive", "unknown"]).default("active"),
});

const assetTypeIcons: Record<string, React.ElementType> = {
  domain: Globe,
  subdomain: MonitorSmartphone,
  ip: Server,
  service: Lock,
  certificate: Lock,
};

function NewScanDialog() {
  const [open, setOpen] = useState(false);
  const [scanType, setScanType] = useState<"easm" | "full">("full");
  const [scanMode, setScanMode] = useState<"standard" | "gold">("gold");
  const { toast } = useToast();
  const { selectedWorkspaceId, selectedWorkspace } = useDomain();
  const form = useForm<z.infer<typeof scanFormSchema>>({
    resolver: zodResolver(scanFormSchema),
    defaultValues: { target: selectedWorkspace?.name ?? "" },
  });

  useEffect(() => {
    if (open && selectedWorkspace?.name) {
      form.setValue("target", selectedWorkspace.name);
    }
  }, [open, selectedWorkspace?.name]);

  const mutation = useMutation({
    mutationFn: async (data: z.infer<typeof scanFormSchema>) => {
      const res = await apiRequest("POST", "/api/scans", { target: data.target, type: scanType, status: "pending", workspaceId: selectedWorkspaceId || undefined, mode: scanMode });
      return res.json();
    },
    onSuccess: () => {
      if (selectedWorkspaceId) {
        queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/scans`] });
        queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/assets`] });
        queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/findings`] });
        queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/recon-modules`] });
      }
      queryClient.invalidateQueries({ queryKey: ["/api/workspaces"] });
      toast({ title: "Scan started", description: scanType === "full" ? "Full scan (EASM + OSINT) has been initiated." : "EASM scan has been initiated." });
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
        <Button data-testid="button-new-easm-scan">
          <Scan className="w-4 h-4 mr-2" />
          New Scan
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Start Scan</DialogTitle>
        </DialogHeader>
        <Form {...form}>
          <form onSubmit={form.handleSubmit((data) => mutation.mutate(data))} className="space-y-4">
            <FormField
              control={form.control}
              name="target"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Target Domain</FormLabel>
                  <FormControl>
                    <Input
                      placeholder="example.com"
                      data-testid="input-scan-target"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <div className="space-y-2">
              <FormLabel>Scan Type</FormLabel>
              <Select value={scanType} onValueChange={(v) => setScanType(v as "easm" | "full")}>
                <SelectTrigger data-testid="select-scan-type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="full">Full Scan (EASM + OSINT)</SelectItem>
                  <SelectItem value="easm">EASM Only</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {scanType === "full" ? "Complete scan with all recon modules" : "Attack surface only"}
              </p>
            </div>
            <div className="space-y-2">
              <FormLabel>Scan Mode</FormLabel>
              <Select value={scanMode} onValueChange={(v) => setScanMode(v as "standard" | "gold")}>
                <SelectTrigger data-testid="select-scan-mode">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="gold">Gold (comprehensive, no limits)</SelectItem>
                  <SelectItem value="standard">Standard (quick scan)</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {scanMode === "gold" ? "No limits—probe all subdomains, full wordlists, per-asset analysis" : "Faster scan with capped subdomains and paths"}
              </p>
            </div>
            <Button type="submit" className="w-full" disabled={mutation.isPending} data-testid="button-start-scan">
              {mutation.isPending ? "Starting..." : "Start Scan"}
            </Button>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

function AddAssetDialog() {
  const [open, setOpen] = useState(false);
  const { toast } = useToast();
  const { selectedWorkspaceId } = useDomain();
  const form = useForm<z.infer<typeof assetFormSchema>>({
    resolver: zodResolver(assetFormSchema),
    defaultValues: { value: "", type: "domain", status: "active" },
  });

  const mutation = useMutation({
    mutationFn: async (data: z.infer<typeof assetFormSchema>) => {
      const res = await apiRequest("POST", `/api/workspaces/${selectedWorkspaceId}/assets`, data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/assets`] });
      toast({ title: "Asset added" });
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
        <Button variant="outline" data-testid="button-add-asset">
          <Plus className="w-4 h-4 mr-2" />
          Add Asset
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add Asset</DialogTitle>
        </DialogHeader>
        <Form {...form}>
          <form onSubmit={form.handleSubmit((data) => mutation.mutate(data))} className="space-y-4">
            <FormField
              control={form.control}
              name="value"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Value</FormLabel>
                  <FormControl>
                    <Input placeholder="example.com or 192.168.1.1" data-testid="input-asset-value" {...field} />
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
                  <FormLabel>Type</FormLabel>
                  <Select onValueChange={field.onChange} defaultValue={field.value}>
                    <FormControl>
                      <SelectTrigger data-testid="select-asset-type">
                        <SelectValue />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="domain">Domain</SelectItem>
                      <SelectItem value="subdomain">Subdomain</SelectItem>
                      <SelectItem value="ip">IP Address</SelectItem>
                      <SelectItem value="service">Service</SelectItem>
                      <SelectItem value="certificate">Certificate</SelectItem>
                    </SelectContent>
                  </Select>
                </FormItem>
              )}
            />
            <Button type="submit" className="w-full" disabled={mutation.isPending} data-testid="button-save-asset">
              {mutation.isPending ? "Adding..." : "Add Asset"}
            </Button>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

export default function EASM() {
  const { selectedWorkspaceId } = useDomain();
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");

  const { data: scans = [], isLoading: loadingScans } = useQuery<ScanType[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/scans`],
    enabled: !!selectedWorkspaceId,
    refetchInterval: (query) => {
      const data = query.state.data as ScanType[] | undefined;
      const hasRunning = data?.some((s) => s.status === "running" || s.status === "pending");
      return hasRunning ? 2000 : false;
    },
  });

  const hasRunningScans = scans.some((s) => s.status === "running" || s.status === "pending");
  const { data: assets = [], isLoading: loadingAssets } = useQuery<Asset[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/assets`],
    enabled: !!selectedWorkspaceId,
    refetchInterval: hasRunningScans ? 4000 : false,
  });

  const easmScans = scans.filter((s) => s.type === "easm" || s.type === "full");

  const filteredAssets = assets.filter((a) => {
    const matchesSearch = a.value.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesType = typeFilter === "all" || a.type === typeFilter;
    return matchesSearch && matchesType;
  });

  const assetsByType = assets.reduce((acc, a) => {
    acc[a.type] = (acc[a.type] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  if (loadingAssets || loadingScans) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-8 w-64 mb-2" />
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-24" />
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
          <h1 className="text-2xl font-semibold tracking-tight" data-testid="text-easm-title">Attack Surface</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Monitor and manage your external attack surface
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <AddAssetDialog />
          <NewScanDialog />
        </div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        {["domain", "subdomain", "ip", "service", "certificate"].map((type) => {
          const Icon = assetTypeIcons[type] || Globe;
          return (
            <Card
              key={type}
              className={`cursor-pointer transition-colors ${typeFilter === type ? "ring-1 ring-primary" : ""}`}
              onClick={() => setTypeFilter(typeFilter === type ? "all" : type)}
              data-testid={`card-asset-type-${type}`}
            >
              <CardContent className="p-4 flex items-center gap-3">
                <Icon className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                <div>
                  <p className="text-lg font-semibold">{assetsByType[type] || 0}</p>
                  <p className="text-xs text-muted-foreground capitalize">{type}s</p>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {easmScans.length > 0 && (
        <Card data-testid="card-easm-scans">
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm font-medium">EASM Scans</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {easmScans.slice(0, 3).map((scan) => {
                const s = scan as ScanType & { progressMessage?: string | null; progressPercent?: number | null; estimatedSecondsRemaining?: number | null };
                const isRunning = scan.status === "running" || scan.status === "pending";
                return (
                  <div key={scan.id} className="flex flex-col gap-1 p-3 rounded-md bg-muted/40">
                    <div className="flex items-center justify-between gap-3 min-w-0">
                      <div className="flex items-center gap-3 min-w-0">
                        <Scan className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                        <div className="min-w-0">
                          <p className="text-sm font-medium truncate">{scan.target}</p>
                          <p className="text-xs text-muted-foreground">
                            {(scan as any).summary?.assetsDiscovered != null && `${(scan as any).summary.assetsDiscovered} assets · `}
                            {scan.findingsCount ?? 0} findings · {scan.type}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0">
                        {(scan as any).summary?.mode === "gold" && (
                          <Badge variant="outline" className="text-xs bg-amber-600/15 text-amber-400 border-0 no-default-hover-elevate no-default-active-elevate">Gold</Badge>
                        )}
                        <ScanStatusBadge status={scan.status} />
                        {selectedWorkspaceId && (
                          <DeleteScanButton scan={scan} workspaceId={selectedWorkspaceId} />
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
                    {scan.status === "failed" && (scan as any).errorMessage && (
                      <p className="text-xs text-red-400 mt-1" title={(scan as any).errorMessage}>
                        {(scan as any).errorMessage}
                      </p>
                    )}
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      <Card data-testid="card-assets-table">
        <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
          <CardTitle className="text-sm font-medium">
            Discovered Assets ({filteredAssets.length})
          </CardTitle>
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Search assets..."
                className="pl-9 h-9 w-48"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                data-testid="input-search-assets"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {filteredAssets.length === 0 ? (
            <div className="text-center py-12">
              <Globe className="w-10 h-10 text-muted-foreground/40 mx-auto mb-3" />
              <p className="text-sm text-muted-foreground">No assets found</p>
              <p className="text-xs text-muted-foreground mt-1">Add assets manually or run an EASM scan</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Asset</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>First Seen</TableHead>
                    <TableHead>Tags</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredAssets.map((asset) => {
                    const Icon = assetTypeIcons[asset.type] || Globe;
                    return (
                      <TableRow key={asset.id} data-testid={`row-asset-${asset.id}`}>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <Icon className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                            <span className="font-mono text-sm">{asset.value}</span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className="capitalize text-xs no-default-hover-elevate no-default-active-elevate">
                            {asset.type}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <div className={`w-2 h-2 rounded-full ${
                              asset.status === "active" ? "bg-green-500" :
                              asset.status === "inactive" ? "bg-slate-500" :
                              "bg-yellow-500"
                            }`} />
                            <span className="text-sm capitalize">{asset.status}</span>
                          </div>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {asset.firstSeen ? new Date(asset.firstSeen).toLocaleDateString() : "—"}
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1 flex-wrap">
                            {(asset.tags || []).map((tag, i) => (
                              <Badge key={i} variant="outline" className="text-xs no-default-hover-elevate no-default-active-elevate">
                                {tag}
                              </Badge>
                            ))}
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
