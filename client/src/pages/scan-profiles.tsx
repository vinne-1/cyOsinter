import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter, DialogDescription } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { Plus, Trash2, Settings2, Copy, Star } from "lucide-react";
import type { ScanProfileConfig } from "../../../shared/schema";

interface ScanProfile {
  id: string;
  workspaceId: string;
  name: string;
  description: string | null;
  scanType: string;
  mode: string;
  config: ScanProfileConfig;
  isDefault: boolean;
  createdAt: string;
  updatedAt: string;
}

const DEFAULT_CONFIG: ScanProfileConfig = {
  enableTakeoverCheck: true,
  enableApiDiscovery: true,
  enableSecretScan: true,
  enableNuclei: true,
  subdomainWordlistCap: 500,
  directoryWordlistCap: 200,
  portScanEnabled: false,
  customPorts: [],
  excludePaths: [],
  maxConcurrency: 5,
  timeoutMinutes: 30,
};

function ScanProfilesPage() {
  const { selectedWorkspace: workspace } = useDomain();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);
  const [form, setForm] = useState({
    name: "",
    description: "",
    scanType: "full",
    mode: "standard",
    config: { ...DEFAULT_CONFIG },
  });

  const { data: profiles = [], isLoading } = useQuery<ScanProfile[]>({
    queryKey: ["/api/scan-profiles", workspace?.id],
    queryFn: async () => {
      if (!workspace) return [];
      const res = await fetch(`/api/scan-profiles?workspaceId=${workspace.id}`);
      if (!res.ok) throw new Error("Failed to load profiles");
      return res.json();
    },
    enabled: !!workspace,
  });

  const createMutation = useMutation({
    mutationFn: async (data: typeof form) => {
      const res = await fetch("/api/scan-profiles", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...data, workspaceId: workspace?.id }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ message: "Failed" }));
        throw new Error(err.message);
      }
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/scan-profiles"] });
      setDialogOpen(false);
      resetForm();
      toast({ title: "Profile created" });
    },
    onError: (err: Error) => toast({ title: "Error", description: err.message, variant: "destructive" }),
  });

  const updateMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: typeof form }) => {
      const res = await fetch(`/api/scan-profiles/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ message: "Failed" }));
        throw new Error(err.message);
      }
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/scan-profiles"] });
      setDialogOpen(false);
      setEditId(null);
      resetForm();
      toast({ title: "Profile updated" });
    },
    onError: (err: Error) => toast({ title: "Error", description: err.message, variant: "destructive" }),
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await fetch(`/api/scan-profiles/${id}`, { method: "DELETE" });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/scan-profiles"] });
      toast({ title: "Profile deleted" });
    },
  });

  function resetForm() {
    setForm({ name: "", description: "", scanType: "full", mode: "standard", config: { ...DEFAULT_CONFIG } });
    setEditId(null);
  }

  function openEdit(profile: ScanProfile) {
    setEditId(profile.id);
    setForm({
      name: profile.name,
      description: profile.description ?? "",
      scanType: profile.scanType,
      mode: profile.mode,
      config: { ...DEFAULT_CONFIG, ...profile.config },
    });
    setDialogOpen(true);
  }

  function handleSubmit() {
    if (editId) {
      updateMutation.mutate({ id: editId, data: form });
    } else {
      createMutation.mutate(form);
    }
  }

  function duplicateProfile(profile: ScanProfile) {
    setEditId(null);
    setForm({
      name: `${profile.name} (copy)`,
      description: profile.description ?? "",
      scanType: profile.scanType,
      mode: profile.mode,
      config: { ...DEFAULT_CONFIG, ...profile.config },
    });
    setDialogOpen(true);
  }

  if (!workspace) {
    return (
      <div className="p-6">
        <p className="text-muted-foreground">Select a workspace to manage scan profiles.</p>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Scan Profiles</h1>
          <p className="text-muted-foreground">Configure reusable scan configurations with custom settings.</p>
        </div>
        <Dialog open={dialogOpen} onOpenChange={(open) => { setDialogOpen(open); if (!open) resetForm(); }}>
          <DialogTrigger asChild>
            <Button><Plus className="w-4 h-4 mr-2" /> New Profile</Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>{editId ? "Edit Profile" : "Create Scan Profile"}</DialogTitle>
              <DialogDescription>Configure scan parameters for reusable scan templates.</DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Profile Name</Label>
                  <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="e.g. Deep Scan" />
                </div>
                <div className="space-y-2">
                  <Label>Scan Type</Label>
                  <Select value={form.scanType} onValueChange={(v) => setForm({ ...form, scanType: v })}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="full">Full (EASM + OSINT + Nuclei + DAST)</SelectItem>
                      <SelectItem value="easm">EASM Only</SelectItem>
                      <SelectItem value="osint">OSINT Only</SelectItem>
                      <SelectItem value="dast">DAST Only (Active Testing)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="space-y-2">
                <Label>Description</Label>
                <Textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder="Optional description..." rows={2} />
              </div>
              <div className="space-y-2">
                <Label>Mode</Label>
                <Select value={form.mode} onValueChange={(v) => setForm({ ...form, mode: v })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="standard">Standard</SelectItem>
                    <SelectItem value="gold">Gold (Deep)</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="border-t pt-4">
                <h3 className="font-semibold mb-3">Scan Modules</h3>
                <div className="grid grid-cols-2 gap-3">
                  {([
                    ["enableTakeoverCheck", "Subdomain Takeover Detection"],
                    ["enableApiDiscovery", "API Endpoint Discovery"],
                    ["enableSecretScan", "Secret Exposure Scanner"],
                    ["enableNuclei", "Nuclei Template Scanner"],
                    ["portScanEnabled", "Port Scanning"],
                  ] as const).map(([key, label]) => (
                    <div key={key} className="flex items-center justify-between p-2 rounded border">
                      <Label className="text-sm">{label}</Label>
                      <Switch
                        checked={!!form.config[key]}
                        onCheckedChange={(checked) =>
                          setForm({ ...form, config: { ...form.config, [key]: checked } })
                        }
                      />
                    </div>
                  ))}
                </div>
              </div>

              <div className="border-t pt-4">
                <h3 className="font-semibold mb-3">Limits</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label className="text-sm">Subdomain Wordlist Cap</Label>
                    <Input type="number" min={0} max={100000} value={form.config.subdomainWordlistCap ?? 500} onChange={(e) => setForm({ ...form, config: { ...form.config, subdomainWordlistCap: parseInt(e.target.value) || 0 } })} />
                  </div>
                  <div className="space-y-2">
                    <Label className="text-sm">Directory Wordlist Cap</Label>
                    <Input type="number" min={0} max={100000} value={form.config.directoryWordlistCap ?? 200} onChange={(e) => setForm({ ...form, config: { ...form.config, directoryWordlistCap: parseInt(e.target.value) || 0 } })} />
                  </div>
                  <div className="space-y-2">
                    <Label className="text-sm">Max Concurrency</Label>
                    <Input type="number" min={1} max={50} value={form.config.maxConcurrency ?? 5} onChange={(e) => setForm({ ...form, config: { ...form.config, maxConcurrency: parseInt(e.target.value) || 5 } })} />
                  </div>
                  <div className="space-y-2">
                    <Label className="text-sm">Timeout (minutes)</Label>
                    <Input type="number" min={1} max={1440} value={form.config.timeoutMinutes ?? 30} onChange={(e) => setForm({ ...form, config: { ...form.config, timeoutMinutes: parseInt(e.target.value) || 30 } })} />
                  </div>
                </div>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => { setDialogOpen(false); resetForm(); }}>Cancel</Button>
              <Button onClick={handleSubmit} disabled={!form.name.trim()}>
                {editId ? "Save Changes" : "Create Profile"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {isLoading ? (
        <p className="text-muted-foreground">Loading profiles...</p>
      ) : profiles.length === 0 ? (
        <Card>
          <CardContent className="p-8 text-center">
            <Settings2 className="w-12 h-12 mx-auto mb-4 text-muted-foreground/40" />
            <p className="text-muted-foreground">No scan profiles yet. Create one to save reusable scan configurations.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {profiles.map((profile) => {
            const enabledModules = [
              profile.config.enableTakeoverCheck && "Takeover",
              profile.config.enableApiDiscovery && "API Discovery",
              profile.config.enableSecretScan && "Secrets",
              profile.config.enableNuclei && "Nuclei",
              profile.config.portScanEnabled && "Ports",
            ].filter(Boolean);

            return (
              <Card key={profile.id} className="relative">
                {profile.isDefault && (
                  <div className="absolute top-3 right-3">
                    <Star className="w-4 h-4 text-yellow-500 fill-yellow-500" />
                  </div>
                )}
                <CardHeader className="pb-3">
                  <CardTitle className="text-lg">{profile.name}</CardTitle>
                  {profile.description && (
                    <CardDescription>{profile.description}</CardDescription>
                  )}
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex gap-2">
                    <Badge variant="outline">{profile.scanType}</Badge>
                    <Badge variant={profile.mode === "gold" ? "default" : "secondary"}>{profile.mode}</Badge>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {enabledModules.map((mod) => (
                      <Badge key={mod as string} variant="secondary" className="text-xs">{mod}</Badge>
                    ))}
                  </div>
                  <div className="text-xs text-muted-foreground">
                    Concurrency: {profile.config.maxConcurrency ?? 5} | Timeout: {profile.config.timeoutMinutes ?? 30}m
                  </div>
                  <div className="flex gap-2 pt-2">
                    <Button size="sm" variant="outline" onClick={() => openEdit(profile)}>
                      <Settings2 className="w-3 h-3 mr-1" /> Edit
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => duplicateProfile(profile)}>
                      <Copy className="w-3 h-3 mr-1" /> Clone
                    </Button>
                    <Button size="sm" variant="ghost" className="text-destructive" onClick={() => deleteMutation.mutate(profile.id)}>
                      <Trash2 className="w-3 h-3" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default ScanProfilesPage;
