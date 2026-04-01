import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
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
import { Webhook, Plus, Trash2, TestTube, Pencil, CheckCircle2, XCircle } from "lucide-react";
import { useDomain } from "@/lib/domain-context";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface WebhookEntry {
  id: string;
  name: string;
  url: string;
  secret?: string;
  events: string[];
  provider: string;
  enabled: boolean;
  createdAt: string;
  lastTriggered?: string;
}

const EVENT_OPTIONS = [
  { value: "scan_completed", label: "Scan Completed" },
  { value: "critical_finding", label: "Critical Finding" },
  { value: "sla_breach", label: "SLA Breach" },
  { value: "new_finding", label: "New Finding" },
];

const providerColors: Record<string, string> = {
  slack: "bg-purple-100 text-purple-800",
  teams: "bg-blue-100 text-blue-800",
  pagerduty: "bg-green-100 text-green-800",
  generic: "bg-gray-100 text-gray-800",
};

function maskUrl(url: string): string {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}/****`;
  } catch {
    return "****";
  }
}

function CreateWebhookDialog({ workspaceId }: { workspaceId: string }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [secret, setSecret] = useState("");
  const [provider, setProvider] = useState("generic");
  const [events, setEvents] = useState<Record<string, boolean>>({});
  const { toast } = useToast();

  const create = useMutation({
    mutationFn: () =>
      apiRequest("POST", `/api/workspaces/${workspaceId}/webhooks`, {
        name,
        url,
        secret: secret || undefined,
        provider,
        events: Object.entries(events).filter(([, v]) => v).map(([k]) => k),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${workspaceId}/webhooks`] });
      toast({ title: "Webhook created" });
      setOpen(false);
      setName(""); setUrl(""); setSecret(""); setProvider("generic"); setEvents({});
    },
    onError: (err: Error) => {
      toast({ title: "Failed to create webhook", description: err.message, variant: "destructive" });
    },
  });

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button><Plus className="w-4 h-4 mr-2" />Add Webhook</Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader><DialogTitle>Create Webhook</DialogTitle></DialogHeader>
        <div className="space-y-4">
          <div className="space-y-2">
            <Label>Name</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="My webhook" />
          </div>
          <div className="space-y-2">
            <Label>URL</Label>
            <Input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://hooks.example.com/..." />
          </div>
          <div className="space-y-2">
            <Label>Secret (optional)</Label>
            <Input value={secret} onChange={(e) => setSecret(e.target.value)} type="password" />
          </div>
          <div className="space-y-2">
            <Label>Provider</Label>
            <Select value={provider} onValueChange={setProvider}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="generic">Generic</SelectItem>
                <SelectItem value="slack">Slack</SelectItem>
                <SelectItem value="teams">Microsoft Teams</SelectItem>
                <SelectItem value="pagerduty">PagerDuty</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label>Events</Label>
            {EVENT_OPTIONS.map((ev) => (
              <div key={ev.value} className="flex items-center gap-2">
                <Switch
                  checked={!!events[ev.value]}
                  onCheckedChange={(c) => setEvents({ ...events, [ev.value]: c })}
                />
                <span className="text-sm">{ev.label}</span>
              </div>
            ))}
          </div>
          <Button onClick={() => create.mutate()} disabled={!name || !url || create.isPending} className="w-full">
            {create.isPending ? "Creating..." : "Create Webhook"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default function WebhookConfig() {
  const { selectedWorkspaceId } = useDomain();
  const { toast } = useToast();

  const { data: webhooks = [], isLoading } = useQuery<WebhookEntry[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/webhooks`],
    enabled: !!selectedWorkspaceId,
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiRequest("DELETE", `/api/webhooks/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/webhooks`] });
      toast({ title: "Webhook deleted" });
    },
  });

  const testMutation = useMutation({
    mutationFn: (id: string) => apiRequest("POST", `/api/webhooks/${id}/test`),
    onSuccess: () => toast({ title: "Test sent successfully" }),
    onError: (err: Error) => toast({ title: "Test failed", description: err.message, variant: "destructive" }),
  });

  if (isLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-48" />
        <div className="grid gap-4 md:grid-cols-2">
          {[1, 2].map((i) => <Skeleton key={i} className="h-40" />)}
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Webhook className="w-6 h-6 text-primary" />
          <h1 className="text-2xl font-bold">Webhooks</h1>
        </div>
        {selectedWorkspaceId && <CreateWebhookDialog workspaceId={selectedWorkspaceId} />}
      </div>

      {webhooks.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-16">
            <Webhook className="w-12 h-12 text-muted-foreground mb-4" />
            <p className="text-muted-foreground">No webhooks configured</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          {webhooks.map((wh) => (
            <Card key={wh.id}>
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-base">{wh.name}</CardTitle>
                <div className="flex items-center gap-1">
                  {wh.enabled ? (
                    <CheckCircle2 className="w-4 h-4 text-green-500" />
                  ) : (
                    <XCircle className="w-4 h-4 text-red-500" />
                  )}
                  <Badge className={providerColors[wh.provider] || ""} variant="secondary">
                    {wh.provider}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-sm font-mono text-muted-foreground">{maskUrl(wh.url)}</p>
                <div className="flex flex-wrap gap-1">
                  {wh.events.map((ev) => (
                    <Badge key={ev} variant="outline" className="text-xs">
                      {ev.replace(/_/g, " ")}
                    </Badge>
                  ))}
                </div>
                <div className="flex gap-2 pt-2">
                  <Button size="sm" variant="outline" onClick={() => testMutation.mutate(wh.id)} disabled={testMutation.isPending}>
                    <TestTube className="w-3 h-3 mr-1" />Test
                  </Button>
                  <Button size="sm" variant="destructive" onClick={() => deleteMutation.mutate(wh.id)}>
                    <Trash2 className="w-3 h-3 mr-1" />Delete
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
