import { useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
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
import { CalendarClock, Plus, Trash2, Clock, Play, Pause } from "lucide-react";
import { useDomain } from "@/lib/domain-context";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { ScheduledScan } from "@shared/schema";

const DOMAIN_REGEX = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

const cronPresets = [
  { label: "Every hour", value: "0 * * * *" },
  { label: "Every 6 hours", value: "0 */6 * * *" },
  { label: "Daily at 2 AM", value: "0 2 * * *" },
  { label: "Weekly (Monday 2 AM)", value: "0 2 * * 1" },
  { label: "Monthly (1st, 2 AM)", value: "0 2 1 * *" },
];

const formSchema = z.object({
  target: z.string().min(1, "Target is required").refine(
    (val) => DOMAIN_REGEX.test(val.trim()),
    { message: "Enter a valid domain (e.g. example.com)" }
  ),
  scanType: z.enum(["easm", "osint", "full", "dast"]),
  cronExpression: z.string().min(1, "Schedule is required").refine(
    (val) => val.trim().split(/\s+/).length === 5,
    { message: "Invalid cron expression" }
  ),
  mode: z.enum(["standard", "gold"]),
});

function cronToHuman(cron: string): string {
  const preset = cronPresets.find((p) => p.value === cron);
  if (preset) return preset.label;

  const [min, hour, dom, mon, dow] = cron.split(" ");
  const parts: string[] = [];

  if (min !== "*" && hour !== "*") {
    parts.push(`at ${hour.padStart(2, "0")}:${min.padStart(2, "0")}`);
  } else if (min.startsWith("*/") || hour.startsWith("*/")) {
    const interval = min.startsWith("*/") ? `${min.slice(2)} min` : `${hour.slice(2)} hr`;
    parts.push(`every ${interval}`);
  }

  if (dow !== "*") {
    const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    parts.push(`on ${dow.split(",").map((d) => days[parseInt(d)] ?? d).join(", ")}`);
  }
  if (dom !== "*") parts.push(`day ${dom}`);
  if (mon !== "*") parts.push(`month ${mon}`);

  return parts.length > 0 ? parts.join(", ") : cron;
}

interface ScanProfile {
  id: string;
  name: string;
  scanType: string;
  mode: string;
}

function NewScheduledScanDialog() {
  const [open, setOpen] = useState(false);
  const [usePreset, setUsePreset] = useState(true);
  const [selectedProfileId, setSelectedProfileId] = useState<string>("__none__");
  const { toast } = useToast();
  const { selectedWorkspaceId, selectedWorkspace } = useDomain();

  const { data: profiles = [] } = useQuery<ScanProfile[]>({
    queryKey: ["/api/scan-profiles", { workspaceId: selectedWorkspaceId }],
    enabled: !!selectedWorkspaceId,
  });

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      target: "",
      scanType: "full",
      cronExpression: "0 2 * * 1",
      mode: "standard",
    },
  });

  useEffect(() => {
    if (open && selectedWorkspace?.name) {
      form.setValue("target", selectedWorkspace.name);
    }
  }, [open, selectedWorkspace?.name]);

  const mutation = useMutation({
    mutationFn: async (data: z.infer<typeof formSchema>) => {
      const res = await apiRequest("POST", `/api/workspaces/${selectedWorkspaceId}/scheduled-scans`, data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/scheduled-scans`] });
      toast({ title: "Scheduled scan created" });
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
        <Button data-testid="button-new-scheduled-scan">
          <Plus className="w-4 h-4 mr-2" />
          New Schedule
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Schedule Recurring Scan</DialogTitle>
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
                    <Input placeholder="example.com" data-testid="input-scheduled-target" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            {profiles.length > 0 && (
              <div className="space-y-2">
                <FormLabel>Scan Profile</FormLabel>
                <Select value={selectedProfileId} onValueChange={(v) => {
                  setSelectedProfileId(v);
                  if (v && v !== "__none__") {
                    const p = profiles.find((pr) => pr.id === v);
                    if (p) {
                      form.setValue("scanType", p.scanType as "easm" | "osint" | "full" | "dast");
                      form.setValue("mode", p.mode as "standard" | "gold");
                    }
                  }
                }}>
                  <SelectTrigger>
                    <SelectValue placeholder="None (manual config)" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__none__">None (manual config)</SelectItem>
                    {profiles.map((p) => (
                      <SelectItem key={p.id} value={p.id}>{p.name} ({p.scanType}, {p.mode})</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <FormLabel>Scan Type</FormLabel>
                <Select value={form.watch("scanType")} onValueChange={(v) => form.setValue("scanType", v as "easm" | "osint" | "full")}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="full">Full (EASM + OSINT + DAST)</SelectItem>
                    <SelectItem value="easm">EASM Only</SelectItem>
                    <SelectItem value="osint">OSINT Only</SelectItem>
                    <SelectItem value="dast">DAST Only</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <FormLabel>Mode</FormLabel>
                <Select value={form.watch("mode")} onValueChange={(v) => form.setValue("mode", v as "standard" | "gold")}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="standard">Standard</SelectItem>
                    <SelectItem value="gold">Gold</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <FormLabel>Schedule</FormLabel>
                <button
                  type="button"
                  className="text-xs text-primary hover:underline"
                  onClick={() => setUsePreset(!usePreset)}
                >
                  {usePreset ? "Custom cron" : "Presets"}
                </button>
              </div>
              {usePreset ? (
                <Select
                  value={form.watch("cronExpression")}
                  onValueChange={(v) => form.setValue("cronExpression", v)}
                >
                  <SelectTrigger data-testid="select-cron-preset"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {cronPresets.map((p) => (
                      <SelectItem key={p.value} value={p.value}>{p.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              ) : (
                <FormField
                  control={form.control}
                  name="cronExpression"
                  render={({ field }) => (
                    <FormItem>
                      <FormControl>
                        <Input placeholder="0 2 * * 1" data-testid="input-cron-expression" {...field} />
                      </FormControl>
                      <p className="text-[10px] text-muted-foreground">Format: min hour day month weekday</p>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              )}
            </div>

            <Button type="submit" className="w-full" disabled={mutation.isPending} data-testid="button-create-schedule">
              {mutation.isPending ? "Creating..." : "Create Schedule"}
            </Button>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

export default function ScheduledScans() {
  const { selectedWorkspaceId } = useDomain();
  const { toast } = useToast();

  const { data: schedules = [], isLoading } = useQuery<ScheduledScan[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/scheduled-scans`],
    enabled: !!selectedWorkspaceId,
  });

  const toggleEnabled = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) => {
      await apiRequest("PATCH", `/api/scheduled-scans/${id}`, { enabled });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/scheduled-scans`] });
      toast({ title: "Schedule updated" });
    },
    onError: (err: Error) => toast({ title: "Toggle failed", description: err.message, variant: "destructive" }),
  });

  const deleteSchedule = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/scheduled-scans/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/scheduled-scans`] });
      toast({ title: "Schedule deleted" });
    },
    onError: (err: Error) => toast({ title: "Delete failed", description: err.message, variant: "destructive" }),
  });

  if (isLoading) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-8 w-64" />
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-24" />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight" data-testid="text-scheduled-scans-title">
            Scheduled Scans
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Configure automated recurring security scans
          </p>
        </div>
        <NewScheduledScanDialog />
      </div>

      {schedules.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <CalendarClock className="w-10 h-10 text-muted-foreground/40 mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">No scheduled scans</p>
            <p className="text-xs text-muted-foreground mt-1">
              Create a schedule to automatically run scans at regular intervals
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {schedules.map((schedule) => (
            <Card key={schedule.id} data-testid={`card-scheduled-scan-${schedule.id}`}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between gap-4 flex-wrap">
                  <div className="flex items-start gap-3 min-w-0 flex-1">
                    <div className={`flex items-center justify-center w-9 h-9 rounded-md flex-shrink-0 ${
                      schedule.enabled ? "bg-primary/10" : "bg-muted"
                    }`}>
                      {schedule.enabled ? (
                        <Play className="w-4 h-4 text-primary" />
                      ) : (
                        <Pause className="w-4 h-4 text-muted-foreground" />
                      )}
                    </div>
                    <div className="min-w-0 space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <p className="text-sm font-medium">{schedule.target}</p>
                        <Badge variant="outline" className="text-[10px] uppercase">
                          {schedule.scanType}
                        </Badge>
                        {schedule.mode === "gold" && (
                          <Badge variant="secondary" className="text-[10px]">Gold</Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-1 text-xs text-muted-foreground">
                        <Clock className="w-3 h-3" />
                        <span>{cronToHuman(schedule.cronExpression)}</span>
                      </div>
                      <div className="flex items-center gap-3 text-[10px] text-muted-foreground/70">
                        {schedule.lastRunAt && (
                          <span>Last run: {new Date(schedule.lastRunAt).toLocaleString()}</span>
                        )}
                        {schedule.enabled && schedule.nextRunAt && (
                          <span>Next: {new Date(schedule.nextRunAt).toLocaleString()}</span>
                        )}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <Switch
                      checked={schedule.enabled}
                      onCheckedChange={(checked) =>
                        toggleEnabled.mutate({ id: schedule.id, enabled: checked })
                      }
                      data-testid={`switch-schedule-${schedule.id}`}
                    />
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8 text-muted-foreground hover:text-destructive"
                      onClick={() => deleteSchedule.mutate(schedule.id)}
                      data-testid={`button-delete-schedule-${schedule.id}`}
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
