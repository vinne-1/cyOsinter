import { useMemo, useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger,
} from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { MetricTile } from "@/components/metric-tile";
import { severityMeta } from "@/lib/severity";
import { cn } from "@/lib/utils";
import {
  Briefcase, Plus, Clock, UserRound, Loader2, Radar, CircleDot, AlertOctagon,
} from "lucide-react";

interface CaseRow {
  id: string;
  reference: string;
  title: string;
  description: string | null;
  status: string;
  severity: string;
  ownerId: string | null;
  ownerName: string | null;
  dueAt: string | null;
  slaBreached: boolean;
  findingCount: number;
  createdAt: string;
}

interface CaseSummary { total: number; open: number; unassigned: number; breached: number }

const STATUS_META: Record<string, { label: string; chip: string }> = {
  open:          { label: "Open",          chip: "bg-severity-low/15 text-severity-low ring-1 ring-inset ring-severity-low/25" },
  investigating: { label: "Investigating", chip: "bg-severity-medium/15 text-severity-medium ring-1 ring-inset ring-severity-medium/25" },
  contained:     { label: "Contained",     chip: "bg-severity-high/15 text-severity-high ring-1 ring-inset ring-severity-high/25" },
  resolved:      { label: "Resolved",      chip: "bg-severity-ok/15 text-severity-ok ring-1 ring-inset ring-severity-ok/25" },
  closed:        { label: "Closed",        chip: "bg-severity-info/15 text-severity-info ring-1 ring-inset ring-severity-info/25" },
};

const FILTERS = ["all", "open", "investigating", "contained", "resolved", "closed"] as const;

export default function CasesPage() {
  const { selectedWorkspaceId } = useDomain();
  const { toast } = useToast();
  const [filter, setFilter] = useState<(typeof FILTERS)[number]>("all");
  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState({ title: "", description: "", severity: "medium" });

  const { data: envelope, isLoading } = useQuery<{ data: CaseRow[] }>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/cases`],
    enabled: !!selectedWorkspaceId,
  });
  const { data: summary } = useQuery<CaseSummary>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/cases-summary`],
    enabled: !!selectedWorkspaceId,
  });

  // The list endpoint returns the paginated envelope, which the default query
  // function unwraps to the array — accept either shape.
  const rows = useMemo<CaseRow[]>(() => {
    const raw = envelope as unknown;
    return Array.isArray(raw) ? (raw as CaseRow[]) : (envelope?.data ?? []);
  }, [envelope]);

  const visible = useMemo(
    () => (filter === "all" ? rows : rows.filter((c) => c.status === filter)),
    [rows, filter],
  );

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/cases`] });
    queryClient.invalidateQueries({ queryKey: [`/api/workspaces/${selectedWorkspaceId}/cases-summary`] });
  };

  const createCase = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/workspaces/${selectedWorkspaceId}/cases`, form);
      return res.json();
    },
    onSuccess: (c: CaseRow) => {
      invalidate();
      setCreateOpen(false);
      setForm({ title: "", description: "", severity: "medium" });
      toast({ title: `${c.reference} created` });
    },
    onError: (err: Error) => toast({ title: "Could not create case", description: err.message, variant: "destructive" }),
  });

  const setStatus = useMutation({
    mutationFn: async ({ id, status }: { id: string; status: string }) => {
      await apiRequest("PATCH", `/api/cases/${id}`, { status });
    },
    onSuccess: () => { invalidate(); toast({ title: "Case updated" }); },
    onError: (err: Error) => toast({ title: "Update failed", description: err.message, variant: "destructive" }),
  });

  if (!selectedWorkspaceId) {
    return (
      <div className="p-6">
        <Card>
          <CardContent className="py-16 text-center">
            <Radar className="mx-auto mb-4 h-12 w-12 text-muted-foreground/40" aria-hidden="true" />
            <p className="text-base font-medium text-muted-foreground">No workspace selected</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-[1600px] space-y-6 p-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Cases</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            A finding is an observation; a case is the work. Group related findings under one owner
            and one deadline.
          </p>
        </div>

        <Dialog open={createOpen} onOpenChange={setCreateOpen}>
          <DialogTrigger asChild>
            <Button data-testid="button-new-case">
              <Plus className="mr-2 h-4 w-4" aria-hidden="true" /> New case
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>New case</DialogTitle>
              <DialogDescription>
                The deadline is derived from severity, using the same policy as findings.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div className="space-y-2">
                <label htmlFor="case-title" className="text-sm font-medium">Title</label>
                <Input
                  id="case-title"
                  value={form.title}
                  onChange={(e) => setForm({ ...form, title: e.target.value })}
                  placeholder="Remediate TLS configuration on public hosts"
                />
              </div>
              <div className="space-y-2">
                <label htmlFor="case-desc" className="text-sm font-medium">Description</label>
                <Textarea
                  id="case-desc"
                  rows={3}
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  placeholder="What needs to happen, and how we will know it is done."
                />
              </div>
              <div className="space-y-2">
                <label htmlFor="case-sev" className="text-sm font-medium">Severity</label>
                <Select value={form.severity} onValueChange={(v) => setForm({ ...form, severity: v })}>
                  <SelectTrigger id="case-sev" aria-label="Case severity">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {["critical", "high", "medium", "low", "info"].map((sv) => (
                      <SelectItem key={sv} value={sv}>{severityMeta(sv).label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <DialogFooter>
              <Button
                onClick={() => createCase.mutate()}
                disabled={!form.title.trim() || createCase.isPending}
              >
                {createCase.isPending
                  ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Creating…</>
                  : "Create case"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricTile label="Total cases" value={summary?.total ?? 0} hint="All time" icon={Briefcase} testId="cases-total" />
        <MetricTile label="Open" value={summary?.open ?? 0} hint="Not yet resolved" icon={CircleDot} testId="cases-open" />
        <MetricTile
          label="Unassigned"
          value={summary?.unassigned ?? 0}
          hint="Nobody is accountable"
          icon={UserRound}
          accent="hsl(var(--sev-medium))"
          emphasis={(summary?.unassigned ?? 0) > 0}
          testId="cases-unassigned"
        />
        <MetricTile
          label="SLA breached"
          value={summary?.breached ?? 0}
          hint="Past the deadline"
          icon={Clock}
          accent="hsl(var(--sev-critical))"
          emphasis={(summary?.breached ?? 0) > 0}
          testId="cases-breached"
        />
      </div>

      <div className="rounded-xl border border-hairline bg-surface-2">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-hairline p-4">
          <h2 className="text-sm font-semibold">
            Cases <span className="font-normal text-muted-foreground">({visible.length})</span>
          </h2>
          <div className="flex flex-wrap gap-1">
            {FILTERS.map((f) => (
              <button
                key={f}
                type="button"
                onClick={() => setFilter(f)}
                aria-pressed={filter === f}
                className={cn(
                  "rounded-md px-2.5 py-1 text-xs font-medium capitalize transition-colors",
                  filter === f
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:bg-surface-3 hover:text-foreground",
                )}
              >
                {f}
              </button>
            ))}
          </div>
        </div>

        {isLoading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-16 rounded-lg" />)}
          </div>
        ) : visible.length === 0 ? (
          <div className="py-16 text-center">
            <Briefcase className="mx-auto mb-4 h-12 w-12 text-muted-foreground/40" aria-hidden="true" />
            <p className="text-base font-medium">
              {rows.length === 0 ? "No cases yet" : "No cases match this filter"}
            </p>
            {rows.length === 0 && (
              <p className="mx-auto mt-1 max-w-md text-sm text-muted-foreground">
                Open a case when work spans several findings, or when someone needs to own a
                deadline rather than a list.
              </p>
            )}
          </div>
        ) : (
          <ul className="divide-y divide-hairline">
            {visible.map((c) => {
              const sev = severityMeta(c.severity);
              const status = STATUS_META[c.status] ?? STATUS_META.open;
              return (
                <li
                  key={c.id}
                  className="flex flex-wrap items-center gap-x-4 gap-y-2 p-4 transition-colors hover:bg-surface-3/40"
                  data-testid={`case-${c.reference}`}
                >
                  <span aria-hidden="true" className={cn("h-8 w-1.5 shrink-0 rounded-full", sev.solid)} />

                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-xs text-muted-foreground">{c.reference}</span>
                      <span className="truncate text-sm font-medium">{c.title}</span>
                      {c.slaBreached && (
                        <span className="inline-flex items-center gap-1 rounded bg-severity-critical/12 px-1.5 py-0.5 text-[0.6875rem] font-medium text-severity-critical">
                          <AlertOctagon className="h-3 w-3" aria-hidden="true" /> Overdue
                        </span>
                      )}
                    </div>
                    <p className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
                      <span>{c.findingCount} finding{c.findingCount === 1 ? "" : "s"}</span>
                      <span className={cn(!c.ownerName && "text-severity-medium")}>
                        {c.ownerName ?? "Unassigned"}
                      </span>
                      {c.dueAt && <span>Due {new Date(c.dueAt).toLocaleDateString()}</span>}
                    </p>
                  </div>

                  <span className={cn("shrink-0 rounded-md px-2 py-0.5 text-xs font-medium", sev.chip)}>
                    {sev.label}
                  </span>
                  <span className={cn("shrink-0 rounded-md px-2 py-0.5 text-xs font-medium", status.chip)}>
                    {status.label}
                  </span>

                  <Select value={c.status} onValueChange={(v) => setStatus.mutate({ id: c.id, status: v })}>
                    <SelectTrigger className="h-8 w-36 shrink-0" aria-label={`Change status of ${c.reference}`}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {Object.entries(STATUS_META).map(([value, m]) => (
                        <SelectItem key={value} value={value}>{m.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
}
