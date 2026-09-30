import { useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
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
import { GitCompareArrows, ArrowUp, ArrowDown, Minus, Sparkles, Loader2, AlertTriangle } from "lucide-react";
import { useDomain } from "@/lib/domain-context";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface Scan {
  id: string;
  target: string;
  status: string;
  /** Scans have no `createdAt` — `startedAt` is when the row was created. */
  startedAt: string | null;
}

interface DiffFinding {
  title: string;
  severity: string;
  /** The server sends `affectedAsset` (the `Finding` shape), not `asset`. */
  affectedAsset: string | null;
  category: string;
}

interface ScanDiffNarrative {
  summary: string;
  watchFor: string[];
}

interface ScanDiff {
  newFindings: DiffFinding[];
  fixedFindings: DiffFinding[];
  persistingFindings: DiffFinding[];
  riskDelta: number;
}

const severityColors: Record<string, string> = {
  critical: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300",
  high: "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300",
  medium: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300",
  low: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300",
  info: "bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300",
};

type TabKey = "new" | "fixed" | "persisting";

const TABS: { key: TabKey; label: string }[] = [
  { key: "new", label: "New Findings" },
  { key: "fixed", label: "Fixed Findings" },
  { key: "persisting", label: "Persisting Findings" },
];

function FindingsTable({ findings }: { findings: DiffFinding[] }) {
  if (findings.length === 0) {
    return (
      <p className="text-sm text-muted-foreground text-center py-8">
        No findings in this category
      </p>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Title</TableHead>
          <TableHead>Severity</TableHead>
          <TableHead>Affected Asset</TableHead>
          <TableHead>Category</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {findings.map((f, idx) => (
          <TableRow key={`${f.title}-${f.affectedAsset}-${idx}`}>
            <TableCell className="font-medium">{f.title}</TableCell>
            <TableCell>
              <Badge className={severityColors[f.severity] || ""} variant="secondary">
                {f.severity}
              </Badge>
            </TableCell>
            <TableCell className="text-sm text-muted-foreground">{f.affectedAsset ?? "—"}</TableCell>
            <TableCell>
              <Badge variant="outline">{f.category}</Badge>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export default function ScanComparison() {
  const { selectedWorkspaceId } = useDomain();
  const { toast } = useToast();
  const [scanA, setScanA] = useState<string>("");
  const [scanB, setScanB] = useState<string>("");
  const [activeTab, setActiveTab] = useState<TabKey>("new");
  const [narrative, setNarrative] = useState<ScanDiffNarrative | null>(null);

  const { data: scans = [], isLoading: scansLoading } = useQuery<Scan[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/scans`],
    enabled: !!selectedWorkspaceId,
  });

  const { data: diff, isLoading: diffLoading } = useQuery<ScanDiff>({
    queryKey: [`/api/scans/${scanA}/diff/${scanB}`],
    enabled: !!scanA && !!scanB && scanA !== scanB,
  });

  const explainMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/scans/${scanA}/diff/${scanB}/explain`, undefined, { timeoutMs: 120000 });
      return res.json() as Promise<ScanDiffNarrative>;
    },
    onSuccess: (data) => setNarrative(data),
    onError: (err: Error) => {
      toast({ title: "AI explanation failed", description: err.message, variant: "destructive" });
    },
  });
  useEffect(() => {
    setNarrative(null);
  }, [scanA, scanB]);

  if (scansLoading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-12 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  const tabFindings: Record<TabKey, DiffFinding[]> = {
    new: diff?.newFindings ?? [],
    fixed: diff?.fixedFindings ?? [],
    persisting: diff?.persistingFindings ?? [],
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-3">
        <GitCompareArrows className="w-6 h-6 text-primary" />
        <div>
          <h1 className="text-2xl font-bold">Scan Comparison</h1>
          <p className="text-sm text-muted-foreground">
            Compare two scans side by side to track changes over time
          </p>
        </div>
      </div>

      <Card>
        <CardContent className="py-4">
          <div className="flex items-center gap-4 flex-wrap">
            <div className="flex-1 min-w-[200px] space-y-1">
              <label className="text-sm font-medium" htmlFor="baseline-scan">Baseline Scan</label>
              <Select value={scanA} onValueChange={setScanA}>
                <SelectTrigger id="baseline-scan" aria-label="Baseline scan">
                  <SelectValue placeholder="Select baseline scan" />
                </SelectTrigger>
                <SelectContent>
                  {scans.map((s) => (
                    <SelectItem key={s.id} value={s.id}>
                      {s.target} - {s.startedAt ? new Date(s.startedAt).toLocaleDateString() : "—"}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex-1 min-w-[200px] space-y-1">
              <label className="text-sm font-medium" htmlFor="comparison-scan">Comparison Scan</label>
              <Select value={scanB} onValueChange={setScanB}>
                <SelectTrigger id="comparison-scan" aria-label="Comparison scan">
                  <SelectValue placeholder="Select comparison scan" />
                </SelectTrigger>
                <SelectContent>
                  {scans
                    .filter((s) => s.id !== scanA)
                    .map((s) => (
                      <SelectItem key={s.id} value={s.id}>
                        {s.target} - {s.startedAt ? new Date(s.startedAt).toLocaleDateString() : "—"}
                      </SelectItem>
                    ))}
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {!scanA || !scanB ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-16">
            <GitCompareArrows className="w-12 h-12 text-muted-foreground mb-4" />
            <p className="text-muted-foreground">Select two scans to compare</p>
          </CardContent>
        </Card>
      ) : diffLoading ? (
        <div className="space-y-4">
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-64 w-full" />
        </div>
      ) : diff ? (
        <>
          <Card>
            <CardContent className="py-4 flex items-center gap-4">
              <span className="text-sm font-medium">Risk Delta:</span>
              <span
                className={`text-lg font-bold flex items-center gap-1 ${
                  diff.riskDelta < 0
                    ? "text-green-600"
                    : diff.riskDelta > 0
                      ? "text-red-600"
                      : "text-muted-foreground"
                }`}
              >
                {diff.riskDelta < 0 ? (
                  <ArrowDown className="w-4 h-4" />
                ) : diff.riskDelta > 0 ? (
                  <ArrowUp className="w-4 h-4" />
                ) : (
                  <Minus className="w-4 h-4" />
                )}
                {diff.riskDelta > 0 ? "+" : ""}
                {diff.riskDelta}
              </span>
              <div className="flex gap-4 ml-auto text-sm text-muted-foreground">
                <span>
                  <span className="font-semibold text-red-600">{diff.newFindings.length}</span> new
                </span>
                <span>
                  <span className="font-semibold text-green-600">{diff.fixedFindings.length}</span>{" "}
                  fixed
                </span>
                <span>
                  <span className="font-semibold text-foreground">
                    {diff.persistingFindings.length}
                  </span>{" "}
                  persisting
                </span>
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={() => explainMutation.mutate()}
                disabled={explainMutation.isPending}
                data-testid="button-explain-scan-diff"
              >
                {explainMutation.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Sparkles className="w-4 h-4 mr-2" />}
                {explainMutation.isPending ? "Asking GLM..." : narrative ? "Re-explain" : "Explain with AI"}
              </Button>
            </CardContent>
          </Card>

          {narrative && (
            <Card data-testid="card-scan-diff-narrative">
              <CardContent className="p-4 space-y-2">
                <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">AI Summary</p>
                <p className="text-sm leading-relaxed">{narrative.summary}</p>
                {narrative.watchFor.length > 0 && (
                  <ul className="space-y-1">
                    {narrative.watchFor.map((w, i) => (
                      <li key={i} className="flex items-start gap-2 text-xs">
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-500 flex-shrink-0 mt-0.5" />
                        {w}
                      </li>
                    ))}
                  </ul>
                )}
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader className="pb-0">
              <div className="flex gap-2 border-b">
                {TABS.map((tab) => (
                  <button
                    key={tab.key}
                    onClick={() => setActiveTab(tab.key)}
                    className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
                      activeTab === tab.key
                        ? "border-primary text-primary"
                        : "border-transparent text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    {tab.label} ({tabFindings[tab.key].length})
                  </button>
                ))}
              </div>
            </CardHeader>
            <CardContent className="pt-4">
              <FindingsTable findings={tabFindings[activeTab]} />
            </CardContent>
          </Card>
        </>
      ) : null}
    </div>
  );
}
