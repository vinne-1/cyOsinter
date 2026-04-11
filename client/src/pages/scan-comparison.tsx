import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
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
import { GitCompareArrows, ArrowUp, ArrowDown, Minus } from "lucide-react";
import { useDomain } from "@/lib/domain-context";

interface Scan {
  id: number;
  target: string;
  status: string;
  startedAt: string | null;
}

interface DiffFinding {
  title: string;
  severity: string;
  asset: string;
  category: string;
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
          <TableRow key={`${f.title}-${f.asset}-${idx}`}>
            <TableCell className="font-medium">{f.title}</TableCell>
            <TableCell>
              <Badge className={severityColors[f.severity] || ""} variant="secondary">
                {f.severity}
              </Badge>
            </TableCell>
            <TableCell className="text-sm text-muted-foreground">{f.asset}</TableCell>
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
  const [scanA, setScanA] = useState<string>("");
  const [scanB, setScanB] = useState<string>("");
  const [activeTab, setActiveTab] = useState<TabKey>("new");

  const { data: scans = [], isLoading: scansLoading } = useQuery<Scan[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/scans`],
    enabled: !!selectedWorkspaceId,
  });

  const { data: diff, isLoading: diffLoading } = useQuery<ScanDiff>({
    queryKey: [`/api/scans/${scanA}/diff/${scanB}`],
    enabled: !!scanA && !!scanB && scanA !== scanB,
  });

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
              <label className="text-sm font-medium">Baseline Scan</label>
              <Select value={scanA} onValueChange={setScanA}>
                <SelectTrigger>
                  <SelectValue placeholder="Select baseline scan" />
                </SelectTrigger>
                <SelectContent>
                  {scans.map((s) => (
                    <SelectItem key={s.id} value={String(s.id)}>
                      {s.target} - {s.startedAt ? new Date(s.startedAt).toLocaleDateString() : "pending"}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex-1 min-w-[200px] space-y-1">
              <label className="text-sm font-medium">Comparison Scan</label>
              <Select value={scanB} onValueChange={setScanB}>
                <SelectTrigger>
                  <SelectValue placeholder="Select comparison scan" />
                </SelectTrigger>
                <SelectContent>
                  {scans
                    .filter((s) => String(s.id) !== scanA)
                    .map((s) => (
                      <SelectItem key={s.id} value={String(s.id)}>
                        {s.target} - {s.startedAt ? new Date(s.startedAt).toLocaleDateString() : "pending"}
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
                {diff.riskDelta} risk pts
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
            </CardContent>
          </Card>

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
