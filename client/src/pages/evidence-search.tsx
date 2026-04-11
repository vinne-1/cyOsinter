import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Search, FileSearch, Inbox, Globe } from "lucide-react";
import { buildUrl } from "@/lib/queryClient";
import { useDebounce } from "@/hooks/use-debounce";

interface EvidenceResult {
  type: "finding" | "recon";
  id: string;
  title: string;
  snippet: string;
  host: string | null;
}

interface SearchResponse {
  query: string;
  total: number;
  results: EvidenceResult[];
}

type FilterType = "all" | "finding" | "recon";

function ResultCard({ result }: { result: EvidenceResult }) {
  const isFinding = result.type === "finding";
  return (
    <div className="border rounded-lg p-4 space-y-1.5 hover:bg-muted/30 transition-colors">
      <div className="flex items-start gap-2">
        <div className="mt-0.5 shrink-0">
          {isFinding
            ? <Inbox className="w-4 h-4 text-orange-500" />
            : <Globe className="w-4 h-4 text-blue-500" />}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-medium text-sm">{result.title}</span>
            <Badge variant="outline" className="text-xs capitalize">
              {result.type === "finding" ? "Finding" : "Recon"}
            </Badge>
          </div>
          {result.host && (
            <p className="text-xs font-mono text-muted-foreground mt-0.5">{result.host}</p>
          )}
          <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{result.snippet}</p>
        </div>
      </div>
    </div>
  );
}

export default function EvidenceSearchPage() {
  const { selectedWorkspace: ws } = useDomain();
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<FilterType>("all");
  const debouncedQuery = useDebounce(query, 400);

  const { data, isLoading, isFetching } = useQuery<SearchResponse>({
    queryKey: [`/api/workspaces/${ws?.id}/search`, debouncedQuery, filter],
    queryFn: () => {
      const params = new URLSearchParams({
        q: debouncedQuery,
        type: filter,
        limit: "50",
      });
      return fetch(
        buildUrl(`/api/workspaces/${ws!.id}/search?${params}`),
        { headers: { Authorization: `Bearer ${localStorage.getItem("auth_token")}` } },
      ).then((r) => r.json());
    },
    enabled: !!ws && debouncedQuery.length >= 2,
  });

  if (!ws) return <div className="p-6 text-muted-foreground">Select a workspace.</div>;

  const FILTER_LABELS: Record<FilterType, string> = { all: "All", finding: "Findings", recon: "Recon" };

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <FileSearch className="w-6 h-6 text-primary" />
          Evidence Search
        </h1>
        <p className="text-muted-foreground">
          Full-text search across all findings and recon data for this workspace.
        </p>
      </div>

      <div className="flex gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Search findings, subdomains, ports, banners..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="pl-9"
          />
        </div>
        <div className="flex gap-1">
          {(["all", "finding", "recon"] as FilterType[]).map((f) => (
            <Button
              key={f}
              variant={filter === f ? "default" : "outline"}
              size="sm"
              onClick={() => setFilter(f)}
            >
              {FILTER_LABELS[f]}
            </Button>
          ))}
        </div>
      </div>

      {debouncedQuery.length < 2 ? (
        <Card><CardContent className="p-8 text-center">
          <Search className="w-12 h-12 mx-auto mb-4 text-muted-foreground/40" />
          <p className="text-muted-foreground">Type at least 2 characters to search.</p>
        </CardContent></Card>
      ) : isLoading || isFetching ? (
        <p className="text-muted-foreground">Searching...</p>
      ) : !data || data.total === 0 ? (
        <Card><CardContent className="p-8 text-center">
          <p className="text-muted-foreground">No results for "{debouncedQuery}".</p>
        </CardContent></Card>
      ) : (
        <>
          <p className="text-sm text-muted-foreground">
            {data.total} result{data.total !== 1 ? "s" : ""} for "{data.query}"
          </p>
          <div className="space-y-2">
            {data.results.map((r) => (
              <ResultCard key={`${r.type}-${r.id}`} result={r} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}
