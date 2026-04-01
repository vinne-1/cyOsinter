import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Zap, ExternalLink } from "lucide-react";
import type { ReconModule } from "@shared/schema";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ModuleHeader } from "./shared";

export function NucleiPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as {
    source?: string;
    hits?: Array<{
      templateId: string;
      templateName?: string;
      severity: string;
      host: string;
      matchedAt?: string;
      info?: { name?: string; description?: string };
      matcherName?: string;
      extractedResults?: string[];
    }>;
    templateCount?: number;
    allTemplatesLoaded?: boolean;
    skipped?: boolean;
    verifiedAt?: string;
  };
  const hits = d?.hits ?? [];
  const allTemplatesLoaded = d?.allTemplatesLoaded ?? false;
  const skipped = d?.skipped ?? false;

  return (
    <div className="space-y-4" data-testid="panel-nuclei">
      <ModuleHeader title="Nuclei Scan" icon={Zap} confidence={mod.confidence || 0} generatedAt={mod.generatedAt} />
      <div className="flex items-center gap-2 flex-wrap">
        {allTemplatesLoaded && (
          <Badge variant="outline" className="bg-green-600/15 text-green-400 border-0 no-default-hover-elevate no-default-active-elevate">
            All templates loaded
          </Badge>
        )}
        <span className="text-sm text-muted-foreground">
          {hits.length} finding{hits.length !== 1 ? "s" : ""} from Nuclei vulnerability scanner
        </span>
      </div>
      <p className="text-sm text-muted-foreground">
        {d?.source ?? "Nuclei scanner (all templates)"}. Template-based vulnerability detection across discovered hosts.
      </p>
      {skipped || hits.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <Zap className="w-12 h-12 text-muted-foreground/40 mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">
              {skipped ? "Nuclei scan was skipped" : "No Nuclei findings for this workspace"}
            </p>
            <p className="text-xs text-muted-foreground mt-1">
              {skipped ? (d?.source ?? "Nuclei CLI not installed. Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest") : "Run a full scan to execute Nuclei (requires Nuclei CLI installed)"}
            </p>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Template</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Host</TableHead>
                  <TableHead>Matched At</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {hits.map((h, i) => (
                  <TableRow key={i}>
                    <TableCell>
                      <div className="space-y-0.5">
                        <span className="font-mono text-xs">{h.templateId}</span>
                        {h.templateName && (
                          <p className="text-xs text-muted-foreground">{h.templateName}</p>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant="outline"
                        className={
                          h.severity === "critical" ? "bg-red-600/15 text-red-400 border-0" :
                          h.severity === "high" ? "bg-orange-600/15 text-orange-400 border-0" :
                          h.severity === "medium" ? "bg-yellow-600/15 text-yellow-400 border-0" :
                          "bg-slate-600/15 text-slate-400 border-0"
                        }
                      >
                        {h.severity}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <a href={h.host.startsWith("http") ? h.host : `https://${h.host}`} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline text-sm">
                        {h.host}
                      </a>
                    </TableCell>
                    <TableCell>
                      {h.matchedAt ? (
                        <a href={h.matchedAt} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline text-xs">
                          <ExternalLink className="w-3 h-3 inline mr-1" />
                          Evidence
                        </a>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
