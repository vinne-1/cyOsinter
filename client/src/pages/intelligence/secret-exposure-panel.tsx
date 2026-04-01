import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { KeyRound, FileWarning } from "lucide-react";
import { ModuleHeader, SeverityDot } from "./shared";
import type { ReconModule } from "@shared/schema";

export function SecretExposurePanel({ mod }: { mod: ReconModule }) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const d = mod.data as Record<string, any>;
  const matchCount = d.matchCount as number | undefined;
  const leakyPaths = d.leakyPaths as string[] | undefined;
  const patternTypes = d.patternTypes as string[] | undefined;
  const matches = d.matches as Array<{
    path: string;
    patternName: string;
    matchedValue: string;
    severity: string;
  }> | undefined;

  const criticalCount = matches?.filter((m) => m.severity === "critical").length ?? 0;
  const highCount = matches?.filter((m) => m.severity === "high").length ?? 0;

  return (
    <Card data-testid="panel-secret-exposure">
      <CardContent className="p-5">
        <ModuleHeader title="Secret Exposure" icon={KeyRound} confidence={mod.confidence ?? 0} generatedAt={mod.generatedAt} />

        {(!matchCount || matchCount === 0) && (!leakyPaths || leakyPaths.length === 0) ? (
          <p className="text-sm text-muted-foreground">No exposed secrets detected.</p>
        ) : (
          <div className="space-y-4">
            {/* Summary stats */}
            <div className="grid grid-cols-3 gap-3">
              <div className="p-2 rounded-md bg-muted/30 text-center">
                <p className="text-lg font-semibold">{matchCount ?? 0}</p>
                <p className="text-[10px] text-muted-foreground">Secrets Found</p>
              </div>
              <div className="p-2 rounded-md bg-red-500/5 text-center">
                <p className="text-lg font-semibold text-red-500">{criticalCount}</p>
                <p className="text-[10px] text-muted-foreground">Critical</p>
              </div>
              <div className="p-2 rounded-md bg-orange-500/5 text-center">
                <p className="text-lg font-semibold text-orange-500">{highCount}</p>
                <p className="text-[10px] text-muted-foreground">High</p>
              </div>
            </div>

            {/* Pattern types */}
            {patternTypes && patternTypes.length > 0 && (
              <div>
                <p className="text-xs font-medium text-muted-foreground mb-2">Detected Secret Types</p>
                <div className="flex flex-wrap gap-1.5">
                  {patternTypes.map((t, i) => (
                    <Badge key={i} variant="outline" className="text-[10px]">{t}</Badge>
                  ))}
                </div>
              </div>
            )}

            {/* Individual matches */}
            {matches && matches.length > 0 && (
              <div>
                <p className="text-xs font-medium text-muted-foreground mb-2">Matches</p>
                <div className="space-y-1.5">
                  {matches.slice(0, 15).map((m, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs p-1.5 rounded bg-muted/20">
                      <SeverityDot severity={m.severity} />
                      <span className="font-mono truncate flex-1">{m.path}</span>
                      <span className="text-muted-foreground truncate max-w-[140px]">{m.patternName}</span>
                    </div>
                  ))}
                  {matches.length > 15 && (
                    <p className="text-[10px] text-muted-foreground">+ {matches.length - 15} more</p>
                  )}
                </div>
              </div>
            )}

            {/* Leaky paths */}
            {leakyPaths && leakyPaths.length > 0 && (
              <div>
                <p className="text-xs font-medium text-muted-foreground mb-2">Exposed Files</p>
                <div className="space-y-1">
                  {leakyPaths.map((p, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs">
                      <FileWarning className="w-3 h-3 text-orange-400 flex-shrink-0" />
                      <span className="font-mono">{p}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
