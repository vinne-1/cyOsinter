import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, ExternalLink } from "lucide-react";
import { ModuleHeader, SeverityDot } from "./shared";
import type { ReconModule } from "@shared/schema";

export function TakeoverPanel({ mod }: { mod: ReconModule }) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const d = mod.data as Record<string, any>;
  const results = d.takeoverResults as Array<{
    subdomain: string;
    cname: string;
    service: string | null;
    vulnerable: boolean;
    confidence: string;
  }> | undefined;

  return (
    <Card data-testid="panel-takeover">
      <CardContent className="p-5">
        <ModuleHeader title="Subdomain Takeover" icon={AlertTriangle} confidence={mod.confidence ?? 0} generatedAt={mod.generatedAt} />
        {!results || results.length === 0 ? (
          <p className="text-sm text-muted-foreground">No subdomain takeover vulnerabilities detected.</p>
        ) : (
          <div className="space-y-3">
            <p className="text-sm text-muted-foreground">
              {results.length} vulnerable subdomain{results.length > 1 ? "s" : ""} detected
            </p>
            {results.map((r, i) => (
              <div key={i} className="flex items-start gap-3 p-3 rounded-md bg-muted/30 border">
                <SeverityDot severity={r.confidence === "high" ? "critical" : "high"} />
                <div className="flex-1 min-w-0 space-y-1">
                  <p className="text-sm font-medium font-mono">{r.subdomain}</p>
                  <p className="text-xs text-muted-foreground">
                    CNAME: <span className="font-mono">{r.cname}</span>
                  </p>
                  <div className="flex items-center gap-2 flex-wrap">
                    {r.service && (
                      <Badge variant="outline" className="text-[10px]">{r.service}</Badge>
                    )}
                    <Badge
                      variant={r.confidence === "high" ? "destructive" : "secondary"}
                      className="text-[10px]"
                    >
                      {r.confidence} confidence
                    </Badge>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
