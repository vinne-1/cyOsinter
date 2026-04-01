import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Link2 } from "lucide-react";
import type { ReconModule } from "@shared/schema";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ModuleHeader, SeverityDot } from "./shared";

export function ThirdPartySurfacePanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as Record<string, any>;
  return (
    <div className="space-y-4" data-testid="panel-third-party">
      <ModuleHeader title="Third-Party & Supply Chain" icon={Link2} confidence={mod.confidence || 0} generatedAt={mod.generatedAt} />
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">SaaS Services Detected</CardTitle></CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Service</TableHead>
                  <TableHead>Category</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Confidence</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(d.saasServices || []).map((s: any, i: number) => (
                  <TableRow key={i}>
                    <TableCell className="text-sm font-medium">{s.name}</TableCell>
                    <TableCell><Badge variant="outline" className="text-xs no-default-hover-elevate no-default-active-elevate">{s.category}</Badge></TableCell>
                    <TableCell className="text-sm text-muted-foreground">{s.source}</TableCell>
                    <TableCell className="text-sm font-mono">{s.confidence}%</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Vendor Portals</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.vendorPortals || []).map((v: any, i: number) => (
              <div key={i} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/40">
                <div>
                  <p className="text-sm font-mono">{v.subdomain}</p>
                  <p className="text-xs text-muted-foreground">{v.vendor} - {v.type}</p>
                </div>
                <span className="text-xs text-muted-foreground">{v.source}</span>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Breach References</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.breachReferences || []).map((b: any, i: number) => (
              <div key={i} className="p-2 rounded-md bg-muted/40 space-y-1">
                <div className="flex items-center gap-2">
                  <SeverityDot severity={b.severity} />
                  <span className="text-sm font-medium">{b.source}</span>
                </div>
                <p className="text-xs text-muted-foreground">{b.description}</p>
                <p className="text-xs text-muted-foreground">{b.date}</p>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
      {(d.riskFlags || []).length > 0 && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Supply Chain Risk Flags</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {d.riskFlags.map((f: any, i: number) => (
              <div key={i} className="flex items-center gap-3 p-2 rounded-md bg-muted/40">
                <SeverityDot severity={f.severity} />
                <div className="flex-1">
                  <span className="text-sm font-medium">{f.service}</span>
                  <p className="text-xs text-muted-foreground">{f.risk}</p>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
