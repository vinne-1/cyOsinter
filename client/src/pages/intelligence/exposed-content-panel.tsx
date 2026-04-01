import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { FileWarning } from "lucide-react";
import type { ReconModule } from "@shared/schema";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ModuleHeader, SeverityDot, EvidenceLink } from "./shared";

const RESPONSE_TYPE_ORDER = ["success", "forbidden", "unauthorized", "redirect", "redirect_to_login", "server_error", "not_found", "soft_404", "other"] as const;
const RESPONSE_TYPE_LABELS: Record<string, string> = {
  success: "Accessible (200)",
  forbidden: "Forbidden (403)",
  unauthorized: "Unauthorized (401)",
  redirect: "Redirect (3xx)",
  redirect_to_login: "Redirect to Login (protected)",
  server_error: "Server Error (5xx)",
  not_found: "Page Not Found (404)",
  soft_404: "Soft 404 (200 with not-found content)",
  other: "Other",
};

function deriveResponseType(v: { status?: number; accessible?: boolean }): string {
  const s = v.status;
  if (s === 200) return v.accessible ? "success" : "not_found";
  if (s === 404) return "not_found";
  if (s === 403) return "forbidden";
  if (s === 401) return "unauthorized";
  if (s && [301, 302, 307, 308].includes(s)) return "redirect";
  if (s && s >= 500) return "server_error";
  return "other";
}

export function ExposedContentPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as Record<string, any>;
  const publicFiles = d.publicFiles || [];
  const pathChecks = d.pathChecks ? Object.entries(d.pathChecks) as [string, { status: number; accessible?: boolean; responseType?: string; severity?: string; validated?: boolean; confidence?: string; redirectTarget?: string }][] : [];
  const rows: Array<{ path: string; type: string; severity: string; responseType: string; validated?: boolean; confidence?: string; redirectTarget?: string; firstSeen: string; evidenceUrl?: string }> = publicFiles.length
    ? publicFiles.map((f: any) => ({ ...f, responseType: f.responseType ?? "other" }))
    : pathChecks.map(([path, v]) => ({
        path,
        type: path.replace(/^\//, "").replace(/\//g, " ") || "path",
        severity: v.severity ?? (v.accessible ? "low" : "info"),
        responseType: v.responseType ?? deriveResponseType(v),
        validated: v.validated,
        confidence: v.confidence,
        redirectTarget: v.redirectTarget,
        firstSeen: "-",
        evidenceUrl: path.startsWith("http") ? path : undefined,
      }));

  const grouped = rows.reduce((acc, r) => {
    const rt = r.responseType;
    if (!acc[rt]) acc[rt] = [];
    acc[rt].push(r);
    return acc;
  }, {} as Record<string, typeof rows>);

  const dirBrute = d.directoryBruteforce;
  const hitCounts: Record<string, number> = dirBrute?.hits?.reduce((acc: Record<string, number>, h: { responseType?: string }) => {
    const rt = h.responseType ?? "other";
    acc[rt] = (acc[rt] ?? 0) + 1;
    return acc;
  }, {} as Record<string, number>) ?? {};

  const positiveResponseTypes = ["success", "redirect", "redirect_to_login", "forbidden", "unauthorized"];
  const dirBruteGrouped = (dirBrute?.hits || []).reduce((acc: Record<string, Array<{ path: string; status: number; responseType?: string; severity?: string; evidenceUrl?: string }>>, h: { path: string; status: number; responseType?: string; severity?: string; evidenceUrl?: string }) => {
    const rt = h.responseType ?? (h.status >= 200 && h.status < 300 ? "success" : h.status >= 300 && h.status < 400 ? "redirect" : h.status === 403 ? "forbidden" : h.status === 401 ? "unauthorized" : h.status === 404 ? "not_found" : "other");
    if (!acc[rt]) acc[rt] = [];
    acc[rt].push(h);
    return acc;
  }, {} as Record<string, Array<{ path: string; status: number; responseType?: string; severity?: string; evidenceUrl?: string }>>);

  return (
    <div className="space-y-4" data-testid="panel-exposed-content">
      <ModuleHeader title="Exposed Content & Leaks" icon={FileWarning} confidence={mod.confidence || 0} generatedAt={mod.generatedAt} />
      {dirBrute && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Directory Bruteforce</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <p className="text-xs text-muted-foreground">Wordlist: {dirBrute.wordlistSource}</p>
            <div className="flex flex-wrap gap-3">
              <span className="text-sm"><strong>{dirBrute.tried}</strong> tried</span>
              <span className="text-sm"><strong>{dirBrute.hits?.length ?? 0}</strong> total</span>
              {Object.entries(hitCounts).map(([rt, n]) => (
                <span key={rt} className="text-sm text-muted-foreground">{RESPONSE_TYPE_LABELS[rt] ?? rt}: <strong>{n}</strong></span>
              ))}
            </div>
            {(dirBrute.hits?.length ?? 0) > 0 && (
              <div className="space-y-4">
                {[...RESPONSE_TYPE_ORDER, ...Object.keys(dirBruteGrouped).filter((k) => !(RESPONSE_TYPE_ORDER as readonly string[]).includes(k))].map((rt) => {
                  const items = dirBruteGrouped[rt];
                  if (!items?.length) return null;
                  const isPositive = positiveResponseTypes.includes(rt);
                  return (
                    <div key={rt}>
                      <h4 className={`text-sm font-medium mb-2 ${isPositive ? "text-green-400" : ""}`}>
                        {RESPONSE_TYPE_LABELS[rt] ?? rt} ({items.length})
                        {isPositive && <span className="text-xs text-muted-foreground ml-1">(positive hit)</span>}
                      </h4>
                      <div className="overflow-x-auto max-h-48">
                        <Table>
                          <TableHeader><TableRow><TableHead>Path</TableHead><TableHead>Status</TableHead><TableHead>Response</TableHead><TableHead>Severity</TableHead><TableHead>Evidence</TableHead></TableRow></TableHeader>
                          <TableBody>
                            {items.slice(0, 50).map((h: { path: string; status: number; responseType?: string; severity?: string; evidenceUrl?: string }, i: number) => (
                              <TableRow key={`${rt}-${i}`}>
                                <TableCell className="font-mono text-xs">{h.path}</TableCell>
                                <TableCell>{h.status}</TableCell>
                                <TableCell className="text-xs">{RESPONSE_TYPE_LABELS[h.responseType ?? "other"] ?? h.responseType}</TableCell>
                                <TableCell><div className="flex items-center gap-1.5"><SeverityDot severity={h.severity ?? "info"} /><span className="text-xs capitalize">{h.severity ?? "info"}</span></div></TableCell>
                                <TableCell><EvidenceLink url={h.evidenceUrl} label="Open" /></TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                        {items.length > 50 && <p className="text-xs text-muted-foreground mt-1">+ {items.length - 50} more</p>}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>
      )}
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Public Files & Endpoints ({rows.length})</CardTitle></CardHeader>
        <CardContent className="space-y-6">
          {[...RESPONSE_TYPE_ORDER, ...Object.keys(grouped).filter((k) => !(RESPONSE_TYPE_ORDER as readonly string[]).includes(k))].map((rt) => {
            const items = grouped[rt];
            if (!items?.length) return null;
            return (
              <div key={rt}>
                <h4 className="text-sm font-medium mb-2">{RESPONSE_TYPE_LABELS[rt] ?? rt} ({items.length})</h4>
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader><TableRow><TableHead>Path</TableHead><TableHead>Type</TableHead><TableHead>Severity</TableHead><TableHead>Confidence</TableHead><TableHead>Evidence</TableHead></TableRow></TableHeader>
                    <TableBody>
                      {items.map((f: any, i: number) => (
                        <TableRow key={`${rt}-${i}`}>
                          <TableCell className="font-mono text-sm">{f.path}</TableCell>
                          <TableCell className="text-sm">{f.type}</TableCell>
                          <TableCell><div className="flex items-center gap-1.5"><SeverityDot severity={f.severity} /><span className="text-sm capitalize">{f.severity}</span></div></TableCell>
                          <TableCell>{f.confidence ? <Badge variant="outline" className="text-xs border-0 no-default-hover-elevate no-default-active-elevate">{f.confidence}</Badge> : null}</TableCell>
                          <TableCell><EvidenceLink url={f.evidenceUrl} /></TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </div>
            );
          })}
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Secrets Exposure Indicators</CardTitle></CardHeader>
        <CardContent className="space-y-2">
          {(d.secretsExposure || []).map((s: any, i: number) => (
            <div key={i} className="flex items-start justify-between gap-3 p-2 rounded-md bg-muted/40">
              <div className="flex items-start gap-2">
                <SeverityDot severity={s.severity} />
                <div>
                  <p className="text-sm font-medium">{s.pattern}</p>
                  <p className="text-xs text-muted-foreground">{s.location}</p>
                  {s.redacted && <Badge variant="outline" className="text-xs mt-1 no-default-hover-elevate no-default-active-elevate">Redacted</Badge>}
                </div>
              </div>
              <EvidenceLink url={s.evidenceUrl} />
            </div>
          ))}
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Archived / Changed URLs</CardTitle></CardHeader>
        <CardContent className="space-y-2">
          {(d.archivedUrls || []).map((u: any, i: number) => (
            <div key={i} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/40">
              <div className="flex items-center gap-2">
                <Badge variant="outline" className={`text-xs border-0 no-default-hover-elevate no-default-active-elevate ${u.status === "Removed" ? "bg-red-600/15 text-red-400" : "bg-yellow-600/15 text-yellow-400"}`}>{u.status}</Badge>
                <span className="text-sm font-mono">{u.url}</span>
              </div>
              <span className="text-xs text-muted-foreground">{u.source} | {u.lastSeen}</span>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
