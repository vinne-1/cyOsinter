import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Shield, AlertTriangle, RefreshCw, Lock, CheckCircle } from "lucide-react";
import { buildUrl } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface TlsCert {
  id: string;
  host: string;
  subject: string | null;
  issuer: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  protocol: string | null;
  isWildcard: boolean;
  san: string[];
  signatureAlgorithm: string | null;
  lastSeen: string;
}

interface ExpiryBucket { count: number; certs: TlsCert[] }
interface ExpiryCalendar {
  total: number;
  buckets: Record<string, ExpiryBucket>;
}

function expiryColor(days: number | null): string {
  if (days == null) return "text-muted-foreground";
  if (days <= 0) return "text-red-600";
  if (days <= 7) return "text-red-500";
  if (days <= 14) return "text-orange-500";
  if (days <= 30) return "text-yellow-500";
  return "text-green-500";
}

function expiryBadgeVariant(days: number | null): "destructive" | "default" | "secondary" | "outline" {
  if (days == null) return "secondary";
  if (days <= 7) return "destructive";
  if (days <= 30) return "default";
  return "outline";
}

function CertCard({ cert }: { cert: TlsCert }) {
  const days = cert.daysRemaining;
  return (
    <div className="border rounded-lg p-4 space-y-2">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <Lock className="w-4 h-4 shrink-0 text-muted-foreground" />
          <span className="font-mono text-sm font-medium truncate">{cert.host}</span>
          {cert.isWildcard && <Badge variant="outline" className="text-xs shrink-0">Wildcard</Badge>}
        </div>
        <Badge variant={expiryBadgeVariant(days)} className="shrink-0">
          {days == null ? "Unknown" : days <= 0 ? "Expired" : `${days}d`}
        </Badge>
      </div>
      {cert.subject && (
        <p className="text-xs text-muted-foreground truncate">Subject: {cert.subject}</p>
      )}
      {cert.issuer && (
        <p className="text-xs text-muted-foreground truncate">Issuer: {cert.issuer}</p>
      )}
      <div className="flex items-center gap-3 text-xs text-muted-foreground">
        {cert.protocol && <span>{cert.protocol}</span>}
        {cert.signatureAlgorithm && <span>{cert.signatureAlgorithm}</span>}
        {cert.validTo && (
          <span className={expiryColor(days)}>
            Expires {new Date(cert.validTo).toLocaleDateString()}
          </span>
        )}
      </div>
      {cert.san && cert.san.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-1">
          {cert.san.slice(0, 4).map((s, i) => (
            <span key={i} className="text-[10px] bg-muted px-1 rounded font-mono">{s}</span>
          ))}
          {cert.san.length > 4 && (
            <span className="text-[10px] text-muted-foreground">+{cert.san.length - 4} more</span>
          )}
        </div>
      )}
    </div>
  );
}

function BucketCard({ label, color, bucket }: { label: string; color: string; bucket: ExpiryBucket }) {
  return (
    <Card className={`border-l-4 ${color}`}>
      <CardContent className="p-4">
        <div className="text-2xl font-bold">{bucket.count}</div>
        <div className="text-sm text-muted-foreground">{label}</div>
      </CardContent>
    </Card>
  );
}

export default function CertificatesPage() {
  const { selectedWorkspace: ws } = useDomain();
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data: calendar, isLoading } = useQuery<ExpiryCalendar>({
    queryKey: [`/api/workspaces/${ws?.id}/certificates/expiry-calendar`],
    enabled: !!ws,
  });

  const { data: allCerts = [] } = useQuery<TlsCert[]>({
    queryKey: [`/api/workspaces/${ws?.id}/certificates`],
    enabled: !!ws,
  });

  const { mutate: refresh, isPending: refreshing } = useMutation({
    mutationFn: () =>
      fetch(buildUrl(`/api/workspaces/${ws!.id}/certificates/refresh`), { method: "POST" }).then((r) => r.json()),
    onSuccess: () => {
      toast({ title: "Certificate inventory refresh started" });
      setTimeout(() => qc.invalidateQueries({ queryKey: [`/api/workspaces/${ws?.id}/certificates`] }), 3000);
    },
  });

  if (!ws) return <div className="p-6 text-muted-foreground">Select a workspace.</div>;

  const buckets = calendar?.buckets;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Certificate Lifecycle</h1>
          <p className="text-muted-foreground">TLS certificate inventory and expiry tracking across all assets.</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refresh()} disabled={refreshing}>
          <RefreshCw className={`w-4 h-4 mr-2 ${refreshing ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </div>

      {isLoading ? (
        <p className="text-muted-foreground">Loading certificate inventory...</p>
      ) : !calendar ? (
        <Card><CardContent className="p-8 text-center">
          <Shield className="w-12 h-12 mx-auto mb-4 text-muted-foreground/40" />
          <p className="text-muted-foreground">No certificate data. Run a scan to populate the inventory.</p>
        </CardContent></Card>
      ) : (
        <>
          {/* Summary buckets */}
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
            <BucketCard label="Expired" color="border-red-600" bucket={buckets?.expired ?? { count: 0, certs: [] }} />
            <BucketCard label="≤ 7 days" color="border-red-500" bucket={buckets?.days7 ?? { count: 0, certs: [] }} />
            <BucketCard label="≤ 14 days" color="border-orange-500" bucket={buckets?.days14 ?? { count: 0, certs: [] }} />
            <BucketCard label="≤ 30 days" color="border-yellow-500" bucket={buckets?.days30 ?? { count: 0, certs: [] }} />
            <BucketCard label="≤ 60 days" color="border-blue-400" bucket={buckets?.days60 ?? { count: 0, certs: [] }} />
            <BucketCard label="≤ 90 days" color="border-blue-300" bucket={buckets?.days90 ?? { count: 0, certs: [] }} />
            <BucketCard label="Healthy" color="border-green-500" bucket={buckets?.healthy ?? { count: 0, certs: [] }} />
          </div>

          {/* Urgent certs */}
          {(buckets?.expired.count ?? 0) + (buckets?.days7.count ?? 0) + (buckets?.days14.count ?? 0) > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-red-500">
                  <AlertTriangle className="w-5 h-5" />
                  Urgent Attention Required
                </CardTitle>
              </CardHeader>
              <CardContent className="grid gap-3 md:grid-cols-2">
                {[...(buckets?.expired.certs ?? []), ...(buckets?.days7.certs ?? []), ...(buckets?.days14.certs ?? [])].map((c) => (
                  <CertCard key={c.id} cert={c} />
                ))}
              </CardContent>
            </Card>
          )}

          {/* All certs */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2">
                <Lock className="w-5 h-5" />
                All Certificates ({calendar.total})
              </CardTitle>
            </CardHeader>
            <CardContent className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
              {allCerts.map((c) => <CertCard key={c.id} cert={c} />)}
              {allCerts.length === 0 && (
                <p className="text-muted-foreground col-span-3 py-4 text-center">No certificates found.</p>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
