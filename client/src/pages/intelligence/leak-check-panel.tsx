/**
 * Leak Check Panel — lists discovered emails/domains/IPs from findings and
 * provides free breach-checking via:
 *   A) Quick-launch external site links (LeakCheckLauncher)
 *   B) Inline CORS-open API results (EmailRep.io, Shodan InternetDB)
 */

import { useQuery } from "@tanstack/react-query";
import { useDomain } from "@/lib/domain-context";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { ShieldQuestion, Download, AlertTriangle, CheckCircle2, Mail, Globe, Server, Info } from "lucide-react";
import { LeakCheckLauncher } from "@/components/leak-check-launcher";
import { useEmailRepCheck, useShodanInternetDB } from "@/hooks/use-breach-check";
import type { Finding } from "@shared/schema";

// ── Inline result sub-components ──────────────────────────────────────────────

function EmailRepBadge({ email }: { email: string }) {
  const { data, isLoading, isError } = useEmailRepCheck(email);

  if (isLoading) return <Skeleton className="h-5 w-24" />;
  if (isError) return (
    <span className="text-[10px] text-muted-foreground italic">CORS unavailable</span>
  );
  if (!data) return null;

  const breached = data.details.credentials_leaked || data.details.data_breach;
  const suspicious = data.suspicious;

  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      <Badge
        variant="outline"
        className={`text-[10px] ${breached ? "border-red-500 text-red-500" : suspicious ? "border-orange-500 text-orange-500" : "border-green-500 text-green-500"}`}
      >
        {breached ? "Credentials Leaked" : suspicious ? "Suspicious" : "Clean"}
      </Badge>
      <span className="text-[10px] text-muted-foreground capitalize">Rep: {data.reputation}</span>
      {data.details.disposable && (
        <Badge variant="secondary" className="text-[10px]">Disposable</Badge>
      )}
      {data.details.spam && (
        <Badge variant="secondary" className="text-[10px]">Spam</Badge>
      )}
    </div>
  );
}

function ShodanIpBadge({ ip }: { ip: string }) {
  const { data, isLoading, isError } = useShodanInternetDB(ip);

  if (isLoading) return <Skeleton className="h-5 w-24" />;
  if (isError) return (
    <span className="text-[10px] text-muted-foreground italic">not indexed</span>
  );
  if (!data) return null;

  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      {data.vulns.length > 0 && (
        <Badge variant="outline" className="text-[10px] border-red-500 text-red-500">
          {data.vulns.length} CVE{data.vulns.length > 1 ? "s" : ""}
        </Badge>
      )}
      {data.ports.length > 0 && (
        <span className="text-[10px] text-muted-foreground">{data.ports.length} open ports</span>
      )}
      {data.tags.includes("cdn") && <Badge variant="secondary" className="text-[10px]">CDN</Badge>}
      {data.tags.includes("cloud") && <Badge variant="secondary" className="text-[10px]">Cloud</Badge>}
      {data.tags.includes("tor") && (
        <Badge variant="outline" className="text-[10px] border-orange-500 text-orange-500">Tor</Badge>
      )}
      {data.vulns.length === 0 && data.ports.length === 0 && (
        <span className="text-[10px] text-muted-foreground">No known vulns</span>
      )}
    </div>
  );
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function extractTargets(findings: Finding[]) {
  const emails = new Set<string>();
  const domains = new Set<string>();
  const ips = new Set<string>();

  for (const f of findings) {
    const asset = f.affectedAsset ?? "";

    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(asset)) {
      emails.add(asset.toLowerCase());
    } else if (/^(\d{1,3}\.){3}\d{1,3}$/.test(asset)) {
      ips.add(asset);
    } else if (asset && !asset.startsWith("http") && asset.includes(".")) {
      domains.add(asset.toLowerCase());
    }

    // Also pull emails from description text (simple regex)
    const desc = (f.description ?? "") + " " + (f.title ?? "");
    const emailMatches = desc.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g) ?? [];
    for (const e of emailMatches) {
      emails.add(e.toLowerCase());
    }
  }

  return {
    emails: Array.from(emails).slice(0, 30),
    domains: Array.from(domains).slice(0, 20),
    ips: Array.from(ips).slice(0, 20),
  };
}

function buildExportText(emails: string[], domains: string[], ips: string[]) {
  const SITES_EMAIL = [
    "https://haveibeenpwned.com/account/",
    "https://leakcheck.io/?check=",
    "https://dehashed.com/search?query=",
    "https://breachdirectory.org/?search=",
    "https://intelx.io/?s=",
  ];
  const SITES_DOMAIN = [
    "https://urlscan.io/search/#domain%3A",
    "https://dehashed.com/search?query=",
    "https://intelx.io/?s=",
  ];
  const SITES_IP = [
    "https://www.shodan.io/host/",
    "https://viz.greynoise.io/ip/",
    "https://www.abuseipdb.com/check/",
  ];

  const lines: string[] = ["# Leak Check URLs — generated by Cyber Shield Pro", ""];

  if (emails.length > 0) {
    lines.push("## EMAILS");
    for (const e of emails) {
      for (const s of SITES_EMAIL) lines.push(`${s}${encodeURIComponent(e)}`);
      lines.push("");
    }
  }
  if (domains.length > 0) {
    lines.push("## DOMAINS");
    for (const d of domains) {
      for (const s of SITES_DOMAIN) lines.push(`${s}${encodeURIComponent(d)}`);
      lines.push("");
    }
  }
  if (ips.length > 0) {
    lines.push("## IPs");
    for (const ip of ips) {
      for (const s of SITES_IP) lines.push(`${s}${encodeURIComponent(ip)}`);
      lines.push("");
    }
  }

  return lines.join("\n");
}

// ── Main panel ─────────────────────────────────────────────────────────────────

export function LeakCheckPanel() {
  const { selectedWorkspaceId } = useDomain();

  const { data: findings = [], isLoading } = useQuery<Finding[]>({
    queryKey: [`/api/workspaces/${selectedWorkspaceId}/findings`],
    enabled: !!selectedWorkspaceId,
  });

  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-5 space-y-3">
          <Skeleton className="h-6 w-48" />
          <Skeleton className="h-32 w-full" />
        </CardContent>
      </Card>
    );
  }

  const { emails, domains, ips } = extractTargets(findings);
  const total = emails.length + domains.length + ips.length;

  function handleExport() {
    const text = buildExportText(emails, domains, ips);
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "breach-check-urls.txt";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <Card data-testid="panel-leak-check">
      <CardContent className="p-5 space-y-5">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldQuestion className="w-5 h-5 text-primary" />
            <div>
              <p className="text-sm font-semibold">Leak Check</p>
              <p className="text-xs text-muted-foreground">
                Opens external breach-check sites pre-filled. Only test authorised targets.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="ghost" size="icon" className="h-7 w-7">
                    <Info className="w-4 h-4 text-muted-foreground" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent side="left" className="max-w-xs text-xs">
                  This feature opens third-party websites and submits your target data to them.
                  Inline badges (EmailRep, Shodan) call free APIs directly from your browser.
                  Only use on targets you are authorised to test.
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
            <Button variant="outline" size="sm" onClick={handleExport} disabled={total === 0} data-testid="btn-export-leak-urls">
              <Download className="w-4 h-4 mr-1.5" />
              Export URLs
            </Button>
          </div>
        </div>

        {/* Summary stats */}
        <div className="grid grid-cols-3 gap-3">
          <div className="p-2 rounded-md bg-muted/30 text-center">
            <Mail className="w-4 h-4 mx-auto mb-1 text-blue-400" />
            <p className="text-lg font-semibold">{emails.length}</p>
            <p className="text-[10px] text-muted-foreground">Emails</p>
          </div>
          <div className="p-2 rounded-md bg-muted/30 text-center">
            <Globe className="w-4 h-4 mx-auto mb-1 text-green-400" />
            <p className="text-lg font-semibold">{domains.length}</p>
            <p className="text-[10px] text-muted-foreground">Domains</p>
          </div>
          <div className="p-2 rounded-md bg-muted/30 text-center">
            <Server className="w-4 h-4 mx-auto mb-1 text-purple-400" />
            <p className="text-lg font-semibold">{ips.length}</p>
            <p className="text-[10px] text-muted-foreground">IPs</p>
          </div>
        </div>

        {total === 0 && (
          <div className="text-center py-8">
            <CheckCircle2 className="w-8 h-8 text-muted-foreground/40 mx-auto mb-2" />
            <p className="text-sm text-muted-foreground">No emails, domains, or IPs extracted from findings yet.</p>
            <p className="text-xs text-muted-foreground mt-1">Run an OSINT or EASM scan first.</p>
          </div>
        )}

        {/* Emails */}
        {emails.length > 0 && (
          <section className="space-y-2">
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
              <Mail className="w-3 h-3" /> Emails
            </p>
            <div className="space-y-1.5">
              {emails.map((email) => (
                <div key={email} className="flex items-center gap-2 p-2 rounded-md bg-muted/20 text-xs">
                  <span className="font-mono flex-1 truncate">{email}</span>
                  <EmailRepBadge email={email} />
                  <LeakCheckLauncher value={email} type="email" size="icon" />
                </div>
              ))}
            </div>
          </section>
        )}

        {/* Domains */}
        {domains.length > 0 && (
          <section className="space-y-2">
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
              <Globe className="w-3 h-3" /> Domains
            </p>
            <div className="space-y-1.5">
              {domains.map((domain) => (
                <div key={domain} className="flex items-center gap-2 p-2 rounded-md bg-muted/20 text-xs">
                  <span className="font-mono flex-1 truncate">{domain}</span>
                  <LeakCheckLauncher value={domain} type="domain" size="icon" />
                </div>
              ))}
            </div>
          </section>
        )}

        {/* IPs */}
        {ips.length > 0 && (
          <section className="space-y-2">
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
              <Server className="w-3 h-3" /> IPs
            </p>
            <div className="space-y-1.5">
              {ips.map((ip) => (
                <div key={ip} className="flex items-center gap-2 p-2 rounded-md bg-muted/20 text-xs">
                  <span className="font-mono flex-1">{ip}</span>
                  <ShodanIpBadge ip={ip} />
                  <LeakCheckLauncher value={ip} type="ip" size="icon" />
                </div>
              ))}
            </div>
          </section>
        )}

        {total > 0 && (
          <div className="flex items-center gap-1.5 p-2 rounded-md bg-yellow-500/5 border border-yellow-500/20">
            <AlertTriangle className="w-3.5 h-3.5 text-yellow-500 flex-shrink-0" />
            <p className="text-[10px] text-muted-foreground">
              Inline badges call EmailRep.io and Shodan InternetDB directly from your browser.
              Quick-launch buttons open external sites — only submit data for targets you are authorised to test.
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
