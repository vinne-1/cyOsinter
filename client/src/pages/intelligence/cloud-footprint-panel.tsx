import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Cloud } from "lucide-react";
import type { ReconModule } from "@shared/schema";
import { ModuleHeader, GradeBadge, StatusIcon } from "./shared";

// Normalize cloud_footprint emailSecurity (backend may send { found, record, issues }) and derive grades when missing
function normalizeCloudFootprintData(d: Record<string, unknown>) {
  const raw = d.emailSecurity as Record<string, unknown> | undefined;
  if (!raw) return { email: d.emailSecurity, grades: (d.grades || {}) as Record<string, string> };
  const email: Record<string, { status: string; record: string; issue?: string }> = {};
  const grades: Record<string, string> = { ...(d.grades as Record<string, string>) };
  const gradeNum = (g: string) => ({ A: 4, B: 3, C: 2, D: 1, F: 0 }[g] ?? 0);
  for (const key of ["spf", "dmarc"]) {
    const v = raw[key] as { found?: boolean; record?: string; issues?: string[]; status?: string; issue?: string } | undefined;
    if (!v) continue;
    if ("found" in v && typeof v.found === "boolean") {
      const issues = v.issues ?? [];
      const status = v.found && issues.length === 0 ? "pass" : v.found ? "fail" : "none";
      const issue = issues.length ? issues.join("; ") : undefined;
      email[key] = { status, record: v.record ?? "", issue };
      if (!grades[key]) {
        grades[key] = !v.found ? "F" : issues.length === 0 ? "A" : (v.record?.includes?.("+all") || key === "dmarc" && v.record?.includes?.("p=none")) ? (key === "spf" ? "D" : "C") : "B";
      }
    } else if (v.status !== undefined) {
      email[key] = { status: v.status, record: v.record ?? "", issue: v.issue };
    }
  }
  // Fallback when backend sent new shape (status/record/issue) but no grades
  if (!grades.spf && email.spf?.record) {
    grades.spf = email.spf.status === "pass" ? "A" : email.spf.status === "fail" ? "B" : "F";
  }
  if (!grades.dmarc && email.dmarc?.record) {
    grades.dmarc = email.dmarc.status === "pass" ? "A" : email.dmarc.status === "fail" ? "B" : "F";
  }
  if (!grades.overall && (grades.spf || grades.dmarc)) {
    const n = (gradeNum(grades.spf) + gradeNum(grades.dmarc)) / 2;
    grades.overall = n >= 3.5 ? "A" : n >= 2.5 ? "B" : n >= 1.5 ? "C" : n >= 0.5 ? "D" : "F";
  }
  return { email: { ...raw, ...email }, grades };
}

/**
 * One transport-security control.
 *
 * `n/a` is a real state here, not a missing value: a domain with no MX cannot
 * receive mail, so it is not failing MTA-STS — it has nothing to protect.
 * Rendering that as a failure would contradict the scanner, which deliberately
 * raises no finding in the same situation.
 */
function TransportControl({
  name,
  status,
  detail,
  explanation,
  passLabel,
}: {
  name: string;
  status: string;
  detail?: string;
  explanation: string;
  /**
   * What "working" is called for this control. Each of the three does a
   * different thing — MTA-STS enforces, TLS-RPT reports, BIMI verifies — and a
   * shared "Enforcing" badge would describe two of them wrongly.
   */
  passLabel: string;
}) {
  const tone =
    status === "pass"
      ? "bg-severity-ok/15 text-severity-ok"
      : status === "partial"
        ? "bg-severity-medium/15 text-severity-medium"
        : status === "n/a"
          ? "bg-muted text-muted-foreground"
          : "bg-severity-high/15 text-severity-high";
  const label =
    status === "pass"
      ? passLabel
      : status === "partial"
        ? "Partial"
        : status === "n/a"
          ? "Not applicable"
          : "Not configured";
  return (
    <div className="p-2 rounded-md bg-muted/40 space-y-1">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <StatusIcon pass={status === "pass"} />
          <span className="text-sm font-medium">{name}</span>
        </div>
        <Badge variant="outline" className={`text-xs border-0 no-default-hover-elevate no-default-active-elevate ${tone}`}>
          {label}
        </Badge>
      </div>
      {detail && <p className="text-xs font-mono text-muted-foreground break-all">{detail}</p>}
      {/* A named control means nothing to a reader who has not met it, and this
          panel is where they meet it. */}
      <p className="text-xs text-muted-foreground">{explanation}</p>
    </div>
  );
}

export function CloudFootprintPanel({ mod }: { mod: ReconModule }) {
  const d = mod.data as Record<string, any>;
  const { email: emailRaw, grades } = normalizeCloudFootprintData(d);
  const email = (emailRaw ?? {}) as Record<
    string,
    {
      status: string;
      record: string;
      issue?: string;
      /** SPF only: DNS-querying mechanisms used, against the RFC 7208 limit. */
      lookups?: number;
      lookupLimit?: number;
      lookupsExceeded?: boolean;
    }
  >;
  const transport = d.mailTransport as
    | {
        mtaSts?: string;
        tlsRpt?: string;
        bimi?: string;
        mtaStsMode?: string;
        mtaStsMx?: string[];
        tlsRptDestinations?: string[];
        bimiLogoUrl?: string;
        bimiVmcUrl?: string;
      }
    | undefined;
  const srvServices = (d.srvServices ?? []) as Array<{
    service: string;
    description: string;
    exposure: string;
    targets: string[];
  }>;
  return (
    <div className="space-y-4" data-testid="panel-cloud-footprint">
      <ModuleHeader title="Cloud & Email Security" icon={Cloud} confidence={mod.confidence || 0} generatedAt={mod.generatedAt} />
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card><CardContent className="p-3 text-center"><GradeBadge grade={grades.spf || "N/A"} /><p className="text-xs text-muted-foreground mt-1">SPF</p></CardContent></Card>
        <Card><CardContent className="p-3 text-center"><GradeBadge grade={grades.dmarc || "N/A"} /><p className="text-xs text-muted-foreground mt-1">DMARC</p></CardContent></Card>
        <Card><CardContent className="p-3 text-center"><GradeBadge grade={grades.dkim || "N/A"} /><p className="text-xs text-muted-foreground mt-1">DKIM</p></CardContent></Card>
        <Card><CardContent className="p-3 text-center"><GradeBadge grade={grades.overall || "N/A"} /><p className="text-xs text-muted-foreground mt-1">Overall</p></CardContent></Card>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Cloud Providers</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.cloudProviders || []).map((cp: any, i: number) => (
              <div key={i} className="p-2 rounded-md bg-muted/40 space-y-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-medium">{cp.provider}</span>
                  <span className="text-xs text-muted-foreground">{cp.confidence}%</span>
                </div>
                <div className="flex gap-1 flex-wrap">
                  {(cp.evidence || []).map((e: string, j: number) => (
                    <Badge key={j} variant="outline" className="text-xs no-default-hover-elevate no-default-active-elevate">{e}</Badge>
                  ))}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Storage Endpoints</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {(d.storageEndpoints || []).map((s: any, i: number) => (
              <div key={i} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/40">
                <div>
                  <p className="text-sm font-medium font-mono">{s.name}</p>
                  <p className="text-xs text-muted-foreground">{s.type} ({s.provider})</p>
                </div>
                <div className="flex items-center gap-2">
                  {s.accessible ? <Badge variant="outline" className="text-xs bg-red-600/15 text-red-400 border-0 no-default-hover-elevate no-default-active-elevate">Public</Badge> : <Badge variant="outline" className="text-xs bg-green-600/15 text-green-400 border-0 no-default-hover-elevate no-default-active-elevate">Private</Badge>}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Email Security</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          {email.spf && (
            <div className="p-2 rounded-md bg-muted/40 space-y-1">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2"><StatusIcon pass={email.spf.status === "pass"} /><span className="text-sm font-medium">SPF</span></div>
                <GradeBadge grade={grades.spf || "N/A"} />
              </div>
              <p className="text-xs font-mono text-muted-foreground break-all">{email.spf.record}</p>
              {/* RFC 7208 caps evaluation at 10 DNS lookups. Past that a
                  receiver returns permerror and treats the domain as having no
                  SPF at all, so the count matters before it is exceeded. */}
              {typeof email.spf.lookups === "number" && (
                <p className="text-xs">
                  <span className="text-muted-foreground">DNS lookups: </span>
                  <span
                    className={
                      email.spf.lookupsExceeded
                        ? "text-severity-high"
                        : email.spf.lookups >= 9
                          ? "text-severity-medium"
                          : "text-severity-ok"
                    }
                  >
                    {email.spf.lookups} of {email.spf.lookupLimit ?? 10}
                  </span>
                </p>
              )}
              {email.spf.issue && <p className="text-xs text-yellow-400">{email.spf.issue}</p>}
            </div>
          )}
          {email.dmarc && (
            <div className="p-2 rounded-md bg-muted/40 space-y-1">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2"><StatusIcon pass={email.dmarc.status === "pass"} /><span className="text-sm font-medium">DMARC</span></div>
                <GradeBadge grade={grades.dmarc || "N/A"} />
              </div>
              <p className="text-xs font-mono text-muted-foreground break-all">{email.dmarc.record}</p>
              {email.dmarc.issue && <p className="text-xs text-yellow-400">{email.dmarc.issue}</p>}
            </div>
          )}
          {email.dkim && (
            <div className="p-2 rounded-md bg-muted/40 space-y-1">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <StatusIcon pass={email.dkim.status === "pass"} unknown={email.dkim.status !== "pass"} />
                  <span className="text-sm font-medium">DKIM</span>
                </div>
                <GradeBadge grade={grades.dkim || "N/A"} />
              </div>
              {/* DKIM keys live at a selector the domain owner chooses, and a
                  scan can only try the common ones. Not finding a record is
                  therefore "we could not check", not "DKIM is missing", and
                  saying so keeps the reader from chasing a control they have. */}
              {email.dkim.status !== "pass" && (
                <p className="text-xs text-muted-foreground">
                  No record found at the common selectors. DKIM keys are published under a selector the domain chooses,
                  so this cannot be confirmed from outside without knowing it.
                </p>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Transport security is its own card rather than three more rows above,
          because it answers a different question. SPF/DKIM/DMARC establish that
          a message is authentic; these establish that the connection carrying
          it cannot be silently downgraded to cleartext. A domain can score A on
          the first group and have none of the second, and one merged score
          would hide exactly that. */}
      {transport && (
        <Card data-testid="card-mail-transport">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Mail Transport Security</CardTitle>
            <p className="text-xs text-muted-foreground">
              Whether mail to this domain can be forced onto an unencrypted connection.
            </p>
          </CardHeader>
          <CardContent className="space-y-3">
            <TransportControl
              name="MTA-STS"
              passLabel="Enforcing"
              status={transport.mtaSts ?? "none"}
              detail={
                transport.mtaStsMode
                  ? `mode: ${transport.mtaStsMode}${transport.mtaStsMx?.length ? ` · mx: ${transport.mtaStsMx.join(", ")}` : ""}`
                  : undefined
              }
              explanation="Tells sending servers to refuse delivery over an unencrypted or untrusted connection. SPF, DKIM and DMARC do not cover this — they authenticate the message, not the channel carrying it."
            />
            <TransportControl
              name="TLS-RPT"
              passLabel="Reporting"
              status={transport.tlsRpt ?? "none"}
              detail={transport.tlsRptDestinations?.length ? transport.tlsRptDestinations.join(", ") : undefined}
              explanation="Asks sending providers to report failed TLS negotiations. Without it, an active downgrade against this domain produces no signal the owner can see."
            />
            <TransportControl
              name="BIMI"
              passLabel="Verified"
              status={transport.bimi ?? "none"}
              detail={transport.bimiVmcUrl ? `VMC: ${transport.bimiVmcUrl}` : transport.bimiLogoUrl}
              explanation="Shows a verified brand logo in the inbox. It takes effect only with a DMARC policy of quarantine or reject and a Verified Mark Certificate."
            />
          </CardContent>
        </Card>
      )}

      {/* SRV records are a voluntary public statement of which services run
          where. Grouped by exposure so the ones that should not be public read
          first, rather than sitting as one row in an undifferentiated list. */}
      {srvServices.length > 0 && (
        <Card data-testid="card-srv-services">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Advertised Services (SRV)</CardTitle>
            <p className="text-xs text-muted-foreground">
              Services this domain names in public DNS, with the host and port each runs on.
            </p>
          </CardHeader>
          <CardContent className="space-y-2">
            {[...srvServices]
              .sort((a, b) => Number(b.exposure === "internal") - Number(a.exposure === "internal"))
              .map((svc, i) => (
                <div key={i} className="flex items-start justify-between gap-2 p-2 rounded-md bg-muted/40">
                  <div className="min-w-0">
                    <p className="text-sm font-medium">{svc.description}</p>
                    <p className="text-xs font-mono text-muted-foreground break-all">{svc.targets.join(", ")}</p>
                  </div>
                  <Badge
                    variant="outline"
                    className={`shrink-0 text-xs border-0 no-default-hover-elevate no-default-active-elevate ${
                      svc.exposure === "internal"
                        ? "bg-severity-medium/15 text-severity-medium"
                        : "bg-muted text-muted-foreground"
                    }`}
                  >
                    {svc.exposure === "internal" ? "Internal" : "Public"}
                  </Badge>
                </div>
              ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
