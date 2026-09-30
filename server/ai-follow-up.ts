/**
 * AI follow-up report.
 *
 * One report segment, three steps, in this order:
 *   1. GLM consolidates this workspace's security findings into themes.
 *   2. The server runs a short allowlist of checks the model picked — live
 *      fingerprint, security headers, DNSSEC, TLS versions, SPF/DMARC —
 *      against hosts already in this workspace.
 *   3. GLM writes one consolidated narrative from the themes and the check
 *      results.
 *
 * The model may only name a check from the allowlist. It does not choose
 * URLs, payloads, or tools. A host is probed only when it is inside the
 * workspace domain. When GLM does not answer, the same steps still run from
 * the finding categories, and the segment says the narrative is rule-based.
 */

import { recordResolver } from "./scanner/dns.js";
import { isUsableDomain } from "./scanner/breach-exposure.js";
import { isInScope } from "./scanner/crawler.js";
import { checkDnssec } from "./scanner/dnssec.js";
import { probeHosts } from "./scanner/http-probe.js";
import { httpGetNoRedirect } from "./scanner/http.js";
import { analyzeDmarcDeep, analyzeSpfDeep, type TxtLookup } from "./scanner/spf-dmarc-deep.js";
import { enumerateTlsVersions } from "./scanner/tls-protocols.js";
import { isSafeOutboundUrl } from "./utils/ssrf.js";
import { completeAi } from "./ai-service.js";
import { createLogger } from "./logger.js";

const log = createLogger("ai-follow-up");

export const FOLLOW_UP_CHECK_IDS = [
  "http_fingerprint",
  "security_headers",
  "dnssec",
  "tls_versions",
  "mail_auth",
] as const;

export type FollowUpCheckId = (typeof FOLLOW_UP_CHECK_IDS)[number];

const CHECK_LABEL: Record<FollowUpCheckId, string> = {
  http_fingerprint: "Live host fingerprint",
  security_headers: "Security headers",
  dnssec: "DNSSEC",
  tls_versions: "TLS versions",
  mail_auth: "SPF and DMARC",
};

/** Categories that justify a check when the model does not name one. */
const CHECKS_FOR_CATEGORY: Record<string, FollowUpCheckId[]> = {
  ssl_issue: ["tls_versions", "http_fingerprint"],
  transport_security: ["security_headers", "tls_versions"],
  security_headers: ["security_headers"],
  cookie_security: ["security_headers", "http_fingerprint"],
  dns_misconfiguration: ["dnssec", "mail_auth"],
  email_security: ["mail_auth"],
  certificate_authority: ["dnssec"],
  information_disclosure: ["http_fingerprint", "security_headers"],
  exposed_service: ["http_fingerprint"],
  network_exposure: ["http_fingerprint"],
};

const HEADER_NAMES = [
  "strict-transport-security",
  "content-security-policy",
  "x-content-type-options",
  "x-frame-options",
  "referrer-policy",
  "permissions-policy",
];

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const MAX_CHECKS = 4;
const MAX_HOSTS = 5;
const CHECK_TIMEOUT_MS = 25_000;

export interface FollowUpFinding {
  id: string;
  title: string;
  severity: string;
  category: string;
  affectedAsset?: string | null;
  status?: string | null;
  description?: string | null;
  remediation?: string | null;
}

export interface FollowUpTheme {
  title: string;
  severity: string;
  findingIds: string[];
  narrative: string;
  action: string;
}

export interface FollowUpCheckResult {
  id: FollowUpCheckId;
  label: string;
  status: "completed" | "unavailable" | "skipped";
  summary: string;
}

export interface AiFollowUpSegment {
  generatedBy: "glm" | "rules";
  model?: string;
  domain: string | null;
  consolidatedAt: string;
  themes: FollowUpTheme[];
  checks: FollowUpCheckResult[];
  narrative: string;
  nextSteps: string[];
}

export interface CheckContext {
  domain: string;
  hosts: string[];
}

export function hostFromAsset(value: string): string | null {
  const raw = value.trim();
  if (!raw) return null;
  if (raw.includes("://")) {
    try {
      return new URL(raw).hostname.toLowerCase().replace(/\.$/, "") || null;
    } catch {
      return null;
    }
  }
  const host = raw.split("/")[0]?.split(":")[0]?.toLowerCase().replace(/\.$/, "") ?? "";
  if (!host || !/^[a-z0-9.-]+$/.test(host)) return null;
  return host;
}

/**
 * The best usable domain to run live verification against, tried in order:
 * an explicit known target (e.g. the domain a scan was just triggered
 * against), the workspace's own `domain`/`name` field, then — the fallback
 * that matters — the host named on the findings themselves.
 *
 * `workspace.domain` is unset for roughly half the workspaces in this
 * product, and `workspace.name` is a display label, not a hostname ("zepto"
 * for a workspace scanned against "zepto.com"). Both fail `isUsableDomain`,
 * so verification silently ran zero checks even though the workspace holds
 * findings with a perfectly usable host in `affectedAsset` — indistinguishable
 * in the UI from "we checked and found nothing," which is exactly the
 * three-state collapse this codebase's own conventions warn against.
 */
export function resolveVerifiableTarget(
  candidates: Array<string | null | undefined>,
  findings: Array<{ affectedAsset?: string | null }>,
): string | null {
  for (const candidate of candidates) {
    if (candidate && isUsableDomain(candidate)) return candidate;
  }
  for (const finding of findings) {
    if (!finding.affectedAsset) continue;
    const host = hostFromAsset(finding.affectedAsset);
    if (host && isUsableDomain(host)) return host;
  }
  return null;
}

/** Apex plus in-scope hostnames named by findings. Out-of-scope names are dropped. */
export function hostsForFollowUp(domain: string, assets: Array<string | null | undefined>, limit = MAX_HOSTS): string[] {
  const root = domain.trim().toLowerCase();
  const out: string[] = [];
  const push = (host: string | null) => {
    if (!host || out.includes(host) || out.length >= limit) return;
    if (!isUsableDomain(host)) return;
    if (root && host !== root && !isInScope(`https://${host}/`, root)) return;
    out.push(host);
  };
  if (isUsableDomain(root)) push(root);
  for (const asset of assets) {
    if (asset) push(hostFromAsset(asset));
  }
  return out;
}

export function chooseFollowUpChecks(categories: string[], requested: string[]): FollowUpCheckId[] {
  const known = new Set<string>(FOLLOW_UP_CHECK_IDS);
  const picked: FollowUpCheckId[] = [];
  const add = (id: FollowUpCheckId) => {
    if (!picked.includes(id) && picked.length < MAX_CHECKS) picked.push(id);
  };
  for (const id of requested) {
    if (known.has(id)) add(id as FollowUpCheckId);
  }
  if (picked.length > 0) return picked;
  for (const category of categories) {
    for (const id of CHECKS_FOR_CATEGORY[category] ?? []) add(id);
  }
  if (picked.length === 0) {
    add("http_fingerprint");
    add("security_headers");
  }
  return picked;
}

export function themesFromFindings(findings: FollowUpFinding[]): FollowUpTheme[] {
  const groups = new Map<string, FollowUpFinding[]>();
  for (const finding of findings) {
    const key = finding.category || "unclassified";
    const list = groups.get(key) ?? [];
    list.push(finding);
    groups.set(key, list);
  }
  const rank = (severity: string) => SEVERITIES.indexOf(severity as (typeof SEVERITIES)[number]);
  return Array.from(groups.entries()).slice(0, 8).map(([category, rows]) => {
    const worst = [...rows].sort((a, b) => {
      const ar = rank(a.severity);
      const br = rank(b.severity);
      return (ar < 0 ? 9 : ar) - (br < 0 ? 9 : br);
    })[0];
    const titles = rows.slice(0, 4).map((row) => row.title).join("; ");
    return {
      title: category.replace(/_/g, " "),
      severity: SEVERITIES.includes(worst?.severity as (typeof SEVERITIES)[number]) ? worst!.severity : "info",
      findingIds: rows.map((row) => row.id).slice(0, 20),
      narrative: `${rows.length} open finding(s) in this category: ${titles}.`,
      action: (worst?.remediation ?? "").slice(0, 400),
    };
  });
}

export function fallbackNarrative(domain: string | null, themes: FollowUpTheme[], checks: FollowUpCheckResult[]): string {
  const where = domain ?? "this workspace";
  const themeLine = themes.length > 0
    ? `Consolidated ${themes.length} issue group(s) for ${where}.`
    : `No security findings were available to consolidate for ${where}.`;
  const checkLine = checks.length > 0
    ? checks.map((check) => `${check.label}: ${check.summary}`).join(" ")
    : "No follow-up checks were run.";
  return `${themeLine} ${checkLine}`.slice(0, 2000);
}

function extractObject(raw: string): Record<string, unknown> | null {
  const start = raw.indexOf("{");
  if (start < 0) return null;
  let depth = 0;
  for (let i = start; i < raw.length; i++) {
    if (raw[i] === "{") depth++;
    else if (raw[i] === "}") {
      depth--;
      if (depth === 0) {
        try {
          const parsed = JSON.parse(raw.slice(start, i + 1)) as unknown;
          return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null;
        } catch {
          return null;
        }
      }
    }
  }
  return null;
}

function asThemes(value: unknown, allowedIds: Set<string>): FollowUpTheme[] {
  if (!Array.isArray(value)) return [];
  const themes: FollowUpTheme[] = [];
  for (const item of value.slice(0, 8)) {
    if (!item || typeof item !== "object") continue;
    const row = item as Record<string, unknown>;
    const title = String(row.title ?? "").trim().slice(0, 160);
    const narrative = String(row.narrative ?? "").trim().slice(0, 800);
    if (!title || !narrative) continue;
    const severity = String(row.severity ?? "medium");
    const findingIds = Array.isArray(row.findingIds)
      ? row.findingIds.map((id) => String(id)).filter((id) => allowedIds.has(id)).slice(0, 20)
      : [];
    themes.push({
      title,
      severity: SEVERITIES.includes(severity as (typeof SEVERITIES)[number]) ? severity : "medium",
      findingIds,
      narrative,
      action: String(row.action ?? "").trim().slice(0, 400),
    });
  }
  return themes;
}

function asStringList(value: unknown, max: number): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((item) => String(item).trim()).filter((item) => item.length > 0).slice(0, max).map((item) => item.slice(0, 300));
}

function findingBrief(findings: FollowUpFinding[]): string {
  return findings.slice(0, 25).map((finding) => {
    const description = (finding.description ?? "").replace(/\s+/g, " ").slice(0, 180);
    return `- [${finding.id}] ${finding.title} | ${finding.severity} | ${finding.category} | ${finding.affectedAsset ?? ""} | ${description}`;
  }).join("\n");
}

function withTimeout<T>(work: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} timed out`)), ms);
    work.then(
      (value) => { clearTimeout(timer); resolve(value); },
      (err) => { clearTimeout(timer); reject(err); },
    );
  });
}

/**
 * Uses the same hardened public-resolver config as `scanner/dns.ts`
 * (`recordResolver`, 1.1.1.1 + 8.8.8.8), not the OS default — the local
 * resolver returns ETIMEOUT/ESERVFAIL for names public resolvers answer
 * fine, which is exactly the flaky-resolver bug that module was written to
 * fix. Using `node:dns`'s default here would reintroduce it for every
 * SPF/DMARC check this report runs.
 */
async function lookupTxt(name: string): Promise<string[][] | null> {
  try {
    return await recordResolver.resolveTxt(name);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    // ENODATA / ENOTFOUND means the name answered and has no TXT. A timeout
    // or a refused query is a different fact and must stay "did not answer".
    if (code === "ENODATA" || code === "ENOTFOUND" || code === "NXDOMAIN") return [];
    return null;
  }
}

/** An apex with no TXT and no address did not resolve; "no SPF" would be a guess. */
async function domainResolves(domain: string): Promise<boolean> {
  const ask = async (kind: "resolve4" | "resolve6") => {
    try {
      await recordResolver[kind](domain);
      return true;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      return code !== "ENOTFOUND" && code !== "ENODATA" && code !== "NXDOMAIN";
    }
  };
  const v4 = await ask("resolve4");
  if (v4) return true;
  return ask("resolve6");
}

/**
 * `httpGetNoRedirect` (not a bare `fetch`) so this joins every other outbound
 * scanner request on the deployment-wide `SCANNER_MAX_OUTBOUND` socket
 * semaphore and sends the coherent browser-profile header set CLAUDE.md
 * requires for third-party calls — a bare `fetch` here was invisible to both,
 * letting AI-insights/AI-enriched-scan traffic silently escape the socket
 * ceiling the deployment relies on to bound total outbound connections.
 */
async function readPublicHeaders(host: string): Promise<{ status: number; missing: string[]; present: string[] } | { refused: string }> {
  const url = `https://${host}/`;
  if (!(await isSafeOutboundUrl(url))) return { refused: "the host does not resolve to a public address" };
  const res = await httpGetNoRedirect(url, 8000);
  if (!res) return { refused: "the host did not answer" };
  const headerNames = new Set(Object.keys(res.headers).map((k) => k.toLowerCase()));
  const present = HEADER_NAMES.filter((name) => headerNames.has(name));
  const missing = HEADER_NAMES.filter((name) => !headerNames.has(name));
  return { status: res.status, missing, present };
}

export async function runOneCheck(id: FollowUpCheckId, ctx: CheckContext): Promise<FollowUpCheckResult> {
  const label = CHECK_LABEL[id];
  if (!isUsableDomain(ctx.domain) || ctx.hosts.length === 0) {
    return { id, label, status: "skipped", summary: "No usable workspace domain, so this check was not run." };
  }
  try {
    if (id === "http_fingerprint") {
      const probes = await withTimeout(
        probeHosts(ctx.hosts, { concurrency: 3, allowExternalEngine: true }),
        CHECK_TIMEOUT_MS,
        label,
      );
      if (probes.length === 0) {
        return { id, label, status: "completed", summary: `None of ${ctx.hosts.length} host(s) answered.` };
      }
      const lines = probes.slice(0, 5).map((probe) => {
        const bits = [`${probe.host} ${probe.scheme} ${probe.status}`];
        if (probe.server) bits.push(probe.server);
        if (probe.title) bits.push(probe.title.slice(0, 80));
        if (probe.cleartextWithoutUpgrade) bits.push("cleartext without upgrade");
        return bits.join(" · ");
      });
      return { id, label, status: "completed", summary: lines.join("; ").slice(0, 700) };
    }

    if (id === "security_headers") {
      const lines: string[] = [];
      for (const host of ctx.hosts.slice(0, 3)) {
        const read = await readPublicHeaders(host);
        if ("refused" in read) {
          lines.push(`${host}: not checked (${read.refused})`);
          continue;
        }
        lines.push(
          read.missing.length === 0
            ? `${host}: HTTP ${read.status}, all tracked headers present`
            : `${host}: HTTP ${read.status}, missing ${read.missing.join(", ")}`,
        );
      }
      return { id, label, status: "completed", summary: lines.join("; ").slice(0, 700) };
    }

    if (id === "dnssec") {
      const status = await withTimeout(checkDnssec(ctx.domain), CHECK_TIMEOUT_MS, label);
      return { id, label, status: "completed", summary: `${status.state}. ${status.detail}`.slice(0, 500) };
    }

    if (id === "tls_versions") {
      const report = await withTimeout(enumerateTlsVersions(ctx.domain), CHECK_TIMEOUT_MS, label);
      if (report.unreachable) {
        return { id, label, status: "unavailable", summary: "TLS versions could not be determined; the host did not complete a handshake." };
      }
      const obsolete = report.obsoleteAccepted.length > 0
        ? `accepts obsolete ${report.obsoleteAccepted.join(", ")}`
        : "does not accept TLS 1.0 or 1.1";
      const modern = report.modernAccepted.length > 0 ? `; modern: ${report.modernAccepted.join(", ")}` : "";
      return { id, label, status: "completed", summary: `${ctx.domain} ${obsolete}${modern}`.slice(0, 500) };
    }

    const txt = await lookupTxt(ctx.domain);
    const dmarcTxt = await lookupTxt(`_dmarc.${ctx.domain}`);
    if (txt === null || dmarcTxt === null) {
      return { id, label, status: "unavailable", summary: "DNS TXT lookups did not complete, so SPF and DMARC were not assessed." };
    }
    if (txt.length === 0 && !(await domainResolves(ctx.domain))) {
      return { id, label, status: "unavailable", summary: "The domain did not resolve, so SPF and DMARC were not assessed." };
    }
    const lookup: TxtLookup = async (name) => (await lookupTxt(name)) ?? [];
    const spf = await analyzeSpfDeep(ctx.domain, txt, lookup);
    const dmarc = await analyzeDmarcDeep(ctx.domain, dmarcTxt, lookup);
    const spfLine = spf.found ? (spf.issues[0] ?? "SPF record present") : "No SPF record";
    const dmarcLine = dmarc.found ? (dmarc.issues[0] ?? "DMARC record present") : "No DMARC record";
    return { id, label, status: "completed", summary: `${spfLine}. ${dmarcLine}.`.slice(0, 700) };
  } catch (err) {
    const message = err instanceof Error ? err.message : "check failed";
    log.warn({ check: id, err: message }, "follow-up check failed");
    return { id, label, status: "unavailable", summary: "This check did not complete." };
  }
}

/**
 * Live checks, chosen deterministically from finding categories, with no GLM
 * planning call — the caller (AI Insights, an AI-enriched scan) is already
 * about to make its own GLM synthesis call, and a second call just to pick
 * checks would double the round trips for no benefit over the category map.
 *
 * This is the single implementation of "what can we actually verify live"
 * shared across the AI Follow-up report, AI Insights and AI-enriched scans —
 * one set of checks, one scope guard (`hostsForFollowUp`), one place to add a
 * new check.
 */
export async function runVerificationChecks(
  domain: string,
  findings: FollowUpFinding[],
  runCheck: (id: FollowUpCheckId, ctx: CheckContext) => Promise<FollowUpCheckResult> = runOneCheck,
): Promise<FollowUpCheckResult[]> {
  const normalized = domain.trim().toLowerCase();
  const usable = isUsableDomain(normalized) ? normalized : null;
  if (!usable) return [];
  const hosts = hostsForFollowUp(usable, findings.map((finding) => finding.affectedAsset));
  const categories = Array.from(new Set(findings.map((finding) => finding.category)));
  const selected = chooseFollowUpChecks(categories, []);
  const ctx: CheckContext = { domain: usable, hosts };
  const results: FollowUpCheckResult[] = [];
  for (const id of selected) {
    results.push(await runCheck(id, ctx));
  }
  return results;
}

export async function buildAiFollowUpReport(input: {
  workspaceName: string;
  domain: string;
  findings: FollowUpFinding[];
  model?: string;
  complete?: (prompt: string) => Promise<string>;
  runCheck?: (id: FollowUpCheckId, ctx: CheckContext) => Promise<FollowUpCheckResult>;
}): Promise<AiFollowUpSegment> {
  const domain = input.domain.trim().toLowerCase();
  const usable = isUsableDomain(domain) ? domain : null;
  const hosts = usable ? hostsForFollowUp(usable, input.findings.map((finding) => finding.affectedAsset)) : [];
  const allowedIds = new Set(input.findings.map((finding) => finding.id));
  const categories = Array.from(new Set(input.findings.map((finding) => finding.category)));
  const complete = input.complete ?? ((prompt: string) => completeAi(prompt));
  const runCheck = input.runCheck ?? runOneCheck;

  let generatedBy: "glm" | "rules" = "rules";
  let themes = themesFromFindings(input.findings);
  let requested: string[] = [];

  const planPrompt = `You are writing a follow-up for workspace "${input.workspaceName.slice(0, 120)}" (${usable ?? "no domain configured"}).

Consolidate these security findings into at most 6 themes. A theme groups findings that are the same kind of problem. Then choose follow-up checks ONLY from this list:
${FOLLOW_UP_CHECK_IDS.map((id) => `- ${id}: ${CHECK_LABEL[id]}`).join("\n")}

FINDINGS:
${findingBrief(input.findings) || "(none)"}

Respond with JSON only:
{
  "themes": [{ "title": "", "severity": "critical|high|medium|low|info", "findingIds": [], "narrative": "", "action": "" }],
  "checks": ["http_fingerprint"]
}
Use finding ids from the list. Do not invent hosts, urls, or checks outside the list.`;

  try {
    const planned = extractObject(await complete(planPrompt));
    const parsedThemes = asThemes(planned?.themes, allowedIds);
    // `generatedBy` is what the UI shows as "Written by GLM" vs "Rule-based" —
    // it must track whether GLM's THEMES were actually usable, not merely
    // whether it returned parseable JSON. GLM can return valid JSON whose
    // themes all fail validation (missing title/narrative, e.g.), in which
    // case `themes` stays the `themesFromFindings` fallback — reporting that
    // as "Written by GLM" would be labelling rule-based content as AI output.
    if (parsedThemes.length > 0) {
      themes = parsedThemes;
      generatedBy = "glm";
    }
    if (Array.isArray(planned?.checks)) requested = planned.checks.map((id) => String(id));
  } catch (err) {
    log.warn({ err: err instanceof Error ? err.message : "plan failed" }, "follow-up plan used category defaults");
  }

  const selected = chooseFollowUpChecks(categories, requested);
  const ctx: CheckContext = { domain: usable ?? "", hosts };
  const checks: FollowUpCheckResult[] = [];
  for (const id of selected) {
    checks.push(await runCheck(id, ctx));
  }

  let narrative = fallbackNarrative(usable, themes, checks);
  let nextSteps = themes.map((theme) => theme.action).filter((action) => action.length > 0).slice(0, 6);
  if (generatedBy === "glm") {
    const writePrompt = `Write the consolidated follow-up report for ${usable ?? input.workspaceName}.

THEMES:
${themes.map((theme) => `- ${theme.title} (${theme.severity}): ${theme.narrative} Action: ${theme.action || "see the finding"}`).join("\n")}

FOLLOW-UP CHECKS (these already ran; do not claim anything they do not say):
${checks.map((check) => `- ${check.label} [${check.status}]: ${check.summary}`).join("\n")}

Respond with JSON only:
{ "narrative": "3-6 sentences covering the consolidated issues and what the follow-up checks showed", "nextSteps": ["short action"] }
If a check is unavailable or skipped, say so. Do not add findings the checks did not return.`;
    try {
      const written = extractObject(await complete(writePrompt));
      const text = String(written?.narrative ?? "").trim().slice(0, 2000);
      const steps = asStringList(written?.nextSteps, 6);
      if (text) narrative = text;
      if (steps.length > 0) nextSteps = steps;
    } catch (err) {
      log.warn({ err: err instanceof Error ? err.message : "narrative failed" }, "follow-up narrative used the rule-based text");
    }
  }

  return {
    generatedBy,
    model: input.model,
    domain: usable,
    consolidatedAt: new Date().toISOString(),
    themes,
    checks,
    narrative,
    nextSteps,
  };
}
