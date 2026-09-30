/**
 * AI service for finding enrichment, report generation, and scan consolidation.
 * Calls Zhipu GLM (OpenAI-compatible chat completions). The free model is
 * glm-4.5-flash. The API key stays in GLM_API_KEY on the server.
 */

import type { Finding } from "@shared/schema";
import type { ReconModule } from "@shared/schema";
import { getCVEForFinding, type CVERecord } from "./cve-service";
import { createLogger } from "./logger";
import type { FollowUpCheckResult } from "./ai-follow-up.js";

const log = createLogger("ai");

/** Chat calls return in seconds. This bounds a stuck request. */
export const AI_REQUEST_TIMEOUT_MS = 120_000;

const GLM_DEFAULT_BASE = "https://open.bigmodel.cn/api/paas/v4";
const GLM_DEFAULT_MODEL = "glm-4.5-flash";
const GLM_RETRY_DELAYS_MS = [3000, 8000];

export { getOllamaConfig, setOllamaConfig } from "./api-integrations";

export interface GlmConfig {
  apiKey: string;
  baseUrl: string;
  model: string;
  enabled: boolean;
}

/** Server-side GLM settings. Enabled only when a key is present. */
export function getGlmConfig(): GlmConfig {
  const apiKey = process.env.GLM_API_KEY?.trim() ?? "";
  const baseUrl = (process.env.GLM_BASE_URL?.trim() || GLM_DEFAULT_BASE).replace(/\/$/, "");
  const model = process.env.GLM_MODEL?.trim() || GLM_DEFAULT_MODEL;
  return { apiKey, baseUrl, model, enabled: apiKey.length > 0 };
}

interface GlmMessage {
  content?: string;
  reasoning_content?: string;
}

interface GlmChoice {
  finish_reason?: string;
  message?: GlmMessage;
}

let statusCache: { at: number; value: { reachable: boolean; modelLoaded?: boolean; provider: string; model?: string } } | null = null;

/**
 * One short completion, cached for a minute so the integrations page does not
 * spend a request every time it polls.
 */
export async function getOllamaStatus(): Promise<{ reachable: boolean; modelLoaded?: boolean; provider: string; model?: string }> {
  const cfg = getGlmConfig();
  if (!cfg.enabled) return { reachable: false, provider: "glm", model: cfg.model };
  if (statusCache && Date.now() - statusCache.at < 60_000) return statusCache.value;
  try {
    const text = await callGlm("Reply with the single word ok.", undefined, { maxTokens: 32, timeoutMs: 30_000 });
    const value = { reachable: text.trim().length > 0, modelLoaded: true, provider: "glm", model: cfg.model };
    if (value.reachable) statusCache = { at: Date.now(), value };
    return value;
  } catch (err) {
    log.warn({ err: err instanceof Error ? err.message : "request failed", model: cfg.model }, "GLM status check failed");
    return { reachable: false, provider: "glm", model: cfg.model };
  }
}

function redactSecret(text: string, secret: string): string {
  if (!secret) return text;
  return text.split(secret).join("[redacted]");
}

/**
 * The actual HTTP round trip, shared by `callGlm` (single prompt+system) and
 * `callGlmChat` (a full multi-turn conversation) — one retry/timeout/error
 * implementation rather than two copies that could drift.
 */
async function postGlmMessages(
  messages: Array<{ role: string; content: string }>,
  options?: { maxTokens?: number; timeoutMs?: number },
): Promise<string> {
  const cfg = getGlmConfig();
  if (!cfg.enabled) throw new Error("GLM is not configured. Set GLM_API_KEY on the server.");
  const url = `${cfg.baseUrl}/chat/completions`;
  const bodyStr = JSON.stringify({
    model: cfg.model,
    messages,
    temperature: 0.2,
    max_tokens: options?.maxTokens ?? 4096,
    // This model spends the token budget on reasoning unless thinking is off,
    // and the visible answer then comes back empty.
    thinking: { type: "disabled" },
  });

  let lastErr: Error | null = null;
  for (let attempt = 1; attempt <= GLM_RETRY_DELAYS_MS.length + 1; attempt++) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), options?.timeoutMs ?? AI_REQUEST_TIMEOUT_MS);
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${cfg.apiKey}`,
        },
        body: bodyStr,
        signal: ctrl.signal,
      });
      clearTimeout(t);
      const raw = await res.text();
      const safe = redactSecret(raw, cfg.apiKey);
      if (!res.ok) {
        const retryable = res.status === 429 || res.status === 503;
        if (retryable && attempt <= GLM_RETRY_DELAYS_MS.length) {
          const delay = GLM_RETRY_DELAYS_MS[attempt - 1] ?? 3000;
          log.warn({ status: res.status, attempt, delayMs: delay, model: cfg.model }, "GLM busy, retrying");
          await new Promise((r) => setTimeout(r, delay));
          continue;
        }
        throw new Error(`GLM error ${res.status}: ${safe.slice(0, 180)}`);
      }
      const json = JSON.parse(safe) as { choices?: GlmChoice[] };
      const message = json.choices?.[0]?.message;
      const content = (message?.content ?? "").trim();
      if (content) return content;
      const reasoning = (message?.reasoning_content ?? "").trim();
      if (reasoning) return reasoning;
      throw new Error("GLM returned an empty completion.");
    } catch (err) {
      clearTimeout(t);
      lastErr = err instanceof Error ? err : new Error(String(err));
      if (lastErr.name === "AbortError" || lastErr.message.includes("aborted")) {
        throw new Error("GLM request timed out. The model did not answer in time.");
      }
      if (lastErr.message.startsWith("GLM error") || lastErr.message.startsWith("GLM returned")) throw lastErr;
      const retryable = lastErr.message.includes("fetch failed") || lastErr.message.includes("ECONNRESET");
      if (retryable && attempt <= GLM_RETRY_DELAYS_MS.length) {
        const delay = GLM_RETRY_DELAYS_MS[attempt - 1] ?? 3000;
        log.warn({ attempt, delayMs: delay, model: cfg.model }, "GLM connection error, retrying");
        await new Promise((r) => setTimeout(r, delay));
        continue;
      }
      throw new Error("Cannot reach the GLM API. Check GLM_BASE_URL and network access.");
    }
  }
  throw lastErr ?? new Error("GLM request failed.");
}

async function callGlm(
  prompt: string,
  system?: string,
  options?: { format?: "json"; maxTokens?: number; timeoutMs?: number },
): Promise<string> {
  const messages: Array<{ role: string; content: string }> = [];
  const systemParts = [system, options?.format === "json" ? "Respond with one JSON object and no markdown." : ""]
    .filter((part): part is string => !!part && part.trim().length > 0);
  if (systemParts.length > 0) messages.push({ role: "system", content: systemParts.join("\n\n") });
  messages.push({ role: "user", content: prompt });
  return postGlmMessages(messages, { maxTokens: options?.maxTokens, timeoutMs: options?.timeoutMs });
}

async function callOllama(prompt: string, system?: string, options?: { format?: "json" }): Promise<string> {
  return callGlm(prompt, system, options);
}

/** JSON completion used by the follow-up report. Throws when GLM is not configured or does not answer. */
export async function completeAi(prompt: string, system?: string): Promise<string> {
  return callGlm(prompt, system, { format: "json" });
}

export interface ChatTurn {
  role: "user" | "assistant";
  content: string;
}

/**
 * Multi-turn chat completion for the in-app assistant. Unlike `callGlm`
 * (one prompt + optional system string), this carries the whole conversation
 * so far, because the assistant has to remember earlier turns within a chat
 * session. The system prompt — including all grounding and untrusted-data
 * framing — is entirely the caller's responsibility; this function adds none
 * of its own.
 */
export async function callGlmChat(
  system: string,
  turns: ChatTurn[],
  options?: { maxTokens?: number; timeoutMs?: number },
): Promise<string> {
  const messages: Array<{ role: string; content: string }> = [{ role: "system", content: system }];
  for (const turn of turns) messages.push({ role: turn.role, content: turn.content });
  return postGlmMessages(messages, options);
}

export function sanitize(text: string): string {
  return (text ?? "")
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, "")
    .slice(0, 8000);
}

/** Extract JSON from Ollama response (handles markdown code blocks, trailing text). */
function extractJSON<T>(raw: string): T | null {
  const trimmed = raw.trim();
  const jsonBlock = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/);
  const candidate = jsonBlock ? jsonBlock[1].trim() : trimmed;
  const start = candidate.indexOf("{");
  if (start < 0) return null;
  let depth = 0;
  let end = -1;
  for (let i = start; i < candidate.length; i++) {
    if (candidate[i] === "{") depth++;
    else if (candidate[i] === "}") {
      depth--;
      if (depth === 0) {
        end = i + 1;
        break;
      }
    }
  }
  const jsonStr = end > 0 ? candidate.slice(start, end) : candidate.slice(start);
  try {
    return JSON.parse(jsonStr) as T;
  } catch {
    return null;
  }
}

export function buildFindingContext(f: Finding): string {
  const desc = (f.description ?? "").trim().slice(0, 150);
  const evidence = (f.evidence ?? [])
    .map((e: Record<string, unknown>) => (e.snippet as string) ?? (e.description as string))
    .filter(Boolean)
    .join(" ")
    .slice(0, 100);
  const cveData = f.aiEnrichment as { cveData?: { cveIds?: string[]; records?: Array<{ cveId: string }> } } | null | undefined;
  const cveIds = cveData?.cveData?.records?.map((r) => r.cveId) ?? cveData?.cveData?.cveIds ?? [];
  const cveStr = cveIds.length > 0 ? ` CVEs: ${cveIds.join(", ")}` : "";
  return `- ${f.title} (${f.severity}, ${f.category})${cveStr}\n  ${desc}${evidence ? ` | Evidence: ${evidence}` : ""}\n  Asset: ${(f.affectedAsset ?? "N/A").slice(0, 80)}`;
}

export function buildReconContext(reconModules: ReconModule[]): string {
  const lines: string[] = [];
  const byType = reconModules.reduce((acc, m) => {
    if (!(m.moduleType in acc)) acc[m.moduleType] = m;
    return acc;
  }, {} as Record<string, ReconModule>);

  const attackSurface = byType.attack_surface?.data as Record<string, unknown> | undefined;
  if (attackSurface) {
    const score = attackSurface.surfaceRiskScore;
    const tls = (attackSurface.tlsPosture as Record<string, unknown> | undefined)?.grade;
    const headers = Array.isArray(attackSurface.securityHeaders)
      ? (attackSurface.securityHeaders[0] as Record<string, unknown>)?.grade
      : undefined;
    const leaks = (attackSurface.serverInfo as Record<string, unknown> | undefined)?.leaks;
    const ips = (attackSurface.publicIPs as unknown[])?.length ?? 0;
    lines.push(`Attack surface: risk=${score ?? "N/A"}, TLS=${tls ?? "N/A"}, headers=${headers ?? "N/A"}, leaks=${leaks ? "yes" : "no"}, publicIPs=${ips}`);
  }

  const techStack = byType.tech_stack?.data as Record<string, unknown> | undefined;
  if (techStack) {
    const frontend = (techStack.frontend as Array<{ name?: string }>) ?? [];
    const backend = (techStack.backend as Array<{ name?: string }>) ?? [];
    const techs = [...frontend, ...backend].map((t) => t?.name).filter(Boolean).join(", ");
    if (techs) lines.push(`Tech stack: ${techs}`);
  }

  const cloud = byType.cloud_footprint?.data as Record<string, unknown> | undefined;
  if (cloud) {
    const email = cloud.emailSecurity as Record<string, unknown> | undefined;
    const spf = email?.spf && typeof email.spf === "object" ? (email.spf as Record<string, unknown>)?.status : undefined;
    const dmarc = email?.dmarc && typeof email.dmarc === "object" ? (email.dmarc as Record<string, unknown>)?.status : undefined;
    lines.push(`Cloud/email: SPF=${spf ?? "N/A"}, DMARC=${dmarc ?? "N/A"}`);
  }

  const webPresence = byType.web_presence?.data as Record<string, unknown> | undefined;
  if (webPresence) {
    const live = (webPresence.liveSubdomains as unknown[])?.length ?? 0;
    const dangling = (webPresence.danglingCnames as unknown[])?.length ?? 0;
    lines.push(`Web presence: ${live} live subdomains, ${dangling} dangling CNAMEs`);
  }

  /*
   * Everything below was added so "AI Insights" synthesizes the WHOLE
   * Intelligence page, not four of its eighteen tabs. Each line summarizes
   * one module's real top-level fields (checked against the shapes actually
   * stored in `recon_modules.data` for a live workspace, not guessed) —
   * the same one-line-per-module discipline as the four above. A module
   * absent from this workspace's scan simply contributes no line, which is
   * correct: it was never run, not run-and-clean.
   */
  const dnsOverview = byType.dns_overview?.data as Record<string, unknown> | undefined;
  if (dnsOverview) {
    const dnssecState = (dnsOverview.dnssec as Record<string, unknown> | undefined)?.state ?? "unknown";
    const zoneTransfer = dnsOverview.zoneTransfer as Array<{ transferred?: boolean }> | undefined;
    const axfrVulnerable = zoneTransfer?.some((z) => z.transferred) ?? false;
    lines.push(`DNS: DNSSEC ${dnssecState}, zone transfer ${axfrVulnerable ? "ALLOWED (vulnerable)" : "refused"}`);
  }

  const domainInfo = byType.domain_info?.data as Record<string, unknown> | undefined;
  if (domainInfo?.domainInfo) {
    // Raw WHOIS field names (title-case with spaces), not camelCase — this
    // module stores the registry's own field labels verbatim.
    const info = domainInfo.domainInfo as Record<string, unknown>;
    lines.push(`Domain registration: registrar=${info["Registrar"] ?? "N/A"}, created=${info["Creation Date"] ?? "N/A"}`);
  }

  const websiteOverview = byType.website_overview?.data as Record<string, unknown> | undefined;
  if (websiteOverview) {
    const ports = (websiteOverview.openPorts as unknown[])?.length ?? 0;
    const techs = ((websiteOverview.techStack as Array<{ name?: string }> | undefined) ?? []).map((t) => t?.name).filter(Boolean).slice(0, 8).join(", ");
    lines.push(`Website overview: ${ports} open port(s)${techs ? `, tech: ${techs}` : ""}`);
  }

  const exposedContent = byType.exposed_content?.data as Record<string, unknown> | undefined;
  if (exposedContent) {
    const files = (exposedContent.publicFiles as unknown[])?.length ?? 0;
    const dirs = (exposedContent.directoryBruteforce as unknown[])?.length ?? 0;
    lines.push(`Exposed content: ${files} public file(s), ${dirs} directory hit(s)`);
  }

  const apiDiscovery = byType.api_discovery?.data as Record<string, unknown> | undefined;
  if (apiDiscovery) {
    lines.push(`API discovery: ${apiDiscovery.endpointCount ?? 0} endpoint(s) found${apiDiscovery.openApiSpec ? " (OpenAPI spec exposed)" : ""}`);
  }

  const nuclei = byType.nuclei?.data as Record<string, unknown> | undefined;
  if (nuclei) {
    lines.push(
      nuclei.skipped
        ? `Nuclei: skipped (${nuclei.skipReason ?? "not available"})`
        : `Nuclei: ${(nuclei.hits as unknown[])?.length ?? 0} hit(s) from ${nuclei.templateCount ?? 0} template(s)`,
    );
  }

  const dastLite = byType.dast_lite?.data as Record<string, unknown> | undefined;
  if (dastLite) {
    lines.push(`DAST: ${dastLite.testsPassed ?? 0}/${dastLite.testsRun ?? 0} tests passed, ${(dastLite.findings as unknown[])?.length ?? 0} finding(s)`);
  }

  const takeover = byType.subdomain_takeover?.data as Record<string, unknown> | undefined;
  if (takeover) {
    lines.push(`Subdomain takeover: ${takeover.vulnerableCount ?? 0} of ${takeover.checkedCount ?? 0} checked host(s) takeoverable`);
  }

  const bgp = byType.bgp_routing?.data as Record<string, unknown> | undefined;
  if (bgp?.ips) {
    lines.push(`BGP/IP reputation: ${Object.keys(bgp.ips as Record<string, unknown>).length} IP(s) profiled`);
  }

  const routedFootprint = byType.routed_footprint?.data as Record<string, unknown> | undefined;
  if (routedFootprint) {
    lines.push(`Routed footprint: ${routedFootprint.ownedAsnCount ?? 0} owned ASN(s), ~${routedFootprint.ownedAddressCount ?? 0} addresses`);
  }

  const redirectChain = byType.redirect_chain?.data as Record<string, unknown> | undefined;
  if (redirectChain) {
    lines.push(`Redirect chain: ${(redirectChain.redirectChain as unknown[])?.length ?? 0} hop(s)`);
  }

  const peopleExposure = byType.people_exposure?.data as Record<string, unknown> | undefined;
  if (peopleExposure) {
    lines.push(`People exposure: ${peopleExposure.observedCount ?? (peopleExposure.people as unknown[])?.length ?? 0} person/people found`);
  }

  const brandThreats = byType.brand_threats?.data as Record<string, unknown> | undefined;
  if (brandThreats) {
    const counts = brandThreats.counts as Record<string, number> | undefined;
    lines.push(`Brand threats: ${(brandThreats.registered as unknown[])?.length ?? 0} lookalike domain(s) registered (${counts?.high ?? 0} high-risk)`);
  }

  const ransomwareExposure = byType.ransomware_exposure?.data as Record<string, unknown> | undefined;
  if (ransomwareExposure) {
    const counts = ransomwareExposure.counts as Record<string, number> | undefined;
    lines.push(
      ransomwareExposure.error
        ? `Ransomware leak-site check: could not complete (${ransomwareExposure.error})`
        : `Ransomware leak-site exposure: ${counts?.confirmed ?? 0} confirmed, ${counts?.possible ?? 0} possible match(es) out of ${ransomwareExposure.recordsChecked ?? 0} records checked`,
    );
  }

  const mobileApps = byType.mobile_apps?.data as Record<string, unknown> | undefined;
  if (mobileApps) {
    lines.push(
      `Mobile app monitoring: ${(mobileApps.official as unknown[])?.length ?? 0} official app(s), ${(mobileApps.thirdParty as unknown[])?.length ?? 0} third-party app(s) using the brand`,
    );
  }

  const breachExposure = byType.breach_exposure?.data as Record<string, unknown> | undefined;
  if (breachExposure) {
    lines.push(
      breachExposure.unavailable
        ? `Breach corpus check: could not complete (${breachExposure.unavailableReason ?? "unavailable"})`
        : `Breach corpus: ${(breachExposure.confirmed as unknown[])?.length ?? 0} confirmed, ${(breachExposure.unverified as unknown[])?.length ?? 0} unverified record(s) naming this domain`,
    );
  }

  const codeLeak = byType.code_leak?.data as Record<string, unknown> | undefined;
  if (codeLeak) {
    const counts = codeLeak.counts as Record<string, number> | undefined;
    lines.push(
      codeLeak.error
        ? `Code leak sweep: could not complete (${codeLeak.error})`
        : `Public code leak sweep: ${counts?.withSecrets ?? 0} file(s) with a matched secret, ${counts?.mentionsOnly ?? 0} mention-only`,
    );
  }

  const discoveryHealth = byType.discovery_health?.data as Record<string, unknown> | undefined;
  if (discoveryHealth) {
    const failed = (discoveryHealth.sourcesFailed as unknown[])?.length ?? 0;
    lines.push(`Discovery: ${discoveryHealth.totalHosts ?? 0} host(s) found across all sources${failed > 0 ? `, ${failed} source(s) failed` : ""}`);
  }

  const verificationSummary = byType.verification_summary?.data as Record<string, unknown> | undefined;
  if (verificationSummary) {
    lines.push(`Verification: ${verificationSummary.confirmedCount ?? 0} confirmed, ${verificationSummary.withheldCount ?? 0} withheld as unconfirmed`);
  }

  if (lines.length === 0) return reconModules.map((m) => m.moduleType).join(", ");
  return lines.join("\n");
}

export async function fetchCVEContextForInsights(
  findings: Finding[],
  reconModules: ReconModule[],
  maxFindings = 5
): Promise<CVERecord[]> {
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const hasCVE = (f: Finding) => {
    const ae = f.aiEnrichment as { cveData?: { records?: unknown[] } } | null | undefined;
    return (ae?.cveData?.records?.length ?? 0) > 0;
  };
  const toFetch = findings
    .filter((f) => !hasCVE(f))
    .sort((a, b) => (severityOrder[a.severity as keyof typeof severityOrder] ?? 5) - (severityOrder[b.severity as keyof typeof severityOrder] ?? 5))
    .slice(0, maxFindings);
  const allCve: CVERecord[] = [];
  const seen = new Set<string>();
  for (const f of toFetch) {
    try {
      const records = await getCVEForFinding(f, reconModules);
      for (const r of records) {
        if (!seen.has(r.cveId)) {
          seen.add(r.cveId);
          allCve.push(r);
        }
      }
    } catch {
      // skip failed
    }
  }
  return allCve.slice(0, 15);
}

export interface EnrichmentResult {
  enhancedDescription: string;
  contextualRisks?: string;
  additionalRemediation?: string;
}

export async function enrichFinding(
  finding: Finding,
  _context?: ReconModule[]
): Promise<EnrichmentResult> {
  const evidenceSnippets = (finding.evidence ?? [])
    .map((e: Record<string, unknown>) => (e.snippet as string) ?? (e.description as string))
    .filter(Boolean)
    .join("\n---\n");
  const prompt = `You are a cybersecurity analyst. Enrich this finding with clearer, actionable context.

FINDING:
Title: ${sanitize(finding.title)}
Description: ${sanitize(finding.description)}
Severity: ${finding.severity}
Category: ${finding.category}
Affected Asset: ${sanitize(finding.affectedAsset ?? "N/A")}
Remediation: ${sanitize(finding.remediation ?? "N/A")}
${evidenceSnippets ? `Evidence snippets:\n${sanitize(evidenceSnippets)}` : ""}

Respond in JSON only, no markdown, with exactly these keys:
- "enhancedDescription": string (clearer, more actionable description)
- "contextualRisks": string (brief context on why this matters)
- "additionalRemediation": string (extra remediation steps if any)`;

  const system = "Output valid JSON only. No other text.";
  const raw = await callOllama(prompt, system, { format: "json" });
  try {
    const parsed = extractJSON<EnrichmentResult>(raw) ?? (() => {
      try {
        return JSON.parse(raw) as EnrichmentResult;
      } catch {
        return null;
      }
    })();
    if (!parsed) throw new Error("No parsed result");
    return {
      enhancedDescription: String(parsed.enhancedDescription ?? finding.description).slice(0, 4000),
      contextualRisks: parsed.contextualRisks ? String(parsed.contextualRisks).slice(0, 1000) : undefined,
      additionalRemediation: parsed.additionalRemediation ? String(parsed.additionalRemediation).slice(0, 1000) : undefined,
    };
  } catch {
    return {
      enhancedDescription: raw.slice(0, 4000) || finding.description,
    };
  }
}

export type ReportContent = Record<string, unknown>;

export async function generateReportSummary(
  findings: Finding[],
  content: ReportContent
): Promise<string> {
  const crit = (content.criticalCount as number) ?? 0;
  const high = (content.highCount as number) ?? 0;
  const total = (content.totalFindings as number) ?? findings.length;
  const findingTitles = findings.slice(0, 20).map((f) => `- ${f.title} (${f.severity})`).join("\n");
  const prompt = `You are a cybersecurity report writer. Write a concise executive summary (2-4 sentences) for this security assessment report.

REPORT OVERVIEW:
- Total findings: ${total}
- Critical: ${crit}, High: ${high}
- Categories: ${(content.categories as string[] ?? []).join(", ")}

SAMPLE FINDINGS:
${findingTitles}

Write a professional executive summary that highlights key risks and recommends next steps. Be direct and actionable. Output only the summary text, no headers or labels.`;

  const raw = await callOllama(prompt);
  return raw.slice(0, 2000).trim() || `This report covers ${total} security findings.`;
}

export interface NewFinding {
  title: string;
  description: string;
  severity: string;
  category: string;
  affectedAsset?: string;
  remediation?: string;
}

export interface ConsolidateResult {
  newFindings: NewFinding[];
  mergedUpdates: Array<{ findingId: string; updates: Partial<Finding> }>;
}

export async function consolidateScanResults(
  uploadedText: string,
  existingFindings: Finding[],
  workspaceTarget: string
): Promise<ConsolidateResult> {
  const existingSummary = existingFindings
    .slice(0, 30)
    .map((f) => `[${f.id}] ${f.title} | ${f.affectedAsset ?? ""}`)
    .join("\n");
  const prompt = `You are a cybersecurity analyst. Consolidate uploaded scan results into findings.

TARGET: ${sanitize(workspaceTarget)}

EXISTING FINDINGS (id, title, asset):
${existingSummary || "(none)"}

UPLOADED SCAN OUTPUT:
${sanitize(uploadedText).slice(0, 12000)}

Analyze the uploaded scan. For NEW issues not covered by existing findings, output new findings. For issues that EXTEND or MATCH existing findings, output merged updates.

Respond in JSON only:
{
  "newFindings": [
    { "title": "...", "description": "...", "severity": "critical|high|medium|low|info", "category": "...", "affectedAsset": "...", "remediation": "..." }
  ],
  "mergedUpdates": [
    { "findingId": "<existing id>", "updates": { "description": "...", "evidence": [...] } }
  ]
}

Only include mergedUpdates for findings that truly match (same issue). Be conservative. Output valid JSON only.`;

  const system = "Output valid JSON only. No markdown, no extra text.";
  const raw = await callOllama(prompt, system);
  try {
    const parsed = JSON.parse(raw) as ConsolidateResult;
    const newFindings = Array.isArray(parsed.newFindings)
      ? parsed.newFindings.filter((f) => f && f.title && f.description)
      : [];
    const mergedUpdates = Array.isArray(parsed.mergedUpdates)
      ? parsed.mergedUpdates.filter((u) => u && u.findingId && u.updates)
      : [];
    return { newFindings, mergedUpdates };
  } catch {
    return { newFindings: [], mergedUpdates: [] };
  }
}

export interface WorkspaceInsightsResult {
  summary: string;
  keyRisks: string[];
  threatLandscape: string;
  /** true = AI-generated, false = fallback (rule-based, no LLM) */
  isAIGenerated?: boolean;
  /** When fallback: why AI was not used */
  fallbackReason?: "ollama_disabled" | "ollama_timeout" | "ollama_error";
  /** When fallback: actual error message for debugging (sanitized, max 500 chars) */
  fallbackErrorDetail?: string;
  /**
   * Live checks run against the workspace's own hosts before the model wrote
   * this summary — the same allowlisted probes the AI Follow-up report runs
   * (`runVerificationChecks` in ai-follow-up.ts). Absent when the workspace
   * has no usable domain, so the UI can tell "verified" from "nothing to
   * verify" rather than rendering an empty table as a clean result.
   */
  verification?: FollowUpCheckResult[];
}

function sanitizeErrorDetail(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err);
  return msg.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, "").slice(0, 500);
}

export function buildFallbackInsights(
  findings: Finding[],
  reconModules: ReconModule[],
  workspaceName: string
): WorkspaceInsightsResult {
  const crit = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  const safeWorkspaceName = (workspaceName ?? "").replace(/[\x00-\x1f]/g, "").slice(0, 200);
  const summary = `Workspace ${safeWorkspaceName} has ${findings.length} security findings (${crit} critical, ${high} high). ` +
    (reconModules.length > 0
      ? `Intelligence data includes ${reconModules.length} recon modules. `
      : "") +
    (crit > 0 || high > 0
      ? "Prioritize remediation of high and critical severity items."
      : "No critical or high severity findings at this time.");
  const keyRisks = findings
    .filter((f) => f.severity === "critical" || f.severity === "high")
    .slice(0, 6)
    .map((f) => `${f.title} (${f.severity})`);
  const threatLandscape = reconModules.length > 0
    ? `Recon modules: ${reconModules.map((m) => m.moduleType).join(", ")}. Run scans to gather tech stack and attack surface data.`
    : "Run scans to gather intelligence data.";
  return { summary, keyRisks, threatLandscape, isAIGenerated: false };
}

function collectCVEFromFindings(findings: Finding[]): CVERecord[] {
  const seen = new Set<string>();
  const out: CVERecord[] = [];
  for (const f of findings) {
    const ae = f.aiEnrichment as { cveData?: { records?: Array<{ cveId: string; description?: string; cvssScore?: number; url: string }> } } | null | undefined;
    const records = ae?.cveData?.records ?? [];
    for (const r of records) {
      if (!seen.has(r.cveId)) {
        seen.add(r.cveId);
        out.push({
          cveId: r.cveId,
          description: (r.description ?? "").slice(0, 200),
          cvssScore: r.cvssScore,
          url: r.url ?? `https://nvd.nist.gov/vuln/detail/${r.cveId}`,
        });
      }
    }
  }
  return out.slice(0, 15);
}

export async function generateWorkspaceInsights(
  findings: Finding[],
  reconModules: ReconModule[],
  workspaceName: string,
  options?: { cveContext?: CVERecord[]; webSearchContext?: string; verification?: FollowUpCheckResult[] }
): Promise<WorkspaceInsightsResult> {
  const glm = getGlmConfig();
  const verification = options?.verification;
  log.info({ model: glm.model, enabled: glm.enabled, checks: verification?.length ?? 0 }, "AI insights config");
  if (!glm.enabled) {
    return {
      ...buildFallbackInsights(findings, reconModules, workspaceName),
      isAIGenerated: false,
      fallbackReason: "ollama_disabled",
      fallbackErrorDetail: "GLM is not configured. Set GLM_API_KEY on the server.",
      verification,
    };
  }

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sortedFindings = [...findings].sort(
    (a, b) => (severityOrder[a.severity as keyof typeof severityOrder] ?? 5) - (severityOrder[b.severity as keyof typeof severityOrder] ?? 5)
  );
  const findingContext = sortedFindings.slice(0, 10).map(buildFindingContext).join("\n\n");
  const reconContext = buildReconContext(reconModules);

  const existingCve = collectCVEFromFindings(findings);
  const allCve = [...existingCve];
  for (const c of options?.cveContext ?? []) {
    if (!allCve.some((x) => x.cveId === c.cveId)) allCve.push(c);
  }
  const cveBlock =
    allCve.length > 0
      ? allCve.map((c) => `- ${c.cveId}: ${c.description.slice(0, 150)} (CVSS: ${c.cvssScore ?? "N/A"})`).join("\n")
      : "(none)";

  const webBlock = options?.webSearchContext?.trim()
    ? options.webSearchContext.slice(0, 500)
    : "(none)";

  const crit = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;

  // These checks already ran against the workspace's real hosts before this
  // prompt was built (see routes/findings.ts). Handing the model their
  // results — rather than asking it to reason only from stored finding text —
  // is the same "grounded in a live probe, not a stale description" principle
  // the AI Follow-up report uses, so the two features cannot disagree about
  // what is currently true of the target.
  const verificationBlock = verification && verification.length > 0
    ? verification.map((c) => `- ${c.label} [${c.status}]: ${c.summary}`).join("\n")
    : "(no live checks were run for this synthesis)";

  const prompt = `You are a cybersecurity analyst. Synthesize intelligence for workspace "${sanitize(workspaceName)}".

FINDINGS (${findings.length} total, ${crit} critical, ${high} high):
${findingContext || "(none)"}

RECON INTELLIGENCE:
${reconContext}

KNOWN VULNERABILITIES (CVE):
${cveBlock}

EXTERNAL THREAT INTEL:
${webBlock}

LIVE VERIFICATION (probed just now against the workspace's own hosts — treat this as the current ground truth; do not contradict it, and say so explicitly if it disagrees with a stored finding):
${verificationBlock}

CORRELATE: Link findings to recon data, CVEs, known threats, and the live verification. Prioritize by severity and exploitability.

Respond in valid JSON only. No markdown, no code blocks. Use exactly these keys:
- "summary": string, 2-4 sentences on overall risk level, main vulnerabilities, and recommended priorities
- "keyRisks": array of 3-6 strings, each a specific risk (e.g. "Exposed admin panel allows brute force")
- "threatLandscape": string, 2-3 sentences on tech stack, exposed services, and attack vectors`;

  const system = "Output valid JSON only. No markdown, no extra text. Include all three keys: summary, keyRisks, threatLandscape.";
  try {
    const raw = await callOllama(prompt, system, { format: "json" });
    const parsed = extractJSON<WorkspaceInsightsResult>(raw) ?? (() => {
      try {
        return JSON.parse(raw) as WorkspaceInsightsResult;
      } catch {
        return null;
      }
    })();
    if (!parsed || typeof parsed !== "object") {
      log.warn({ rawLength: raw?.length }, "AI insights: GLM returned non-JSON, using fallback");
      return {
        ...buildFallbackInsights(findings, reconModules, workspaceName),
        isAIGenerated: false,
        fallbackReason: "ollama_error",
        fallbackErrorDetail: `GLM returned invalid JSON (raw length: ${raw?.length ?? 0}).`,
        verification,
      };
    }
    // Handle tinyllama/small models that may misspell keys (e.g. threaTLandScape)
    const obj = parsed as unknown as Record<string, unknown>;
    const threatLandscapeKey = Object.keys(obj).find((k) => k.toLowerCase().includes("threat") && k.toLowerCase().includes("landscape")) ?? "threatLandscape";
    const aiSummary = String(parsed.summary ?? obj.summary ?? "").trim().slice(0, 2000);
    const aiKeyRisks = Array.isArray(parsed.keyRisks)
      ? parsed.keyRisks.slice(0, 6).map(String).filter(Boolean)
      : Array.isArray(obj.keyRisks)
        ? (obj.keyRisks as string[]).slice(0, 6).map(String).filter(Boolean)
        : [];
    const aiThreatLandscape = String(parsed.threatLandscape ?? obj[threatLandscapeKey] ?? "").trim().slice(0, 1500);
    const fallback = buildFallbackInsights(findings, reconModules, workspaceName);
    return {
      summary: aiSummary || fallback.summary,
      keyRisks: aiKeyRisks.length > 0 ? aiKeyRisks : fallback.keyRisks,
      threatLandscape: aiThreatLandscape || fallback.threatLandscape,
      isAIGenerated: true,
      verification,
    };
  } catch (err) {
    const errDetail = sanitizeErrorDetail(err);
    log.warn({ errDetail }, "AI insights: GLM error");
    const isTimeout =
      err instanceof Error &&
      (err.name === "AbortError" || (err.message && err.message.includes("aborted")));
    return {
      ...buildFallbackInsights(findings, reconModules, workspaceName),
      isAIGenerated: false,
      verification,
      fallbackReason: isTimeout ? "ollama_timeout" : "ollama_error",
      fallbackErrorDetail: errDetail,
    };
  }
}

export interface DetailedAnalysisResult {
  analysis: string;
  recommendations: string[];
}

export async function analyzeFindingDetails(
  finding: Finding,
  cveData?: CVERecord[],
  reconContext?: string
): Promise<DetailedAnalysisResult> {
  const evidenceSnippets = (finding.evidence ?? [])
    .map((e: Record<string, unknown>) => (e.snippet as string) ?? (e.description as string))
    .filter(Boolean)
    .join("\n---\n");
  const cveBlock = cveData?.length
    ? `\nRELATED CVEs:\n${cveData.map((c) => `- ${c.cveId}: ${c.description.slice(0, 200)} (CVSS: ${c.cvssScore ?? "N/A"})`).join("\n")}`
    : "";
  const reconBlock = reconContext ? `\nRECON CONTEXT:\n${sanitize(reconContext).slice(0, 1500)}` : "";

  const prompt = `You are a cybersecurity analyst. Provide detailed analysis of this finding.

FINDING:
Title: ${sanitize(finding.title)}
Description: ${sanitize(finding.description)}
Severity: ${finding.severity}
Category: ${finding.category}
Affected Asset: ${sanitize(finding.affectedAsset ?? "N/A")}
Remediation: ${sanitize(finding.remediation ?? "N/A")}
${evidenceSnippets ? `Evidence:\n${sanitize(evidenceSnippets)}` : ""}${cveBlock}${reconBlock}

Respond in JSON only:
{
  "analysis": "string (2-4 paragraph detailed analysis: impact, attack vectors, business risk)",
  "recommendations": ["string", "string", ...] (3-6 actionable recommendations)
}`;

  const system = "Output valid JSON only. No markdown, no extra text.";
  let raw: string;
  try {
    raw = await callOllama(prompt, system, { format: "json" });
  } catch (err) {
    log.warn({ err }, "AI analyze: Ollama error");
    return {
      analysis: finding.description,
      recommendations: [],
    };
  }
  try {
    const parsed = extractJSON<DetailedAnalysisResult>(raw) ?? (() => {
      try {
        return JSON.parse(raw) as DetailedAnalysisResult;
      } catch {
        return null;
      }
    })();
    if (!parsed || typeof parsed !== "object") {
      return { analysis: raw.slice(0, 4000) || finding.description, recommendations: [] };
    }
    return {
      analysis: String(parsed.analysis ?? "").slice(0, 4000),
      recommendations: Array.isArray(parsed.recommendations)
        ? parsed.recommendations.slice(0, 6).map(String)
        : [],
    };
  } catch {
    return {
      analysis: raw.slice(0, 4000) || finding.description,
      recommendations: [],
    };
  }
}

export interface AttackChainNarrative {
  narrative: string;
  priorityAction: string;
}

/**
 * A narrative for an attack chain that `attack-simulation.ts` already
 * matched against real findings — the model explains and prioritizes a
 * sequence that is already evidenced, it does not invent one. Same
 * discipline as the AI Follow-up report's write step: the caller supplies
 * exactly what matched, and the prompt tells the model not to add steps or
 * findings beyond that list.
 */
export async function explainAttackChain(input: {
  playbookName: string;
  mitreTactics: string[];
  matchedSteps: Array<{ order: number; action: string; matchingFindingTitles: string[] }>;
  riskScore: number;
  /** True when the same underlying finding backs 2+ different steps — the
   *  chain's "coverage" is reused evidence, not distinct proof of progress. */
  lowConfidence?: boolean;
  /** Live checks run against the target JUST NOW, alongside the static
   *  category match — manual recon the model can weigh instead of judging
   *  from stored finding titles alone. */
  verification?: Array<{ label: string; status: string; summary: string }>;
}): Promise<AttackChainNarrative> {
  const stepsBlock = input.matchedSteps
    .map((s) => `${s.order}. ${s.action} — evidenced by: ${s.matchingFindingTitles.slice(0, 5).join("; ") || "(no specific finding titles)"}`)
    .join("\n");

  const verificationBlock = input.verification && input.verification.length > 0
    ? input.verification.map((v) => `- ${v.label} (${v.status}): ${v.summary}`).join("\n")
    : "(no live verification was run)";

  const confidenceNote = input.lowConfidence
    ? "\nLOW CONFIDENCE WARNING: the matched steps above are not independent — the SAME underlying finding is being cited as evidence for two or more different steps, which is category-keyword overlap, not proof each stage is actually achievable. Say so explicitly and do not describe this as a demonstrated or high-confidence chain."
    : "";

  const prompt = `You are a penetration tester briefing a client on ONE already-matched attack chain. Do not invent steps, findings, or targets beyond what is given below.

CHAIN: "${sanitize(input.playbookName)}" (MITRE ATT&CK: ${input.mitreTactics.join(", ") || "none listed"})
RISK SCORE: ${input.riskScore}/100${confidenceNote}

MATCHED STEPS (each already has real findings behind it):
${stepsBlock || "(no steps matched)"}

LIVE VERIFICATION (checks run against the target just now, not just static category matching):
${verificationBlock}

Write:
- "narrative": 2-4 sentences explaining, in plain language, how an attacker chains these SPECIFIC matched steps together against this target, referencing the evidence given AND the live verification results. If the evidence is thin, reused across steps, or the live checks do not corroborate it, say plainly that this is a low-confidence or speculative chain rather than describing it as demonstrated.
- "priorityAction": one sentence naming the single highest-leverage fix that would break this chain (i.e. which matched step, if remediated, most reduces the risk). If the chain is low-confidence, this can instead recommend what to verify first.

Respond in JSON only, no markdown, with exactly these two keys.`;

  const system = "Output valid JSON only. No markdown, no extra text. Never introduce a step, finding, or target not given in the prompt.";
  const raw = await callOllama(prompt, system, { format: "json" });
  const parsed = extractJSON<AttackChainNarrative>(raw);
  return {
    narrative: (parsed?.narrative ?? "").trim().slice(0, 1200) || raw.slice(0, 1200),
    priorityAction: (parsed?.priorityAction ?? "").trim().slice(0, 400),
  };
}

export interface ComplianceNarrative {
  summary: string;
  topGaps: string[];
}

/**
 * A narrative over a compliance report the deterministic mapper already
 * computed — the model explains and prioritizes, it never re-grades a
 * control. Pass/fail/partial/unknown are facts from `compliance-mapper.ts`;
 * asking a model to also assert compliance status would be exactly the
 * overclaim this codebase's own compliance work has repeatedly had to
 * correct (an unmapped category silently reading as a pass, DPDP process
 * controls that an external scan cannot assess at all). The prompt states
 * the counts and per-control verdicts as given facts and forbids changing
 * them.
 */
export async function explainComplianceReport(input: {
  framework: string;
  frameworkVersion: string;
  score: number;
  passCount: number;
  failCount: number;
  partialCount: number;
  unknownCount: number;
  failingControls: Array<{ id: string; title: string; severity: string; findingCount: number }>;
  notAssessableCount: number;
}): Promise<ComplianceNarrative> {
  const failBlock = input.failingControls
    .map((c) => `- [${c.id}] ${c.title} (${c.severity}, ${c.findingCount} finding(s))`)
    .join("\n") || "(none failing)";

  const prompt = `You are a compliance analyst. These are FACTS already computed by a deterministic mapper — do not change any verdict, invent a control, or claim a status for a control not listed.

FRAMEWORK: ${sanitize(input.framework)} ${sanitize(input.frameworkVersion)}
SCORE: ${input.score}/100
CONTROLS: ${input.passCount} pass, ${input.failCount} fail, ${input.partialCount} partial, ${input.unknownCount} unassessed${input.notAssessableCount > 0 ? `, ${input.notAssessableCount} not externally assessable (process controls, out of scope for a surface scan)` : ""}

FAILING CONTROLS:
${failBlock}

Write:
- "summary": 2-3 sentences, plain-language business risk of the current gaps, for a reader who is not a security engineer.
- "topGaps": array of up to 4 strings, each naming ONE failing control from the list above and the single most important reason it matters.

Respond in JSON only, no markdown, with exactly these two keys.`;

  const system = "Output valid JSON only. No markdown, no extra text. Never assert a control's status beyond what is given; never invent a control.";
  const raw = await callOllama(prompt, system, { format: "json" });
  const parsed = extractJSON<ComplianceNarrative>(raw);
  return {
    summary: (parsed?.summary ?? "").trim().slice(0, 1000) || raw.slice(0, 1000),
    topGaps: Array.isArray(parsed?.topGaps) ? parsed.topGaps.slice(0, 4).map((s) => String(s).slice(0, 300)) : [],
  };
}

export interface ReportQaResult {
  /** true = no problems the model could point to; false = it named at least one */
  clean: boolean;
  /** Each item names a SPECIFIC inconsistency, unsupported claim, or clarity problem — never a generic "looks good". */
  issues: string[];
  /** One sentence: is this ready to send to a client as-is, or does it need a look first. */
  recommendation: string;
}

/**
 * A QA pass over a report BEFORE the operator shares it externally.
 *
 * This checks the report's own internal consistency (do the stated counts
 * match the findings actually listed, does the summary claim something the
 * findings don't support) and prose clarity — it is a proofreader, not a
 * second opinion on severity or a compliance certification. It must never
 * assert a finding is wrong or invent one that is not in `findingTitles`;
 * the prompt says so twice because a QA tool that hallucinates a problem is
 * worse than one that misses a real one — it trains the reader to stop
 * trusting it, the same lesson this codebase already learned about a false
 * "no findings" reading as a clean result.
 */
export async function reviewReportForQA(input: {
  title: string;
  reportType: string;
  summary: string;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  findingTitles: string[];
}): Promise<ReportQaResult> {
  const findingsBlock = input.findingTitles.slice(0, 40).map((t) => `- ${t}`).join("\n") || "(none)";
  const truncatedNote = input.findingTitles.length > 40 ? `\n(+${input.findingTitles.length - 40} more not shown)` : "";

  const prompt = `You are proofreading a security report before it is sent to a client. Check ONLY what is given below — do not judge severity, do not invent a finding, do not claim a finding is wrong.

REPORT: "${sanitize(input.title)}" (${input.reportType})

STATED COUNTS: ${input.totalFindings} total findings, ${input.criticalCount} critical, ${input.highCount} high

EXECUTIVE SUMMARY AS WRITTEN:
${sanitize(input.summary).slice(0, 1500)}

FINDING TITLES ACTUALLY LISTED (${input.findingTitles.length}):
${findingsBlock}${truncatedNote}

Check for:
1. Does the summary's own numbers or severity claims match the stated counts and the finding titles listed?
2. Does the summary claim something (a specific vulnerability class, an affected system) that no listed finding title supports?
3. Is the summary vague, repetitive, or missing an actionable next step?

Respond in JSON only, no markdown, with exactly these keys:
- "issues": array of strings, each naming ONE specific problem found (empty array if none)
- "recommendation": one sentence — ready to send, or what to fix first`;

  const system = "Output valid JSON only. No markdown, no extra text. Report only problems you can point to in the text given; never invent a finding or a claim that is not there.";
  const raw = await callOllama(prompt, system, { format: "json" });
  const parsed = extractJSON<{ issues?: unknown; recommendation?: unknown }>(raw);
  const issues = Array.isArray(parsed?.issues) ? parsed.issues.slice(0, 8).map((s) => String(s).slice(0, 300)) : [];
  return {
    clean: issues.length === 0,
    issues,
    recommendation: String(parsed?.recommendation ?? "").trim().slice(0, 400) || raw.slice(0, 400),
  };
}

export interface TrendNarrative {
  summary: string;
  drivers: string[];
}

/**
 * A narrative over trend data the server already aggregated
 * (`routes/analytics.ts` — posture snapshots, findings-by-day, categories,
 * MTTR). Same discipline as the other explain endpoints: the model
 * describes direction and likely cause from the numbers given, it does not
 * introduce a finding, category or date that is not in the data.
 */
export async function explainTrends(input: {
  workspaceName: string;
  securityScoreTrend: Array<{ date: string; securityScore: number | null }>;
  findingsByDay: Array<{ date: string; total: number; critical: number; high: number }>;
  topCategories: Array<{ category: string; total: number; open: number; critical: number; high: number }>;
  mttr: { totalResolved: number; overallAvgHours: number | null };
}): Promise<TrendNarrative> {
  const scoreLine = input.securityScoreTrend.length >= 2
    ? `${input.securityScoreTrend[0]?.securityScore ?? "N/A"} → ${input.securityScoreTrend[input.securityScoreTrend.length - 1]?.securityScore ?? "N/A"} over ${input.securityScoreTrend.length} snapshots`
    : `${input.securityScoreTrend.length} snapshot(s), not enough to show a direction`;
  const findingsBlock = input.findingsByDay.slice(-14).map((d) => `${d.date}: ${d.total} total (${d.critical} critical, ${d.high} high)`).join("\n") || "(no dated findings)";
  const categoriesBlock = input.topCategories.slice(0, 8).map((c) => `- ${c.category}: ${c.total} total, ${c.open} open, ${c.critical} critical, ${c.high} high`).join("\n") || "(none)";
  const mttrLine = input.mttr.totalResolved > 0
    ? `${input.mttr.totalResolved} findings resolved, average ${input.mttr.overallAvgHours ?? "N/A"} hours to resolve`
    : "no findings resolved yet — MTTR not established";

  const prompt = `You are a security analyst summarizing trend data for workspace "${sanitize(input.workspaceName)}". Use ONLY the numbers given below — do not name a specific vulnerability or date not shown here.

SECURITY SCORE TREND: ${scoreLine}

FINDINGS DISCOVERED BY DAY (most recent 14):
${findingsBlock}

TOP CATEGORIES (by volume):
${categoriesBlock}

MEAN TIME TO RESOLVE: ${mttrLine}

Write:
- "summary": 2-3 sentences on the overall direction (improving, worsening, or flat) and what is driving it.
- "drivers": array of up to 3 strings, each naming ONE specific category or pattern from the data above that best explains the trend.

Respond in JSON only, no markdown, with exactly these two keys.`;

  const system = "Output valid JSON only. No markdown, no extra text. Never name a category, date or number not present in the prompt.";
  const raw = await callOllama(prompt, system, { format: "json" });
  const parsed = extractJSON<{ summary?: unknown; drivers?: unknown }>(raw);
  return {
    summary: String(parsed?.summary ?? "").trim().slice(0, 1000) || raw.slice(0, 1000),
    drivers: Array.isArray(parsed?.drivers) ? parsed.drivers.slice(0, 3).map((s) => String(s).slice(0, 300)) : [],
  };
}

export interface BrandThreatNarrative {
  summary: string;
  priorities: string[];
}

/**
 * A narrative correlating the five independent brand-threat signals
 * (typosquats, ransomware leak sites, source-code leaks, mobile app abuse,
 * breach corpus) into one read, instead of an operator mentally combining
 * five separate panels.
 *
 * The three-state discipline this codebase uses everywhere else (checked /
 * found-nothing / never-run) is the hardest thing to get right here, so the
 * prompt is explicit: a `null` signal is NOT EVIDENCE of anything and must
 * be named as "not yet checked", never folded into "no threats found". That
 * is the exact "No Data reads as a pass" failure this file's compliance and
 * dark-web work already had to correct twice.
 */
export async function explainBrandThreats(input: {
  domain: string;
  typosquat: { checked: boolean; registeredCount?: number; highRiskCount?: number };
  ransomware: { checked: boolean; confirmedCount?: number };
  codeLeaks: { checked: boolean; configured: boolean; withSecretsCount?: number; totalCount?: number };
  mobileApps: { checked: boolean; officialCount?: number; thirdPartyCount?: number; brandInBundleIdCount?: number };
  breaches: { checked: boolean; confirmedCount?: number; unverifiedCount?: number };
}): Promise<BrandThreatNarrative> {
  const line = (label: string, s: { checked: boolean }, detail: string) =>
    `- ${label}: ${s.checked ? detail : "NOT YET CHECKED — say so, do not imply clean"}`;

  const factsBlock = [
    line("Lookalike domains", input.typosquat, `${input.typosquat.registeredCount ?? 0} registered, ${input.typosquat.highRiskCount ?? 0} high-risk`),
    line("Ransomware leak sites", input.ransomware, `${input.ransomware.confirmedCount ?? 0} confirmed posting(s) naming this domain`),
    line(
      "Source-code leaks",
      input.codeLeaks,
      input.codeLeaks.configured
        ? `${input.codeLeaks.totalCount ?? 0} matching repositories, ${input.codeLeaks.withSecretsCount ?? 0} containing secret-shaped values`
        : "check not configured on this deployment (no GITHUB_TOKEN) — not the same as clean",
    ),
    line("Mobile app impersonation", input.mobileApps, `${input.mobileApps.officialCount ?? 0} official app(s), ${input.mobileApps.thirdPartyCount ?? 0} third-party app(s) using the brand, ${input.mobileApps.brandInBundleIdCount ?? 0} with the brand in their bundle id (not proof of ownership)`),
    line("Public breach corpus", input.breaches, `${input.breaches.confirmedCount ?? 0} confirmed breach record(s), ${input.breaches.unverifiedCount ?? 0} unverified`),
  ].join("\n");

  const prompt = `You are a brand-protection analyst. These are FACTS about "${sanitize(input.domain)}" from five independent checks — some may say NOT YET CHECKED, which you must report as "not yet checked", never as clean or safe.

${factsBlock}

Write:
- "summary": 2-4 sentences on overall brand-abuse exposure, explicitly noting anything not yet checked rather than ignoring it.
- "priorities": array of up to 3 strings, each naming the single most urgent action from what WAS checked (empty array if nothing was checked or everything is clean).

Respond in JSON only, no markdown, with exactly these two keys.`;

  const system = "Output valid JSON only. No markdown, no extra text. A signal marked NOT YET CHECKED must be reported as unchecked, never as absence of a threat.";
  const raw = await callOllama(prompt, system, { format: "json" });
  const parsed = extractJSON<{ summary?: unknown; priorities?: unknown }>(raw);
  return {
    summary: String(parsed?.summary ?? "").trim().slice(0, 1200) || raw.slice(0, 1200),
    priorities: Array.isArray(parsed?.priorities) ? parsed.priorities.slice(0, 3).map((s) => String(s).slice(0, 300)) : [],
  };
}

export interface ScanDiffNarrative {
  summary: string;
  watchFor: string[];
}

/**
 * A narrative over a scan-to-scan diff `differential-reporting.ts` already
 * computed (new / fixed / persisting findings, risk delta). The model
 * explains what changed between the two scans and why it matters — it does
 * not decide whether a finding is new or fixed (that is a deterministic set
 * comparison already done), and every finding it can name is already in one
 * of the three lists given.
 */
export async function explainScanDiff(input: {
  target: string;
  scan1Date: string;
  scan2Date: string;
  riskDelta: number;
  newFindings: Array<{ title: string; severity: string; category: string }>;
  fixedFindings: Array<{ title: string; severity: string; category: string }>;
  persistingCount: number;
}): Promise<ScanDiffNarrative> {
  const list = (findings: Array<{ title: string; severity: string; category: string }>) =>
    findings.slice(0, 20).map((f) => `- ${f.title} (${f.severity}, ${f.category})`).join("\n") || "(none)";

  const prompt = `You are a security analyst summarizing what changed between two scans of "${sanitize(input.target)}" — ${input.scan1Date} vs ${input.scan2Date}. Use ONLY the findings listed below; do not name anything not listed.

RISK DELTA: ${input.riskDelta > 0 ? "+" : ""}${input.riskDelta} (positive = worse)

NEW FINDINGS (${input.newFindings.length}):
${list(input.newFindings)}

FIXED FINDINGS (${input.fixedFindings.length}):
${list(input.fixedFindings)}

PERSISTING (unchanged): ${input.persistingCount} finding(s), not itemized here

Write:
- "summary": 2-3 sentences on whether posture improved or worsened and the main reason why, referencing specific findings/categories from the lists above.
- "watchFor": array of up to 3 strings, each naming ONE new finding (from the NEW list) most worth prioritizing (empty array if no new findings).

Respond in JSON only, no markdown, with exactly these two keys.`;

  const system = "Output valid JSON only. No markdown, no extra text. Only name a finding that appears in the NEW or FIXED lists given.";
  const raw = await callOllama(prompt, system, { format: "json" });
  const parsed = extractJSON<{ summary?: unknown; watchFor?: unknown }>(raw);
  return {
    summary: String(parsed?.summary ?? "").trim().slice(0, 1000) || raw.slice(0, 1000),
    watchFor: Array.isArray(parsed?.watchFor) ? parsed.watchFor.slice(0, 3).map((s) => String(s).slice(0, 300)) : [],
  };
}

export interface AssetRiskNarrative {
  summary: string;
  drivers: string[];
}

/**
 * A narrative correlating risk factors ACROSS an asset estate — the page
 * shows overallScore + factors per asset, one row at a time, and nothing
 * currently says "which factor is systemically driving the estate's score."
 *
 * Grounded strictly in server-computed AGGREGATE counts (score bands, most
 * common contributing factor names, average), never in a per-asset listing —
 * an estate can hold hundreds of assets, and naming individual hostnames
 * would both blow the prompt budget and invite the model to draw a
 * conclusion about one host it wasn't actually shown in detail. This also
 * preserves the codebase's `findingCount === 0` vs `not_assessed` rule: the
 * caller must exclude unscored assets from the aggregates before calling
 * this, the same way the page's own "Average Score" tile does — a factor
 * from zero findings is "not assessed," never "clean."
 */
export async function explainAssetRisk(input: {
  totalAssets: number;
  scoredAssets: number;
  averageScore: number;
  bandCounts: { critical: number; high: number; medium: number; low: number };
  topFactors: Array<{ name: string; assetCount: number }>;
  trendCounts: { improving: number; stable: number; degrading: number; unknown: number };
}): Promise<AssetRiskNarrative> {
  const factorsBlock = input.topFactors.slice(0, 6).map((f) => `- ${f.name}: contributes to ${f.assetCount} scored asset(s)`).join("\n") || "(no contributing factors recorded)";

  const prompt = `You are a security analyst summarizing an asset risk estate. Use ONLY the aggregate numbers given below — do not name a specific hostname, you were not given any.

ASSETS: ${input.totalAssets} total, ${input.scoredAssets} scored (have findings — the rest are "not assessed," not clean)
AVERAGE SCORE (scored assets only): ${input.averageScore.toFixed(1)}/100

SCORE BANDS (scored assets only): ${input.bandCounts.critical} critical (>=80), ${input.bandCounts.high} high (>=60), ${input.bandCounts.medium} medium (>=40), ${input.bandCounts.low} low (<40)

MOST COMMON CONTRIBUTING RISK FACTORS ACROSS SCORED ASSETS:
${factorsBlock}

TREND: ${input.trendCounts.improving} improving, ${input.trendCounts.stable} stable, ${input.trendCounts.degrading} degrading, ${input.trendCounts.unknown} no history yet

Write:
- "summary": 2-3 sentences on the overall estate posture and which factor(s) are systemically driving it, referencing the aggregate numbers above.
- "drivers": array of up to 3 strings, each naming ONE factor from the list above and roughly how many assets it affects.

Respond in JSON only, no markdown, with exactly these two keys.`;

  const system = "Output valid JSON only. No markdown, no extra text. Never name a hostname — only aggregate counts were given. A count of 0 scored assets for a band or factor means not assessed, never clean.";
  const raw = await callOllama(prompt, system, { format: "json" });
  const parsed = extractJSON<{ summary?: unknown; drivers?: unknown }>(raw);
  return {
    summary: String(parsed?.summary ?? "").trim().slice(0, 1000) || raw.slice(0, 1000),
    drivers: Array.isArray(parsed?.drivers) ? parsed.drivers.slice(0, 3).map((s) => String(s).slice(0, 300)) : [],
  };
}
