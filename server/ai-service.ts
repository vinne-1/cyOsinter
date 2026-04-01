/**
 * AI service for finding enrichment, report generation, and scan consolidation.
 * Uses Ollama with DeepSeek R1 Abliterated (or configurable model).
 */

import type { Finding } from "@shared/schema";
import type { ReconModule } from "@shared/schema";
import { getOllamaConfig } from "./api-integrations";
import { getCVEForFinding, type CVERecord } from "./cve-service";
import { createLogger } from "./logger";

const log = createLogger("ai");

export const AI_REQUEST_TIMEOUT_MS = 30 * 60 * 1000; // 30 min for CPU inference
const TIMEOUT_MS = AI_REQUEST_TIMEOUT_MS;

export { getOllamaConfig, setOllamaConfig } from "./api-integrations";

export async function getOllamaStatus(): Promise<{ reachable: boolean; modelLoaded?: boolean }> {
  const ollamaConfig = getOllamaConfig();
  const base = ollamaConfig.baseUrl.replace(/\/$/, "");
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 5000);
    const res = await fetch(`${base}/api/tags`, { signal: ctrl.signal });
    clearTimeout(t);
    if (!res.ok) return { reachable: true, modelLoaded: false };
    const json = (await res.json()) as { models?: Array<{ name?: string }> };
    const models = json.models ?? [];
    const modelLoaded = models.some((m) => (m.name ?? "").includes(ollamaConfig.model.split(":")[0]));
    return { reachable: true, modelLoaded };
  } catch {
    return { reachable: false };
  }
}

const OLLAMA_RETRY_ATTEMPTS = 3;
const OLLAMA_RETRY_DELAYS_MS = [5000, 10000, 15000]; // exponential backoff

function getErrnoCode(err: unknown): string | undefined {
  return (err as NodeJS.ErrnoException)?.code;
}

async function callOllama(prompt: string, system?: string, options?: { format?: "json" }): Promise<string> {
  const ollamaConfig = getOllamaConfig();
  if (!ollamaConfig.enabled) throw new Error("Ollama AI is disabled");
  const base = ollamaConfig.baseUrl.replace(/\/$/, "");
  const url = `${base}/api/generate`;
  const body: Record<string, unknown> = {
    model: ollamaConfig.model,
    prompt: system ? `${system}\n\n${prompt}` : prompt,
    stream: false,
  };
  if (options?.format === "json") body.format = "json";
  const bodyStr = JSON.stringify(body);

  let lastErr: Error | null = null;
  for (let attempt = 1; attempt <= OLLAMA_RETRY_ATTEMPTS; attempt++) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: bodyStr,
        signal: ctrl.signal,
      });
      clearTimeout(t);
      if (!res.ok) {
        const errText = await res.text();
        const is503 = res.status === 503;
        if (is503 && attempt < OLLAMA_RETRY_ATTEMPTS) {
          const delay = OLLAMA_RETRY_DELAYS_MS[attempt - 1] ?? 5000;
          log.warn({ url, attempt, maxAttempts: OLLAMA_RETRY_ATTEMPTS, delayMs: delay }, "Ollama 503 (model loading?), retrying");
          await new Promise((r) => setTimeout(r, delay));
          continue;
        }
        const snippet = errText.slice(0, 200).toLowerCase();
        const resourceHint =
          snippet.includes("memory") ||
          snippet.includes("oom") ||
          snippet.includes("out of memory") ||
          snippet.includes("cuda") ||
          snippet.includes("gpu") ||
          is503
            ? " Likely due to insufficient resources (CPU/memory/GPU) or model loading."
            : "";
        throw new Error(`Ollama error ${res.status}: ${errText.slice(0, 150)}${resourceHint}`);
      }
      const json = (await res.json()) as { response?: string };
      return (json.response ?? "").trim();
    } catch (err) {
      clearTimeout(t);
      lastErr = err instanceof Error ? err : new Error(String(err));
      const errCode = getErrnoCode(err);
      const isConnectionError =
        lastErr.message.includes("ECONNREFUSED") ||
        lastErr.message.includes("fetch failed") ||
        lastErr.message.includes("ECONNRESET") ||
        lastErr.message.includes("socket hang up");
      if (isConnectionError && attempt < OLLAMA_RETRY_ATTEMPTS) {
        const delay = OLLAMA_RETRY_DELAYS_MS[attempt - 1] ?? 5000;
        log.warn({ url, attempt, maxAttempts: OLLAMA_RETRY_ATTEMPTS, errCode: errCode ?? "n/a", delayMs: delay, err: lastErr }, "Ollama connection error, retrying");
        await new Promise((r) => setTimeout(r, delay));
        continue;
      }
      if (lastErr.name === "AbortError" || lastErr.message.includes("aborted")) {
        throw new Error(
          "Ollama request timed out. This may be due to insufficient CPU or memory—try a smaller model (e.g. tinyllama) or free up system resources."
        );
      }
      if (lastErr.message.includes("ECONNREFUSED") || lastErr.message.includes("fetch failed")) {
        log.warn({ url, errCode: errCode ?? "n/a", err: lastErr }, "Ollama final failure");
        throw new Error("Cannot reach Ollama. Ensure ollama serve is running and the base URL is correct.");
      }
      throw lastErr;
    }
  }
  throw lastErr ?? new Error("Ollama request failed. This may be due to insufficient resources (CPU/memory) or Ollama being overloaded.");
}

function sanitize(text: string): string {
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

function buildFindingContext(f: Finding): string {
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

function buildReconContext(reconModules: ReconModule[]): string {
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

TARGET: ${workspaceTarget}

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
  const summary = `Workspace ${workspaceName} has ${findings.length} security findings (${crit} critical, ${high} high). ` +
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

async function warmUpOllama(baseUrl: string, model: string): Promise<void> {
  const url = `${baseUrl.replace(/\/$/, "")}/api/generate`;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 15000);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model, prompt: "Hi", stream: false }),
      signal: ctrl.signal,
    });
    clearTimeout(t);
    if (res.ok) {
      await res.json();
    }
  } catch {
    clearTimeout(t);
    // Ignore warm-up failures; goal is to trigger model load
  }
}

export async function generateWorkspaceInsights(
  findings: Finding[],
  reconModules: ReconModule[],
  workspaceName: string,
  options?: { cveContext?: CVERecord[]; webSearchContext?: string }
): Promise<WorkspaceInsightsResult> {
  const ollamaConfig = getOllamaConfig();
  log.warn({ baseUrl: ollamaConfig.baseUrl, model: ollamaConfig.model, enabled: ollamaConfig.enabled }, "AI insights config");
  if (!ollamaConfig.enabled) {
    return {
      ...buildFallbackInsights(findings, reconModules, workspaceName),
      isAIGenerated: false,
      fallbackReason: "ollama_disabled",
      fallbackErrorDetail: "Ollama AI is disabled. Enable it in Integrations and click Save.",
    };
  }

  // Pre-flight: verify Ollama is reachable before long-running inference
  const status = await getOllamaStatus();
  if (!status.reachable) {
    log.warn({ baseUrl: ollamaConfig.baseUrl }, "AI insights: Ollama not reachable");
    return {
      ...buildFallbackInsights(findings, reconModules, workspaceName),
      isAIGenerated: false,
      fallbackReason: "ollama_error",
      fallbackErrorDetail: `Ollama not reachable at ${ollamaConfig.baseUrl}. Ensure ollama serve is running.`,
    };
  }

  // Warm-up: trigger model load before main inference (ignores failures)
  await warmUpOllama(ollamaConfig.baseUrl, ollamaConfig.model);

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

  const prompt = `You are a cybersecurity analyst. Synthesize intelligence for workspace "${workspaceName}".

FINDINGS (${findings.length} total, ${crit} critical, ${high} high):
${findingContext || "(none)"}

RECON INTELLIGENCE:
${reconContext}

KNOWN VULNERABILITIES (CVE):
${cveBlock}

EXTERNAL THREAT INTEL:
${webBlock}

CORRELATE: Link findings to recon data, CVEs, and known threats. Prioritize by severity and exploitability.

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
      log.warn({ rawLength: raw?.length }, "AI insights: Ollama returned non-JSON, using fallback");
      return {
        ...buildFallbackInsights(findings, reconModules, workspaceName),
        isAIGenerated: false,
        fallbackReason: "ollama_error",
        fallbackErrorDetail: `Ollama returned invalid JSON (raw length: ${raw?.length ?? 0}). Try a different model or ensure format: json is supported.`,
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
    };
  } catch (err) {
    const errDetail = sanitizeErrorDetail(err);
    log.warn({ errDetail }, "AI insights: Ollama error");
    const isTimeout =
      err instanceof Error &&
      (err.name === "AbortError" || (err.message && err.message.includes("aborted")));
    return {
      ...buildFallbackInsights(findings, reconModules, workspaceName),
      isAIGenerated: false,
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
