import { createLogger } from "../logger.js";
import { runWithConcurrency } from "./utils.js";

const log = createLogger("waf-bypass");

const TEST_TIMEOUT_MS = 6000;
const TEST_CONCURRENCY = 4;

interface BypassTest {
  technique: string;
  payload: string;
  description: string;
}

const BYPASS_TESTS: BypassTest[] = [
  {
    technique: "Case Manipulation",
    payload: "<ScRiPt>alert(1)</sCrIpT>",
    description: "Mixed case to evade case-sensitive pattern matching",
  },
  {
    technique: "URL Encoding",
    payload: "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    description: "URL-encoded script tag to bypass string matching",
  },
  {
    technique: "Double Encoding",
    payload: "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
    description: "Double URL encoding to bypass single-decode WAF rules",
  },
  {
    technique: "Unicode Normalization",
    payload: "\uFF1Cscript\uFF1Ealert(1)\uFF1C/script\uFF1E",
    description: "Fullwidth Unicode characters that may normalize to ASCII",
  },
  {
    technique: "Comment Injection",
    payload: "<!--<script>alert(1)</script>-->",
    description: "HTML comment wrapping to confuse WAF parsing",
  },
  {
    technique: "Null Byte Injection",
    payload: "%00<script>alert(1)</script>",
    description: "Null byte prefix to terminate string matching early",
  },
  {
    technique: "HTTP Parameter Pollution",
    payload: "q=safe&q=<script>alert(1)</script>",
    description: "Duplicate parameter names to bypass first-param-only inspection",
  },
  {
    technique: "Method Override",
    payload: "<script>alert(1)</script>",
    description: "X-HTTP-Method-Override header to change request method interpretation",
  },
];

export interface WAFBypassResults {
  wafDetected: string | null;
  testsRun: number;
  blocked: number;
  bypassed: number;
  effectivenessScore: number;
  bypasses: Array<{
    technique: string;
    payload: string;
    evidence: string;
  }>;
  findings: Array<{
    title: string;
    description: string;
    severity: string;
    category: string;
    affectedAsset: string;
    remediation: string;
  }>;
  duration: number;
}

async function safeFetchGet(
  url: string,
  headers: Record<string, string>,
  timeout: number,
  signal?: AbortSignal,
): Promise<{ status: number; body: string } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  const onAbort = () => controller.abort();
  signal?.addEventListener("abort", onAbort, { once: true });

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "Cyshield-Scanner/1.0", ...headers },
      redirect: "follow",
    });
    const body = (await res.text()).substring(0, 10000);
    return { status: res.status, body };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", onAbort);
  }
}

function payloadReflectedInBody(body: string, test: BypassTest): boolean {
  // Check if key XSS payload markers appear in the response body (unescaped)
  const bodyLower = body.toLowerCase();

  // For URL-encoded and double-encoded payloads, check decoded form
  if (test.technique === "URL Encoding" || test.technique === "Double Encoding") {
    return bodyLower.includes("<script>") && bodyLower.includes("alert(1)");
  }

  // For case manipulation, check case-insensitive
  if (test.technique === "Case Manipulation") {
    return bodyLower.includes("<script>") && bodyLower.includes("alert(1)");
  }

  // For null byte, check if the script tag appears after the null byte
  if (test.technique === "Null Byte Injection") {
    return bodyLower.includes("<script>") && bodyLower.includes("alert(1)");
  }

  // For comment injection, check if the script tag appears (even inside comment)
  if (test.technique === "Comment Injection") {
    return bodyLower.includes("<script>alert(1)</script>");
  }

  // General check
  return bodyLower.includes("<script>") && bodyLower.includes("alert(1)");
}

function isBlocked(status: number, body: string): boolean {
  // WAF block responses typically return 403, 406, 429, or contain block page indicators
  if (status === 403 || status === 406 || status === 429 || status === 503) return true;

  const bodyLower = body.toLowerCase();
  const blockIndicators = [
    "blocked", "access denied", "forbidden", "request blocked",
    "web application firewall", "waf", "security violation",
    "not acceptable", "suspicious activity", "cloudflare",
    "akamai", "imperva", "incapsula", "sucuri",
  ];

  return blockIndicators.some((indicator) => bodyLower.includes(indicator));
}

function buildBypassUrl(domain: string, test: BypassTest): { url: string; headers: Record<string, string> } {
  const baseUrl = `https://${domain}/`;
  const headers: Record<string, string> = {};

  if (test.technique === "HTTP Parameter Pollution") {
    return { url: `${baseUrl}?${test.payload}`, headers };
  }

  if (test.technique === "Method Override") {
    headers["X-HTTP-Method-Override"] = "PUT";
    return { url: `${baseUrl}?q=${encodeURIComponent(test.payload)}`, headers };
  }

  return { url: `${baseUrl}?q=${encodeURIComponent(test.payload)}`, headers };
}

export async function runWAFBypassTest(
  domain: string,
  wafDetected: string | null,
  signal?: AbortSignal,
): Promise<WAFBypassResults> {
  const startTime = Date.now();

  // Return early if no WAF detected
  if (!wafDetected) {
    log.info({ domain }, "No WAF detected, skipping bypass tests");
    return {
      wafDetected: null,
      testsRun: 0,
      blocked: 0,
      bypassed: 0,
      effectivenessScore: 0,
      bypasses: [],
      findings: [],
      duration: Date.now() - startTime,
    };
  }

  log.info({ domain, waf: wafDetected }, "Starting WAF bypass testing");

  const bypasses: WAFBypassResults["bypasses"] = [];
  const findings: WAFBypassResults["findings"] = [];
  let blocked = 0;
  let bypassed = 0;

  const results = await runWithConcurrency(
    BYPASS_TESTS,
    TEST_CONCURRENCY,
    async (test) => {
      const { url, headers } = buildBypassUrl(domain, test);
      const res = await safeFetchGet(url, headers, TEST_TIMEOUT_MS, signal);
      if (!res) return { test, outcome: "error" as const };

      if (isBlocked(res.status, res.body)) {
        return { test, outcome: "blocked" as const };
      }

      if (payloadReflectedInBody(res.body, test)) {
        return { test, outcome: "bypassed" as const, evidence: `Payload reflected in response body (HTTP ${res.status})` };
      }

      // Request went through but payload not reflected - counts as blocked by WAF
      return { test, outcome: "blocked" as const };
    },
    signal,
  );

  for (const result of results) {
    if (!result || result.outcome === "error") continue;

    if (result.outcome === "blocked") {
      blocked++;
    } else if (result.outcome === "bypassed") {
      bypassed++;
      bypasses.push({
        technique: result.test.technique,
        payload: result.test.payload,
        evidence: result.evidence ?? "Payload was not blocked by WAF",
      });
    }
  }

  const testsRun = blocked + bypassed;
  const effectivenessScore = testsRun > 0 ? Math.round((blocked / testsRun) * 100) : 100;

  // Generate findings for successful bypasses
  if (bypasses.length > 0) {
    findings.push({
      title: `WAF Bypass Detected (${wafDetected})`,
      description: `${bypasses.length} out of ${testsRun} WAF bypass techniques succeeded against ${wafDetected}. The WAF effectiveness score is ${effectivenessScore}%. Successful techniques: ${bypasses.map((b) => b.technique).join(", ")}.`,
      severity: bypasses.length >= 4 ? "high" : "medium",
      category: "waf_bypass",
      affectedAsset: domain,
      remediation: `Review and update WAF rules for ${wafDetected}. Enable additional rule sets to cover the bypassed techniques. Consider using a more comprehensive WAF solution or layered security approach.`,
    });

    for (const bypass of bypasses) {
      findings.push({
        title: `WAF Bypass: ${bypass.technique}`,
        description: `The ${bypass.technique} technique successfully bypassed ${wafDetected} on ${domain}. ${bypass.evidence}.`,
        severity: "medium",
        category: "waf_bypass",
        affectedAsset: domain,
        remediation: getRemediationForTechnique(bypass.technique, wafDetected),
      });
    }
  }

  const duration = Date.now() - startTime;

  log.info(
    { domain, waf: wafDetected, testsRun, blocked, bypassed, effectivenessScore, duration },
    "WAF bypass testing complete",
  );

  return {
    wafDetected,
    testsRun,
    blocked,
    bypassed,
    effectivenessScore,
    bypasses,
    findings,
    duration,
  };
}

function getRemediationForTechnique(technique: string, waf: string): string {
  const remediations: Record<string, string> = {
    "Case Manipulation": `Configure ${waf} to perform case-insensitive pattern matching for XSS detection rules.`,
    "URL Encoding": `Ensure ${waf} decodes URL-encoded payloads before applying security rules. Enable recursive URL decoding.`,
    "Double Encoding": `Enable double-decode detection in ${waf}. Configure the WAF to recursively decode payloads before inspection.`,
    "Unicode Normalization": `Configure ${waf} to normalize Unicode characters before applying security rules. Enable Unicode-aware pattern matching.`,
    "Comment Injection": `Update ${waf} rules to detect and block script tags within HTML comments. Enable full HTML parsing in WAF rules.`,
    "Null Byte Injection": `Configure ${waf} to strip or reject null bytes in request parameters. Enable null byte detection rules.`,
    "HTTP Parameter Pollution": `Configure ${waf} to inspect all instances of duplicate parameters, not just the first occurrence.`,
    "Method Override": `Block or restrict X-HTTP-Method-Override headers in ${waf}. Only allow method override from trusted internal sources.`,
  };

  return remediations[technique] ?? `Review and update ${waf} rules to detect and block this bypass technique.`;
}
