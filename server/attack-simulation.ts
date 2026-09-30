import { createLogger } from "./logger";
import { storage } from "./storage";
import { isSecurityFinding } from "./scanner/finding-taxonomy";
import type { Finding } from "@shared/schema";

const log = createLogger("attack-simulation");

/** Statuses that mean the work is done — see the filter in runAttackSimulation. */
const CLOSED_STATUSES = new Set(["resolved", "false_positive", "accepted_risk", "closed"]);

export interface PlaybookStep {
  order: number;
  action: string;
  description: string;
  findingCategories: string[];
  severity: string;
}

export interface Playbook {
  id: string;
  name: string;
  description: string;
  category: string;
  steps: PlaybookStep[];
  mitreTactics: string[];
}

export interface SimulationResult {
  playbook: Playbook;
  exploitable: boolean;
  matchedSteps: Array<{ step: PlaybookStep; matchingFindings: Finding[] }>;
  riskScore: number;
  recommendations: string[];
  /** True when the chain's "coverage" is really one finding cited as evidence
   *  for two or more different steps, rather than distinct findings each
   *  showing real progress along the chain. `riskScore` and `exploitable`
   *  already reflect this dampening — callers deciding whether to DISPLAY a
   *  chain should also check `riskScore` against `MIN_DISPLAY_RISK_SCORE`. */
  lowConfidence: boolean;
}

/**
 * Below this, the matched evidence is too thin to present as an actionable
 * attack chain — a category token or two happened to overlap, not a chain an
 * attacker could actually walk. Callers rendering a list of chains (not a
 * single lookup) should omit results scoring below this floor rather than
 * showing a confident-looking "Risk: 50" built from one weak finding.
 */
export const MIN_DISPLAY_RISK_SCORE = 30;

const PLAYBOOKS: readonly Playbook[] = [
  {
    id: "sqli-chain",
    name: "SQL Injection Chain",
    description: "Exploit SQL injection to extract sensitive data and escalate privileges via database access.",
    category: "injection",
    mitreTactics: ["TA0001", "TA0006", "TA0009"],
    steps: [
      {
        order: 1,
        action: "Identify injectable parameter",
        description: "Locate input fields or API parameters vulnerable to SQL injection.",
        findingCategories: ["sql-injection", "injection", "sqli", "vulnerability"],
        severity: "critical",
      },
      {
        order: 2,
        action: "Extract database schema",
        description: "Use UNION-based or error-based techniques to enumerate tables and columns.",
        // `information_disclosure` deliberately excluded: a robots.txt hint
        // or a directory-listing finding does not show a database schema was
        // ever enumerated. `injection` is the real taxonomy category for a
        // confirmed SQL injection finding (see finding-taxonomy.ts), so an
        // actual SQLi finding legitimately supports this step too — the same
        // one finding proving several stages of ONE real vulnerability is
        // correct; a generic disclosure finding proving them is not.
        findingCategories: ["injection", "sql-injection", "vulnerability"],
        severity: "high",
      },
      {
        order: 3,
        action: "Dump sensitive data",
        description: "Extract credentials, PII, or other sensitive records from the database.",
        findingCategories: ["injection", "sql-injection", "data_leak", "leaked_credential", "secret_exposure"],
        severity: "critical",
      },
      {
        order: 4,
        action: "Escalate via database functions",
        description: "Use xp_cmdshell, LOAD_FILE, or similar to gain OS-level access.",
        findingCategories: ["sql-injection", "privilege-escalation", "rce", "vulnerability"],
        severity: "critical",
      },
    ],
  },
  {
    id: "xss-account-takeover",
    name: "XSS to Account Takeover",
    description: "Chain cross-site scripting with session theft to take over user accounts.",
    category: "client-side",
    mitreTactics: ["TA0001", "TA0006", "TA0005"],
    steps: [
      {
        order: 1,
        action: "Inject malicious script",
        description: "Find a reflected or stored XSS vulnerability to inject JavaScript.",
        findingCategories: ["xss", "cross-site-scripting", "reflected-xss", "stored-xss"],
        severity: "high",
      },
      {
        order: 2,
        action: "Steal session tokens",
        description: "Exfiltrate cookies or localStorage tokens via injected script.",
        findingCategories: ["xss", "session-management", "cookie-security", "missing-httponly"],
        severity: "high",
      },
      {
        order: 3,
        action: "Impersonate victim user",
        description: "Use stolen session to access the victim account and perform actions.",
        findingCategories: ["session-management", "authentication", "access-control", "cookie_security"],
        severity: "critical",
      },
    ],
  },
  {
    id: "ssrf-cloud-metadata",
    name: "SSRF Cloud Metadata",
    description: "Exploit server-side request forgery to access cloud instance metadata and steal credentials.",
    category: "server-side",
    mitreTactics: ["TA0001", "TA0006", "TA0008"],
    steps: [
      {
        order: 1,
        action: "Identify SSRF endpoint",
        description: "Find a server-side endpoint that fetches user-supplied URLs.",
        findingCategories: ["ssrf", "server-side-request-forgery", "url-redirect", "open_redirect", "vulnerability"],
        severity: "high",
      },
      {
        order: 2,
        action: "Access cloud metadata service",
        description: "Request http://169.254.169.254/latest/meta-data/ to access instance metadata.",
        findingCategories: ["ssrf", "cloud-misconfiguration", "metadata-exposure", "cloud_exposure", "container_exposure"],
        severity: "critical",
      },
      {
        order: 3,
        action: "Extract IAM credentials",
        description: "Retrieve temporary security credentials from the metadata endpoint.",
        findingCategories: ["ssrf", "credential-exposure", "cloud-misconfiguration", "secret_exposure", "leaked_credential", "cloud_exposure"],
        severity: "critical",
      },
      {
        order: 4,
        action: "Pivot to cloud resources",
        description: "Use stolen IAM credentials to access S3 buckets, databases, or other cloud services.",
        findingCategories: ["cloud-misconfiguration", "privilege-escalation", "lateral-movement", "cloud_exposure", "container_exposure", "infrastructure_disclosure"],
        severity: "critical",
      },
    ],
  },
  {
    id: "subdomain-takeover",
    name: "Subdomain Takeover",
    description: "Claim unclaimed subdomains pointing to deprovisioned services to host malicious content.",
    category: "dns",
    mitreTactics: ["TA0001", "TA0042"],
    steps: [
      {
        order: 1,
        action: "Identify dangling DNS records",
        description: "Find CNAME or A records pointing to deprovisioned cloud services.",
        findingCategories: ["subdomain-takeover", "dns-misconfiguration", "dangling-dns"],
        severity: "high",
      },
      {
        order: 2,
        action: "Verify service is claimable",
        description: "Confirm the target service (S3, Azure, Heroku, etc.) can be registered by an attacker.",
        findingCategories: ["subdomain-takeover", "cloud-misconfiguration", "cloud_exposure"],
        severity: "high",
      },
      {
        order: 3,
        action: "Host malicious content",
        description: "Deploy phishing pages or malware under the trusted subdomain.",
        findingCategories: ["subdomain-takeover", "phishing"],
        severity: "critical",
      },
    ],
  },
  {
    id: "api-auth-bypass",
    name: "API Authentication Bypass",
    description: "Exploit weak API authentication to access unauthorized endpoints and data.",
    category: "api",
    mitreTactics: ["TA0001", "TA0003", "TA0009"],
    steps: [
      {
        order: 1,
        action: "Discover unprotected endpoints",
        description: "Identify API endpoints missing authentication or authorization checks.",
        // `information_disclosure` kept ONLY here: a robots.txt/sitemap hint
        // revealing an API path is genuine (weak) evidence of "an endpoint was
        // discovered" — the one claim it actually supports. It is deliberately
        // absent from every later step, which claim things a disclosure hint
        // says nothing about.
        findingCategories: ["broken-authentication", "missing-auth", "api-security", "idor", "api_exposure", "information_disclosure"],
        severity: "high",
      },
      {
        order: 2,
        action: "Enumerate sensitive resources",
        description: "Access user data, admin panels, or internal APIs without credentials.",
        findingCategories: ["broken-authentication", "access-control", "idor", "api_exposure", "data_leak"],
        severity: "high",
      },
      {
        order: 3,
        action: "Extract or modify data",
        description: "Read sensitive information or perform unauthorized mutations.",
        findingCategories: ["data-exposure", "access-control", "api-security", "data_leak", "api_exposure", "leaked_credential", "secret_exposure"],
        severity: "critical",
      },
    ],
  },
  {
    id: "privilege-escalation",
    name: "Privilege Escalation",
    description: "Escalate from low-privilege access to admin-level control through misconfigurations.",
    category: "access-control",
    mitreTactics: ["TA0004", "TA0003"],
    steps: [
      {
        order: 1,
        action: "Gain initial low-privilege access",
        description: "Obtain a valid low-privilege account through credential stuffing, default creds, or registration.",
        // A generic information-disclosure hint (robots.txt, a directory
        // listing) does not hand over an account — only a real credential or
        // auth-bypass finding does.
        findingCategories: ["default-credentials", "weak-password", "broken-authentication", "leaked_credential", "secret_exposure"],
        severity: "medium",
      },
      {
        order: 2,
        action: "Identify privilege boundaries",
        description: "Map role differences and find endpoints that check roles client-side only.",
        findingCategories: ["access-control", "idor", "broken-access-control", "missing-authorization", "api_exposure"],
        severity: "high",
      },
      {
        order: 3,
        action: "Bypass authorization checks",
        description: "Manipulate requests to access admin functions (parameter tampering, JWT manipulation).",
        findingCategories: ["privilege-escalation", "access-control", "jwt-vulnerability", "broken-access-control", "vulnerability", "api_exposure"],
        severity: "critical",
      },
      {
        order: 4,
        action: "Achieve full administrative access",
        description: "Take over admin account or grant self elevated permissions.",
        findingCategories: ["privilege-escalation", "account-takeover", "access-control", "leaked_credential", "vulnerability"],
        severity: "critical",
      },
    ],
  },
];

export function getPlaybooks(): Playbook[] {
  return [...PLAYBOOKS];
}

/** Normalize a category so hyphen/underscore/space and case differences don't matter
 *  (e.g. "cookie-security", "cookie_security", "Cookie Security" all compare equal). */
function normalizeCategory(c: string): string {
  return c.toLowerCase().replace(/[-_\s]+/g, "");
}

function doesStepMatch(step: PlaybookStep, allFindings: readonly Finding[]): Finding[] {
  const categorySet = new Set(step.findingCategories.map(normalizeCategory));
  return allFindings.filter((f) => categorySet.has(normalizeCategory(f.category ?? "")));
}

function buildRecommendations(
  playbook: Playbook,
  matchedSteps: SimulationResult["matchedSteps"],
): string[] {
  const recommendations: string[] = [];

  if (matchedSteps.length === 0) {
    recommendations.push(
      `No findings match the "${playbook.name}" attack chain. Continue monitoring for new vulnerabilities.`,
    );
    return recommendations;
  }

  for (const { step, matchingFindings } of matchedSteps) {
    const uniqueAssets = [
      ...Array.from(new Set(matchingFindings.map((f) => f.affectedAsset).filter(Boolean))),
    ];
    const assetSuffix = uniqueAssets.length > 0 ? ` on ${uniqueAssets.join(", ")}` : "";
    recommendations.push(
      `Remediate step ${step.order} ("${step.action}"): ${matchingFindings.length} matching finding(s)${assetSuffix}.`,
    );
  }

  const totalSteps = playbook.steps.length;
  const matchedCount = matchedSteps.length;
  const coverage = Math.round((matchedCount / totalSteps) * 100);

  if (coverage >= 75) {
    recommendations.push(
      `CRITICAL: ${coverage}% of the "${playbook.name}" attack chain is viable. Prioritize immediate remediation.`,
    );
  } else if (coverage >= 50) {
    recommendations.push(
      `HIGH: ${coverage}% of the "${playbook.name}" attack chain has matching findings. Address these findings promptly.`,
    );
  } else {
    recommendations.push(
      `MODERATE: ${coverage}% of the "${playbook.name}" attack chain has partial coverage. Monitor and remediate as part of regular vulnerability management.`,
    );
  }

  return recommendations;
}

/**
 * Only open security rows are steps an attacker could take today.
 *
 * A `recon` or `control` row is not a rung on an attack chain, and a
 * REMEDIATED finding is the opposite of one — leaving closed rows in means
 * fixing an issue never clears the path it was part of, so the simulation
 * keeps reporting the organisation as exploitable through a hole that no
 * longer exists.
 */
export function actionableFindings(findings: readonly Finding[]): Finding[] {
  return findings.filter((f) => isSecurityFinding(f) && !CLOSED_STATUSES.has(f.status ?? "open"));
}

/**
 * Matches one playbook against an ALREADY-FETCHED, already-filtered finding
 * set. Pure — no DB access — so a caller checking every playbook against the
 * same workspace (the Attack Paths list) fetches findings once and reuses
 * them, instead of `simulateAttack`'s one-query-per-playbook.
 */
export function matchPlaybook(playbook: Playbook, actionable: readonly Finding[]): SimulationResult {
  const matchedSteps: SimulationResult["matchedSteps"] = [];

  for (const step of playbook.steps) {
    const matching = doesStepMatch(step, actionable);
    if (matching.length > 0) {
      matchedSteps.push({ step, matchingFindings: matching });
    }
  }

  const coverageExploitable = matchedSteps.length >= Math.ceil(playbook.steps.length * 0.5);

  const rawRiskScore = Math.min(
    100,
    Math.round(
      (matchedSteps.length / playbook.steps.length) * 100 *
        (coverageExploitable ? 1.0 : 0.6),
    ),
  );

  // A "chain" whose entire matched evidence reduces to ONE finding is not a
  // chain — it is one weak, generic signal (e.g. "Robots.txt Reveals Sensitive
  // Paths") stretched across several steps that each claim something the
  // finding does not actually show. This is deliberately narrower than "any
  // finding shared by two steps": several playbooks legitimately let one
  // strong, specific finding (a confirmed SQLi, a real exposed API) evidence
  // multiple adjacent stages of the SAME vulnerability, and that is correct,
  // not a stretch — see the SQL-injection-chain category comments above. What
  // is never legitimate is the WHOLE chain resting on a single finding.
  const distinctFindingIds = new Set(matchedSteps.flatMap(({ matchingFindings }) => matchingFindings.map((f) => f.id)));
  const lowConfidence = matchedSteps.length >= 2 && distinctFindingIds.size === 1;

  const exploitable = coverageExploitable && !lowConfidence;
  const riskScore = lowConfidence ? Math.min(rawRiskScore, 35) : rawRiskScore;

  const recommendations = buildRecommendations(playbook, matchedSteps);

  return { playbook, exploitable, matchedSteps, riskScore, recommendations, lowConfidence };
}

/**
 * Simulate ONE attack playbook against real findings in a workspace. Fetches
 * findings itself, so a caller checking multiple playbooks against the same
 * workspace should fetch once with `storage.getFindings` + `actionableFindings`
 * and call `matchPlaybook` directly instead (see `GET .../attack-paths`).
 */
export async function simulateAttack(
  workspaceId: string,
  playbookId: string,
): Promise<SimulationResult> {
  try {
    const playbook = PLAYBOOKS.find((p) => p.id === playbookId);
    if (!playbook) {
      log.warn({ playbookId }, "Unknown playbook requested");
      throw new Error(`Playbook not found: ${playbookId}`);
    }

    const result = await storage.getFindings(workspaceId, { limit: 10000 });
    const allFindings = actionableFindings(result.data);

    log.info(
      {
        workspaceId,
        playbookId,
        findingsCount: allFindings.length,
        totalRows: result.data.length,
      },
      "Running attack simulation",
    );

    const matched = matchPlaybook(playbook, allFindings);

    log.info(
      {
        playbookId,
        exploitable: matched.exploitable,
        matchedSteps: matched.matchedSteps.length,
        totalSteps: playbook.steps.length,
        riskScore: matched.riskScore,
      },
      "Attack simulation complete",
    );

    return matched;
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Unknown error";
    log.error({ workspaceId, playbookId, error: message }, "Attack simulation failed");
    throw new Error(`Attack simulation failed: ${message}`);
  }
}
