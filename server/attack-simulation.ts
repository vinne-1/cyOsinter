import { createLogger } from "./logger";
import { storage } from "./storage";
import type { Finding } from "@shared/schema";

const log = createLogger("attack-simulation");

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
}

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
        findingCategories: ["sql-injection", "injection", "sqli"],
        severity: "critical",
      },
      {
        order: 2,
        action: "Extract database schema",
        description: "Use UNION-based or error-based techniques to enumerate tables and columns.",
        findingCategories: ["sql-injection", "information-disclosure", "error-handling"],
        severity: "high",
      },
      {
        order: 3,
        action: "Dump sensitive data",
        description: "Extract credentials, PII, or other sensitive records from the database.",
        findingCategories: ["sql-injection", "sensitive-data", "data-exposure"],
        severity: "critical",
      },
      {
        order: 4,
        action: "Escalate via database functions",
        description: "Use xp_cmdshell, LOAD_FILE, or similar to gain OS-level access.",
        findingCategories: ["sql-injection", "privilege-escalation", "rce"],
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
        findingCategories: ["session-management", "authentication", "access-control"],
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
        findingCategories: ["ssrf", "server-side-request-forgery", "url-redirect"],
        severity: "high",
      },
      {
        order: 2,
        action: "Access cloud metadata service",
        description: "Request http://169.254.169.254/latest/meta-data/ to access instance metadata.",
        findingCategories: ["ssrf", "cloud-misconfiguration", "metadata-exposure"],
        severity: "critical",
      },
      {
        order: 3,
        action: "Extract IAM credentials",
        description: "Retrieve temporary security credentials from the metadata endpoint.",
        findingCategories: ["ssrf", "credential-exposure", "cloud-misconfiguration"],
        severity: "critical",
      },
      {
        order: 4,
        action: "Pivot to cloud resources",
        description: "Use stolen IAM credentials to access S3 buckets, databases, or other cloud services.",
        findingCategories: ["cloud-misconfiguration", "privilege-escalation", "lateral-movement"],
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
        findingCategories: ["subdomain-takeover", "cloud-misconfiguration"],
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
        findingCategories: ["broken-authentication", "missing-auth", "api-security", "idor"],
        severity: "high",
      },
      {
        order: 2,
        action: "Enumerate sensitive resources",
        description: "Access user data, admin panels, or internal APIs without credentials.",
        findingCategories: ["broken-authentication", "access-control", "idor", "information-disclosure"],
        severity: "high",
      },
      {
        order: 3,
        action: "Extract or modify data",
        description: "Read sensitive information or perform unauthorized mutations.",
        findingCategories: ["data-exposure", "access-control", "api-security"],
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
        findingCategories: ["default-credentials", "weak-password", "broken-authentication"],
        severity: "medium",
      },
      {
        order: 2,
        action: "Identify privilege boundaries",
        description: "Map role differences and find endpoints that check roles client-side only.",
        findingCategories: ["access-control", "idor", "broken-access-control", "missing-authorization"],
        severity: "high",
      },
      {
        order: 3,
        action: "Bypass authorization checks",
        description: "Manipulate requests to access admin functions (parameter tampering, JWT manipulation).",
        findingCategories: ["privilege-escalation", "access-control", "jwt-vulnerability", "broken-access-control"],
        severity: "critical",
      },
      {
        order: 4,
        action: "Achieve full administrative access",
        description: "Take over admin account or grant self elevated permissions.",
        findingCategories: ["privilege-escalation", "account-takeover", "access-control"],
        severity: "critical",
      },
    ],
  },
];

export function getPlaybooks(): Playbook[] {
  return [...PLAYBOOKS];
}

function doesStepMatch(step: PlaybookStep, allFindings: readonly Finding[]): Finding[] {
  const categorySet = new Set(step.findingCategories.map((c) => c.toLowerCase()));
  return allFindings.filter((f) => {
    const findingCategory = (f.category ?? "").toLowerCase();
    return categorySet.has(findingCategory);
  });
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
 * Simulate an attack playbook against real findings in a workspace.
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
    const allFindings = result.data;

    log.info(
      { workspaceId, playbookId, findingsCount: allFindings.length },
      "Running attack simulation",
    );

    const matchedSteps: SimulationResult["matchedSteps"] = [];

    for (const step of playbook.steps) {
      const matching = doesStepMatch(step, allFindings);
      if (matching.length > 0) {
        matchedSteps.push({ step, matchingFindings: matching });
      }
    }

    const exploitable = matchedSteps.length >= Math.ceil(playbook.steps.length * 0.5);

    const riskScore = Math.min(
      100,
      Math.round(
        (matchedSteps.length / playbook.steps.length) * 100 *
          (exploitable ? 1.0 : 0.6),
      ),
    );

    const recommendations = buildRecommendations(playbook, matchedSteps);

    log.info(
      {
        playbookId,
        exploitable,
        matchedSteps: matchedSteps.length,
        totalSteps: playbook.steps.length,
        riskScore,
      },
      "Attack simulation complete",
    );

    return { playbook, exploitable, matchedSteps, riskScore, recommendations };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Unknown error";
    log.error({ workspaceId, playbookId, error: message }, "Attack simulation failed");
    throw new Error(`Attack simulation failed: ${message}`);
  }
}
