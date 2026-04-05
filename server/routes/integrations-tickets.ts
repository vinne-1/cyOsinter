/**
 * Jira & GitHub Issues integration: create tickets from findings.
 * Credentials stored per-workspace in integrations config.
 */

import { Router } from "express";
import { z } from "zod";
import { storage } from "../storage";
import { createLogger } from "../logger";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";
import { encryptObject, decryptObject } from "../crypto";
import { isPrivateHost } from "../utils/ssrf.js";

const log = createLogger("integrations-tickets");

const INTEGRATIONS_CONFIG_PATH = join(process.cwd(), ".local", "integrations.json");

interface TicketingConfig {
  jira?: {
    baseUrl: string;
    email: string;
    apiToken: string;
    projectKey: string;
  };
  github?: {
    token: string;
    owner: string;
    repo: string;
  };
}

function loadTicketingConfig(): TicketingConfig {
  try {
    if (!existsSync(INTEGRATIONS_CONFIG_PATH)) return {};
    const raw = readFileSync(INTEGRATIONS_CONFIG_PATH, "utf-8").trim();
    // Try encrypted format first (base64 blob), fall back to legacy JSON
    try {
      return decryptObject<TicketingConfig>(raw);
    } catch {
      // Legacy plaintext JSON — migrate on next save
      const data = JSON.parse(raw) as Record<string, unknown>;
      return {
        jira: data.jira as TicketingConfig["jira"],
        github: data.github as TicketingConfig["github"],
      };
    }
  } catch {
    return {};
  }
}

function saveTicketingConfig(config: TicketingConfig): void {
  try {
    const dir = join(process.cwd(), ".local");
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    // Merge with existing config
    const existing = loadTicketingConfig();
    if (config.jira) existing.jira = config.jira;
    if (config.github) existing.github = config.github;
    // Write encrypted
    writeFileSync(INTEGRATIONS_CONFIG_PATH, encryptObject(existing as unknown as Record<string, unknown>), "utf-8");
  } catch (err) {
    log.warn({ err }, "Failed to save ticketing config");
  }
}

function severityToJiraPriority(severity: string): string {
  switch (severity) {
    case "critical": return "Highest";
    case "high": return "High";
    case "medium": return "Medium";
    case "low": return "Low";
    default: return "Lowest";
  }
}

function severityToLabel(severity: string): string {
  switch (severity) {
    case "critical": return "priority:critical";
    case "high": return "priority:high";
    case "medium": return "priority:medium";
    case "low": return "priority:low";
    default: return "priority:info";
  }
}

const jiraConfigSchema = z.object({
  baseUrl: z.string().url("Must be a valid URL"),
  email: z.string().email("Must be a valid email"),
  apiToken: z.string().min(1, "API token is required"),
  projectKey: z.string().min(1, "Project key is required"),
});

const githubConfigSchema = z.object({
  token: z.string().min(1, "Token is required"),
  owner: z.string().min(1, "Repository owner is required"),
  repo: z.string().min(1, "Repository name is required"),
});

const createTicketSchema = z.object({
  findingId: z.string().min(1),
  provider: z.enum(["jira", "github"]),
});

const bulkCreateTicketSchema = z.object({
  findingIds: z.array(z.string().min(1)).min(1).max(50),
  provider: z.enum(["jira", "github"]),
});

export const integrationsTicketsRouter = Router();

// GET /api/integrations/ticketing — show connection status
integrationsTicketsRouter.get("/integrations/ticketing", (_req, res) => {
  const config = loadTicketingConfig();
  res.json({
    jira: {
      configured: !!(config.jira?.baseUrl && config.jira?.apiToken),
      projectKey: config.jira?.projectKey ?? null,
    },
    github: {
      configured: !!(config.github?.token && config.github?.owner),
      owner: config.github?.owner ?? null,
      repo: config.github?.repo ?? null,
    },
  });
});

// PUT /api/integrations/ticketing/jira — save Jira config
integrationsTicketsRouter.put("/integrations/ticketing/jira", async (req, res) => {
  try {
    const parsed = jiraConfigSchema.parse(req.body);
    // SSRF protection: reject private/loopback Jira URLs
    const jiraHost = new URL(parsed.baseUrl).hostname;
    if (await isPrivateHost(jiraHost)) {
      return res.status(400).json({ message: "Jira URL must not target private or internal networks" });
    }
    const config = loadTicketingConfig();
    config.jira = parsed;
    saveTicketingConfig(config);
    res.json({ success: true });
  } catch (err) {
    if (err instanceof z.ZodError) return res.status(400).json({ message: err.errors[0]?.message });
    res.status(500).json({ message: "Internal server error" });
  }
});

// PUT /api/integrations/ticketing/github — save GitHub config
integrationsTicketsRouter.put("/integrations/ticketing/github", (req, res) => {
  try {
    const parsed = githubConfigSchema.parse(req.body);
    const config = loadTicketingConfig();
    config.github = parsed;
    saveTicketingConfig(config);
    res.json({ success: true });
  } catch (err) {
    if (err instanceof z.ZodError) return res.status(400).json({ message: err.errors[0]?.message });
    res.status(500).json({ message: "Internal server error" });
  }
});

// POST /api/integrations/ticketing/create — create a single ticket
integrationsTicketsRouter.post("/integrations/ticketing/create", async (req, res) => {
  try {
    const { findingId, provider } = createTicketSchema.parse(req.body);
    const finding = await storage.getFinding(findingId);
    if (!finding) return res.status(404).json({ message: "Finding not found" });

    const config = loadTicketingConfig();
    let ticketUrl: string;

    if (provider === "jira") {
      if (!config.jira?.baseUrl || !config.jira?.apiToken) {
        return res.status(400).json({ message: "Jira is not configured" });
      }
      ticketUrl = await createJiraTicket(config.jira, finding);
    } else {
      if (!config.github?.token || !config.github?.owner) {
        return res.status(400).json({ message: "GitHub is not configured" });
      }
      ticketUrl = await createGitHubIssue(config.github, finding);
    }

    // Update finding with ticket reference
    const existing = (finding.aiEnrichment as Record<string, unknown>) ?? {};
    await storage.updateFinding(finding.id, {
      aiEnrichment: { ...existing, ticketUrl, ticketProvider: provider, ticketCreatedAt: new Date().toISOString() },
    });

    res.json({ ticketUrl });
  } catch (err) {
    log.error({ err }, "Failed to create ticket");
    if (err instanceof z.ZodError) return res.status(400).json({ message: err.errors[0]?.message });
    res.status(500).json({ message: "Internal server error" });
  }
});

// POST /api/integrations/ticketing/bulk-create — create tickets for multiple findings
integrationsTicketsRouter.post("/integrations/ticketing/bulk-create", async (req, res) => {
  try {
    const { findingIds, provider } = bulkCreateTicketSchema.parse(req.body);
    const config = loadTicketingConfig();

    if (provider === "jira" && (!config.jira?.baseUrl || !config.jira?.apiToken)) {
      return res.status(400).json({ message: "Jira is not configured" });
    }
    if (provider === "github" && (!config.github?.token || !config.github?.owner)) {
      return res.status(400).json({ message: "GitHub is not configured" });
    }

    const results: Array<{ findingId: string; ticketUrl?: string; error?: string }> = [];

    for (const findingId of findingIds) {
      try {
        const finding = await storage.getFinding(findingId);
        if (!finding) {
          results.push({ findingId, error: "Not found" });
          continue;
        }

        let ticketUrl: string;
        if (provider === "jira") {
          ticketUrl = await createJiraTicket(config.jira!, finding);
        } else {
          ticketUrl = await createGitHubIssue(config.github!, finding);
        }

        const existing = (finding.aiEnrichment as Record<string, unknown>) ?? {};
        await storage.updateFinding(finding.id, {
          aiEnrichment: { ...existing, ticketUrl, ticketProvider: provider, ticketCreatedAt: new Date().toISOString() },
        });
        results.push({ findingId, ticketUrl });
      } catch (err) {
        results.push({ findingId, error: "Failed" });
      }
    }

    res.json({ results });
  } catch (err) {
    if (err instanceof z.ZodError) return res.status(400).json({ message: err.errors[0]?.message });
    res.status(500).json({ message: "Internal server error" });
  }
});

// DELETE /api/integrations/ticketing/jira — remove Jira config
integrationsTicketsRouter.delete("/integrations/ticketing/jira", (_req, res) => {
  try {
    const config = loadTicketingConfig();
    delete config.jira;
    const dir = join(process.cwd(), ".local");
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(INTEGRATIONS_CONFIG_PATH, encryptObject(config as unknown as Record<string, unknown>), "utf-8");
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ message: "Internal server error" });
  }
});

// DELETE /api/integrations/ticketing/github — remove GitHub config
integrationsTicketsRouter.delete("/integrations/ticketing/github", (_req, res) => {
  try {
    const config = loadTicketingConfig();
    delete config.github;
    const dir = join(process.cwd(), ".local");
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(INTEGRATIONS_CONFIG_PATH, encryptObject(config as unknown as Record<string, unknown>), "utf-8");
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ message: "Internal server error" });
  }
});

// ── Provider implementations ──

interface FindingLike {
  id: string;
  title: string;
  description: string;
  severity: string;
  category: string;
  affectedAsset: string | null;
  remediation: string | null;
  cvssScore: string | null;
}

async function createJiraTicket(
  config: NonNullable<TicketingConfig["jira"]>,
  finding: FindingLike,
): Promise<string> {
  const bodyAdf = {
    type: "doc",
    version: 1,
    content: [
      { type: "heading", attrs: { level: 2 }, content: [{ type: "text", text: "Finding Details" }] },
      { type: "paragraph", content: [{ type: "text", text: finding.description }] },
      { type: "heading", attrs: { level: 3 }, content: [{ type: "text", text: "Details" }] },
      {
        type: "bulletList",
        content: [
          { type: "listItem", content: [{ type: "paragraph", content: [{ type: "text", text: `Severity: ${finding.severity.toUpperCase()}` }] }] },
          { type: "listItem", content: [{ type: "paragraph", content: [{ type: "text", text: `Category: ${finding.category}` }] }] },
          { type: "listItem", content: [{ type: "paragraph", content: [{ type: "text", text: `Affected Asset: ${finding.affectedAsset ?? "N/A"}` }] }] },
          ...(finding.cvssScore ? [{ type: "listItem" as const, content: [{ type: "paragraph" as const, content: [{ type: "text" as const, text: `CVSS Score: ${finding.cvssScore}` }] }] }] : []),
        ],
      },
      ...(finding.remediation
        ? [
            { type: "heading" as const, attrs: { level: 3 }, content: [{ type: "text" as const, text: "Remediation" }] },
            { type: "paragraph" as const, content: [{ type: "text" as const, text: finding.remediation }] },
          ]
        : []),
    ],
  };

  const baseUrl = config.baseUrl.replace(/\/+$/, "");
  // Re-validate SSRF at request time (URL may have been saved before check existed)
  const jiraHost = new URL(baseUrl).hostname;
  if (await isPrivateHost(jiraHost)) {
    throw new Error("Jira URL targets a private network — update your Jira configuration");
  }
  const res = await fetch(`${baseUrl}/rest/api/3/issue`, {
    method: "POST",
    headers: {
      "Authorization": `Basic ${Buffer.from(`${config.email}:${config.apiToken}`).toString("base64")}`,
      "Content-Type": "application/json",
      "Accept": "application/json",
    },
    body: JSON.stringify({
      fields: {
        project: { key: config.projectKey },
        summary: `[${finding.severity.toUpperCase()}] ${finding.title}`,
        description: bodyAdf,
        issuetype: { name: "Bug" },
        priority: { name: severityToJiraPriority(finding.severity) },
        labels: ["security", severityToLabel(finding.severity), `category:${finding.category}`],
      },
    }),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Jira API error ${res.status}: ${text.substring(0, 300)}`);
  }

  const data = (await res.json()) as { key?: string };
  return `${baseUrl}/browse/${data.key}`;
}

async function createGitHubIssue(
  config: NonNullable<TicketingConfig["github"]>,
  finding: FindingLike,
): Promise<string> {
  const body = [
    `## ${finding.title}`,
    "",
    finding.description,
    "",
    "### Details",
    `- **Severity:** ${finding.severity.toUpperCase()}`,
    `- **Category:** ${finding.category}`,
    `- **Affected Asset:** ${finding.affectedAsset ?? "N/A"}`,
    ...(finding.cvssScore ? [`- **CVSS Score:** ${finding.cvssScore}`] : []),
    ...(finding.remediation ? ["", "### Remediation", finding.remediation] : []),
    "",
    `> Created by Cyber Shield Pro`,
  ].join("\n");

  const owner = encodeURIComponent(config.owner);
  const repo = encodeURIComponent(config.repo);

  const res = await fetch(`https://api.github.com/repos/${owner}/${repo}/issues`, {
    method: "POST",
    headers: {
      Authorization: `token ${config.token}`,
      "Content-Type": "application/json",
      Accept: "application/vnd.github.v3+json",
    },
    body: JSON.stringify({
      title: `[${finding.severity.toUpperCase()}] ${finding.title}`,
      body,
      labels: ["security", severityToLabel(finding.severity)],
    }),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`GitHub API error ${res.status}: ${text.substring(0, 300)}`);
  }

  const data = (await res.json()) as { html_url?: string };
  return data.html_url ?? "";
}
