import { describe, expect, it } from "vitest";
import {
  buildAiFollowUpReport,
  chooseFollowUpChecks,
  hostsForFollowUp,
  resolveVerifiableTarget,
  themesFromFindings,
  type FollowUpCheckId,
  type FollowUpCheckResult,
} from "../../../server/ai-follow-up";

const hsts = {
  id: "f-1",
  title: "Missing HSTS",
  severity: "medium",
  category: "transport_security",
  affectedAsset: "www.example.com",
  status: "open",
  description: "The apex does not send Strict-Transport-Security.",
  remediation: "Send a Strict-Transport-Security header.",
};

describe("hostsForFollowUp", () => {
  it("keeps the apex and in-scope hosts, and drops everything else", () => {
    const hosts = hostsForFollowUp("example.com", [
      "www.example.com",
      "https://api.example.com/login",
      "example.com.evil.net",
      "notexample.com",
      "1.2.3.4",
      "Bigbaskt",
    ]);
    expect(hosts).toEqual(["example.com", "www.example.com", "api.example.com"]);
  });

  it("caps the host list", () => {
    const assets = ["a", "b", "c", "d", "e", "f"].map((label) => `${label}.example.com`);
    expect(hostsForFollowUp("example.com", assets, 3)).toHaveLength(3);
  });
});

describe("resolveVerifiableTarget", () => {
  // Regression: a workspace with no `domain` set and a NAME that is a label,
  // not a hostname ("zepto" for a workspace scanned against "zepto.com"),
  // made manual "Regenerate" on AI Insights show "No usable domain to verify
  // for this workspace" even though the workspace held findings whose
  // affectedAsset was the perfectly usable "zepto.com".
  it("falls back to a finding's affectedAsset when no candidate is a usable domain", () => {
    const result = resolveVerifiableTarget(["zepto", undefined], [
      { affectedAsset: "zepto.com" },
    ]);
    expect(result).toBe("zepto.com");
  });

  it("prefers the first usable candidate over the findings", () => {
    const result = resolveVerifiableTarget(["example.com", "zepto"], [
      { affectedAsset: "other.com" },
    ]);
    expect(result).toBe("example.com");
  });

  it("returns null when nothing is usable", () => {
    const result = resolveVerifiableTarget(["zepto", null], [{ affectedAsset: null }, { affectedAsset: "Bigbaskt" }]);
    expect(result).toBeNull();
  });
});

describe("chooseFollowUpChecks", () => {
  it("keeps only allowlisted ids the model named", () => {
    expect(chooseFollowUpChecks(["transport_security"], ["dnssec", "zone_transfer", "dnssec"])).toEqual(["dnssec"]);
  });

  it("falls back to the categories when the model names nothing usable", () => {
    expect(chooseFollowUpChecks(["transport_security", "email_security"], [])).toEqual([
      "security_headers",
      "tls_versions",
      "mail_auth",
    ]);
  });
});

describe("buildAiFollowUpReport", () => {
  it("consolidates with the model, runs only the checks it named, and writes the narrative", async () => {
    const ran: FollowUpCheckId[] = [];
    const segment = await buildAiFollowUpReport({
      workspaceName: "Example",
      domain: "example.com",
      findings: [hsts],
      model: "glm-4.5-flash",
      complete: async (prompt) => {
        if (prompt.includes("FOLLOW-UP CHECKS")) {
          return JSON.stringify({
            narrative: "One medium transport issue. The header check confirmed HSTS is still missing.",
            nextSteps: ["Add HSTS on www.example.com"],
          });
        }
        return JSON.stringify({
          themes: [{
            title: "Transport security",
            severity: "medium",
            findingIds: ["f-1", "not-a-real-id"],
            narrative: "HSTS is missing on the site.",
            action: "Send Strict-Transport-Security.",
          }],
          checks: ["security_headers", "nuclei"],
        });
      },
      runCheck: async (id) => {
        ran.push(id);
        const result: FollowUpCheckResult = {
          id,
          label: id,
          status: "completed",
          summary: "www.example.com: HTTP 200, missing strict-transport-security",
        };
        return result;
      },
    });

    expect(ran).toEqual(["security_headers"]);
    expect(segment.generatedBy).toBe("glm");
    expect(segment.themes[0]?.findingIds).toEqual(["f-1"]);
    expect(segment.narrative).toContain("HSTS is still missing");
    expect(segment.nextSteps).toEqual(["Add HSTS on www.example.com"]);
    expect(segment.domain).toBe("example.com");
  });

  it("still groups findings and skips checks when the model is unavailable and the workspace has no domain", async () => {
    const segment = await buildAiFollowUpReport({
      workspaceName: "Bigbaskt",
      domain: "Bigbaskt",
      findings: [hsts],
      complete: async () => {
        throw new Error("GLM is not configured");
      },
    });

    expect(segment.generatedBy).toBe("rules");
    expect(segment.domain).toBeNull();
    expect(segment.themes.map((theme) => theme.title)).toEqual(["transport security"]);
    expect(segment.checks.length).toBeGreaterThan(0);
    expect(segment.checks.every((check) => check.status === "skipped")).toBe(true);
    expect(segment.narrative).toContain("this workspace");
    expect(segment.checks[0]?.summary).toContain("No usable workspace domain");
    expect(themesFromFindings([hsts])[0]?.findingIds).toEqual(["f-1"]);
  });

  it("does not report 'glm' when the model returns JSON but every theme fails validation", async () => {
    // The plan call returns parseable JSON, so a naive `if (planned) generatedBy = "glm"`
    // would mark this as AI-generated — but every theme is missing required
    // fields, so `asThemes` rejects all of them and `themes` stays the
    // `themesFromFindings` rule-based fallback. Reporting "glm" here would
    // label rule-based content as AI output, which is what the UI's
    // "Written by GLM" badge asserts to the reader.
    const segment = await buildAiFollowUpReport({
      workspaceName: "Example",
      domain: "example.com",
      findings: [hsts],
      complete: async (prompt) => {
        if (prompt.includes("FOLLOW-UP CHECKS")) {
          throw new Error("write step should not run when themes are rule-based");
        }
        return JSON.stringify({
          themes: [{ severity: "medium" }], // no title, no narrative — asThemes rejects it
          checks: ["security_headers"],
        });
      },
    });

    expect(segment.generatedBy).toBe("rules");
    expect(segment.themes.map((theme) => theme.title)).toEqual(["transport security"]);
  });
});
