/**
 * Content-Security-Policy analysis.
 *
 * The check was `!!headers.get("content-security-policy")`, so a site publishing
 * `script-src * 'unsafe-inline' 'unsafe-eval'` passed. Presence was standing in
 * for protection.
 *
 * Half of these tests assert that a CORRECT policy produces NO finding. That is
 * the harder half: naive CSP checkers reliably fire on nonce-based policies and
 * on `strict-dynamic`, both of which are the recommended modern configuration,
 * and a checker that punishes the right answer trains people to ignore it.
 */
import { describe, it, expect } from "vitest";
import { parseCsp, analyzeCsp, buildCspFinding } from "../../../server/scanner/csp-analysis";

const issues = (header: string | null, reportOnly?: string | null) =>
  analyzeCsp(header, reportOnly).weaknesses.map((w) => `${w.directive}: ${w.issue}`).join(" | ");

describe("parseCsp", () => {
  it("splits directives and source lists", () => {
    expect(parseCsp("default-src 'self'; script-src 'self' https://cdn.example.com")).toEqual({
      "default-src": ["'self'"],
      "script-src": ["'self'", "https://cdn.example.com"],
    });
  });

  it("lowercases directive names but preserves source case", () => {
    // A nonce is case-sensitive; the directive name is not.
    expect(parseCsp("Script-SRC 'nonce-AbC123'")).toEqual({ "script-src": ["'nonce-AbC123'"] });
  });

  it("keeps only the first of a repeated directive, as browsers do", () => {
    expect(parseCsp("script-src 'self'; script-src *")["script-src"]).toEqual(["'self'"]);
  });

  it("tolerates trailing semicolons and extra whitespace", () => {
    expect(parseCsp("  default-src   'self' ;; ")).toEqual({ "default-src": ["'self'"] });
  });
});

describe("policies that are genuinely weak", () => {
  it("flags unsafe-inline when there is no nonce or hash", () => {
    expect(issues("script-src 'self' 'unsafe-inline'")).toMatch(/unsafe-inline/);
  });

  it("flags unsafe-eval", () => {
    expect(issues("script-src 'self' 'unsafe-eval'; base-uri 'none'")).toMatch(/unsafe-eval/);
  });

  it("flags a wildcard script source", () => {
    expect(issues("script-src *; base-uri 'none'")).toMatch(/any origin/);
    expect(issues("script-src https:; base-uri 'none'")).toMatch(/any origin/);
    expect(issues("script-src 'self' data:; base-uri 'none'")).toMatch(/any origin/);
  });

  /** Scripts are unrestricted regardless of what else the policy contains. */
  it("flags a policy with neither script-src nor default-src", () => {
    const a = analyzeCsp("img-src 'self'");
    expect(a.weaknesses.some((w) => w.directive === "script-src" && w.severity === "high")).toBe(true);
  });

  it("flags a report-only policy as enforcing nothing", () => {
    const a = analyzeCsp(null, "script-src 'self'; base-uri 'none'");
    expect(a.reportOnly).toBe(true);
    expect(a.present).toBe(false);
    expect(issues(null, "script-src 'self'; base-uri 'none'")).toMatch(/nothing is blocked/);
  });

  /** An injected <base> tag defeats an otherwise correct nonce policy. */
  it("flags missing base-uri, and rates it higher when a nonce is in use", () => {
    const withNonce = analyzeCsp("script-src 'nonce-abc123'");
    const baseIssue = withNonce.weaknesses.find((w) => w.directive === "base-uri");
    expect(baseIssue?.severity).toBe("medium");

    const withoutNonce = analyzeCsp("script-src 'self'");
    expect(withoutNonce.weaknesses.find((w) => w.directive === "base-uri")?.severity).toBe("low");
  });

  it("notes a trailing-wildcard host as a lesser weakness", () => {
    const a = analyzeCsp("script-src 'self' *.example.com; base-uri 'none'");
    expect(a.weaknesses.some((w) => w.severity === "low" && /every host under/.test(w.issue))).toBe(true);
  });
});

describe("policies that are CORRECT and must not be flagged", () => {
  /**
   * The classic false positive. CSP Level 2 browsers IGNORE 'unsafe-inline'
   * when a nonce is present, and including it is the documented way to remain
   * compatible with CSP1 browsers — so flagging it penalises the recommended
   * configuration.
   */
  it("does not flag unsafe-inline alongside a nonce", () => {
    expect(issues("script-src 'nonce-r4nd0m' 'unsafe-inline'; base-uri 'none'")).not.toMatch(/unsafe-inline/);
  });

  it("does not flag unsafe-inline alongside a hash", () => {
    expect(issues("script-src 'sha256-abc123=' 'unsafe-inline'; base-uri 'none'")).not.toMatch(/unsafe-inline/);
  });

  /**
   * Under 'strict-dynamic' browsers ignore the host allowlist entirely and trust
   * only nonced scripts, so a wildcard beside it is not the hole it appears.
   */
  it("does not flag a host allowlist under strict-dynamic", () => {
    const header = "script-src 'nonce-abc' 'strict-dynamic' https: *; base-uri 'none'; object-src 'none'";
    expect(analyzeCsp(header).weaknesses).toEqual([]);
  });

  it("reports no weakness for a well-built policy", () => {
    const header = "default-src 'self'; script-src 'nonce-abc123'; base-uri 'none'; object-src 'none'";
    const a = analyzeCsp(header);
    expect(a.weaknesses).toEqual([]);
    expect(a.usesNonceOrHash).toBe(true);
  });

  /** A missing header is the OTHER finding; this analyser must stay quiet. */
  it("says nothing when there is no policy at all", () => {
    const a = analyzeCsp(null, null);
    expect(a.present).toBe(false);
    expect(a.weaknesses).toEqual([]);
  });
});

describe("buildCspFinding", () => {
  /** A policy is one artefact with one fix; four rows for four directives is noise. */
  it("emits ONE finding listing every weakness", () => {
    const header = "script-src * 'unsafe-inline' 'unsafe-eval'";
    const f = buildCspFinding("app.example.com", "https://app.example.com", header, analyzeCsp(header));
    expect(f).not.toBeNull();
    expect(f!.severity).toBe("high");
    expect((f!.evidence.weaknesses as unknown[]).length).toBeGreaterThan(1);
    expect(f!.description).toMatch(/unsafe-inline/);
    expect(f!.description).toMatch(/unsafe-eval/);
  });

  it("returns null for a policy with no weaknesses", () => {
    const header = "script-src 'nonce-abc'; base-uri 'none'; object-src 'none'";
    expect(buildCspFinding("app.example.com", "https://app.example.com", header, analyzeCsp(header))).toBeNull();
  });

  it("titles a report-only policy differently, because the fix differs", () => {
    const header = "script-src 'self'; base-uri 'none'";
    const f = buildCspFinding("app.example.com", "https://app.example.com", header, analyzeCsp(null, header));
    expect(f!.title).toMatch(/report-only/i);
  });

  it("takes the worst severity across weaknesses", () => {
    const header = "script-src 'self' 'unsafe-eval'; base-uri 'none'";
    const f = buildCspFinding("app.example.com", "https://app.example.com", header, analyzeCsp(header));
    expect(f!.severity).toBe("medium");
  });
});
