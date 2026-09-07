/**
 * Content-Security-Policy analysis — the policy's CONTENT, not its presence.
 *
 * The header was checked with `!!res.headers.get("content-security-policy")`.
 * A site publishing
 *
 *     Content-Security-Policy: default-src *; script-src * 'unsafe-inline' 'unsafe-eval'
 *
 * therefore passed, while a policy like that stops essentially no XSS. Presence
 * was standing in for protection, which is the same "a 200 is not evidence"
 * mistake in a different place: the header existing is not the control working.
 *
 * ## The three nuances that make naive CSP checkers wrong
 *
 * Most CSP linters flag these incorrectly, and each produces a confident false
 * positive against a *correctly* configured modern policy:
 *
 *  1. **`'unsafe-inline'` is IGNORED when a nonce or hash is present.** CSP
 *     Level 2 browsers drop it entirely in that case, and including it is the
 *     documented way to stay compatible with CSP1 browsers. Flagging it there
 *     penalises the recommended configuration.
 *  2. **`'strict-dynamic'` makes host allowlists ignored.** A `*` sitting beside
 *     `'strict-dynamic'` is not the hole it looks like — browsers that
 *     understand the keyword disregard the list and trust only nonced scripts.
 *  3. **Report-Only enforces NOTHING.** `Content-Security-Policy-Report-Only` is
 *     a measurement tool. Treating it as protection is worse than seeing no
 *     header at all, because it looks like a control is in place.
 *
 * ## What actually defeats a policy
 *
 * `base-uri` deserves its place here: without it, an injected `<base>` tag
 * redirects every relative script URL to an attacker's origin, which defeats a
 * nonce-based policy that is otherwise correct. It is the most commonly missing
 * directive in policies that look strong.
 */

export interface CspWeakness {
  directive: string;
  issue: string;
  severity: "high" | "medium" | "low";
}

export interface CspAnalysis {
  present: boolean;
  /** True when the only policy is Report-Only, which enforces nothing. */
  reportOnly: boolean;
  directives: Record<string, string[]>;
  weaknesses: CspWeakness[];
  /** True when a nonce or hash is used, which changes how 'unsafe-inline' reads. */
  usesNonceOrHash: boolean;
  usesStrictDynamic: boolean;
}

/** Sources that permit essentially any script origin. */
const WILDCARD_SOURCES = new Set(["*", "http:", "https:", "data:", "blob:"]);

/**
 * Parses a policy into directive → source-list.
 *
 * Directive names are case-insensitive per the spec; source values are not
 * (a nonce is case-sensitive), so only the name is lowercased.
 */
export function parseCsp(header: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const part of header.split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const name = tokens[0].toLowerCase();
    // A repeated directive is ignored by browsers after the first occurrence.
    if (!(name in out)) out[name] = tokens.slice(1);
  }
  return out;
}

/**
 * Assesses a policy.
 *
 * `enforced` is the `Content-Security-Policy` header; `reportOnlyHeader` is
 * `Content-Security-Policy-Report-Only`. Both are needed because a site with
 * only the latter has no enforcement, and saying so is the point.
 */
export function analyzeCsp(
  enforced: string | null | undefined,
  reportOnlyHeader?: string | null,
): CspAnalysis {
  const header = enforced?.trim() || "";
  const reportOnly = !header && Boolean(reportOnlyHeader?.trim());

  if (!header && !reportOnly) {
    return { present: false, reportOnly: false, directives: {}, weaknesses: [], usesNonceOrHash: false, usesStrictDynamic: false };
  }

  const effective = header || reportOnlyHeader!.trim();
  const directives = parseCsp(effective);
  const weaknesses: CspWeakness[] = [];

  // `script-src` falls back to `default-src`; if neither exists, scripts are
  // unrestricted no matter what else the policy says.
  const scriptSrc = directives["script-src"] ?? directives["default-src"] ?? null;
  const scriptDirective = directives["script-src"] ? "script-src" : "default-src";

  const has = (list: string[] | null, token: string) =>
    Boolean(list?.some((s) => s.toLowerCase() === token));

  const usesNonceOrHash = Boolean(
    scriptSrc?.some((s) => /^'nonce-/i.test(s) || /^'sha(256|384|512)-/i.test(s)),
  );
  const usesStrictDynamic = has(scriptSrc, "'strict-dynamic'");

  if (reportOnly) {
    weaknesses.push({
      directive: "Content-Security-Policy-Report-Only",
      issue: "the policy is report-only, so violations are reported but nothing is blocked — this provides no protection",
      severity: "medium",
    });
  }

  if (!scriptSrc) {
    weaknesses.push({
      directive: "script-src",
      issue: "neither script-src nor default-src is set, so script sources are not restricted at all",
      severity: "high",
    });
  } else {
    // 'unsafe-inline' is dropped by browsers when a nonce or hash is present, so
    // it is only a weakness in the absence of both.
    if (has(scriptSrc, "'unsafe-inline'") && !usesNonceOrHash) {
      weaknesses.push({
        directive: scriptDirective,
        issue: "'unsafe-inline' is allowed with no nonce or hash present, so injected inline scripts execute — this removes most of the XSS protection a CSP provides",
        severity: "high",
      });
    }

    if (has(scriptSrc, "'unsafe-eval'")) {
      weaknesses.push({
        directive: scriptDirective,
        issue: "'unsafe-eval' is allowed, so eval() and Function() remain available to injected code",
        severity: "medium",
      });
    }

    // A host allowlist is meaningless under 'strict-dynamic': browsers that
    // support it ignore the list and trust only nonced/hashed scripts.
    if (!usesStrictDynamic) {
      const wildcards = scriptSrc.filter((s) => WILDCARD_SOURCES.has(s.toLowerCase()));
      if (wildcards.length > 0) {
        weaknesses.push({
          directive: scriptDirective,
          issue: `${wildcards.join(", ")} permits scripts from effectively any origin, so the allowlist restricts nothing`,
          severity: "high",
        });
      }
      // A trailing-wildcard host such as `*.example.com` is far weaker than it
      // looks if any subdomain hosts user content.
      const wildcardHosts = scriptSrc.filter((s) => s.startsWith("*.") || s.includes("://*"));
      if (wildcardHosts.length > 0) {
        weaknesses.push({
          directive: scriptDirective,
          issue: `${wildcardHosts.join(", ")} trusts every host under that domain, so one subdomain serving user-controlled content defeats the policy`,
          severity: "low",
        });
      }
    }
  }

  /*
   * Without base-uri, an injected <base> tag repoints every relative script URL
   * at an attacker's origin — which defeats an otherwise correct nonce policy.
   * It is the directive most often missing from policies that look strong.
   */
  if (!directives["base-uri"]) {
    weaknesses.push({
      directive: "base-uri",
      issue: "base-uri is not set, so an injected <base> tag can redirect relative script URLs to another origin and defeat a nonce-based policy",
      severity: usesNonceOrHash ? "medium" : "low",
    });
  }

  const objectSrc = directives["object-src"] ?? directives["default-src"] ?? null;
  if (objectSrc && !has(objectSrc, "'none'") && objectSrc.some((s) => WILDCARD_SOURCES.has(s.toLowerCase()))) {
    weaknesses.push({
      directive: "object-src",
      issue: "object-src is not 'none', so plugin content remains a script-execution path",
      severity: "low",
    });
  }

  return {
    present: Boolean(header),
    reportOnly,
    directives,
    weaknesses,
    usesNonceOrHash,
    usesStrictDynamic,
  };
}

export interface CspFinding {
  title: string;
  description: string;
  severity: "high" | "medium" | "low";
  category: string;
  affectedAsset: string;
  remediation: string;
  evidence: Record<string, unknown>;
}

/**
 * One finding per host listing every weakness, not one per weakness — a policy
 * is a single artefact with a single fix, and four rows for four directives is
 * the aggregation mistake `checkCookieSecurity` exists to avoid.
 */
export function buildCspFinding(
  host: string,
  url: string,
  header: string,
  analysis: CspAnalysis,
): CspFinding | null {
  if (analysis.weaknesses.length === 0) return null;

  const worst = analysis.weaknesses.some((w) => w.severity === "high")
    ? "high"
    : analysis.weaknesses.some((w) => w.severity === "medium")
      ? "medium"
      : "low";

  return {
    title: analysis.reportOnly
      ? `Content-Security-Policy is report-only on ${host}`
      : `Weak Content-Security-Policy on ${host}`,
    description:
      `${host} sets a Content-Security-Policy, but it does not provide the protection its presence implies. ` +
      `${analysis.weaknesses.map((w) => `${w.directive}: ${w.issue}`).join(". ")}. ` +
      `A header that exists is not the same as a policy that restricts anything, which is why this is reported ` +
      `separately from a missing header.`,
    severity: worst,
    category: "security_headers",
    affectedAsset: host,
    remediation:
      "Serve scripts with a per-response nonce and use `script-src 'nonce-<random>' 'strict-dynamic'`, " +
      "drop 'unsafe-inline' and 'unsafe-eval', and set `base-uri 'none'` and `object-src 'none'`. " +
      "Roll the policy out with Report-Only first, then enforce it — a report-only policy left in place blocks nothing.",
    evidence: {
      url,
      policy: header.slice(0, 1000),
      reportOnly: analysis.reportOnly,
      usesNonceOrHash: analysis.usesNonceOrHash,
      usesStrictDynamic: analysis.usesStrictDynamic,
      weaknesses: analysis.weaknesses,
    },
  };
}
