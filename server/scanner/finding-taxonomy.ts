/**
 * Finding taxonomy — what KIND of thing did we just observe?
 *
 * The scanner previously answered only "which category string?", and everything
 * it could not place went to `informational`. That bucket held 25 of 76 stored
 * findings and mixed three genuinely different kinds of observation:
 *
 *   - "Weak HTTP Strict-Transport-Security"  — a real security weakness
 *   - "DNSSEC Detection"                     — a control that is PRESENT
 *   - "AWS Service - Detect"                 — a technology fact
 *
 * Reporting all three identically is the single biggest classification problem
 * in the engine. It inflates the finding count, drags the posture score down for
 * good news, and trains an analyst to skim past the inbox. `informational` also
 * collided with the `info` SEVERITY, so a field meant to say *what* a finding is
 * ended up restating *how bad* it is.
 *
 * This splits the question in two:
 *   `kind`      — security | control | recon   (what sort of observation)
 *   `category`  — the security taxonomy, only meaningful when kind === security
 */

/**
 * - `security` — a weakness or exposure. Belongs in the findings inbox.
 * - `control`  — evidence a protection is IN PLACE. Good news; it belongs in a
 *                posture view, never in the triage queue, and must never deduct
 *                from the score.
 * - `recon`    — a technology or configuration fact with no security verdict.
 *                Useful as intelligence, noise as a finding.
 */
export type FindingKind = "security" | "control" | "recon";

export interface Classification {
  kind: FindingKind;
  /** Security taxonomy for `security`; the control's name for `control`. */
  category: string;
  /** True when this must not be persisted as a finding. */
  skip: boolean;
  /** Why it was classified this way — surfaced in evidence for auditability. */
  reason: string;
}

/**
 * Controls whose PRESENCE is the point. Matching one means the target is doing
 * something right, so it is recorded as posture, not as a problem.
 *
 * Order matters: a "weak"/"missing" qualifier is checked first by the caller,
 * because "Weak HSTS" and "HSTS enabled" both mention HSTS but mean opposites.
 */
const POSITIVE_CONTROLS: Array<{ pattern: RegExp; control: string }> = [
  { pattern: /dnssec/i, control: "DNSSEC" },
  { pattern: /security\.txt/i, control: "security.txt" },
  { pattern: /\bcaa\b.*record|caa-record/i, control: "CAA records" },
  { pattern: /dmarc.*(found|detect|present|configured)/i, control: "DMARC" },
  { pattern: /spf.*(found|detect|present|configured)/i, control: "SPF" },
  { pattern: /\bmta-?sts\b/i, control: "MTA-STS" },
  { pattern: /\bbimi\b/i, control: "BIMI" },
  { pattern: /strict-transport-security.*(enabled|present|configured)/i, control: "HSTS" },
  { pattern: /content-security-policy.*(present|configured|enabled)/i, control: "Content-Security-Policy" },
  { pattern: /waf.*(detect|present)/i, control: "WAF" },
];

/**
 * Words that invert a control into a weakness. "Weak HSTS" is not the HSTS
 * control being present — it is the HSTS control being wrong, and the previous
 * classifier had no rule for it so it fell through to the catch-all.
 */
// `misconfigur` and `unsafe` sit outside the trailing \b group on purpose.
// Inside it the pattern was /\bmisconfigur\b/, which demands a word boundary
// immediately after "misconfigur" — so it matched nothing, and every
// "… - Misconfigured" observation fell straight through the negation check into
// recon and out of the findings inbox. Found by running this classifier over
// the findings already stored in the database rather than over invented cases.
const NEGATIVE_QUALIFIER =
  /\b(weak|missing|absent|invalid|expired|insecure|disabled|deprecated|not\s+(set|present|configured|enabled)|without)\b|\bmisconfigur|\bunsafe/i;

/** Security categories, matched before the generic fallbacks. */
const SECURITY_ROUTES: Array<{ pattern: RegExp; category: string }> = [
  { pattern: /strict-transport-security|\bhsts\b/i, category: "transport_security" },
  { pattern: /missing.*security.*header|security-headers|http-missing-security|x-frame-options|x-content-type|referrer-policy|permissions-policy/i, category: "security_headers" },
  { pattern: /content-security-policy|\bcsp\b/i, category: "security_headers" },
  { pattern: /expect-ct/i, category: "security_headers" },
  // Subresource Integrity: without it a compromised CDN silently swaps the
  // script a page loads, so it is a supply-chain weakness rather than a header
  // nicety. It had no rule at all and was landing in `unclassified`.
  { pattern: /subresource.integrity|\bsri\b/i, category: "supply_chain" },
  { pattern: /cookie/i, category: "cookie_security" },
  { pattern: /\bcors\b/i, category: "cors_misconfiguration" },
  { pattern: /\bxss\b|cross-site.scripting/i, category: "xss" },
  { pattern: /open.redirect/i, category: "open_redirect" },
  { pattern: /subdomain.takeover|\btakeover\b/i, category: "subdomain_takeover" },
  { pattern: /\bspf\b|\bdmarc\b|\bdkim\b|mail.*(spoof|security)/i, category: "email_security" },
  { pattern: /dns.*(misconfig|wildcard|zone.transfer|axfr)/i, category: "dns_misconfiguration" },
  { pattern: /directory.listing|index.of|path.traversal|\.git|\.env|backup.file/i, category: "information_disclosure" },
  { pattern: /default.(credential|password|login)|weak.password/i, category: "authentication" },
  { pattern: /sql.injection|\bsqli\b|command.injection|\brce\b|ssrf|xxe|\bssti\b/i, category: "injection" },
  { pattern: /clickjack|frame.options/i, category: "clickjacking" },
  // A reachable admin or login panel is attack surface whether or not the
  // template's wording happens to include the word "exposed".
  { pattern: /exposed.(panel|admin|console|dashboard)|admin.(panel|login)|(login|admin|management)\s*panel/i, category: "exposed_service" },
  { pattern: /api.*(expos|leak|doc|swagger|graphql)/i, category: "api_exposure" },
  { pattern: /secret|api.key|token.*(leak|expos)|credential/i, category: "secret_exposure" },
  // Deliberately NOT a bare /\bssl\b/. "SSL DNS Names" and "Detect SSL Certificate
  // Issuer" are certificate enumeration; a bare match promoted every one of them
  // into the findings inbox as a security issue. A cert observation is only a
  // finding when something about it is actually wrong.
  // Two lookaheads rather than `subject.*problem`, because the words arrive in
  // either order: "Expired TLS certificate" puts the problem first and
  // "TLS certificate expired" puts it last. A sequential pattern silently missed
  // half of them.
  {
    pattern:
      /(?=.*\b(ssl|tls|certificate|cert)\b)(?=.*(weak|expir|invalid|self.?sign|mismatch|revoke|insecure|untrust|deprecat|downgrade))|sslv[23]|tls\s*1\.[01]\b/i,
    category: "ssl_issue",
  },
];

/**
 * Pure enumeration: technology, versions, fingerprints. Real intelligence, but
 * not a security verdict, so it is dropped from the findings inbox and lives in
 * the recon modules instead.
 */
// `\bdetect(ion|ed|s)?\b` is deliberately broad. It is safe because the
// security routes above run FIRST, so anything with a real security meaning has
// already returned by the time we get here — "Weak HSTS - Detect" leaves as
// transport_security, a CVE leaves as a vulnerability. What is left is genuine
// enumeration. The narrower `-detect$` missed the common shapes outright:
// "Apache Detection on host" and "AWS Service - Detect on host" both fell
// through to `unclassified`, which made the taxonomy look full of gaps it did
// not have.
const RECON_PATTERNS =
  /tech[-_]?detect|\bdetect(ion|ed|s)?\b|wappalyzer|fingerprint|favicon|screenshot|metadata|http-title|form-detection|dns-names|issuer|\bwhois\b|dns-?record|\bcname\b|robots\.txt|sitemap|openid|oauth.*(discover|config)|asset.?links|saas.*(service|detect)|tenant\s*id|wildcard\s+dns/i;

/**
 * Classifies a scanner observation.
 *
 * @param templateId  Nuclei template id, or a stable id for a native check.
 * @param name        Human-readable title.
 * @param severity    Reported severity.
 * @param isCve       Whether the observation is CVE-backed.
 */
export function classifyObservation(
  templateId: string,
  name: string,
  severity: string,
  isCve: boolean,
): Classification {
  const hay = `${templateId} ${name}`;
  const actionable = isCve || ["low", "medium", "high", "critical"].includes(severity);
  const negated = NEGATIVE_QUALIFIER.test(hay);

  // A CVE is always a security finding, whatever else the text mentions.
  if (isCve) {
    return { kind: "security", category: "vulnerability", skip: false, reason: "CVE-backed" };
  }

  // Positive controls — but only when nothing negates them. "Weak HSTS" and
  // "HSTS enabled" both mention HSTS and mean opposite things.
  if (!negated) {
    for (const { pattern, control } of POSITIVE_CONTROLS) {
      if (pattern.test(hay)) {
        return {
          kind: "control",
          category: control,
          // Never a finding: a control being present is not work to do.
          skip: true,
          reason: `${control} is present — recorded as posture, not a finding`,
        };
      }
    }
  }

  // Security routing, most specific first.
  for (const { pattern, category } of SECURITY_ROUTES) {
    if (pattern.test(hay)) {
      return { kind: "security", category, skip: false, reason: `matched ${category}` };
    }
  }

  // Anything still graded low or above is a security finding even if we cannot
  // name it precisely — better an unclassified real issue than a dropped one.
  if (actionable) {
    return { kind: "security", category: "vulnerability", skip: false, reason: `severity ${severity}` };
  }

  // A negation word means something is WRONG, even if no route named it. Falling
  // through to recon here would silently discard real weaknesses whose wording
  // the taxonomy does not yet cover — the exact failure this module exists to
  // stop. Keep it and label it so the gap is visible.
  if (negated) {
    return {
      kind: "security",
      category: "unclassified",
      skip: false,
      reason: "negative qualifier present but no category rule matched — taxonomy needs a rule",
    };
  }

  // Enumeration and fingerprinting.
  if (RECON_PATTERNS.test(hay)) {
    return { kind: "recon", category: "technology", skip: true, reason: "enumeration, not a security verdict" };
  }

  // Genuinely unplaceable info-severity observation. Kept, but honestly labelled
  // so it is obvious the taxonomy needs a rule rather than hidden in a bucket.
  return { kind: "recon", category: "unclassified", skip: true, reason: "no rule matched an info-severity observation" };
}

/**
 * Security categories emitted DIRECTLY by detector modules, without passing
 * through `classifyObservation`.
 *
 * Only the Nuclei path is routed by this file; every native detector sets its
 * own `category` literal. Listing them here makes `SECURITY_CATEGORIES` the
 * single source of truth for "every security category the engine can produce",
 * which downstream consumers need in order to be complete.
 *
 * That completeness is not cosmetic. `compliance-mapper.ts` keys its
 * framework mapping on this vocabulary, and a category missing from it maps to
 * no control at all — so the control silently renders "No Data" rather than
 * the failure it should be. A live workspace showed nine of ten OWASP controls
 * as unassessed for exactly this reason: 27 of its 31 findings were
 * `cookie_security`, which no mapping covered.
 */
const DETECTOR_CATEGORIES = [
  "brand_threat",
  "certificate_authority",
  "cloud_exposure",
  "container_exposure",
  "dark_web",
  "data_leak",
  "http_methods",
  "infrastructure_disclosure",
  "leaked_credential",
  "network_exposure",
  "osint_exposure",
  "outdated_software",
  "threat_intelligence",
  "waf_bypass",
  "web_application",
] as const;

/**
 * Every security category the engine can emit — routed or native.
 *
 * Used for UI filters, docs, and the compliance mapping's coverage guard.
 */
export const SECURITY_CATEGORIES: readonly string[] = Array.from(
  new Set([...SECURITY_ROUTES.map((r) => r.category), "vulnerability", ...DETECTOR_CATEGORIES]),
).sort();

export const KNOWN_CONTROLS: readonly string[] = POSITIVE_CONTROLS.map((c) => c.control);

/**
 * Is this row WORK, as opposed to good news or a neutral fact?
 *
 * `security` is the only kind that belongs in the triage inbox, the security
 * score, the SLA clock, a trend, a compliance mapping or a client's findings
 * register. A `control` finding records a protection that IS in place
 * ("DNSSEC Detection", "security.txt File") and a `recon` finding is a
 * technology observation ("Apache Detection", "robots.txt file").
 *
 * This exists as one function because the rule was open-coded and kept being
 * MISSED — each time in a place nobody was looking, each time found by
 * reconciling a number rather than by a test:
 *
 *   SLA summary and sweep     `control` findings carried remediation deadlines
 *                             and would page somebody as an overdue breach
 *   trend endpoints           `/trends` said 14 open findings where the inbox
 *                             said 4
 *   report content            a client's register listed 14 rows for 4 findings
 *   DOCX register             …and opened with "DNSSEC Detection", a control
 *                             that is WORKING, as the first row a client reads
 *   finding groups            groups titled after a technology fact, claiming
 *                             five instances of outstanding work
 *   asset risk scoring        a recon row raised a host's risk score; on one
 *                             workspace 10 of 14 scored rows were not work
 *   attack simulation         a remediated finding still matched an attack
 *                             chain, so fixing it never cleared the path
 *   scan diff                 "Apache Detection" reported as a NEW FINDING,
 *                             and counted into `riskDelta`
 *   AI insights panel        "has 14 security findings" where the inbox
 *                             showed 4, in those words, to the operator
 *   threat-intel enrichment   `enrichedCount` reported to the operator counted
 *                             rows nobody triages
 *
 * The sweep that found the last four enumerated every read of the findings
 * table rather than waiting to trip over the next one. Do that after adding a
 * consumer. One place deliberately does NOT filter by status —
 * `differential-reporting` — because which rows are closed is the diff's own
 * subject matter, and removing them deletes the "fixed" half of the answer.
 *
 * A row written before the `kind` column existed reads as `security`, so
 * nothing stops being counted by accident — the default is the safe direction.
 */
export function isSecurityFinding(f: { kind?: string | null }): boolean {
  return (f.kind ?? "security") === "security";
}
