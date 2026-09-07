/**
 * Risk factors — a security rating decomposed into the areas a reader can act on.
 *
 * ## Why a factor model at all
 *
 * A single 0-100 score tells an executive whether things are bad, and nothing
 * about where to look. Security-rating vendors solved this with a fixed set of
 * factors, each independently graded, and it is genuinely the right shape: it
 * survives being read by a board, an insurer and an engineer, who each need a
 * different depth from the same page.
 *
 * ## The one thing this does differently, on purpose
 *
 * Rating vendors publish a factor score even when they never assessed it. A real
 * SecurityScorecard report for a mid-size financial firm shows **Endpoint
 * Security 100, IP Reputation 100, Hacker Chatter 100, Social Engineering 100**,
 * each with "0 issues". For an external scan those are not findings of
 * excellence — they are the absence of telemetry. An outside observer cannot see
 * a company's endpoint estate at all.
 *
 * Presenting that as a perfect score is the "No Data reads as a pass" failure
 * this codebase keeps correcting, and it is worse here than elsewhere because
 * the number is carried into board packs and vendor questionnaires.
 *
 * So a factor here has three states, not two:
 *
 *  - **assessed** — detectors for this factor ran, and this is the score;
 *  - **clean** — they ran and found nothing, which IS good news and scores 100;
 *  - **not assessed** — nothing capable of judging this factor ran, so there is
 *    no score. Rendered as "Not assessed", never as 100.
 *
 * A client comparing us to a rating vendor will see fewer perfect scores. That
 * is the correct outcome: the missing ones were never earned.
 */

import {
  computeSecurityScore,
  type FindingForScore,
  type ScoreSeverity,
} from "./scoring";

export type FactorId =
  | "application_security"
  | "network_security"
  | "dns_health"
  | "software_currency"
  | "supply_chain"
  | "data_exposure"
  | "cloud_posture"
  | "access_control"
  | "brand_and_intel";

export interface FactorDefinition {
  id: FactorId;
  title: string;
  /** What this factor covers, in a sentence a non-engineer can read. */
  description: string;
  /** Finding categories that roll up into this factor. */
  categories: string[];
}

/**
 * The factor set, derived from what this engine actually detects.
 *
 * Every category the taxonomy can emit belongs to exactly one factor — a
 * category in no factor would silently vanish from the rating, which is the
 * same defect as an unmapped compliance category.
 */
export const RISK_FACTORS: FactorDefinition[] = [
  {
    id: "application_security",
    title: "Application Security",
    description: "How the public web applications are configured — headers, cookies, content policy and injection defences.",
    categories: [
      "security_headers", "clickjacking", "xss", "injection", "cookie_security",
      "cors_misconfiguration", "http_methods", "open_redirect", "web_application",
    ],
  },
  {
    id: "network_security",
    title: "Network Security",
    description: "What is reachable from the internet, and whether the transport protecting it is sound.",
    categories: [
      "open_port", "network_exposure", "exposed_service", "ssl_issue",
      "transport_security", "waf_bypass",
    ],
  },
  {
    id: "dns_health",
    title: "DNS & Email Health",
    description: "Whether DNS and mail authentication are configured so the domain cannot be trivially spoofed.",
    categories: ["dns_misconfiguration", "email_security", "subdomain_takeover", "certificate_authority"],
  },
  {
    id: "software_currency",
    title: "Software Currency",
    description: "Whether internet-facing software and client-side libraries carry known, published vulnerabilities.",
    categories: ["vulnerability", "outdated_software", "nuclei_finding"],
  },
  {
    id: "supply_chain",
    title: "Supply Chain",
    description: "Risk arriving through third-party code and dependencies rather than through your own systems.",
    categories: ["supply_chain"],
  },
  {
    id: "data_exposure",
    title: "Data Exposure",
    description: "Credentials, documents and infrastructure detail that are publicly reachable when they should not be.",
    categories: [
      "data_leak", "secret_exposure", "leaked_credential", "exposed_document",
      "information_disclosure", "infrastructure_disclosure", "exposed_credentials",
      "exposed_infrastructure", "data_breach",
    ],
  },
  {
    id: "cloud_posture",
    title: "Cloud & Container Posture",
    description: "Storage buckets, container endpoints and cloud services exposed without the access control they need.",
    categories: ["cloud_exposure", "container_exposure", "s3_exposure"],
  },
  {
    id: "access_control",
    title: "Access Control",
    description: "Authentication surfaces and APIs reachable from the internet, and how they are protected.",
    categories: ["authentication", "api_exposure"],
  },
  {
    id: "brand_and_intel",
    title: "Brand & Threat Intelligence",
    description: "Impersonation, leaked-data exposure and public intelligence about the organisation and its people.",
    categories: ["brand_threat", "dark_web", "threat_intelligence", "osint_exposure"],
  },
];

/** Category → factor, built once. */
const FACTOR_BY_CATEGORY: Record<string, FactorId> = (() => {
  const map: Record<string, FactorId> = {};
  for (const f of RISK_FACTORS) for (const c of f.categories) map[c] = f.id;
  return map;
})();

export function factorForCategory(category: string): FactorId | null {
  return FACTOR_BY_CATEGORY[category] ?? null;
}

export type FactorState = "assessed" | "clean" | "not_assessed";

export interface FactorScore {
  id: FactorId;
  title: string;
  description: string;
  state: FactorState;
  /** 0-100 when assessed or clean; null when nothing judged this factor. */
  score: number | null;
  /** A-F when scored; null when not assessed. */
  grade: string | null;
  findingCount: number;
  /** Worst open severity contributing to this factor. */
  worstSeverity: ScoreSeverity | null;
  /** Plain-language reason, so the state is never mysterious. */
  reason: string;
}

/**
 * A–F. **The only definition of these bands in the product.**
 *
 * There were briefly three copies — this one, `scoreGrade` in the client's
 * `severity.ts`, and a `gradeLetter` in the DOCX builder — and they did not
 * agree: two used a C at 70 and a D at 60, the pre-existing one used 65 and 50.
 * A score of 68 was therefore a C on the dashboard hero, a D on the factor card
 * and a D again in the report, from one number. The client and the report
 * builder now both delegate here.
 */
export function gradeForScore(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  return "F";
}

const SEVERITY_RANK: ScoreSeverity[] = ["critical", "high", "medium", "low", "info"];
const CLOSED = new Set(["resolved", "false_positive", "accepted_risk"]);

export interface FactorInput extends FindingForScore {
  /** Needed to attribute a finding to a factor, and to compute its impact. */
  id: string;
  category?: string | null;
}

/**
 * Scores each factor.
 *
 * `assessedCategories` is the set of categories whose detectors actually RAN
 * during the scan — not the categories that produced findings. Without it a
 * factor that was never examined is indistinguishable from one examined and
 * found clean, which is the whole distinction this module exists to preserve.
 * When it is omitted, factors with no findings are reported `not_assessed`
 * rather than being awarded a perfect score on no evidence.
 */
export function computeFactorScores(
  findings: FactorInput[],
  assessedCategories?: Iterable<string>,
): FactorScore[] {
  const assessed = assessedCategories ? new Set(assessedCategories) : null;

  const open = findings.filter(
    (f) => !CLOSED.has(f.status ?? "open") && (f.kind ?? "security") === "security",
  );

  return RISK_FACTORS.map((def) => {
    const mine = open.filter((f) => f.category && factorForCategory(f.category) === def.id);

    // A finding attributed to this factor is itself proof the factor was
    // assessed — something looked and reported. Consulting only the module map
    // would let a factor whose detector is not listed there report
    // `not_assessed` **with its findings silently dropped from the rating**,
    // which under-reports risk rather than merely withholding a score. Found for
    // real: three osint_exposure findings vanished from Brand & Threat
    // Intelligence because no module in the map claims that category.
    const wasAssessed =
      mine.length > 0 || (assessed ? def.categories.some((c) => assessed.has(c)) : false);

    if (!wasAssessed) {
      return {
        id: def.id,
        title: def.title,
        description: def.description,
        state: "not_assessed" as FactorState,
        score: null,
        grade: null,
        findingCount: 0,
        worstSeverity: null,
        reason:
          "No check capable of judging this factor ran, so there is no score. This is not a clean result — it is an absence of evidence.",
      };
    }

    if (mine.length === 0) {
      return {
        id: def.id,
        title: def.title,
        description: def.description,
        state: "clean" as FactorState,
        score: 100,
        grade: "A",
        findingCount: 0,
        worstSeverity: null,
        reason: "Checks for this factor ran and found nothing outstanding.",
      };
    }

    // Reuse the product's own scoring so a factor score and the overall score
    // cannot drift apart in how they treat volume and severity.
    const score = computeSecurityScore(mine);
    const worst = SEVERITY_RANK.find((s) => mine.some((f) => f.severity === s)) ?? null;

    return {
      id: def.id,
      title: def.title,
      description: def.description,
      state: "assessed" as FactorState,
      score,
      grade: gradeForScore(score),
      findingCount: mine.length,
      worstSeverity: worst,
      reason: `${mine.length} open finding${mine.length === 1 ? "" : "s"} in this area, worst severity ${worst ?? "info"}.`,
    };
  });
}

/*
 * There is deliberately NO per-finding `scoreImpactOf` here.
 *
 * It existed briefly, modelled on SecurityScorecard's per-issue "SCORE IMPACT"
 * (-5.1, -2.3). Measured against a live workspace it returned **0.0 for every
 * finding**, and that was correct rather than broken: the model is banded, so
 * removing one of several findings at the capping severity changes nothing.
 *
 * It was removed rather than left unwired. A function with that name and that
 * signature is exactly what someone reaches for when a designer asks for a
 * per-issue number, and it would have printed a column of zeroes — or, if
 * "fixed" by dividing the band deduction across findings, a fabricated gradient
 * the score does not actually have. `analyseScoreCeiling` answers the real
 * question: what is binding, and what does clearing it buy.
 */

/**
 * What is currently capping the score, and what clearing it would buy.
 *
 * This exists because per-finding impact is usually **zero**, and that is a
 * property of the model rather than a bug. The score is clamped into a band by
 * the worst severity *present at all*, so with two open medium findings the
 * ceiling is 85 whether you fix one of them or neither. A rating vendor showing
 * "-0.9" per issue implies a smooth gradient that a banded model does not have.
 *
 * The honest and far more actionable statement is the gate itself: *"your score
 * cannot exceed 85 while any medium finding is open; clear all 2 and the ceiling
 * becomes 95."* That is a target an engineer can plan a sprint around, and it is
 * true, which the per-issue decimal would not be.
 */
export interface CeilingAnalysis {
  score: number;
  /** The severity whose presence sets the current ceiling, if any. */
  cappedBy: ScoreSeverity | null;
  /** Highest score reachable while that severity remains present. */
  currentCeiling: number;
  /** How many findings of that severity must ALL be cleared to lift it. */
  blockingCount: number;
  /** The score that becomes reachable once they are cleared. */
  ceilingIfCleared: number;
  /** The gain from clearing the whole band — the number worth planning around. */
  gain: number;
  /**
   * What is actually holding the score down.
   *
   * `ceiling` — the score is clamped against the band's upper bound, so fixing
   * SOME of the blocking findings changes nothing; only clearing the band
   * moves it.
   *
   * `volume` — the score is already below the ceiling because of how many
   * findings there are, so each one fixed helps. Saying "capped at 85" here
   * would be false twice over: the cap is not binding, and it would tell an
   * engineer that partial progress is worthless when it is not.
   */
  binding: "ceiling" | "volume" | "none";
  summary: string;
}

const BAND_CEILING: Record<string, number> = {
  critical: 45, high: 70, medium: 85, low: 95, info: 100, none: 100,
};

export function analyseScoreCeiling(all: FactorInput[]): CeilingAnalysis {
  const open = all.filter(
    (f) => !CLOSED.has(f.status ?? "open") && (f.kind ?? "security") === "security",
  );
  const score = computeSecurityScore(open);

  // The worst severity that actually carries weight — info never caps.
  const capping = (["critical", "high", "medium", "low"] as ScoreSeverity[])
    .find((s) => open.some((f) => f.severity === s)) ?? null;

  if (!capping) {
    return {
      score, cappedBy: null, currentCeiling: 100, blockingCount: 0,
      ceilingIfCleared: 100, gain: 0, binding: "none",
      summary: "Nothing is capping the score — no findings above informational are open.",
    };
  }

  const blocking = open.filter((f) => f.severity === capping);
  const cleared = open.filter((f) => f.severity !== capping);
  const ceilingIfCleared = computeSecurityScore(cleared);

  const ceiling = BAND_CEILING[capping] ?? 100;

  // Is the band actually the constraint? With a handful of findings the score
  // sits clamped at the ceiling and only clearing the band moves it. With
  // sixty, volume has already pulled the score well below that ceiling, and
  // every one fixed helps — measured on a live workspace showing 55 against a
  // ceiling of 85, where the old wording claimed "capped at 85" and told the
  // reader partial fixes were worthless. Both were false.
  const binding: "ceiling" | "volume" = score >= ceiling ? "ceiling" : "volume";

  return {
    score,
    cappedBy: capping,
    currentCeiling: ceiling,
    blockingCount: blocking.length,
    ceilingIfCleared,
    gain: Math.round((ceilingIfCleared - score) * 10) / 10,
    binding,
    summary:
      binding === "ceiling"
        ? `The score cannot exceed ${ceiling} while any ${capping} finding is open. ` +
          `Clearing all ${blocking.length} would raise it to about ${ceilingIfCleared}.`
        : `${blocking.length} open ${capping} findings are holding the score at ${score}. ` +
          `Clearing them all would raise it to about ${ceilingIfCleared}; fixing some of them helps proportionally.`,
  };
}

/**
 * Which recon modules constitute an assessment of which categories.
 *
 * This is the evidence behind `clean` vs `not_assessed`, and it is deliberately
 * keyed on the module having RUN rather than on it having produced findings — a
 * port scan that completes and finds nothing open is a real assessment of
 * network exposure, while a port scan that never ran is not.
 *
 * A module absent from this map contributes nothing, which is the safe
 * direction: an unmapped module can only ever leave a factor `not_assessed`,
 * never award it an unearned 100.
 */
export const MODULE_ASSESSES: Record<string, string[]> = {
  web_presence: ["security_headers", "clickjacking", "cookie_security", "cors_misconfiguration", "http_methods"],
  dast_lite: ["xss", "injection", "open_redirect", "cookie_security", "security_headers"],
  attack_surface: ["open_port", "network_exposure", "exposed_service", "ssl_issue", "transport_security"],
  website_overview: ["ssl_issue", "transport_security", "security_headers"],
  dns_overview: ["dns_misconfiguration", "email_security"],
  cloud_footprint: ["cloud_exposure", "s3_exposure", "email_security", "dns_misconfiguration"],
  subdomain_takeover: ["subdomain_takeover", "dns_misconfiguration"],
  tech_stack: ["outdated_software", "vulnerability"],
  nuclei: ["nuclei_finding", "vulnerability"],
  third_party_surface: ["supply_chain"],
  code_footprint: ["secret_exposure", "leaked_credential", "data_leak"],
  secret_exposure: ["secret_exposure", "exposed_credentials", "information_disclosure"],
  exposed_content: ["exposed_document", "information_disclosure", "infrastructure_disclosure"],
  api_discovery: ["api_exposure", "authentication"],
  brand_signals: ["brand_threat"],
  dark_web_monitoring: ["dark_web", "threat_intelligence", "data_breach"],
  linkedin_people: ["osint_exposure"],
  linkedin_company: ["osint_exposure"],
  org_identity: ["osint_exposure"],
  ip_reputation: ["threat_intelligence", "network_exposure"],
  routed_footprint: ["network_exposure"],
  bgp_routing: ["network_exposure"],
};

/** The categories a completed set of recon modules can be said to have judged. */
export function assessedCategoriesFromModules(moduleTypes: Iterable<string>): Set<string> {
  const out = new Set<string>();
  for (const t of Array.from(moduleTypes)) for (const c of MODULE_ASSESSES[t] ?? []) out.add(c);
  return out;
}
