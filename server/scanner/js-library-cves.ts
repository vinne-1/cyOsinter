/**
 * Known vulnerabilities in the client-side libraries a site actually serves.
 *
 * ## Why this exists
 *
 * `tech-fingerprints.ts` has always captured library VERSIONS — the jQuery
 * fingerprint carries `version: /jquery[.-]?(\d+\.\d+\.\d+)/i` and friends. The
 * only thing that consumed the version was `recon-builder.ts`, which used it to
 * emit "Exact version disclosed — aids targeted exploitation; suppress version
 * banners."
 *
 * So the engine could see that a site served **jQuery 1.8.3** and reported the
 * *disclosure of the version number* while saying nothing about the five known
 * XSS advisories affecting it. The most useful fact it held was the one fact it
 * did not act on — the same "collected but never consumed" failure this codebase
 * keeps finding in itself.
 *
 * ## Where the data comes from
 *
 * [OSV.dev](https://osv.dev), Google's open vulnerability database: free, no API
 * key, no registration, and the authoritative aggregator for GitHub Security
 * Advisories. It answers "is package X at version Y affected?" directly, so the
 * version-range arithmetic — the part that is easy to get subtly wrong and that
 * a hand-maintained table gets wrong silently as it ages — happens upstream
 * against curated data.
 *
 * Verified against it: jQuery 1.8.3 returns 5 advisories, jQuery 3.7.1 returns
 * zero. A current library producing no finding matters as much as an old one
 * producing several.
 *
 * ## Three states, not two
 *
 * If OSV cannot be reached, this returns `unavailable: true` and NO empty result
 * set. "We could not check" and "we checked and found nothing" must never render
 * identically — the same rule `code-leak-watch` and `ransomware-watch` follow.
 * A library detected without a version is likewise reported as *unassessed*
 * rather than assumed clean: an unknown version is not a safe version.
 *
 * Outbound requests go through `stealthFetch`, not bare `fetch`. That is how
 * every other third-party source here reaches the network (crt.sh, RIPEstat,
 * OTX all use `fetchJSON`, which wraps it), and it matters for one specific
 * reason: `stealth.ts` holds a DEPLOYMENT-WIDE socket semaphore, and CLAUDE.md
 * is explicit that "sockets are a property of the deployment, not of a scan".
 * A module calling `fetch` directly spends sockets the ceiling does not count.
 */

import { createLogger } from "../logger.js";
import { stealthFetch } from "./stealth.js";

const log = createLogger("js-library-cves");

const OSV_QUERY_URL = "https://api.osv.dev/v1/query";
const OSV_TIMEOUT_MS = 10_000;

/**
 * Detected technology name (lowercased) to its npm package name.
 *
 * Only libraries that ship to the browser and have a meaningful npm advisory
 * history are listed. A server-side technology such as nginx is deliberately
 * absent: its version comes from a banner that is often wrong or deliberately
 * faked, and OSV's npm ecosystem does not describe it.
 */
const NPM_PACKAGE_BY_TECH: Readonly<Record<string, string>> = {
  jquery: "jquery",
  "jquery ui": "jquery-ui",
  "jquery-ui": "jquery-ui",
  bootstrap: "bootstrap",
  lodash: "lodash",
  underscore: "underscore",
  moment: "moment",
  "moment.js": "moment",
  handlebars: "handlebars",
  knockout: "knockout",
  backbone: "backbone",
  "backbone.js": "backbone",
  ember: "ember-source",
  "ember.js": "ember-source",
  d3: "d3",
  "d3.js": "d3",
  axios: "axios",
  react: "react",
  vue: "vue",
  "vue.js": "vue",
  svelte: "svelte",
  next: "next",
  "next.js": "next",
  nuxt: "nuxt",
  "nuxt.js": "nuxt",
  dompurify: "dompurify",
  "core-js": "core-js",
  prismjs: "prismjs",
  "chart.js": "chart.js",
  select2: "select2",
  tinymce: "tinymce",
  ckeditor: "ckeditor4",
};

export interface LibraryAdvisory {
  /** GHSA (or other OSV) identifier. */
  id: string;
  /** First CVE alias, when the advisory has one. */
  cve?: string;
  summary: string;
  /** LOW | MODERATE | HIGH | CRITICAL, as published by the advisory database. */
  severity: string;
  /** Version this advisory was fixed in, when the range declares one. */
  fixed?: string;
}

export interface VulnerableLibrary {
  /** Display name as detected, e.g. "jQuery". */
  library: string;
  /** npm package the advisories were looked up under. */
  packageName: string;
  version: string;
  advisories: LibraryAdvisory[];
  /** Worst advisory severity, mapped to this engine's scale. */
  severity: "low" | "medium" | "high";
  /** Highest fixed version across the advisories — the upgrade target. */
  fixedIn?: string;
}

export interface LibraryCveResult {
  vulnerable: VulnerableLibrary[];
  /** Libraries that were looked up (had a version and a known package mapping). */
  checked: string[];
  /**
   * Detected but NOT assessed, with the reason. An unknown version is not a
   * safe version, so these stay visible rather than being silently dropped.
   */
  unassessed: Array<{ library: string; reason: string }>;
  /** OSV could not be reached. NOT the same as "no vulnerabilities found". */
  unavailable: boolean;
}

/** Minimal shape of the detected-technology records this consumes. */
export interface TechWithVersion {
  name: string;
  version?: string;
  category?: string;
}

/**
 * Resolves a detected technology to the npm package OSV knows it by.
 *
 * "Angular" is the case that needs care: the fingerprint matches both AngularJS
 * 1.x (npm `angular`, long unmaintained and carrying real advisories) and modern
 * Angular (npm `@angular/core`). They are different packages with different
 * advisory histories, and the major version is what separates them — querying
 * the wrong one would either invent vulnerabilities or miss them.
 */
export function npmPackageFor(name: string, version?: string): string | null {
  const key = name.trim().toLowerCase();

  if (key === "angular" || key === "angularjs") {
    if (!version) return null; // cannot tell 1.x from modern Angular
    return /^1\./.test(version) ? "angular" : "@angular/core";
  }

  return NPM_PACKAGE_BY_TECH[key] ?? null;
}

/**
 * A version string OSV will accept, or null.
 *
 * Fingerprints capture versions out of filenames and markup, so values like
 * `3.3.7`, `1.8`, or `2.1.4-rc1` all turn up. A partial version is padded rather
 * than rejected — `1.8` genuinely means `1.8.0` for range purposes — but
 * anything that is not a leading numeric version is refused, because guessing
 * here produces confident wrong answers in both directions.
 */
export function normalizeVersion(raw: string | undefined): string | null {
  if (!raw) return null;
  const m = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/.exec(raw.trim());
  if (!m) return null;
  return `${m[1]}.${m[2] ?? "0"}.${m[3] ?? "0"}`;
}

/** OSV/GHSA severity to this engine's scale. */
function mapSeverity(osvSeverity: string): "low" | "medium" | "high" {
  switch (osvSeverity.toUpperCase()) {
    case "CRITICAL":
    case "HIGH":
      return "high";
    case "MODERATE":
    case "MEDIUM":
      return "medium";
    default:
      return "low";
  }
}

const RANK: Record<"low" | "medium" | "high", number> = { low: 0, medium: 1, high: 2 };

/** Highest of two dotted versions, used to pick the single upgrade target. */
function maxVersion(a: string | undefined, b: string | undefined): string | undefined {
  if (!a) return b;
  if (!b) return a;
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x > y ? a : b;
  }
  return a;
}

interface OsvVuln {
  id?: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  database_specific?: { severity?: string };
  affected?: Array<{ ranges?: Array<{ events?: Array<{ introduced?: string; fixed?: string }> }> }>;
}

/**
 * Per-process cache keyed `package@version`.
 *
 * One estate serves the same jQuery build from ninety hosts. Without this, a
 * Gold scan would ask OSV the identical question ninety times — pointless load
 * on a free public service that has no obligation to absorb it.
 */
const cache = new Map<string, LibraryAdvisory[] | null>();

/** Queries OSV. Returns null when the service could not be reached. */
async function queryOsv(packageName: string, version: string): Promise<LibraryAdvisory[] | null> {
  const key = `${packageName}@${version}`;
  const cached = cache.get(key);
  if (cached !== undefined) return cached;

  let result: LibraryAdvisory[] | null = null;
  try {
    const res = await stealthFetch(
      OSV_QUERY_URL,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ package: { name: packageName, ecosystem: "npm" }, version }),
      },
      OSV_TIMEOUT_MS,
    );
    if (!res.ok) {
      log.warn({ packageName, version, status: res.status }, "OSV query failed");
    } else {
      const body = (await res.json()) as { vulns?: OsvVuln[] };
      result = (body.vulns ?? []).map((v) => {
        let fixed: string | undefined;
        for (const a of v.affected ?? []) {
          for (const r of a.ranges ?? []) {
            for (const e of r.events ?? []) {
              if (e.fixed) fixed = maxVersion(fixed, e.fixed);
            }
          }
        }
        return {
          id: v.id ?? "unknown",
          cve: (v.aliases ?? []).find((a) => a.startsWith("CVE-")),
          summary: (v.summary ?? v.details ?? "").split("\n")[0]!.slice(0, 300),
          severity: v.database_specific?.severity ?? "MODERATE",
          fixed,
        };
      });
    }
  } catch (err) {
    log.warn({ err, packageName, version }, "OSV unreachable");
  }

  cache.set(key, result);
  return result;
}

/** Test seam: clears the per-process advisory cache. */
export function resetOsvCache(): void {
  cache.clear();
}

/**
 * Checks detected technologies against OSV.
 *
 * Only libraries carrying a usable version are queried. Everything else is
 * recorded in `unassessed` with the reason, so a reader can tell "this library
 * is fine" from "we could not tell".
 */
export async function findVulnerableLibraries(
  techs: TechWithVersion[],
): Promise<LibraryCveResult> {
  const vulnerable: VulnerableLibrary[] = [];
  const checked: string[] = [];
  const unassessed: Array<{ library: string; reason: string }> = [];
  let anyReachable = false;
  let anyAttempted = false;

  // Deduplicate by name+version: the same library can be reported by more than
  // one fingerprint signal (script src and inline markup, say).
  const seen = new Set<string>();

  for (const tech of techs) {
    const dedupeKey = `${tech.name.toLowerCase()}@${tech.version ?? ""}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);

    const packageName = npmPackageFor(tech.name, tech.version);
    if (!packageName) continue; // not a library we can map — silently out of scope

    const version = normalizeVersion(tech.version);
    if (!version) {
      unassessed.push({
        library: tech.name,
        reason: tech.version
          ? `version "${tech.version}" could not be parsed`
          : "no version could be determined from the page",
      });
      continue;
    }

    anyAttempted = true;
    const advisories = await queryOsv(packageName, version);
    if (advisories === null) {
      unassessed.push({ library: `${tech.name} ${version}`, reason: "vulnerability database unreachable" });
      continue;
    }

    anyReachable = true;
    checked.push(`${tech.name} ${version}`);
    if (advisories.length === 0) continue;

    let severity: "low" | "medium" | "high" = "low";
    let fixedIn: string | undefined;
    for (const a of advisories) {
      const s = mapSeverity(a.severity);
      if (RANK[s] > RANK[severity]) severity = s;
      fixedIn = maxVersion(fixedIn, a.fixed);
    }

    vulnerable.push({
      library: tech.name,
      packageName,
      version,
      advisories: advisories.sort((a, b) => RANK[mapSeverity(b.severity)] - RANK[mapSeverity(a.severity)]),
      severity,
      fixedIn,
    });
  }

  return {
    vulnerable,
    checked,
    unassessed,
    // Only "unavailable" if we tried and never once got through. If nothing was
    // queryable at all, the service's reachability is simply not in question.
    unavailable: anyAttempted && !anyReachable,
  };
}

/**
 * Renders the result as findings for one host.
 *
 * **One finding per library, not per advisory.** jQuery 1.8.3 carries five
 * advisories; five rows would bury everything else in the inbox and inflate the
 * severity counts the posture score derives from — the same mistake
 * `checkCookieSecurity` exists to avoid. Every advisory is preserved as
 * evidence.
 *
 * Severity is capped at `high`. A vulnerable client-side library is a real
 * finding, but this check confirms only that the library is *present and
 * outdated* — not that the application passes untrusted input into the
 * vulnerable sink. Calling that critical would be the severity inflation
 * CLAUDE.md warns about, and the description says plainly what was and was not
 * established.
 */
export interface LibraryFinding {
  title: string;
  description: string;
  severity: "low" | "medium" | "high" | "info";
  category: string;
  affectedAsset: string;
  /**
   * Representative base score for the severity band, NOT a score computed for
   * this deployment. The advisories carry their own CVSS vectors in evidence;
   * exploitability here depends on how the application uses the library, which
   * this check does not establish, so a precise-looking score would imply
   * precision that was never measured.
   */
  cvssScore: string;
  remediation: string;
  evidence: Record<string, unknown>;
}

/** Band-representative scores; see the note on `cvssScore`. */
const BAND_SCORE: Record<"low" | "medium" | "high" | "info", string> = {
  high: "7.5",
  medium: "5.3",
  low: "3.7",
  info: "0.0",
};

export function buildLibraryFindings(
  host: string,
  result: LibraryCveResult,
): LibraryFinding[] {
  const findings: LibraryFinding[] = result.vulnerable.map((lib): LibraryFinding => {
    const ids = lib.advisories.map((a) => a.cve ?? a.id);
    const upgrade = lib.fixedIn
      ? ` Upgrade to ${lib.packageName} ${lib.fixedIn} or later.`
      : " No fixed version is published for all of these advisories.";

    return {
      title: `Outdated ${lib.library} (${lib.version}) with ${lib.advisories.length} known ${lib.advisories.length === 1 ? "advisory" : "advisories"} on ${host}`,
      description:
        `${host} serves ${lib.library} ${lib.version}, which is affected by ${lib.advisories.length} published ` +
        `${lib.advisories.length === 1 ? "advisory" : "advisories"} (${ids.slice(0, 5).join(", ")}${ids.length > 5 ? ", …" : ""}). ` +
        `This confirms the library is present and outdated; it does not confirm the application passes attacker-controlled ` +
        `input into the affected code path, so treat it as exposure to be removed rather than a proven exploit.${upgrade}`,
      severity: lib.severity,
      category: "outdated_software",
      affectedAsset: host,
      cvssScore: BAND_SCORE[lib.severity],
      remediation: lib.fixedIn
        ? `Upgrade ${lib.library} to ${lib.fixedIn} or later on ${host}. If the version is pinned by a theme or vendor bundle, upgrade that bundle rather than patching the file in place, or it will regress on the next deploy.`
        : `No single fixed version covers every advisory affecting ${lib.library} ${lib.version}. Move to the current major release, or remove the library if the page no longer needs it.`,
      evidence: {
        library: lib.library,
        package: lib.packageName,
        version: lib.version,
        fixedIn: lib.fixedIn ?? null,
        source: "OSV.dev (open vulnerability database)",
        advisories: lib.advisories.map((a) => ({
          id: a.id,
          cve: a.cve ?? null,
          severity: a.severity,
          summary: a.summary,
          fixed: a.fixed ?? null,
        })),
      },
    };
  });

  // Record what could NOT be assessed, so "we looked and could not confirm"
  // stays distinguishable from "we never looked".
  if (result.unavailable || result.unassessed.length > 0) {
    findings.push({
      title: `Client-side libraries not fully assessed on ${host}`,
      description: result.unavailable
        ? `The vulnerability database could not be reached, so the client-side libraries on ${host} were not checked. This is not a statement that they are current.`
        : `Some libraries on ${host} could not be assessed: ${result.unassessed.map((u) => `${u.library} (${u.reason})`).join("; ")}.`,
      severity: "info",
      category: "outdated_software",
      affectedAsset: host,
      cvssScore: BAND_SCORE.info,
      remediation: result.unavailable
        ? "Re-run the scan when the vulnerability database is reachable; this host's client-side libraries have not been assessed."
        : "Where a library's version could not be determined, confirm it from the deployed bundle — an unknown version is not a safe version.",
      evidence: {
        unavailable: result.unavailable,
        unassessed: result.unassessed,
        assessed: result.checked,
      },
    });
  }

  return findings;
}
