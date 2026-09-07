/**
 * Dependency confusion: internal package names that nobody owns publicly.
 *
 * ## The attack
 *
 * A build that resolves `@acme/billing-utils` from an internal registry will,
 * under a great many default configurations, fall back to the PUBLIC registry
 * when the name is not found — or prefer the public copy when it advertises a
 * higher version. If nobody has claimed that name publicly, an attacker can
 * publish it, and their `postinstall` runs inside the target's build. This is
 * Alex Birsan's 2021 research, and it worked against Apple, Microsoft, PayPal
 * and Netflix.
 *
 * ## Why this belongs in an EASM scan
 *
 * The signal is externally visible. `secret-scanner.ts` already fetches
 * `/package.json`, `/composer.json` and `/requirements.txt` when they are
 * exposed — and scanned them for SECRETS only, discarding the dependency list
 * entirely. The manifest was already in hand; the highest-value thing in it was
 * being thrown away, which is the same "fetched, one use extracted" pattern this
 * codebase keeps finding.
 *
 * ## What this does NOT establish
 *
 * Whether the target's build is actually configured to fall back to the public
 * registry. A scoped registry in `.npmrc`, or `--index-url` with
 * `--no-index`, is the correct mitigation and is **invisible from outside**.
 * So an unclaimed name is reported as *claimable*, with that caveat stated in
 * the finding rather than buried — the difference between "an attacker could
 * register this name" and "your build will install it" is the whole gap between
 * a lead and a vulnerability.
 *
 * ## Three states
 *
 * A registry that cannot be reached yields `unavailable`, never an empty risk
 * list. "We could not check whether these names are claimed" and "every name is
 * claimed" are opposite conclusions.
 */

import { createLogger } from "../logger.js";
import { stealthFetch } from "./stealth.js";

const log = createLogger("dependency-confusion");

const NPM_REGISTRY = "https://registry.npmjs.org";
const PYPI_REGISTRY = "https://pypi.org/pypi";
const LOOKUP_TIMEOUT_MS = 10_000;

/** Bounds work against a public registry that has no duty to absorb it. */
const MAX_LOOKUPS = 60;

/**
 * Specifier prefixes that do NOT resolve from a public registry.
 *
 * A dependency pinned to a git URL, a tarball, a local path or a workspace is
 * not subject to this attack at all, so including it would be a pure false
 * positive — and these are exactly the forms a monorepo's internal packages
 * usually take.
 */
const NON_REGISTRY_PREFIXES = [
  "file:", "link:", "portal:", "workspace:",
  "git:", "git+", "github:", "gitlab:", "bitbucket:",
  "http://", "https://",
];

export type Ecosystem = "npm" | "pypi";

export interface DependencyRef {
  name: string;
  specifier: string;
  ecosystem: Ecosystem;
  dev: boolean;
  scope?: string;
}

export interface ConfusionRisk {
  name: string;
  ecosystem: Ecosystem;
  dev: boolean;
  scope?: string;
  severity: "high" | "medium" | "low";
  reason: string;
}

export interface DependencyConfusionResult {
  risks: ConfusionRisk[];
  /** Names successfully checked against a registry. */
  checked: string[];
  /** Dependencies deliberately not checked, with the reason. */
  skipped: Array<{ name: string; reason: string }>;
  /** A registry could not be reached. NOT the same as "everything is claimed". */
  unavailable: boolean;
}

/**
 * Extracts registry-resolved dependencies from a `package.json`.
 *
 * Returns an empty list rather than throwing on malformed JSON: this input comes
 * off the public internet, and a scanner that dies on a truncated file is worse
 * than one that reports nothing for it.
 */
export function parsePackageJson(content: string): DependencyRef[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return [];
  }
  if (!parsed || typeof parsed !== "object") return [];

  const doc = parsed as Record<string, unknown>;
  const refs: DependencyRef[] = [];

  for (const [field, dev] of [["dependencies", false], ["devDependencies", true]] as const) {
    const block = doc[field];
    if (!block || typeof block !== "object") continue;
    for (const [name, spec] of Object.entries(block as Record<string, unknown>)) {
      const specifier = typeof spec === "string" ? spec : "";
      // `npm:real-package@^1` aliases resolve the ALIASED name, so that is the
      // name whose ownership matters.
      const aliased = /^npm:(@?[^@]+(?:\/[^@]+)?)(?:@|$)/.exec(specifier);
      const effective = aliased ? aliased[1] : name;
      const scope = effective.startsWith("@") ? effective.split("/")[0] : undefined;
      refs.push({ name: effective, specifier, ecosystem: "npm", dev, scope });
    }
  }

  return refs;
}

/**
 * Extracts package names from a `requirements.txt`.
 *
 * Only plain requirement lines are taken. `-e`, `-r`, and direct URL references
 * do not resolve a name from the public index, and a line pinning a local wheel
 * is not confusable.
 */
export function parseRequirementsTxt(content: string): DependencyRef[] {
  const refs: DependencyRef[] = [];
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;
    if (/^[a-z+]+:\/\//i.test(line)) continue;
    if (line.includes("@") && /@\s*(git\+|https?:|file:)/i.test(line)) continue;
    const m = /^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*([<>=!~].*)?$/.exec(line);
    if (!m) continue;
    refs.push({ name: m[1], specifier: (m[3] ?? "").trim(), ecosystem: "pypi", dev: false });
  }
  return refs;
}

/** Whether a specifier resolves from a public registry at all. */
export function resolvesFromRegistry(specifier: string): boolean {
  const s = specifier.trim().toLowerCase();
  if (s === "") return true; // bare/latest
  return !NON_REGISTRY_PREFIXES.some((p) => s.startsWith(p));
}

/**
 * Whether a name could actually be registered on the public registry.
 *
 * This matters because the manifest is fetched off the public internet, so the
 * names in it are attacker-controlled — and an unregistrable name 404s exactly
 * like an unclaimed one. Without this check, a `package.json` containing
 * `"../../evil": "^1.0.0"` produced a finding saying an attacker could register
 * `../../evil`, which nobody can. Found by adversarial QA, not by a real
 * manifest, but a hostile manifest is precisely what an attacker controls when
 * they know a scanner reads it.
 *
 * npm's published rules: at most 214 characters, no leading dot or underscore,
 * lowercase, URL-safe; scoped names are `@scope/name`. PyPI names are letters,
 * digits, and `.`/`-`/`_` separators.
 */
export function isRegistrablePackageName(name: string, ecosystem: Ecosystem): boolean {
  const n = name.trim();
  if (!n || n.length > 214 || n !== name) return false;
  if (ecosystem === "pypi") return /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/.test(n);

  const body = /^[a-z0-9][a-z0-9._-]*$/;
  if (n.startsWith("@")) {
    const parts = n.slice(1).split("/");
    return parts.length === 2 && body.test(parts[0]!) && body.test(parts[1]!);
  }
  return body.test(n);
}

type Existence = "claimed" | "unclaimed" | "unknown";

async function headExists(url: string): Promise<Existence> {
  try {
    const res = await stealthFetch(url, { method: "GET", headers: { accept: "application/json" } }, LOOKUP_TIMEOUT_MS);
    if (res.status === 404) return "unclaimed";
    if (res.ok) return "claimed";
    return "unknown";
  } catch {
    return "unknown";
  }
}

/** Whether ANY public package exists under an npm scope. */
async function npmScopeIsClaimed(scope: string): Promise<Existence> {
  const bare = scope.replace(/^@/, "");
  try {
    const res = await stealthFetch(
      `${NPM_REGISTRY}/-/v1/search?text=scope:${encodeURIComponent(bare)}&size=1`,
      {},
      LOOKUP_TIMEOUT_MS,
    );
    if (!res.ok) return "unknown";
    const body = (await res.json()) as { total?: number };
    return (body.total ?? 0) > 0 ? "claimed" : "unclaimed";
  } catch {
    return "unknown";
  }
}

function registryUrl(ref: DependencyRef): string {
  if (ref.ecosystem === "pypi") return `${PYPI_REGISTRY}/${encodeURIComponent(ref.name)}/json`;
  // `encodeURIComponent` then restore `@`, which npm's path form requires
  // unescaped. Doing it this way rather than only replacing `/` means a name
  // carrying `?` or `#` cannot bolt a query string or fragment onto the URL.
  const encoded = encodeURIComponent(ref.name).replace(/%40/g, "@");
  return `${NPM_REGISTRY}/${encoded}`;
}

/**
 * Checks which dependencies name packages nobody owns publicly.
 *
 * Sequential and capped: this talks to free public registries, and a scan of a
 * large estate should not turn into a crawl of npm.
 */
export async function checkDependencyConfusion(
  refs: DependencyRef[],
): Promise<DependencyConfusionResult> {
  const risks: ConfusionRisk[] = [];
  const checked: string[] = [];
  const skipped: Array<{ name: string; reason: string }> = [];
  const scopeCache = new Map<string, Existence>();

  let attempted = 0;
  let anyReachable = false;

  const seen = new Set<string>();
  const queue = refs.filter((r) => {
    const key = `${r.ecosystem}:${r.name}`;
    if (seen.has(key)) return false;
    seen.add(key);
    if (!resolvesFromRegistry(r.specifier)) {
      skipped.push({ name: r.name, reason: `resolved from ${r.specifier.split(":")[0]}:, not a public registry` });
      return false;
    }
    // An unregistrable name 404s exactly like an unclaimed one, so without this
    // a malformed entry would be reported as a name an attacker could take.
    if (!isRegistrablePackageName(r.name, r.ecosystem)) {
      skipped.push({ name: r.name, reason: "not a registrable package name, so it cannot be claimed by anyone" });
      return false;
    }
    return true;
  });

  for (const ref of queue.slice(0, MAX_LOOKUPS)) {
    attempted += 1;
    const existence = await headExists(registryUrl(ref));

    if (existence === "unknown") {
      skipped.push({ name: ref.name, reason: "registry lookup failed" });
      continue;
    }
    anyReachable = true;
    checked.push(ref.name);
    if (existence === "claimed") continue;

    // Unclaimed. How exposed depends on whether a scope stands in the way.
    if (ref.ecosystem === "npm" && ref.scope) {
      let scopeState = scopeCache.get(ref.scope);
      if (scopeState === undefined) {
        scopeState = await npmScopeIsClaimed(ref.scope);
        scopeCache.set(ref.scope, scopeState);
      }

      if (scopeState === "unclaimed") {
        risks.push({
          name: ref.name, ecosystem: "npm", dev: ref.dev, scope: ref.scope, severity: "high",
          reason: `neither the package nor the ${ref.scope} scope exists on the public registry, so an attacker can register the scope and publish this exact name`,
        });
      } else if (scopeState === "claimed") {
        risks.push({
          name: ref.name, ecosystem: "npm", dev: ref.dev, scope: ref.scope, severity: "low",
          reason: `the package is not published publicly, but the ${ref.scope} scope is already registered — whoever owns that scope could publish this name, so confirm the scope belongs to your organisation`,
        });
      } else {
        skipped.push({ name: ref.name, reason: `scope ${ref.scope} ownership could not be determined` });
      }
      continue;
    }

    // Unscoped: anyone may publish this name today.
    risks.push({
      name: ref.name, ecosystem: ref.ecosystem, dev: ref.dev, severity: "high",
      reason: `no package of this name exists on the public ${ref.ecosystem === "npm" ? "npm" : "PyPI"} registry, so anyone may publish one`,
    });
  }

  if (queue.length > MAX_LOOKUPS) {
    skipped.push({
      name: `${queue.length - MAX_LOOKUPS} further dependencies`,
      reason: `lookup budget of ${MAX_LOOKUPS} reached`,
    });
  }

  return {
    risks,
    checked,
    skipped,
    unavailable: attempted > 0 && !anyReachable,
  };
}

export interface ConfusionFinding {
  title: string;
  description: string;
  severity: "high" | "medium" | "low" | "info";
  category: string;
  affectedAsset: string;
  cvssScore: string;
  remediation: string;
  evidence: Record<string, unknown>;
}

/**
 * Renders the result as findings for one host.
 *
 * One finding per host per severity band, listing every affected package — not
 * one per package. A monorepo can reference dozens of internal names and they
 * are all the same misconfiguration with the same fix.
 */
export function buildConfusionFindings(
  host: string,
  source: string,
  result: DependencyConfusionResult,
): ConfusionFinding[] {
  const findings: ConfusionFinding[] = [];

  const claimable = result.risks.filter((r) => r.severity === "high");
  if (claimable.length > 0) {
    const names = claimable.map((r) => r.name);
    findings.push({
      title: `Dependency confusion: ${claimable.length} unclaimed package name${claimable.length === 1 ? "" : "s"} referenced by ${host}`,
      description:
        `${host} exposes ${source}, which references ${claimable.length} package name${claimable.length === 1 ? "" : "s"} ` +
        `that ${claimable.length === 1 ? "does" : "do"} not exist on the public registry: ${names.slice(0, 10).join(", ")}` +
        `${names.length > 10 ? `, and ${names.length - 10} more` : ""}. Anyone can publish ${claimable.length === 1 ? "that name" : "those names"} ` +
        `today. If any build resolving this manifest can reach the public registry, it may install the attacker's package and execute its ` +
        `install scripts inside the build. This does not confirm such a fallback is configured — a scoped private registry is the correct ` +
        `mitigation and cannot be observed from outside — so treat this as a name an attacker can take, not as a confirmed compromise path.`,
      severity: "high",
      category: "data_leak",
      affectedAsset: host,
      cvssScore: "8.1",
      remediation:
        `Claim ${claimable.length === 1 ? "the name" : "these names"} on the public registry as a placeholder so nobody else can, and pin the ` +
        `internal registry explicitly (npm: a scoped registry in .npmrc; pip: --index-url with --no-index) so a public fallback cannot occur. ` +
        `Then stop serving ${source} publicly — it is the map an attacker uses to find these names.`,
      evidence: { source, host, packages: claimable, checkedCount: result.checked.length },
    });
  }

  const scopeOwned = result.risks.filter((r) => r.severity === "low");
  if (scopeOwned.length > 0) {
    findings.push({
      title: `Private package names under a third-party-registrable scope on ${host}`,
      description:
        `${scopeOwned.length} referenced package${scopeOwned.length === 1 ? " is" : "s are"} not published publicly, but ` +
        `${scopeOwned.length === 1 ? "its" : "their"} npm scope is already registered on the public registry. Whoever owns that scope could ` +
        `publish these exact names. Confirm the scope belongs to your organisation; if it does, this is working as intended.`,
      severity: "low",
      category: "data_leak",
      affectedAsset: host,
      cvssScore: "3.7",
      remediation: "Verify your organisation owns each npm scope referenced here, and claim any it does not.",
      evidence: { source, host, packages: scopeOwned },
    });
  }

  if (result.unavailable || result.skipped.length > 0) {
    findings.push({
      title: `Dependency names on ${host} not fully checked`,
      description: result.unavailable
        ? `No package registry could be reached, so the dependencies referenced by ${source} on ${host} were not checked. This is not a statement that they are all claimed.`
        : `Some dependencies were not checked: ${result.skipped.slice(0, 10).map((s) => `${s.name} (${s.reason})`).join("; ")}.`,
      severity: "info",
      category: "data_leak",
      affectedAsset: host,
      cvssScore: "0.0",
      remediation: result.unavailable
        ? "Re-run when the package registries are reachable."
        : "Dependencies resolved from a git URL, local path or workspace are not subject to this attack and are skipped deliberately.",
      evidence: { source, host, unavailable: result.unavailable, skipped: result.skipped, checked: result.checked },
    });
  }

  return findings;
}
