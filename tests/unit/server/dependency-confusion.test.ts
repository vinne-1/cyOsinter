/**
 * Dependency confusion.
 *
 * `secret-scanner.ts` already fetched `/package.json` and `/requirements.txt`
 * when they were exposed, and scanned them for SECRETS only — discarding the
 * dependency list, which is the whole dependency-confusion signal. The manifest
 * was in hand; the most valuable thing in it was thrown away.
 *
 * Registries are mocked: the suite must not depend on npm or PyPI being
 * reachable, and the behaviour worth pinning is what this concludes from an
 * answer — including when there is no answer.
 */
import { describe, it, expect, vi, afterEach } from "vitest";

vi.mock("../../../server/logger", () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));

import {
  isRegistrablePackageName,
  parsePackageJson,
  parseRequirementsTxt,
  resolvesFromRegistry,
  checkDependencyConfusion,
  buildConfusionFindings,
} from "../../../server/scanner/dependency-confusion";

/**
 * `claimed` lists packages that exist publicly; `scopes` lists npm scopes that
 * have at least one public package. Anything else 404s.
 */
function mockRegistries(opts: { claimed?: string[]; scopes?: string[]; fail?: boolean } = {}) {
  const claimed = new Set(opts.claimed ?? []);
  const scopes = new Set(opts.scopes ?? []);
  return vi.fn(async (url: string) => {
    if (opts.fail) throw new Error("ENOTFOUND");

    const scopeSearch = /text=scope:([^&]+)/.exec(url);
    if (scopeSearch) {
      return { ok: true, status: 200, json: async () => ({ total: scopes.has(decodeURIComponent(scopeSearch[1])) ? 1 : 0 }) };
    }

    const npm = /registry\.npmjs\.org\/(.+)$/.exec(url);
    const pypi = /pypi\.org\/pypi\/([^/]+)\/json$/.exec(url);
    const name = npm ? decodeURIComponent(npm[1].replace(/%2f/gi, "/")) : pypi ? decodeURIComponent(pypi[1]) : "";

    return claimed.has(name)
      ? { ok: true, status: 200, json: async () => ({ name }) }
      : { ok: false, status: 404, json: async () => ({}) };
  });
}

afterEach(() => vi.unstubAllGlobals());

describe("parsePackageJson", () => {
  it("reads dependencies and devDependencies", () => {
    const refs = parsePackageJson(JSON.stringify({
      dependencies: { express: "^4.0.0" },
      devDependencies: { vitest: "^1.0.0" },
    }));
    expect(refs.map((r) => [r.name, r.dev])).toEqual([["express", false], ["vitest", true]]);
  });

  it("records the scope of a scoped package", () => {
    const [ref] = parsePackageJson(JSON.stringify({ dependencies: { "@acme/utils": "^1.0.0" } }));
    expect(ref.scope).toBe("@acme");
  });

  /** `npm:` aliases install a DIFFERENT name — that is the name whose ownership matters. */
  it("follows an npm: alias to the package actually installed", () => {
    const [ref] = parsePackageJson(JSON.stringify({ dependencies: { mylodash: "npm:lodash@^4" } }));
    expect(ref.name).toBe("lodash");
  });

  /** This input comes off the public internet; dying on it is worse than ignoring it. */
  it("returns nothing for malformed or non-object JSON", () => {
    expect(parsePackageJson("{not json")).toEqual([]);
    expect(parsePackageJson("[]")).toEqual([]);
    expect(parsePackageJson("null")).toEqual([]);
    expect(parsePackageJson("<!doctype html><html></html>")).toEqual([]);
  });
});

describe("parseRequirementsTxt", () => {
  it("reads plain requirement lines and strips extras", () => {
    const names = parseRequirementsTxt("requests==2.31.0\ndjango>=4.2\nflask[async]~=3.0\n").map((r) => r.name);
    expect(names).toEqual(["requests", "django", "flask"]);
  });

  it("ignores comments, flags, and direct references", () => {
    const names = parseRequirementsTxt([
      "# comment",
      "-r other.txt",
      "-e .",
      "https://example.com/pkg.whl",
      "localpkg @ file:///tmp/x",
      "realpkg",
    ].join("\n")).map((r) => r.name);
    expect(names).toEqual(["realpkg"]);
  });
});

describe("resolvesFromRegistry", () => {
  /** A git/file/workspace dependency is not subject to this attack at all. */
  it("rejects specifiers that bypass the public registry", () => {
    for (const spec of ["file:../x", "link:../x", "workspace:*", "git+https://g/x.git", "github:o/r", "https://x/y.tgz"]) {
      expect(resolvesFromRegistry(spec), spec).toBe(false);
    }
  });

  it("accepts ordinary version ranges", () => {
    for (const spec of ["^1.0.0", "~2.1", "*", "", "latest", ">=3 <4"]) {
      expect(resolvesFromRegistry(spec), spec).toBe(true);
    }
  });
});

describe("checkDependencyConfusion", () => {
  const npmRef = (name: string, specifier = "^1.0.0") => ({
    name, specifier, ecosystem: "npm" as const, dev: false,
    scope: name.startsWith("@") ? name.split("/")[0] : undefined,
  });

  it("says nothing about packages that exist publicly", async () => {
    vi.stubGlobal("fetch", mockRegistries({ claimed: ["express", "lodash"] }));
    const r = await checkDependencyConfusion([npmRef("express"), npmRef("lodash")]);
    expect(r.risks).toEqual([]);
    expect(r.checked).toEqual(["express", "lodash"]);
    expect(r.unavailable).toBe(false);
  });

  /** The classic case: an unscoped internal name anyone may publish today. */
  it("flags an unscoped name nobody owns as high", async () => {
    vi.stubGlobal("fetch", mockRegistries({ claimed: ["express"] }));
    const r = await checkDependencyConfusion([npmRef("express"), npmRef("acme-internal-utils")]);
    expect(r.risks).toHaveLength(1);
    expect(r.risks[0]).toMatchObject({ name: "acme-internal-utils", severity: "high" });
  });

  it("flags a scoped name as high when the scope itself is unregistered", async () => {
    vi.stubGlobal("fetch", mockRegistries({ scopes: [] }));
    const r = await checkDependencyConfusion([npmRef("@acme/billing")]);
    expect(r.risks[0]).toMatchObject({ name: "@acme/billing", severity: "high" });
    expect(r.risks[0].reason).toMatch(/register the scope/);
  });

  /**
   * A registered scope is a real barrier — an attacker cannot publish into a
   * scope they do not own — so this is a "confirm you own it", not a takeover.
   */
  it("downgrades a scoped name when the scope is already registered", async () => {
    vi.stubGlobal("fetch", mockRegistries({ scopes: ["acme"] }));
    const r = await checkDependencyConfusion([npmRef("@acme/billing")]);
    expect(r.risks[0]).toMatchObject({ severity: "low" });
    expect(r.risks[0].reason).toMatch(/already registered/);
  });

  it("skips dependencies that do not resolve from a registry", async () => {
    vi.stubGlobal("fetch", mockRegistries({}));
    const r = await checkDependencyConfusion([npmRef("internal-thing", "file:../internal-thing")]);
    expect(r.risks).toEqual([]);
    expect(r.skipped[0].reason).toMatch(/not a public registry/);
  });

  it("checks PyPI names too", async () => {
    vi.stubGlobal("fetch", mockRegistries({ claimed: ["requests"] }));
    const r = await checkDependencyConfusion([
      { name: "requests", specifier: "==2.31.0", ecosystem: "pypi", dev: false },
      { name: "acme-internal-py", specifier: "", ecosystem: "pypi", dev: false },
    ]);
    expect(r.risks.map((x) => x.name)).toEqual(["acme-internal-py"]);
    expect(r.risks[0].reason).toMatch(/PyPI/);
  });

  /** "We could not check" and "everything is claimed" are opposite conclusions. */
  it("reports unavailable rather than clean when no registry answers", async () => {
    vi.stubGlobal("fetch", mockRegistries({ fail: true }));
    const r = await checkDependencyConfusion([npmRef("anything")]);
    expect(r.unavailable).toBe(true);
    expect(r.risks).toEqual([]);
    expect(r.checked).toEqual([]);
  });

  it("is not 'unavailable' when there was nothing to look up", async () => {
    vi.stubGlobal("fetch", mockRegistries({ fail: true }));
    const r = await checkDependencyConfusion([npmRef("x", "file:../x")]);
    expect(r.unavailable).toBe(false);
  });

  it("deduplicates a name listed twice", async () => {
    const fetchMock = mockRegistries({ claimed: ["express"] });
    vi.stubGlobal("fetch", fetchMock);
    await checkDependencyConfusion([npmRef("express"), npmRef("express")]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  /** A public registry has no duty to absorb a scan of a large estate. */
  it("caps the number of registry lookups", async () => {
    const fetchMock = mockRegistries({ claimed: [] });
    vi.stubGlobal("fetch", fetchMock);
    const many = Array.from({ length: 200 }, (_, i) => npmRef(`pkg-${i}`));
    const r = await checkDependencyConfusion(many);
    expect(r.checked.length).toBeLessThanOrEqual(60);
    expect(r.skipped.some((s) => /budget/.test(s.reason))).toBe(true);
  });
});

describe("buildConfusionFindings", () => {
  const npmRef = (name: string) => ({ name, specifier: "^1.0.0", ecosystem: "npm" as const, dev: false });

  /** One finding listing every name — they are one misconfiguration with one fix. */
  it("emits a single finding for all claimable names", async () => {
    vi.stubGlobal("fetch", mockRegistries({ claimed: [] }));
    const r = await checkDependencyConfusion([npmRef("a-internal"), npmRef("b-internal"), npmRef("c-internal")]);
    const findings = buildConfusionFindings("app.example.com", "/package.json", r);

    const high = findings.filter((f) => f.severity === "high");
    expect(high).toHaveLength(1);
    expect(high[0].title).toMatch(/3 unclaimed package names/);
    expect(high[0].affectedAsset).toBe("app.example.com");
  });

  /**
   * A scoped private registry is the correct mitigation and is invisible from
   * outside, so the finding must not assert the build is exploitable.
   */
  it("states that a public-registry fallback was not confirmed", async () => {
    vi.stubGlobal("fetch", mockRegistries({ claimed: [] }));
    const r = await checkDependencyConfusion([npmRef("a-internal")]);
    const [f] = buildConfusionFindings("app.example.com", "/package.json", r);
    expect(f.description).toMatch(/does not confirm/i);
    expect(f.remediation).toMatch(/\.npmrc|index-url/);
  });

  it("emits nothing when every dependency is publicly owned", async () => {
    vi.stubGlobal("fetch", mockRegistries({ claimed: ["express"] }));
    const r = await checkDependencyConfusion([npmRef("express")]);
    expect(buildConfusionFindings("app.example.com", "/package.json", r)).toEqual([]);
  });

  it("reports an unreachable registry as unassessed, not as clean", async () => {
    vi.stubGlobal("fetch", mockRegistries({ fail: true }));
    const r = await checkDependencyConfusion([npmRef("anything")]);
    const findings = buildConfusionFindings("app.example.com", "/package.json", r);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("info");
    expect(findings[0].description).toMatch(/not a statement that they are all claimed/i);
  });
});

/**
 * The manifest is fetched off the public internet, so its package names are
 * attacker-controlled. An unregistrable name 404s exactly like an unclaimed one,
 * so without this check a hostile `package.json` containing `"../../evil"`
 * produced a finding claiming an attacker could register `../../evil` — which
 * nobody can. Found by adversarial QA.
 */
describe("isRegistrablePackageName", () => {
  it("accepts real npm names", () => {
    for (const n of ["express", "lodash.merge", "@acme/billing", "a", "some-pkg_2"]) {
      expect(isRegistrablePackageName(n, "npm"), n).toBe(true);
    }
  });

  it("rejects names nobody could ever register", () => {
    for (const n of ["../../evil", "..%2f..%2fevil", "foo?callback=x", "foo#frag", "UPPERCASE", "@noslash", "@a/b/c", " lead", "trail ", "", "x".repeat(215)]) {
      expect(isRegistrablePackageName(n, "npm"), n).toBe(false);
    }
  });

  it("applies PyPI's own grammar, which permits capitals", () => {
    expect(isRegistrablePackageName("Django", "pypi")).toBe(true);
    expect(isRegistrablePackageName("../../evil", "pypi")).toBe(false);
  });
});

describe("hostile manifests", () => {
  const hostile = (names: string[]) =>
    JSON.stringify({ dependencies: Object.fromEntries(names.map((n) => [n, "^1.0.0"])) });

  /** The false positive itself: a 404 on an impossible name is not a risk. */
  it("never reports an unregistrable name as claimable", async () => {
    vi.stubGlobal("fetch", mockRegistries({ claimed: [] }));
    const refs = parsePackageJson(hostile(["../../evil", "foo?callback=x", "real-internal-pkg"]));
    const r = await checkDependencyConfusion(refs);

    expect(r.risks.map((x) => x.name)).toEqual(["real-internal-pkg"]);
    expect(r.skipped.some((s) => /cannot be claimed by anyone/.test(s.reason))).toBe(true);
  });

  /** And the hostile names must never reach the network at all. */
  it("does not issue a request for an unregistrable name", async () => {
    const fetchMock = mockRegistries({ claimed: [] });
    vi.stubGlobal("fetch", fetchMock);
    await checkDependencyConfusion(parsePackageJson(hostile(["../../evil"])));
    expect(fetchMock).not.toHaveBeenCalled();
  });

  /**
   * The host must never change, whatever the manifest says. Verified by
   * adversarial QA: `https://evil.example/x` stays on registry.npmjs.org.
   */
  it("keeps every lookup on the registry host", async () => {
    const urls: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      urls.push(url);
      return { ok: false, status: 404, json: async () => ({}) };
    }));
    await checkDependencyConfusion(parsePackageJson(hostile(["@scope/pkg", "normal-pkg"])));
    for (const u of urls) {
      const parsed = new URL(u);
      expect(parsed.origin).toBe("https://registry.npmjs.org");
      // A query string is only ever the scope search this module builds itself;
      // nothing from the manifest may add one.
      expect(parsed.search === "" || parsed.search.startsWith("?text=scope:")).toBe(true);
      expect(parsed.hash).toBe("");
    }
  });
});
