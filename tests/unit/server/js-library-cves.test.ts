/**
 * Known vulnerabilities in served client-side libraries.
 *
 * `tech-fingerprints.ts` captured library versions from the day it was written,
 * and the only consumer used them to emit "Exact version disclosed — suppress
 * version banners". So the engine could see a site running jQuery 1.8.3 and
 * reported the *disclosure of the version number* rather than the five known XSS
 * advisories affecting it.
 *
 * OSV is mocked here: the suite must not depend on a public service being
 * reachable, and the interesting behaviour is what this module does with the
 * answer — including when there is no answer.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("../../../server/logger", () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));

import {
  npmPackageFor,
  normalizeVersion,
  findVulnerableLibraries,
  buildLibraryFindings,
  resetOsvCache,
} from "../../../server/scanner/js-library-cves";

/** Advisory shaped like a real OSV record. */
const advisory = (id: string, severity: string, fixed?: string) => ({
  id,
  summary: `Cross-Site Scripting in ${id}`,
  aliases: [`CVE-2020-${id.slice(-4)}`],
  database_specific: { severity },
  affected: fixed ? [{ ranges: [{ events: [{ introduced: "0" }, { fixed }] }] }] : [],
});

/** Serves a fixed OSV response per `package@version`; anything else is clean. */
function mockOsv(byKey: Record<string, unknown[]>, opts: { fail?: boolean } = {}) {
  return vi.fn(async (_url: string, init: { body: string }) => {
    if (opts.fail) throw new Error("ECONNREFUSED");
    const q = JSON.parse(init.body) as { package: { name: string }; version: string };
    const vulns = byKey[`${q.package.name}@${q.version}`] ?? [];
    return { ok: true, json: async () => ({ vulns }) };
  });
}

beforeEach(() => resetOsvCache());
afterEach(() => vi.unstubAllGlobals());

describe("npmPackageFor", () => {
  it("maps known browser libraries to their npm package", () => {
    expect(npmPackageFor("jQuery")).toBe("jquery");
    expect(npmPackageFor("Bootstrap")).toBe("bootstrap");
    expect(npmPackageFor("Moment.js")).toBe("moment");
  });

  /**
   * The fingerprint matches AngularJS 1.x and modern Angular alike, but they are
   * different npm packages with different advisory histories. Querying the wrong
   * one either invents vulnerabilities or misses them.
   */
  it("separates AngularJS 1.x from modern Angular by major version", () => {
    expect(npmPackageFor("Angular", "1.5.8")).toBe("angular");
    expect(npmPackageFor("Angular", "17.2.0")).toBe("@angular/core");
  });

  it("refuses to guess Angular's package without a version", () => {
    expect(npmPackageFor("Angular")).toBeNull();
  });

  /** Server software is out of scope: its banner is unreliable and not npm. */
  it("returns null for technologies it cannot map", () => {
    expect(npmPackageFor("nginx", "1.18.0")).toBeNull();
    expect(npmPackageFor("Cloudflare")).toBeNull();
  });
});

describe("normalizeVersion", () => {
  it("pads a partial version", () => {
    expect(normalizeVersion("1.8")).toBe("1.8.0");
    expect(normalizeVersion("3")).toBe("3.0.0");
  });

  it("accepts a leading v and trailing pre-release noise", () => {
    expect(normalizeVersion("v3.3.7")).toBe("3.3.7");
    expect(normalizeVersion("2.1.4-rc1")).toBe("2.1.4");
  });

  it("refuses anything that is not a version rather than guessing", () => {
    expect(normalizeVersion("latest")).toBeNull();
    expect(normalizeVersion("")).toBeNull();
    expect(normalizeVersion(undefined)).toBeNull();
  });
});

describe("findVulnerableLibraries", () => {
  it("reports advisories for an outdated library", async () => {
    vi.stubGlobal("fetch", mockOsv({
      "jquery@1.8.3": [advisory("GHSA-aaaa", "MODERATE", "3.4.0"), advisory("GHSA-bbbb", "MODERATE", "3.5.0")],
    }));

    const r = await findVulnerableLibraries([{ name: "jQuery", version: "1.8.3" }]);

    expect(r.vulnerable).toHaveLength(1);
    expect(r.vulnerable[0]).toMatchObject({ packageName: "jquery", version: "1.8.3", severity: "medium" });
    // The upgrade target is the HIGHEST fixed version across advisories —
    // upgrading to the lowest would still leave the others open.
    expect(r.vulnerable[0].fixedIn).toBe("3.5.0");
    expect(r.unavailable).toBe(false);
  });

  /** A current library producing no finding matters as much as an old one producing several. */
  it("reports nothing for a current version", async () => {
    vi.stubGlobal("fetch", mockOsv({}));
    const r = await findVulnerableLibraries([{ name: "jQuery", version: "3.7.1" }]);
    expect(r.vulnerable).toEqual([]);
    expect(r.checked).toEqual(["jQuery 3.7.1"]);
    expect(r.unavailable).toBe(false);
  });

  it("takes the worst severity across advisories", async () => {
    vi.stubGlobal("fetch", mockOsv({
      "bootstrap@3.3.7": [advisory("GHSA-l", "LOW"), advisory("GHSA-h", "CRITICAL"), advisory("GHSA-m", "MODERATE")],
    }));
    const r = await findVulnerableLibraries([{ name: "Bootstrap", version: "3.3.7" }]);
    // Capped at high: presence and age are established, exploitability is not.
    expect(r.vulnerable[0].severity).toBe("high");
  });

  /**
   * Three states. An unreachable database must never render as "nothing found".
   */
  it("reports unavailable rather than clean when OSV cannot be reached", async () => {
    vi.stubGlobal("fetch", mockOsv({}, { fail: true }));
    const r = await findVulnerableLibraries([{ name: "jQuery", version: "1.8.3" }]);

    expect(r.unavailable).toBe(true);
    expect(r.vulnerable).toEqual([]);
    expect(r.checked).toEqual([]);
    expect(r.unassessed[0].reason).toMatch(/unreachable/);
  });

  it("is not 'unavailable' when there was simply nothing to look up", async () => {
    vi.stubGlobal("fetch", mockOsv({}, { fail: true }));
    const r = await findVulnerableLibraries([{ name: "nginx", version: "1.18.0" }]);
    // Nothing was queryable, so the service's reachability is not in question.
    expect(r.unavailable).toBe(false);
  });

  it("records a library with no version as unassessed, not as safe", async () => {
    vi.stubGlobal("fetch", mockOsv({}));
    const r = await findVulnerableLibraries([{ name: "React" }]);
    expect(r.vulnerable).toEqual([]);
    expect(r.unassessed).toEqual([
      { library: "React", reason: "no version could be determined from the page" },
    ]);
  });

  /**
   * One estate serves the same build from many hosts; asking a free public
   * service the identical question repeatedly is load it has no duty to absorb.
   */
  it("caches by package and version", async () => {
    const fetchMock = mockOsv({ "jquery@1.8.3": [advisory("GHSA-aaaa", "MODERATE", "3.4.0")] });
    vi.stubGlobal("fetch", fetchMock);

    await findVulnerableLibraries([{ name: "jQuery", version: "1.8.3" }]);
    await findVulnerableLibraries([{ name: "jQuery", version: "1.8.3" }]);
    await findVulnerableLibraries([{ name: "jQuery", version: "1.8.3" }]);

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("deduplicates the same library reported by two fingerprint signals", async () => {
    const fetchMock = mockOsv({});
    vi.stubGlobal("fetch", fetchMock);
    await findVulnerableLibraries([
      { name: "jQuery", version: "3.7.1" },
      { name: "jQuery", version: "3.7.1" },
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe("buildLibraryFindings", () => {
  /**
   * jQuery 1.8.3 carries five advisories. Five rows would bury everything else
   * in the inbox and inflate the counts the posture score derives from — the
   * mistake `checkCookieSecurity` exists to avoid.
   */
  it("emits ONE finding per library, keeping every advisory as evidence", async () => {
    vi.stubGlobal("fetch", mockOsv({
      "jquery@1.8.3": [
        advisory("GHSA-a", "MODERATE", "3.4.0"),
        advisory("GHSA-b", "MODERATE", "3.5.0"),
        advisory("GHSA-c", "LOW", "3.5.0"),
      ],
    }));
    const r = await findVulnerableLibraries([{ name: "jQuery", version: "1.8.3" }]);
    const findings = buildLibraryFindings("app.example.com", r);

    expect(findings).toHaveLength(1);
    expect((findings[0].evidence.advisories as unknown[])).toHaveLength(3);
    expect(findings[0].affectedAsset).toBe("app.example.com");
    expect(findings[0].category).toBe("outdated_software");
    expect(findings[0].remediation).toMatch(/3\.5\.0/);
  });

  /** The claim must not overstate what was established. */
  it("says presence is confirmed but exploitability is not", async () => {
    vi.stubGlobal("fetch", mockOsv({ "jquery@1.8.3": [advisory("GHSA-a", "MODERATE", "3.4.0")] }));
    const r = await findVulnerableLibraries([{ name: "jQuery", version: "1.8.3" }]);
    const [f] = buildLibraryFindings("app.example.com", r);
    expect(f.description).toMatch(/does not confirm/i);
  });

  it("emits an info finding when the database was unreachable", async () => {
    vi.stubGlobal("fetch", mockOsv({}, { fail: true }));
    const r = await findVulnerableLibraries([{ name: "jQuery", version: "1.8.3" }]);
    const findings = buildLibraryFindings("app.example.com", r);

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("info");
    expect(findings[0].description).toMatch(/not a statement that they are current/i);
  });

  it("emits nothing at all when everything checked was current", async () => {
    vi.stubGlobal("fetch", mockOsv({}));
    const r = await findVulnerableLibraries([{ name: "jQuery", version: "3.7.1" }]);
    expect(buildLibraryFindings("app.example.com", r)).toEqual([]);
  });
});
