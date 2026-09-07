/**
 * Bare-ID routes must prove workspace membership themselves.
 *
 * A "bare-ID" route is one whose path carries an id but NO `:workspaceId` —
 * `GET /api/scans/:id1/diff/:id2`, `GET /api/asset-risk/:assetId/history`.
 * `requireWorkspaceRole` cannot help there: it derives the workspace from the
 * URL, and there is none to derive. So the handler has to resolve the object,
 * read its `workspaceId`, and check the caller is a member.
 *
 * Two routes did not, and both leaked across tenants. `scan-diff` was the worse
 * of the pair: it returned full finding objects — titles, descriptions,
 * affected assets — for any two scan ids an authenticated user cared to name,
 * because `compareScanFindings` resolves each scan, takes its `workspaceId`,
 * and reads that workspace's findings without the caller ever being consulted.
 *
 * The static scan at the bottom is the part that matters long-term: it fails
 * when a NEW bare-ID route appears without a guard, so this class of bug cannot
 * come back quietly.
 */
import { describe, it, expect } from "vitest";
import fs from "fs";
import path from "path";

const ROUTES_DIR = path.join(process.cwd(), "server", "routes");

interface RouteRef {
  file: string;
  method: string;
  routePath: string;
  line: number;
  registration: string;
  body: string;
}

/** Every route registration in server/routes, with its handler body. */
function collectRoutes(): RouteRef[] {
  const re = /^\s*\w+Router\.(get|post|put|patch|delete)\(\s*["']([^"']+)["']([^)]*)/gm;
  const out: RouteRef[] = [];
  for (const file of fs.readdirSync(ROUTES_DIR).filter((f) => f.endsWith(".ts"))) {
    const src = fs.readFileSync(path.join(ROUTES_DIR, file), "utf8");
    const lines = src.split("\n");
    const matches = Array.from(src.matchAll(re));
    for (let i = 0; i < matches.length; i++) {
      const m = matches[i];
      const start = src.slice(0, m.index!).split("\n").length - 1;
      const nextIdx = matches[i + 1]?.index;
      const end = nextIdx === undefined ? lines.length : src.slice(0, nextIdx).split("\n").length - 1;
      out.push({
        file,
        method: m[1].toUpperCase(),
        routePath: m[2],
        line: start + 1,
        registration: m[3],
        body: lines.slice(start, end).join("\n"),
      });
    }
  }
  return out;
}

/** A route that names an id but cannot derive the workspace from its path. */
function isBareId(r: RouteRef): boolean {
  return /:\w+/.test(r.routePath) && !r.routePath.includes(":workspaceId");
}

/**
 * Routes that legitimately need no workspace check, with the reason.
 * Anything not listed here must guard itself.
 */
const EXEMPT: Record<string, string> = {
  "GET /playbooks/:id": "playbooks are static built-in definitions, not tenant data",
  "DELETE /api-keys/:id": "scoped by eq(apiKeys.userId, req.user.id) — ownership, not workspace",
};

function isGuarded(r: RouteRef): boolean {
  const viaMiddleware = /requireWorkspaceRole|wsAuth|wsWrite|wsAdmin|requireRole/.test(r.registration);
  const viaHandler = /getWorkspaceMember|workspaceMembers|apiKeys\.userId|users\.id/.test(r.body);
  return viaMiddleware || viaHandler;
}

describe("bare-ID routes", () => {
  it("finds routes to check (the scanner itself works)", () => {
    const routes = collectRoutes();
    expect(routes.length).toBeGreaterThan(50);
    expect(routes.filter(isBareId).length).toBeGreaterThan(5);
  });

  /**
   * The regression guard. A new bare-ID route with no membership check is a
   * cross-tenant read, and it should fail the build rather than ship.
   */
  it("every bare-ID route proves membership or is explicitly exempt", () => {
    const unguarded = collectRoutes()
      .filter(isBareId)
      .filter((r) => !EXEMPT[`${r.method} ${r.routePath}`])
      .filter((r) => !isGuarded(r))
      .map((r) => `${r.file}:${r.line} ${r.method} ${r.routePath}`);

    expect(
      unguarded,
      `Bare-ID routes with no workspace membership check (cross-tenant read):\n${unguarded.join("\n")}\n` +
        "Resolve the object, read its workspaceId, and check storage.getWorkspaceMember — " +
        "or add it to EXEMPT with a reason.",
    ).toEqual([]);
  });

  /** The two that were actually leaking, pinned by name so a revert is loud. */
  it("scan-diff checks BOTH scans, not just the first", () => {
    const src = fs.readFileSync(path.join(ROUTES_DIR, "scan-diff.ts"), "utf8");
    expect(src).toContain("getWorkspaceMember(scan1.workspaceId");
    expect(src).toContain("getWorkspaceMember(scan2.workspaceId");
    // Diffing across workspaces is meaningless and smuggles one tenant's data
    // into a response about another.
    expect(src).toContain("scan1.workspaceId !== scan2.workspaceId");
  });

  it("asset-risk history resolves the asset and checks its workspace", () => {
    const src = fs.readFileSync(path.join(ROUTES_DIR, "asset-risk.ts"), "utf8");
    expect(src).toContain("getWorkspaceMember(asset.workspaceId");
  });

  /**
   * Membership failures must be 404, not 403 — a 403 confirms the id belongs to
   * somebody, which is the enumeration oracle the convention exists to close.
   */
  it("answers a non-member with 404 rather than 403", () => {
    for (const file of ["scan-diff.ts", "asset-risk.ts"]) {
      const src = fs.readFileSync(path.join(ROUTES_DIR, file), "utf8");
      expect(src, `${file} should not 403 on membership`).not.toMatch(/sendError\(res,\s*403/);
      expect(src, `${file} should 404 on membership`).toMatch(/sendNotFound\(/);
    }
  });

  /*
   * There is deliberately NO blanket static check for
   * `if (!member || wrongRole) return 403`.
   *
   * It was written and then removed, because the shape alone is not the bug.
   * `POST /api/scans` uses exactly that line and leaks nothing: it performs no
   * prior existence lookup, so a nonexistent workspace and someone else's
   * workspace both answer 403 — measured, identical responses.
   *
   * The webhook handlers leaked because they did something extra: 404 on a
   * missing row, THEN 403 on a non-member. That PAIR is the oracle, and a
   * regex over one line cannot see it. A static rule that fires on correct code
   * is worse than none — it trains people to edit the test.
   *
   * `scripts/probe-cross-tenant.mjs` checks the property empirically instead,
   * by making real requests as a second tenant.
   */
});

/**
 * Workspace PATCH and DELETE hand-roll their membership check rather than using
 * `requireWorkspaceRole`, and both collapsed "not a member" and "wrong role"
 * into a single 403. That is a membership oracle: iterate workspace ids and
 * every 403 is a confirmed tenant, while a 404 is not.
 *
 * Found by an API smoke sweep — every READ of another tenant's workspace
 * answered 404 and DELETE answered 403, which is the inconsistency that gives it
 * away. The rule is the one `requireWorkspaceRole` already follows: non-member
 * ⇒ 404, member with an insufficient role ⇒ 403, because that member already
 * knows the workspace exists.
 */
describe("workspace PATCH/DELETE do not leak existence", () => {
  const source = fs.readFileSync(path.join(ROUTES_DIR, "workspaces.ts"), "utf-8");

  it("answers 404 before 403 in both handlers", () => {
    // Each handler must reject a non-member with 404 on its own line, before
    // any role comparison reaches a 403.
    const notMember404 = source.match(
      /if \(!membership\) return res\.status\(404\)/g,
    );
    expect(notMember404).not.toBeNull();
    expect(notMember404!.length).toBeGreaterThanOrEqual(2);
  });

  it("no longer folds a missing membership into the role check", () => {
    expect(source).not.toMatch(/if \(!membership \|\|/);
  });
});
