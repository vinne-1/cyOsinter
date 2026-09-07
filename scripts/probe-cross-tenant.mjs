/**
 * Authorization probe: cross-tenant isolation, role escalation, key scopes.
 *
 * Three properties no unit test can establish, because each needs two real
 * identities and a live request:
 *
 *  1. a non-member reaches nothing, and cannot tell an existing id from an
 *     absent one;
 *  2. a member cannot exceed their role inside their own workspace;
 *  3. an API key cannot exceed its scope, and no key manages keys.
 *
 * Sections 2 and 3 came up CLEAN when first run — recorded here so the
 * coverage is not mistaken for untested ground later.
 *
 * Creates two tenants that share nothing, gives one of them resources, and has
 * the other try to reach every bare-ID route. Two failures are looked for:
 *
 *  - a **2xx**, which is a straight cross-tenant read or write;
 *  - a **403 where a nonexistent id would have produced 404**, which is a
 *    membership oracle: a stranger iterating ids learns which exist from the
 *    status code alone.
 *
 * The second is why this exists as a script rather than a lint rule. The shape
 * `if (!member || wrongRole) return 403` is NOT the bug on its own —
 * `POST /api/scans` uses exactly that and leaks nothing, because it performs no
 * prior existence lookup, so a nonexistent workspace and someone else's
 * workspace answer identically. The webhook handlers leaked because they 404 on
 * a missing row and 403 on a non-member; that PAIR is the oracle, and no regex
 * over a single line can see it. A static rule strict enough to catch it fires
 * on correct code, which trains people to edit the test.
 *
 *   node scripts/probe-cross-tenant.mjs
 *
 * Exits non-zero on any leak or oracle. Creates and removes its own fixtures;
 * the users it makes are `@e2e.local`, so a stray run is also cleaned by the
 * Playwright teardown.
 */
const BASE = process.env.APP_URL || "http://localhost:5050";

const call = async (path, method = "GET", body = null, token = null) => {
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(BASE + path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let parsed = null;
  try { parsed = text ? JSON.parse(text) : null; } catch { /* non-JSON is fine */ }
  return { status: res.status, body: parsed };
};
const rows = (x) => (Array.isArray(x) ? x : (x?.data ?? []));

const stamp = Date.now();
const PASSWORD = "ProbePassw0rd!x";

async function makeTenant(tag) {
  const email = `xtenant-${tag}-${stamp}@e2e.local`;
  await call("/api/auth/register", "POST", { email, password: PASSWORD, username: `xt${tag}${stamp}` });
  const { body } = await call("/api/auth/login", "POST", { email, password: PASSWORD });
  if (!body?.token) throw new Error(`could not create probe tenant ${tag}`);
  return { email, token: body.token };
}

const outsider = await makeTenant("a");
const owner = await makeTenant("b");

// The owner's resources. The outsider must reach none of them.
const ws = (await call("/api/workspaces", "POST",
  { name: `xtenant-probe-${stamp}.example.com`, description: "cross-tenant probe" }, owner.token)).body;
const scan = (await call("/api/scans", "POST",
  { target: "example.com", type: "passive", workspaceId: ws.id }, owner.token)).body;
const report = (await call(`/api/workspaces/${ws.id}/reports`, "POST",
  { title: "probe", type: "full_report", workspaceId: ws.id }, owner.token)).body;
const kase = (await call(`/api/workspaces/${ws.id}/cases`, "POST",
  { title: "probe case", severity: "low", workspaceId: ws.id }, owner.token)).body;
const profile = (await call("/api/scan-profiles", "POST",
  { workspaceId: ws.id, name: "probe", scanType: "easm", mode: "standard", config: {} }, owner.token)).body;
const hook = (await call(`/api/workspaces/${ws.id}/webhooks`, "POST",
  { name: "probe", url: "https://hooks.slack.com/services/T/B/p", events: ["critical_finding"], provider: "slack" },
  owner.token)).body;

/** A definitely-absent id of the same shape, for the oracle comparison. */
const ABSENT = "00000000-0000-4000-8000-000000000000";

const targets = [
  ["GET", `/api/workspaces/${ws.id}`, `/api/workspaces/${ABSENT}`],
  ["PATCH", `/api/workspaces/${ws.id}`, `/api/workspaces/${ABSENT}`],
  ["DELETE", `/api/workspaces/${ws.id}`, `/api/workspaces/${ABSENT}`],
  ["GET", `/api/scans/${scan?.id}`, `/api/scans/${ABSENT}`],
  ["POST", `/api/scans/${scan?.id}/cancel`, `/api/scans/${ABSENT}/cancel`],
  ["GET", `/api/reports/${report?.id}`, `/api/reports/${ABSENT}`],
  ["GET", `/api/cases/${kase?.id}`, `/api/cases/${ABSENT}`],
  ["GET", `/api/cases/${kase?.id}/findings`, `/api/cases/${ABSENT}/findings`],
  ["GET", `/api/scan-profiles/${profile?.id}`, `/api/scan-profiles/${ABSENT}`],
  ["PATCH", `/api/webhooks/${hook?.id}`, `/api/webhooks/${ABSENT}`],
  ["DELETE", `/api/webhooks/${hook?.id}`, `/api/webhooks/${ABSENT}`],
  ["POST", `/api/webhooks/${hook?.id}/test`, `/api/webhooks/${ABSENT}/test`],
  ["GET", `/api/scans/${scan?.id}/diff/${scan?.id}`, `/api/scans/${ABSENT}/diff/${ABSENT}`],
];

const problems = [];
let checked = 0;

for (const [method, realPath, absentPath] of targets) {
  if (realPath.includes("undefined")) {
    console.log(`  skipped (fixture missing): ${method} ${realPath}`);
    continue;
  }
  const payload = method === "PATCH" ? { name: "hijacked" } : (method === "POST" ? {} : null);
  const real = await call(realPath, method, payload, outsider.token);
  const absent = await call(absentPath, method, payload, outsider.token);
  checked++;

  if (real.status >= 200 && real.status < 300) {
    problems.push(`LEAK ${real.status} ${method} ${realPath} — a non-member reached another tenant's resource`);
  } else if (real.status !== absent.status) {
    problems.push(
      `ORACLE ${method} ${realPath} — existing id answers ${real.status} but an absent id answers ` +
      `${absent.status}, so the status alone reveals the resource exists`,
    );
  }
}

// Best-effort cleanup. The workspace cascade removes its scans, reports, cases,
// profiles and webhooks; the users are @e2e.local so the Playwright teardown
// sweeps anything a crashed run leaves behind.
await call(`/api/workspaces/${ws.id}`, "DELETE", null, owner.token);

console.log(`checked ${checked} cross-tenant request pair(s)`);

// ── Role escalation inside a workspace ──────────────────────────────────────
//
// Cross-tenant isolation says nothing about what a MEMBER may do. There is no
// HTTP route to add a member (the creator becomes owner and that is all), so
// the membership row is written directly — it is the real state an
// administrator would create if that route existed.
const { execFileSync } = await import("child_process");
const psql = (sql) =>
  execFileSync(
    "docker",
    ["exec", "cyshield-db", "psql", "-U", "postgres", "-d", "cyshield", "-t", "-A", "-c", sql],
    { encoding: "utf8" },
  ).trim();

const roleWs = (await call("/api/workspaces", "POST",
  { name: `role-probe-${stamp}.example.com`, description: "role probe" }, owner.token)).body;
const outsiderId = psql(`select id from users where email='${outsider.email}'`);

/** Each privileged call and the LOWEST role that should be allowed it. */
const ROLE_CASES = [
  ["POST", `/api/workspaces/${roleWs.id}/purge`, {}, "owner"],
  ["PATCH", `/api/workspaces/${roleWs.id}`, { description: "escalated" }, "admin"],
  ["POST", `/api/workspaces/${roleWs.id}/webhooks`,
    { name: "esc", url: "https://hooks.slack.com/services/T/B/e", events: ["critical_finding"], provider: "slack" },
    "admin"],
  ["PUT", `/api/workspaces/${roleWs.id}/retention`,
    { scanRetentionDays: 30, findingRetentionDays: 30, snapshotRetentionDays: 30, archiveEnabled: false },
    "admin"],
];
const RANK = { viewer: 0, analyst: 1, admin: 2, owner: 3 };
let roleChecks = 0;

for (const role of ["viewer", "analyst"]) {
  psql(`delete from workspace_members where workspace_id='${roleWs.id}' and user_id='${outsiderId}'`);
  psql(`insert into workspace_members (workspace_id, user_id, role) values ('${roleWs.id}','${outsiderId}','${role}')`);
  for (const [method, routePath, body, minRole] of ROLE_CASES) {
    const { status } = await call(routePath, method, body, outsider.token);
    roleChecks++;
    // Only a 2xx matters. A 4xx that is not 403 — a 409, say — still means the
    // request was authorized and refused for an unrelated reason.
    if (status >= 200 && status < 300 && RANK[role] < RANK[minRole]) {
      problems.push(`ESCALATION ${role} performed ${method} ${routePath} which needs ${minRole} (${status})`);
    }
  }
}
psql(`delete from workspace_members where user_id='${outsiderId}'`);
await call(`/api/workspaces/${roleWs.id}`, "DELETE", null, owner.token);
console.log(`checked ${roleChecks} role-gated call(s)`);

// ── API key scope ───────────────────────────────────────────────────────────
//
// `api_keys.scope` was once validated, stored, badged in the UI and enforced
// NOWHERE, so a key created as "read" could delete workspaces. The rule that
// matters most is the last one: no key manages keys, at any scope including
// full — a leaked key that can mint another survives its own revocation, and
// listing key names is the reconnaissance step for that move.
const adminLogin = await call("/api/auth/login", "POST", {
  email: process.env.SEED_ADMIN_EMAIL || "admin@cyshield.local",
  password: process.env.SEED_ADMIN_PASSWORD || "ChangeMe123!",
});
const sess = adminLogin.body?.token ?? null;
const anyWs = sess ? rows((await call("/api/workspaces", "GET", null, sess)).body)[0] : null;
const mintedKeys = [];
let scopeChecks = 0;

if (sess && anyWs) {
  for (const scope of ["read", "scan", "full"]) {
    const made = await call("/api/api-keys", "POST",
      { name: `scope-probe-${scope}-${stamp}`, scope }, sess);
    if (!made.body?.key) continue;
    mintedKeys.push(made.body.id);
    // `call` adds the Bearer prefix itself; passing one here produced
    // "Bearer Bearer <key>", every request 401d, and the whole section
    // skipped while the script still printed "scopes enforced".
    const keyAuth = made.body.key;

    const readRes = await call(`/api/workspaces/${anyWs.id}/findings`, "GET", null, keyAuth);
    const listKeys = await call("/api/api-keys", "GET", null, keyAuth);
    const mintKey = await call("/api/api-keys", "POST", { name: "minted-by-key", scope: "full" }, keyAuth);
    scopeChecks += 3;

    if (!(readRes.status >= 200 && readRes.status < 300)) {
      problems.push(`scope=${scope} cannot read (${readRes.status}) — every scope should read`);
    }
    if (listKeys.status >= 200 && listKeys.status < 300) {
      problems.push(`scope=${scope} can LIST api keys — no key may manage keys`);
    }
    if (mintKey.status >= 200 && mintKey.status < 300) {
      problems.push(`scope=${scope} can MINT an api key — no key may manage keys`);
    }
  }
  for (const id of mintedKeys) await call(`/api/api-keys/${id}`, "DELETE", null, sess);
}
console.log(`checked ${scopeChecks} api-key scope call(s); cleaned ${mintedKeys.length} key(s)`);

/*
 * A gate that checks nothing must not claim success.
 *
 * The api-key section silently checked ZERO calls for a while — a bad auth
 * header made every mint fail, each scope hit `continue`, and the script still
 * printed "scopes enforced". That is the vacuous-guard failure this codebase
 * keeps finding in its own tests, reproduced in the tool written to find it.
 */
for (const [label, count] of [
  ["cross-tenant", checked], ["role-gated", roleChecks], ["api-key scope", scopeChecks],
]) {
  if (count === 0) problems.push(`NO COVERAGE: the ${label} section checked nothing — it cannot have passed`);
}

if (problems.length) {
  console.error("");
  console.error(`${problems.length} authorization problem(s):`);
  for (const problem of problems) console.error(`  ${problem}`);
  process.exit(1);
}
console.log("");
console.log("no cross-tenant reads, no existence oracles, no role escalation, scopes enforced.");
