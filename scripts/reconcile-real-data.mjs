/**
 * Cross-check every aggregate the product publishes against the findings API.
 *
 * This exists because reconciling a rendered number against its source has
 * found more real bugs in this codebase than any other technique, and all of
 * them were invisible to the test suite — the suites were green throughout:
 *
 *  - `certificate_authority` and `web_application` were in no taxonomy, so they
 *    deducted from the security score while appearing in **no** risk factor and
 *    **no** compliance control. Caught because 98 open findings summed to 97 in
 *    the factor rows;
 *  - `getSlaSummary` and the SLA sweep did not filter `kind`, so `control`
 *    findings — evidence a protection IS in place — carried remediation
 *    deadlines and would eventually page somebody as an SLA breach. Caught
 *    because `slaOpen` was 26 where `openSec` was 21;
 *  - the trend endpoints did not filter `kind` either, so `/trends` reported
 *    **14 open findings on a workspace whose inbox showed 4**.
 *
 * Every one is the same shape: a number that describes something slightly
 * different from what its label claims, with nothing throwing.
 *
 *   node scripts/reconcile-real-data.mjs
 *
 * Exits non-zero on any disagreement. Like `smoke-real-data.mjs` this is a
 * SCRIPT, not a test: it reads whatever workspaces exist, so it cannot assert
 * fixed numbers or gate CI.
 */
const BASE = process.env.APP_URL || "http://localhost:5050";
const EMAIL = process.env.SEED_ADMIN_EMAIL || "admin@cyshield.local";
const PASSWORD = process.env.SEED_ADMIN_PASSWORD || "ChangeMe123!";

const login = await fetch(`${BASE}/api/auth/login`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
});
if (!login.ok) {
  console.error(`Login failed (${login.status}). Is the app running on ${BASE}?`);
  process.exit(1);
}
const { token } = await login.json();
const H = { Authorization: `Bearer ${token}` };

const get = async (path) => {
  const r = await fetch(BASE + path, { headers: H });
  const t = await r.text();
  return t ? JSON.parse(t) : null;
};
/** Both pagination conventions unwrap to rows; see queryClient.getQueryFn. */
const rows = (x) => (Array.isArray(x) ? x : (x?.data ?? []));

const problems = [];
/** Workspaces actually examined — see the coverage guard at the end. */
let reconciled = 0;
const check = (cond, msg) => { if (!cond) problems.push(msg); };

const workspaces = rows(await get("/api/workspaces"));
if (workspaces.length === 0) {
  console.error("No workspaces visible — this script needs real data to be useful.");
  process.exit(1);
}

for (const w of workspaces) {
  const findings = rows(await get(`/api/workspaces/${w.id}/findings`));
  if (findings.length === 0) continue;
  reconciled++;

  // The one definition everything else is checked against: what the triage
  // inbox and the security score both count.
  const openSec = findings.filter(
    (f) => f.status === "open" && (f.kind ?? "security") === "security",
  );
  const sevCount = (s) => openSec.filter((f) => f.severity === s).length;
  const at = (msg) => `[${w.name}] ${msg}`;

  // ── Compliance: every open security finding must reach at least one control.
  // An unmapped one renders as "No Data", which reads as a pass.
  const compliance = (await get(`/api/workspaces/${w.id}/compliance`)) ?? {};
  const mapped = new Set();
  for (const report of Object.values(compliance)) {
    for (const m of report.mappings ?? []) for (const id of m.findingIds ?? []) mapped.add(id);
  }
  const unmapped = openSec.filter((f) => !mapped.has(f.id));
  check(
    unmapped.length === 0,
    at(`${unmapped.length}/${openSec.length} open findings reach NO compliance control` +
       ` — categories: ${[...new Set(unmapped.map((f) => f.category))].join(", ")}`),
  );

  // ── SLA: the clock applies to WORK, so its buckets must partition exactly the
  // open security set, and must not silently include controls or recon facts.
  const sla = await get(`/api/workspaces/${w.id}/sla-summary`);
  if (sla && typeof sla.open === "number") {
    check(sla.open === openSec.length,
      at(`sla-summary open ${sla.open} != open security findings ${openSec.length}`));
    check((sla.breached ?? 0) + (sla.dueSoon ?? 0) + (sla.onTrack ?? 0) === sla.open,
      at(`sla buckets do not partition open (${sla.breached}/${sla.dueSoon}/${sla.onTrack} vs ${sla.open})`));
  }

  // ── Trends must agree with the inbox about how many findings exist.
  const trend = (await get(`/api/workspaces/${w.id}/trends/findings`)) ?? [];
  const trendTotal = trend.reduce((a, d) => a + (d.total ?? 0), 0);
  check(trendTotal === openSec.length,
    at(`trends/findings totals ${trendTotal} != open security ${openSec.length}`));
  for (const s of ["critical", "high", "medium", "low", "info"]) {
    const t = trend.reduce((a, d) => a + (d[s] ?? 0), 0);
    check(t === sevCount(s), at(`trends/findings ${s}=${t} != ${sevCount(s)}`));
  }

  const cats = (await get(`/api/workspaces/${w.id}/trends/categories`)) ?? [];
  const catOpen = cats.reduce((a, c) => a + (c.open ?? 0), 0);
  check(catOpen === openSec.length,
    at(`trends/categories open sums to ${catOpen} != open security ${openSec.length}`));

  /*
   * ── The AI insights panel says the number out loud.
   *
   * `buildFallbackInsights` writes "Workspace X has N security findings",
   * using those words, and was handed every row in the workspace — so a live
   * workspace read **"has 14 security findings"** with 4 in its inbox, the
   * other ten being recon rows and two working controls. The same set is the
   * LLM's prompt context.
   *
   * The GET route is checked rather than the summary POST because the POST can
   * block for up to 30 minutes on Ollama inference; both are fed by the same
   * filter, so this catches the same defect without the wait.
   */
  const insights = await get(`/api/workspaces/${w.id}/ai-insights`);
  /*
   * A response that is not the expected shape means the check DID NOT RUN.
   *
   * The first version read `insights?.findings ?? []` and compared its length,
   * so a 429 — a body of `{ message: … }` — became "0 findings" and was
   * reported as a real disagreement on five of six workspaces. A gate that
   * turns "could not check" into "checked and wrong" is the same three-state
   * failure this whole audit keeps finding, committed inside the tool written
   * to catch it. A false alarm is not the safe direction either: it trains
   * whoever reads the output to disbelieve it.
   */
  if (!Array.isArray(insights?.findings)) {
    problems.push(at(`ai-insights did not answer with findings (${JSON.stringify(insights).slice(0, 80)}) — NOT CHECKED`));
  } else {
    check(insights.findings.length === openSec.length,
      at(`ai-insights offers ${insights.findings.length} findings != open security ${openSec.length}`));
  }

  // ── Finding groups must not cite findings that do not exist.
  const ids = new Set(findings.map((f) => f.id));
  const groups = rows(await get(`/api/workspaces/${w.id}/finding-groups`));
  const ghosts = groups.flatMap((g) => (g.findingIds ?? [])).filter((id) => !ids.has(id));
  check(ghosts.length === 0, at(`${ghosts.length} grouped finding id(s) do not exist`));

  /*
   * A group is rendered as triage work — a severity badge and an "N instances"
   * count — so everything inside one is presented as outstanding exposure.
   * `groupFindings` used to cluster every row in the workspace, and two live
   * groups mixed kinds: "Strapi API - Detect" claimed 5 instances built from
   * `recon` technology facts AND security findings, taking its title and
   * severity from whichever member came first.
   */
  const byId = new Map(findings.map((f) => [f.id, f]));
  const CLOSED = new Set(["resolved", "false_positive", "accepted_risk"]);
  const wrongKind = [];
  for (const g of groups) {
    for (const id of g.findingIds ?? []) {
      const f = byId.get(id);
      if (!f) continue;
      if ((f.kind ?? "security") !== "security") wrongKind.push(`${g.title}: ${f.kind}`);
      else if (CLOSED.has(f.status)) wrongKind.push(`${g.title}: ${f.status}`);
    }
  }
  check(
    wrongKind.length === 0,
    at(`${wrongKind.length} grouped finding(s) are not open security work — ` +
       `${[...new Set(wrongKind)].slice(0, 3).join("; ")}`),
  );

  // ── The asset page filters client-side, so a truncated fetch changes answers.
  const assets = await get(`/api/workspaces/${w.id}/assets?limit=1`);
  const assetTotal = assets?.total ?? 0;
  const scored = rows(await get(`/api/asset-risk?workspaceId=${w.id}`));
  check(scored.length <= assetTotal,
    at(`${scored.length} scored assets > ${assetTotal} in inventory`));

  /*
   * The risk score must actually respond to the findings.
   *
   * Both category-driven factors named categories no detector emits — the set
   * was hyphenated (`open-port`, `tls`) while the engine emits snake_case — so
   * they matched nothing, and medium/low findings fed no factor at all. The
   * result was that EVERY asset in EVERY workspace scored 0.0 and rendered
   * green: 2,633 assets, 163 open findings, a uniformly clean page. Every unit
   * test passed, because they fed the factors the same invented vocabulary the
   * factors expected.
   *
   * A number that is constant regardless of its inputs is not a low score, it
   * is a disconnected one, so this asserts the connection rather than a value.
   */
  const withFindings = scored.filter((a) => (a.findingCount ?? 0) > 0);
  if (openSec.length > 0) {
    check(withFindings.length > 0,
      at(`${openSec.length} open security findings but no asset has any attributed — ` +
         "findings are unjoinable to the inventory"));
    check(withFindings.some((a) => a.overallScore > 0),
      at(`${withFindings.length} assets carry findings yet every score is 0 — ` +
         "the risk factors are disconnected from the findings"));

    /*
     * The severity has to survive the journey to the page.
     *
     * 40 is where the UI stops colouring a score green, so a workspace holding
     * an open MEDIUM (or worse) finding whose every asset still reads green is
     * reporting a clean estate over outstanding work. This is the check that
     * catches the whole class: a single `some(score > 0)` passed on live data
     * even while medium and low findings fed nothing, because one unrelated
     * TLS finding somewhere in the estate was enough to satisfy it.
     */
    const worstOpen = ["critical", "high", "medium"].some((s) =>
      openSec.some((f) => (f.severity ?? "").toLowerCase() === s),
    );
    if (worstOpen) {
      check(withFindings.some((a) => a.overallScore >= 40),
        at("holds an open medium-or-worse finding, yet every asset scores below " +
           "40 — the risk page renders the whole estate green"));
    }
  }

  // Every asset the page renders must say how many findings it was scored
  // from: a 0 from nothing found and a 0 from low findings are different
  // claims, and the table renders them differently.
  check(scored.every((a) => typeof a.findingCount === "number"),
    at("asset risk rows are missing findingCount"));

  // An asset with nothing attributed must not carry a score, or the page
  // asserts an assessment it never made.
  const phantom = scored.filter((a) => (a.findingCount ?? 0) === 0 && a.overallScore > 0);
  check(phantom.length === 0,
    at(`${phantom.length} asset(s) score above 0 with no findings behind them`));

  // NOTE: report content is NOT checked here. There is no read-only endpoint
  // that returns it, and a check against a URL that does not exist would pass
  // forever while asserting nothing. `scripts/verify-report-content.mts` drives
  // the real builders instead.

  console.log(
    `${w.name}: openSec=${openSec.length} mapped=${openSec.length - unmapped.length}` +
    ` sla=${sla?.open ?? "-"} trend=${trendTotal} cats=${catOpen} assets=${scored.length}/${assetTotal}`,
  );
}

/*
 * A gate that checked nothing must not report success.
 *
 * Every workspace with no findings is skipped, so on a fresh or emptied
 * database this would loop over nothing and print its success line. The
 * authorization probe shipped with exactly that hole — a bad header made
 * every request 401, each iteration hit `continue`, and it still claimed the
 * property held. Counting what was actually examined is the cheapest defence.
 */
if (reconciled === 0) {
  problems.push(
    "NO COVERAGE: no workspace had findings, so nothing was reconciled — this run cannot have passed",
  );
}

if (problems.length) {
  console.error(`\n${problems.length} disagreement(s):`);
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log("\nevery published aggregate agrees with the findings API.");
