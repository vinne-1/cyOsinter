/**
 * End-to-end live validation: login → full GOLD scan → poll → fetch findings +
 * summary → generate & download DOCX report. All HTTP via curl (avoids the Windows
 * Node-fetch libuv teardown crash). Usage: node scripts/live-scan-report.mjs <target>
 */
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";

const BASE = process.env.BASE || "http://localhost:5050";
const TARGET = process.argv[2] || "mydesk.theranym.com";
const EMAIL = process.env.SEED_ADMIN_EMAIL || "admin@cyshield.local";
const PASS = process.env.SEED_ADMIN_PASSWORD || "ChangeMe123!";
const OUT = process.env.OUT || "./live-report.docx";

function curl(args) {
  const out = execFileSync("curl", ["-s", ...args], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return out;
}
function api(method, path, token, body) {
  const args = ["-X", method, `${BASE}${path}`, "-H", "Content-Type: application/json"];
  if (token) args.push("-H", `Authorization: Bearer ${token}`);
  if (body) args.push("-d", JSON.stringify(body));
  const raw = curl(args);
  try { return JSON.parse(raw); } catch { return { __raw: raw }; }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  console.log(`[1] Login as ${EMAIL}`);
  const login = api("POST", "/api/auth/login", null, { email: EMAIL, password: PASS });
  const token = login.token || login.data?.token || login.session?.token;
  if (!token) { console.error("Login failed:", JSON.stringify(login).slice(0, 300)); process.exit(1); }
  console.log("    token acquired");

  console.log("[2a] Create a fresh workspace (clean dedup baseline)");
  const wsName = `verify-${TARGET}-${Date.now()}`;
  const ws = api("POST", "/api/workspaces", token, { name: wsName, domain: TARGET });
  const freshWs = ws.id || ws.data?.id;
  if (!freshWs) { console.error("Workspace create failed:", JSON.stringify(ws).slice(0, 300)); process.exit(1); }
  console.log(`    workspace=${freshWs} (${wsName})`);

  const MODE = process.env.MODE || "gold";
  console.log(`[2b] Trigger FULL ${MODE.toUpperCase()} scan on ${TARGET}`);
  const scan = api("POST", "/api/scans", token, { target: TARGET, type: "full", mode: MODE, workspaceId: freshWs });
  const scanId = scan.id || scan.data?.id;
  const workspaceId = scan.workspaceId || scan.data?.workspaceId;
  if (!scanId) { console.error("Scan trigger failed:", JSON.stringify(scan).slice(0, 400)); process.exit(1); }
  console.log(`    scanId=${scanId} workspaceId=${workspaceId}`);

  console.log("[3] Poll until complete (max 15 min)");
  let status = "pending", summary = null, lastPct = -1;
  for (let i = 0; i < 180; i++) {
    await sleep(5000);
    const s = api("GET", `/api/scans/${scanId}`, token);
    status = s.status || s.data?.status || status;
    const pct = s.progressPercent ?? s.data?.progressPercent ?? "";
    summary = s.summary || s.data?.summary || summary;
    if (pct !== lastPct) { process.stdout.write(`    [${i}] status=${status} ${pct !== "" ? pct + "%" : ""}\n`); lastPct = pct; }
    if (status === "completed" || status === "failed") break;
  }
  console.log(`    final status=${status}`);
  console.log(`    summary=${JSON.stringify(summary)}`);
  if (status !== "completed") { console.error("Scan did not complete."); process.exit(1); }

  console.log("[4] Fetch findings");
  const f = api("GET", `/api/workspaces/${workspaceId}/findings?limit=500`, token);
  const findings = f.data || f.findings || (Array.isArray(f) ? f : []);
  console.log(`    ${findings.length} finding(s) persisted (post-gate)`);
  const bySev = {};
  const byCat = {};
  for (const x of findings) {
    bySev[x.severity] = (bySev[x.severity] || 0) + 1;
    byCat[x.category] = (byCat[x.category] || 0) + 1;
  }
  console.log("    by severity:", JSON.stringify(bySev));
  console.log("    by category:", JSON.stringify(byCat));

  // Dump each finding + whether it carries a live verification marker
  console.log("\n[5] Per-finding verification markers:");
  for (const x of findings) {
    const ev = Array.isArray(x.evidence) ? x.evidence : [];
    const v = ev.find((e) => e && e.type === "verification");
    console.log(`  - [${x.severity}] ${x.category} :: ${x.title} @ ${x.affectedAsset}`);
    console.log(`      verify: ${v ? `${v.verificationStatus} — ${v.snippet}` : "(none)"}`);
  }

  console.log("\n[6] Create report record");
  const rep = api("POST", `/api/workspaces/${workspaceId}/reports`, token, {
    title: `Live validation — ${TARGET}`, type: "full_report",
  });
  const reportId = rep.id || rep.data?.id;
  if (!reportId) { console.error("Report create failed:", JSON.stringify(rep).slice(0, 300)); process.exit(1); }
  console.log(`    reportId=${reportId} (polling generation)`);
  let repStatus = "draft";
  for (let i = 0; i < 40; i++) {
    await sleep(3000);
    const r = api("GET", `/api/reports/${reportId}`, token);
    repStatus = r.status || r.data?.status || repStatus;
    if (repStatus === "completed") break;
    if (repStatus === "draft" && i > 2) break; // generation errored back to draft
  }
  console.log(`    report status=${repStatus}`);

  console.log("[7] Download DOCX report (with live evidence screenshots)");
  const dl = curl([
    "-X", "GET", `${BASE}/api/workspaces/${workspaceId}/reports/${reportId}/export?format=docx&evidence=1`,
    "-H", `Authorization: Bearer ${token}`, "-o", OUT, "-w", "%{http_code}",
  ]);
  console.log(`    report HTTP ${dl} → ${OUT}`);

  // Persist a machine-readable dump for inspection
  writeFileSync("./live-findings.json", JSON.stringify({ target: TARGET, status, summary, findings }, null, 2));
  console.log("    wrote ./live-findings.json");
  console.log("\nDONE");
}
main().catch((e) => { console.error(e); process.exit(2); });
