// Orchestrate a full scan via the running app API. Prints token + scanId.
const BASE = "http://localhost:5050";
const EMAIL = "auth-shared@e2e.local";
const PASS = "TestPassword123!";
const TARGET = "procellbiologics.com";
const MODE = process.argv[2] || "safe";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  // Wait for app + DB readiness
  let ready = false;
  for (let i = 0; i < 30; i++) {
    try {
      const p = await fetch(`${BASE}/api/workspaces`, { headers: { Authorization: "Bearer dummy" } });
      if (p.status !== 500 && p.status !== 502 && p.status !== 0) { ready = true; break; }
    } catch { /* not up yet */ }
    console.log(`waiting for app... (${i + 1})`);
    await sleep(3000);
  }
  if (!ready) throw new Error("app not ready");
  console.log("app ready");

  // Login (register if needed)
  let token;
  let r = await fetch(`${BASE}/api/auth/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: EMAIL, password: PASS }) });
  if (r.ok) { token = (await r.json()).token; console.log("logged in"); }
  else {
    r = await fetch(`${BASE}/api/auth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: "Report User", email: EMAIL, password: PASS }) });
    if (!r.ok) throw new Error("login+register failed: " + r.status + " " + (await r.text()));
    token = (await r.json()).token; console.log("registered");
  }
  const H = { "content-type": "application/json", Authorization: `Bearer ${token}` };

  // Find or create workspace
  let workspaceId;
  const wl = await (await fetch(`${BASE}/api/workspaces`, { headers: H })).json();
  const list = Array.isArray(wl) ? wl : (wl.data || []);
  const existing = list.find((w) => (w.name || "").toLowerCase() === TARGET);
  if (existing) { workspaceId = existing.id; console.log("workspace exists", workspaceId); }
  else {
    const cw = await fetch(`${BASE}/api/workspaces`, { method: "POST", headers: H, body: JSON.stringify({ name: TARGET, description: "OSINT+EASM full scan report" }) });
    if (!cw.ok) throw new Error("create ws failed: " + cw.status + " " + (await cw.text()));
    const wj = await cw.json();
    workspaceId = (wj.data || wj).id;
    console.log("workspace created", workspaceId);
  }

  // Trigger full scan
  const sc = await fetch(`${BASE}/api/scans`, { method: "POST", headers: H, body: JSON.stringify({ target: TARGET, type: "full", mode: MODE, status: "pending", workspaceId, autoGenerateReport: false }) });
  if (!sc.ok) throw new Error("scan trigger failed: " + sc.status + " " + (await sc.text()));
  const sj = await sc.json();
  const scan = sj.data || sj;
  console.log("SCAN_TRIGGERED", JSON.stringify({ token, workspaceId, scanId: scan.id || scan.scanId, mode: MODE }));
}
main().catch((e) => { console.error("ERR", e.message); process.exit(1); });
