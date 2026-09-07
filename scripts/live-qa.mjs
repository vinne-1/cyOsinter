// Live QA against the running app: workspace-name freedom + DOCX export.
const BASE = "http://localhost:5050";
const EMAIL = "auth-shared@e2e.local";
const PASS = "TestPassword123!";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  // wait for app
  let token;
  for (let i = 0; i < 40; i++) {
    try {
      const r = await fetch(`${BASE}/api/auth/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: EMAIL, password: PASS }) });
      if (r.ok) { token = (await r.json()).token; break; }
      if (r.status === 401) { // register once
        const rr = await fetch(`${BASE}/api/auth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: "QA", email: EMAIL, password: PASS }) });
        if (rr.ok) { token = (await rr.json()).token; break; }
      }
    } catch {}
    console.log(`waiting for app... ${i + 1}`); await sleep(3000);
  }
  if (!token) throw new Error("app not reachable / login failed");
  const H = { "content-type": "application/json", Authorization: `Bearer ${token}` };
  console.log("PASS: logged in");

  // 1) arbitrary workspace name (no domain) — should succeed
  const nm = `QA Arbitrary Name ${Date.now()}`;
  let r = await fetch(`${BASE}/api/workspaces`, { method: "POST", headers: H, body: JSON.stringify({ name: nm }) });
  console.log(r.ok ? `PASS: created arbitrary-name workspace ("${nm}")` : `FAIL: arbitrary name rejected ${r.status} ${await r.text()}`);
  const ws = r.ok ? await r.json() : null;

  // 2) arbitrary name + valid domain — should succeed
  const nm2 = `QA With Domain ${Date.now()}`;
  r = await fetch(`${BASE}/api/workspaces`, { method: "POST", headers: H, body: JSON.stringify({ name: nm2, domain: "example.com" }) });
  console.log(r.ok ? `PASS: created workspace with domain (${(await r.json()).domain})` : `FAIL: name+domain rejected ${r.status} ${await r.text()}`);

  // 3) invalid domain — should be rejected (400)
  r = await fetch(`${BASE}/api/workspaces`, { method: "POST", headers: H, body: JSON.stringify({ name: `QA Bad Domain ${Date.now()}`, domain: "not a domain!!" }) });
  console.log(r.status === 400 ? "PASS: invalid domain rejected (400)" : `FAIL: invalid domain not rejected (${r.status})`);

  // 4) DOCX export for the procellbiologics workspace (has findings)
  const wl = await (await fetch(`${BASE}/api/workspaces`, { headers: H })).json();
  const list = Array.isArray(wl) ? wl : (wl.data || []);
  const proc = list.find((w) => (w.name || "").toLowerCase().includes("procell"));
  if (!proc) { console.log("SKIP: no procellbiologics workspace found for DOCX test"); return; }
  const rep = await fetch(`${BASE}/api/workspaces/${proc.id}/reports`, { method: "POST", headers: H, body: JSON.stringify({ title: "QA DOCX Report", type: "full_report", workspaceId: proc.id }) });
  if (!rep.ok) { console.log(`FAIL: report create ${rep.status} ${await rep.text()}`); return; }
  const report = await rep.json();
  // wait for completion
  let status = report.status;
  for (let i = 0; i < 20 && status !== "completed"; i++) {
    await sleep(2000);
    const g = await fetch(`${BASE}/api/reports/${report.id}`, { headers: H });
    if (g.ok) status = (await g.json()).status;
  }
  console.log("report status:", status);
  const ex = await fetch(`${BASE}/api/workspaces/${proc.id}/reports/${report.id}/export?format=docx`, { headers: H });
  const buf = Buffer.from(await ex.arrayBuffer());
  const ct = ex.headers.get("content-type") || "";
  const isDocx = buf.subarray(0, 2).toString("latin1") === "PK" && /wordprocessingml/.test(ct);
  console.log(isDocx ? `PASS: DOCX export valid (${buf.length} bytes, ${ct})` : `FAIL: DOCX export bad (status ${ex.status}, ct ${ct}, head ${buf.subarray(0,4).toString("latin1")})`);
}
main().catch((e) => { console.error("QA ERROR:", e.message); process.exit(1); });
