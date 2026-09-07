/**
 * Live validation of the verification gate against REAL domains (no mocks).
 * Proves: a bogus "missing header" finding on a hardened site is withheld, while a
 * genuinely-absent header on a bare site is confirmed. Run: npx tsx scripts/live-gate-check.mts
 */
import { runVerificationGate } from "../server/scanner/verification-gate.js";

const mk = (o: { title: string; category: string; affectedAsset: string; evidence?: Record<string, unknown>[] }) => ({
  title: o.title, description: "live check", severity: "medium", remediation: "n/a",
  category: o.category, affectedAsset: o.affectedAsset, evidence: o.evidence,
});

async function main() {
  const cases = [
    // Cloudflare publishes HSTS — a "missing HSTS" finding here is a FALSE POSITIVE → must be withheld.
    mk({ title: "Missing Strict-Transport-Security", category: "security_headers", affectedAsset: "www.cloudflare.com" }),
    // example.com does NOT publish CSP — a "missing CSP" finding is REAL → must be confirmed.
    mk({ title: "Missing Content-Security-Policy", category: "security_headers", affectedAsset: "example.com" }),
    // A bogus exposed-secret pointing at a 404 → must be withheld (fail-closed).
    mk({ title: "Exposed .env", category: "secret_exposure", affectedAsset: "example.com", evidence: [{ url: "https://example.com/.env", snippet: "DB_PASSWORD=nope" }] }),
    // A Nuclei-style vulnerability → unverifiable, kept by policy.
    mk({ title: "CVE-2021-0000", category: "vulnerability", affectedAsset: "example.com" }),
  ];

  const { confirmed, withheld } = await runVerificationGate(cases, { target: "mixed" });

  console.log("\n=== CONFIRMED (kept) ===");
  for (const c of confirmed) console.log(`  [KEEP] ${c.category} :: ${c.title} @ ${c.affectedAsset}`);
  console.log("\n=== WITHHELD (dropped as unreproducible / FP) ===");
  for (const w of withheld) console.log(`  [DROP] ${w.category} :: ${w.title} @ ${w.affectedAsset}  — ${w.reason}`);

  // Assertions
  const keptTitles = new Set(confirmed.map((c) => c.title));
  const dropTitles = new Set(withheld.map((w) => w.title));
  const checks: Array<[string, boolean]> = [
    ["Cloudflare HSTS false-positive withheld", dropTitles.has("Missing Strict-Transport-Security")],
    ["example.com missing-CSP confirmed", keptTitles.has("Missing Content-Security-Policy")],
    ["bogus .env (404) withheld", dropTitles.has("Exposed .env")],
    ["Nuclei CVE kept (unverifiable)", keptTitles.has("CVE-2021-0000")],
  ];
  console.log("\n=== RESULT ===");
  let pass = 0;
  for (const [label, ok] of checks) { console.log(`  ${ok ? "PASS" : "FAIL"}: ${label}`); if (ok) pass++; }
  console.log(`\n${pass}/${checks.length} live gate checks passed`);
  process.exit(pass === checks.length ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(2); });
