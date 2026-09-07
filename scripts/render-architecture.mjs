/**
 * Renders the architecture diagrams used by the strategy document.
 *
 * Written as HTML and screenshotted rather than drawn in a diagram tool, for the
 * same reason the UI figures are captured from the running app: the source is
 * text in the repository, so a diagram can be corrected in a diff and
 * regenerated, instead of being a binary nobody can edit.
 *
 *   node scripts/render-architecture.mjs [--out docs/screenshots]
 */
import { chromium } from "playwright";
import fs from "fs";
import path from "path";

const args = process.argv.slice(2);
const OUT = args.includes("--out") ? args[args.indexOf("--out") + 1] : "docs/screenshots";

const CSS = `
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: "Segoe UI", system-ui, sans-serif; background: #fff; color: #1a1d23; padding: 34px; }
  .wrap { width: 1240px; }
  h1 { font-size: 21px; font-weight: 650; margin-bottom: 3px; letter-spacing: -0.2px; }
  .sub { font-size: 12.5px; color: #5b6472; margin-bottom: 22px; }
  .row { display: flex; gap: 12px; margin-bottom: 12px; align-items: stretch; }
  .band { border: 1px solid #d8dee7; border-radius: 9px; padding: 12px 13px; flex: 1; background: #fbfcfe; }
  .band.brand { background: #e8f4f7; border-color: #a9d4de; }
  .band.warn  { background: #fdf4e7; border-color: #eccfa2; }
  .band.new   { background: #edf7ee; border-color: #b3d9b8; }
  .band.plan  { background: #f3f0fa; border-color: #cfc3e8; border-style: dashed; }
  .band h2 { font-size: 11px; text-transform: uppercase; letter-spacing: 0.7px; color: #0e7490; margin-bottom: 8px; font-weight: 660; }
  .band.warn h2 { color: #b45309; } .band.new h2 { color: #2f7d3a; } .band.plan h2 { color: #6b4fa8; }
  .chips { display: flex; flex-wrap: wrap; gap: 5px; }
  .chip { font-size: 11px; background: #fff; border: 1px solid #d8dee7; border-radius: 5px; padding: 3px 7px; white-space: nowrap; }
  .chip.k { border-color: #a9d4de; background: #f2fafc; }
  .note { font-size: 11px; color: #5b6472; margin-top: 7px; line-height: 1.45; }
  .arrow { text-align: center; color: #93a0b0; font-size: 15px; margin: 1px 0 5px; letter-spacing: 3px; }
  .legend { display: flex; gap: 16px; margin-top: 16px; font-size: 11px; color: #5b6472; }
  .key { display: flex; align-items: center; gap: 5px; }
  .sw { width: 11px; height: 11px; border-radius: 3px; border: 1px solid #d8dee7; }
`;

/** Current architecture, as the system actually stands. */
const CURRENT = `
<div class="wrap">
  <h1>Cyshield Pro — architecture as built</h1>
  <div class="sub">Self-hosted. Scan data never leaves the operator's infrastructure — the property that makes it viable under Indian data-localisation rules.</div>

  <div class="row">
    <div class="band"><h2>1 · Discovery — seven independent methods</h2>
      <div class="chips">
        <span class="chip">Certificate transparency</span><span class="chip">Wordlist brute-force</span>
        <span class="chip">9 keyless passive indexes</span><span class="chip k">Chaos</span>
        <span class="chip k">SecurityTrails</span><span class="chip k">BeVigil (mobile APKs)</span>
        <span class="chip">Permutation (learns the estate's own naming)</span>
        <span class="chip">Certificate SANs</span><span class="chip">ASN / BGP footprint</span>
        <span class="chip">Reverse DNS &amp; co-hosting</span><span class="chip">A + AAAA + CNAME</span>
      </div>
      <div class="note">Every host carries provenance: which sources named it, and how many agree. Sources that fail are recorded as failed — never as "found nothing".</div>
    </div>
  </div>
  <div class="arrow">▼</div>

  <div class="row">
    <div class="band"><h2>2 · Probe &amp; fingerprint</h2>
      <div class="chips"><span class="chip">httpx / native probe</span><span class="chip">Ports</span><span class="chip">TLS versions accepted</span><span class="chip">Favicon hash</span><span class="chip">Tech + library versions</span><span class="chip">WAF / CDN</span><span class="chip">Crawler (katana / native)</span></div>
    </div>
    <div class="band"><h2>3 · Detect — 57 modules</h2>
      <div class="chips"><span class="chip">DNS &amp; mail (SPF/DMARC/MTA-STS)</span><span class="chip">Headers &amp; CSP content</span><span class="chip">Cookies</span><span class="chip">Secrets</span><span class="chip">Cloud &amp; container</span><span class="chip">DAST-lite</span><span class="chip">Nuclei</span><span class="chip">OSV library CVEs</span><span class="chip">Dependency confusion</span><span class="chip">Takeover</span></div>
    </div>
  </div>
  <div class="arrow">▼</div>

  <div class="row">
    <div class="band warn"><h2>4 · Evidence pipeline — the part that decides what is true</h2>
      <div class="chips">
        <span class="chip">① Response oracle — soft-404 calibration, so a 200 is not evidence</span>
        <span class="chip">② Body signatures — positive proof the response IS the artefact named</span>
        <span class="chip">③ Verification gate — re-probe at report time; withhold what cannot be reproduced</span>
      </div>
      <div class="note">Anything withheld is recorded as withheld, so "we looked and could not confirm" never renders the same as "we never looked". Measured: 0 false positives across 11 independently verified findings.</div>
    </div>
  </div>
  <div class="arrow">▼</div>

  <div class="row">
    <div class="band"><h2>5 · Attribute &amp; score</h2>
      <div class="chips"><span class="chip">Per-host attribution</span><span class="chip">Severity bands + √n damping</span><span class="chip">SLA clock</span><span class="chip">Cases</span><span class="chip">Finding dedup</span></div>
    </div>
    <div class="band new"><h2>6 · Report &amp; comply</h2>
      <div class="chips"><span class="chip">DOCX / PDF / CSV / XLSX</span><span class="chip">OWASP</span><span class="chip">CIS</span><span class="chip">NIST</span><span class="chip k">CERT-In (6-hour)</span><span class="chip k">DPDP Act</span></div>
    </div>
    <div class="band"><h2>7 · Egress</h2>
      <div class="chips"><span class="chip">SIEM — ECS / CEF</span><span class="chip">Webhooks (HMAC)</span><span class="chip">WebSocket alerts</span><span class="chip">Audit trail</span></div>
    </div>
  </div>

  <div class="legend">
    <div class="key"><span class="sw" style="background:#f2fafc;border-color:#a9d4de"></span> keyed source / India framework</div>
    <div class="key"><span class="sw" style="background:#fdf4e7;border-color:#eccfa2"></span> evidence gates</div>
    <div class="key"><span class="sw" style="background:#edf7ee;border-color:#b3d9b8"></span> client-facing output</div>
  </div>
</div>`;

/** Target architecture: what closes the remaining gap, and what blocks each. */
const PLANNED = `
<div class="wrap">
  <h1>Cyshield Pro — target architecture</h1>
  <div class="sub">Dashed = not yet built. Each carries what actually blocks it, so the plan is a schedule rather than a wish list.</div>

  <div class="row">
    <div class="band"><h2>Built today</h2>
      <div class="chips"><span class="chip">7-method discovery</span><span class="chip">57 detectors</span><span class="chip">3-gate evidence pipeline</span><span class="chip">Per-host attribution</span><span class="chip">5 compliance frameworks</span><span class="chip">SIEM + webhooks</span><span class="chip">Breach corpus</span><span class="chip">Tor transport</span></div>
    </div>
  </div>
  <div class="arrow">▼</div>

  <div class="row">
    <div class="band plan"><h2>Continuous posture — the CERT-In six-hour answer</h2>
      <div class="chips"><span class="chip">Scheduled re-scan → diff</span><span class="chip">Change alerting</span><span class="chip">Draft CERT-In incident form</span><span class="chip">Time-to-notice metric</span></div>
      <div class="note"><strong>Blocked by:</strong> nothing. Scheduler, diff, alerting and the CERT-In mapping all exist — this is wiring, not new capability. Highest value per unit of effort.</div>
    </div>
    <div class="band plan"><h2>ASVS Level 2</h2>
      <div class="chips"><span class="chip">253 cumulative requirements</span><span class="chip">Requirement-by-requirement assessment</span></div>
      <div class="note"><strong>Blocked by:</strong> assessment effort, not code. Much of L2 is already implemented; L1 is at 58 pass / 0 fail.</div>
    </div>
  </div>

  <div class="row">
    <div class="band plan"><h2>Per-account breach exposure</h2>
      <div class="chips"><span class="chip">Employee credential exposure</span><span class="chip">Stealer-log correlation</span></div>
      <div class="note"><strong>Blocked by:</strong> a paid HIBP subscription <em>and</em> proof of domain ownership — deliberately, because it enumerates individuals. Domain-level breach exposure is already built and keyless.</div>
    </div>
    <div class="band plan"><h2>Internet-wide pivoting</h2>
      <div class="chips"><span class="chip">favicon.hash → every host</span><span class="chip">Certificate pivot</span><span class="chip">Shodan / Censys search</span></div>
      <div class="note"><strong>Blocked by:</strong> paid API tier. The Shodan free plan allows host lookup but returns 403 on search. The hash is already computed and shown, so an operator can pivot manually today.</div>
    </div>
  </div>

  <div class="row">
    <div class="band plan"><h2>Entity model — subsidiaries &amp; acquisitions</h2>
      <div class="chips"><span class="chip">Corporate registry</span><span class="chip">WHOIS history</span></div>
      <div class="note"><strong>Blocked by:</strong> data availability. Tested: RDAP unreachable, registrant org GDPR-redacted, crt.sh org search needs the O field modern DV certs omit. This is also Cortex Xpanse's documented weakness — nobody solves it cheaply.</div>
    </div>
    <div class="band plan"><h2>Android / social brand abuse</h2>
      <div class="chips"><span class="chip">Google Play</span><span class="chip">X / LinkedIn / Meta</span></div>
      <div class="note"><strong>Blocked by:</strong> platform policy. No free Play search API; social search is paywalled or withdrawn. iOS is covered and the report states Android was not checked.</div>
    </div>
  </div>

  <div class="row">
    <div class="band plan"><h2>Deep &amp; dark web breadth</h2>
      <div class="chips"><span class="chip">Forum &amp; marketplace monitoring</span><span class="chip">Vetted-access sources</span></div>
      <div class="note"><strong>Blocked by:</strong> a business and legal decision, not engineering. Tor transport and the public ransomware leak-site corpus are already built; forum access needs vetted membership and carries real exposure.</div>
    </div>
    <div class="band plan"><h2>JARM / TLS-stack fingerprinting</h2>
      <div class="chips"><span class="chip">10-probe TLS hash</span></div>
      <div class="note"><strong>Blocked by:</strong> the runtime. Node's tls cannot craft the ClientHello JARM needs, and a hash that does not match the published corpus is worse than none — comparability is the entire point.</div>
    </div>
  </div>
</div>`;

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1310, height: 1000 }, deviceScaleFactor: 2 });
const page = await ctx.newPage();
fs.mkdirSync(OUT, { recursive: true });

for (const [file, html] of [["arch-current", CURRENT], ["arch-planned", PLANNED]]) {
  await page.setContent(`<style>${CSS}</style>${html}`, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(250);
  const el = await page.$(".wrap");
  await el.screenshot({ path: path.join(OUT, `${file}.png`) });
  console.log(`captured ${file}.png`);
}
await browser.close();
