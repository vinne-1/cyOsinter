// Manual verification of each finding against the live target.
import dns from "node:dns/promises";
const D = "procellbiologics.com";
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

async function head(url, method = "GET", extra = {}) {
  try {
    const r = await fetch(url, { method, redirect: "manual", headers: { "User-Agent": UA }, ...extra });
    const h = {};
    r.headers.forEach((v, k) => (h[k] = v));
    let bodyLen = 0, snippet = "";
    if (method === "GET") { const b = await r.text(); bodyLen = b.length; snippet = b.slice(0, 160).replace(/\s+/g, " "); }
    return { status: r.status, server: h["server"], loc: h["location"], allow: h["allow"], ct: h["content-type"], bodyLen, snippet, h };
  } catch (e) { return { error: e.message }; }
}

async function main() {
  console.log("== SECURITY HEADERS (homepage) ==");
  const home = await head(`https://${D}/`);
  const wanted = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy"];
  console.log("status", home.status, "server", home.server);
  for (const w of wanted) console.log(`  ${w}: ${home.h?.[w] ? "PRESENT" : "MISSING"}`);
  console.log("  set-cookie:", home.h?.["set-cookie"] ? "yes" : "no");

  console.log("\n== EXPOSED PATHS ==");
  for (const p of ["/robots.txt", "/sitemap.xml", "/wp-login.php", "/wp-config.php", "/server-status", "/.htaccess", "/.htpasswd", "/media", "/media/", "/.git/config", "/xmlrpc.php", "/wp-json/wp/v2/users"]) {
    const r = await head(`https://${D}${p}`);
    console.log(`  ${p} -> ${r.status}${r.loc ? " -> " + r.loc : ""} len=${r.bodyLen} ${r.ct || ""}`);
  }

  console.log("\n== XSS REFLECTION TEST ==");
  const marker = "xssprobe" + Date.now();
  for (const u of [`https://${D}/?s=<b>${marker}</b>`, `https://${D}/search?query=<b>${marker}</b>`]) {
    try {
      const r = await fetch(u, { headers: { "User-Agent": UA } });
      const b = await r.text();
      const raw = b.includes(`<b>${marker}</b>`);
      const enc = b.includes(`&lt;b&gt;${marker}`) || b.includes(marker) && !raw;
      console.log(`  ${u.slice(0, 60)} -> status ${r.status} | RAW-REFLECT: ${raw} | encoded/other: ${enc}`);
    } catch (e) { console.log("  err", e.message); }
  }

  console.log("\n== HTTP METHODS (OPTIONS Allow + direct PUT/DELETE) ==");
  const opt = await head(`https://${D}/`, "OPTIONS");
  console.log("  OPTIONS Allow:", opt.allow || "(none)", "status", opt.status);
  for (const m of ["PUT", "DELETE"]) {
    const r = await head(`https://${D}/`, m);
    console.log(`  ${m} / -> ${r.status}`);
  }

  console.log("\n== S3 BUCKET ==");
  const s3 = await head(`https://${D.replace(/\./g, "-")}.s3.amazonaws.com/`);
  console.log("  procellbiologics-com.s3.amazonaws.com ->", s3.status, "|", s3.snippet?.slice(0, 120));

  console.log("\n== EMAIL AUTH (DNS) ==");
  try { const spf = (await dns.resolveTxt(D)).flat().filter(t => t.includes("v=spf1")); console.log("  SPF:", spf[0] || "MISSING"); } catch { console.log("  SPF: query error"); }
  try { const dmarc = (await dns.resolveTxt(`_dmarc.${D}`)).flat(); console.log("  DMARC:", dmarc[0] || "MISSING"); } catch (e) { console.log("  DMARC: MISSING (" + e.code + ")"); }
  try { const mx = await dns.resolveMx(D); console.log("  MX:", mx.map(m => m.exchange).join(", ")); } catch { console.log("  MX: none"); }

  console.log("\n== DNS/IP ==");
  try { const a = await dns.resolve4(D); console.log("  A:", a.join(", ")); } catch {}
  try { const ns = await dns.resolveNs(D); console.log("  NS:", ns.join(", ")); } catch {}
}
main();
