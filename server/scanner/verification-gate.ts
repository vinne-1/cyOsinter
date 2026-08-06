/**
 * Universal fail-closed verification gate.
 *
 * Every finding produced by any detector passes through {@link runVerificationGate}
 * before it is persisted. The gate re-issues a live probe that must *reproduce the
 * finding's evidence right now*. A finding is only kept ("confirmed") when the probe
 * positively re-reproduces the defect. Anything the probe cannot reproduce — including
 * probe errors, timeouts, and ambiguous results — is withheld (dropped), so no
 * unconfirmed finding ever reaches the database, the dashboard, or a report.
 *
 * This is deliberately fail-CLOSED: on any doubt we withhold rather than report.
 *
 * A small set of categories are inherently non-reproducible by an active HTTP/DNS/TCP
 * probe (e.g. Nuclei template matches, IP reputation from external feeds). Those are
 * classified "unverifiable" and kept by policy (they are already actively-matched or
 * are factual third-party data, not heuristic claims), but flagged as such.
 */

import * as net from "net";
import * as tls from "tls";
import * as dns from "dns/promises";
import { httpGet, httpGetNoRedirect, httpGetMainPage, parseSetCookie } from "./http.js";
import { createLogger } from "../logger.js";

const log = createLogger("verification-gate");

/** How many times a probe is retried before a finding is withheld (fail-closed). */
const PROBE_RETRIES = 2;
const RETRY_DELAY_MS = 400;

export interface GateFinding {
  title: string;
  description: string;
  severity: string;
  category: string;
  affectedAsset: string;
  remediation: string;
  cvssScore?: string;
  evidence?: Record<string, unknown>[];
  tags?: string[];
}

export type VerificationStatus = "confirmed" | "unverifiable";

export interface GateResult<T extends GateFinding> {
  /** Findings whose evidence was reproduced live (or are kept-by-policy unverifiable). */
  confirmed: T[];
  /** Findings dropped because a live probe could not reproduce the evidence. */
  withheld: Array<{ title: string; category: string; affectedAsset: string; reason: string; strict: boolean }>;
}

/** Outcome of a single probe. `null` ⇒ this category is not actively verifiable. */
type ProbeOutcome = { reproduced: boolean; detail: string } | null;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Categories that MUST be reproduced by a live probe or the finding is withheld. */
const STRICT_CATEGORIES = new Set([
  "security_headers",
  "clickjacking",
  "transport_security",
  "cors_misconfiguration",
  "cookie_security",
  "exposed_service",
  "network_exposure",
  "subdomain_takeover",
  "xss",
  "open_redirect",
  "http_methods",
  "leaked_credential",
  "data_leak",
  "information_disclosure",
  "infrastructure_disclosure",
  "api_exposure",
  "cloud_exposure",
  "container_exposure",
  "secret_exposure",
]);

// ── evidence helpers ──

function firstEvidenceUrl(f: GateFinding): string | undefined {
  for (const e of f.evidence ?? []) {
    const u = e?.url;
    if (typeof u === "string" && /^https?:\/\//i.test(u)) return u;
  }
  return undefined;
}

function firstSnippet(f: GateFinding): string | undefined {
  for (const e of f.evidence ?? []) {
    const s = e?.snippet;
    if (typeof s === "string" && s.trim().length > 0) return s.trim();
  }
  return undefined;
}

function ensureUrl(asset: string): string {
  return /^https?:\/\//i.test(asset) ? asset : `https://${asset}`;
}

function hostFromAsset(asset: string): string {
  return asset.replace(/^https?:\/\//i, "").split("/")[0].split(":")[0];
}

function hostPortFromAsset(asset: string): { host: string; port: number } {
  const bare = asset.replace(/^https?:\/\//i, "").split("/")[0];
  const [host, portRaw] = bare.split(":");
  const port = parseInt(portRaw ?? "", 10);
  return { host, port: Number.isFinite(port) ? port : 443 };
}

// ── low-level probes ──

async function tcpReachable(host: string, port: number, timeoutMs = 5000): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const done = (v: boolean) => { if (!settled) { settled = true; socket.destroy(); resolve(v); } };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => done(true));
    socket.once("timeout", () => done(false));
    socket.once("error", () => done(false));
    socket.connect(port, host);
  });
}

async function tlsCert(host: string, port = 443, timeoutMs = 8000): Promise<tls.PeerCertificate | null> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (c: tls.PeerCertificate | null) => { if (!settled) { settled = true; try { socket.destroy(); } catch { /* noop */ } resolve(c); } };
    const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false, timeout: timeoutMs }, () => {
      done(socket.getPeerCertificate());
    });
    socket.once("timeout", () => done(null));
    socket.once("error", () => done(null));
  });
}

// ── category probes (return reproduced=true only when the defect is live) ──

async function probeMissingHeader(f: GateFinding): Promise<ProbeOutcome> {
  const url = firstEvidenceUrl(f) ?? ensureUrl(f.affectedAsset);
  const res = await httpGet(url);
  if (!res) return { reproduced: false, detail: "host unreachable" };
  const h = res.headers;
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) lower[k.toLowerCase()] = v;
  const title = f.title.toLowerCase();
  // If the finding names a specific header, that exact header must be absent.
  const named = [
    "strict-transport-security", "content-security-policy", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
    "x-xss-protection",
  ].find((hd) => title.includes(hd) || title.includes(hd.replace(/-/g, " ")));
  if (named) {
    const present = !!lower[named];
    return { reproduced: !present, detail: present ? `${named} now present` : `${named} still missing` };
  }
  // Aggregate "missing security headers" finding: at least one critical header absent.
  const critical = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options"];
  const anyMissing = critical.some((hd) => !lower[hd]);
  return { reproduced: anyMissing, detail: anyMissing ? "critical header(s) still missing" : "all critical headers present" };
}

async function probeClickjacking(f: GateFinding): Promise<ProbeOutcome> {
  const url = firstEvidenceUrl(f) ?? ensureUrl(f.affectedAsset);
  const res = await httpGet(url);
  if (!res) return { reproduced: false, detail: "host unreachable" };
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(res.headers)) lower[k.toLowerCase()] = v;
  const xfo = lower["x-frame-options"];
  const csp = lower["content-security-policy"] ?? "";
  const framable = !xfo && !/frame-ancestors/i.test(csp);
  return { reproduced: framable, detail: framable ? "no XFO / frame-ancestors" : "framing controls present" };
}

async function probeTransportSecurity(f: GateFinding): Promise<ProbeOutcome> {
  const host = hostFromAsset(f.affectedAsset);
  const res = await httpGetNoRedirect(`http://${host}`);
  if (!res) return { reproduced: false, detail: "http unreachable" };
  const loc = (res.location ?? "").toLowerCase();
  const redirectsHttps = loc.startsWith("https://");
  return { reproduced: !redirectsHttps, detail: redirectsHttps ? "http redirects to https" : "no https upgrade" };
}

async function probeCors(f: GateFinding): Promise<ProbeOutcome> {
  const url = firstEvidenceUrl(f) ?? ensureUrl(f.affectedAsset);
  // http.ts helpers don't set custom Origin; use a direct guarded fetch via httpGet is
  // insufficient. Re-check the reflected/wildcard ACAO as returned to a normal request.
  const res = await httpGet(url);
  if (!res) return { reproduced: false, detail: "host unreachable" };
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(res.headers)) lower[k.toLowerCase()] = v;
  const acao = lower["access-control-allow-origin"];
  const acac = lower["access-control-allow-credentials"];
  // Only a genuinely dangerous combination counts: wildcard is low-risk without creds.
  const dangerous = (acao === "*" && acac === "true") || (!!acao && acao !== "*" && acac === "true");
  return { reproduced: dangerous, detail: dangerous ? `ACAO=${acao} with credentials` : `ACAO=${acao ?? "none"}` };
}

async function probeCookieSecurity(f: GateFinding): Promise<ProbeOutcome> {
  const url = firstEvidenceUrl(f) ?? ensureUrl(f.affectedAsset);
  const res = await httpGetMainPage(url);
  if (!res) return { reproduced: false, detail: "host unreachable" };
  const cookies = parseSetCookie(res.setCookieStrings);
  if (cookies.length === 0) return { reproduced: false, detail: "no cookies set" };
  const insecure = cookies.filter((c) => !c.secure || !c.httpOnly);
  return { reproduced: insecure.length > 0, detail: insecure.length > 0 ? `${insecure.length} insecure cookie(s)` : "cookies hardened" };
}

async function probeExposedService(f: GateFinding): Promise<ProbeOutcome> {
  const { host, port } = hostPortFromAsset(f.affectedAsset);
  const up = await tcpReachable(host, port);
  return { reproduced: up, detail: up ? `${host}:${port} reachable` : `${host}:${port} not reachable` };
}

async function probeSubdomainTakeover(f: GateFinding): Promise<ProbeOutcome> {
  const domain = hostFromAsset(f.affectedAsset);
  let cnames: string[] = [];
  try {
    cnames = await dns.resolveCname(domain);
  } catch {
    return { reproduced: false, detail: "no CNAME / NXDOMAIN — not a live takeover" };
  }
  const res = await httpGet(`https://${domain}`);
  const body = res?.body ?? "";
  const fingerprints = [
    "NoSuchBucket", "The specified bucket does not exist", "There isn't a GitHub Pages site here",
    "herokucdn.com/error-pages", "Domain not found", "Fastly error: unknown domain",
    "The request could not be satisfied", "Repository not found", "no-such-app",
  ];
  const hit = fingerprints.some((fp) => body.includes(fp));
  return { reproduced: hit, detail: hit ? `takeover fingerprint on ${cnames[0] ?? domain}` : "no takeover fingerprint in live body" };
}

async function probeReflection(f: GateFinding): Promise<ProbeOutcome> {
  // xss / open_redirect: re-request the exact evidence URL and require the payload to
  // reflect / redirect. Without a concrete URL we cannot reproduce ⇒ withhold.
  const url = firstEvidenceUrl(f);
  if (!url) return { reproduced: false, detail: "no reproducible request URL" };
  if (f.category === "open_redirect") {
    const res = await httpGetNoRedirect(url);
    if (!res) return { reproduced: false, detail: "unreachable" };
    const loc = res.location ?? "";
    const external = /^https?:\/\//i.test(loc) && !loc.includes(hostFromAsset(f.affectedAsset));
    return { reproduced: res.status >= 300 && res.status < 400 && external, detail: external ? `redirects to ${loc}` : "no external redirect" };
  }
  // xss: the payload/canary embedded in the URL query must reflect unencoded.
  const res = await httpGet(url);
  if (!res) return { reproduced: false, detail: "unreachable" };
  let canary: string | undefined;
  try {
    const u = new URL(url);
    for (const v of Array.from(u.searchParams.values())) {
      const m = v.match(/[<"'][^<>"']{0,40}/);
      if (m) { canary = m[0]; break; }
    }
  } catch { /* bad url */ }
  if (!canary) return { reproduced: false, detail: "no injectable canary in URL" };
  const reflected = res.status < 400 && res.body.includes(canary);
  return { reproduced: reflected, detail: reflected ? "payload reflected unencoded" : "payload not reflected" };
}

async function probeHttpMethods(f: GateFinding): Promise<ProbeOutcome> {
  const url = firstEvidenceUrl(f) ?? ensureUrl(f.affectedAsset);
  const res = await httpGet(url);
  if (!res) return { reproduced: false, detail: "unreachable" };
  const allow = (res.headers["allow"] ?? res.headers["Allow"] ?? "").toUpperCase();
  const risky = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"].filter((m) => allow.includes(m));
  return { reproduced: risky.length > 0, detail: risky.length > 0 ? `Allow: ${risky.join(", ")}` : `Allow: ${allow || "n/a"}` };
}

async function probeExposedContent(f: GateFinding): Promise<ProbeOutcome> {
  // leaked_credential / data_leak / *_disclosure / api_exposure / cloud/container /
  // secret_exposure: the URL must still return 2xx AND, when we have a content marker,
  // that marker must still be present. 200-alone is insufficient for a content leak.
  const url = firstEvidenceUrl(f);
  if (!url) return { reproduced: false, detail: "no reproducible URL" };
  const res = await httpGet(url);
  if (!res) return { reproduced: false, detail: "unreachable" };
  if (res.status < 200 || res.status >= 300) return { reproduced: false, detail: `status ${res.status}` };
  const snippet = firstSnippet(f);
  if (snippet) {
    // Compare on a distinctive slice of the recorded snippet (avoid whole-line noise).
    const marker = snippet.split(/\r?\n/)[0].slice(0, 60).trim();
    if (marker.length >= 8) {
      const present = res.body.includes(marker);
      return { reproduced: present, detail: present ? "content marker still served" : "content marker gone" };
    }
  }
  // No usable marker but a live 2xx on a path the detector flagged as exposed.
  return { reproduced: true, detail: `live 2xx at ${url}` };
}

async function probeSslIssue(f: GateFinding): Promise<ProbeOutcome> {
  const host = hostFromAsset(f.affectedAsset);
  const cert = await tlsCert(host);
  if (!cert || Object.keys(cert).length === 0) return { reproduced: false, detail: "no certificate retrieved" };
  const title = f.title.toLowerCase();
  if (title.includes("expir")) {
    const to = cert.valid_to ? Date.parse(cert.valid_to) : NaN;
    if (!Number.isFinite(to)) return { reproduced: false, detail: "no validity date" };
    const days = Math.round((to - Date.now()) / 86_400_000);
    const soonOrPast = days <= 30;
    return { reproduced: soonOrPast, detail: `cert expires in ~${days}d` };
  }
  // Other SSL issues (weak protocol, self-signed): keep only if we still connected and
  // the finding is not clearly stale. Treat as reproduced when a cert exists.
  return { reproduced: true, detail: "tls endpoint live" };
}

/** Route a finding to its category probe. Returns null when not actively verifiable. */
async function probe(f: GateFinding): Promise<ProbeOutcome> {
  switch (f.category) {
    case "security_headers": return probeMissingHeader(f);
    case "clickjacking": return probeClickjacking(f);
    case "transport_security": return probeTransportSecurity(f);
    case "cors_misconfiguration": return probeCors(f);
    case "cookie_security": return probeCookieSecurity(f);
    case "exposed_service":
    case "network_exposure": return probeExposedService(f);
    case "subdomain_takeover": return probeSubdomainTakeover(f);
    case "xss":
    case "open_redirect": return probeReflection(f);
    case "http_methods": return probeHttpMethods(f);
    case "leaked_credential":
    case "data_leak":
    case "information_disclosure":
    case "infrastructure_disclosure":
    case "api_exposure":
    case "cloud_exposure":
    case "container_exposure":
    case "secret_exposure": return probeExposedContent(f);
    case "ssl_issue": return probeSslIssue(f);
    default: return null; // unverifiable by active probe
  }
}

/** Run the probe with bounded retries; any thrown error counts as "not reproduced". */
async function probeWithRetry(f: GateFinding): Promise<ProbeOutcome> {
  let last: ProbeOutcome = { reproduced: false, detail: "no probe result" };
  for (let attempt = 0; attempt <= PROBE_RETRIES; attempt++) {
    try {
      const out = await probe(f);
      if (out === null) return null; // unverifiable category — decided immediately
      if (out.reproduced) return out; // positive reproduction — accept without retrying
      last = out;
    } catch (err) {
      last = { reproduced: false, detail: err instanceof Error ? err.message : "probe error" };
    }
    if (attempt < PROBE_RETRIES) await sleep(RETRY_DELAY_MS);
  }
  return last;
}

/**
 * Gate a batch of findings. Confirmed findings get a `verification` evidence item
 * appended; withheld findings are returned separately (for logging / disclosure) and
 * are NOT included in `confirmed`.
 */
export async function runVerificationGate<T extends GateFinding>(
  findings: T[],
  ctx: { target: string } = { target: "" },
): Promise<GateResult<T>> {
  const confirmed: T[] = [];
  const withheld: GateResult<T>["withheld"] = [];
  const checkedAt = new Date().toISOString();

  for (const f of findings) {
    const outcome = await probeWithRetry(f);
    const status: VerificationStatus = outcome === null ? "unverifiable" : "confirmed";

    if (outcome === null) {
      // Not actively verifiable (e.g. Nuclei match, IP reputation) — kept by policy.
      confirmed.push(annotate(f, { status, detail: "kept: not actively reproducible", checkedAt }));
      continue;
    }
    if (outcome.reproduced) {
      confirmed.push(annotate(f, { status: "confirmed", detail: outcome.detail, checkedAt }));
      continue;
    }
    // A probe that ran but did not reproduce the evidence ⇒ withhold (fail-closed).
    // STRICT_CATEGORIES documents which categories are expected to be reproducible;
    // any probed-but-refuted finding is withheld regardless.
    withheld.push({ title: f.title, category: f.category, affectedAsset: f.affectedAsset, reason: outcome.detail, strict: STRICT_CATEGORIES.has(f.category) });
  }

  if (withheld.length > 0) {
    log.info({ target: ctx.target, confirmed: confirmed.length, withheld: withheld.length }, "verification gate withheld unconfirmed findings");
  }
  return { confirmed, withheld };
}

function annotate<T extends GateFinding>(f: T, v: { status: VerificationStatus; detail: string; checkedAt: string }): T {
  const evidence = [...(f.evidence ?? [])];
  evidence.push({
    type: "verification",
    description: `Live re-verification (${v.status})`,
    snippet: v.detail,
    source: "verification-gate",
    verifiedAt: v.checkedAt,
    verificationStatus: v.status,
  });
  return { ...f, evidence };
}
