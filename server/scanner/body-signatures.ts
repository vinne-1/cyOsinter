/**
 * Positive content signatures — "does this body actually BE the thing we claim?"
 *
 * The response oracle answers "is this 200 real, or the host's catch-all?".
 * This module answers the second, independent question: even on a genuinely
 * distinct 200, does the content match the finding we are about to write?
 *
 * Both are needed. A server can return a distinct 200 for `/metrics` (so the
 * oracle says "real") that is still a marketing page, not a Prometheus
 * exposition — and "Prometheus Metrics Endpoint Exposed" would be wrong.
 * Detectors here must show the content IS a Prometheus exposition before they
 * are allowed to say so.
 *
 * Every predicate is deliberately strict and evidence-shaped: it looks for the
 * structure the real artefact must have, not for a keyword that could appear in
 * prose. Each returns a boolean, so the call site reads as the claim it gates.
 */

/**
 * True for anything a browser would render as a document.
 *
 * Written to survive the ways a real page starts: a byte-order mark, leading
 * whitespace, a lowercase doctype, an XML prolog, or an HTML comment before the
 * doctype. The previous check was `body.trim().startsWith("<!DOCTYPE")` — case
 * sensitive, so every framework that emits `<!doctype html>` slipped through and
 * had its markup scanned for secrets.
 */
export function looksLikeHtml(body: string): boolean {
  const head = body.replace(/^﻿/, "").trimStart().slice(0, 2000);
  if (/^<!doctype\s+html/i.test(head)) return true;
  if (/^<html[\s>]/i.test(head)) return true;
  // A prolog or comment can precede the real start.
  const stripped = head.replace(/^<\?xml[^>]*\?>\s*/i, "").replace(/^(?:<!--[\s\S]*?-->\s*)+/, "");
  if (/^<!doctype\s+html/i.test(stripped) || /^<html[\s>]/i.test(stripped)) return true;
  // Server-rendered fragments without a doctype still carry document furniture.
  return /<head[\s>]/i.test(head) && /<(?:body|title|meta|script|link)[\s>]/i.test(head);
}

/** Parseable JSON whose root is an object or array. */
export function parseJsonBody(body: string): unknown | null {
  const t = body.trim();
  if (!t.startsWith("{") && !t.startsWith("[")) return null;
  try { return JSON.parse(t); } catch { return null; }
}

function asRecord(v: unknown): Record<string, unknown> | null {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

/**
 * A dotenv file: at least two `KEY=VALUE` assignment lines, and no markup.
 *
 * Two lines rather than one because a single `=` appears in far too much
 * incidental text; the shape only becomes distinctive when it repeats.
 */
export function looksLikeEnvFile(body: string): boolean {
  if (looksLikeHtml(body)) return false;
  const lines = body.split(/\r?\n/).map((l) => l.trim());
  const assignments = lines.filter((l) => /^(?:export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*=/.test(l) && !l.startsWith("#"));
  if (assignments.length < 2) return false;
  // Guard against JS/TS source, which is also full of `x = ...`.
  const codeish = lines.filter((l) => /^(?:const|let|var|function|import|export default|class)\b/.test(l)).length;
  return codeish < assignments.length / 2;
}

/** A git config file: the INI section headers git actually writes. */
export function looksLikeGitConfig(body: string): boolean {
  if (looksLikeHtml(body)) return false;
  return /^\s*\[core\]/m.test(body) && /repositoryformatversion|bare\s*=|filemode\s*=/i.test(body);
}

/** `.git/HEAD`: a single symbolic ref line. */
export function looksLikeGitHead(body: string): boolean {
  return /^ref:\s+refs\/[\w./-]+\s*$/m.test(body.trim()) && body.trim().length < 200;
}

/**
 * A server-generated directory index.
 *
 * Requires the index furniture (a parent link or a sortable column header)
 * alongside the title, because the literal string "Index of /" appears in
 * plenty of ordinary prose and navigation.
 */
export function looksLikeDirectoryListing(body: string): boolean {
  const hasTitle = /<title>\s*Index of \//i.test(body) || /<h1>\s*Index of \//i.test(body);
  const hasParent = /Parent Directory|\.\.<\/a>|>\.\.\s*</i.test(body);
  const hasSortHeaders = /\?C=N;O=[AD]|\?sort=name|Last modified<\/th>|Last modified<\/a>/i.test(body);
  const iisListing = /\[To Parent Directory\]<\/[Aa]>/.test(body) && /<pre>/i.test(body);
  const nginxListing = /<h1>Index of \//i.test(body) && /<hr><pre>/i.test(body);
  return iisListing || nginxListing || (hasTitle && (hasParent || hasSortHeaders));
}

/**
 * A Prometheus/OpenMetrics text exposition.
 *
 * The `# HELP` / `# TYPE` comment pairs are the format's own required framing;
 * a bare `metric 1` line is not distinctive enough on its own.
 */
export function looksLikePrometheusMetrics(body: string): boolean {
  if (looksLikeHtml(body)) return false;
  const help = (body.match(/^# HELP \w+/gm) ?? []).length;
  const type = (body.match(/^# TYPE \w+ (?:counter|gauge|histogram|summary|untyped)/gm) ?? []).length;
  if (help >= 2 && type >= 2) return true;
  // OpenMetrics exposition without comments still has many `name{labels} value` lines.
  const samples = (body.match(/^[a-zA-Z_:][a-zA-Z0-9_:]*(?:\{[^}]*\})?\s+-?[\d.eE+]+$/gm) ?? []).length;
  return samples >= 10;
}

/** A Kubernetes API list response (`/api/v1/pods` and friends). */
export function looksLikeKubernetesApi(body: string): boolean {
  const json = asRecord(parseJsonBody(body));
  if (!json) return false;
  const kind = typeof json.kind === "string" ? json.kind : "";
  const apiVersion = typeof json.apiVersion === "string" ? json.apiVersion : "";
  if (kind === "Status" && /kubernetes/i.test(String(json.reason ?? json.message ?? ""))) return true;
  if (!apiVersion) return false;
  return /^(?:PodList|NamespaceList|NodeList|ServiceList|SecretList|APIResourceList|APIVersions)$/.test(kind);
}

/** A Docker Registry v2 catalog or API root. */
export function looksLikeDockerRegistry(body: string, headers: Record<string, string> = {}): boolean {
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
  if (lower["docker-distribution-api-version"]?.includes("registry/2.0")) return true;
  const json = asRecord(parseJsonBody(body));
  if (!json) return false;
  return Array.isArray(json.repositories) || Array.isArray((json as { tags?: unknown }).tags);
}

/** A phpinfo() page — its own generated table, not a page that mentions PHP. */
export function looksLikePhpInfo(body: string): boolean {
  const hasTitle = /<title>phpinfo\(\)<\/title>/i.test(body);
  const hasTable = /PHP Version\s*<\/(?:h1|td|th)>/i.test(body) || /<h1[^>]*class="p"[^>]*>PHP Version/i.test(body);
  const hasSections = /Configuration File \(php\.ini\) Path|Loaded Configuration File|_SERVER\["|Build Date/i.test(body);
  return hasTitle || (hasTable && hasSections);
}

/** Apache's mod_status page. */
export function looksLikeApacheServerStatus(body: string): boolean {
  return /Apache Server Status for/i.test(body) &&
    /(Server Version|Total accesses|Scoreboard|requests currently being processed)/i.test(body);
}

/** A Spring Boot Actuator response — the health/env/info document shapes. */
export function looksLikeSpringActuator(body: string): boolean {
  const json = asRecord(parseJsonBody(body));
  if (!json) return false;
  if (typeof json.status === "string" && /^(UP|DOWN|OUT_OF_SERVICE|UNKNOWN)$/.test(json.status)) return true;
  if (asRecord(json._links) && Object.keys(asRecord(json._links) ?? {}).some((k) => /health|env|metrics|beans|mappings/.test(k))) return true;
  return Array.isArray(json.propertySources) || Array.isArray(json.activeProfiles) || asRecord(json.contexts) !== null;
}

/** An OpenAPI / Swagger specification document. */
export function looksLikeOpenApiSpec(body: string): boolean {
  const json = asRecord(parseJsonBody(body));
  if (json) {
    const hasVersion = typeof json.openapi === "string" || typeof json.swagger === "string";
    return hasVersion && (asRecord(json.paths) !== null || asRecord(json.info) !== null);
  }
  // YAML form.
  return /^\s*(?:openapi|swagger)\s*:\s*["']?[23]\./m.test(body) && /^\s*paths\s*:/m.test(body);
}

/** Go's net/http/pprof index. */
export function looksLikeGoPprof(body: string): boolean {
  return /\/debug\/pprof\//.test(body) && /(goroutine|heap|threadcreate|allocs|full goroutine stack dump)/i.test(body);
}

/** A GraphQL endpoint's own response — a spec-shaped envelope, not a page. */
export function looksLikeGraphQL(body: string): boolean {
  const json = asRecord(parseJsonBody(body));
  if (json) {
    if (asRecord(json.data) !== null && "data" in json) return true;
    if (Array.isArray(json.errors)) {
      return json.errors.some((e) => {
        const r = asRecord(e);
        return !!r && (typeof r.message === "string") && /query|graphql|must provide|operation/i.test(String(r.message));
      });
    }
    return false;
  }
  return /GraphiQL|graphql-playground|<title>\s*Apollo/i.test(body);
}

/** A SQL dump. */
export function looksLikeSqlDump(body: string): boolean {
  if (looksLikeHtml(body)) return false;
  return /^\s*(?:CREATE TABLE|INSERT INTO|DROP TABLE IF EXISTS|-- MySQL dump|-- PostgreSQL database dump)/im.test(body);
}

/** A plaintext application log. */
export function looksLikeLogFile(body: string): boolean {
  if (looksLikeHtml(body)) return false;
  const lines = body.split(/\r?\n/).slice(0, 50);
  const stamped = lines.filter((l) =>
    /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}/.test(l) ||
    /\[\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2}/.test(l) ||
    /\b(?:DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\b/.test(l),
  ).length;
  return stamped >= 3;
}

/** PEM-encoded private key material. */
export function looksLikePrivateKey(body: string): boolean {
  return /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/.test(body);
}

/** An Apache/nginx htpasswd file: `user:$apr1$...` hash lines. */
export function looksLikeHtpasswd(body: string): boolean {
  if (looksLikeHtml(body)) return false;
  const lines = body.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (lines.length === 0) return false;
  return lines.some((l) => /^[^:\s]+:(?:\$(?:apr1|1|2[aby]|5|6)\$|\{SHA\}|[A-Za-z0-9./]{13}$)/.test(l));
}

/** A Windows IIS `web.config` / .NET configuration document. */
export function looksLikeDotNetConfig(body: string): boolean {
  return /<configuration[\s>]/i.test(body) &&
    /<(?:system\.web|system\.webServer|appSettings|connectionStrings)[\s>]/i.test(body);
}

/** A Terraform state file. */
export function looksLikeTerraformState(body: string): boolean {
  const json = asRecord(parseJsonBody(body));
  if (!json) return false;
  return typeof json.terraform_version === "string" && (Array.isArray(json.resources) || typeof json.lineage === "string");
}

/** A Docker Compose / Kubernetes manifest in YAML form. */
export function looksLikeComposeManifest(body: string): boolean {
  if (looksLikeHtml(body)) return false;
  return /^\s*services\s*:/m.test(body) && /^\s{2,}\w[\w.-]*\s*:\s*$/m.test(body) && /image\s*:|build\s*:/.test(body);
}

/**
 * A publicly LISTABLE object-storage bucket.
 *
 * A 200 from a bucket hostname is not the same as a bucket whose contents
 * anyone can enumerate — a provider will answer 200 with its own landing page,
 * an error document, or a single public object. Each provider's listing has its
 * own root element, and that root is the proof.
 */
export function looksLikeBucketListing(body: string): boolean {
  if (/<ListBucketResult[\s>]/i.test(body)) return true;        // S3 and S3-compatible
  if (/<EnumerationResults[\s>]/i.test(body)) return true;      // Azure Blob
  if (/<ListAllMyBucketsResult[\s>]/i.test(body)) return true;  // S3 account listing
  const json = asRecord(parseJsonBody(body));
  if (!json) return false;
  if (json.kind === "storage#objects" || json.kind === "storage#bucket") return true; // GCS
  return Array.isArray(json.files) && typeof json.bucketName === "string";            // Backblaze B2
}

/**
 * A file the server sent as a downloadable document rather than a page.
 *
 * Used to separate `/backup.zip` really being an archive from a route that
 * happens to be named that and renders HTML.
 */
export function isDocumentResponse(headers: Record<string, string>, body: string): boolean {
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
  const ct = (lower["content-type"] ?? "").toLowerCase();
  if (/^(?:application\/(?:zip|x-gzip|gzip|x-tar|x-7z|x-rar|pdf|octet-stream|sql|vnd\.|msword)|text\/csv)/.test(ct)) return true;
  if (/attachment\s*;/i.test(lower["content-disposition"] ?? "")) return true;
  // Magic bytes for the archive/document types the backup-file paths look for.
  return /^(?:PK\x03\x04|\x1f\x8b|Rar!|7z\xbc\xaf|%PDF-)/.test(body.slice(0, 8));
}
