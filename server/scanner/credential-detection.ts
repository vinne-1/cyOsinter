/**
 * Credential detection and redaction.
 *
 * ## Why this was extracted and rewritten
 *
 * The heuristic that decided "this file contains credentials" was the single
 * largest false-positive source in the scanner, because two of its rules match
 * ordinary web content:
 *
 * 1. A bare UUID was listed as a "Heroku/generic API key". Every request id,
 *    trace id, asset hash and framework key on the modern web is a UUID, so any
 *    HTML page counted as carrying credentials — which escalated
 *    "Exposed Environment File" from high to **critical / CVSS 9.8**.
 * 2. Any 20-character token with entropy >= 4.5 counted, anywhere in the
 *    document. Minified JavaScript, CSP nonces, cache-busting filenames and
 *    base64 payloads all clear that bar.
 *
 * The rewrite keeps three tiers of evidence, strongest first:
 *
 * - **Known key formats** identify themselves by an issuer-assigned prefix and
 *   length, so they need no context.
 * - **Named assignments** (`DB_PASSWORD=...`) need the key name AND a value
 *   that is not a documentation placeholder — `.env.example` files are full of
 *   `API_KEY=your_api_key_here`.
 * - **Entropy** applies only to a value on the right-hand side of a
 *   secret-shaped key name, or to a lone token the caller already isolated as a
 *   candidate. Never to arbitrary tokens inside a document.
 */

/** `NAME = VALUE` assignments whose NAME says the value is a secret. */
const CREDENTIAL_ASSIGNMENT =
  /(?:password|passwd|pwd|api[_-]?key|secret|token|auth[_-]?token|access[_-]?key|db[_-]?pass|database[_-]?url|private[_-]?key|client[_-]?secret|session[_-]?key)\s*[=:]\s*["']?([^\s"',;]+)["']?/gi;

/**
 * Key formats that identify themselves — a match needs no surrounding context
 * because the prefix and length are the vendor's own issued shape.
 *
 * Deliberately excludes bare UUIDs and bare hex digests: those are shapes, not
 * issuers, and matching them is what turned ordinary pages into critical
 * findings. A UUID is only a secret when a key name says so, which the
 * assignment pattern above already covers.
 */
export const STRONG_KEY_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: "AWS access key id", pattern: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: "GitHub token", pattern: /\bgh[pousr]_[A-Za-z0-9_]{36,255}\b/ },
  { name: "GitLab token", pattern: /\bglpat-[A-Za-z0-9\-_]{20,}/ },
  { name: "Slack token", pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,}/ },
  { name: "Google API key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: "OpenAI API key", pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}/ },
  { name: "Stripe live secret key", pattern: /\bsk_live_[0-9a-zA-Z]{24,}/ },
  { name: "Stripe restricted key", pattern: /\brk_live_[0-9a-zA-Z]{24,}/ },
  { name: "SendGrid API key", pattern: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/ },
  { name: "Mailgun API key", pattern: /\bkey-[0-9a-f]{32}\b/ },
  { name: "Twilio API key", pattern: /\bSK[0-9a-f]{32}\b/ },
  { name: "NPM token", pattern: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { name: "Square token", pattern: /\bsq0[a-z]{3}-[A-Za-z0-9_-]{22,}/ },
  { name: "Google OAuth token", pattern: /\bya29\.[A-Za-z0-9_-]{25,}/ },
  { name: "PEM private key", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/ },
  { name: "JSON Web Token", pattern: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/ },
  { name: "Credentialled database URI", pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:/@'"]+:[^\s:/@'"]+@/i },
  { name: "Basic auth header", pattern: /[Aa]uthorization:\s*Basic\s+[A-Za-z0-9+/=]{16,}/ },
  { name: "Bearer token header", pattern: /[Aa]uthorization:\s*Bearer\s+[A-Za-z0-9._-]{20,}/ },
];

/**
 * Values that are documentation, not credentials.
 *
 * `.env.example`, compose templates, and config samples are full of
 * `DB_PASSWORD=` and `API_KEY=your_api_key_here`. Reporting those as a leaked
 * credential is the most common way a config-file check turns into noise.
 */
const PLACEHOLDER_VALUE =
  /^(?:null|nil|none|undefined|true|false|changeme|change_me|password|secret|token|example|test|dummy|placeholder|x{3,}|\*+|\.\.\.|<[^>]*>|\{\{.*\}\}|\$\{.*\}|%[A-Z_]+%|(?:your|my|insert|replace)[_-]\w*|todo|tbd|n\/a)$/i;

export function isPlaceholderValue(value: string): boolean {
  const v = value.trim().replace(/^["']|["']$/g, "");
  if (v.length === 0) return true;
  if (PLACEHOLDER_VALUE.test(v)) return true;
  // A value made only of one repeated character (`****`, `aaaa`).
  return /^(.)\1*$/.test(v) && v.length < 12;
}

/**
 * Shapes that are high-entropy but routinely appear in ordinary web content, so
 * entropy alone must never promote them to "secret": asset fingerprints, content
 * hashes, CSP nonces, cache keys, and URIs.
 */
export function isBenignHighEntropy(token: string): boolean {
  if (/^[0-9a-f]{32}$/i.test(token)) return true;                     // md5 / content hash
  if (/^[0-9a-f]{40}$/i.test(token)) return true;                     // sha1 / git object id
  if (/^[0-9a-f]{64}$/i.test(token)) return true;                     // sha256 / SRI digest
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(token)) return true; // uuid
  if (/^(?:data:|https?:|\/|\.{1,2}\/)/i.test(token)) return true;    // URI or path
  if (/\.(?:js|css|png|jpe?g|svg|woff2?|map|webp|ico|mjs)$/i.test(token)) return true; // fingerprinted asset
  if (/^sha(?:256|384|512)-/.test(token)) return true;                // subresource integrity
  return false;
}

/** Shannon entropy in bits per character. */
export function shannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const freq: Record<string, number> = {};
  for (const c of str) freq[c] = (freq[c] ?? 0) + 1;
  const len = str.length;
  return -Object.values(freq).reduce((sum, f) => {
    const p = f / len;
    return sum + p * Math.log2(p);
  }, 0);
}

export interface CredentialIndicator {
  kind: "known-key" | "named-assignment" | "high-entropy-value" | "bare-token";
  name: string;
  /** Already masked — safe to store and to render in a report. */
  redacted: string;
}

/** Show enough of a secret to recognise it, never enough to use it. */
export function maskValue(raw: string): string {
  const v = raw.trim();
  if (v.length <= 8) return "*".repeat(v.length);
  return `${v.slice(0, 4)}${"*".repeat(Math.min(v.length - 8, 24))}${v.slice(-4)}`;
}

/**
 * Every piece of credential evidence in `text`, already masked.
 *
 * Two modes, because callers ask two different questions:
 *
 * - A short single token is a CANDIDATE VALUE the caller already isolated, so
 *   entropy is meaningful evidence on its own.
 * - A document is judged conservatively: a high-entropy token must sit on the
 *   right-hand side of a secret-shaped key name. Without that rule, minified
 *   JavaScript, CSP nonces, and asset hashes made every page look like a leak.
 */
export function findCredentialIndicators(text: string): CredentialIndicator[] {
  const out: CredentialIndicator[] = [];
  const seen = new Set<string>();
  const add = (i: CredentialIndicator) => {
    const key = `${i.kind}:${i.name}:${i.redacted}`;
    if (!seen.has(key)) { seen.add(key); out.push(i); }
  };

  for (const { name, pattern } of STRONG_KEY_PATTERNS) {
    const m = text.match(pattern);
    if (m) add({ kind: "known-key", name, redacted: maskValue(m[0]) });
  }

  const assignment = new RegExp(CREDENTIAL_ASSIGNMENT.source, CREDENTIAL_ASSIGNMENT.flags);
  let am: RegExpExecArray | null;
  while ((am = assignment.exec(text)) !== null) {
    const value = am[1] ?? "";
    if (isPlaceholderValue(value)) continue;
    const keyName = am[0].split(/[=:]/)[0].trim();
    const strong = value.length >= 16 && shannonEntropy(value) >= 3.0 && !isBenignHighEntropy(value);
    add({ kind: strong ? "high-entropy-value" : "named-assignment", name: keyName, redacted: maskValue(value) });
  }

  // A lone token handed to us as a candidate value: entropy is the whole test.
  const trimmed = text.trim();
  if (out.length === 0 && trimmed.length <= 120 && !/\s/.test(trimmed)) {
    if (
      trimmed.length >= 20 &&
      /[A-Za-z]/.test(trimmed) &&
      /[0-9]/.test(trimmed) &&
      !isBenignHighEntropy(trimmed) &&
      shannonEntropy(trimmed) >= 4.0
    ) {
      add({ kind: "bare-token", name: "high-entropy token", redacted: maskValue(trimmed) });
    }
  }

  return out;
}

/** Whether `text` carries credential material. */
export function hasCredentialPattern(text: string): boolean {
  return findCredentialIndicators(text).length > 0;
}

/**
 * Redact secrets before a body is stored as evidence or exported in a report.
 *
 * Covers BOTH shapes: `name=value` assignments and standalone self-identifying
 * keys. Handling only the first let a bare `AKIA...` through verbatim into a
 * stored finding and an exported report.
 */
export function redactCredentialValues(text: string): string {
  let out = text.replace(
    new RegExp(CREDENTIAL_ASSIGNMENT.source, CREDENTIAL_ASSIGNMENT.flags),
    (m) => m.replace(/([=:]\s*)["']?[^\s"',;]+["']?/, "$1****REDACTED****"),
  );
  for (const { pattern } of STRONG_KEY_PATTERNS) {
    const global = pattern.flags.includes("g") ? pattern : new RegExp(pattern.source, `${pattern.flags}g`);
    out = out.replace(global, (m) => maskValue(m));
  }
  return out;
}
