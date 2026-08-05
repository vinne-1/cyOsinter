import { httpGet, httpGetNoRedirect } from "./http.js";
import { createLogger } from "../logger.js";
import type { VerifiedFinding } from "./types.js";

/**
 * WordPress-specific verification checks that encode findings which generic
 * path-probing misses but which manual review reliably catches:
 *  - User/administrator enumeration via the REST API and author-scan, and
 *  - an enabled XML-RPC interface (brute-force / pingback amplification).
 *
 * Every check confirms the issue against a live, authenticated-not-required
 * response before emitting a finding, so results are report-grade.
 */

const log = createLogger("wordpress-checks");

export interface WordPressUser {
  id?: number;
  name?: string;
  slug?: string;
}

export interface WordPressCheckResults {
  isWordPress: boolean;
  users: WordPressUser[];
  xmlrpcEnabled: boolean;
  findings: VerifiedFinding[];
}

/** Parse the /wp-json/wp/v2/users JSON body into a validated user list. */
export function parseWpUsers(body: string): WordPressUser[] {
  try {
    const parsed = JSON.parse(body);
    if (!Array.isArray(parsed)) return [];
    const users: WordPressUser[] = [];
    for (const u of parsed) {
      if (u && typeof u === "object" && (typeof u.slug === "string" || typeof u.name === "string")) {
        users.push({ id: typeof u.id === "number" ? u.id : undefined, name: u.name, slug: u.slug });
      }
    }
    return users;
  } catch {
    return [];
  }
}

/** Extract a username slug from an /author/<slug>/ redirect Location. */
export function slugFromAuthorRedirect(location: string): string | null {
  const m = location.match(/\/author\/([^/?#]+)/i);
  return m ? decodeURIComponent(m[1]).toLowerCase() : null;
}

export async function runWordPressChecks(domain: string, signal?: AbortSignal): Promise<WordPressCheckResults> {
  const now = new Date().toISOString();
  const findings: VerifiedFinding[] = [];
  const users: WordPressUser[] = [];
  let isWordPress = false;
  let xmlrpcEnabled = false;

  if (signal?.aborted) return { isWordPress, users, xmlrpcEnabled, findings };

  // ── REST API user enumeration ──
  const rest = await httpGet(`https://${domain}/wp-json/wp/v2/users`);
  if (rest && rest.status === 200 && /application\/json/i.test(rest.headers["content-type"] ?? "")) {
    const parsed = parseWpUsers(rest.body);
    if (parsed.length > 0) {
      isWordPress = true;
      users.push(...parsed);
    }
  }

  // ── Author-scan fallback (/?author=1 → 301/302 to /author/<slug>/) ──
  if (users.length === 0) {
    const a = await httpGetNoRedirect(`https://${domain}/?author=1`);
    if (a && (a.status === 301 || a.status === 302) && a.location) {
      const slug = slugFromAuthorRedirect(a.location);
      if (slug) {
        isWordPress = true;
        users.push({ id: 1, slug });
      }
    }
  }

  if (users.length > 0) {
    const names = users.map((u) => u.slug || u.name).filter(Boolean) as string[];
    findings.push({
      title: `WordPress User / Administrator Enumeration on ${domain}`,
      description:
        `The WordPress REST API and/or author-scan endpoints publicly disclose ${users.length} user account(s) without authentication, ` +
        `including login slug(s): ${names.slice(0, 10).join(", ")}. This hands an attacker valid usernames for password brute-force and ` +
        `credential-stuffing attacks against wp-login.php.`,
      severity: "high",
      category: "information_disclosure",
      affectedAsset: domain,
      cvssScore: "7.5",
      remediation:
        "Restrict /wp-json/wp/v2/users for unauthenticated requests (security plugin or rest_endpoints filter), block /?author= scans, " +
        "rename predictable administrator slugs, and enforce MFA plus login rate-limiting.",
      evidence: [{
        type: "user_enumeration",
        description: "Exposed WordPress user accounts",
        snippet: users.map((u) => `id=${u.id ?? "?"} slug=${u.slug ?? ""} name=${u.name ?? ""}`).join("\n"),
        url: `https://${domain}/wp-json/wp/v2/users`,
        source: "WordPress REST API",
        verifiedAt: now,
      }],
    });
  }

  // ── XML-RPC interface ──
  if (!signal?.aborted) {
    const xr = await httpGet(`https://${domain}/xmlrpc.php`);
    // GET on an enabled xmlrpc.php returns 405 (POST-only) or a 200 body that
    // states it accepts POST. A plain 200 page alone is NOT proof.
    if (xr && (xr.status === 405 || /XML-RPC server accepts POST/i.test(xr.body ?? ""))) {
      xmlrpcEnabled = true;
      isWordPress = true;
      findings.push({
        title: `WordPress XML-RPC Interface Enabled on ${domain}`,
        description:
          `The xmlrpc.php endpoint is enabled (HTTP ${xr.status} to GET, indicating POST support). XML-RPC exposes methods ` +
          `(system.multicall, pingback) routinely abused for credential brute-force amplification and pingback-based DDoS/SSRF.`,
        severity: "low",
        category: "web_application",
        affectedAsset: domain,
        cvssScore: "3.1",
        remediation: "Disable XML-RPC if unused, or block the pingback and system.multicall methods and rate-limit the endpoint.",
        evidence: [{
          type: "xmlrpc",
          description: "xmlrpc.php present and accepting POST",
          snippet: `GET /xmlrpc.php -> ${xr.status}`,
          url: `https://${domain}/xmlrpc.php`,
          source: "HTTP probe",
          verifiedAt: now,
        }],
      });
    }
  }

  log.info({ domain, isWordPress, users: users.length, xmlrpcEnabled }, "WordPress checks complete");
  return { isWordPress, users, xmlrpcEnabled, findings };
}
