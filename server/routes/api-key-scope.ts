/**
 * API key scope enforcement.
 *
 * `api_keys.scope` (read | scan | full) was validated on create, stored,
 * returned by the list endpoint and rendered as a coloured badge in the UI —
 * and then checked by NOTHING at request time. `requireAuth` accepted a `csk_`
 * key and set `req.user` to the full user record, so every key carried the
 * owner's entire authority: a key an operator deliberately created as "read"
 * could delete workspaces, trigger scans, and revoke other keys. Because the UI
 * displayed the scope it was told, the product actively asserted a restriction
 * it did not apply, which is worse than having no scopes at all — an operator
 * hands out a "read-only" key for a dashboard integration believing it is safe.
 *
 * This is the same failure mode CLAUDE.md records for `logAudit`, `enqueueScan`
 * and `checkSLABreaches`: a complete-looking implementation with no caller.
 *
 * ## Where this is enforced
 *
 * At the `/api` choke point immediately after `requireAuth`, exactly like
 * `auditMutations`. A per-route allowlist would rot — the next route added
 * would silently be reachable by a read-only key — whereas a middleware over
 * the whole surface covers a new route the moment it is mounted.
 *
 * ## Fail closed
 *
 * The rule is "deny unless permitted", not "permit unless denied". A scope this
 * module does not recognise gets read-only treatment rather than full access,
 * so a future scope value added to the schema cannot accidentally grant more
 * than intended by being unhandled here.
 */
import type { Request, Response, NextFunction } from "express";
import { sendError } from "./response";

/** Methods that cannot change state, and so are safe for every scope. */
const READ_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/**
 * State-changing routes a `scan` key may reach, matched against the path with
 * the `/api` mount prefix already stripped by Express.
 *
 * Deliberately tiny: a scan key exists so CI or a scheduler can start a scan
 * and stop one it started. It is not a general write credential.
 */
const SCAN_WRITE_PATHS: RegExp[] = [
  /^\/scans\/?$/,
  /^\/scans\/[^/]+\/cancel\/?$/,
];

/** Credential management. Blocked for API keys at every scope — see below. */
const KEY_MANAGEMENT_PATH = /^\/api-keys(\/|$)/;

export type ApiKeyScope = "read" | "scan" | "full";

/**
 * Whether an API-key-authenticated request may proceed.
 *
 * Pure and total so it can be tested without an HTTP layer; the middleware
 * below is a thin wrapper that turns `false` into a 403.
 */
export function isAllowedForScope(scope: string, method: string, path: string): boolean {
  const m = method.toUpperCase();

  /*
   * An API key may never mint, list or revoke API keys, even at `full` scope.
   *
   * `full` means "everything the owning user can do", and the owner can manage
   * their own keys — but allowing that through a key turns a single leaked
   * credential into permanent access: the attacker issues a second key, and
   * revoking the leaked one achieves nothing. Key management therefore requires
   * an interactive session. This mirrors how GitHub treats personal access
   * tokens, and it is the reason the block covers reads too — enumerating key
   * names, prefixes and expiries is reconnaissance for exactly that move.
   */
  if (KEY_MANAGEMENT_PATH.test(path)) return false;

  if (READ_METHODS.has(m)) return true;

  switch (scope) {
    case "full":
      return true;
    case "scan":
      return SCAN_WRITE_PATHS.some((re) => re.test(path));
    case "read":
      return false;
    default:
      // Unknown scope: treat as the least privileged, never the most.
      return false;
  }
}

/**
 * Refuses requests that exceed the scope of the API key presented.
 *
 * Session-authenticated requests carry no `apiKeyScope` and pass through
 * untouched — this middleware narrows API keys, it is not the authorization
 * model. Workspace membership and role checks still apply on top.
 */
export function enforceApiKeyScope(req: Request, res: Response, next: NextFunction): void {
  const scope = req.apiKeyScope;
  if (!scope) return next(); // session auth — nothing to narrow

  if (isAllowedForScope(scope, req.method, req.path)) return next();

  // 403, not 404: the caller is authenticated and the resource's existence is
  // not the secret being protected — the key simply is not permitted to do
  // this, and saying so is what lets an integration author fix their setup.
  sendError(res, 403, `This API key's scope ("${scope}") does not permit this request`);
}
