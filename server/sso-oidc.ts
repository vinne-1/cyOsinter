/**
 * Enterprise SSO via OpenID Connect (authorization code flow + PKCE).
 *
 * ## Why OIDC and not SAML
 *
 * SAML was the other candidate. It is XML, and validating a SAML assertion
 * correctly means XML canonicalisation and XML-DSig — a problem area with a long
 * history of signature-wrapping bypasses that look like working code until
 * somebody wraps an assertion. Implementing that by hand would be reckless, and
 * it needs a vetted library rather than this file. OIDC is what Entra ID, Okta,
 * Google Workspace and Auth0 all prefer, its token format is JOSE rather than
 * XML, and Node verifies RS256 over a JWK natively — so it can be implemented
 * here correctly and read by a reviewer.
 *
 * ## Every validation below is load-bearing
 *
 * An OIDC client that skips a check is not "slightly less strict"; each omission
 * is a specific, named attack:
 *
 *  - **signature** — without it, anyone can mint an ID token for any user.
 *  - **`iss`** — a token from a different issuer is a different identity space;
 *    accepting one lets any IdP assert your users.
 *  - **`aud`** — a token issued for a DIFFERENT client of the same IdP is valid
 *    and signed. Without this check, any other app registered with the same
 *    tenant can log in as its users here.
 *  - **`exp`/`iat`** — replay of an old token.
 *  - **`nonce`** — replay of a token captured from another session; it binds the
 *    token to the authorization request this server started.
 *  - **`state`** — CSRF on the callback; without it an attacker can complete a
 *    login into the victim's browser as themselves.
 *  - **PKCE** — an authorization code intercepted in transit is useless without
 *    the verifier.
 *
 * ## Account linking
 *
 * Users are matched on VERIFIED email only. An IdP that reports `email_verified:
 * false` is asserting it does not know the address belongs to this person, and
 * matching on it would let anyone who can set their profile email take over an
 * existing account. Unverified means no link, no auto-provision.
 */

import crypto from "crypto";
import { createLogger } from "./logger.js";

const log = createLogger("sso-oidc");

export interface OidcConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  /** Extra scopes beyond the required `openid profile email`. */
  scopes: string[];
  /**
   * Create a local user for a successful login that matches no existing account.
   * Off by default: an IdP tenant usually contains far more people than should
   * have access to a security platform.
   */
  autoProvision: boolean;
  enabled: boolean;
}

export interface OidcDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  end_session_endpoint?: string;
}

export interface OidcClaims {
  sub: string;
  email: string;
  emailVerified: boolean;
  name?: string;
}

/** The per-login secrets that must survive the round trip to the IdP. */
export interface OidcLoginState {
  state: string;
  nonce: string;
  codeVerifier: string;
  createdAt: number;
}

export function readOidcConfig(env: NodeJS.ProcessEnv = process.env): OidcConfig {
  const issuer = (env.OIDC_ISSUER ?? "").trim().replace(/\/+$/, "");
  const clientId = (env.OIDC_CLIENT_ID ?? "").trim();
  const clientSecret = (env.OIDC_CLIENT_SECRET ?? "").trim();
  const redirectUri = (env.OIDC_REDIRECT_URI ?? "").trim();
  const extra = (env.OIDC_SCOPES ?? "").trim();
  return {
    issuer,
    clientId,
    clientSecret,
    redirectUri,
    scopes: extra ? extra.split(/[\s,]+/).filter(Boolean) : [],
    autoProvision: /^(1|true|yes)$/i.test(env.OIDC_AUTO_PROVISION ?? ""),
    // All four are required. A half-configured client that silently "works"
    // until the callback is worse than one that reports itself disabled.
    enabled: !!(issuer && clientId && clientSecret && redirectUri),
  };
}

// ── discovery ───────────────────────────────────────────────────────────────

let discoveryCache: { at: number; issuer: string; doc: OidcDiscovery } | null = null;
let jwksCache: { at: number; uri: string; keys: JsonWebKey[] } | null = null;
const DISCOVERY_TTL_MS = 3_600_000;
const JWKS_TTL_MS = 3_600_000;

export function resetOidcCaches(): void {
  discoveryCache = null;
  jwksCache = null;
}

/** Fetch (and cache) the IdP's `.well-known/openid-configuration`. */
export async function discover(config: OidcConfig): Promise<OidcDiscovery> {
  if (discoveryCache && discoveryCache.issuer === config.issuer && Date.now() - discoveryCache.at < DISCOVERY_TTL_MS) {
    return discoveryCache.doc;
  }
  const url = `${config.issuer}/.well-known/openid-configuration`;
  const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new Error(`OIDC discovery failed: ${res.status}`);
  const doc = (await res.json()) as OidcDiscovery;

  // The discovery document states its own issuer, and it must be the one we
  // asked for. A mismatch means the URL is not the issuer it claims to be.
  if (doc.issuer?.replace(/\/+$/, "") !== config.issuer) {
    throw new Error(`OIDC discovery issuer mismatch: expected ${config.issuer}, document says ${doc.issuer}`);
  }
  if (!doc.authorization_endpoint || !doc.token_endpoint || !doc.jwks_uri) {
    throw new Error("OIDC discovery document is missing required endpoints");
  }
  discoveryCache = { at: Date.now(), issuer: config.issuer, doc };
  return doc;
}

async function fetchJwks(uri: string): Promise<JsonWebKey[]> {
  if (jwksCache && jwksCache.uri === uri && Date.now() - jwksCache.at < JWKS_TTL_MS) return jwksCache.keys;
  const res = await fetch(uri, { signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
  const body = (await res.json()) as { keys?: JsonWebKey[] };
  const keys = Array.isArray(body.keys) ? body.keys : [];
  if (keys.length === 0) throw new Error("JWKS contained no keys");
  jwksCache = { at: Date.now(), uri, keys };
  return keys;
}

// ── authorization request ───────────────────────────────────────────────────

function base64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** A fresh state/nonce/PKCE triple for one login attempt. */
export function createLoginState(): OidcLoginState {
  return {
    state: base64url(crypto.randomBytes(32)),
    nonce: base64url(crypto.randomBytes(32)),
    codeVerifier: base64url(crypto.randomBytes(64)),
    createdAt: Date.now(),
  };
}

export function codeChallengeFor(verifier: string): string {
  return base64url(crypto.createHash("sha256").update(verifier).digest());
}

export function buildAuthorizationUrl(
  config: OidcConfig,
  discovery: OidcDiscovery,
  login: OidcLoginState,
): string {
  const url = new URL(discovery.authorization_endpoint);
  const scopes = Array.from(new Set(["openid", "profile", "email", ...config.scopes]));
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", config.clientId);
  url.searchParams.set("redirect_uri", config.redirectUri);
  url.searchParams.set("scope", scopes.join(" "));
  url.searchParams.set("state", login.state);
  url.searchParams.set("nonce", login.nonce);
  url.searchParams.set("code_challenge", codeChallengeFor(login.codeVerifier));
  url.searchParams.set("code_challenge_method", "S256");
  return url.toString();
}

// ── ID token verification ───────────────────────────────────────────────────

interface JwtParts {
  header: { alg?: string; kid?: string; typ?: string };
  payload: Record<string, unknown>;
  signingInput: string;
  signature: Buffer;
}

function decodeJwt(token: string): JwtParts {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("ID token is not a JWS compact serialization");
  const [h, p, s] = parts;
  const header = JSON.parse(Buffer.from(h, "base64url").toString("utf8")) as JwtParts["header"];
  const payload = JSON.parse(Buffer.from(p, "base64url").toString("utf8")) as Record<string, unknown>;
  return { header, payload, signingInput: `${h}.${p}`, signature: Buffer.from(s, "base64url") };
}

/** Algorithms we accept. */
const ALLOWED_ALGS = new Set(["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384"]);

const NODE_HASH: Record<string, string> = {
  RS256: "sha256", RS384: "sha384", RS512: "sha512",
  PS256: "sha256", PS384: "sha384", PS512: "sha512",
  ES256: "sha256", ES384: "sha384",
};

/**
 * Verify an ID token completely, then return its claims.
 *
 * `maxSkewSeconds` allows for clock drift between this server and the IdP;
 * anything beyond a small window is a replay, not a clock.
 */
export async function verifyIdToken(
  idToken: string,
  config: OidcConfig,
  discovery: OidcDiscovery,
  expectedNonce: string,
  opts: { now?: number; maxSkewSeconds?: number } = {},
): Promise<OidcClaims> {
  const now = Math.floor((opts.now ?? Date.now()) / 1000);
  const skew = opts.maxSkewSeconds ?? 120;
  const { header, payload, signingInput, signature } = decodeJwt(idToken);

  // `alg: none` and HMAC-with-the-public-key are the two classic JWT bypasses.
  // An explicit allow-list of asymmetric algorithms closes both.
  const alg = header.alg ?? "";
  if (!ALLOWED_ALGS.has(alg)) throw new Error(`ID token algorithm not allowed: ${alg || "none"}`);

  const keys = await fetchJwks(discovery.jwks_uri);
  const candidates = header.kid ? keys.filter((k) => (k as { kid?: string }).kid === header.kid) : keys;
  if (candidates.length === 0) throw new Error("No JWKS key matches the token's kid");

  let verified = false;
  for (const jwk of candidates) {
    try {
      const key = crypto.createPublicKey({ key: jwk as crypto.JsonWebKey, format: "jwk" });
      const hash = NODE_HASH[alg];
      const options = alg.startsWith("PS")
        ? { padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST }
        : undefined;
      const sig = alg.startsWith("ES")
        ? crypto.verify(hash, Buffer.from(signingInput), { key, dsaEncoding: "ieee-p1363" }, signature)
        : crypto.verify(hash, Buffer.from(signingInput), options ? { key, ...options } : key, signature);
      if (sig) { verified = true; break; }
    } catch {
      // Wrong key type for this algorithm — try the next.
    }
  }
  if (!verified) throw new Error("ID token signature verification failed");

  // ── claims ──
  const iss = String(payload.iss ?? "").replace(/\/+$/, "");
  if (iss !== config.issuer) throw new Error(`ID token issuer mismatch: ${iss}`);

  // `aud` may be a string or an array. A token minted for a different client of
  // the same IdP is genuine and signed — this is the check that stops it.
  const aud = payload.aud;
  const audOk = Array.isArray(aud) ? aud.includes(config.clientId) : aud === config.clientId;
  if (!audOk) throw new Error("ID token audience does not include this client");

  // When `aud` has several entries the IdP must name which one it was really
  // for, and it has to be us.
  if (Array.isArray(aud) && aud.length > 1 && payload.azp !== config.clientId) {
    throw new Error("ID token has multiple audiences and azp is not this client");
  }

  const exp = Number(payload.exp);
  if (!Number.isFinite(exp) || now > exp + skew) throw new Error("ID token has expired");
  const iat = Number(payload.iat);
  if (Number.isFinite(iat) && iat > now + skew) throw new Error("ID token was issued in the future");
  const nbf = Number(payload.nbf);
  if (Number.isFinite(nbf) && now + skew < nbf) throw new Error("ID token is not yet valid");

  // Binds this token to the authorization request THIS server started.
  if (payload.nonce !== expectedNonce) throw new Error("ID token nonce does not match this login attempt");

  const sub = String(payload.sub ?? "");
  if (!sub) throw new Error("ID token has no subject");
  const email = String(payload.email ?? "").trim().toLowerCase();
  if (!email) throw new Error("ID token carries no email claim — cannot map to an account");

  return {
    sub,
    email,
    // Absent `email_verified` is treated as NOT verified. An IdP that does not
    // say the address is verified has not said it is.
    emailVerified: payload.email_verified === true,
    name: typeof payload.name === "string" ? payload.name : undefined,
  };
}

// ── token exchange ──────────────────────────────────────────────────────────

/** Exchange the authorization code for tokens, proving possession via PKCE. */
export async function exchangeCode(
  code: string,
  config: OidcConfig,
  discovery: OidcDiscovery,
  codeVerifier: string,
): Promise<{ id_token: string; access_token?: string }> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: config.redirectUri,
    client_id: config.clientId,
    client_secret: config.clientSecret,
    code_verifier: codeVerifier,
  });
  const res = await fetch(discovery.token_endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: body.toString(),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) {
    // The IdP's error body can contain the client secret in some misconfigured
    // deployments; log the status only.
    log.warn({ status: res.status }, "OIDC token exchange failed");
    throw new Error("OIDC token exchange failed");
  }
  const tokens = (await res.json()) as { id_token?: string; access_token?: string };
  if (!tokens.id_token) throw new Error("Token response contained no id_token");
  return { id_token: tokens.id_token, access_token: tokens.access_token };
}

// ── login-state store ───────────────────────────────────────────────────────

/**
 * Pending logins, keyed by `state`.
 *
 * In memory on purpose: these live for seconds, are useless after one use, and
 * a login that spans a process restart failing closed is correct behaviour. The
 * entry is DELETED on first lookup so a `state` cannot be replayed.
 */
const pending = new Map<string, OidcLoginState>();
const LOGIN_TTL_MS = 10 * 60 * 1000;

/**
 * Hard ceiling on concurrent pending logins.
 *
 * The entries are created by an UNAUTHENTICATED request and live for ten
 * minutes, so without a cap `/sso/login` is a memory-growth primitive for
 * anyone who can reach it. The rate limiter in `index.ts` is the primary
 * control; this is the backstop for when it is misconfigured or removed.
 *
 * At the cap the OLDEST entries are evicted rather than refusing new logins:
 * a flood should degrade the attacker's own stale attempts, not lock out the
 * people trying to sign in.
 */
const MAX_PENDING_LOGINS = 10_000;

/** How often the expiry sweep may run, at most. */
const SWEEP_INTERVAL_MS = 60_000;
let lastSweepAt = 0;

/**
 * Drop expired entries.
 *
 * Rate-limited to once a minute because it is O(n): sweeping on EVERY call made
 * `rememberLogin` O(n) and the whole map O(n²) to fill, which is a denial of
 * service in the function written to prevent one. Entries live ten minutes, so
 * a minute of slack costs nothing — `consumeLogin` re-checks expiry anyway, and
 * that is the check that actually matters for correctness.
 */
function sweepExpired(now: number): void {
  if (now - lastSweepAt < SWEEP_INTERVAL_MS) return;
  lastSweepAt = now;
  const cutoff = now - LOGIN_TTL_MS;
  for (const [k, v] of Array.from(pending.entries())) {
    if (v.createdAt < cutoff) pending.delete(k);
  }
}

export function rememberLogin(login: OidcLoginState): void {
  const now = Date.now();
  sweepExpired(now);

  // Map preserves insertion order, so the first key is always the oldest.
  // Deleting one at a time keeps this O(1) per call rather than rescanning.
  while (pending.size >= MAX_PENDING_LOGINS) {
    const oldest = pending.keys().next();
    if (oldest.done) break;
    pending.delete(oldest.value);
  }

  pending.set(login.state, login);
}

/** Consume a pending login. Returns null if unknown, replayed, or expired. */
export function consumeLogin(state: string): OidcLoginState | null {
  const found = pending.get(state);
  if (!found) return null;
  pending.delete(state); // single use — a replayed state must not work twice
  if (Date.now() - found.createdAt > LOGIN_TTL_MS) return null;
  return found;
}

export function pendingLoginCount(): number {
  return pending.size;
}

export function resetPendingLogins(): void {
  pending.clear();
  lastSweepAt = 0;
}
