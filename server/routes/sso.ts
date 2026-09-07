/**
 * OIDC single sign-on routes.
 *
 * Three endpoints:
 *   GET /api/auth/sso/status    is SSO available? (so the login page can decide)
 *   GET /api/auth/sso/login     start the flow — redirects to the IdP
 *   GET /api/auth/sso/callback  finish it — verify, link, issue a session
 *
 * The security work lives in `server/sso-oidc.ts`; this file is the transport
 * and the account-linking policy. Two rules matter here:
 *
 *  - **A verified email is required to link.** An IdP reporting
 *    `email_verified: false` is saying it does not know the address belongs to
 *    this person. Linking on it would let anyone who can edit their own IdP
 *    profile take over an existing account by claiming its address.
 *  - **Auto-provisioning is opt-in.** An IdP tenant usually contains far more
 *    people than should have access to a security platform, so an unknown user
 *    is refused unless the operator explicitly turned provisioning on.
 *
 * Every outcome is written to the audit trail. `auditMutations` only records
 * non-GET requests and these are GETs by necessity (they are browser
 * redirects), so they log explicitly — the same reason `routes/auth.ts` logs
 * its own login outcomes.
 */

import { Router } from "express";
import { eq } from "drizzle-orm";
import { db } from "../db";
import { users } from "@shared/schema";
import { createSession } from "../auth";
import { sendError } from "./response";
import { createLogger } from "../logger";
import { logAuditAsync, clientIp } from "../audit";
import {
  readOidcConfig,
  discover,
  createLoginState,
  buildAuthorizationUrl,
  rememberLogin,
  consumeLogin,
  exchangeCode,
  verifyIdToken,
} from "../sso-oidc";

const log = createLogger("sso-routes");

export const ssoRouter = Router();

/**
 * Where the browser lands after the callback.
 *
 * The token is handed over in the URL fragment, not the query string: a
 * fragment is never sent to a server, so it stays out of access logs, proxy
 * logs and the `Referer` header of the next request.
 */
function appRedirect(base: string, fragment: Record<string, string>): string {
  const params = new URLSearchParams(fragment).toString();
  return `${base}#${params}`;
}

ssoRouter.get("/auth/sso/status", (_req, res) => {
  const config = readOidcConfig();
  res.json({ enabled: config.enabled, issuer: config.enabled ? config.issuer : undefined });
});

ssoRouter.get("/auth/sso/login", async (req, res) => {
  const config = readOidcConfig();
  if (!config.enabled) return sendError(res, 404, "Single sign-on is not configured");

  try {
    const discovery = await discover(config);
    const login = createLoginState();
    rememberLogin(login);
    res.redirect(buildAuthorizationUrl(config, discovery, login));
  } catch (err) {
    log.error({ err }, "Could not start SSO login");
    sendError(res, 502, "Could not reach the identity provider");
  }
});

ssoRouter.get("/auth/sso/callback", async (req, res) => {
  const config = readOidcConfig();
  if (!config.enabled) return sendError(res, 404, "Single sign-on is not configured");

  const fail = (reason: string, detail?: string) => {
    // The reason is logged, never reflected to the browser: a callback error is
    // attacker-reachable, and echoing detail turns it into an oracle.
    log.warn({ reason, detail }, "SSO callback rejected");
    logAuditAsync({
      // No userId to attribute: the callback failed before an account was
      // established. The reason is still recorded so a campaign against the
      // callback is visible.
      userId: null,
      action: "sso_login_failed",
      resourceType: "user",
      metadata: { reason },
      ipAddress: clientIp(req),
    });
    res.redirect(appRedirect("/auth", { sso_error: "1" }));
  };

  const code = typeof req.query.code === "string" ? req.query.code : "";
  const state = typeof req.query.state === "string" ? req.query.state : "";
  if (typeof req.query.error === "string") return fail("idp_error", req.query.error);
  if (!code || !state) return fail("missing_code_or_state");

  // Single-use: consuming here means a replayed callback finds nothing.
  const login = consumeLogin(state);
  if (!login) return fail("unknown_or_replayed_state");

  try {
    const discovery = await discover(config);
    const tokens = await exchangeCode(code, config, discovery, login.codeVerifier);
    const claims = await verifyIdToken(tokens.id_token, config, discovery, login.nonce);

    if (!claims.emailVerified) return fail("email_not_verified", claims.email);

    const [existing] = await db.select().from(users).where(eq(users.email, claims.email)).limit(1);

    let user = existing;
    if (!user) {
      if (!config.autoProvision) return fail("no_matching_account", claims.email);
      // Provisioned with the lowest role. Elevation is an explicit act by an
      // administrator, never a side effect of logging in.
      const [created] = await db
        .insert(users)
        .values({
          email: claims.email,
          name: claims.name ?? claims.email,
          // No local password: this account can only ever authenticate through
          // the IdP. A random unusable hash is safer than an empty string,
          // which some comparison paths would treat as a match.
          passwordHash: `oidc:${crypto.randomUUID()}`,
          role: "viewer",
        })
        .returning();
      user = created;
      logAuditAsync({
        userId: user.id,
        action: "user_provisioned_via_sso",
        resourceType: "user",
        resourceId: user.id,
        metadata: { email: user.email, issuer: config.issuer },
        ipAddress: clientIp(req),
      });
    }

    if (user.lockedUntil && user.lockedUntil > new Date()) return fail("account_locked", user.email);

    const session = await createSession(user.id, req.ip ?? undefined, req.headers["user-agent"]);

    logAuditAsync({
      userId: user.id,
      action: "login",
      resourceType: "user",
      resourceId: user.id,
      metadata: { email: user.email, method: "sso", issuer: config.issuer },
      ipAddress: clientIp(req),
    });
    log.info({ userId: user.id }, "User logged in via SSO");

    // `refreshToken` is nullable on the session row; omit it rather than
    // putting the string "null" in the fragment for the client to store.
    const fragment: Record<string, string> = {
      sso_token: session.token,
      sso_expires: String(new Date(session.expiresAt).getTime()),
    };
    if (session.refreshToken) fragment.sso_refresh = session.refreshToken;
    res.redirect(appRedirect("/auth", fragment));
  } catch (err) {
    fail("verification_failed", err instanceof Error ? err.message : String(err));
  }
});
