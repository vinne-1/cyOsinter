/**
 * Unit tests for server/sso-oidc.ts.
 *
 * This is authentication code, so the tests that matter are the ones that
 * REJECT. Every check in `verifyIdToken` corresponds to a named attack, and a
 * check that silently stops working is an auth bypass that looks like a passing
 * build — so each one gets a test that fails if the check is removed.
 *
 * Tokens are signed here with a real generated RSA key and served through a
 * stubbed JWKS endpoint, so the signature path is exercised for real rather
 * than mocked away.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import crypto from "crypto";

vi.mock("../../../server/logger.js", () => ({
  createLogger: () => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }),
}));

import {
  readOidcConfig,
  createLoginState,
  codeChallengeFor,
  buildAuthorizationUrl,
  verifyIdToken,
  discover,
  exchangeCode,
  rememberLogin,
  consumeLogin,
  resetPendingLogins,
  resetOidcCaches,
  type OidcConfig,
  type OidcDiscovery,
} from "../../../server/sso-oidc";

const ISSUER = "https://idp.example.com";
const CLIENT_ID = "cyshield-client";

const config: OidcConfig = {
  issuer: ISSUER,
  clientId: CLIENT_ID,
  clientSecret: "s3cret",
  redirectUri: "https://app.example.com/api/auth/sso/callback",
  scopes: [],
  autoProvision: false,
  enabled: true,
};

const discovery: OidcDiscovery = {
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/authorize`,
  token_endpoint: `${ISSUER}/token`,
  jwks_uri: `${ISSUER}/jwks`,
};

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const KID = "test-key-1";
const jwk = { ...(publicKey.export({ format: "jwk" }) as Record<string, unknown>), kid: KID, alg: "RS256", use: "sig" };

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");

function signToken(payload: Record<string, unknown>, header: Record<string, unknown> = {}): string {
  const h = b64({ alg: "RS256", typ: "JWT", kid: KID, ...header });
  const p = b64(payload);
  const sig = crypto.sign("sha256", Buffer.from(`${h}.${p}`), privateKey).toString("base64url");
  return `${h}.${p}.${sig}`;
}

const NOW = 1_800_000_000_000; // fixed clock
const validPayload = (over: Record<string, unknown> = {}) => ({
  iss: ISSUER,
  aud: CLIENT_ID,
  sub: "user-123",
  email: "jo@example.com",
  email_verified: true,
  name: "Jo Example",
  nonce: "the-nonce",
  iat: Math.floor(NOW / 1000) - 10,
  exp: Math.floor(NOW / 1000) + 600,
  ...over,
});

const verify = (token: string, nonce = "the-nonce") =>
  verifyIdToken(token, config, discovery, nonce, { now: NOW });

beforeEach(() => {
  resetOidcCaches();
  resetPendingLogins();
  vi.stubGlobal("fetch", vi.fn(async (url: string) => {
    if (String(url).includes("/jwks")) return { ok: true, status: 200, json: async () => ({ keys: [jwk] }) };
    return { ok: false, status: 404, json: async () => ({}) };
  }));
});
afterEach(() => vi.unstubAllGlobals());

describe("readOidcConfig", () => {
  it("is disabled unless every required value is present", () => {
    expect(readOidcConfig({} as NodeJS.ProcessEnv).enabled).toBe(false);
    // A half-configured client that works until the callback is worse than one
    // that reports itself disabled.
    expect(readOidcConfig({ OIDC_ISSUER: ISSUER, OIDC_CLIENT_ID: "x" } as NodeJS.ProcessEnv).enabled).toBe(false);
    expect(readOidcConfig({
      OIDC_ISSUER: `${ISSUER}/`, OIDC_CLIENT_ID: "x", OIDC_CLIENT_SECRET: "y", OIDC_REDIRECT_URI: "https://a/cb",
    } as NodeJS.ProcessEnv)).toMatchObject({ enabled: true, issuer: ISSUER });
  });

  it("does not auto-provision unless explicitly enabled", () => {
    const base = { OIDC_ISSUER: ISSUER, OIDC_CLIENT_ID: "x", OIDC_CLIENT_SECRET: "y", OIDC_REDIRECT_URI: "https://a/cb" };
    expect(readOidcConfig(base as NodeJS.ProcessEnv).autoProvision).toBe(false);
    expect(readOidcConfig({ ...base, OIDC_AUTO_PROVISION: "true" } as NodeJS.ProcessEnv).autoProvision).toBe(true);
  });
});

describe("authorization request", () => {
  it("sends PKCE, state and nonce", () => {
    const login = createLoginState();
    const url = new URL(buildAuthorizationUrl(config, discovery, login));
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("code_challenge")).toBe(codeChallengeFor(login.codeVerifier));
    expect(url.searchParams.get("state")).toBe(login.state);
    expect(url.searchParams.get("nonce")).toBe(login.nonce);
    expect(url.searchParams.get("scope")).toContain("openid");
  });

  it("generates unguessable, unique per-login secrets", () => {
    const a = createLoginState();
    const b = createLoginState();
    expect(a.state).not.toBe(b.state);
    expect(a.nonce).not.toBe(b.nonce);
    expect(a.codeVerifier.length).toBeGreaterThanOrEqual(43); // RFC 7636 minimum
  });
});

describe("verifyIdToken — acceptance", () => {
  it("accepts a correctly signed, correctly claimed token", async () => {
    const claims = await verify(signToken(validPayload()));
    expect(claims).toEqual({ sub: "user-123", email: "jo@example.com", emailVerified: true, name: "Jo Example" });
  });

  it("accepts an array audience that names this client via azp", async () => {
    const claims = await verify(signToken(validPayload({ aud: [CLIENT_ID, "other"], azp: CLIENT_ID })));
    expect(claims.sub).toBe("user-123");
  });
});

describe("verifyIdToken — every rejection is a named attack", () => {
  it("rejects a tampered signature", async () => {
    const token = signToken(validPayload());
    const [h, p] = token.split(".");
    const forged = `${h}.${p}.${Buffer.from("nonsense").toString("base64url")}`;
    await expect(verify(forged)).rejects.toThrow(/signature/i);
  });

  /** `alg: none` — the classic JWT bypass. */
  it("rejects alg:none", async () => {
    const h = b64({ alg: "none", typ: "JWT", kid: KID });
    const p = b64(validPayload());
    await expect(verify(`${h}.${p}.`)).rejects.toThrow(/algorithm not allowed/i);
  });

  /** HMAC signed with the public key as the secret — the other classic. */
  it("rejects a symmetric algorithm", async () => {
    const h = b64({ alg: "HS256", typ: "JWT", kid: KID });
    const p = b64(validPayload());
    const pub = publicKey.export({ format: "pem", type: "spki" }) as string;
    const sig = crypto.createHmac("sha256", pub).update(`${h}.${p}`).digest("base64url");
    await expect(verify(`${h}.${p}.${sig}`)).rejects.toThrow(/algorithm not allowed/i);
  });

  it("rejects a token from a different issuer", async () => {
    await expect(verify(signToken(validPayload({ iss: "https://evil-idp.example" })))).rejects.toThrow(/issuer/i);
  });

  /**
   * The subtle one: a token minted for a DIFFERENT client of the same IdP is
   * genuine and correctly signed. Without the audience check, any other app in
   * the tenant can log in as its users here.
   */
  it("rejects a genuine token issued for another client", async () => {
    await expect(verify(signToken(validPayload({ aud: "some-other-app" })))).rejects.toThrow(/audience/i);
  });

  it("rejects a multi-audience token whose azp is not this client", async () => {
    await expect(verify(signToken(validPayload({ aud: [CLIENT_ID, "other"], azp: "other" })))).rejects.toThrow(/azp/i);
  });

  it("rejects an expired token", async () => {
    await expect(verify(signToken(validPayload({ exp: Math.floor(NOW / 1000) - 3600 })))).rejects.toThrow(/expired/i);
  });

  it("rejects a token issued in the future", async () => {
    await expect(verify(signToken(validPayload({ iat: Math.floor(NOW / 1000) + 3600 })))).rejects.toThrow(/future/i);
  });

  /** Replay of a token captured from a different session. */
  it("rejects a token whose nonce does not match this login attempt", async () => {
    await expect(verify(signToken(validPayload({ nonce: "someone-elses-nonce" })))).rejects.toThrow(/nonce/i);
  });

  it("rejects a token with no email, which cannot map to an account", async () => {
    await expect(verify(signToken(validPayload({ email: undefined })))).rejects.toThrow(/email/i);
  });

  /**
   * An IdP that does not assert the address is verified has not verified it.
   * The claims still return, but flagged — the caller must refuse to link.
   */
  it("reports an unverified email as unverified rather than assuming", async () => {
    const claims = await verify(signToken(validPayload({ email_verified: false })));
    expect(claims.emailVerified).toBe(false);
    const absent = await verify(signToken(validPayload({ email_verified: undefined })));
    expect(absent.emailVerified).toBe(false);
  });

  it("rejects a token signed by a key that is not in the JWKS", async () => {
    const other = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const h = b64({ alg: "RS256", typ: "JWT", kid: KID });
    const p = b64(validPayload());
    const sig = crypto.sign("sha256", Buffer.from(`${h}.${p}`), other.privateKey).toString("base64url");
    await expect(verify(`${h}.${p}.${sig}`)).rejects.toThrow(/signature/i);
  });

  it("rejects a malformed token outright", async () => {
    await expect(verify("not-a-jwt")).rejects.toThrow(/compact serialization/i);
  });
});

describe("discover", () => {
  it("refuses a document whose issuer is not the one we asked for", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: true, status: 200,
      json: async () => ({ ...discovery, issuer: "https://someone-else" }),
    })));
    await expect(discover(config)).rejects.toThrow(/issuer mismatch/i);
  });

  it("refuses a document missing required endpoints", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: true, status: 200, json: async () => ({ issuer: ISSUER }),
    })));
    await expect(discover(config)).rejects.toThrow(/missing required endpoints/i);
  });
});

describe("exchangeCode", () => {
  it("proves possession with the PKCE verifier", async () => {
    const fetchMock = vi.fn(async () => ({ ok: true, status: 200, json: async () => ({ id_token: "tok" }) }));
    vi.stubGlobal("fetch", fetchMock);
    const out = await exchangeCode("the-code", config, discovery, "the-verifier");
    expect(out.id_token).toBe("tok");
    const body = String((fetchMock.mock.calls[0][1] as { body: string }).body);
    expect(body).toContain("code_verifier=the-verifier");
    expect(body).toContain("grant_type=authorization_code");
  });

  it("fails when the IdP returns no id_token", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: true, status: 200, json: async () => ({ access_token: "a" }) })));
    await expect(exchangeCode("c", config, discovery, "v")).rejects.toThrow(/no id_token/i);
  });
});

describe("login state store", () => {
  it("consumes a state exactly once, so a replayed callback fails", () => {
    const login = createLoginState();
    rememberLogin(login);
    expect(consumeLogin(login.state)).toMatchObject({ nonce: login.nonce });
    expect(consumeLogin(login.state)).toBeNull();
  });

  it("rejects an unknown state — the CSRF case", () => {
    expect(consumeLogin("state-an-attacker-made-up")).toBeNull();
  });

  it("rejects an expired login attempt", () => {
    const login = { ...createLoginState(), createdAt: Date.now() - 20 * 60 * 1000 };
    rememberLogin(login);
    expect(consumeLogin(login.state)).toBeNull();
  });
});

/**
 * The pending-login map is memory an UNAUTHENTICATED caller controls: entries
 * are created by `/sso/login` and live ten minutes. The rate limiter is the
 * primary control; this cap is the backstop.
 */
describe("pending login capacity", () => {
  it("evicts the oldest attempts rather than refusing new logins", () => {
    // A flood should degrade the attacker's own stale attempts, not lock out
    // the people trying to sign in — so the newest entry must survive.
    const first = createLoginState();
    rememberLogin(first);
    for (let i = 0; i < 10_050; i++) rememberLogin(createLoginState());
    const newest = createLoginState();
    rememberLogin(newest);

    expect(consumeLogin(newest.state)).not.toBeNull();
    // The earliest attempt was pushed out by the cap.
    expect(consumeLogin(first.state)).toBeNull();
  });
});
