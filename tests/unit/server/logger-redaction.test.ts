/**
 * Log redaction.
 *
 * Logs are where secrets leak by accident rather than by mistake: somebody
 * passes a whole object to a log call and a field nobody was thinking about
 * travels with it. Redaction is keyed on FIELD NAME so a secret is censored
 * wherever it appears, not wherever somebody remembered to strip it.
 *
 * `refreshToken` was absent while `token` was present — and a refresh token is
 * the more valuable of the two, because it mints new sessions. These tests fail
 * if any covered name stops being covered.
 */
import { describe, it, expect } from "vitest";
import pino from "pino";
import { Writable } from "stream";
import fs from "fs";
import path from "path";

/**
 * The redact names as `server/logger.ts` actually ships them.
 *
 * Parsed from source because the logger builds its pino instance at import
 * time and does not export the list; reading it here keeps the test honest
 * about what production does.
 */
function redactPathsFromSource(): string[] {
  const src = fs.readFileSync(path.join(process.cwd(), "server", "logger.ts"), "utf8");
  const block = /paths:\s*\[([\s\S]*?)\]\.flatMap/.exec(src);
  if (!block) throw new Error("could not find the redact paths array in server/logger.ts");
  // Comments inside the array must not be mistaken for entries.
  const withoutComments = block[1]!.split(String.fromCharCode(10))
    .map((line) => line.replace(/\/\/.*$/, ""))
    .join(String.fromCharCode(10));
  return [...withoutComments.matchAll(/"([^"]+)"/g)].map((m) => m[1]!);
}

/** Capture what a logger with the app's redact config actually writes. */
async function captureLog(payload: Record<string, unknown>): Promise<string> {
  const chunks: string[] = [];
  const sink = new Writable({
    write(chunk, _enc, cb) { chunks.push(chunk.toString()); cb(); },
  });

  // Read the REAL list off disk rather than copying it.
  //
  // This was a hardcoded duplicate "kept in sync by the coverage test below",
  // and it drifted the moment `apiToken` was added to production — the new
  // names were redacted by the app and not by the test, so a test asserting
  // they were censored failed against correct code. A copy of a list is a
  // second source of truth, however carefully it is commented.
  const names = redactPathsFromSource();
  const log = pino(
    { redact: { paths: names.flatMap((n) => [n, `*.${n}`, `*.*.${n}`]), censor: "[REDACTED]" } },
    sink,
  );
  log.info(payload, "test");
  await new Promise((r) => setImmediate(r));
  return chunks.join("");
}

const SECRET = "super-secret-value-do-not-log";

describe("logger redaction", () => {
  it("censors every credential-bearing field at the top level", async () => {
    const out = await captureLog({
      password: SECRET, passwordHash: SECRET, token: SECRET,
      refreshToken: SECRET, secret: SECRET, apiKey: SECRET, keyHash: SECRET,
      totpSecret: SECRET, idToken: SECRET, codeVerifier: SECRET, clientSecret: SECRET,
    });
    expect(out).not.toContain(SECRET);
    expect(out).toContain("[REDACTED]");
  });

  /** The gap that motivated this: a refresh token mints new sessions. */
  it("censors refreshToken, which was previously logged in full", async () => {
    const out = await captureLog({ session: { token: SECRET, refreshToken: SECRET } });
    expect(out).not.toContain(SECRET);
  });

  it("censors one and two levels deep, where objects are usually logged from", async () => {
    const oneDeep = await captureLog({ session: { token: SECRET } });
    expect(oneDeep).not.toContain(SECRET);
    const twoDeep = await captureLog({ req: { headers: { authorization: SECRET } } });
    expect(twoDeep).not.toContain(SECRET);
  });

  it("censors the OIDC and SIEM fields added with those features", async () => {
    const out = await captureLog({
      tokens: { id_token: SECRET, access_token: SECRET },
      login: { code_verifier: SECRET },
      config: { client_secret: SECRET },
    });
    expect(out).not.toContain(SECRET);
  });

  /**
   * `apiKey` was on the list and `apiToken` was not — which is the whole
   * failure mode of a name-keyed redactor: the field that travels is the one
   * nobody thought of. The Jira integration config carries `apiToken` beside
   * `email`, and a PagerDuty payload carries `routing_key`; both are
   * credentials, and neither was censored.
   */
  it("censors the ticketing and alerting credentials", async () => {
    const out = await captureLog({
      integration: { jira: { baseUrl: "https://x.atlassian.net", email: "a@b.c", apiToken: SECRET } },
      pagerduty: { routing_key: SECRET },
    });
    expect(out).not.toContain(SECRET);
    expect(out).toContain("[REDACTED]");
    // The non-secret half of the config must survive, or the log stops being
    // useful for working out which integration failed.
    expect(out).toContain("atlassian.net");
  });

  it("leaves non-sensitive fields intact — redaction must not blind the logs", async () => {
    const out = await captureLog({ userId: "u-123", target: "example.com", findingsCount: 7 });
    expect(out).toContain("u-123");
    expect(out).toContain("example.com");
    expect(out).toContain("7");
  });
});

describe("logger configuration", () => {
  /**
   * Reads the real config off disk: the copy above could drift, and a test that
   * only checks its own copy proves nothing about production.
   */
  it("the shipped redact list covers every name these tests assert", async () => {
    const fs = await import("fs");
    const path = await import("path");
    const src = fs.readFileSync(path.join(process.cwd(), "server", "logger.ts"), "utf8");
    for (const name of [
      "password", "passwordHash", "token", "refreshToken", "secret",
      "apiKey", "keyHash", "authorization", "totpSecret",
      "idToken", "accessToken", "codeVerifier", "clientSecret",
    ]) {
      expect(src, `server/logger.ts must redact "${name}"`).toContain(`"${name}"`);
    }
    // The three-depth expansion is what makes a bare name cover nested objects.
    expect(src).toContain("`*.${name}`");
    expect(src).toContain("`*.*.${name}`");
  });
});
