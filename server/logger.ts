import pino from "pino";

const isDev = process.env.NODE_ENV !== "production";

export const logger = pino({
  level: process.env.LOG_LEVEL || (isDev ? "debug" : "info"),
  /**
   * Fields that must never reach a log line.
   *
   * Logs are the one place secrets leak by accident rather than by mistake: an
   * object gets passed whole to a log call, and a field nobody thought about
   * travels with it. The list is therefore keyed on FIELD NAME, so a secret is
   * redacted wherever it appears rather than wherever somebody remembered.
   *
   * `refreshToken` was missing while `token` was present — and a refresh token
   * is the more valuable of the two, because it mints new sessions. `keyHash`
   * was missing too. The OIDC and SIEM fields were added with those features and
   * belong here for the same reason: `codeVerifier` is the PKCE secret, and an
   * `idToken` is a bearer credential for the duration of its validity.
   *
   * Each name is listed at three depths because pino's `*` matches exactly one
   * level: a bare name, `*.name`, and `*.*.name`. A secret nested deeper than
   * that in a log payload is a sign the call site is logging an entire request
   * or response object, which is its own problem.
   */
  redact: {
    paths: [
      "password", "passwordHash", "token", "refreshToken", "refresh_token",
      "secret", "clientSecret", "client_secret", "apiKey", "keyHash",
      "authorization", "Authorization", "cookie", "Cookie",
      "totpSecret", "totp_secret",
      "idToken", "id_token", "accessToken", "access_token",
      "codeVerifier", "code_verifier", "code_challenge",
      // Ticketing and alerting credentials. `apiKey` was listed and `apiToken`
      // was not, which is the whole failure mode of a name-keyed redactor: the
      // field that travels is the one nobody thought of. The Jira config
      // carries `apiToken` beside `email`, and a PagerDuty payload carries
      // `routing_key` — neither is currently passed whole to a log call, and
      // that is exactly the assumption this list exists to stop depending on.
      "apiToken", "api_token", "routingKey", "routing_key",
    ].flatMap((name) => [name, `*.${name}`, `*.*.${name}`]),
    censor: "[REDACTED]",
  },
  transport: isDev
    ? { target: "pino-pretty", options: { colorize: true, translateTime: "HH:MM:ss", ignore: "pid,hostname" } }
    : undefined,
});

/** Create a child logger with a component/module name */
export function createLogger(component: string) {
  return logger.child({ component });
}
