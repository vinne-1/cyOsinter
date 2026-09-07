# OWASP ASVS 5.0.0 — Conformance Assessment

**Standard:** [OWASP Application Security Verification Standard 5.0.0](https://owasp.org/www-project-application-security-verification-standard/) (released May 2025) — 345 requirements across 17 chapters.

**Scope of this document:** every **Level 1** requirement (70), assessed against the code with a
reference. Level 2 is tracked at the end and is not yet claimed.

**Why L1 first and L2 as the target:** ASVS defines L2 as the level for "most business
applications handling personal or financial data". A platform that stores another
organisation's attack surface — subdomains, open ports, unpatched services, exposed
credentials — is squarely in that class. L1 is therefore the floor, not the goal.

**How to read a verdict.** `PASS` means a specific control was located in the code and, where
observable, exercised. `N/A` means the requirement addresses a feature this application does
not have, with the reason stated — never "we skipped it". `OPERATOR` means the control is real
but lives in the deployment rather than the codebase.

Assessed against branch `feat/stealth-safe-mode`. Re-run the verification protocol in
`CLAUDE.md` before trusting it.

---

## Summary

| | Count |
|---|---|
| L1 requirements | 70 |
| PASS | 58 |
| N/A (feature not present) | 9 |
| OPERATOR (deployment-provided) | 3 |
| **FAIL** | **0** |

Five of those passes were failures when this assessment started; they are marked **`[fixed]`**
below with what was actually wrong.

---

## V1 — Encoding and Sanitization

| Req | Verdict | Evidence |
|---|---|---|
| V1.2.1 | PASS `[fixed]` | React escapes by default. The one `dangerouslySetInnerHTML` in the client (`components/ui/chart.tsx`) writes a `<style>` block; config keys and colour values are now allowlisted (`SAFE_CSS_KEY`, `SAFE_CSS_COLOR`) so `url()` and rule-breaking braces cannot reach the stylesheet. Previously unguarded — no live caller, but the sink was one API-driven chart config away from being real. |
| V1.2.2 | PASS | No `javascript:` sinks; outbound URLs are built with `URL`, and user-influenced URLs additionally pass `isSafeOutboundUrl` (`server/utils/ssrf.ts`). |
| V1.2.3 | PASS | Responses are serialised by `res.json`; no hand-built JSON. |
| V1.2.4 | PASS | Drizzle ORM throughout; no `sql.raw` or `sql.identifier` anywhere in `server/`. Tagged-template SQL is parameterised. |
| V1.2.5 | PASS | External scanners are launched as `spawn(bin, argsArray)` with **no `shell: true` anywhere** (`nuclei.ts`, `crawler.ts`, `http-probe.ts`), so an attacker-controlled target name is an argument, never shell syntax. |
| V1.3.1 | N/A | No WYSIWYG editor and no HTML accepted from users. |
| V1.3.2 | PASS | No `eval` or `new Function` in `server/` or `client/src/`. |
| V1.5.1 | PASS | XML is parsed by `fast-xml-parser` (`server/parsers/nmap.ts`), which does not resolve external entities. Sitemaps are matched with a `<loc>` regex, not an XML parser, so there is no DTD surface at all. |

## V2 — Validation and Business Logic

| Req | Verdict | Evidence |
|---|---|---|
| V2.1.1 | PASS | Validation rules are Zod schemas in `server/routes/schemas.ts`; the convention ("Zod for all input — validate at route boundary, never trust raw `req.body`") is documented in `CLAUDE.md`. |
| V2.2.1 | PASS | Zod is positive validation — allow-listed shapes, enums and ranges. |
| V2.2.2 | PASS | Enforced server-side at the route boundary; client validation is additive only. |
| V2.3.1 | PASS | `server/case-workflow.ts` is an explicit state machine: `open → resolved` is refused because skipping triage leaves no record that anyone looked. |

## V3 — Web Frontend Security

| Req | Verdict | Evidence |
|---|---|---|
| V3.2.1 | PASS | `X-Content-Type-Options: nosniff` and `X-Frame-Options: SAMEORIGIN` via helmet; confirmed on a live response. |
| V3.2.2 | PASS | React renders text as text; no innerHTML paths for user data. |
| V3.3.1 | N/A | The application sets **no cookies**. Auth is a bearer token in `localStorage`, so `Secure` / `__Host-` do not apply. |
| V3.4.1 | PASS `[fixed]` | HSTS was disabled unconditionally, so a TLS-fronted deployment got none. It is now applied per-request when `req.secure` (`max-age=31536000; includeSubDomains`) — verified present behind `X-Forwarded-Proto: https` and correctly absent on plain HTTP, which is what keeps a LAN install from pinning HTTPS it cannot serve. |
| V3.4.2 | PASS | No CORS middleware is mounted and no `Access-Control-Allow-Origin` is emitted, so the browser's same-origin default stands. |
| V3.5.1 | PASS | No cookie or other ambient credential exists, so a cross-origin request carries no authority; CSRF is structurally unreachable rather than mitigated. |
| V3.5.2 | N/A | The application does not rely on CORS preflight to protect any functionality. |
| V3.5.3 | PASS | All state change is POST/PATCH/PUT/DELETE; `auditMutations` refuses to audit GET/HEAD/OPTIONS precisely because they are not state-changing. |

## V4 — API and Web Service

| Req | Verdict | Evidence |
|---|---|---|
| V4.1.1 | PASS | `Content-Type: application/json; charset=utf-8` on API responses; confirmed live. |
| V4.4.1 | PASS | `client/src/hooks/use-websocket.ts` selects `wss:` whenever the page is HTTPS, so the socket never downgrades below the page. |

## V5 — File Handling

| Req | Verdict | Evidence |
|---|---|---|
| V5.2.1 | PASS | `multer({ storage: memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } })` in `server/routes/imports.ts`. |
| V5.2.2 | PASS | MIME type is checked against an allow-list, and the content is then handed to a format-specific parser that rejects anything not of that shape — so a renamed file fails on structure, not on its claimed type. |
| V5.3.1 | PASS | Uploads live in memory and are never written to disk or served, so there is nothing to execute. |
| V5.3.2 | PASS | No filesystem path is ever constructed from a user-supplied filename. |

## V6 — Authentication

| Req | Verdict | Evidence |
|---|---|---|
| V6.1.1 | PASS | Rate limiting, per-account lockout and their thresholds are documented in `CLAUDE.md`. |
| V6.2.1 | PASS | 12-character minimum (`PASSWORD_MIN_LENGTH`), above the standard's floor of 8. |
| V6.2.2 | PASS `[fixed]` | **There was no way to change a password at all** — no endpoint, no screen. `POST /api/auth/change-password` and `client/src/pages/account.tsx` now exist. |
| V6.2.3 | PASS `[fixed]` | The change requires the current password, so a stolen session token cannot seize the account permanently. |
| V6.2.4 | PASS `[fixed]` | New passwords are screened against **5,000** known-common passwords (`server/data/common-passwords.ts`). The standard asks for 3,000 *that match the policy* — a generic top-3000 is almost entirely under 12 characters and would have screened nothing, so the list is the 5,000 most frequent entries of at least 12 characters from the SecLists `Pwdb_top-1000000` corpus. Rejects `q1w2e3r4t5y6`, which passes every classic composition rule. |
| V6.2.5 | PASS | No composition rules — deliberately. See `server/password-policy.ts`. |
| V6.2.6 | PASS | All password fields are `type="password"`. |
| V6.2.7 | PASS | No paste blocking; `autoComplete="current-password"` / `"new-password"` so password managers work. |
| V6.2.8 | PASS | No trimming, case folding or truncation on any password path. |
| V6.3.1 | PASS | Per-account lockout (`users.locked_until`) plus per-IP limits backed by a shared Postgres store, so the budget is not multiplied by replica count. |
| V6.3.2 | PASS | No default account ships. Admin seeding requires `SEED_ADMIN_EMAIL` *and* `SEED_ADMIN_PASSWORD` to be set explicitly. |
| V6.4.1 | N/A | The application generates no initial passwords or activation codes. |
| V6.4.2 | PASS | No password hints and no knowledge-based "secret questions". |

## V7 — Session Management

| Req | Verdict | Evidence |
|---|---|---|
| V7.2.1 | PASS | `validateSession` verifies against the database on every request. |
| V7.2.2 | PASS | Tokens are minted per session; no static shared secret. |
| V7.2.3 | PASS | `crypto.randomBytes(32)` — 256 bits, twice the required 128. Only the SHA-256 hash is stored. |
| V7.2.4 | PASS | Each login creates a new session; refresh rotates the token and keeps the spent row so replay stays detectable, revoking the whole `family_id` chain on reuse. A password change re-issues as well. |
| V7.4.1 | PASS | Logout deletes the session row, so the token cannot be used again. |
| V7.4.2 | PASS | Deleting a user cascades to `sessions`; a password change calls `deleteUserSessions` before issuing the replacement, so there is no window where old tokens and the new password are both valid. |

## V8 — Authorization

| Req | Verdict | Evidence |
|---|---|---|
| V8.1.1 | PASS | Workspace roles and the 404-not-403 convention are documented in `CLAUDE.md`. |
| V8.2.1 | PASS | `requireRole` / `requireWorkspaceRole`; API keys are further narrowed by `enforceApiKeyScope`. |
| V8.2.2 | PASS | Every bare-ID route resolves the object and checks membership. `tests/unit/server/bare-id-authorization.test.ts` statically fails the build when a new bare-ID route appears unguarded. |
| V8.3.1 | PASS | All authorization is server-side middleware; the client holds no authorization state. |

## V9 — Self-contained Tokens *(applies to OIDC ID tokens)*

| Req | Verdict | Evidence |
|---|---|---|
| V9.1.1 | PASS | `verifyIdToken` verifies the RS256 signature against the issuer's JWKS before reading any claim. |
| V9.1.2 | PASS | Explicit algorithm allow-list, which is what closes `alg:none` and HMAC-with-the-public-key. |
| V9.1.3 | PASS | Keys come only from the discovery document's `jwks_uri`; the token cannot nominate its own key source. |
| V9.2.1 | PASS | `exp`, `iat` and `nbf` are all verified. |

## V10 — OAuth and OIDC

| Req | Verdict | Evidence |
|---|---|---|
| V10.4.1–V10.4.5 | N/A (5) | Every L1 requirement in this chapter constrains the **authorization server**. This application is a relying party only — it never issues authorization codes or tokens to third-party clients. Its client-side obligations are met (PKCE S256, single-use `state`, `nonce`); and its own refresh tokens are covered by family-reuse detection, which is stricter than V10.4.5 asks of a public client. |

## V11 — Cryptography

| Req | Verdict | Evidence |
|---|---|---|
| V11.3.1 | PASS | AES-256-GCM via `createCipheriv` with a random IV. No ECB, no `createCipher`. |
| V11.3.2 | PASS | AES-GCM is the only symmetric cipher used. |
| V11.4.1 | PASS | SHA-256 and scrypt for all security purposes. Two non-cryptographic uses exist and are **protocol-mandated, not chosen**: SHA-1 for the HaveIBeenPwned k-anonymity range API, and MD5 for the Gravatar profile identifier. Neither authenticates, signs or derives anything. |

## V12 — Secure Communication

| Req | Verdict | Evidence |
|---|---|---|
| V12.1.1 | OPERATOR | TLS terminates at the operator's reverse proxy; the application speaks HTTP behind it by design. |
| V12.2.1 | OPERATOR | Same. Once TLS is present the app enforces it onward via HSTS (V3.4.1). |
| V12.2.2 | OPERATOR | Certificate provisioning is the deployment's responsibility. |

## V13 — Configuration

| Req | Verdict | Evidence |
|---|---|---|
| V13.4.1 | PASS | `.git` is excluded in `.dockerignore`, and the runtime image copies only `dist`, `shared` and `drizzle.config.ts`. |

## V14 — Data Protection

| Req | Verdict | Evidence |
|---|---|---|
| V14.2.1 | PASS | No token, key or password is ever placed in a URL or query string. The SSO callback returns its session token in the URL **fragment**, which browsers never transmit to a server — so it stays out of access logs, `Referer` headers and proxy records. |
| V14.3.1 | PASS | Logout clears `auth_token` from `localStorage`; asserted by `tests/e2e/z-auth.spec.ts`. |

## V15 — Secure Coding and Architecture

| Req | Verdict | Evidence |
|---|---|---|
| V15.1.1 | PASS `[fixed]` | Risk-based remediation time frames (Critical 7d / High 30d / Moderate 90d / Low next refresh) are now written down in `CLAUDE.md`. They previously were not, which made the policy unauditable — "we patch quickly" is not a commitment anyone can check. |
| V15.2.1 | PASS | `npm audit --audit-level=high` gates CI: 0 high, 0 critical. Six moderate advisories resolve to two direct dependencies (`drizzle-kit`, `exceljs`), both build/export tooling rather than request-path code, both accepted under the documented exception clause. |
| V15.3.1 | PASS | Responses project explicit fields — the auth routes return `{ id, email, name, role }`, never the user row, so `passwordHash` and `totpSecret` cannot leak by spread. |

---

## Level 2

L2 adds 183 requirements on top of L1 (253 cumulative). It is **not claimed here.** Several
L2 controls are already in place as a by-product of work done for other reasons — token
family-reuse detection, a full audit trail over every mutation, SIEM export in ECS/CEF,
per-account lockout, TOTP, SSO with PKCE, data retention enforcement, and workspace-level
authorization with existence-hiding 404s. What is missing is not primarily code but a
requirement-by-requirement assessment of the same rigour as the table above.

Publishing an unverified L2 badge would be the same category of error this codebase keeps
finding in itself: a claim the product asserts but does not perform.
