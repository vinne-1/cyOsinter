# Cyber-Shield-Pro — CLAUDE.md

Project context for AI-assisted development. Read this before touching any code.

## What This Is

Cyber-Shield-Pro (repo: cyOsinter) is a self-hosted **External Attack Surface Management (EASM) and OSINT scanner**. Users add domains, trigger scans, and get security findings (subdomains, open ports, TLS issues, exposed secrets, DNS misconfigs, CVEs, etc.) in a web dashboard.

## Stack

| Layer | Tech |
|---|---|
| Backend | Express.js + TypeScript + Node.js |
| Database | PostgreSQL via Drizzle ORM (`server/storage.ts`) |
| Frontend | React + TypeScript + Vite + Tailwind + shadcn/ui |
| Auth | Session tokens (Bearer) stored in `localStorage` as `auth_token` |
| Scanner | Custom modules in `server/scanner/` — DNS, TLS, port scan, OSINT, Nuclei, DAST |
| AI | Ollama (local LLM) via `server/ai-service.ts` |
| Queue | In-memory scan queue in `server/scan-queue.ts` |

## Verification Protocol

**Run all three before committing. All must pass.**

```bash
npx tsc --noEmit          # TypeScript — zero errors required
npm test                   # Vitest unit tests — 1556 tests / 97 files, all must pass
npx playwright test        # E2E tests — 17 tests, all must pass
node scripts/smoke-real-data.mjs        # renders every route/tab against REAL data
node scripts/reconcile-real-data.mjs    # cross-checks every published aggregate
npx tsx scripts/verify-report-content.mts   # the report describes the right findings
node scripts/probe-cross-tenant.mjs         # no cross-tenant reads, no existence oracles
```

The suite above runs against an EMPTY workspace, so it cannot see a bug that
only appears once rows arrive. `smoke-real-data.mjs` is the fourth gate for
anything touching a page component — see the blind-spot note below.

`tests/e2e/accessibility.spec.ts` sweeps every route with axe (WCAG 2.1 A/AA)
and must stay at **0 serious/critical**. It is part of `npx playwright test`, so
there is no separate a11y command to remember to run.

**Restart the dev server before verifying anything server-side.** `npm run dev`
is `tsx server/index.ts` with no watch, so a running process keeps the code and
the Drizzle schema it started with. This has twice produced a convincing false
result: once a "verified" upgrade that the old process was still serving, and
once a `kind` column that looked missing from the API when the column was fine
and the process was old. Confirm the restart (`grep "serving on port"`) rather
than assuming it.

The E2E suite needs the app on port 5050 and Postgres on 5433 (`docker compose up -d db`,
then `PORT=5050 npm run dev`). Playwright reuses an already-running server.

Or use the convenience script:
```bash
bash scripts/inspect.sh
```

## Measured Against an External Bar

`docs/asvs-5.0-conformance.md` assesses this codebase against **OWASP ASVS 5.0.0**
requirement by requirement: all 70 Level 1 requirements, each with a code
reference — 58 PASS, 9 N/A (feature genuinely absent, reason stated), 3 OPERATOR
(deployment-provided), **0 FAIL**. Five were failures when the assessment
started; the most serious was that **no password change existed anywhere in the
product** (V6.2.2), so a user who believed their password was compromised had no
way to rotate it.

L2 (253 cumulative) is deliberately NOT claimed. Much of it is already in place,
but claiming a level without a requirement-by-requirement assessment is precisely
the failure mode this file keeps documenting: an assertion the product makes and
does not perform.

Keep the document honest when changing auth, session, or crypto code — a stale
conformance claim is worse than none.

`docs/detection-accuracy.md` measures the other bar the category advertises — a
false-positive rate under 1%, achieved by *structural validation* rather than
after-the-fact filtering. It audits the findings already in the database against
live ground truth (DNS resolved directly, headers fetched with curl, certificate
read with openssl): of the 11 security findings independently verifiable that
way, 8 confirmed true, 1 indeterminate, and **2 were false positives from one
root cause** — the SPF terminator check did not follow `redirect=`, so a domain
whose provider publishes `~all` was reported as having no policy. Fixed in
`spf-dmarc-deep.ts`.

Two rules that audit produced, both easy to get wrong:
- **A remediated finding is not a false positive.** A certificate-expiry finding
  from 11 Aug was renewed on 27 Aug; grading it against today's state would score
  a correct finding as an error.
- **Eleven findings is a sample, not a rate.** The document says so rather than
  extrapolating a headline number, which is the same discipline the scanner
  itself applies to `unknown`.

## Key Architecture Decisions

### Auth & Workspace Isolation
- Every `/api` route after `app.use("/api", requireAuth)` requires a valid session
- All workspace-scoped resources check `storage.getWorkspaceMember(workspaceId, userId)` — returning 404 (not 403) if the user is not a member, to avoid leaking resource existence
- `POST /workspaces` adds the creating user as "owner" via `storage.addWorkspaceMember()`
- `GET /workspaces` returns only workspaces the user is a member of (superadmins see all)
- Superadmins bypass `requireWorkspaceRole` checks but not `requireAuth`

### SSRF Prevention
- All outbound HTTP to user-controlled URLs goes through `isPrivateHost()` /
  `isSafeOutboundUrl()` in `server/utils/ssrf.ts` (DNS-based, fail-closed)
- Applies to: webhook URLs, Jira baseUrl, sitemap `<loc>` URLs, report evidence
  re-verification
- Scanner has its own SSRF controls in `server/scanner/http.ts`

**There used to be TWO guards and they disagreed.** `isSafeExternalUrl` in
`routes/middleware.ts` — the one actually used on the report re-verification
path — was a hostname STRING blocklist, which misses everything that matters: a
host that merely *resolves* to 127.0.0.1, `127.0.0.2`, the decimal/octal/hex
spellings of a literal (`http://2130706433/` is 127.0.0.1), and every IPv6 form.
That fetch also used `redirect: "follow"`, so a public URL could 302 to
`169.254.169.254`. The string guard is deleted, report-helpers uses
`isSafeOutboundUrl` with `redirect: "manual"`, and the resolving guard now checks
**A and AAAA both** — a public A with a loopback AAAA slipped through whenever
the runtime preferred IPv6.

Rules if you touch it: resolution is the only question that matters (what address
will the socket connect to?); unresolvable is **private**, not allowed; and a
caller that follows redirects must re-check every hop, because a 302 picks a new
address the original check never saw.

### Audit Trail
- `auditMutations` (server/audit.ts) is mounted at `/api` after `requireAuth` and
  records EVERY successful non-GET request — a new route is audited the moment it
  is mounted, without the author remembering to instrument it
- Authentication outcomes are logged explicitly in `routes/auth.ts` (`login`,
  `login_failed`, `logout`, `user_registered`, `mfa_challenge_failed`), because a
  failed login is a 401 that the middleware deliberately ignores
- `logAudit` never throws: a failed audit write must not break the request

**Resolve the path with `req.originalUrl`, synchronously.** `auditMutations` read
`req.path` inside `res.on("finish")`. Express rewrites `req.url` (which `req.path`
derives from) as it descends into a mounted sub-router, and `finish` fires while
that rewrite is still in effect — so the path recorded was relative to whichever
router answered. `app.use("/api/workspaces", workspacesRouter)` is the only
prefixed mount and the only one affected, which is the worst possible one:

| request | recorded as |
|---|---|
| `POST /api/workspaces` | `resource_changed`, path `/`, resourceType NULL |
| `DELETE /api/workspaces/:id` | `<uuid>_deleted` — an invented action name |
| `POST /api/workspaces/:id/assets` | the uuid read as the collection |

That was **501 of ~1200 rows**, and it meant "who deleted this workspace" had no
answer in the audit trail. `req.originalUrl` is the one value Express never
rewrites. The historical rows are deliberately **left as they are** — an audit log
is evidence, and retroactively rewriting it is the one thing it must never do.

`describeMutation` also refuses to name an action after an id-shaped segment
(uuid, numeric, long hex), falling back to `resource_changed`. The audit viewer
facets on `action`, so an unbounded name adds a facet entry per record ever
touched. This does not weaken the positional rule — position still decides which
segments are ids, because a short non-hex id like `/scans/abc` defeats any shape
test; the check applies only to the name about to be published.

Note the trap in how this survived: the `describeMutation` unit tests passed the
FULL path and passed. The pure function was always correct — only the caller was
wrong. A test one level up, where the rewrite is visible, is what catches this.

### Enterprise SSO — OIDC, and why not SAML
`sso-oidc.ts` + `routes/sso.ts`. SAML was the other candidate and was rejected
deliberately: validating a SAML assertion means XML canonicalisation and
XML-DSig, an area with a long history of signature-wrapping bypasses that look
like working code until somebody wraps an assertion. That needs a vetted library,
not hand-rolled code. OIDC is what Entra ID, Okta and Google prefer, its tokens
are JOSE rather than XML, and Node verifies RS256 over a JWK natively.

**Every check in `verifyIdToken` is a named attack, not strictness for its own
sake.** Removing any one is an auth bypass that still compiles:
- **signature** — otherwise anyone mints a token for any user;
- **`alg` allow-list** — closes `alg:none` and HMAC-with-the-public-key;
- **`iss`** — a token from another issuer is a different identity space;
- **`aud`** (+ `azp` when multi-audience) — the subtle one: a token minted for a
  DIFFERENT client of the same IdP is genuine and correctly signed. Without this,
  any other app in the tenant logs in as its users;
- **`exp`/`iat`/`nbf`** — replay of an old token;
- **`nonce`** — replay of a token captured from another session;
- **`state`**, single-use — CSRF on the callback;
- **PKCE S256** — an intercepted authorization code is useless without the verifier.

Account policy: link on **verified email only** — an IdP reporting
`email_verified: false` is saying it does not know the address belongs to that
person, and linking on it is account takeover by profile edit. Absent means
unverified. Auto-provisioning is **opt-in** (`OIDC_AUTO_PROVISION`) and creates
`viewer`; elevation is an administrator's explicit act, never a side effect of
logging in. The session token comes back in the URL **fragment**, which is never
sent to a server, so it stays out of access logs and `Referer`.

Config: `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI`
(all four required or SSO reports itself disabled), plus optional `OIDC_SCOPES`
and `OIDC_AUTO_PROVISION`. The router mounts BEFORE `requireAuth` — a login route
behind the auth gate cannot work.

### SIEM egress — and the one place the SSRF guard deliberately does not apply
`siem-export.ts` hangs off `emitAlert`, the single choke point every security
event already passes through, for the same reason `auditMutations` is mounted
once at `/api`: a new event type is exported the moment it is emitted, without
the author remembering to instrument it. Delivery is **not awaited** — a SIEM
round trip must not sit in the path of storing a finding — and `sendToSiem`
never throws.

Formats are **ECS** (Elastic/OpenSearch) and **CEF** (ArcSight, QRadar, Splunk,
Sentinel), because handing a SIEM bespoke JSON means somebody writes and
maintains a custom parser. Transports: HTTPS collectors, or
`syslog+udp://` / `syslog+tcp://`. CEF escaping is security-relevant, not
cosmetic — a finding title names hosts, cookies and paths, and CEF is
pipe-delimited, so an unescaped `|` fabricates fields that were never sent.

**`SIEM_ENDPOINT` is deliberately NOT passed through `isPrivateHost()`.** Every
other outbound URL is guarded because it came from USER input (a webhook a member
typed, a Jira base URL, a sitemap `<loc>`). This one is OPERATOR configuration
from the deployment environment, and a SIEM is normally on a private network
(`syslog://siem.internal:514`). Guarding it would block the correct
configuration and protect against nothing — an operator who can set environment
variables can already reach whatever the process can. That distinction is why
this is its own module rather than another webhook provider.

### Health Probes
- `/healthz` — liveness; touches no dependency, so a DB outage does not get the
  process killed and restarted (which would not fix the DB)
- `/readyz` — readiness; verifies Postgres and returns 503 when it is down.
  This is what `docker-compose.yml` health-checks. Never point a health check at
  `/`: the SPA returns 200 even when the database is unreachable.

### Pagination — read this before showing a count
List endpoints return `{ data, total, limit, offset }` with a **default page size
of 500**. `getQueryFn` in `queryClient.ts` auto-unwraps that envelope down to the
array, which discards `total`. Rendering `items.length` therefore reports the
PAGE SIZE, not the real count — a workspace with 1067 assets displayed "500".
Use `useListQuery` (client/src/hooks/use-list-query.ts) and render its `total`
whenever a number is shown to the user.

### Finding Aggregation
Per-instance findings must be collapsed per host. A live scan emitted 27 separate
"Insecure Cookie: <name>" findings for one site, which buried every other issue
and inflated the severity counts the posture score is derived from. See
`checkCookieSecurity` in `server/scanner/dast-lite.ts` for the shape: one finding,
severity set by the worst attribute, every instance preserved in `evidence`.

### Scan Concurrency — do not remove this gate
`POST /api/scans` used to call `triggerScan` directly with no global limit, so N
requests for N different targets started N concurrent full scans, each fanning
out hundreds of DNS and HTTP requests. Execution is now gated on
`acquireSlot()` (server/scan-slots.ts), a Postgres **advisory lock** — chosen
because the lock dies with the database session, so a crashed worker frees its
slot with no lease or reconciliation job. A scan row stays `pending` until it
holds a slot; only then does it become `running`.

`SCAN_CONCURRENCY` (default 3) is the limit for the whole deployment, and each
held slot occupies a pooled connection, so size the pool above it.

### Dead Code — check before assuming a feature works
Four features shipped with full implementations that nothing ever called. Each
looked complete in the code and did nothing at runtime:
- `logAudit` — audit_logs had 0 rows
- `enqueueScan` / `startQueuePoller` — no concurrency limit existed at all
- `checkSLABreaches` / `computeDueDate` — 0 of 126 findings had a due date
- `api_keys.scope` — validated, stored, badged in the UI, enforced NOWHERE
- `retention_policies` — configurable per workspace, applied only if a superadmin
  called the admin route by hand, i.e. never (`last_cleanup_at` was NULL for every
  row, and the `retention_purge` audit action had no writer)
- `dispatchWebhookEvent` — endpoint matching, HMAC signing, retries and
  `failCount` tracking, all complete, with **no caller anywhere**. The table, the
  config page and the event checkboxes existed; an operator who ticked "Critical
  Finding" received nothing, ever
- `sla_breached` alerts — the sweep marked findings overdue and wrote an audit
  row and stopped there, so `sla_breach` (offered as a subscribable webhook
  event) could not occur at all

All seven are now wired. Finding these is mechanical: enumerate exported
functions and grep for a reference outside the defining file. That sweep over
`server/` flagged 40 of 530 exports; most were constants or test seams, and these
two were real. **Before trusting any feature here, grep for a caller.**

### API key scope
`api_keys.scope` (read | scan | full) is enforced by `enforceApiKeyScope`
(`server/routes/api-key-scope.ts`), mounted at `/api` right after `requireAuth`
— the same choke-point trick as `auditMutations`, so a route added later is
covered without its author remembering. `requireAuth` puts the key's scope on
`req.apiKeyScope`; session auth leaves it undefined and passes through, because
this narrows keys and is not the authorization model (membership and role checks
still apply on top).

It was previously enforced nowhere. `requireAuth` accepted a `csk_` key and set
`req.user` to the full user record, so a key an operator created as **"read"
could delete workspaces** — and the UI rendered the scope as a badge, meaning the
product asserted a restriction it did not apply. That is worse than having no
scopes: someone hands out a "read-only" key for a dashboard believing it is safe.

Rules if you touch it:
- **Fail closed.** An unrecognised scope gets read-only treatment, never full, so
  a scope value added to the schema later cannot grant more by being unhandled.
- **No API key may manage API keys, at any scope including `full`.** A leaked key
  that can mint another key survives its own revocation. Reads are blocked too —
  enumerating key names and prefixes is the reconnaissance step for that move.
  Key management requires an interactive session (the same stance GitHub takes on
  personal access tokens).
- `scan` writes are a two-entry allowlist (`POST /scans`, `POST /scans/:id/cancel`),
  not a `/scans` prefix match — otherwise `DELETE /scans/:id` would ride along.

### Cases
A finding is an OBSERVATION; a case is the WORK. One piece of work routinely
spans several findings, and one finding can recur across several pieces of work,
so `case_findings` is a join table rather than a column on `findings`.

- References are per-workspace (`CASE-1`, `CASE-2`), derived from that
  workspace's max — a global sequence would leak how many cases other tenants
  have created.
- The deadline uses the SAME `SLA_HOURS` policy as findings, so a case cannot
  promise a slower deadline than the findings inside it. Raising severity
  re-derives from the ORIGINAL creation time, so it tightens the deadline rather
  than granting a fresh window.
- Lifecycle lives in `server/case-workflow.ts` (pure, DB-free, testable).
  `open → resolved` is refused: skipping the middle states leaves no record that
  anyone looked at it. Any active state may go to `closed`; `closed` reopens to
  `open` only, so the work is re-triaged rather than resuming on stale
  conclusions.

### Retention
`startRetentionSweep()` (server/retention-sweep.ts) applies each workspace's
policy daily; `POST /retention/cleanup` is now just a manual trigger for the same
function. Retention is a claim made to auditors and data subjects, so a policy
nothing applies is a false claim rather than a missing nicety.

Three rules that are easy to regress:
- **`archiveEnabled` means DO NOT DELETE.** The flag was ignored, so a workspace
  configured to archive-then-delete got the delete and no archive. Archiving is
  not implemented; skipping is the only safe reading. Those workspaces are counted
  in `skippedArchive` and `last_cleanup_at` is deliberately NOT stamped, so the
  skip stays visible rather than looking like a successful clean.
- **Per-workspace error isolation.** One `try` used to wrap the whole loop, so a
  single failing policy stopped retention for every workspace after it.
- **Count with `rowCount`, never `.returning()`.** The original materialised every
  deleted row just to call `.length` on it — a year of findings, loaded into memory
  inside a background job.

Deletions write a `retention_purge` audit entry (with `userId: null` — there is no
actor), and only when something was actually removed, so the log stays a record of
deletions rather than a daily heartbeat.

**Expired sessions ride on this sweep.** `cleanExpiredSessions` existed with no
caller, and `validateSession` only deletes an expired row when someone PRESENTS
it — so a session nobody returns to persisted forever, carrying `ip_address` and
`user_agent` long past the purpose they were collected for. A live database had
**60 expired rows of 264**. It sits outside the per-workspace loop and its own
`try`, because sessions are global and one workspace's policy failing must not
skip them.

### SLA
`storage.createFinding` sets `priority` and `dueDate` from severity — do this at
the choke point, never per call site. `startSlaMonitor()` sweeps hourly, marks
overdue findings, backfills rows created before the clock existed, and writes an
`sla_breached` audit entry. Deadlines live in `SLA_HOURS` (finding-workflow.ts).

### Anti-Bot Detection
Two layers, both free:
- `server/scanner/browser-profile.ts` — every outbound request sends a COMPLETE,
  internally coherent header set. A Chrome UA with no `sec-ch-ua` or
  `Sec-Fetch-*` is filtered on the first hop. Rotate whole profiles, never
  individual headers: a Firefox UA carrying Chrome client hints is a stronger
  tell than not rotating.
- `server/evidence/browser-stealth.ts` — Playwright launch args plus an init
  script that clears `navigator.webdriver`, restores `window.chrome`, the plugin
  and language arrays, and the WebGL vendor. Measured: 6/6 signals removed.

NOT fixed, and not fixable from Node's `fetch`: the TLS (JA3/JA4) and HTTP/2
fingerprints. Anything behind Cloudflare/DataDome needs curl-impersonate or an
engine-level browser.

**Engine is swappable via `CYSHIELD_BROWSER_ENGINE`** (see browser-engine.ts).
Measured trap: **patchright 1.62.2 accepts `addInitScript` and never runs it**
(it removes `Runtime.enable`), so selecting it silently drops every page-level
patch. `resolveBrowserEngine()` returns `supportsInitScript` — check it before
relying on those patches; the screenshot service warns when they are skipped.
CloakBrowser's binary is separately licensed (v148+ is a paid subscription,
redistribution prohibited), so it can never be baked into the image.

### A 200 is not evidence — the three gates every path finding must pass
**Read this before adding any detector that probes a path.**

`status === 200` was treated as proof that a path exists. It is not. A
single-page app, a framework catch-all route, or any custom 200 error page
answers `/.env`, `/api/v1/pods` and `/metrics` with `index.html`. Container
detection reported **"Kubernetes Pods API Exposed Without Authentication"
(critical)** for a static marketing site on exactly that basis.

The old defence was a fingerprint string, `` `${len}:${first100chars}` ``,
compared with `===`. Exact equality is the wrong test: real error pages embed a
request id, a CSRF token, or the echoed path, so the fingerprint differed on
every request and the guard never fired.

Three gates now stand between a response and a finding. Gate 2 is the
load-bearing one and is never skipped.

1. **`response-oracle.ts` — does this path exist?** `calibrate(origin)` probes
   random paths that cannot exist, in the shapes detectors actually request
   (bare, `.json`, `.php`, trailing-slash), then judges real probes by
   SIMILARITY (normalised-token Jaccard, size fallback for short bodies) rather
   than equality. This is `ffuf`'s auto-calibration. Two samples per shape: a
   host whose own error page is unstable gets that shape DROPPED, because
   similarity to one unstable sample would withhold genuine findings.
   `classifyAgainstBaseline` returns `soft-404 | real | unknown` — **`unknown`
   is never treated as a pass.**
2. **`body-signatures.ts` — is it the thing we are about to name?** A detector
   may not claim "Prometheus metrics endpoint" without a Prometheus exposition,
   or "Kubernetes API" without a Kubernetes document. Predicates look for the
   artefact's required structure, never a keyword that could appear in prose.
   `looksLikeHtml` is the one to reuse: the old check was
   `body.trim().startsWith("<!DOCTYPE")` — **case sensitive**, so every
   framework emitting `<!doctype html>` had its markup scanned for secrets.
3. **`verification-gate.ts` — is it still true?** Already existed, but
   `probeExposedContent` accepted a live 2xx outright when the finding carried
   no content marker, so the gate rubber-stamped precisely the false positives
   it exists to catch. It now calibrates the origin (cached per run) and
   withholds anything indistinguishable from the host's not-found response.

Detectors record what they withheld (`suppressed` / `unconfirmed`) instead of
silently dropping it — "we looked and could not confirm" must stay
distinguishable from "we never looked".

### Credential detection: shape is not an issuer
`credential-detection.ts` (extracted from `osint-helpers.ts`) decides whether a
finding is reported AND whether it is escalated to critical, so its two worst
rules were the largest FP source in the engine:

- A **bare UUID** was listed as a "Heroku/generic API key". Every request id,
  trace id, asset hash and framework key on the web is a UUID, so any HTML page
  counted as carrying credentials — escalating "Exposed Environment File" from
  high to **critical / CVSS 9.8**.
- **Any 20-char token with entropy ≥ 4.5**, anywhere in the document. Minified
  JS, CSP nonces and cache-busting filenames all clear that bar.

Three tiers of evidence now, strongest first: **known key formats** (issuer
prefix + length, no context needed); **named assignments** (`DB_PASSWORD=…`,
with a value that is not a documentation placeholder — `.env.example` files are
full of `API_KEY=your_api_key_here`); and **entropy**, which applies only to the
right-hand side of a secret-shaped key name, or to a lone token a caller already
isolated as a candidate. Never to arbitrary tokens inside a document.

`SECRET_PATTERNS` entries carry `requiresContext` (a shape-only pattern needs
the service named nearby) and `validate` (a JWT is base64-decoded and must carry
an `alg` claim). **Every consumer of the set must honour both** — `code-leak-watch`
ignored them and would have reported any repo file containing a UUID.

### Dead data is the recurring failure here — wire it or delete it
Four features shipped complete and did nothing. Two more were added by the
discovery work and were dead on arrival until caught by grepping for a consumer:
`asnFootprint` and `passiveSourcesFailed` were written to `reconData` and read by
nothing, and `crawlResults` lived on a local object that went out of scope.

`newSinceLastRun` was the worst of the class, because it was not merely unread —
it was hardcoded `false` while the UI rendered a "New Since Last Run" counter and
a per-host **New/Known badge**. The product displayed a change-detection feature
that always said "Known" no matter what appeared.

The rule, extended: **grep for a caller, then check the data it consumes is
shaped the way it expects, then check a reader can actually see it.** A recon
field with no `moduleType` surfacing it is invisible; a `moduleType` with no
entry in `moduleTypeToPanel` and `moduleOrder` (client/src/pages/intelligence/
index.tsx) renders nowhere. Panels mount inside `TabsContent`, so only the ACTIVE
tab exists in the DOM — a test that queries for a panel without clicking its tab
will report it missing when it is fine.

Change detection is now a genuine three-state signal. `ScanOptions.knownHosts`
is `undefined` when the workspace has never completed a scan, which is NOT the
same as an empty baseline: with nothing to compare against, "new" is true of
everything and useless, and "known" asserts nothing changed. The UI shows
"No prior scan to compare" rather than `0`. An *empty* baseline is a real
baseline — the workspace scanned and knew of no hosts — so anything found then
genuinely is new.

### Verification provenance belongs in the report
Every finding carries the gate's re-verification stamp in its evidence, but
`evidenceToText` flattened it into the same blob as everything else, so the
strongest claim the report makes — a live probe reproduced this, at this time —
was the least visible thing on the page. It is now excluded from that blob and
printed under its own **Verification** heading, and an `unverifiable` finding
says so plainly instead of borrowing the word "confirmed".

### Aggregation applies to stored rows too, not just new scans
`checkCookieSecurity` collapsing per-instance findings changed what new scans
produce and could not change what was already stored — a live workspace still
showed 26 separate "Insecure Cookie" rows for one host. `scripts/
backfill-finding-aggregation.mts` folds them: keeps the OLDEST row (so its SLA
clock and case links stay valid), takes the WORST severity, the most-progressed
status, and preserves every instance as evidence plus an audit note recording
the merge. Dry-run by default, idempotent, and it moves `case_findings` links to
the survivor so a case never loses its evidence. Applied: 76 findings → 51.

### Host probing returns a fingerprint, not a liveness bit
Live-host detection issued a HEAD to `https://host` and `http://host` and kept
one bit: did anything answer. So a scan could report ninety live subdomains and
say **nothing about any of them** — the operator opened each by hand to find out
which mattered. `http-probe.ts` replaces it with one GET per host that yields
status, title, server, content length, redirect target, technologies and
WAF/CDN for the same round trip. GET rather than HEAD because many servers
handle HEAD inconsistently (405, or a different status), so it is a worse
liveness signal *and* carries no body to fingerprint from.

`httpx` is used when installed, native otherwise. The JSON shape is validated
before any result is trusted — ProjectDiscovery's `httpx` shares its name with a
Python HTTP client, and the wrong binary on PATH must yield null and fall back,
not nonsense.

Three details worth keeping:
- **`contentLength` is omitted, not guessed, when the body hit `httpGet`'s
  5000-char cap.** Reporting 5000 states a measurement never taken, and would
  make a 4 MB page and a 5 KB page look identical.
- **Hosts that answered nothing are omitted**, not recorded as status 0 — a
  zero-status row puts dead hosts in the live inventory.
- **Cleartext is only a finding when HTTPS also works.** An HTTP-only host is
  described by the `scheme` field; it is not a transport-security failure.

**`killIfRunning()` guards every `child.kill()`** in the katana and httpx
delegations. Killing an already-closed handle trips a libuv assertion on Windows
(`!(handle->flags & UV_HANDLE_CLOSING)`) that aborts the **whole Node process**,
not just the scan — and the `close` handler necessarily runs after the child is
gone. This was hit for real, not theorised.

### The crawler exists so active tests aim at real endpoints
There was no crawler. The engine fetched the main page, the sitemap and an
archive index, and that was its whole picture of the application. It showed in
DAST-lite: the XSS and open-redirect checks probed a hardcoded guess list
(`/?q=`, `/search?query=`, `/login?next=`) because nothing had ever told them
what the application's parameters actually were. **An active check aimed at
endpoints the target does not have will not find the one it does** — probing
`/?q=` on an app whose search parameter is `keyword` tests nothing.

`crawler.ts` builds the endpoint inventory and `scan-trigger` runs it BEFORE
DAST, feeding `parameterised` in as `InjectionTarget[]`. The guess list survives
as the fallback, so a site the crawler cannot reach is never tested less than it
was.

Three properties to preserve:
- **Dedupe by SHAPE, not string.** `endpointShape()` keys on origin + path +
  sorted parameter NAMES, so a catalogue of 10,000 products collapses to one
  endpoint. Without it the crawl never terminates usefully and the active tests
  probe one parameter ten thousand times. This is the most important behaviour
  in the module.
- **Scope is enforced on every URL.** Links point anywhere; following them
  off-domain is both an SSRF surface and traffic on hosts nobody authorised.
  `isInScope` compares against the registrable root, so `example.com.evil.net`
  and `notexample.com` are both refused.
- **The request budget is capped** (`maxPages`, and 15 injection targets). An
  application with 200 parameters would otherwise turn one check into 200
  requests against a live target.

**katana is used when installed**, native crawl otherwise — same scope check and
same shape-dedup on both paths, so results are comparable whichever ran. The
native crawler is the baseline because a self-hosted scanner has to work out of
the box with no Go toolchain present; this mirrors how `nuclei` is optional.

### ASN expansion — the only discovery vector that does not start from a name
Every other method here starts from a NAME: a wordlist entry, a CT record, an
archived URL. All of them are blind to an asset with no DNS record pointing at
it — a forgotten VPN concentrator, a decommissioned relay, a jump host addressed
only by IP. `asn-expansion.ts` finds those from the other end: if the
organisation runs its own AS, the global routing table already publishes every
prefix it is responsible for. This is the substrate Censys ASM and Cortex Xpanse
are built on, and it is free and keyless.

**Attribution is the entire module, and refusal is the default.** Naively
expanding the AS behind a target's IP is catastrophic: a site behind Cloudflare
resolves into AS13335, and expanding it would attribute ten million addresses —
every Cloudflare customer on earth — to one customer, with scanner traffic
attached. Three gates, any of which refuses:
- a known hosting/CDN/cloud/transit AS is never expanded, however the name matches;
- the AS name must contain an org token of **4+ characters** (matching on "bt"
  or "ge" would attribute unrelated networks on a two-letter coincidence);
- an AS announcing carrier-scale IPv4 space is infrastructure regardless of name.

Two things about that size gate, both found by running it for real rather than
by reasoning about it:
- **It counts IPv4 only.** An IPv6 /32 is the standard single-organisation
  allocation and covers 2^96 addresses, so counting IPv6 classified *every*
  IPv6-announcing organisation as a carrier. The first live test against a
  university caught it.
- **The threshold is generous** (a /11). Stanford's AS32 genuinely announces
  ~330,000 IPv4 addresses and is unambiguously its own estate. The provider-name
  list is the primary defence; this is only the backstop for a carrier that list
  does not name.

Routing data comes from **RIPEstat first, BGPView second**. `api.bgpview.io` was
not resolvable at all from the development network while RIPEstat answered fine
— exactly the single-source dependency that turns "this organisation announces
nothing" into a confident wrong answer. Output is `recon`, never a finding:
owning IP space is not a weakness, it is the map you need before looking for one.

### Discovery provenance — which sources agreed, and which never answered
`fetchSubdomainsFromFreeSources` aggregates nine keyless indexes (crt.sh,
Certspotter, HackerTarget, OTX, Anubis, ThreatMiner, urlscan, RapidDNS, and
hostnames mined out of the Wayback CDX index). It used to merge them into one
flat set and keep only a per-source count, which threw away the strongest
quality signal available at zero cost: **whether independent collectors agree.**

It now returns `provenance` (which sources named each host) and
`confidenceFromSources` grades corroboration — 3+ sources `high`, 2 `medium`, 1
`low`. Deliberately conservative, because the property being graded is
independence, not the reputation of any one source. A live run found 78 hosts of
which 54 were single-source: previously indistinguishable from the 4x-corroborated
ones. `recon-builder` carries this onto the asset inventory, where a host we
actually reached over HTTPS is marked `confirmed` — a live handshake outranks
any number of indexes agreeing, because an index can be stale and DNS cannot.

**The collector contract is `string[] | null`.** `null` means the source did not
answer; `[]` means it answered and had nothing. This is load-bearing and was
found by running it for real: `fetchJSON`/`fetchText` return null on *both* an
error and an empty body, so collapsing the two reported a timed-out crt.sh as
**"crtsh: 0 subdomains"** for a domain with hundreds of certificates. Sources
that did not answer go in `sourcesFailed`, never in `bySource`. Same rule as
`code-leak-watch` and `ransomware-watch`: a check that could not run must never
render as a check that found nothing.

### Compliance: an unmapped category renders as "No Data", which reads as a pass
`compliance-mapper.ts` keys its framework mapping on the finding `category`
vocabulary. A category absent from `CATEGORY_MAP` matches no control, so the
control is classed `unknown` and the UI shows **"No Data"** — which a reader
takes as "not assessed" and, in practice, as "probably fine". That is strictly
worse than reporting the failure.

The map had drifted badly from what detectors actually emit. A live workspace
showed **nine of ten OWASP controls as No Data while holding 31 open findings**,
because 27 of them were `cookie_security` and no such key existed. Meanwhile
four keys that WERE present (`open_port`, `s3_exposure`, `nuclei_finding`,
`exposed_document`) named categories no detector has ever produced, so they
matched nothing. Net effect: 2 of 31 findings reached any control; now all 31
do, and CIS/NIST went from 0 assessed controls to 3 each.

`SECURITY_CATEGORIES` in `finding-taxonomy.ts` is now the single source of truth
for the vocabulary — it unions the Nuclei routing categories with
`DETECTOR_CATEGORIES`, the ones native modules set as literals.
`compliance-coverage.test.ts` asserts every one of them is mapped AND that each
mapping names control ids that exist, so this drift is a build failure rather
than a blank cell. `unclassified` is deliberately excluded: it means the
taxonomy itself has a gap, and inventing a control for it would hide that.

Remaining "No Data" on OWASP A03/A06/A08/A09/A10 for a typical external scan is
honest, not a bug — an external scanner cannot assess logging failures (A09) and
will only assess injection (A03) when DAST actually finds one.

### The Asset Risk page scored 0.0 for every asset in the product

`per-asset-findings.ts` fixed attribution, and the note below says "the scoring
engine was correct; nothing it consumed was attributable". **The second half was
true and the first half was not**, and nobody re-measured after the attribution
fix landed. Driving `calculateAssetRisk` over the live database: **2,633 assets
across six workspaces, 163 open findings, and every single asset scored 0.0** —
rendered in green, with a green progress bar, by `scoreColor`. Five separate
defects, each sufficient on its own:

- **Both category-driven factors named categories no detector emits.** The sets
  were hyphenated (`open-port`, `exposed-service`, `tls`, `missing-hsts`) while
  every detector emits snake_case (`network_exposure`, `exposed_service`,
  `ssl_issue`, `transport_security`). `computeExposureFactor` and
  `computeTlsFactor` matched **nothing, ever** — 35% of the weight structurally
  dead. This is the same drift `compliance-mapper.ts` had with `open_port` and
  `s3_exposure`, in a module that had no coverage guard.
- **Medium and low findings fed no factor at all.** Only critical and high were
  scored, and the entire live database is medium/low/info — so the two factors
  that did work were unreachable too.
- **One open CRITICAL scored 8/100.** `20 x 0.4` on a weighted average of
  rarely-saturating factors. The most serious finding the product can report
  rendered green.
- **No `kind` filter** — the seventh place this rule was open-coded and missed.
  On one workspace it meant 10 of 14 rows scored, including eight
  "Apache Detection" recon rows and a working DNSSEC control.
- **No status filter**, so remediating a finding never moved the number.

Fixed: real taxonomy names, a `Medium & Low Findings` factor continuing the
product's own severity ladder (`SEVERITY_DEDUCTION`: 20/10/5/2 — not a second
ladder that could disagree), and severity **bands** mirroring
`computeSecurityScore`'s floors and ceilings inverted, so severity dominates
volume while the factors still position the score inside its band and continue
to explain it.

**`trend` was a fabricated verdict.** Measured live: `degrading` for 100% of
assets holding any finding and `stable` for 100% without — it was a restatement
of `findingCount > 0`, rendered as a red rising arrow claiming risk was
INCREASING OVER TIME. There is no score history in this product at all;
`getAssetRiskHistory` says so in its own comment. `open > resolved * 2` is true
of any open finding when nothing has been closed. It is `unknown` now ("No
history" in the UI) unless remediation has actually happened, and
`determineTrend` is fed findings of every status because a closed row is the
only evidence it has — filtering to open ones first made `improving`
unreachable.

Two more things the page asserted without evidence, both now fixed:
`findingCount` is reported per asset so a 0 from *nothing found* is not rendered
identically to a 0 from low-scoring findings; and the "Average Score" headline
divided by the whole estate (654 of 743 Bigbasket assets have no findings), so
it collapsed towards zero no matter what the findings said. It now averages over
scored assets and prints the denominator.

**Every unit test passed throughout — all 60 of them.** They fed the factors the
same invented vocabulary the factors expected: a closed loop of two wrong things
agreeing, in a file that never touched the real taxonomy. Two guards now:
`asset-risk-scoring.test.ts` checks both category sets against
`SECURITY_CATEGORIES` and that the weights sum to 1, and
`reconcile-real-data.mjs` asserts that a workspace holding an open medium-or-
worse finding cannot render its whole estate below 40. The second one matters
more — a single `some(score > 0)` check passed on live data even with the bug
present, because one unrelated TLS finding satisfied it. Both were verified by
reintroducing the real bug; the reconciler named five of six workspaces and
exited 1.

### The AI insights panel said "N security findings" and counted everything

`buildFallbackInsights` writes *"Workspace X has N security findings"* — those
words, to the operator — and it was handed every row in the workspace. A live
workspace read **"has 14 security findings"** while its inbox showed 4: eight
"… - Detect" recon rows and two controls that are WORKING, presented as
outstanding work. Closed rows counted too. That is the **eighth** place the
`kind` rule was open-coded and missed.

It is not a rare path. Ollama is unreachable in most deployments of this repo,
so the fallback IS the live behaviour — and the same unfiltered set becomes the
LLM's prompt context (the top 10 by severity), so on a workspace whose findings
are all info-severity the model was being asked to write a security summary of
a technology list.

Filtered at all three call sites in `routes/findings.ts` via `insightFindings`.
Verified live: 14 → 4 and 98 → 98, matching the inbox exactly.

**The GET route was behind the AI rate limiter and runs no AI.**
`app.use("/api/workspaces/:id/ai-insights", aiRateLimit)` mounts by PREFIX, so
`GET /ai-insights` — which reads findings and recon modules out of Postgres and
returns them — shared a **3/min** budget with a 30-minute Ollama call. An
operator flipping between four workspaces in a minute got *"Too many AI
requests"* for requests that used no AI, and the message sent them to debug the
wrong thing. Now mounted on `/ai-insights/summary`, the only route here that
calls a model.

**A gate that turns "could not check" into "checked and wrong" is the same bug.**
The first version of the reconciler check read `insights?.findings ?? []` and
compared the length — so a 429 (`{ message: … }`) became "0 findings" and was
reported as a real disagreement on five of six workspaces. It now requires the
expected shape and reports `NOT CHECKED` otherwise. A false alarm is not the
safe direction either: it trains whoever reads the output to disbelieve it.

**Asset risk scores a HOST once.** The `assets` unique constraint is
(workspaceId, **type**, value), so an apex stored once as `domain` and again as
`subdomain` is two rows for one host — and the page keys on hostname, so it
rendered the same host twice with an identical score and counted it twice in
the estate average and the critical-risk tile. Live data: 4 such rows across
2,633. `type` is discovery provenance; a host's identity is its name.

**Checked and found correct, recorded so it is not re-derived:**
- `computeSecurityScore` filters status AND kind internally, so the posture
  backfill and continuous monitoring are safe without their own filter.
- `securityScore: allFindings.length > 0 ? … : null` guards on the UNFILTERED
  length, which looks wrong and is not: recon rows are evidence a scan ran, so
  a workspace holding only recon scores 100 = "we looked, found nothing", which
  is the documented `clean` state rather than a free pass.
- `cases.ts` selects findings by explicit `findingIds` with no `kind` filter —
  correct, and deliberately so, for the same reason an explicit `findingIds`
  selection is honoured verbatim in `selectReportFindings`.

### Attribute a finding to the host it was observed on
`affectedAsset` is what joins a finding to the asset inventory, and
`asset-risk-scoring.ts` matches by hostname. A finding attributed to the scan
target instead of the specific host is therefore not just imprecise — it is
unjoinable, and every feature downstream of the inventory silently returns zero.

A Gold scan already fetches each live subdomain's certificate, grades its
security headers and records its server banner. All of that landed in
`reconData.perAssetTls` / `perAssetHeaders` / `perAssetLeaks` **and stopped
there** — no finding was ever produced from it, so the only header/TLS/
disclosure findings a scan emitted were for the apex. Measured on a real
workspace: 90 live subdomains analysed, 263 assets in inventory, all 31 findings
attributed to the apex, and the Asset Risk page reporting **0.0 for 262 of 263
assets**. The scoring engine was correct; nothing it consumed was attributable.

`per-asset-findings.ts` closes this. The shape to copy when adding a detector
that observes many hosts:
- **One finding per host per category**, that host's individual issues kept as
  structured evidence. One finding per (host, header) would be 90 x 6 rows for a
  single misconfiguration — the mistake `checkCookieSecurity` exists to avoid.
- **Never a single roll-up listing every affected host.** It reads well and
  re-creates the bug: it cannot be scored against an asset, assigned an owner,
  or tracked to closure per host.
- `finding-dedup.ts` clusters the per-host findings into one group for the
  inbox, and `computeSecurityScore`'s `sqrt(n)` damping keeps 90 instances of
  one misconfiguration from scoring like 90 independent problems (90 mediums
  land on the medium floor of 55, not 0).
- A `PER_CATEGORY_CAP` guards a large estate: past the cap the remainder becomes
  one `recon` overflow finding rather than thousands of rows.

### Severity must match what an attacker can actually do
Four inflations, each of which trained a reader to skim past the inbox:

- **A dangling CNAME is not a takeover.** It is only takeoverable if the target
  is claimable: a known multi-tenant service, or a registrable domain with no NS
  records. A broken record pointing into a zone somebody else still controls is
  `dns_misconfiguration` at low, not `subdomain_takeover` at critical.
  `TakeoverResult.takeoverable` carries the distinction.
- **A health endpoint is not a vulnerability.** `/health`, `/healthz`, `/ready`,
  `/status`, `/info`, `/metrics` are *supposed* to answer a load balancer
  unauthenticated. They were pooled with `/actuator/heapdump` into one high
  finding. They are now `recon`; only endpoints that disclose configuration,
  memory, or wiring produce a security finding.
- **A 401/403 is the access control working.** Rated `medium`, so every
  protected admin path a scan touched became a medium-severity exposure and the
  count scaled with the wordlist. Now `info`.
- **A guessed bucket name is not the customer's asset.** Every provider answers
  403 for a bucket that exists anywhere in the world, so `<domain>-dev` almost
  certainly "exists" — in a stranger's account. Only an exact-name match may be
  attributed; a listable guessed variant is reported at medium with the
  ownership caveat stated. A 200 must also return the provider's own listing
  root (`looksLikeBucketListing`) before we call the bucket public.

Also: **PATCH is not a dangerous HTTP method** — it is the ordinary
partial-update verb of every REST API, and counting it reported every correctly
built API. TRACE is confirmed by issuing one and requiring the echo; PUT/DELETE
are never exercised against a target, so their finding says "advertised", not
"processed". CORS is probed with an actual attacker `Origin` header, because a
reflected-origin misconfiguration is invisible to a request that sends none.
GraphQL introspection is tested with a real introspection query rather than
asserted from the endpoint existing.

### Three states, not two
Several checks can fail to run, and that is NOT the same as passing or failing.
Each of these keeps the third state explicitly, because collapsing it produces a
confident wrong answer:
- `dnssec.ts` — `unverifiable` (both DoH resolvers failed) vs `unsigned`
- `tls-protocols.ts` — `indeterminate` (OUR OpenSSL would not offer TLS 1.0, or
  the host was unreachable) vs the server refusing. Without
  `ciphers: "DEFAULT@SECLEVEL=0"` every host on the internet looks like it
  safely refuses TLS 1.0.
- `spf-dmarc-deep.ts` — the external-reporter check is SKIPPED without a
  resolver rather than assumed to fail
- The UI mirrors this: `StatusIcon` has an `unknown` state, and `GradeBadge`
  renders "N/A" neutral rather than red.

### Never report "clean" for a check that did not run
`code-leak-watch` needs `GITHUB_TOKEN` (free, no scopes) because GitHub's code
search API has no unauthenticated form. Without it the module returns an
`error`, the API answers 503, and the UI says "Not configured — this check has
not run". It must never return an empty result set, because "no leaks found" and
"we never looked" would then render identically. The same rule applies to
`ransomware-watch` on a feed outage.

Secrets found in repositories are masked with `maskSecret()` before storage —
NOT `redactCredentialValues()`, which only rewrites `name=value` shapes and let a
bare AWS key through verbatim into what would have been a stored finding and an
exported report.

### Discovery was IPv4-only — AAAA was never asked for
`resolveDNS` backs every discovery path (wordlist bruteforce, permutation,
certificate-SAN validation) and queried **A and CNAME only**. A host published
solely on IPv6 resolved to nothing and was discarded as non-existent, so an
entire class of asset was invisible — increasingly ordinary ones: cloud load
balancers, modern ingress, v6-only estates.

The inconsistency was already visible in this repo: `isPrivateHost` checks A
**and** AAAA precisely because ignoring AAAA there was a security hole, while
discovery ignored it and silently lost assets. Verified against real hosts —
`ipv6.test-ipv6.com`, `v6.ipv6-test.com` and `ipv6.lookup.test-ipv6.com` publish
AAAA with no A and no CNAME, and were found by nothing.

Two things to preserve:
- **`resolved` is computed inside `resolveDNS`, not by callers.** Six call sites
  open-coded `ips.length === 0 && cnames.length === 0`, which is exactly how IPv6
  came to be missed — and how a caller added later would inherit the old meaning
  of "live" for free. All three queries run concurrently, so AAAA costs one more
  query and no extra latency.
- **`checkDNSWildcard` covers AAAA too.** Once IPv6-only hosts count as live, an
  IPv4-only wildcard check becomes a hole in the other direction: a zone whose
  wildcard answers AAAA would have every generated permutation "resolve" and pass
  the filter. The filter also requires no CNAME before rejecting, so a host with
  a unique CNAME is never mistaken for the wildcard.

A trap this surfaced: `takeover.test.ts` built bare `{ ips, cnames }` fixtures, so
the new computed flag came back `undefined` (falsy) and a "CNAME target still
resolves" case reported a takeover. Mock fixtures now go through a builder that
computes `resolved` the way production does.

### A CSP that EXISTS is not a CSP that protects
The check was `!!headers.get("content-security-policy")`, so a site publishing
`script-src * 'unsafe-inline' 'unsafe-eval'` passed as configured. Presence was
standing in for protection — the same "a 200 is not evidence" mistake in a
different place. `csp-analysis.ts` assesses the policy's content and reports it
separately from a missing header, because the fix differs.

**Three nuances decide whether this is useful or noise.** Naive CSP checkers get
all three wrong, and each fires on a *correctly* configured modern policy:
- **`'unsafe-inline'` is IGNORED when a nonce or hash is present.** CSP2 browsers
  drop it, and including it is the documented CSP1 fallback. Flagging it there
  punishes the recommended configuration.
- **`'strict-dynamic'` makes host allowlists ignored.** A `*` beside it is not a
  hole — browsers that understand the keyword trust only nonced scripts.
- **Report-Only enforces NOTHING.** It is worse than no header, because it looks
  like a control is in place.

`base-uri` is checked because without it an injected `<base>` tag repoints every
relative script URL and defeats an otherwise correct nonce policy — the directive
most often missing from policies that look strong.

Validated against production policies rather than only fixtures: **github.com and
developer.mozilla.org → no weaknesses** (strict and nonce-based respectively),
**www.google.com → report-only + `unsafe-eval`**, which is accurate. Zero false
positives on the well-configured pair is the result that matters; a checker that
punishes the right answer trains people to ignore it.

### Favicon hashing — and why JARM is deliberately absent
`favicon.ts` computes the Shodan-compatible `http.favicon.hash`. The famous use
of it (pivoting in Shodan/FOFA to find every host serving the same icon) needs an
API key, so that is NOT what this does. Two things it does keyless:
- **Groups the estate.** Ninety subdomains are rarely ninety applications. Hosts
  sharing an icon are almost always the same app behind different names, and the
  host whose icon matches nothing else is the one worth opening first. Verified:
  `github.com`/`www.github.com` cluster, `wikipedia.org`/`en.wikipedia.org`
  cluster, and the two organisations stay separate.
- **Hands the operator a pivot.** The hash is emitted so someone with a Shodan
  account can search `http.favicon.hash:<n>` themselves. Withholding the cheap
  half of a technique because we cannot do the expensive half is not a decision
  worth defending.

**No product is ever named from a hash.** Public hash-to-product tables exist;
asserting "this is a Jenkins instance" from an unverified table is exactly the
claim the body-signature gates exist to prevent.

Two implementation details, either of which silently produces a number that
matches **nothing anywhere** — this hash is not approximately useful:
- **Shodan hashes the base64, not the bytes** — and specifically Python's
  `base64.encodebytes`: 76-character lines with a trailing newline.
- **`Math.imul` is required** for the 32-bit multiplies. Plain `*` overflows into
  a float and drops the low bits, which is the classic way this is written wrong
  in JavaScript. Pinned against published MurmurHash3 vectors (`""`→0,
  `"a"`→1009084850, `"abc"`→3017643002, `"hello"`→613153351), not against
  whatever the implementation happened to emit.

`httpGetBuffer` exists for this: `httpGet` decodes to a string and truncates at
5,000 chars, and an icon round-tripped through UTF-8 decoding is no longer the
bytes the server sent.

**JARM was assessed and rejected.** Its ten probes depend on exact TLS extension
ordering and GREASE values; Node's `tls.connect` exposes `ciphers`, versions,
ALPN and sigalgs but cannot craft the ClientHello that precisely. A
"JARM-like" hash computed anyway would not match the published JARM corpus — and
comparability with that corpus is the entire point of JARM, so a non-matching
value is worse than none. Building it would need a hand-rolled ClientHello over a
raw socket; the clustering value it would add is already served by favicon
grouping, tech fingerprints and certificate issuer, at a fraction of the risk.

### Keyed discovery sources, and the two bugs they exposed
`passive-sources.ts` gained three keyed collectors — **Chaos**, **SecurityTrails**
and **BeVigil** — alongside the nine keyless ones, and `certspotter` now sends a
key when one is set (the endpoint works without one; a key only raises the rate
limit). Keyed collectors join the list ONLY when their key is configured: an
unconfigured source must not appear in `sourcesFailed`, because "the operator has
no key" and "this source did not answer" are different facts and only the second
says anything about the target.

Two shape traps: **Chaos and SecurityTrails return bare LABELS, not FQDNs**
(`["www","api"]`), so each is joined to the domain — emitting them raw would put
`www` into the inventory as a hostname. BeVigil returns full hostnames, and is
worth having precisely because its input is unlike the others': an endpoint
hardcoded in an APK has often never appeared in a certificate, wordlist or crawl.

**Measured: aggregated discovery for one target went from ~169 hosts to 48,063**
(Chaos alone contributed 47,691, of which 45,843 were found by no other source;
BeVigil contributed 8 nobody else had). That ~284× change broke two things
written when "all discovered hosts" meant a few hundred:
- **`GOLD_PROBE_BATCH` was `0`, meaning no cap.** Probing 48k hosts means 48k DNS
  plus 48k HTTP plus per-asset TLS and headers. It is now a finite 5,000 and
  truncation is RECORDED in `probeCoverage`, so a reader can tell a small estate
  from a truncated look at a large one — the same reason the crawler records
  `truncated`.
- **Dedup used `Array.includes` inside a loop.** O(n²): 48k hosts against 15k
  permutation candidates is ~10⁸ comparisons. Now a `Set`.

`fetchJSON` takes an optional `headers` argument for keyed sources. Its contract
is unchanged and still load-bearing: **null means "did not answer", not
"answered with nothing"**.

### A wrong query parameter photographed an empty product
`scripts/capture-ui.mjs` picks the workspace with the most findings so the
screenshots show a populated product. It asked `/findings?limit=1` and read
`total`. That endpoint pages with **`page`/`pageSize`**, not `limit`/`offset`, so
the request came back UNPAGED — a bare array with no `total` — the count read as
0 for every workspace, and all 19 screens were captured against an empty
workspace. Use `?pageSize=1`. Worth knowing generally: this codebase has two
pagination conventions, and the findings inbox uses the page/pageSize one.

### Third-party API calls go through `stealthFetch`, not bare `fetch`
Every keyless source here reaches the network through `fetchJSON`/`stealthFetch`
— crt.sh, RIPEstat, OTX, the ransomware feed. Three newer modules (OSV, the npm
and PyPI registries, the App Store) were calling `fetch` directly, which works
but spends sockets the **deployment-wide semaphore does not count**. CLAUDE.md is
explicit that "sockets are a property of the deployment, not of a scan", and a
module outside that accounting is how `SCANNER_MAX_OUTBOUND` silently stops
meaning what it says. All three now use `stealthFetch`, which spreads `init` so a
POST with a JSON body passes through unchanged, and falls back to a passthrough
controller when called outside a scan (the on-demand app-store route).

### QA: verify the verifier before calling something a false positive
A pipeline QA run against `example.com` produced three findings, one of which was
"accepts obsolete TLS 1.0/1.1". Checking it with a plain
`openssl s_client -tls1` said the server REFUSED — which looked like a false
positive in the scanner.

It was a false positive in the CHECK. OpenSSL 3.x will not *offer* TLS 1.0
without `DEFAULT@SECLEVEL=0`, so the naive command makes every host on the
internet look safe — exactly what `tls-protocols.ts` already documents and
already handles. Re-run with `SECLEVEL=0`, the server accepts TLS 1.0 and 1.1 and
the finding is correct.

All three findings verified true; nothing was withheld wrongly. The lesson is the
one worth keeping: when a scanner finding disagrees with a quick manual check,
the quick check is the more likely thing to be wrong, and the scanner's own
documented workaround is usually the reason.

### The Tor transport: `fetch` cannot use a SOCKS agent
`tor-fetch.ts` routes .onion requests through a local SOCKS5 proxy. It first
passed the `SocksProxyAgent` to `fetch` as `dispatcher`, which **cannot work**:
that agent is a Node `http.Agent`, while undici's `dispatcher` option requires an
undici `Dispatcher`. `fetch` throws `TypeError: agent.dispatch is not a function`
before a byte leaves the process.

Both `torFetch` and `isTorAvailable` caught that and returned `null` / `false` —
**indistinguishable from "the Tor daemon is not running"**. So the whole feature
reported "Tor unavailable" on every run even with Tor healthy, and the message
sent the operator off to debug their Tor setup instead.

The unit tests passed throughout, because they stubbed `globalThis.fetch` — the
mock replaced the one call that was broken. That is the trap worth remembering:
**a test that mocks the layer you are unsure about proves nothing about it.**

Fixed by using `node:http` / `node:https`, which is what `socks-proxy-agent` is
built for, so no new dependency. Verified empirically rather than by reasoning:
`fetch` + agent throws the TypeError above, while `http.request` + the same agent
dials 127.0.0.1:9050 and logs ECONNREFUSED when Tor is down — the proxy actually
being used. `tor-fetch.test.ts` now mocks `node:http` and asserts the agent is an
`http.Agent`, so a regression to a transport that cannot dial the proxy fails
there rather than in production.

Two more fixed alongside it:
- **The body cap ran after buffering.** `res.text()` then `slice(0, 500_000)`
  cannot prevent the memory exhaustion its own comment described — by the time
  you can slice the string the whole body is resident. A hostile .onion serving
  an endless response would exhaust the process first. The cap now applies while
  streaming and destroys the stream when reached.
- **`isTorAvailable` leaked its timeout** on the error path (no `finally`).

### Driving an Express route directly in a test needs two things
`dark-web-route.test.ts` called the route layer's `handle` and asserted on a mock
response. Every assertion compared against an untouched `null`, and one test
"passed" purely because `null === null`:
- **`req.method` is required.** Express 5's `Route.dispatch` selects handlers by
  it, so a request without one matches no layer and goes straight to `next()` —
  neither guard nor handler runs.
- **`dispatch` returns synchronously** while an `async` guard yields, so
  `await handler(...)` resolves before the handler has run. The test has to wait
  for the *response* to settle, not for the dispatch call.

Guards that query `db` directly (`requireWorkspaceRole`) also need either a
membership row in the `db` mock or the documented `superadmin` bypass. Because
these unit tests take that bypass, the membership behaviour is verified against
the live API instead — a non-member gets **404 on all three dark-web routes**,
never 403, so workspace existence is not disclosed.

### CERT-In and DPDP: the mapping that answers a different question
`compliance-mapper.ts` carries five frameworks now. The two Indian ones are not
more of the same, and the difference is the point.

**CERT-In Directions 2022** oblige every Indian body corporate — regardless of
size — to report a listed incident **within six hours of noticing it**, and the
Annexure I list explicitly includes *"targeted scanning"* and *"probing of
critical networks"*. So the controls here are not hardening items like CIS; they
are the ten reportable incident types, and the mapping answers a question OWASP
cannot: *if this exposure were exploited, which reporting duty would it trigger?*
The UI therefore reports "incident types implicated", not a pass rate — a pass
rate would be the wrong shape for that obligation.

Six hours is a **detection** deadline, not a paperwork one. That is the whole
commercial argument for continuous external monitoring in India, and it is why
this framework was worth adding.

**DPDP Act 2023** is mostly NOT externally assessable, and saying so is the
feature. Only the s.8(4) technical safeguards and the detection half of s.8(5)
are visible from outside; consent, grievance redressal, retention and the
Significant Data Fiduciary duties are process obligations. `ComplianceControl`
gained `externallyAssessable`, and those four are marked `false` so they render
as "not externally assessable" rather than "No Data" — which this file already
documents as reading like a pass. Shipping DPDP as certifiable from a surface
scan would be exactly the overclaim `compliance-guidance.ts` stays unwired to
avoid.

A trap this surfaced, in my own test rather than the code: the fixture builder
took an `over` argument and never spread it, so every fixture was silently
`security_headers` and four assertions failed against correct code. The live API
had already proved the mapping right on real findings.

### Architecture diagrams are HTML, rendered by Playwright
`scripts/render-architecture.mjs` writes the current and target architecture as
HTML and screenshots them at 2x, the same way the UI figures are captured from
the running app. The reason is maintenance: the source is text in the
repository, so a wrong arrow is a diff rather than a redraw, and nobody has to
find the person who owns the diagram tool.

### Derive CVSS at the choke point, like priority and the SLA clock
A real report showed **"CVSS: -" on both MEDIUM findings while the LOW and INFO
ones showed 3.5 and 2.0** — so the most serious items on the page looked the
least assessed, which is the opposite of what a reader should conclude. The
cause was detectors that simply never set `cvssScore`, leaving the column NULL.

`storage.createFinding` now derives it from severity when absent, beside
`computePriority` and `computeDueDate` and for the same reason: a detector added
later inherits it without its author remembering. A detector that can say
something more precise still sets `cvssScore` itself and that value wins.

`computeCvssScore` returns band midpoints, not a vector computed for the
deployment — and the test asserts the bands are strictly ordered, so severity
and score can never disagree in a client's report.

### Aggregated findings carry duplicated verification stamps
The Bigbasket cookie finding has **53 evidence entries, 26 of them byte-identical
verification stamps**. The gate is not at fault: `annotate` adds exactly one per
finding. They accumulated when the aggregation backfill merged 26 separate
cookie findings, each already stamped.

The stored evidence is deliberately left alone — it is the record of what was
observed. `report-docx-input.ts` already renders it correctly, because
`evidenceToText` excludes verification items and `verificationOf` takes one; the
exported report shows a single Verification line. Worth knowing before anyone
"fixes" the stored rows: the noise is in the record, not in what the client sees.

### Half the workspaces have no `domain` — the fallback is a NAME
Routes derive their target as `workspace.domain ?? workspace.name`. In a live
database **3 of 6 workspaces have no domain set**, so that fallback runs often.
Sometimes the name happens to be a domain (`mydesk.theranym.com`) and sometimes
it is a label (`Bigbaskt`) — and the difference is invisible to the module.

Asking a breach catalogue about "bigbaskt" returns nothing, and reporting that
as "no breaches found" hands the reader reassurance that was never established.
`isUsableDomain` now refuses a label, and the two unavailable reasons are kept
apart because they need different fixes: `no-domain` is the operator's
configuration (route answers **400** with what to set), `corpus-unreachable` is
somebody else's service being down (**503**). Telling a reader the wrong one
sends them to debug the wrong thing.

Found by driving the real Bigbasket workspace rather than a fixture — a check
against a seeded domain would never have surfaced it.

### Client-side `toLocaleDateString()` is CORRECT — do not "fix" it
There are 45 of them in `client/src`, and they look exactly like the server-side
bug fixed in `utils/format.ts`. They are not the same thing. In a browser the
locale belongs to the **reader**, so each person sees a format they can read. On
a server it belongs to whichever machine happened to run the job, and the report
goes to someone else — which is why only the server side was pinned.

### Breach-corpus exposure — the part of "dark web" that is clearnet
"Dark web monitoring" covers several different things. `breach-exposure.ts` does
the half reachable with no Tor and no credential handling: it asks the public
breach catalogue whether the scanned organisation appears in it **as the
breached party**.

**HIBP's breach METADATA endpoint is keyless** — only its account search needs a
paid key. `/api/v3/breaches?Domain=` answers "was this organisation breached,
when, how many records, what data classes", and no password, hash or email
address is sent or received. This was previously listed as credential-blocked;
only half of it actually is.

**The distinction that must not be blurred**, because conflating them is a
serious overclaim:
- **Answered:** "acme.com appears in N public breach records as the org breached."
- **NOT answered:** "these 400 @acme.com accounts appear in third-party
  breaches." That is HIBP's domain search — paid, *and* requiring proof of domain
  ownership, deliberately, because it enumerates individuals. The finding states
  this rather than letting a clean result read as the broader assurance.

**The corpus is not uniformly trustworthy and says so per record.** Reporting
every hit at equal weight would manufacture alarm:
- `IsFabricated` — the maintainer believes the breach is INVENTED. These are
  excluded from findings entirely and only counted, because repeating a hoax back
  to a customer as fact is worse than reporting nothing.
- `IsVerified: false` — reported, but as a lead to corroborate, never above `low`.
- `IsStealerLog` — infostealer output, so the remediation is endpoint cleanup,
  not an application fix. Labelled rather than folded in with server-side breaches.

Severity turns on credential exposure: an email-only breach is a phishing input,
a password breach is a credential-stuffing input against every other service the
same people use. And the description says plainly that these are historical
incidents, **not evidence of a current compromise**.

### Never format dates or numbers with the server's locale
`toLocaleString()` with no locale formats per the **server's** locale. In a
browser that is right — the locale belongs to the reader. On a server it is
wrong: the output is a report read by someone else, and the same report renders
differently depending on which machine produced it.

Measured on this machine: 152,445,165 rendered as `15,24,45,165`, and worse, a
date rendered `9/2/2026` where a US reader reads `2/9/2026` — **the same instant,
two different days, with no way for the reader to tell which was meant**. In a
report where dates carry the remediation clock that is not cosmetic.

`server/utils/format.ts` pins all three: `formatReportDate` spells the month and
states UTC (`9 Feb 2026, 16:00 UTC`) so day/month order cannot be confused,
`formatReportDateOnly` for tables, `formatCount` for grouping. All ten
locale-dependent sites — CSV export, PDF export, ASN sizing, OSINT breach counts
— now use them.

### Rogue app detection — brand abuse reaches users off-domain
"Rogue app detection" is a headline module in every digital-risk product
(CloudSEK XVigil's Brand Monitor names it) and this engine had none:
`typosquat.ts` watches lookalike DOMAINS, and nothing looked at app stores. A
fake banking app published under a company's name is the same class of abuse as a
lookalike login page, reaching users through a channel no domain check can see.

`mobile-app-monitor.ts` searches Apple's public, keyless Search API.

**Only `sellerUrl` confers ownership.** A live run against `stripe.com` initially
reported *FacilePay: Stripe Payments*, published by **vBridge Technologies Inc.**,
as an official Stripe app — because its bundle identifier is
`com.stripe.credit.card.payment`. **Bundle identifiers are self-declared and Apple
does not verify them against domain ownership.** That check would have adopted a
stranger's software into the customer's inventory. A brand-matching identifier is
now recorded as `brandInBundleId` (and sorted FIRST, since a third party putting
your name in their identifier is stronger brand usage than one merely saying it)
but never as ownership. The asymmetry is deliberate: under-attributing costs a
reviewer one glance, over-attributing silently adopts someone else's software —
the same stance as the bucket-ownership rule in `cloud-discovery`.

**It never says "fake".** Payment integrations, resellers and partner clients
legitimately carry another company's brand — "Payment for Stripe" by PocketVendor
is a real integration. The claim stays narrow: *this app uses your name and is
published by someone who is not you; confirm it is authorised.*

**Android is stated as not covered.** Google Play has no free official search API
and scraping it is fragile and against its terms, so `storesNotChecked` carries
the reason — a reader must be able to tell "not checked" from "nothing there".

Search-relevance noise is dropped: querying "stripe" returns Square's
point-of-sale app, and reporting that as brand usage would bury the signal. Brand
tokens shorter than 4 characters are refused for the reason `asn-expansion` gives.

`brand_threat` was added to `DETECTOR_CATEGORIES` and mapped with an **empty
OWASP column on purpose** — the Top 10 describes flaws in YOUR application, and
an attacker registering your brand elsewhere is not one. Inventing a control to
fill the column would be a manufactured pass.

### The dead-export sweep, and what it is for
`grep` for an exported symbol with no reference outside its defining file. Over
`server/` that is 529 exports; 11 remain unused and every one is now accounted
for — either a deliberate decision recorded below, a `stopX` shutdown pair, or a
test seam. Re-run it after adding a feature: this codebase's single most common
defect is a complete implementation with no caller, and the sweep finds that
class mechanically instead of by noticing.

It also finds quieter things. Two from the last pass:
- **`stopRetentionSweep` was not called on shutdown** while its four siblings
  were, so the daily interval held the event loop open past SIGTERM.
- **`.git/HEAD` had its check duplicated inline** in `secret-scanner.ts` while
  the shared `looksLikeGitHead` sat unused — and the inline copy was *weaker*,
  matching `ref: refs/` anywhere on any line, so a large HTML page containing
  that text passed. Two implementations of one check is a drift risk in which the
  one that gets fixed is not necessarily the one that runs.

### `workflowState` on findings is vestigial — use `status` and cases
`WORKFLOW_TRANSITIONS` and `isValidTransition` (finding-workflow.ts) define a
five-state finding lifecycle, and **no route can reach it**: `updateFindingSchema`
accepts only `status` and `assignee`, so `workflowState` is written once at
creation and never advanced. It is not unvalidated — it is unreachable.

That is arguably correct rather than broken: "a finding is an OBSERVATION; a case
is the WORK", and the case lifecycle in `case-workflow.ts` is the one that is
enforced and used. Triage state belongs to the case. `sla-monitor` reads
`workflowState` for terminal states but falls through to `status`, so nothing
depends on it advancing.

Left in place and documented rather than wired, because exposing a second
work-tracking lifecycle beside cases would give two answers to "what is being done
about this finding". If it is ever wired, `isValidTransition` must gate it — a
finding jumping `open → verified` leaves no record that anyone triaged it, which
is exactly why the case machine refuses `open → resolved`.

### Two dead modules: one removed, one deliberately left unwired
A sweep for exported symbols with no reference outside their defining file (40 of
530 in `server/`) turned up two modules that nothing called at all.

**`verification-scanner.ts` (398 lines) — DELETED.** It was a superseded
duplicate of `scanner/verification-gate.ts`, which is the live path every finding
passes through. It was also a trap rather than merely dead: it issued requests
with raw `https`/`http`/`net` and had **zero** references to `isSafeOutboundUrl`
or `isPrivateHost`, so wiring it up later would have added an outbound path with
no SSRF guard and no stealth/concurrency control. Removed for the same reason
`getAllFindings()` was — a convenient-sounding name is exactly how the wrong
thing gets called.

**`compliance-guidance.ts` (608 lines) — left unwired, on purpose.** It defines
PCI-DSS 4.0 and SOC-2 controls with remediation steps, a set disjoint from the
mapper's OWASP/CIS/NIST, and it carries no finding→control mapping. Wiring it as
a framework would render almost every control as "No Data", which this file
already documents as reading like a pass. The deeper problem is that an external
attack-surface scan genuinely *cannot* assess most of PCI-DSS or SOC 2 — they are
overwhelmingly process, segmentation and cardholder-data controls — so shipping
them as assessable frameworks would be overclaiming. If it is ever wired, the
mapping has to come first and the unassessable controls have to be labelled
unassessable, not left blank.

### Webhooks hang off `emitAlert`, the same choke point as SIEM
`dispatchWebhookEvent` is now called from `emitAlert`, for the reason given for
`sendToSiem` and `auditMutations`: a new event type is delivered the moment it is
emitted, without the author remembering to instrument it. Not awaited — a
customer's slow endpoint must not sit in the path of storing a finding.

**The two vocabularies differ and the map is explicit.** The config UI offers
three coarse events (`scan_completed`, `critical_finding`, `sla_breach`); alerts
are finer-grained (`new_critical_finding` vs `new_high_finding`).
`WEBHOOK_EVENT_BY_ALERT_TYPE` maps them by hand so a new alert type cannot
silently start firing webhooks nobody subscribed to. `new_high_finding` is
deliberately unmapped: the box says "Critical Finding".

SLA breaches now emit an alert too, **one per workspace per sweep** rather than
one per finding — a sweep can mark dozens at once, and paging once per row is how
an alert channel gets muted. The alert's severity tracks the worst finding that
breached, so a batch of lows does not page like a missed critical.

Verified end to end against a local receiver: a `critical_finding` alert was
delivered with the full payload, and a `scan_completed` alert to an endpoint
subscribed only to `critical_finding` was correctly **not** delivered.

Note the shape: `notifications.ts` imports the dispatcher from `routes/webhooks.ts`,
which is a service importing a route module — backwards, and the reason
`websocket-authorization.test.ts` has to stub it exactly as it stubs
`siem-export.js`. If this bites again, move the dispatcher to a `server/`-level
module beside `siem-export.ts`.

### Certificate SANs are a discovery source, not just a display field
`getCertificateInfo` has returned `altNames` since it was written, and they were
stored for display and nothing else. A SAN list is the organisation's OWN
statement about which hostnames it serves — better evidence than a wordlist
guess, and more current than a CT index, because it is read from the live
handshake rather than a log of what was once issued. The certificate was already
being fetched, so `inScopeSans` (tls.ts) adds analysis, not traffic. Hosts it
finds are tagged `tls-san` in `discoverySources`.

Two filters are load-bearing, and a live test showed why: **wikipedia.org's
certificate carries 41 SANs**, almost all wildcards for *other* domains
(wikibooks.org, wikidata.org, mediawiki.org).
- **Wildcards are dropped.** `*.example.com` is not a host; resolving it is
  meaningless and putting it in an inventory asserts an asset that does not
  exist. What a wildcard tells you is that unknown siblings exist — which is what
  the permutation stage is for.
- **Out-of-scope names are dropped.** Shared and multi-domain certificates
  routinely cover unrelated domains, and attributing somebody else's hostname to
  this target is the attribution error `asn-expansion` refuses by default.

SANs are still RESOLVED before being accepted: a certificate outlives the host it
was issued for, and an unresolvable SAN is a decommissioned name, not an asset.
The stage runs BEFORE permutation, so names it finds are permuted too.

### Dependency confusion — the manifest was already fetched
`secret-scanner.ts` fetches `/package.json` and `/requirements.txt` when they are
exposed, and scanned them for SECRETS only. The dependency list — the entire
dependency-confusion signal — was discarded. An exposed manifest is deliberately
NOT a finding by itself (it is normal on many deployments), but the names inside
it are: any name the target references that nobody owns on the public registry
can be registered by an attacker, whose install scripts then run inside a build
that falls back to public. That is Birsan's 2021 research, which worked against
Apple, Microsoft, PayPal and Netflix.

`dependency-confusion.ts` checks them against npm and PyPI — both keyless. The
body is carried back from the request `secret-scanner` already made, so this adds
analysis, not traffic.

Three rules that keep it honest:
- **Report a name as CLAIMABLE, never as exploitable.** Whether the build falls
  back to the public registry depends on `.npmrc` scoping or `--index-url`, which
  is the correct mitigation and is **invisible from outside**. The finding says
  so rather than implying compromise.
- **Scope changes the severity.** An unscoped unclaimed name is `high` — anyone
  can publish it today. A scoped name whose SCOPE is already registered is `low`:
  an attacker cannot publish into a scope they do not own, so the action is
  "confirm you own that scope", not "you are exposed".
- **Non-registry specifiers are skipped, not flagged.** `file:`, `link:`,
  `workspace:`, `git+`, and tarball URLs do not resolve from a public registry at
  all — and those are exactly the forms a monorepo's internal packages take, so
  including them would be pure false positive.

Lookups are capped (60) and deduplicated; an unreachable registry yields
`unavailable`, never an empty risk list.

### Permutation — the only discovery method that learns THIS target's naming
Discovery ran three ways: certificate transparency, a 2,258-word list, and nine
passive indexes. All three can only return a name that already exists somewhere
public — in a certificate, a wordlist, or somebody's index. A host that was never
certificated, never crawled, and is not named after a common English word was
invisible to every one of them, and making the wordlist longer does not fix that.

`permutation.ts` generates candidates from the hosts discovery already found
(`alterx`/`dnsgen` in spirit, native so it needs no Go toolchain — same stance as
`nuclei`, `katana` and `httpx`). Hosts it finds are tagged `dns-permutation` in
`discoverySources`, so they carry provenance like every other method.

Three properties to preserve:
- **The vocabulary is LEARNED, not fixed.** A curated env list (`dev`, `uat`, …)
  is the obvious half; the valuable half is the tokens observed in the target's
  own hostnames, so an organisation using `corp` or `emea` gets those permuted.
  That is the entire reason this beats a longer wordlist. `tokenize` splits the
  digit boundary (`web01` → `web`) or the vocabulary fills with `web01`, `web02`
  instead of the reusable stem.
- **Candidates are emitted in descending likelihood and hard-capped** (1,500
  standard / 15,000 gold). Permutation is combinatorial — 90 hosts × 40 words ×
  3 join styles is tens of thousands of queries against one target. Truncating at
  a cap is only defensible if what survives the cut is the part worth trying.
- **Wildcard filtering is not optional here.** On a wildcard domain EVERY
  generated name resolves, so an unfiltered permutation stage would invent
  thousands of hosts. It reuses the wildcard IPs the bruteforce already measured
  rather than probing again.

Only observed hosts are permuted. Permuting a guess compounds guesses and spends
the budget two steps from any evidence.

### Known vulnerabilities in the libraries a site SERVES
`tech-fingerprints.ts` captured library versions from the day it was written
(`version: /jquery[.-]?(\d+\.\d+\.\d+)/i` and friends). The only consumer was
`recon-builder`, which used the version to say *"Exact version disclosed —
suppress version banners"*. So the engine could see a host running jQuery 1.8.3
and reported the **disclosure of the version number** while saying nothing about
the five known XSS advisories affecting it — the most useful fact it held was the
one fact it did not act on.

Worse, `http-probe.ts` did `detectTechStack(...).map(t => t.name)`, discarding the
version one line after it was found, so nothing downstream *could* use it.
`HostProbe.libraryVersions` now carries versioned entries alongside the flat
display list.

`js-library-cves.ts` checks them against **OSV.dev** — free, keyless, and the
authoritative aggregator for GitHub Security Advisories. Version-range arithmetic
happens upstream against curated data, which is the part a hand-maintained table
gets wrong silently as it ages.

Rules if you touch it:
- **One finding per library, not per advisory.** jQuery 1.8.3 has five; five rows
  would bury the inbox and inflate the counts the score derives from. Advisories
  are preserved as evidence.
- **Severity caps at `high`, and the description says why.** This confirms the
  library is present and outdated — NOT that the application passes attacker
  input into the affected sink. Calling that critical is the severity inflation
  documented above.
- **Three states.** OSV unreachable ⇒ `unavailable`, never an empty result set.
  A library with no detectable version is `unassessed`, not clean — an unknown
  version is not a safe version.
- **AngularJS 1.x is npm `angular`; modern Angular is `@angular/core`.** One
  fingerprint matches both, and the major version is the only thing separating
  them. Querying the wrong package invents or misses vulnerabilities.
- Results are cached per `package@version`: one estate serves the same build from
  ninety hosts, and OSV is a free public service with no duty to absorb that.

Verified live: jQuery 1.8.3 → 5 advisories (fix 4.4.0), AngularJS 1.5.8 → 13,
jQuery 3.7.1 and 4.0.0 → zero. A current library producing no finding matters as
much as an old one producing several.

### Dependencies

**Remediation time frames** (ASVS 5.0 V15.1.1 requires these to be written down;
an undocumented policy cannot be audited, and "we patch things quickly" is not a
commitment anyone can check):

| Advisory severity | Fix or document an exception within |
|---|---|
| Critical | 7 days |
| High | 30 days |
| Moderate | 90 days |
| Low | next dependency refresh |

The clock starts when the advisory becomes visible to `npm audit`, not when
someone notices. An exception must name the reason and the compensating control
— the two moderates below are exactly that, not an oversight.

`npm audit --audit-level=high` gates CI, so a HIGH or CRITICAL advisory blocks
the build. It went from 23 advisories (11 high) to 6 moderate / 0 high.

`drizzle-orm` was upgraded 0.39 → 0.45.2 to clear GHSA-gpj5-g38j-94v9, a SQL
injection via improperly escaped identifiers. It was NOT exploitable here — there
is no `sql.raw`, no `sql.identifier`, and no user input reaching a column or sort
position — but leaving a known SQLi in the ORM of a security product is not a
posture worth defending. If you ever add a dynamic identifier, that assessment
stops holding.

`npm audit` reports **6 moderate advisories, but only 2 direct dependencies**:
`drizzle-kit` and `exceljs`. The other four (`esbuild`, `@esbuild-kit/*`, `uuid`)
are transitive under those two and disappear with them — worth knowing before
someone reads "6" as six separate problems to chase.

Both are build/export tooling rather than request-path code, both are only
fixable by a breaking major, and both are accepted under the exception clause
above: `drizzle-kit` runs at migration time, `exceljs` on report export. The gate
is set at high so the pipeline does not go permanently red over them.

### A coverage test that starts from the taxonomy validates it against itself

`compliance-coverage.test.ts` and `risk-factors.test.ts` both assert that every
entry in `SECURITY_CATEGORIES` maps to a control and to a factor. Both passed
while **two real categories were mapped nowhere**, because a detector emitting a
category the taxonomy has never heard of is invisible to a test that starts from
the taxonomy.

Caught by reconciling the UI against the database: a Bigbasket scan held 98 open
security findings while the risk-factor rows summed to **97**. The missing one
was `certificate_authority` (the CAA check) — in no taxonomy at all, so it
deducted from the security score, appeared in **no** risk factor, and mapped to
**no** compliance control, rendering as "No Data", which reads as a pass.
`web_application` (the WordPress XML-RPC check) had all three defects too.

`emitted-categories.test.ts` now scans the SOURCE — every `category: "..."`
within eight lines of a `severity:` literal — and asserts each is in
`SECURITY_CATEGORIES` and attributed to a factor. It names the emitting
`file:line` when it fails, and it was verified to fail by reintroducing the real
bug rather than assumed to work. Two vocabularies are excluded by name and for a
reason: `attack-simulation.ts` labels attack-path scenarios and
`tech-fingerprints.ts` labels technologies; neither writes a finding.

**Reconciling a rendered aggregate against `psql` is worth more than another
unit test here.** Both coverage tests were green throughout.

### Dead external APIs are a recurring class — test them, do not trust them

Generalising the dark-web finding, every keyless external endpoint the scanner
depends on was called live. Most are healthy (crt.sh, Certspotter, HackerTarget,
RapidDNS, OSV, npm, PyPI, HIBP, iTunes, internetdb.shodan.io, RIPEstat, ip-api,
pwnedpasswords). Three were not:

- **AlienVault OTX** answers `429 {"detail": "Anonymous access to this endpoint
  is limited."}` to every unauthenticated request — it is no longer a keyless
  source. It is now gated on `OTX_API_KEY` like Chaos/SecurityTrails/BeVigil, so
  an unconfigured key means the collector is **not attempted** rather than
  attempted and reported failed. "The operator has no key" and "this source did
  not answer" are different facts and only the second says anything about the
  target — and a `sourcesFailed` that is never empty is one nobody reads.
- **ThreatMiner** answers 522 (origin down) consistently. Left in place: unlike
  OTX it is a genuine outage of a working service, and the collector contract
  already reports it as failed rather than as zero hosts.
- **`darkpaste.com`** answers 404, and was a plain-HTTP CLEARNET host being
  fetched through the Tor transport. Removed.

Cloudflare DoH looked broken at first and was not: it needs
`accept: application/dns-json`. Check your own request before blaming the API.

### Three bugs that made "all sources answered" a lie

Found by auditing the module I had just fixed, which is the point: the panel's
green state was now derived from source accounting that did not work.

1. **`searchDarkPasteSites` and `searchCredentialDumps` both ended in a
   hardcoded `return { failed: false }`.** A run where every source was
   unreachable reported itself as a completed check that found nothing.
2. **The caller then discarded the flag anyway**, pushing to `sourcesChecked`
   unconditionally. Both halves had to be wrong for the bug to show, and both
   were — a live run reported "3 of 3 sources answered" while two had reached
   nothing at all.
3. **`textMentionsDomain` had no production caller.** It was written to fix the
   substring false positive (`"notexample.com"` contains `"example.com"`),
   tested with six passing cases, and wired into nothing — while both matchers
   still used `.includes()`. The passing tests were the reason nobody looked.
   This is the codebase's signature defect, committed by the author of the
   warning about it.

**The .onion sources are now empty, and that is the honest state.** The paste
address publishes no hidden-service descriptor (Tor fails it in 8ms), and
`2l3uq6jnojweppqy.onion` is a **v2** address — sixteen characters. Tor removed
v2 support in October 2021, so it has been structurally unresolvable for over
five years and could never have returned anything. Neither is replaced with a
guess: onion services churn, and an unverified address recreates the
permanent-failure noise this was dug out of. An empty source set is reported as
**absent** — neither checked nor failed — because listing it either way
misdescribes the run.

What remains genuinely works: the ransomware leak-site corpus (31,513 records,
keyless), with the Tor transport verified live and ready for any vetted address
added later. The panel names what it searched rather than counting it: *"Searched
the ransomware leak-site corpus — no mention of this domain."*

### Dark web monitoring: two of its four sources could never work

Making the panel honest (below) exposed the real problem — the check itself was
broken, and had been since it was written. Verified against the live endpoints:

| Source | Reality |
|---|---|
| `ahmia.fi/api/v1` | **404 — that API does not exist** |
| `ahmia.fi/search/?q=` | 302 to its homepage for any non-interactive client, over clearnet AND over its .onion service, so Tor does not rescue it |
| `onion.live/api` | **404** |

Both were **deleted**, not left to fail. A source that cannot succeed is not a
degraded source, it is a missing one, and leaving them meant every run reported
two permanent failures — which trains a reader to ignore `sourcesFailed`, the
one field that decides whether "nothing found" can be trusted.

**The replacement is the ransomware leak-site corpus**, reusing
`checkRansomwareExposure` from `ransomware-watch.ts`: keyless, already proven in
this codebase, 31,512 records, and genuinely dark-web — ransomware crews publish
victims on .onion sites and ransomware.live aggregates those postings. A hit is
the highest-severity dark-web signal there is: the organisation is already being
extorted. The corpus grades its own matches, and that grade is carried across
rather than re-derived, so this panel and Brand Threats cannot disagree about
the same record.

**Tor is now a real service**, not an assumption. `docker-compose.yml` gains a
`tor` service behind a `darkweb` profile (opt-in: starting a Tor client is an
operator's decision, not a side effect of starting the app), and
`start-cyshield.bat /darkweb` brings it up and waits for a circuit. The
healthcheck tests for `"IsTor":true` rather than for an open port, because an
open SOCKS port with no circuit accepts connections and then fails every
request. `stop-cyshield.bat` passes `--profile darkweb` — a profiled service is
invisible to a bare `compose stop` and would be left running.

Measured before: 2 of 6 sources answered, 4 failed, Tor unavailable.
Measured after: **3 of 3 sources answered, zero failures**, and the panel's
green state is earned rather than asserted.

Note for the tests: this module reaches the network TWO ways, and both must be
mocked. `torFetch*` is the obvious one; `checkRansomwareExposure` owns its own
fetch of a 21 MB corpus, and an earlier version of the test file mocked only the
first — so a test asserting "no mentions" quietly downloaded the real corpus.

### "Nothing found" is two different results in the dark web panel

The panel rendered a green `ShieldCheck` and "No dark web mentions found for
bigbasket.com" while the small print underneath said the Tor proxy was
unavailable and 4 of 6 sources had failed. Two sources answered. A reader takes
the green tick, not the footnote — this is the "No Data reads as a pass" failure
in its most literal form, in the module whose own documentation says a check
that could not run must never render as a check that found nothing.

The empty state now branches on `!torAvailable || sourcesFailed.length > 0`:
an incomplete run gets an amber `AlertTriangle`, the headline "Dark web check
was incomplete", the ratio that actually answered, the failed sources by name,
and what to do about it. Only a run where every source answered gets the green
tick. Verified live: "2 of 6 sources answered… This is **not** a clean result."

### Finding groups clustered `recon` facts together with security findings

`groupFindings` selected every row in the workspace — no `kind` filter, no
status filter — and groups are rendered as triage work: a severity badge and an
"N instances" count. Two live groups mixed kinds:

```
Strapi API - Detect on admin.alkemlabs.com        5 instances   kinds: recon,security
Microsoft Azure Domain Tenant ID - Detect         4 instances   kinds: recon,security
```

A group titled after a technology fact, claiming five instances of outstanding
work, taking its severity from whichever member happened to come first. That is
the **sixth** place the `kind` rule was open-coded and missed. Closed rows were
grouped too, so a resolved finding inflated an open group.

Now filtered to open `security` rows via `isSecurityFinding`. After: every group
is `security` + `open`, zero contamination, and the recon-titled groups are
gone.

**Checked before calling it a bug, and one half was not one.** Five open
security findings sat in no group at all, which looked like the other side of
the same defect — but `groupFindings` requires `group.length > 1`, so
singletons are correctly ungrouped. Reporting that would have been a false
finding.

`reconcile-real-data.mjs` now asserts group composition, verified non-vacuous by
reverting the filter: it named `Apache Detection … : recon` and exited 1.

Two things left alone deliberately: `MAX_FOR_GROUPING = 2000` takes an unordered
`slice`, so *which* 2000 is arbitrary, and the truncation is logged but not
recorded in the result. Neither bites at current volumes (98 findings is the
largest workspace) — but if grouping ever runs on a capped estate, the cap
should be surfaced the way `probeCoverage` is.

### Every gate asserts its own coverage

After the authorization probe was caught reporting success while checking zero
calls, the other three were audited for the same hole. Two had it:

| gate | hole |
|---|---|
| `reconcile-real-data.mjs` | `if (findings.length === 0) continue` — on a fresh or emptied database every workspace is skipped and the success line still prints |
| `verify-report-content.mts` | the same skip, and no guard at all for an empty workspace list |
| `smoke-real-data.mjs` | already errored on zero workspaces, but nothing asserted that a page was actually rendered |

All four now count what they examined and report
`NO COVERAGE: … this run cannot have passed` when that count is zero. **Each was
verified by forcing the skip** (`if (true) continue`, an emptied scope list) and
watching it exit non-zero with that message.

This matters more than a normal test bug: a green gate is the evidence behind
every "verified" claim in these notes. A gate that passes vacuously does not
merely fail to find bugs — it retroactively weakens every conclusion drawn from
it.

**Audited and found correct in the same pass**, recorded so it is not re-derived:

- **Retention date arithmetic** is `Date.now() - days * 86_400_000` — UTC
  milliseconds, so none of the local-timezone `setDate` hazards apply.
- **`if (policy.scanRetentionDays)` is falsy-safe** only because the route
  validates `.min(1)`; a 0 would silently mean "retain forever", the opposite of
  what it says. If that bound is ever relaxed, this check must become an explicit
  `!= null`.
- **`archiveEnabled` still skips before any deletion**, counted and logged.
- **All five background workers** (`scheduler`, `queuePoller`, `slaMonitor`,
  `retentionSweep`, `rateLimitCleanup`) are started and stopped, with every stop
  in the SIGINT/SIGTERM handler.

### The authorization probe covers three properties, and two were already right

`scripts/probe-cross-tenant.mjs` grew two sections. Both came up CLEAN on first
run, which is recorded here so the coverage is not later mistaken for untested
ground:

- **Role escalation.** A `viewer` and an `analyst` were made members of a real
  workspace (directly, since no HTTP route adds members) and made to attempt
  every owner- and admin-only call. All 8 refused correctly, and `analyst` was
  still allowed to start a scan — over-restriction is a bug too.
- **API key scope.** `read`, `scan` and `full` keys were minted and exercised.
  Each can read, `scan` and above can write, and — the rule that matters —
  **no key at any scope, including `full`, can list or mint API keys.** A leaked
  key that can mint another survives its own revocation.

**The probe then failed the way its own targets do.** The api-key section
silently checked **zero** calls for several runs: `call()` prepends `Bearer`,
and the section passed it a string that already had one, so every request 401d,
every scope hit `continue` — and the script still printed *"scopes enforced"*.
A gate reporting success while checking nothing is the exact vacuous-guard
failure this file documents, reproduced inside the tool written to catch it.

Each section now asserts its own coverage: a count of zero is reported as
`NO COVERAGE: … it cannot have passed`, and exits non-zero. Verified by emptying
the scope list.

Worth keeping in mind when reading a clean run: **a 409 is not a denial.** An
early version of the scope probe flagged `full` as over-restricted because a
duplicate-scan 409 was counted as a refusal. Only a 2xx proves permission and
only a 403 proves refusal; everything else is a different conversation.

### A membership oracle in three webhook handlers — and why no lint rule catches it

All three bare-ID webhook handlers (PATCH, DELETE, POST /test) read

```ts
if (!member || !["owner", "admin"].includes(member.role)) return 403;
```

folding "not a member" and "wrong role" into one answer. Because those handlers
404 on a missing row FIRST, the two paths became distinguishable: someone else's
webhook answered 403, a nonexistent one answered 404, so a stranger iterating
ids learned which existed from the status code alone. Nothing leaked — 11 of 13
probed routes correctly answered 404 — but this is the exact rule already
applied to `requireWorkspaceRole` and the workspace routes.

**The existing static test could not see it: it checked a hardcoded list of two
files** (`scan-diff.ts`, `asset-risk.ts`) and `webhooks.ts` was never in scope.
A guard whose scope is a curated subset is the recurring theme of this whole
audit.

**A blanket static rule was written, then deleted.** The shape alone is not the
bug: `POST /api/scans` uses that identical line and leaks nothing, because it
performs no prior existence lookup — a nonexistent workspace and someone else's
workspace both answer 403, measured and identical. The oracle needs the PAIR:
404 on missing, 403 on non-member. No regex over one line can see that, and a
rule strict enough to try fires on correct code, which teaches people to edit
the test.

`scripts/probe-cross-tenant.mjs` checks the property empirically instead: it
creates two tenants, gives one resources, and compares the outsider's response
for a REAL id against the same route with an absent id. Different statuses mean
an oracle. Verified non-vacuous by reverting the fix — it named all three
handlers with the 403-vs-404 comparison and exited 1.

Note when running it repeatedly: registration is rate-limited to 3/min, so
back-to-back runs fail on tenant creation rather than on a finding.

### Credential handling: what the audit confirmed, and the one gap it found

Worth recording the negatives as well as the fix — several of these looked like
defects and were not.

| checked | result |
|---|---|
| 76 API endpoints swept for secret-shaped fields and values | **0 leaks**. Webhook routes return `hasSecret: true`, never the value |
| `users.password_hash` | scrypt, N=65536 (OWASP minimum), 16-byte per-user salt, `timingSafeEqual` compare. It failed a bcrypt regex because it is not bcrypt — the check was wrong, not the code |
| `sessions.token` | 134/134 stored as SHA-256, none in the clear |
| secrets at rest | webhook secrets encrypted; the plaintext never returns from any route |

**The gap: `apiKey` was in the log redaction list and `apiToken` was not.** That
is the whole failure mode of a name-keyed redactor — the field that travels is
the one nobody thought of. The Jira integration config carries `apiToken` beside
`email`, and a PagerDuty payload carries `routing_key`. Neither is passed whole
to a log call today, which is exactly the assumption the list exists so nobody
has to depend on. Both added.

**The test had a hardcoded COPY of the list**, commented as "kept in sync by the
coverage test below". It drifted the instant production changed: the app
redacted the new names and the test's private copy did not, so a correct fix
failed its own test. `captureLog` now parses the shipped array out of
`server/logger.ts`. A copy of a list is a second source of truth however
carefully it is commented — the same lesson as the three A–F band tables and the
three report-scope rules.

An empty dataset also nearly passed the sweep for the right reason and the wrong
evidence: no webhooks existed, so the endpoint that could leak a secret was
never exercised. Creating one with a known secret is what actually proved
`hasSecret` behaviour.

### A followed redirect leaks whatever the request was carrying

The Jira ticket path already re-validated at request time — its own comment says
*"URL may have been saved before check existed"* — but the `fetch` had no
`redirect` option, so it followed. That request carries
`Authorization: Basic <email:apiToken>`, so a 302 from a customer-supplied Jira
host would have handed those credentials to whatever address the redirect named,
which the check immediately above had never seen.

Now `redirect: "manual"`, and the guard is `isSafeOutboundUrl` on the full URL
rather than `isPrivateHost` on the hostname, so the protocol is checked too.

**The rest of this class is clean, and it was worth confirming rather than
assuming:**

| path | status |
|---|---|
| scheduled scans | re-validates the target at fire time (`triggerScan`'s own DOMAIN_REGEX, commented as being for the scheduler) and passes the stored per-schedule `mode` |
| `getDueScheduledScans` | filters `enabled = true`, so a disabled schedule cannot fire |
| GitHub issue creation | posts to the literal `api.github.com`, not a user-supplied host |
| Ollama, SIEM | operator configuration from the environment, deliberately unguarded — see the SIEM note above |
| DoH, OSV, crt.sh, OTX | literal hosts |

`webhook_endpoints.url` is the ONLY user-supplied URL column in the schema, which
is why the sweep is short — but the credentials travelling to a config-supplied
host is the same risk, and Jira had it.

### Validating a user-supplied URL on SAVE is not validating it on SEND

`webhook_endpoints.url` was guarded by `isPrivateHost` on create, on update and
on the test button — and **not at delivery**. Two holes at once, both of which
the report-evidence path had already been fixed for:

- **DNS rebinding.** The guard answers "what does this hostname resolve to
  *now*", and a webhook fires days or months later. A host that resolved public
  when the endpoint was saved can resolve to `127.0.0.1` or `169.254.169.254` by
  the time a critical finding triggers delivery, and nothing looked again.
- **`fetch` defaults to `redirect: "follow"`.** A public receiver could 302 the
  POST — signature header and decrypted secret included — to an address nothing
  vetted.

`deliverWebhook` now calls `isSafeOutboundUrl` immediately before connecting and
sends `redirect: "manual"`. A redirect from a webhook receiver is a
misconfiguration, so treating it as the final answer loses nothing.

Verified by inserting the rebinding shape directly — a row pointing at
`localhost`, which the create route correctly refuses and which is exactly why
delivery must check again: every retry was refused with
*"Delivery refused: endpoint resolves to a private or internal address"*, and a
public Slack URL still passes.

`ssrf.test.ts` now statically asserts that the delivery path calls the
**resolving** guard and sets `redirect: "manual"`. Verified non-vacuous by
deleting the redirect option: it fails naming the missing protection. Extend
`SOURCES` there when another path starts POSTing to a user-supplied URL.

### `autoGenerateReport` — the promise the product made out loud

The dashboard has an **auto-generate report checkbox**. Ticking it sent
`autoGenerateReport: true`, the request schema validated it, and the UI raised a
toast reading *"(report will be auto-generated)"*. The server read the flag
**nowhere**, and no report was ever created.

That makes three of this shape found by the same sweep — `api_keys.scope`,
`scan_profiles.isDefault`, and this one — but this is the worst of them: the
other two implied a promise through a badge, this one stated it in a sentence to
the user's face.

It is now honoured at the scan-completion choke point in `scan-trigger.ts`,
beside `emitScanCompleted`. Two properties worth keeping:

- **Not awaited, and its failure is logged rather than thrown.** A report that
  could not be built must not turn a completed scan into a failed one.
- **Scope is left to `selectReportFindings`** — no `findingIds` means "this
  workspace's outstanding exposure", the same rule every other report path uses.

**Wiring it exposed a second defect that had been invisible.** Launching several
scan types with the box ticked sent the flag on EVERY scan, so N scans produced N
near-identical reports of the same workspace — under a toast that promises "a
report". The dashboard now requests it once per batch. A dead flag cannot
duplicate anything; the duplication only became reachable once the flag started
meaning something.

**Verify past the count.** The first check saw reports go 0 → 1 and looked like
success, but the row was `status: generating` with an empty body — Ollama was
unreachable and `buildReportContent` was still retrying. It completed correctly
~10s later (267-char summary, 27 content keys). The count was not the evidence;
the content was.

### A default scan profile that nothing read, and a button that overrode it

`scan_profiles.isDefault` was validated on write, stored, and rendered as a
**star on the profile card** — and read by nothing. `POST /api/scans` applied a
profile only when an explicit `profileId` was passed, so an operator who marked
a profile as their default got `standard` on every scan and the star was a
promise the product did not keep. Same defect as `api_keys.scope`: configured,
badged, enforced nowhere.

Compounding it, the dashboard's quick-launch panel hardcoded `mode: "gold"` —
the most aggressive profile — which would have overridden the default even once
it worked. Worse, it applied gold to the **"Passive OSINT (non-intrusive)"**
button, whose own description reads *"safe when only passive testing is
authorized"*. The request contradicted the label the user had just read, and
mode is a statement about the rate the TARGET sees.

Both fixed. Precedence is now, deliberately:

1. an explicit `profileId` — the caller named a profile;
2. an explicit `mode` — a UI that offers the choice and the user made one;
3. the workspace's default profile;
4. `standard`.

The default must not outrank an explicit `mode`, or it would silently override
someone who just picked something else in the scan dialog.

**Behaviour change worth knowing:** the dashboard buttons now run `standard`
where they previously ran `gold`, unless a default profile says otherwise. A
one-click button should follow configuration rather than silently select the
heaviest mode; an operator who wants gold sets it as their default profile and
now actually gets it.

Verified by making the difference observable: a default profile of `gold` with
**no mode in the request** resolved to `gold`. The first attempt used a
`standard` default profile, which the old code would also have produced — a test
that cannot distinguish the fix from the bug proves nothing.

### `selectReportFindings` — and the client that made the server's default unreachable

The CSV/XLSX export route was a THIRD copy of "which findings go in a report",
after `buildReportContent` and `buildDocxInput`. A client's export listed
"DNSSEC Detection", "security.txt File", "robots.txt file" and "AWS Service -
Detect" as findings, under a summary line reading *"This report covers 14
security findings"* when four of them were.

Fixing it exposed the actual root cause, one layer further out. Reports store
their scope as `findingIds`, and `reports.tsx` sent:

```ts
findingIds: selectedFindings.length > 0 ? selectedFindings : findings.map(f => f.id)
```

So "the user selected nothing" arrived at the server as **an explicit,
deliberate selection of every row** — and the security-only default was
therefore honoured-away and never ran, in all three paths at once. The client
now sends `undefined`, and the server is the single place that decides what "no
selection" means.

`server/report-scope.ts` is now that decision, used by all three:

- **no explicit selection** → security findings only. A report with no stated
  scope means "our outstanding exposure", which controls and recon facts are not.
- **an explicit `findingIds`** → exactly those rows, unfiltered. Including a
  control as evidence that something IS configured is a legitimate thing for an
  operator to put in a report, and filtering it back out would disobey them.

Verified end to end on a fresh report: stored `findingIds` 0, CSV finding rows
4 = open security 4, summary reading *"This report covers 4 security findings"*.

**Old reports keep their stored scope**, which is correct — a report is a
snapshot of what was included when it was made, and rewriting that retroactively
is the same thing the audit log must never do.

### `isSecurityFinding` — one rule, because open-coding it kept failing

Only `security` findings are WORK. A `control` finding records a protection that
IS in place ("DNSSEC Detection", "security.txt File"); a `recon` finding is a
technology fact ("Apache Detection", "robots.txt file"). The rule is three
tokens long, which is exactly why it kept being written inline and kept being
missed — **four separate places, none caught by a test**:

| where | what a reader saw |
|---|---|
| SLA summary + sweep | `control` findings carried remediation deadlines and would page somebody as an overdue breach |
| both trend endpoints | `/trends` said **14 open findings** where the inbox said 4 |
| `buildReportContent` | the client's report counted 14 findings for 4 of work |
| `buildDocxInput` | …and the DOCX register **opened with "DNSSEC Detection"** — a protection that is working — as the first row the client reads |

The last two are the same defect in two places because the report is assembled
by two independent paths. It is now `isSecurityFinding()` in
`finding-taxonomy.ts`, used by all of them, with a test pinning that an absent
`kind` reads as `security` — rows written before the column existed must not
silently drop out of the score, the inbox and every report.

An EXPLICIT `findingIds` selection is still honoured exactly as given in both
report paths: if an operator picked specific rows, that is their call.

### The report needed its own verifier, and the first one I wrote was vacuous

Neither the unit suite nor the API reconciler can see report content — there is
no read-only endpoint that returns it. My first attempt added a check against
`/report-preview`, **an endpoint that does not exist**, which would have passed
forever while asserting nothing. That is the same defect this file warns about
in `textMentionsDomain`, committed while writing the guard against it.

`scripts/verify-report-content.mts` drives the real builders instead
(`buildReportContent` AND `buildDocxInput`, because they are separate paths) and
compares each against the workspace's open security findings. Verified
non-vacuous by removing the DOCX filter: it exited 1 naming both workspaces and
both counts.

### `getFindings(id)` with no limit is a silent wrong answer, not a page

`DEFAULT_LIMIT` is 500. That is a sensible page for a list endpoint and a
**data-loss bug** for anything that filters, counts or exports afterwards: the
caller gets 500 rows and nothing tells it there were more. Twenty-four call
sites had no explicit limit.

Measured on live data, in a client deliverable. Report generation and IP
enrichment both did `getAssets(workspaceId)` with no limit and then filtered for
`type === "ip"`. Assets are ordered `firstSeen DESC`, so the oldest fall off the
end of the page:

| workspace | IP assets | inside the first 500 |
|---|---|---|
| Bigbasket | 228 | **159** (30% lost) |
| mydesk.theranym.com | 2 | **0** (all lost) |

The report simply omitted them. `FULL_SET_LIMIT` (storage.ts) is now what a
consuming caller passes; the accessors' 500 stays the default for display.
Verified after the fix: mydesk went 0 → 2 enriched IPs.

Row counts worth knowing before assuming a cap is safe: assets peak at **1,067**
per workspace, findings at 98, recon modules at 33, scans at 6. Only assets
exceed the default today — the rest are latent.

### A cap must report itself, even a deliberate one

`enrichIPs` caps at `MAX_IPS_PER_BATCH = 10`, which is correct — each IP costs
several third-party calls plus a 500 ms pace. But it returned a bare map, so a
caller that asked about 228 IPs got 10 with **nothing saying the other 218 were
skipped**, and both the panel and the report presented those ten as the estate.

It now returns `{ enrichment, requested, enriched, truncated }`, and the panel
says so: *"Showing 10 of 217 public IPs. Enrichment is rate-limited per batch,
so the remainder were not checked — this is not a finding that they are clean."*
The report records the same under `content.ipEnrichmentCoverage`.

Same rule as `probeCoverage` and the crawler's `truncated`: **truncating is
fine, truncating silently is not.** A deliberate cap is still indistinguishable
from a complete answer unless it says otherwise.

### Reconciling a published number against its source is the highest-yield check

Three bugs, none of which threw, none of which any suite caught, all found the
same way — asking whether a number the product publishes agrees with the rows it
claims to describe:

| Symptom | Cause |
|---|---|
| 98 open findings summed to **97** in the factor rows | `certificate_authority` and `web_application` were in no taxonomy, so they deducted from the score while appearing in no factor and no compliance control |
| `slaOpen` **26** where `openSec` was 21 | the SLA summary and sweep did not filter `kind`, so `control` findings carried remediation deadlines |
| `/trends` reported **14** open findings on a workspace whose inbox showed **4** | the trend endpoints did not filter `kind` either |

`scripts/reconcile-real-data.mjs` is that check, made repeatable. It cross-checks
compliance coverage, the SLA buckets, both trend endpoints, finding-group
references and asset-risk coverage against one definition — the open `security`
findings the inbox and the score both count. Verified non-vacuous by reverting
the trends fix: it named all six disagreements with both numbers.

**All five analytics endpoints also fetched with the storage default of 500**,
so compliance and every trend silently described the first 500 rows.
`securityFindings()` in `routes/analytics.ts` is now the single accessor: one
explicit ceiling, one `kind` filter.

The compliance mapper still has no `kind` handling of its own and is safe only
because the control categories (`DNSSEC`, `security.txt`, `technology`) happen
to sit outside `SECURITY_CATEGORIES`. That is an accident of the current
taxonomy, not a guarantee — a `control` finding carrying a security category
would mark that control **FAILED for evidence the control is working**. The
route filters before the mapper sees it; if you ever call the mapper directly,
filter first.

### The E2E suite runs against an EMPTY product — that is its blind spot

`tests/e2e/accessibility.spec.ts` sweeps every route and every tab, and it logs
in as a throwaway `@e2e.local` account with **no workspaces and no data**. Every
page therefore renders its empty state, and any defect that only appears once
rows arrive is invisible to the entire suite.

Demonstrated, not theorised. `/asset-risk` shipped **completely broken**: a
`usePagedList` call placed after the `isLoading` / `isError` early returns meant
the hook ran on a loaded render and not on a loading one, so React counted a
different number of hooks between renders, threw *"Rendered more hooks than
during the previous render"*, and tore the page down. Nothing failed — and axe
cannot help, because **a page that rendered nothing has no accessibility
violations**. An empty page looks perfectly accessible.

Worse, it fooled the measurement that was supposed to prove the paging work: the
"largest rendered list" scan read a crashed page as a successful reduction from
1,067 rows. The honest ceiling, with the page actually rendering, is **51**.

`scripts/smoke-real-data.mjs` closes the gap. It drives the operator's REAL
workspaces through every route and tab and fails on an uncaught error, an error
boundary, or a single list over `--max-rows`. It is a script, not a test,
because it reads whatever data happens to exist and so cannot assert fixed
numbers or gate CI. Run it after touching any page component:

```bash
node scripts/smoke-real-data.mjs
```

Verified non-vacuous by reintroducing the real bug: it named both the uncaught
error and the error boundary, per workspace and per route. The a11y sweep also
now records uncaught errors alongside its axe scan — cheap, and it catches
anything that throws in the empty state — but the data-dependent half needs the
script.

**Two rules this produced:**
- **Every hook runs before every early return.** `usePagedList`, like any hook,
  must be called unconditionally; derive the data above the `isLoading` guard,
  where the `Array.isArray(x) ? x : []` fallback already handles the undefined.
- **A measurement taken through the surface you changed proves nothing about the
  layer underneath.** A row count that drops because the page crashed looks
  exactly like a row count that drops because paging works.

### Fetching everything and RENDERING everything are different decisions

The asset fix below is right — a page that filters client-side must load the
whole set or the filter changes the answers. But it made the table emit **1,067
`<tr>` elements**, which is not a table anyone reads, it is a scroll.

`components/list-pager.tsx` (`usePagedList` + `<ListPager>`) pages the VIEW while
the data stays complete: search, sort and counts still see every row. Applied to
the seven unbounded renders found by measuring the largest single rendered list
across every workspace, route and tab:

| | largest single list |
|---|---|
| before | **1,067** (EASM assets, asset-risk) |
| after asset tables | 380 (one exposures group) |
| after grouped exposures | 134 (Nuclei hits) |
| after Nuclei | **51** |

Three things worth keeping:

- **Reset to page 1 when the filter or sort changes.** Filtering while on page 43
  leaves the reader on a page that no longer exists, and an empty table after
  typing reads as "no matches" — the same failure this codebase already shipped
  server-side, where `Math.max(1, NaN)` returned an empty inbox with a 200 and a
  correct-looking total. `usePagedList` also CLAMPS rather than trusts, because
  `all` can shrink under a stable resetKey (a deleted row, a poll returning less).
- **A grouped list needs a child component, not a hook in a loop.** The exposures
  panel renders one table per response type; calling `usePagedList` inside that
  `.map()` breaks the rules of hooks the moment the number of groups changes.
  `ExposureGroup` is a component for that reason alone.
- **Only render the pager when there is more than one page.** A pager under a
  four-row table makes the page look more complicated than it is.

**Two count bugs surfaced while testing it**, both the "the number describes the
view, not the data" class:
- `Discovered Assets ({filteredAssets.length})` rendered **"Discovered Assets (0)"**
  directly above "1,067 assets in this workspace". The title now shows the total
  with a separate "N shown" when a filter is active.
- The empty state said **"No assets found — Add assets manually or run an EASM
  scan"** on a workspace holding 1,067 assets whose search matched nothing,
  sending the reader to redo work already done. "Nothing here" and "nothing
  MATCHES" are different facts; the second now names the search term, states the
  workspace total, and offers Clear filters.

### The SLA clock applies to WORK, and only `security` findings are work

`getSlaSummary` and `runSlaSweep` filtered `status` but not `kind`, and
`storage.createFinding` set a `dueDate` on every row regardless. So a `control`
finding — evidence that a protection IS in place — carried a remediation
deadline, and once it passed the sweep marked it breached and emitted an
`sla_breached` alert **and a webhook** for good news.

Caught by reconciling the API against `psql`: `slaOpen` was 26 where
`openSec` was 21, and 14 where it was 4. Measured: **15 non-security rows held
deadlines, 2 of them `control`.**

Fixed at all three levels — the choke point (`createFinding` derives a deadline
only when `kind === "security"`), the sweep, and the summary — and the 15 stored
deadlines were cleared. `kind` defaults to `security` in the schema, so rows
written before the column existed are still swept. After: `slaOpen` equals
`openSec` exactly for every workspace.

### A page that filters client-side must fetch the whole set

`easm.tsx` fetched assets with a plain `useQuery` at the storage default of 500,
then filtered, counted and searched that array in the browser. On live data two
workspaces hold **743 and 1067 assets**, so 243 and 567 were invisible: the
per-type tiles undercounted, and searching for one of the missing hosts rendered
**"No assets found" for an asset that exists**. A page size is only a display
limit when the server does the filtering; here it changed the answers.

It now uses `useListQuery` with an explicit `?limit=5000` and renders a notice if
even that is exceeded, so a partial set is never shown as if complete. Verified:
tiles sum, table rows and the server's `total` all agree at 1067 and 743.

**React Query matches query keys by ARRAY ELEMENT, not substring.** Adding
`?limit=5000` to the path silently broke both `invalidateQueries` calls, which
still named the bare path — so adding an asset would no longer refresh the list.
`assetsQueryKey()` is now the single definition all three call sites use. Any
time a query key gains a parameter, grep for its invalidations.

Before adding client-side filtering to a list, check the row count in the
database first: `/findings` already fetches to an explicit
`FILTERABLE_FINDING_CEILING` of 10,000 for exactly this reason.

### Every aggregate must open to the rows behind it

A factor score, a compliance control's "14 findings", a severity count — each is
derived from specific rows, and none of them could be opened. A reader shown
"Security Misconfiguration · Fail · 14 findings" had to go to the inbox and
reconstruct which fourteen by guessing at categories. The compliance mapping had
carried `findingIds` all along and the page rendered only their `.length`.

`components/finding-drilldown.tsx` is one component used by both the
risk-factor card and the compliance page, so a finding reads identically
wherever it is surfaced. Two rules:
- **Group with the SAME predicate the count uses** (open, `kind === "security"`,
  category mapped to that factor). A drill-down listing a different set from the
  number beside it undermines the number instead of explaining it.
- **An id that resolves to nothing is dropped from the list but still counted.**
  It means the finding was deleted or filtered since the report was generated;
  inventing a placeholder row would assert something we cannot show.

### The band ceiling is only sometimes what is holding the score down

`analyseScoreCeiling` returns `binding`, and the wording for one regime is
actively wrong in the other. Measured on a live workspace: **60 open medium
findings, ceiling 85, actual score 55** — the panel read "Score is capped at 85"
while displaying 55, and told the reader "fixing only some of them does not move
it". Both false. At that volume the score is below the ceiling *because of* the
count, so every finding closed helps, and discouraging partial remediation is
the opposite of what the data supports.

- `binding: "ceiling"` — the score sits clamped at the band's ceiling; only
  clearing the whole band moves it.
- `binding: "volume"` — count has already pulled the score below the ceiling;
  progress is incremental and must be described that way.

The card and the DOCX report both branch on it. A test asserts the summary never
claims a cap above the score it is reporting.

### The live scan view, and the step vocabulary it corrected

`scan-trigger.ts` has always written `progressMessage`, `progressPercent` and
`currentStep` at every phase boundary, and the scanners emit a named step per
stage. All of it reached the UI as a 1.5px bar and one truncated line — so
during the longest-running part of the product an operator could not tell a
working scan from a wedged one. `components/live-scan-view.tsx` surfaces the
reporting that already existed: a phase tracker, the current activity, elapsed
and ETA, and a rolling activity log.

**It exposed a real inconsistency.** Only the `full` branch tagged its
scanners' progress (`[EASM] …`, step `easm_…`); the `easm`, `passive` and
`osint` branches passed `onProgress` straight through. So the same scanner
reported `easm_takeover_check` in a full scan and a bare `takeover_check` in an
EASM-only one — one step vocabulary or two depending on how the scan started.
Nothing read `currentStep` closely enough to notice until the phase tracker
showed every phase as "not started" while the scan was plainly running.
`tagged()` in `scan-trigger.ts` now applies the prefix on every branch;
percentages are untouched, because a single-type scan owns the whole range.

The activity log is client-side and append-only on purpose: the server keeps
only the CURRENT message, and adding a progress-history table would create one
whose only reader is a panel open for a few minutes.

### Two pagination conventions, and the unwrap that only knew one

`getQueryFn` unwrapped `{ data, total, limit, offset }` and required `offset`.
The findings inbox returns `{ data, total, page, pageSize, totalPages }` from
`parsePageParams` — no `offset` — so that shape reached components **as an
object**, and the first thing a list page does with it is `.filter`. The symptom
is not a bad list: it is `x.filter is not a function` thrown during render,
which the error boundary turns into a full-page "Something went wrong" with
every working thing on the page gone with it.

The test is now "an array of rows beside any pagination metadata", which both
conventions satisfy and a domain object carrying a `data` field does not
(`GET /findings/export-data` answers `{ findings, modules, workspaceName }`).
`tests/unit/client/query-envelope.test.ts` pins both directions.

### The a11y sweep now expands disclosures too

Same structural blind spot the tab activation fixed. Collapsed drill-downs
render their contents only once expanded, so everything inside them was never
measured. The sweep now clicks up to six `factor-toggle-*` / `control-toggle-*`
buttons per route and re-scans.

**Four unnamed progress bars were found this way** (`aria-progressbar-name`,
serious) in `scan-sections.tsx` ×2, `easm.tsx` and `osint.tsx` — all inside
running-scan blocks, which is exactly why a sweep of idle routes never saw
them. Note the limit: `live-scan-view.tsx` only mounts while a scan runs, so it
is NOT covered by the standing sweep. It was measured manually against a real
running scan (0 serious/critical, activity log populated); re-measure that way
if you change it.

### The security rating: a factor is `not_assessed`, never a free 100

`shared/risk-factors.ts` decomposes the score into nine factors, the shape every
security-rating vendor uses because it survives being read by a board, an
insurer and an engineer at once. One thing is deliberately different, and it is
the whole reason the module exists.

A real SecurityScorecard report (Brickwork Ratings, Sept 2026, 22pp) grades ten
factors and shows **Endpoint Security 100, IP Reputation 100, Hacker Chatter
100, Social Engineering 100**, each "0 issues". An outside observer cannot see a
company's endpoint estate at all — those are not findings of excellence, they
are the absence of telemetry. That is the "No Data reads as a pass" failure this
file documents for compliance controls, and it is **worse** here, because the
number travels into board packs and vendor questionnaires as an assurance.

So a factor has three states: `assessed`, `clean` (checks ran, found nothing —
real good news, scores 100), and `not_assessed` (nothing capable of judging it
ran; renders "Not assessed", never a score). We will show fewer perfect scores
than a rating vendor. The missing ones were never earned.

**Findings are themselves proof of assessment, and this was a real bug.** The
first version consulted only `MODULE_ASSESSES` (recon module → categories it
judges) and returned `not_assessed` **with `findingCount` 0**, so three real
`osint_exposure` findings vanished out of Brand & Threat Intelligence because no
module in the map claims that category. Withholding a score is safe; dropping
findings under-reports risk. `wasAssessed` now starts from `mine.length > 0`.

**There is no per-issue "score impact", on purpose.** SecurityScorecard prints
-5.1 / -2.3 per issue, implying a smooth gradient. Ours is banded, so with two
open mediums the ceiling is 85 whether you fix one or neither — the honest
marginal impact of each is **0.0**, which is useless to act on.
`analyseScoreCeiling` states the gate instead: *"the score cannot exceed 85
while any medium finding is open; clearing all 2 raises it to about 95."* That
is a sprint target, and it is true. Measured on a live workspace: 85 → 95.

Rules if you touch it:
- **Every emittable category maps to exactly one factor.** `risk-factors.test.ts`
  asserts this against `SECURITY_CATEGORIES`, the same guarantee
  `compliance-coverage.test.ts` makes — an unmapped category would deduct from
  the overall score while appearing in none of the areas the reader is told to
  act on, so the page would not add up.
- **A module absent from `MODULE_ASSESSES` may only withhold a score, never
  grant one.** That is the safe direction for an unmapped detector.
- **`gradeForScore` is the ONLY A–F band table in the product.** There were
  briefly three and they disagreed: `scoreGrade` (client) put a C at 65 and a D
  at 50, the factor card and the DOCX builder used 70 and 60 — so a 68 was a C
  on the dashboard hero and a D on the factor table, from one number. Both
  callers now delegate to `shared/risk-factors.ts`.
- Tailwind arbitrary values need the `var()` form: `bg-[--sev-ok]` silently
  produces no colour, which is how a token palette drifts with nothing failing.

### Scoring — severity bands, not a linear sum
`computeSecurityScore` was `100 - 20*critical - 10*high - 5*medium - ...`, flat
and unbounded. A real workspace with **0 critical, 0 high, 27 medium** scored
**0/100 "Grade F · Critical"**, because 27 x 5 alone floored it. Three fixes:
- **Diminishing returns** (`weight * sqrt(n)`): 27 hosts missing the same header
  is one misconfiguration with 27 instances, not 27 independent problems.
- **Severity bands**: a floor AND a ceiling per worst-severity-present. The floor
  stops volume alone reaching 0; the ceiling stops a workspace with an open
  critical being graded well. Without the ceiling, one critical and a hundred
  lows both scored 80.
- **Info scores 0**, and `false_positive` / `accepted_risk` no longer deduct —
  the old filter was `status !== "resolved"`, so dismissing a finding did nothing.

### E2E leaves no residue
`tests/e2e/global-teardown.ts` removes what the suite creates. There was no
teardown at all, so every run leaked ~8 workspaces; ten runs had left 89
workspaces, 65 of them fixtures, burying the real ones in the switcher.

It deletes by **ownership, not name**: only workspaces whose every member is an
`@e2e.local` account. One human member and the row survives, so a real workspace
can never be caught by it. It also needs `import "dotenv/config"` — Playwright
runs teardown in its own process, and without that DATABASE_URL is undefined and
the cleanup silently no-ops.

### Dashboard layout — bento, not a card row
The dashboard metrics are a **bento grid** (`client/src/components/bento.tsx`),
not a uniform row of cards. That is deliberate: a rigid grid of equal-sized
cards is the documented failure mode for dense dashboards, because every metric
gets identical visual weight and the layout tells the reader nothing. Eye-
tracking behind the pattern shows users fixate ~2.6x longer on larger tiles, so
tile SIZE is the cheapest hierarchy signal there is.

Rules to preserve when adding a tile:
- 4 columns desktop / 2 tablet / 1 mobile, reordered by importance on mobile.
- **The cell arithmetic must close.** A part-filled final row reads as a bug.
  Currently: hero 2x2 (4 cells) + open findings (2) + 2 singles = 8, then two
  2-wide tiles = 4. Three full rows.
- Padding scales with tile size; a hero and a stat chip must not share one value.
- Keep gutters identical at every breakpoint — inconsistent spacing is the most
  common way a bento grid falls apart.

### Accessibility — measured, keep it at zero
axe-core (WCAG 2 A/AA, serious + critical) is at **0 across all 26 pages**.
Several token-level rules came out of it and are easy to regress:
- `--primary-foreground` is NEAR-BLACK, not white. White on the brand cyan
  measures **2.86:1** (AA needs 4.5:1); near-black measures ~6.8:1. Every
  primary button in the app failed before this. Do not "fix" it back to white.
- **Never stack an opacity modifier on already-tinted text.** This caused two
  separate failures: `text-muted-foreground/60` in the sidebar (2.39:1) and
  `opacity-75` on attack-path labels (4.31:1). Use a token, not an opacity.
- `--sev-info` sits at 68% lightness because 58% measured 4.37:1 as chip text.
Icon-only buttons need an `aria-label`; Radix `SelectTrigger` needs one too (the
placeholder is not an accessible name). Decorative charts get `aria-hidden` AND
`tabIndex={-1}`/`rootTabIndex={-1}`, or they leave a tab stop inside hidden content.

Also: a link inside a paragraph must be underlined, not colour-only (WCAG 1.4.1);
`<main>` carries `tabIndex={0}` because it scrolls, and a scrollable region that
cannot be focused is unreachable by keyboard — it doubles as the skip-link target.

**The sweep now activates every tab.** Tabbed content mounts one panel at a
time, so visiting a route only ever measured the DEFAULT tab — a structural
blind spot, not a coverage gap. Two real defects lived for months in intelligence
panels the sweep had never once rendered: a `text-muted-foreground/50` timestamp
in the shared `ModuleHeader` measuring **2.65:1**, and a `max-h-48 overflow-auto`
region no keyboard could reach. Both are the exact failures the rules above
already name, which is the point — a rule nothing measures is a comment.

Careful with the fix for a scrollable region: `tabIndex={0}` makes it reachable,
but adding `role="group"` to a `<ul>` **overrides its implicit `list` role** and
orphans every `<li>` inside it (axe: `listitem`). Use `tabIndex` plus
`aria-label` on a list, and reserve `role="group"` for elements with no implicit
role to destroy.

Re-check with: axe-core injected via Playwright against the running app, sweeping
every route AND every tab within it. All must stay at zero.

### Bare-ID routes: the audit that found two cross-tenant reads
A "bare-ID" route carries an id but NO `:workspaceId`, so `requireWorkspaceRole`
cannot help — there is no workspace in the URL to derive. The handler must
resolve the object, read its `workspaceId`, and check membership itself.

Two did not, and both leaked across tenants:
- **`GET /api/scans/:id1/diff/:id2`** returned full finding objects — titles,
  descriptions, affected assets — for ANY two scan ids an authenticated user
  named. `compareScanFindings` resolves each scan, takes its `workspaceId`, and
  reads that workspace's findings; the caller was never consulted. It now checks
  BOTH scans (checking only the first leaks the other half) and refuses a
  cross-workspace diff, which is meaningless anyway.
- **`GET /api/asset-risk/:assetId/history`** did the same for any asset id.

`bare-id-authorization.test.ts` statically scans `server/routes` and fails when a
NEW bare-ID route appears without a guard, with an `EXEMPT` map for the genuine
exceptions (`/playbooks/:id` is static built-in data; `/api-keys/:id` scopes by
`userId`, which is ownership rather than workspace).

**`PATCH` and `DELETE /workspaces/:id` hand-roll their check and leaked the same
oracle for longer.** Both read
`if (!membership || membership.role !== "owner") return 403`, folding "not a
member" and "wrong role" into one answer — so iterating workspace ids and
watching for 403 confirmed which existed. An API smoke sweep exposed it by the
inconsistency: every READ of another tenant's workspace answered 404 while DELETE
answered 403. Both now answer 404 for a non-member and 403 only for a member with
an insufficient role, and a non-member can no longer tell an existing workspace
from a nonexistent one.

**`requireWorkspaceRole` now answers 404 for a non-member and 403 only for a
member with the wrong role.** It returned 403 for both, which is a membership
oracle: iterate workspace ids and every 403 is a confirmed tenant. The bare-ID
routes already used 404, so the same resource leaked or did not depending on
which route reached it. A member with an insufficient role already knows the
workspace exists, so 403 is the honest answer there.

### The container runs unprivileged, and CI proves it
The image ran as **root** while executing external scanners and driving a
browser against attacker-controlled pages — and root in the container is the
first half of most escapes. It now runs as `node` (uid 1000).

Order matters in the Dockerfile: `chown` before `USER`, and
`nuclei -update-templates` **after** it. Nuclei stores templates under the
RUNNING user's home, so updating them as root leaves the runtime user with a
scanner that silently finds nothing — a failure that looks like "no findings"
rather than an error.

CI's `image` job builds the container and asserts the uid is not 0, that nuclei
templates exist under the runtime user's `$HOME`, and that a `HEALTHCHECK` is
declared. Nothing built the image before, so a Dockerfile change could break the
only artefact customers actually run while every other job stayed green.

### Log redaction is keyed on field name, at three depths
Secrets reach logs by accident, not by mistake: an object is passed whole to a
log call and a field nobody considered travels with it. `server/logger.ts`
redacts by NAME so a secret is censored wherever it appears.

`refreshToken` was missing while `token` was present — and a refresh token is
the more valuable of the two, because it mints new sessions. `keyHash` was
missing. The OIDC/SIEM fields (`idToken`, `codeVerifier`, `clientSecret`,
`access_token`) were added with those features. Each name is expanded to
`name`, `*.name` and `*.*.name`, because pino's `*` matches exactly one level;
a secret nested deeper than that means the call site is logging a whole request
object, which is its own problem.

### Clamp pagination centrally — the open-coded version had three bugs
Eleven routes wrote `Math.min(parseInt(x) || 500, 5000)`, which has no LOWER
bound. All three consequences were reachable by typing a URL:
- `?limit=-5` produced **-5**: `-5` is truthy so `|| 500` never fired, and
  `Math.min` returned it — a negative SQL LIMIT and a 500 for the caller.
- `?limit=1e9` produced **1**, because `parseInt` stops at the `e`. An
  obviously over-large request quietly returned one row.
- `?offset=9999999999999999999` produced 1e19, past the bigint Postgres holds.

`parsePagination` / `parsePageParams` in `routes/response.ts` are now the only
places this is done. They use `Number`, not `parseInt`, so `"1e9"` is a number to
cap and `"12abc"` is not a number at all — and they clamp rather than reject,
because a caller asking past the cap wants as much as they can have.

**`Math.max(1, NaN)` is `NaN`.** The findings inbox computed its page that way,
so `?page=abc` sliced `NaN..NaN` and returned an **empty inbox with a 200 and a
correct-looking `total`** — an analyst reads that as "no findings", not as a
malformed request. `?pageSize=0` had a matching bug in the other direction: the
guard `ps === 0` could never fire because the clamp floored to 1 first, so it
returned a one-row page instead of the unpaged list the author intended.

That route also fetched with the storage default of 500 and then filtered in
memory, so a workspace with more findings silently lost the rest AND reported a
`total` derived from the truncated page — the same "the count reflects the page
size, not the data" bug the list endpoints were fixed for. It now fetches to an
explicit, named ceiling.

### Concurrency budgets are per-scan; the socket ceiling must be global
`httpConcurrency` is a PER-SCAN budget and `runWithStealth` builds a fresh
`StealthController` per scan, so the limit multiplied by however many scans ran
at once: the standard profile's 64 x the default `SCAN_CONCURRENCY=3` is **192
concurrent sockets** from one deployment — enough to exhaust file descriptors in
a small container, trip upstream limits, and get the egress address blocked.

For safe mode it was worse than a resource problem. An operator choosing
"low-and-slow" is stating an intent about the rate the TARGET sees, and three
concurrent safe scans quietly emitted three times it.

`stealth.ts` now holds a deployment-wide semaphore (`SCANNER_MAX_OUTBOUND`,
default 96) that every controller shares. **Pacing stays per-scan** — it is
per-target politeness and must not serialise unrelated targets — but sockets are
a property of the deployment, not of a scan. Per-scan slot is acquired FIRST:
taking the global slot first would let a safe-mode scan pin scarce global
capacity while blocked on its own limit of 2.

### Index, do not rescan, when matching findings to assets
`findingsForAsset` filtered the entire finding list once per asset — O(assets x
findings) with a `toLowerCase()` allocation on every pair, so 10,000 assets and
10,000 findings meant 10^8 comparisons for one page load. `indexFindingsByAsset`
inverts the three matching rules (exact, dot-suffix parent, `host:port` prefix)
and buckets findings once: O(findings x labels) to build, O(1) to look up.
Its test asserts equivalence against the original predicate rather than assuming
it, because an index that matches *almost* the same set is a silent wrong answer.

### The WebSocket had NO authentication at all
`/ws` accepted any connection with no credential, and its `subscribe` handler
set `client.workspaceId` straight from the client's own message with no
membership check. `broadcast` then matched on exactly that value — so **any
unauthenticated caller who knew or guessed a workspace id received that tenant's
live findings**: titles, descriptions, affected assets, pushed as they were
discovered. Both gates were missing at once: *who are you*, and *are you a
member of what you are asking for*. Demonstrated against the running server
before the fix.

Now: `subscribe` must carry a session token, it is validated with the same
`validateSession` the HTTP gate uses, membership is checked (superadmins bypass,
as elsewhere), and a non-member gets `not_found` rather than `forbidden` for the
same existence-hiding reason the HTTP routes answer 404. `broadcast` additionally
requires `client.userId` — set only after both checks pass — so an
unauthenticated socket can never be a recipient even if some future code path
sets `workspaceId` alone. Sockets that never authenticate are closed after a
grace period, and total connections are capped.

The client sends the token in its subscribe frame; it has no credential of its
own otherwise.

### Scan cancellation was plumbed but unreachable
`checkAborted(signal)` sat between every phase and `signal` was passed into every
`runWithConcurrency` — but `scanOptions.signal` was hardcoded `undefined` and no
route ever asked to cancel. A Gold scan aimed at the wrong domain ran its full
thirty-plus minutes with no way to stop the outbound traffic.

`POST /api/scans/:id/cancel` now exists, backed by an in-memory registry of
in-flight `AbortController`s (in memory because a controller cannot survive a
restart, and a scan whose process died is not running anyway). Viewers may watch
a scan but not stop one.

**A cancellation is recorded as `cancelled`, not `failed`.** It previously wrote
`status: "failed"` even while setting the message "Scan was cancelled", which put
a deliberate operator action into the failure count every dashboard and alert
reads — and no failure alert is emitted, because the person who pressed the
button does not need paging about their own action.

### No `getAllFindings()`
It existed with **zero callers**: an unbounded select across every workspace,
which becomes a cross-tenant read the moment someone reaches for the
convenient-sounding name. Removed rather than left as a trap. Findings are always
fetched per workspace with a caller-chosen page size.

### Error Handling
- Route catch blocks return generic messages — never expose `err.message` to clients
- Internal errors are logged via pino (`server/logger.ts`) with full context
- Centralized error handler in `server/routes/response.ts`
- Auth middleware: DB errors return "Internal server error", actual auth failures return "Authentication error"

### Scan Pipeline
```
POST /api/scans
  → triggerScan() (server/scan-trigger.ts)
  → enqueueScan() (server/scan-queue.ts)
  → runEASMScan() or runOSINTScan() (server/scanner/)
  → findings written to DB
  → WebSocket notification via server/notifications.ts
```

### Response Format
All API errors use `sendError(res, status, message)` from `server/routes/response.ts`:
```json
{ "success": false, "error": "...", "statusCode": N }
```

## File Map

```
server/
  index.ts           — Express app setup, rate limiting, middleware
  routes/
    index.ts         — Route registration, auth gate, asset bare-ID routes
    auth.ts          — Login, register, refresh, logout
    sso.ts           — OIDC single sign-on (mounted BEFORE requireAuth)
    auth-middleware.ts — requireAuth, requireWorkspaceRole, requireRole
    workspaces.ts    — Workspace CRUD + asset sub-routes
    scans.ts         — Scan CRUD + trigger
    findings.ts      — Finding CRUD + AI enrichment
    admin.ts         — Admin ops, monitoring, doctor, status
    audit.ts         — Audit log viewer (admin only) + action facets
    health.ts        — /healthz (liveness) and /readyz (DB-backed readiness)
    brand-threats.ts — Lookalike/typosquat domain sweeps
    cases.ts         — Case CRUD, finding links, per-workspace references
    api-key-scope.ts — Enforces api_keys.scope on every /api request
    response.ts      — sendError, sendNotFound, errorHandler
    schemas.ts       — All Zod schemas
  storage.ts         — IStorage interface + DatabaseStorage implementation
  scanner/
    index.ts         — runEASMScan, runOSINTScan, buildReconModules
    easm-scan.ts     — Main EASM orchestrator
    osint-scan.ts    — Main OSINT orchestrator
    http.ts          — httpGet/httpRequest helpers, fetchSitemapUrls (SSRF guard)
    response-oracle.ts  — soft-404 auto-calibration; a 200 is not evidence
    body-signatures.ts  — positive proof a body IS the artefact being named
    credential-detection.ts — key formats, placeholders, entropy, redaction
    per-asset-findings.ts — attributes findings to the HOST they were seen on
    asn-expansion.ts    — BGP routed footprint; attribution gate refuses by default
    crawler.ts          — endpoint inventory (katana when installed, native otherwise)
    http-probe.ts       — enriched host fingerprint (httpx when installed, native otherwise)
    js-library-cves.ts  — served client-side libraries vs OSV.dev advisories
    permutation.ts      — candidates from the target's own naming convention
    dependency-confusion.ts — unclaimed internal package names (npm + PyPI)
    favicon.ts          — Shodan-compatible favicon hash; groups an estate
    csp-analysis.ts     — CSP CONTENT, not presence (nonce/strict-dynamic aware)
    mobile-app-monitor.ts — app-store apps using the brand; sellerUrl is the only proof
    breach-exposure.ts  — public breach catalogue; metadata only, never accounts
    typosquat.ts     — Lookalike domain generation + DNS confirmation
    ransomware-watch.ts — Leak-site exposure vs. the public ransomware.live corpus
    code-leak-watch.ts  — Public-repo search for org identifiers + secret scan
    browser-profile.ts  — Coherent browser identities for outbound requests
    finding-taxonomy.ts — kind (security|control|recon) x category, single source
    spf-dmarc-deep.ts   — SPF lookup budget (RFC 7208 §4.6.4) + DMARC sp/rua
    caa-analysis.ts     — Which CAs may issue; absence is the finding
    dnssec.ts           — Real DNSKEY/DS/AD check over DoH (see below)
    zone-transfer.ts    — AXFR over the wire; node cannot ask for it
    tls-protocols.ts    — Versions a host ACCEPTS, not the one it negotiated
    mail-transport-security.ts — MTA-STS, TLS-RPT, BIMI
    srv-discovery.ts    — Service records, incl. exposed AD infrastructure
  evidence/
    browser-stealth.ts  — Playwright anti-detection launch args + init script
    browser-engine.ts   — Pluggable engine: stock | patchright | cloakbrowser
  audit.ts           — Audit trail: logAudit + auditMutations middleware
  totp.ts            — RFC 6238 TOTP (base32, HOTP, constant-time verify)
  sso-oidc.ts        — OIDC discovery, PKCE, full ID-token verification
  siem-export.ts     — ECS/CEF egress over HTTPS or syslog; operator-configured
  scan-slots.ts      — Cross-instance scan concurrency via Postgres advisory locks
  sla-monitor.ts     — Hourly sweep marking findings past their remediation deadline
  retention-sweep.ts — Daily sweep applying each workspace's data-retention policy
  rate-limit-store.ts — Postgres-backed store so sensitive limits are global
  case-workflow.ts   — Case lifecycle rules (pure; no DB, so it is testable)
  scan-queue.ts      — Durable queue (Postgres, FOR UPDATE SKIP LOCKED)
  scan-trigger.ts    — triggerScan entry point
  notifications.ts   — WebSocket event emitters
  ai-service.ts      — Ollama integration
  report-export.ts   — CSV/Excel export (with formula injection protection)
  crypto.ts          — encrypt/decrypt for stored secrets

shared/
  schema.ts          — Drizzle schema (all tables)
  scoring.ts         — Security score computation
  risk-factors.ts    — 9-factor rating; three states; the only A-F band table

client/src/
  pages/             — React pages (Dashboard, EASM, OSINT, Reports, etc.)
  components/        — shadcn/ui + custom components
  hooks/
    use-list-query.ts — Paginated fetch that PRESERVES the server's `total`
  lib/
    queryClient.ts   — React Query setup + error handling
    severity.ts      — Severity colour/label source of truth (--sev-* tokens)

tests/
  unit/server/       — Vitest unit tests
  unit/client/       — Vitest tests for client-side logic (query envelope unwrap)
  e2e/               — Playwright E2E tests (17 tests, incl. axe a11y sweep)
    pages/           — Page Object Models
    global-setup.ts  — Cached auth state
```

## Database Schema (key tables)

- `users` — id, username, passwordHash, role (user/admin/superadmin)
- `sessions` — id, userId, token, expiresAt
- `workspaces` — id, name (domain), description, status
- `workspace_members` — workspaceId, userId, role (owner/admin/analyst/viewer)
- `scans` — id, workspaceId, target, status, type, mode
- `findings` — id, workspaceId, scanId, title, severity, category, kind, status
  - `kind` is security | control | recon. `category` says WHICH kind of thing,
    `kind` says WHETHER it is a problem at all. Only `security` reaches the
    triage inbox or affects the score — a control being in place is good news,
    and deducting for it would score a well-configured domain below an empty
    one. Classification lives in `server/scanner/finding-taxonomy.ts`; repair
    stored rows with `scripts/backfill-finding-kind.mts` (dry-run by default).
- `assets` — id, workspaceId, type, value
- `api_keys` — id, userId, keyHash, name, expiresAt, revokedAt
- `scheduled_scans` — id, workspaceId, cronExpression, enabled
- `webhook_endpoints` — id, workspaceId, url (HTTPS only), secret (encrypted)
- `scan_queue` — durable queue; claimed with FOR UPDATE SKIP LOCKED + lease
- `rate_limits` — shared fixed-window counters for the sensitive limiters
- `cases` / `case_findings` — units of work, with owner + SLA, linked to findings

**Auth columns worth knowing:**
- `sessions.token` / `refresh_token` store SHA-256 HASHES, never the token
- `sessions.rotated_at` — a spent refresh row is KEPT so reuse stays detectable
- `sessions.family_id` — groups a login's rotation chain; a replay revokes it all
- `users.failed_login_attempts` / `locked_until` — per-account lockout, which an
  IP rate limit cannot provide against distributed credential stuffing

## Coding Conventions

- **No `err.message` to clients** — use generic messages in catch blocks
- **No mutation** — spread for updates (`{ ...existing, field: value }`)
- **Workspace isolation** — every bare-ID route must check membership before returning data
- **Zod for all input** — validate at route boundary, never trust raw `req.body`
- **Rate limits** — login 10/min, register 3/min, scan 5/min; general **600/min**.
  600 is not slack: this is a data-dense SPA (the dashboard alone fires 10
  queries), and browsing eight pages measured 51 requests in 12s — ~254/min at a
  normal pace. At the old 100/min an analyst hit 429 after roughly fifteen page
  views and the app looked broken. The general limiter is a blunt DoS guard, not
  an auth control; the sensitive endpoints carry their own tighter shared limits.
  The three sensitive limiters use `PostgresRateLimitStore`, so the budget is
  shared across instances — the default MemoryStore made "5 logins/min" mean
  5 x replicas, backwards for a control that exists to slow credential stuffing.
  The general 100/min throttle stays in memory on purpose: a database round trip
  on every API request is not worth the precision. The store fails OPEN, because
  a counter outage must not deny all traffic; the per-account lockout is the
  control that does not fail open.
- **Imports** — use `.js` extension in server imports (ESM)

## Common Pitfalls

- Running tests on Windows B: drive requires `pool: "vmThreads"` in `vitest.config.ts` — already configured
- `workspace_members` table must exist — run `npm run db:push` after schema changes
- Playwright tests use cached auth state (`tests/e2e/.auth-state.json`). `global-setup`
  now probes the cached token before reusing it, because a session can be invalidated
  well inside the 23h cache window — logging in as `auth-shared@e2e.local` by hand
  supersedes it. Without that probe the app clears the dead token on the first 401 and
  the logout test fails with "auth_token is null", which reads like a logout bug rather
  than a stale fixture.
- The Playwright global-teardown deletes any workspace whose members are ALL `@e2e.local`.
  A workspace created for manual verification with one of those accounts will be removed
  by the next `npx playwright test` — which is correct, but explains a 403 on a workspace
  that existed minutes earlier.
- The `startMonitoring()` function must receive `userId` when creating new workspaces to avoid orphaned workspaces
