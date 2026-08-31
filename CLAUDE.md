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
npm test                   # Vitest unit tests — 700 tests / 47 files, all must pass
npx playwright test        # E2E tests — 10 tests, all must pass
```

The E2E suite needs the app on port 5050 and Postgres on 5433 (`docker compose up -d db`,
then `PORT=5050 npm run dev`). Playwright reuses an already-running server.

Or use the convenience script:
```bash
bash scripts/inspect.sh
```

## Key Architecture Decisions

### Auth & Workspace Isolation
- Every `/api` route after `app.use("/api", requireAuth)` requires a valid session
- All workspace-scoped resources check `storage.getWorkspaceMember(workspaceId, userId)` — returning 404 (not 403) if the user is not a member, to avoid leaking resource existence
- `POST /workspaces` adds the creating user as "owner" via `storage.addWorkspaceMember()`
- `GET /workspaces` returns only workspaces the user is a member of (superadmins see all)
- Superadmins bypass `requireWorkspaceRole` checks but not `requireAuth`

### SSRF Prevention
- All outbound HTTP to user-controlled URLs goes through `isPrivateHost()` (DNS-based, fail-closed)
- Applies to: webhook URLs, Jira baseUrl, sitemap `<loc>` URLs
- Scanner has its own SSRF controls in `server/scanner/http.ts`

### Audit Trail
- `auditMutations` (server/audit.ts) is mounted at `/api` after `requireAuth` and
  records EVERY successful non-GET request — a new route is audited the moment it
  is mounted, without the author remembering to instrument it
- Authentication outcomes are logged explicitly in `routes/auth.ts` (`login`,
  `login_failed`, `logout`, `user_registered`, `mfa_challenge_failed`), because a
  failed login is a 401 that the middleware deliberately ignores
- `logAudit` never throws: a failed audit write must not break the request

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
Three features shipped with full implementations that nothing ever called. Each
looked complete in the code and did nothing at runtime:
- `logAudit` — audit_logs had 0 rows
- `enqueueScan` / `startQueuePoller` — no concurrency limit existed at all
- `checkSLABreaches` / `computeDueDate` — 0 of 126 findings had a due date

All three are now wired. **Before trusting any feature here, grep for a caller.**

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

### Dependencies
`npm audit --audit-level=high` gates CI, so a HIGH or CRITICAL advisory blocks
the build. It went from 23 advisories (11 high) to 6 moderate / 0 high.

`drizzle-orm` was upgraded 0.39 → 0.45.2 to clear GHSA-gpj5-g38j-94v9, a SQL
injection via improperly escaped identifiers. It was NOT exploitable here — there
is no `sql.raw`, no `sql.identifier`, and no user input reaching a column or sort
position — but leaving a known SQLi in the ORM of a security product is not a
posture worth defending. If you ever add a dynamic identifier, that assessment
stops holding.

The two remaining moderates (`drizzle-kit`, `exceljs`) are only fixable by
breaking majors and are deliberately left; the gate is set at high so the
pipeline does not go permanently red over them.

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

Re-check with: axe-core injected via Playwright against the running app, sweeping
every route. All 26 must stay at zero.

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
    auth-middleware.ts — requireAuth, requireWorkspaceRole, requireRole
    workspaces.ts    — Workspace CRUD + asset sub-routes
    scans.ts         — Scan CRUD + trigger
    findings.ts      — Finding CRUD + AI enrichment
    admin.ts         — Admin ops, monitoring, doctor, status
    audit.ts         — Audit log viewer (admin only) + action facets
    health.ts        — /healthz (liveness) and /readyz (DB-backed readiness)
    brand-threats.ts — Lookalike/typosquat domain sweeps
    cases.ts         — Case CRUD, finding links, per-workspace references
    response.ts      — sendError, sendNotFound, errorHandler
    schemas.ts       — All Zod schemas
  storage.ts         — IStorage interface + DatabaseStorage implementation
  scanner/
    index.ts         — runEASMScan, runOSINTScan, buildReconModules
    easm-scan.ts     — Main EASM orchestrator
    osint-scan.ts    — Main OSINT orchestrator
    http.ts          — httpGet helper, fetchSitemapUrls (with SSRF guard)
    typosquat.ts     — Lookalike domain generation + DNS confirmation
    ransomware-watch.ts — Leak-site exposure vs. the public ransomware.live corpus
    code-leak-watch.ts  — Public-repo search for org identifiers + secret scan
    browser-profile.ts  — Coherent browser identities for outbound requests
  evidence/
    browser-stealth.ts  — Playwright anti-detection launch args + init script
    browser-engine.ts   — Pluggable engine: stock | patchright | cloakbrowser
  audit.ts           — Audit trail: logAudit + auditMutations middleware
  totp.ts            — RFC 6238 TOTP (base32, HOTP, constant-time verify)
  scan-slots.ts      — Cross-instance scan concurrency via Postgres advisory locks
  sla-monitor.ts     — Hourly sweep marking findings past their remediation deadline
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

client/src/
  pages/             — React pages (Dashboard, EASM, OSINT, Reports, etc.)
  components/        — shadcn/ui + custom components
  hooks/
    use-list-query.ts — Paginated fetch that PRESERVES the server's `total`
  lib/
    queryClient.ts   — React Query setup + error handling
    severity.ts      — Severity colour/label source of truth (--sev-* tokens)

tests/
  unit/server/       — Vitest unit tests (47 files, 700 tests)
  e2e/               — Playwright E2E tests (10 tests)
    pages/           — Page Object Models
    global-setup.ts  — Cached auth state
```

## Database Schema (key tables)

- `users` — id, username, passwordHash, role (user/admin/superadmin)
- `sessions` — id, userId, token, expiresAt
- `workspaces` — id, name (domain), description, status
- `workspace_members` — workspaceId, userId, role (owner/admin/analyst/viewer)
- `scans` — id, workspaceId, target, status, type, mode
- `findings` — id, workspaceId, scanId, title, severity, category, status
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
- **Rate limits** — auth endpoints: 5/min login, 3/min register; scan: 5/min; general: 100/min.
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
- Playwright tests use cached auth state (`tests/e2e/.auth-state.json`) — delete it if login credentials change
- The `startMonitoring()` function must receive `userId` when creating new workspaces to avoid orphaned workspaces
