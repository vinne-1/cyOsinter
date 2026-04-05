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
npm test                   # Vitest unit tests — 259 tests, all must pass
npx playwright test        # E2E tests — 10 tests, all must pass
```

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
    response.ts      — sendError, sendNotFound, errorHandler
    schemas.ts       — All Zod schemas
  storage.ts         — IStorage interface + DatabaseStorage implementation
  scanner/
    index.ts         — runEASMScan, runOSINTScan, buildReconModules
    easm-scan.ts     — Main EASM orchestrator
    osint-scan.ts    — Main OSINT orchestrator
    http.ts          — httpGet helper, fetchSitemapUrls (with SSRF guard)
  scan-queue.ts      — In-memory queue with concurrency control
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
  hooks/             — React Query hooks for all API calls
  lib/
    queryClient.ts   — React Query setup + error handling

tests/
  unit/server/       — Vitest unit tests (16 files, 259 tests)
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

## Coding Conventions

- **No `err.message` to clients** — use generic messages in catch blocks
- **No mutation** — spread for updates (`{ ...existing, field: value }`)
- **Workspace isolation** — every bare-ID route must check membership before returning data
- **Zod for all input** — validate at route boundary, never trust raw `req.body`
- **Rate limits** — auth endpoints: 5/min login, 3/min register; scan: 5/min; general: 100/min
- **Imports** — use `.js` extension in server imports (ESM)

## Common Pitfalls

- Running tests on Windows B: drive requires `pool: "vmThreads"` in `vitest.config.ts` — already configured
- `workspace_members` table must exist — run `npm run db:push` after schema changes
- Playwright tests use cached auth state (`tests/e2e/.auth-state.json`) — delete it if login credentials change
- The `startMonitoring()` function must receive `userId` when creating new workspaces to avoid orphaned workspaces
