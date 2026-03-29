# Cyshield - Cybersecurity Platform

## Overview
Professional Cybersecurity Platform as a Service providing:
- External Attack Surface Management (EASM)
- OSINT exposure discovery (dorking + public signals)
- Findings Inbox with lifecycle + evidence + scoring
- High-quality deterministic reporting + evidence packs

## Architecture
- **Frontend**: React + Vite + TailwindCSS + shadcn/ui
- **Backend**: Express.js with REST API
- **Database**: PostgreSQL with Drizzle ORM
- **Routing**: wouter (client-side)
- **State Management**: TanStack React Query

## Project Structure
```
client/src/
  App.tsx               - Main app with sidebar layout
  lib/domain-context.tsx - Workspace context (useDomain/useWorkspace hooks)
  components/
    app-sidebar.tsx     - Navigation sidebar
    domain-selector.tsx - Workspace selector dropdown
    theme-provider.tsx  - Dark/light theme
    severity-badge.tsx  - Severity/status badge components
  pages/
    dashboard.tsx       - Security overview dashboard with scan launcher
    easm.tsx            - Attack surface management
    osint.tsx           - OSINT discovery
    findings.tsx        - Findings inbox with lifecycle + evidence display
    intelligence.tsx    - 12 intelligence modules
    reports.tsx         - Report generation

server/
  index.ts             - Express server entry point
  routes.ts            - API routes (workspace-scoped)
  scanner.ts           - Real network reconnaissance engine
  storage.ts           - Database storage layer
  db.ts                - Database connection
  seed.ts              - Minimal seed (no fake data)

shared/
  schema.ts            - Drizzle schema + Zod validation
```

## Scanner (server/scanner.ts)
Real network reconnaissance engine - NO fabricated data. Only verified true positives.
- **EASM Scan**: crt.sh subdomain enumeration, DNS resolution, HTTP probing, SSL certificate inspection, security header analysis, server info leak detection
- **OSINT Scan**: SPF/DMARC/DKIM analysis, sensitive path detection (.env, .git, server-status, robots.txt, swagger), email security posture
- All findings include real evidence with: source attribution, verification timestamps, clickable URLs, actual response snippets

## Workspace Architecture
- Multi-tenant workspace model: each target domain gets its own workspace
- API pattern: `/api/workspaces/:workspaceId/resource` for all scoped data
- POST `/api/scans` auto-creates workspaces when scanning new domains
- Frontend uses `useDomain()` hook with `selectedWorkspaceId` for all queries
- All queries guarded with `enabled: !!selectedWorkspaceId`

## Data Models
- **Workspaces**: Isolated containers per target domain
- **Assets**: Domains, subdomains, IPs, services, certificates (real discoveries)
- **Scans**: EASM and OSINT scan types with lifecycle
- **Findings**: Verified security findings with real evidence, CVSS scoring, status lifecycle
- **Reports**: Executive summary, full report, evidence pack types
- **Recon Modules**: Intelligence data from real scans (web_presence, attack_surface, cloud_footprint, exposed_content)

## API Endpoints
- `GET/POST /api/workspaces` - Workspace CRUD
- `GET /api/workspaces/:id/assets` - Workspace-scoped assets
- `POST /api/scans` - Scan creation (auto-creates workspace)
- `GET /api/workspaces/:id/scans` - Workspace-scoped scans
- `GET /api/workspaces/:id/findings` - Workspace-scoped findings
- `PATCH /api/findings/:id` - Finding status updates
- `GET/POST /api/workspaces/:id/reports` - Workspace-scoped reports
- `GET /api/workspaces/:id/recon-modules` - Intelligence modules

## Design
- Cybersecurity-themed dark mode as default
- Inter font family, JetBrains Mono for code
- Blue/cyan primary colors
- Professional severity color coding (red/orange/yellow/blue)

## Recent Changes
- 2026-02-12: Replaced fake scan engine with real network reconnaissance scanner
- 2026-02-12: All findings now require verified evidence (URLs, response data, timestamps)
- 2026-02-12: Workspace-based multi-tenancy with scoped API routes
- 2026-02-12: Initial MVP build with all core features
