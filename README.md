<div align="center">

<img src="client/public/logo.svg" alt="cyOsinter Logo" width="100" />

# cyOsinter

**External Attack Surface Management · OSINT Discovery · Threat Intelligence · AI-Powered Reporting**

[![Node.js](https://img.shields.io/badge/Node.js-18%2B-339933?style=flat-square&logo=node.js&logoColor=white)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-14%2B-4169E1?style=flat-square&logo=postgresql&logoColor=white)](https://www.postgresql.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

---

*A professional-grade cybersecurity platform for discovering, mapping, and managing your external attack surface — powered by real network reconnaissance, OSINT intelligence, and local AI.*

</div>

---

## Screenshots

> All screenshots below are live results from scanning **hackthissite.org** — a legal CTF/security training platform.

| Login | Dashboard — 16 assets · 16 findings · Score 12/100 |
|-------|-----------|
| ![Login page](docs/screenshots/login.png) | ![Dashboard overview](docs/screenshots/dashboard-overview.png) |

| Dashboard — Severity Distribution & Intel Overview | Attack Surface (EASM) — Gold scan completed |
|-----------------------|-----------------|
| ![Dashboard stats](docs/screenshots/dashboard-stats.png) | ![EASM scanning page](docs/screenshots/easm.png) |

| EASM — 16 Discovered Assets (subdomains, IPs) | OSINT Discovery — 2 Leaked Credentials · 2 Emails |
|-----------------------|-----------------|
| ![EASM assets list](docs/screenshots/easm-assets.png) | ![OSINT discovery page](docs/screenshots/osint.png) |

| Findings Inbox — 2 Critical · 1 High · 5 Medium | Full Findings List |
|----------|-------------|
| ![Findings view](docs/screenshots/findings.png) | ![Findings list](docs/screenshots/findings-list.png) |

| Critical Finding — /.git-credentials CVSS 9.8 | Intelligence — 13 modules · Surface Risk 50/100 |
|----------|-------------|
| ![Critical finding detail](docs/screenshots/finding-critical-detail.png) | ![Intelligence panel](docs/screenshots/intelligence.png) |

| Reports — Full Security Assessment | Threat Intel — IP Reputation Lookup |
|---------|-------------|
| ![Reports page](docs/screenshots/reports.png) | ![Threat intelligence](docs/screenshots/threat-intel.png) |

---

## What is cyOsinter?

cyOsinter is a self-hosted **External Attack Surface Management (EASM)** and **OSINT** platform. Point it at a domain and it automatically enumerates subdomains, probes HTTP/HTTPS services, analyzes SSL certificates, checks security headers, validates SPF/DMARC records, discovers exposed paths, and correlates findings into a prioritized risk view — all stored in your own PostgreSQL database, with no data leaving your infrastructure.

### Core capabilities

| Capability | Description |
|---|---|
| **EASM Scanning** | Subdomain enumeration, DNS resolution, HTTP/S probing, SSL/TLS analysis, port discovery |
| **OSINT Discovery** | WHOIS, SPF/DMARC, security headers, sensitive path detection, email exposure |
| **Nuclei Integration** | Template-based vulnerability scanning with ProjectDiscovery Nuclei |
| **Threat Intelligence** | IP reputation via AbuseIPDB & VirusTotal, CVE lookup via NIST NVD |
| **AI Insights** | Finding enrichment, risk analysis, and report summaries via local Ollama LLM |
| **Continuous Monitoring** | Automated periodic rescans with delta alerting |
| **Report Generation** | PDF, Excel, and JSON exports with executive summary and evidence packs |
| **Multi-Workspace** | Isolate scans and findings per client, project, or domain |
| **Nmap Import** | Parse and ingest existing Nmap XML scan results |

![Dashboard Overview — hackthissite.org scan: 16 assets, 16 findings, Security Score 12/100](docs/screenshots/dashboard-overview.png)

![Severity Distribution & Intelligence Overview — Surface Risk 50/100](docs/screenshots/dashboard-stats.png)

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      Browser Client                      │
│         React 18 · Vite · Tailwind · Radix UI            │
│  Dashboard · EASM · OSINT · Findings · Intelligence ·    │
│           Reports · AI Insights · Integrations           │
└────────────────────────┬────────────────────────────────┘
                         │ HTTP / REST API
┌────────────────────────▼────────────────────────────────┐
│                   Express 5 Server                       │
│   Routes · Scanner · AI Service · CVE Service            │
│   Scoring · PDF/Excel Export · Continuous Monitoring     │
└──────────┬──────────────────────────┬───────────────────┘
           │                          │
┌──────────▼──────────┐   ┌──────────▼──────────────────┐
│    PostgreSQL 14+   │   │       Ollama (optional)       │
│   Drizzle ORM       │   │   Local LLM (tinyllama etc.)  │
│   Workspaces        │   │   AI enrichment & summaries   │
│   Assets / Scans    │   └─────────────────────────────┘
│   Findings / Reports│
└─────────────────────┘
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | React 18, Vite 7, TypeScript, Tailwind CSS, Radix UI, TanStack Query, Wouter, Recharts, Framer Motion |
| **Backend** | Node.js 18+, Express 5, TypeScript, tsx |
| **Database** | PostgreSQL 14+, Drizzle ORM |
| **Validation** | Zod |
| **AI** | Ollama (local LLM — tinyllama, llama3.2, etc.) |
| **Scanning** | Custom DNS/HTTP engine, Nuclei, Nmap parser |
| **Reporting** | jsPDF, xlsx |
| **Containerization** | Docker, Docker Compose |

---

## Quick Start

### Prerequisites

- **Node.js** 18.x or 20.x
- **npm** 9.x+
- **PostgreSQL** 14+ (or Docker)

### 1 — Clone & install

```bash
git clone https://github.com/vinne-1/cyOsinter.git
cd cyOsinter
npm install
```

### 2 — Configure environment

```bash
cp .env.example .env
```

Edit `.env` and set your database connection:

```env
DATABASE_URL="postgresql://postgres:yourpassword@localhost:5432/cyshield"
PORT=5000
NODE_ENV=development
```

### 3 — Start PostgreSQL

**Option A — Docker (recommended):**
```bash
docker compose up -d db
```

**Option B — Local PostgreSQL:**
```bash
psql -U postgres -c "CREATE DATABASE cyshield;"
```

### 4 — Push schema & run

```bash
npm run db:push   # create tables
npm run dev       # start dev server → http://localhost:5000
```

---

## Production Deployment

### One command (recommended) — full stack, zero config

```bash
docker compose up -d --build
```

That's it. This builds the app image (Node + Nuclei + Chromium for report
evidence), starts PostgreSQL and Ollama, **applies the database schema
automatically**, and seeds a default admin. Then open:

> **http://localhost:5050**
>
> Sign in with **`admin@cyshield.local`** / **`ChangeMe123!`** (change these via
> `SEED_ADMIN_EMAIL` / `SEED_ADMIN_PASSWORD`, or just register your own account).

No manual `db:push`, no port juggling — the container listens on 5000 internally
and is published on host port **5050** (override with `APP_HOST_PORT`). The
database is published on **5433** (override with `DB_HOST_PORT`) to avoid clashing
with a local Postgres. Stop with `docker compose stop`; reset everything
(including data) with `docker compose down -v`.

Optional API keys (AbuseIPDB, VirusTotal, Tavily, NVD) enrich the intelligence
and reports — add them to a `.env` file and uncomment the `env_file:` lines in
`docker-compose.yml`.

### Manual (without Docker)

```bash
npm run build          # compile server + bundle client → dist/
npm run start          # run production server
```

---

## Configuration Reference

All configuration is via environment variables in `.env`:

### Required

| Variable | Example | Description |
|---|---|---|
| `DATABASE_URL` | `postgresql://postgres:pass@localhost:5432/cyshield` | PostgreSQL connection string |
| `PORT` | `5000` | Port the server listens on |
| `NODE_ENV` | `development` or `production` | Runtime environment |

### Threat Intelligence (optional)

| Variable | Description | Get it at |
|---|---|---|
| `ABUSEIPDB_API_KEY` | IP reputation and abuse reports | [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api) |
| `VIRUSTOTAL_API_KEY` | Malware and URL analysis | [virustotal.com](https://www.virustotal.com) |
| `NVD_API_KEY` | NIST CVE database (50 req/30s with key vs 5 without) | [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) |
| `TAVILY_API_KEY` | Web search for AI threat intel enrichment | [tavily.com](https://tavily.com) |

### AI / Ollama (optional)

| Variable | Default | Description |
|---|---|---|
| `OLLAMA_ENABLED` | `0` | Set to `1` to enable AI features |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama API endpoint |
| `OLLAMA_MODEL` | `tinyllama` | Model to use for inference |

---

## AI Setup (Ollama)

cyOsinter supports local AI via [Ollama](https://ollama.com) for finding enrichment, risk analysis, and report summaries — no cloud API keys required.

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model
ollama pull tinyllama        # fast, low resource
# or
ollama pull llama3.2         # higher quality

# Start Ollama (if not auto-started)
ollama serve
```

Then in cyOsinter: **Integrations → Ollama → Enable AI → Save**

![AI Insights](docs/screenshots/ai-insights.png)

![Integrations & Settings](docs/screenshots/integrations.png)

Or set in `.env`:
```env
OLLAMA_ENABLED=1
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=tinyllama
```

---

## Project Structure

```
cyOsinter/
├── client/                     # React frontend
│   └── src/
│       ├── pages/              # Dashboard, EASM, Findings, Intelligence, Reports…
│       ├── components/         # Sidebar, domain selector, severity badges, UI kit
│       └── lib/                # Query client, domain context, PDF generation
├── server/                     # Express backend
│   ├── index.ts                # App entry point
│   ├── routes.ts               # All API routes
│   ├── scanner.ts              # EASM & OSINT scan engine
│   ├── ai-service.ts           # Ollama LLM integration
│   ├── cve-service.ts          # NIST NVD CVE lookup
│   ├── continuous-monitoring.ts# Scheduled rescans
│   ├── report-pdf.ts           # PDF report generation
│   ├── report-export.ts        # Excel/CSV export
│   ├── scoring.ts              # Surface risk scoring
│   ├── api-integrations.ts     # AbuseIPDB, VirusTotal, BGPView
│   ├── parsers/nmap.ts         # Nmap XML parser
│   └── wordlists/              # Subdomain & directory wordlists
├── shared/
│   ├── schema.ts               # Drizzle DB schema (all tables)
│   └── scoring.ts              # Security score algorithm
├── docs/                       # Architecture & feature docs
├── script/                     # Build, e2e, and test scripts
├── docker-compose.yml          # Full-stack Docker orchestration
├── Dockerfile                  # Production container build
└── .env.example                # Environment variable template
```

---

## Authentication

cyOsinter uses session-based authentication with Bearer tokens. All API endpoints (except auth routes) require authentication.

### Getting Started

![Login & Registration](docs/screenshots/login.png)

1. **Register** an account at the login page or via `POST /api/auth/register`
2. **Login** to receive a Bearer token
3. Include the token in all API requests: `Authorization: Bearer <token>`

### Auth Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/auth/register` | Create a new account |
| `POST` | `/api/auth/login` | Login and receive a Bearer token |
| `POST` | `/api/auth/refresh` | Refresh an expiring token |
| `POST` | `/api/auth/logout` | Invalidate the current session |
| `GET` | `/api/auth/me` | Get the current user profile |

### Workspace Roles

Resources are scoped to workspaces. Users are assigned roles per workspace:

| Role | Permissions |
|---|---|
| **Owner** | Full access, can delete workspace, manage members |
| **Admin** | Manage scans, findings, reports, integrations |
| **Analyst** | Run scans, manage findings, create reports |
| **Viewer** | Read-only access to findings and reports |

### API Keys

For programmatic access, create API keys at **Settings -> API Keys**. Keys use the `csk_` prefix and are passed via the `Authorization: Bearer csk_...` header.

---

## API Overview

All endpoints are prefixed with `/api`. Workspaced resources use `/api/workspaces/:workspaceId/...`. All endpoints (except `/api/auth/*`) require a valid Bearer token.

**EASM Attack Surface Scanning**

![Attack Surface Scanning — 1 Domain, 3 Subdomains, 11 IPs discovered on hackthissite.org](docs/screenshots/easm.png)

![Discovered Assets — www, git, api subdomains + 137.74.187.x IP block](docs/screenshots/easm-assets.png)

**OSINT Discovery**

![OSINT Discovery — 2 Leaked Credentials, 2 Email addresses exposed](docs/screenshots/osint.png)

**Findings Management**

![Findings Inbox — 2 Critical, 1 High, 5 Medium, 5 Low](docs/screenshots/findings.png)

![Findings List — XSS, Open Redirect, CORS Wildcard, Clickjacking, .git-credentials](docs/screenshots/findings-list.png)

![Critical Finding Detail — Exposed /.git-credentials file, CVSS 9.8](docs/screenshots/finding-critical-detail.png)

**Intelligence & Threat Intel**

![Intelligence Panel — 13 modules populated, Surface Risk 50/100](docs/screenshots/intelligence.png)

![Threat Intel — IP reputation lookup for 137.74.187.145](docs/screenshots/threat-intel.png)

**Reports**

![Reports — hackthissite.org Full Security Assessment, 16 findings](docs/screenshots/reports.png)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/workspaces` | List all workspaces |
| `POST` | `/api/workspaces` | Create workspace |
| `DELETE` | `/api/workspaces/:id` | Delete workspace (owner only) |
| `POST` | `/api/scans` | Start EASM, OSINT, or full scan |
| `GET` | `/api/workspaces/:id/scans` | List scans for workspace |
| `GET` | `/api/workspaces/:id/findings` | List findings |
| `PATCH` | `/api/findings/:id` | Update finding status/assignee |
| `POST` | `/api/workspaces/:id/findings/:fid/enrich` | AI-enrich a finding |
| `POST` | `/api/workspaces/:id/findings/:fid/cve-lookup` | Look up CVEs for a finding |
| `POST` | `/api/workspaces/:id/findings/:fid/analyze` | Deep AI analysis |
| `GET` | `/api/workspaces/:id/recon-modules` | OSINT intelligence modules |
| `POST` | `/api/workspaces/:id/reports` | Generate report |
| `GET` | `/api/workspaces/:id/reports` | List reports |
| `POST` | `/api/continuous-monitoring/start` | Start automated monitoring |
| `POST` | `/api/continuous-monitoring/stop` | Stop monitoring |
| `GET` | `/api/workspaces/:id/ip-enrichment` | IP reputation data |
| `POST` | `/api/workspaces/:id/imports` | Import Nmap/Nikto scan file |
| `GET` | `/api/api-keys` | List API keys |
| `POST` | `/api/api-keys` | Create new API key |

---

## Available Scripts

| Command | Description |
|---|---|
| `npm run dev` | Start development server with hot reload |
| `npm run build` | Build production bundle into `dist/` |
| `npm run start` | Start production server |
| `npm run db:push` | Sync Drizzle schema to database |
| `npm run check` | TypeScript type-check |
| `npm test` | Run unit test suite (Vitest) |
| `npm run test:nuclei` | Test Nuclei scanner integration |

---

## Docker

### Full stack (app + PostgreSQL + Ollama)

```bash
docker compose up -d
```

Services:
- **cyshield-db** — PostgreSQL 16 on port `5432`
- **cyshield-ollama** — Ollama on port `11434`
- **cyshield-app** — cyOsinter on port `5000`

### Database only

```bash
docker compose up -d db
```

### Environment overrides

Create a `.env` file in the project root to override defaults:

```env
POSTGRES_PASSWORD=strongpassword
OLLAMA_ENABLED=1
ABUSEIPDB_API_KEY=your_key
```

---

## Security Architecture

**Attack Paths & Compliance Mapping**

| Attack Paths | Compliance |
|-------------|------------|
| ![Attack Paths](docs/screenshots/attack-paths.png) | ![Compliance](docs/screenshots/compliance.png) |

cyOsinter is built with defense-in-depth security across all layers.

### Authentication & Authorization
- **Password hashing** with scrypt using OWASP-recommended parameters
- **Global auth gate** — all `/api` routes require a valid Bearer token (except `/api/auth/*`)
- **Workspace-scoped RBAC** — every workspace-scoped endpoint verifies the caller's role (owner/admin/analyst/viewer)
- **Bare-ID route isolation** — routes like `GET /findings/:id` verify the caller is a member of the resource's workspace before returning data
- **Admin endpoints** restricted by API key or localhost-only access

### Input Validation & Injection Prevention
- **Zod schema validation** on all mutating endpoints with strict enum constraints
- **Domain regex enforcement** on scan targets (validated at both route and scan-trigger layers)
- **Prompt injection mitigation** — user-controlled strings sanitized before embedding in LLM prompts
- **CSV formula injection defense** — dangerous leading characters (`=`, `+`, `-`, `@`) neutralized in exports
- **XML parser hardening** — attribute value parsing disabled, file size caps enforced

### Network & Infrastructure
- **Rate limiting** — 100 requests/minute general, 5/minute for scans, 3/minute for AI endpoints
- **SSRF protection** — webhook URLs validated against private/loopback ranges with fail-closed DNS resolution
- **Security headers** via Helmet with production-grade Content Security Policy
- **WebSocket hardening** — 4KB message size limit to prevent parsing DoS
- **Pino log redaction** — sensitive fields (password, token, secret, apiKey) automatically redacted
- **Centralized error handling** — no stack traces or internal details leaked to clients

### Important Notices
- cyOsinter performs **real outbound network requests** against target domains. Only scan domains you own or have explicit written permission to test.
- All data stays on your infrastructure — no telemetry, no cloud sync.
- API keys are stored in your `.env` file — never commit `.env` to version control.
- For production, place cyOsinter behind a reverse proxy (nginx/Caddy) with TLS.

---

## License

MIT © vinne-1
