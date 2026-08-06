# Running Cyber-Shield-Pro (cyOsinter)

A self-hosted External Attack Surface Management (EASM) + OSINT scanner. This
guide gets you from zero to a running product in one command.

---

## 1. Prerequisites

- **Docker Desktop** (includes Docker Compose) — running.
  That's the only requirement. No Node, Postgres, or manual setup needed.

Check it's ready:

```bash
docker --version
docker compose version
```

---

## 2. Start it (one command)

From the project folder:

```bash
docker compose up -d --build
```

This builds the app image (Node + Nuclei + headless Chromium for report
screenshots) and starts three containers:

| Container         | What it is                    | Host port |
|-------------------|-------------------------------|-----------|
| `cyshield-app`    | The web app + API             | **5050**  |
| `cyshield-db`     | PostgreSQL 16 (data store)    | 5433      |
| `cyshield-ollama` | Local LLM (optional, for AI)  | 11434     |

On first start it **creates the database schema automatically** and **seeds an
admin account** — no manual migration step.

Wait ~15–30 seconds for the first build, then check it's healthy:

```bash
docker compose ps
```

`cyshield-app` should show `Up ... (healthy)`.

---

## 3. Open the product

> **http://localhost:5050**

Sign in with the default admin:

- **Email:** `admin@cyshield.local`
- **Password:** `ChangeMe123!`

(or click **Register** to make your own account).

> ⚠️ **Change the default password** for anything beyond local use — see §6.

---

## 4. Use it

1. Top-right, click the workspace selector → **Create Workspace**.
   Give it any name; optionally set a **Target domain** (e.g. `example.com`).
2. Go to the **Dashboard** → enter the target → **Launch All Scans** (or use the
   **Attack Surface** / **OSINT Discovery** pages). The dashboard fills in live
   as the scan runs.
3. When findings appear, open **Reports** → **New Report** → open it →
   **Export**:
   - **Word (.docx)** — instant, text + tables.
   - **Word + live evidence (.docx)** — captures live screenshots for every
     finding (~30–60 s).

Scan modes: **Standard** (fast), **Gold** (full coverage, loud), **Safe**
(full coverage but stealthy / rate-limited).

---

## 5. Everyday commands

```bash
# View logs (follow)
docker compose logs -f app

# Stop (keeps data)
docker compose stop

# Start again
docker compose up -d

# Restart just the app
docker compose restart app

# Full reset — DELETES all scan data and users, fresh start
docker compose down -v && docker compose up -d --build
```

---

## 6. Configuration (optional)

All optional — the product works out of the box. Override by exporting env vars
before `docker compose up`, or create a `.env` file (see `.env.example`) and
uncomment the `env_file:` lines in `docker-compose.yml`.

| Variable                | Default               | Purpose                                   |
|-------------------------|-----------------------|-------------------------------------------|
| `APP_HOST_PORT`         | `5050`                | Host port for the app                     |
| `DB_HOST_PORT`          | `5433`                | Host port for Postgres                    |
| `SEED_ADMIN_EMAIL`      | `admin@cyshield.local`| Seeded admin login                        |
| `SEED_ADMIN_PASSWORD`   | `ChangeMe123!`        | Seeded admin password — **change this**   |
| `POSTGRES_PASSWORD`     | `postgres`            | Database password                         |
| `OLLAMA_ENABLED`        | `0`                   | Set `1` to enable AI insights via Ollama  |

Example — change the port and admin password:

```bash
APP_HOST_PORT=8080 SEED_ADMIN_PASSWORD='MyStr0ngPass!' docker compose up -d --build
# → http://localhost:8080
```

**Richer intelligence (optional):** add API keys to a `.env` file —
`ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `TAVILY_API_KEY`, `NVD_API_KEY` — then
uncomment the `env_file:` lines in `docker-compose.yml` and restart. The product
works fully without them.

**AI insights (optional):** set `OLLAMA_ENABLED=1`, then pull a model once:

```bash
docker exec cyshield-ollama ollama pull tinyllama
```

---

## 7. Troubleshooting

- **Port already in use** (`5050` or `5433`): pick another —
  `APP_HOST_PORT=8080 docker compose up -d`.
- **App not healthy / can't reach it:** check logs — `docker compose logs app`.
  The DB must be healthy first (Compose waits for it automatically).
- **Nothing shows after a scan:** scans take a few minutes; the dashboard polls
  live. Confirm the target domain is valid and publicly reachable.
- **Nuclei / Chromium:** both are baked into the image — no host install needed.
- **Start completely over:** `docker compose down -v && docker compose up -d --build`.

---

## 8. Manual run (no Docker)

Only if you don't want Docker. Requires Node 20+ and a PostgreSQL 14+ instance.

```bash
npm ci
cp .env.example .env          # then edit DATABASE_URL to your Postgres
npm run db:push               # create schema
npm run build && npm run start   # → http://localhost:5000
# (or: npm run dev  for hot-reload development)
```

---

That's it — `docker compose up -d --build`, open **http://localhost:5050**, sign in.
