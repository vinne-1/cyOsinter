# Stage 1: Build app
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Stage 2: Production image with Node + Nuclei + Chromium (for report evidence)
FROM node:20-alpine
# Chromium + fonts for headless screenshot evidence (Playwright uses the system
# browser on Alpine — its bundled Chromium is glibc-only and won't run on musl).
RUN apk add --no-cache wget unzip \
    chromium nss freetype harfbuzz ca-certificates ttf-freefont
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium-browser
# Install Nuclei from official image (binary at /usr/local/bin/nuclei)
COPY --from=projectdiscovery/nuclei:latest /usr/local/bin/nuclei /usr/local/bin/nuclei

WORKDIR /app
COPY package*.json ./
# Full install needed for drizzle-kit (db:push)
RUN npm ci
COPY --from=builder /app/dist ./dist
COPY drizzle.config.ts ./
COPY shared ./shared

# ── Run as an unprivileged user ──────────────────────────────────────────────
# This container executes external binaries (nuclei) and drives a browser
# against attacker-controlled content. Running that as root means any RCE or
# browser escape starts with root inside the container, and root in the
# container is the first half of most container escapes. `node` (uid 1000) ships
# with the base image.
#
# The chown must come before USER, and the template fetch must come AFTER it:
# nuclei stores templates under the RUNNING user's home (~/.config/nuclei), so
# updating them as root would leave the runtime user with no templates and a
# scanner that silently finds nothing.
RUN chown -R node:node /app
USER node
RUN nuclei -version && nuclei -update-templates

EXPOSE 5000
ENV NODE_ENV=production

# Readiness, not liveness, and not the SPA: `/` returns 200 even when the
# database is unreachable, so probing it reports healthy while broken. Declared
# here as well as in docker-compose so a plain `docker run` is still checked.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD wget -q --spider http://localhost:5000/readyz || exit 1

# Apply the DB schema NON-INTERACTIVELY on startup (drizzle-kit push --force
# never prompts, so it can't hang the container), then start the server. The
# server starts regardless of the push result.
CMD ["sh", "-c", "npx drizzle-kit push --force || echo '[startup] schema push failed, continuing...'; node dist/index.cjs"]
