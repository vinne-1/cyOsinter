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
RUN nuclei -version && nuclei -update-templates

WORKDIR /app
COPY package*.json ./
# Full install needed for drizzle-kit (db:push)
RUN npm ci
COPY --from=builder /app/dist ./dist
COPY drizzle.config.ts ./
COPY shared ./shared

EXPOSE 5000
ENV NODE_ENV=production

# Run schema push on startup, then start server
CMD ["sh", "-c", "npm run db:push || echo '[startup] db:push failed, continuing...' && node dist/index.cjs"]
