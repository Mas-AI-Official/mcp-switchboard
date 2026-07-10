# MCP Switchboard — container image for Glama (glama.ai) and general self-hosting.
#
# Glama builds this image, starts the server over stdio, and calls `initialize` +
# `tools/list` to introspect it. MCP Switchboard is a governed MCP aggregator: with the
# starter config it mounts the official @modelcontextprotocol/server-everything reference
# server. A failed upstream mount is non-fatal — the gateway still answers introspection.
#
# Build:  docker build -t mcp-switchboard .
# Run:    docker run --rm -i mcp-switchboard        # stdio MCP server

# ---- build stage: compile TypeScript -> dist/ ----
FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# ---- runtime stage ----
FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production
# Vault, audit log and api-key store live here; keep them on the image's writable /app.
ENV SWITCHBOARD_HOME=/app/.switchboard
WORKDIR /app
# Production dependencies only.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
# Compiled output + runtime assets.
COPY --from=build /app/dist ./dist
COPY public ./public
COPY data ./data
COPY server.json switchboard.config.example.yaml README.md LICENSE ./
# `init` scaffolds a starter config on first boot (idempotent — it no-ops if one exists);
# then `serve` runs the gateway. Logs go to stderr so stdout stays a clean stdio JSON-RPC channel.
ENTRYPOINT ["sh", "-c", "node dist/cli.js init >/dev/null 2>&1 || true; exec node dist/cli.js serve"]
