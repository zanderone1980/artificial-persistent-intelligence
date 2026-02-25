# CORD + VIGIL Production Container
# Multi-stage build for minimal attack surface

# ── Stage 1: Builder ─────────────────────────────────────────────────────────
FROM node:21-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache python3 make g++

# Copy package files
COPY package*.json ./
COPY cord_engine/package*.json ./cord_engine/

# Install dependencies
RUN npm ci --only=production

# Copy source
COPY . .

# Run tests (fail fast if broken)
RUN npm test

# ── Stage 2: Production ──────────────────────────────────────────────────────
FROM node:21-alpine

# Security: non-root user
RUN addgroup -g 1001 -S cord && \
    adduser -S cord -u 1001 -G cord

WORKDIR /app

# Copy from builder
COPY --from=builder --chown=cord:cord /app/node_modules ./node_modules
COPY --from=builder --chown=cord:cord /app/cord ./cord
COPY --from=builder --chown=cord:cord /app/vigil ./vigil
COPY --from=builder --chown=cord:cord /app/cord_engine ./cord_engine
COPY --from=builder --chown=cord:cord /app/package.json ./

# Security: read-only filesystem where possible
USER cord

# Environment
ENV NODE_ENV=production
ENV ANTHROPIC_API_KEY=

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node -e "require('./cord').evaluate({text:'health'})" || exit 1

# Expose metrics port (if dashboard enabled)
EXPOSE 3000

# Default: run as library (no CMD - imported by other apps)
# Use: docker run cord-engine node -e "require('./cord').evaluate({text:'...'})"
