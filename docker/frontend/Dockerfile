# ── Stage 1: Build React app ──────────────────────────────────
FROM node:22-alpine AS builder

WORKDIR /app

# Install deps (package.json + lock file for caching)
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install

# Copy source and build
COPY frontend/ ./
RUN npm run build

# ── Stage 2: Serve with nginx ──────────────────────────────────
FROM nginx:alpine

# Remove default nginx config and static files
RUN rm -rf /usr/share/nginx/html/* /etc/nginx/conf.d/default.conf

# Copy our nginx config
COPY docker/frontend/nginx.conf /etc/nginx/conf.d/default.conf

# Copy built React app from builder stage
COPY --from=builder /app/dist/ /usr/share/nginx/html/

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 \
    CMD wget -qO- http://127.0.0.1:5173/ || exit 1

EXPOSE 5173
