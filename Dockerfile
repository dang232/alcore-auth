# ALcore Auth (Repo C, identity-only) — production image.
#
# Base pin: oven/bun:1.4.2 — MUST stay in sync with the CI pin
# (.github/workflows/ci.yml, oven-sh/setup-bun bun-version) and the proven
# local runtime. Bump both together or not at all.
#
# Fail-fast: JWT_SECRET is NEVER baked or defaulted here. Production boot
# without it exits 1 naming the variable (src/config.ts getJwtSecret,
# todo 6/8) — the owner passes it at `docker compose up` time only.
FROM oven/bun:1.4.2

WORKDIR /app

# Install first (own layer) so rebuilds on src-only changes reuse the cache.
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production

# Only the runtime tree enters the image (tests/ci/docs stay out;
# see .dockerignore for the belt-and-suspenders exclusion list).
COPY src ./src

ENV NODE_ENV=production

EXPOSE 8082

# Readiness semantics mirror GET /health/ready (src/lib/readiness.ts):
# 200 only when config + store + signer probes all pass; 503 otherwise.
# Uses ONLY the bun binary (present in oven/bun:* by definition) — no
# curl/wget assumptions about the base image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["bun", "-e", "fetch('http://127.0.0.1:8082/health/ready').then((r)=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]

CMD ["bun", "run", "src/index.ts"]
