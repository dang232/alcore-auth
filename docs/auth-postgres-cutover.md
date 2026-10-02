# Auth PostgreSQL cutover runbook (F0)

Target topology: Auth identity state in managed PostgreSQL, throttle on Redis
(`auth:*` buckets, fail-closed). SQLite (`./data/auth.sqlite` + `auth-data`
volume) stays as the tested fallback. **VPS cutover of live Auth data is a
LATER explicit step — this runbook is proven by code + drill only.**

## 0. Prereqs (staging/prod host)

- Postgres reachable (compose `db` service or managed instance).
- `DATABASE_URL` exported in the operator shell only (never committed).
  Format: `postgres://USER:PASS@HOST:5432/auth`.
- Auth stopped or in a maintenance window: OIDC/product codes live 60s, so a
  backfill taken under traffic can race expiry. Quiesce writes first.

## 1. Snapshot the SQLite fallback (rollback fuel)

```sh
cp ./data/auth.sqlite ./data/auth.sqlite.pre-pg-$(date +%Y%m%d)
cp ./data/auth.sqlite-wal ./data/auth.sqlite-wal.pre-pg-$(date +%Y%m%d) 2>/dev/null || true
```

## 2. Migrate the PostgreSQL schema

```sh
DATABASE_URL='postgres://USER:PASS@HOST:5432/auth' bun scripts/pg-migrate.ts
# expect: pg-migrate: applied 001 (N statements)
# rerun-safe: 001 already applied — nothing to do
```

## 3. Backfill + parity gate (BLOCKS cutover on DIFF)

```sh
DATABASE_URL='postgres://USER:PASS@HOST:5432/auth' \
  bun scripts/backfill-sqlite-to-pg.ts --sqlite ./data/auth.sqlite
# expect per-table: backfill: <table>: sqlite=N copied-attempts=N pg=N
# expect: backfill: PARITY OK — cutover gate passed
# logs carry counts + digest prefixes only — never secret values
```

Reruns are idempotent (`ON CONFLICT DO NOTHING` on every PK).

## 4. Flip the backend

```sh
# compose / systemd env:
AUTH_STORE_BACKEND=postgres
DATABASE_URL='postgres://USER:PASS@HOST:5432/auth'
# Redis (production throttle — required, fail-closed without it):
THROTTLE_BACKEND=redis
REDIS_URL='redis://redis:6379'
docker compose up -d --build auth
curl -s http://127.0.0.1:8082/health/ready
```

Verify: log in, refresh once (rotation), list `/auth/sessions`, run one
OIDC authorize→token round trip. Then `bun test` against staging if seeded.

## 5. Rollback (SQLite snapshot + config flip)

```sh
AUTH_STORE_BACKEND=sqlite   # or unset; DATABASE_URL then unread
# restore the pre-cutover file ONLY if SQLite wrote bad state meanwhile,
# else the live ./data/auth.sqlite is already the newest truth:
# cp ./data/auth.sqlite.pre-pg-YYYYMMDD ./data/auth.sqlite
docker compose up -d --build auth
curl -s http://127.0.0.1:8082/health/ready
```

## 6. Backup / restore drill (PostgreSQL)

```sh
# snapshot (SECRET MATERIAL — chmod 600 applied, never commit):
DATABASE_URL='...' bun scripts/pg-snapshot.ts --out ./auth-backup-YYYYMMDD.auth-snapshot.json
# restore (TRUNCATEs auth tables first, then parity-checks):
DATABASE_URL='...' bun scripts/pg-restore.ts --in ./auth-backup-YYYYMMDD.auth-snapshot.json
# self-contained drill on scratch (PGlite, no server needed):
bun scripts/pg-backup-drill.ts
# expect: drill: BACKUP/RESTORE DRILL PASS
# managed-instance variant: pg_dump -Fc ... / pg_restore ... (same tables)
```

## 7. What is NOT covered here

- Live VPS migration (explicit later step with its own window + backup).
- `/health/ready` `store` cell stays a process-local probe; PG liveness is
  covered by `userCount` + request-path errors + the `db` service
  healthcheck. Making the probe async is F4 follow-up, not this lane.
