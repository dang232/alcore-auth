# ALcore Auth — Repo C (identity-only service)

Identity-only authentication service for the ALcore platform
(`auth.alcore.io.vn`). Built on the [Hono](https://hono.dev) `bun` template
(`bunx create-hono@latest`, generator-owned files committed as generated —
see git history); ALcore identity architecture layered on top.

## Identity-only boundary

This service owns **who** — and nothing else:

- Owns: users, password credentials (argon2id via `Bun.password`),
  OAuth identities (UNIQUE on provider+sub), sessions
  (access 15 min + 30-day rotating refresh), OIDC authorization-code flow,
  email verify/reset tokens.
- Owns NOTHING business: no customers, billing, balances, usage, keys,
  subscriptions, or entitlements. User id is an opaque string, stable for
  downstream linking (`customer.authUserId` in TokenPanel).

Downstream consumers: TokenPanel pulls identity via the provision contract
(`src/lib/provision-hook.ts`, unwired key-builder + doc only — Auth never
calls out) for customer provision/backfill/link.

## Contract

- Port: `8082`, bind `127.0.0.1` (`AUTH_PORT`, `src/config.ts`). Caddy
  `auth.${DOMAIN}` reverse-proxies to it.
- Issuer: `https://auth.alcore.io.vn` (`AUTH_ISSUER`); JWT `iss` claim
  `auth.alcore.io.vn`.
- JWT fail-fast: production boot without `JWT_SECRET` exits 1 naming the
  variable (value never logged). Weak-secret override
  `ALLOW_WEAK_JWT_SECRET=1` is dev/test only.
- Cookies `alcore_at` / `alcore_rt`: always HttpOnly + Secure +
  SameSite=Strict.
- No CORS middleware here (CORS triangle owned elsewhere); cookie policy:
  session cookies live ONLY in this service.

## Endpoints

| Method | Path | Notes |
|---|---|---|
| GET | `/` `/health` | liveness |
| GET | `/health/ready` | readiness: config + store + signer checks (503 + reasons when down) |
| POST | `/auth/register` | 201 `{id, email, emailVerified}`; dup → 409 `email_taken` |
| POST | `/auth/login` | 200 + HttpOnly cookies; wrong credential → identical 401 |
| POST | `/auth/refresh` | rotation; reuse = theft signal → session revoked |
| POST | `/auth/logout` | clears cookies, revokes session |
| GET | `/auth/me` | current user |
| POST | `/auth/verify/request` `/auth/verify/consume` | email verification (always-200 request) |
| POST | `/auth/reset/request` `/auth/reset/consume` | password reset (always-200 request) |
| GET | `/auth/google/callback` | **STUB**: verified-sub only — production MUST verify Google ID tokens server-side |
| GET | `/oidc/authorize` | authorization-code, 60 s single-use codes |
| POST | `/oidc/token` | code exchange server-side; PKCE S256 optional |

`redirect_uri` origin allowlist = web + apex + localhost dev defaults
(env-overridable via `AUTH_ALLOWED_ORIGINS`).

## Run / test

```sh
bun install
bun run dev          # http://localhost:8082 (AUTH_PORT)
bun test             # 18 tests: 12 auth + 6 readiness
bunx tsc --noEmit
```

Required env for prod: `JWT_SECRET` (32+ chars), `AUTH_ISSUER`,
`AUTH_ALLOWED_ORIGINS`. See `src/config.ts`.

## Flags / risks for the owner

- Stores are **in-memory** — a persistent store is a downstream/prod
  decision (flagged, not hidden).
- Google callback is a **stub** (see above).
- **License TBD by owner** (no LICENSE file committed deliberately;
  siblings: TokenPanel AGPL-3.0-only, Libre Apache-2.0).

Plan context: ALcore unified-auth migration (identity extraction of
TokenPanel auth into this standalone Repo C).
