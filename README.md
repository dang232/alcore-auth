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
| POST | `/oidc/exchange` | authenticated request for a short-lived product exchange code |
| POST | `/oidc/exchange/token` | consumes that code once and returns a product-scoped assertion |

Configure OIDC clients with `AUTH_OIDC_CLIENTS=client_id=https://exact/callback`
(comma-separated entries); both `client_id` and exact `redirect_uri` must match.
`AUTH_ALLOWED_ORIGINS` remains an additional origin-level restriction.

Product exchange: the authenticated caller requests `audience` (`tokenpanel` or
`libre`) and `intent` (`product_exchange`). The returned opaque code expires in
60 seconds and is single-use. Exchange it server-side at `/oidc/exchange/token`
to receive a short-lived JWT. Consumers must verify signature and `iss` against
the configured Auth issuer, exact expected `aud`, `sub` as the opaque Auth user
id, future `exp`, and `intent === product_exchange`; reject expired or replayed
exchange codes. Never place JWTs in URLs.

`/oidc/token` takes `grant_type`, `code`, `client_id`, and exact registered
`redirect_uri` in the request body. It returns a short-lived access assertion
for that client; clients must validate signature, issuer, client audience,
subject, expiry, and `intent === oidc`.

## Run / test

```sh
bun install
bun run dev          # http://localhost:8082 (AUTH_PORT)
bun test             # 59 tests across auth, cors, health-ready, mail
bunx tsc --noEmit
```

Required env for prod: `JWT_SECRET` (32+ chars), `AUTH_ISSUER`,
`AUTH_ALLOWED_ORIGINS`. Mail (needed for verification + reset delivery):
`SMTP_HOST`, `SMTP_FROM`, optionally `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS`.
`SMTP_USERNAME` / `SMTP_PASSWORD` are accepted as aliases for the credential
pair, but `SMTP_USER` / `SMTP_PASS` are canonical: they match TokenPanel's
config fields and generated manifest, so the same `.env` works for either
service. See `src/config.ts`.

## Flags / risks for the owner

- Stores are **persistent SQLite** (`bun:sqlite`, `AUTH_DATABASE_PATH`,
  default `./data/auth.sqlite`) with WAL journaling and `foreign_keys = ON`;
  mount that path on a volume to survive container replacement.
- Verification and password-reset mail needs `SMTP_HOST` (plus optional
  `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`). **When
  `SMTP_HOST` is unset the purpose tokens are minted but never delivered**, so
  accounts cannot self-verify or self-reset. Both request endpoints still
  answer an identical always-200 response either way, so an unconfigured
  transport never becomes an account-existence oracle.
- A set `SMTP_HOST` with an empty credential is **not** the same as an unset
  one: the transport is configured, so a request reports `failed` (creds
  rejected) instead of `not_configured` (operator has not finished setup).
  Watch the `[auth-service] mail delivery failed:` line when debugging.
- `email_verified` only flips when a token delivered to the address is
  consumed; with no transport configured it stays `0`.
- **License TBD by owner** (no LICENSE file committed deliberately;
  siblings: TokenPanel AGPL-3.0-only, Libre Apache-2.0).

Plan context: ALcore unified-auth migration (identity extraction of
TokenPanel auth into this standalone Repo C).
