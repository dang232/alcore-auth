# Pull-lazy provision contract (unified-auth-core todo 10)

Status: DONE 2026-10-03. Owner repo: `auth-service`. Commit: `docs(auth)`.

## The rule (one paragraph)

Auth is who-only: it mints identity and Auth proof, and NEVER calls a
product. There is zero `fetch()` from Auth to any product host, zero Auth
outbound S2S client, zero retry queue, and zero business call. The former
`TOKENPANEL_PROVISION_*` push-client config (`getProvisionConfig` in
`src/config.ts`) was deleted in this todo — it had zero references in
`src/` and `compose.yml` and its removal closes the last push seam.
Products pull: after any Auth entry below, the product (or its BFF) calls
Auth-proofed, idempotent endpoints carrying Auth proof, and provisions its
own row. A product the user never contacted has NO ledger row — that row
absence IS the `UNPROVISIONED` state (todo 7), explicit and not an error.

## Entries

| # | Auth entry | Auth proof issued | Product pull (outside Auth) | Proof kind |
|---|------------|-------------------|-----------------------------|------------|
| 1 | `POST /auth/register` | 201 identity + session pair | product exchanges session token for a product code, then redeems it | access-token |
| 2 | `POST /auth/google/verify` | 200 `{access_token}` session JWT + cookies | same pull as 1 | access-token |
| 3 | `GET /auth/google/callback` | 200 session pair, or 302 product handoff | browser lands on product with `?code=&state=`; product redeems via S2S | access-token (+ `me`) |
| 4 | `POST /oidc/exchange` (Bearer session) | `{code, expires_in:60}` single-use | product S2S-redeems the code | access-token |
| 5 | `GET /oidc/exchange/redirect` (cookie session) | 302 `redirect_uri?code=&state=` single-use bound code | product S2S-redeems with redirect+state binding | access-token |
| 6 | `POST /oidc/exchange/token` | `{access_token, token_type:Bearer, expires_in:60}` product-scoped JWT | product verifies + provisions own row | access-token |
| 7 | `GET /auth/me` (Bearer session) | `{id, email, emailVerified}` identity view | product resolves `sub`+email without new mint | me |

`POST /oidc/token` (standard OIDC, `aud=<clientId>`, `intent=oidc`) is NOT a
product-pull proof — products MUST use entry 6 (`aud=<product>`,
`intent=product_exchange`). Attestation-bound pulls (TokenPanel S2S binding
per `auth-attestation`) are product-side verifiers (todos 12/22) and consume
the entry-6 token; Auth mints nothing extra for them.

### 1. `POST /auth/register`

Request:

```http
POST /auth/register HTTP/1.1
Content-Type: application/json

{"email": "ada@example.com", "password": "s3cret-pass"}
```

Response (`201`; `409 {"error":"email_taken"}` on duplicate):

```json
{
  "id": "usr_01J...",
  "email": "ada@example.com",
  "emailVerified": false,
  "access_token": "<session JWT aud=auth intent=session>",
  "refresh_token": "<opaque>",
  "expires_in": 900
}
```

`Set-Cookie: alcore_at=<access_token>; HttpOnly; Secure; SameSite=Strict`
(and `alcore_rt`). The `id` is the `authUserId` the product provisions
against; the response carries NO customer/product/entitlement fields.

### 2. `POST /auth/google/verify`

Request:

```http
POST /auth/google/verify HTTP/1.1
Content-Type: application/json

{"idToken": "<Google ID token>"}
```

Response (`200`; `401 {"error":"invalid_credentials"}` on bad token,
`409 {"error":"identity_conflict"}` when the Google subject and the email
each belong to a different Auth user — never merged):

```json
{"access_token": "<session JWT aud=auth intent=session>"}
```

Session cookies set as in entry 1. Same pull as entry 1 follows.

### 3. `GET /auth/google/callback`

Browser entry. Invalid `state`/`code` → `400 invalid_google_state`
(fail-closed, no session minted). Success → `200` session pair (same shape
as entry 1 plus `user`), OR — when the caller chained a validated product
handoff (`audience ∈ {libre,tokenpanel}`, exact registered `redirect_uri`
whose origin is in `AUTH_ALLOWED_ORIGINS`, `state` 1..512 chars) — a `302`:

```http
HTTP/1.1 302 Found
Location: https://web.alcore.io.vn/auth/alcore/callback?code=<single-use-60s>&state=<echoed>
```

The redirect carries an opaque code, never a session token. The product
redeems it via entry 6 with the `redirect_uri`+`state` binding.

### 4. `POST /oidc/exchange` (Bearer session JWT)

Request:

```http
POST /oidc/exchange HTTP/1.1
Authorization: Bearer <session JWT aud=auth intent=session>
Content-Type: application/json

{"audience": "libre", "intent": "product_exchange"}
```

Response (`200`; `401` unauthenticated, `400 invalid_exchange` on wrong
audience/intent):

```json
{"code": "<single-use-60s>", "expires_in": 60}
```

### 5. `GET /oidc/exchange/redirect` (cookie session)

```http
GET /oidc/exchange/redirect?audience=libre&redirect_uri=https%3A%2F%2Fweb.alcore.io.vn%2Fauth%2Fcallback&state=st-abc HTTP/1.1
Cookie: alcore_at=<session JWT>
```

Cookie-authenticated session → `302` to
`<redirect_uri>?code=<single-use-60s-bound>&state=st-abc`. Unauthenticated →
`401 unauthorized`; unregistered `redirect_uri`/bad audience/state → `400`.
The only browser path to a product code — JavaScript never sees a session
token.

### 6. `POST /oidc/exchange/token` (product S2S redeem)

Request (redirect-bound codes MUST present the binding):

```http
POST /oidc/exchange/token HTTP/1.1
Content-Type: application/json

{
  "code": "<single-use>",
  "audience": "libre",
  "intent": "product_exchange",
  "redirect_uri": "https://web.alcore.io.vn/auth/callback",
  "state": "st-abc"
}
```

Response (`200`; replay/tampered/swapped-audience/wrong-intent →
`400 invalid_grant`, identical shape — no oracle):

```json
{
  "access_token": "<product JWT iss=<AUTH_ISSUER> aud=libre intent=product_exchange, 60s, carries sub+email>",
  "token_type": "Bearer",
  "expires_in": 60
}
```

The product verifies `iss`/`aud`/`intent`/expiry against Auth JWKS/secret,
then runs its idempotent `findOrCreate` keyed by `sub` (`issuer|sub` for
Libre, `authUserId` for TokenPanel) with its canonical idempotency key
(`customer-provision:{authUserId}` / `libre-provision:{issuer|sub}`).
Email-collision → `409`/CONFLICT queue, never merge. Bare `authUserId`
without this token is denied (todos 11/12).

### 7. `GET /auth/me` (identity view, `me` proof kind)

```http
GET /auth/me HTTP/1.1
Authorization: Bearer <session JWT>
```

```json
{"id": "usr_01J...", "email": "ada@example.com", "emailVerified": true}
```

Lets a product holding a valid session token resolve `sub`+verified email
without minting anything. Never a provision trigger by itself.

## UNPROVISIONED (never-contacted product)

`UNPROVISIONED` is stored NOWHERE: absence of a
`(auth_user_id, product)` row in `provisioning_ledger` IS the state (todo 7
guard: new rows must start at `PENDING`). Products treat "no row" as
"first contact — run the idempotent pull", not as an error. Auth exposes no
per-product state endpoint; provisioning states (`PENDING`/`PROVISIONED`/
`FAILED`/`CONFLICT`) are written and read product-side (todos 11-13).

## Forbidden (review gate)

- Auth code MUST NOT contain `fetch()` to a product host, an S2S provision
  client, a retry queue, or a business/entitlement call. The only outbound
  `fetch()` in `src/` is to Google (`oauth2.googleapis.com` token,
  Google JWKS) — identity verification, not product calls.
- No `TOKENPANEL_*`/`LIBRE_*` provision env in Auth config/compose.
- No passwords, product rows, or Auth sessions in the ledger (opaque ids +
  state only).
- No auto-merge on email collision anywhere on the pull path.

## Verification (this todo)

```sh
cd auth-service
grep -rn "fetch(TOKENPANEL\|fetch(LIBRE" src; echo "exit=$?"   # exit=1, no matches
grep -rn "getProvisionConfig\|TOKENPANEL_PROVISION" src; echo "exit=$?"  # exit=1
grep -rn "fetch(" src   # only src/lib/google.ts (JWKS) + src/routes/auth.ts (Google token)
bun test tests/pull-contract.test.ts
```

Behavior-of-record: `tests/auth.test.ts` (register 201 + login/refresh/
logout/verify/reset shapes) and `tests/exchange-redirect.test.ts` (cookie
handoff, tamper/replay/wrong-audience rejects) were read first and are
UNCHANGED by this todo — no contradiction found (no FINDING). New pins live
in `tests/pull-contract.test.ts`.
