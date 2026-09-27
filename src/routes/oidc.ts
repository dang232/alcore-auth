// ALcore Auth Repo C — OIDC authorization-code flow (identity-only).
// authorize → single-use short-TTL code (60s) → server-side token exchange.
// Reusable JWTs NEVER appear in URLs: the redirect carries only the opaque
// code; replay of a code → 400 invalid_grant.

import { Hono } from "hono";
import type { Context } from "hono";
import { getJwtSecret, getIssuer, getAllowedOrigins } from "../config";
import { hashToken, randomToken, verifyAccess, signAccess, JwtError } from "../lib/crypto";
import { oidcStore, sessionStore, userStore } from "../lib/store";
import { authRateLimit } from "../lib/ratelimit";
import { ACCESS_TTL_SECONDS, REFRESH_TTL_MS } from "./auth";

const CODE_TTL_SECONDS = 60;

function limited(c: Context, scope: string): boolean {
  const fwd = c.req.header("x-forwarded-for") ?? "";
  const ip = fwd.split(",")[0]?.trim() || "local";
  const r = authRateLimit(`${scope}:${ip}`);
  if (!r.ok) {
    c.header("Retry-After", String(Math.max(1, Math.ceil(r.retryAfterMs / 1000))));
    return true;
  }
  return false;
}

function bearerSub(c: Context): string | null {
  const h = c.req.header("authorization") ?? "";
  const m = /^Bearer (.+)$/.exec(h.trim());
  const token = m?.[1]?.trim() ?? "";
  if (token === "") return null;
  try {
    const payload = verifyAccess(token, getJwtSecret(), getIssuer());
    return userStore.findById(payload.sub) === undefined ? null : payload.sub;
  } catch (e) {
    if (!(e instanceof JwtError)) throw e;
    return null;
  }
}

function redirectOrigin(url: string): string | null {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

export const oidcRoutes = new Hono();

// GET /oidc/authorize?response_type=code&client_id=..&redirect_uri=..&state=..
oidcRoutes.get("/authorize", async (c) => {
  if (limited(c, "oidc")) return c.json({ error: "rate_limited" }, 429);
  const sub = bearerSub(c);
  if (sub === null) return c.json({ error: "unauthorized" }, 401);
  const responseType = c.req.query("response_type") ?? "";
  const redirectUri = c.req.query("redirect_uri") ?? "";
  const state = c.req.query("state") ?? "";
  if (responseType !== "code") return c.json({ error: "unsupported_response_type" }, 400);
  const origin = redirectOrigin(redirectUri);
  if (origin === null || !getAllowedOrigins().includes(origin)) {
    return c.json({ error: "invalid_redirect_uri" }, 400);
  }
  const rec = oidcStore.issue(sub, redirectUri, CODE_TTL_SECONDS);
  const sep = redirectUri.includes("?") ? "&" : "?";
  const location =
    `${redirectUri}${sep}code=${encodeURIComponent(rec.code)}` +
    (state === "" ? "" : `&state=${encodeURIComponent(state)}`);
  return c.redirect(location, 302);
});

// POST /oidc/token {grant_type:'authorization_code', code, redirect_uri}
oidcRoutes.post("/token", async (c) => {
  if (limited(c, "oidc")) return c.json({ error: "rate_limited" }, 429);
  let body: unknown = null;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "invalid_request" }, 400);
  }
  const b = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
  if (b["grant_type"] !== "authorization_code") {
    return c.json({ error: "unsupported_grant_type" }, 400);
  }
  const code = typeof b["code"] === "string" ? b["code"] : "";
  const redirectUri = typeof b["redirect_uri"] === "string" ? b["redirect_uri"] : "";
  if (code === "" || redirectUri === "") return c.json({ error: "invalid_grant" }, 400);
  const rec = oidcStore.consume(code, redirectUri);
  if (rec === null) return c.json({ error: "invalid_grant" }, 400);
  const refresh = randomToken(32);
  sessionStore.create(rec.userId, hashToken(refresh), REFRESH_TTL_MS);
  const session = sessionStore.findByRefreshHash(hashToken(refresh));
  const access = signAccess(
    { sub: rec.userId, sid: session?.id ?? "unknown", iss: getIssuer() },
    getJwtSecret(),
    ACCESS_TTL_SECONDS,
  );
  return c.json({
    access_token: access,
    refresh_token: refresh,
    token_type: "Bearer",
    expires_in: ACCESS_TTL_SECONDS,
  });
});
