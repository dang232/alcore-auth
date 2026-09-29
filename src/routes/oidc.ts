// ALcore Auth Repo C — OIDC authorization-code flow (identity-only).
// authorize → single-use short-TTL code (60s) → server-side token exchange.
// Reusable JWTs NEVER appear in URLs: the redirect carries only the opaque
// code; replay of a code → 400 invalid_grant.

import { Hono } from "hono";
import type { Context } from "hono";
import { getJwtSecret, getIssuer, getAllowedOrigins, getOidcClients } from "../config";
import { hashToken, randomToken, verifyAccess, signAccess, JwtError } from "../lib/crypto";
import { oidcStore, productExchangeStore, sessionStore, userStore } from "../lib/store";
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
    const payload = verifyAccess(token, getJwtSecret(), getIssuer(), "auth", "session");
    const session = sessionStore.findById(payload.sid);
    if (session === undefined || session.revoked || session.expiresAt <= Date.now() || session.userId !== payload.sub) return null;
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
  const clientId = c.req.query("client_id") ?? "";
  const redirectUri = c.req.query("redirect_uri") ?? "";
  const state = c.req.query("state") ?? "";
  if (responseType !== "code") return c.json({ error: "unsupported_response_type" }, 400);
  const origin = redirectOrigin(redirectUri);
  const registeredUri = getOidcClients().get(clientId);
  if (clientId === "" || registeredUri !== redirectUri || origin === null || !getAllowedOrigins().includes(origin)) {
    return c.json({ error: "invalid_redirect_uri" }, 400);
  }
  const rec = oidcStore.issue(sub, redirectUri, clientId, CODE_TTL_SECONDS);
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
  const clientId = typeof b["client_id"] === "string" ? b["client_id"] : "";
  if (code === "" || redirectUri === "" || clientId === "" || getOidcClients().get(clientId) !== redirectUri) return c.json({ error: "invalid_grant" }, 400);
  const rec = oidcStore.consume(code, redirectUri, clientId);
  if (rec === null) return c.json({ error: "invalid_grant" }, 400);
  const session = sessionStore.create(rec.userId, hashToken(randomToken(32)), REFRESH_TTL_MS);
  const access = signAccess(
    { sub: rec.userId, sid: session.id, iss: getIssuer(), aud: clientId, intent: "oidc" },
    getJwtSecret(),
    ACCESS_TTL_SECONDS,
  );
  return c.json({
    access_token: access,
    token_type: "Bearer",
    expires_in: ACCESS_TTL_SECONDS,
  });
});

const PRODUCT_EXCHANGE_TTL_SECONDS = 60;
const PRODUCT_INTENT = "product_exchange";

oidcRoutes.post("/exchange", async (c) => {
  if (limited(c, "exchange")) return c.json({ error: "rate_limited" }, 429);
  const sub = bearerSub(c);
  if (sub === null) return c.json({ error: "unauthorized" }, 401);
  let body: unknown;
  try { body = await c.req.json(); } catch { return c.json({ error: "invalid_request" }, 400); }
  const request = typeof body === "object" && body !== null ? body : {};
  const audience = "audience" in request ? request.audience : undefined;
  const intent = "intent" in request ? request.intent : undefined;
  if ((audience !== "tokenpanel" && audience !== "libre") || intent !== PRODUCT_INTENT) {
    return c.json({ error: "invalid_exchange" }, 400);
  }
  const authHeader = c.req.header("authorization") ?? "";
  const tokenMatch = /^Bearer (.+)$/.exec(authHeader.trim());
  const authToken = tokenMatch?.[1]?.trim() ?? "";
  if (authToken === "") return c.json({ error: "unauthorized" }, 401);
  let payload;
  try {
    payload = verifyAccess(authToken, getJwtSecret(), getIssuer(), "auth", "session");
  } catch (error) {
    if (error instanceof JwtError) return c.json({ error: "unauthorized" }, 401);
    throw error;
  }
  const session = sessionStore.findById(payload.sid);
  if (session === undefined || session.revoked || session.expiresAt <= Date.now() || session.userId !== payload.sub || sub !== payload.sub) {
    return c.json({ error: "unauthorized" }, 401);
  }
  const code = productExchangeStore.issue(sub, payload.sid, audience, PRODUCT_INTENT, PRODUCT_EXCHANGE_TTL_SECONDS);
  return c.json({ code, expires_in: PRODUCT_EXCHANGE_TTL_SECONDS });
});

oidcRoutes.post("/exchange/token", async (c) => {
  if (limited(c, "exchange")) return c.json({ error: "rate_limited" }, 429);
  let body: unknown;
  try { body = await c.req.json(); } catch { return c.json({ error: "invalid_request" }, 400); }
  const request = typeof body === "object" && body !== null ? body : {};
  const code = "code" in request ? request.code : undefined;
  const audience = "audience" in request ? request.audience : undefined;
  const intent = "intent" in request ? request.intent : undefined;
  if (typeof code !== "string" || code === "" || (audience !== "tokenpanel" && audience !== "libre") || intent !== PRODUCT_INTENT) {
    return c.json({ error: "invalid_grant" }, 400);
  }
  const exchange = productExchangeStore.consume(code, audience, PRODUCT_INTENT);
  if (exchange === null) return c.json({ error: "invalid_grant" }, 400);
  const session = sessionStore.findById(exchange.sessionId);
  if (session === undefined || session.revoked || session.expiresAt <= Date.now() || session.userId !== exchange.userId) {
    return c.json({ error: "invalid_grant" }, 400);
  }
  const token = signAccess({
    sub: exchange.userId, sid: exchange.sessionId, iss: getIssuer(), aud: exchange.audience, intent: exchange.intent,
  }, getJwtSecret(), PRODUCT_EXCHANGE_TTL_SECONDS);
  return c.json({ access_token: token, token_type: "Bearer", expires_in: PRODUCT_EXCHANGE_TTL_SECONDS });
});
