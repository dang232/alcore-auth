// ALcore Auth Repo C — OIDC authorization-code flow (identity-only).
// authorize → single-use short-TTL code (60s) → server-side token exchange.
// Reusable JWTs NEVER appear in URLs: the redirect carries only the opaque
// code; replay of a code → 400 invalid_grant.

import { Hono } from "hono";
import type { Context } from "hono";
import { getCookie } from "hono/cookie";
import { getIssuer, getAllowedOrigins, getOidcClients, getJwtRotationKeys } from "../config";
import { hashToken, randomToken, verifyAccess, signAccess, JwtError, isValidPkceToken } from "../lib/crypto";
import { oidcStore, productExchangeStore, sessionStore, userStore } from "../lib/store";
import { limitedAsync as throttleGuard } from "../lib/ratelimit";
import { emitAudit } from "../lib/audit";
import { ACCESS_TTL_SECONDS, REFRESH_TTL_MS } from "./auth";

const CODE_TTL_SECONDS = 60;

function clientIp(c: Context): string {
  const fwd = c.req.header("x-forwarded-for");
  const first = fwd === undefined ? "" : fwd.split(",")[0]?.trim() ?? "";
  return first === "" ? "local" : first;
}

async function limitedAsync(c: Context, scope: string): Promise<Response | null> {
  const fwd = c.req.header("x-forwarded-for") ?? "";
  const ip = fwd.split(",")[0]?.trim() || "local";
  const g = await throttleGuard(scope, ip);
  if (!g.limited) return null;
  c.header("Retry-After", String(g.retryAfterSec));
  return c.json(g.body, g.status as 429 | 503);
}

function bearerSub(c: Context): string | null {
  const h = c.req.header("authorization") ?? "";
  const m = /^Bearer (.+)$/.exec(h.trim());
  const token = m?.[1]?.trim() ?? "";
  if (token === "") return null;
  try {
    const payload = verifyAccess(token, getJwtRotationKeys(), getIssuer(), "auth", "session");
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
// PKCE (RFC 7636, task 38): code_challenge + code_challenge_method are
// optional for backward compatibility, but when present the method MUST be
// S256 — `plain` (or anything else) is rejected, and a challenge without a
// method is rejected too (the RFC default would be plain). A bound challenge
// must be redeemed with the matching code_verifier at POST /oidc/token.
oidcRoutes.get("/authorize", async (c) => {
  const gateOidc = await limitedAsync(c, "oidc"); if (gateOidc !== null) return gateOidc;
  const sub = bearerSub(c);
  if (sub === null) {
    emitAudit("auth.oidc_authorize", "unauthorized", { ip: clientIp(c) });
    return c.json({ error: "unauthorized" }, 401);
  }
  const responseType = c.req.query("response_type") ?? "";
  const clientId = c.req.query("client_id") ?? "";
  const redirectUri = c.req.query("redirect_uri") ?? "";
  const state = c.req.query("state") ?? "";
  if (responseType !== "code") {
    emitAudit("auth.oidc_authorize", "unsupported_response_type", { userId: sub, clientId, ip: clientIp(c) });
    return c.json({ error: "unsupported_response_type" }, 400);
  }
  const origin = redirectOrigin(redirectUri);
  const registeredUri = getOidcClients().get(clientId);
  if (clientId === "" || registeredUri !== redirectUri || origin === null || !getAllowedOrigins().includes(origin)) {
    emitAudit("auth.oidc_authorize", "invalid_redirect_uri", { userId: sub, clientId, ip: clientIp(c) });
    return c.json({ error: "invalid_redirect_uri" }, 400);
  }
  const challenge = c.req.query("code_challenge") ?? "";
  const method = c.req.query("code_challenge_method") ?? "";
  if (challenge !== "" || method !== "") {
    if (method !== "S256" || !isValidPkceToken(challenge)) {
      emitAudit("auth.oidc_authorize", "invalid_pkce_method", { userId: sub, clientId, ip: clientIp(c) });
      return c.json({ error: "invalid_pkce_method" }, 400);
    }
  }
  const rec = oidcStore.issue(
    sub, redirectUri, clientId, CODE_TTL_SECONDS,
    challenge === "" ? undefined : { challenge, method: "S256" },
  );
  emitAudit("auth.oidc_authorize", "ok", { userId: sub, clientId, ip: clientIp(c) });
  const sep = redirectUri.includes("?") ? "&" : "?";
  const location =
    `${redirectUri}${sep}code=${encodeURIComponent(rec.code)}` +
    (state === "" ? "" : `&state=${encodeURIComponent(state)}`);
  return c.redirect(location, 302);
});

// POST /oidc/token {grant_type:'authorization_code', code, redirect_uri}
// PKCE-bound codes MUST present the matching code_verifier (wrong or missing
// → invalid_grant, same shape as any other code mismatch — no oracle).
// Unbound (pre-PKCE) codes keep the legacy path: verifier ignored.
oidcRoutes.post("/token", async (c) => {
  const gateOidc = await limitedAsync(c, "oidc"); if (gateOidc !== null) return gateOidc;
  let body: unknown = null;
  try {
    body = await c.req.json();
  } catch {
    emitAudit("auth.oidc_token", "invalid_request", { ip: clientIp(c) });
    return c.json({ error: "invalid_request" }, 400);
  }
  const b = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
  if (b["grant_type"] !== "authorization_code") {
    emitAudit("auth.oidc_token", "unsupported_grant_type", { ip: clientIp(c) });
    return c.json({ error: "unsupported_grant_type" }, 400);
  }
  const code = typeof b["code"] === "string" ? b["code"] : "";
  const redirectUri = typeof b["redirect_uri"] === "string" ? b["redirect_uri"] : "";
  const clientId = typeof b["client_id"] === "string" ? b["client_id"] : "";
  const verifier = typeof b["code_verifier"] === "string" ? b["code_verifier"] : undefined;
  if (code === "" || redirectUri === "" || clientId === "" || getOidcClients().get(clientId) !== redirectUri) {
    emitAudit("auth.oidc_token", "invalid_grant", { clientId, ip: clientIp(c) });
    return c.json({ error: "invalid_grant" }, 400);
  }
  const rec = oidcStore.consume(code, redirectUri, clientId, verifier);
  if (rec === null) {
    emitAudit("auth.oidc_token", "invalid_grant", { clientId, ip: clientIp(c) });
    return c.json({ error: "invalid_grant" }, 400);
  }
  emitAudit("auth.oidc_token", "ok", { userId: rec.userId, clientId, ip: clientIp(c) });
  const session = sessionStore.create(rec.userId, hashToken(randomToken(32)), REFRESH_TTL_MS);
  const keys = getJwtRotationKeys();
  const access = signAccess(
    { sub: rec.userId, sid: session.id, iss: getIssuer(), aud: clientId, intent: "oidc" },
    keys.current,
    ACCESS_TTL_SECONDS,
    { kid: keys.currentKid },
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
  const gateExchange = await limitedAsync(c, "exchange"); if (gateExchange !== null) return gateExchange;
  const sub = bearerSub(c);
  if (sub === null) {
    emitAudit("auth.exchange_request", "unauthorized", { ip: clientIp(c) });
    return c.json({ error: "unauthorized" }, 401);
  }
  let body: unknown;
  try { body = await c.req.json(); } catch {
    emitAudit("auth.exchange_request", "invalid_request", { userId: sub, ip: clientIp(c) });
    return c.json({ error: "invalid_request" }, 400);
  }
  const request = typeof body === "object" && body !== null ? body : {};
  const audience = "audience" in request ? request.audience : undefined;
  const intent = "intent" in request ? request.intent : undefined;
  if ((audience !== "tokenpanel" && audience !== "libre") || intent !== PRODUCT_INTENT) {
    emitAudit("auth.exchange_request", "invalid_exchange", { userId: sub, ip: clientIp(c) });
    return c.json({ error: "invalid_exchange" }, 400);
  }
  const authHeader = c.req.header("authorization") ?? "";
  const tokenMatch = /^Bearer (.+)$/.exec(authHeader.trim());
  const authToken = tokenMatch?.[1]?.trim() ?? "";
  if (authToken === "") {
    emitAudit("auth.exchange_request", "unauthorized", { userId: sub, ip: clientIp(c) });
    return c.json({ error: "unauthorized" }, 401);
  }
  let payload;
  try {
    payload = verifyAccess(authToken, getJwtRotationKeys(), getIssuer(), "auth", "session");
  } catch (error) {
    if (error instanceof JwtError) {
      emitAudit("auth.exchange_request", "unauthorized", { userId: sub, ip: clientIp(c) });
      return c.json({ error: "unauthorized" }, 401);
    }
    throw error;
  }
  const session = sessionStore.findById(payload.sid);
  if (session === undefined || session.revoked || session.expiresAt <= Date.now() || session.userId !== payload.sub || sub !== payload.sub) {
    emitAudit("auth.exchange_request", "unauthorized", { userId: sub, ip: clientIp(c) });
    return c.json({ error: "unauthorized" }, 401);
  }
  const code = productExchangeStore.issue(sub, payload.sid, audience, PRODUCT_INTENT, PRODUCT_EXCHANGE_TTL_SECONDS);
  emitAudit("auth.exchange_request", "ok", { userId: sub, ip: clientIp(c) });
  return c.json({ code, expires_in: PRODUCT_EXCHANGE_TTL_SECONDS });
});

/**
 * Resolves the Auth session from the HttpOnly `alcore_at` cookie. Deliberately
 * mirrors `bearerSub`: same issuer/audience/intent checks and the same
 * revoked-or-expired rejection, so a cookie session is exactly as strict as a
 * Bearer session.
 */
function cookieSession(c: Context): { userId: string; sessionId: string } | null {
  const token = getCookie(c, "alcore_at") ?? "";
  if (token === "") return null;
  try {
    const payload = verifyAccess(token, getJwtRotationKeys(), getIssuer(), "auth", "session");
    const session = sessionStore.findById(payload.sid);
    if (session === undefined || session.revoked || session.expiresAt <= Date.now() || session.userId !== payload.sub) {
      return null;
    }
    if (userStore.findById(payload.sub) === undefined) return null;
    return { userId: payload.sub, sessionId: payload.sid };
  } catch (e) {
    if (!(e instanceof JwtError)) throw e;
    return null;
  }
}

// GET /oidc/exchange/redirect?audience=..&redirect_uri=..&state=..
// Browser handoff. Auth is the sole identity owner, so this is the only path a
// browser can use to obtain a product code: it authenticates with the HttpOnly
// session cookie instead of a Bearer header JavaScript cannot read. The redirect
// carries an opaque single-use code, never a session token.
//
// The redirect URI must match a registered AUTH_OIDC_CLIENTS entry exactly AND its
// origin must be in AUTH_ALLOWED_ORIGINS, reusing the /oidc/authorize checks so
// there is one allowlist, not two.
oidcRoutes.get("/exchange/redirect", async (c) => {
  const gateExchangeRedirect = await limitedAsync(c, "exchange-redirect"); if (gateExchangeRedirect !== null) return gateExchangeRedirect;
  const audience = c.req.query("audience") ?? "";
  const redirectUri = c.req.query("redirect_uri") ?? "";
  const state = c.req.query("state") ?? "";
  if (audience !== "tokenpanel" && audience !== "libre") {
    emitAudit("auth.exchange_request", "invalid_audience", { ip: clientIp(c) });
    return c.json({ error: "invalid_audience" }, 400);
  }
  // State is the browser's CSRF binding, echoed back unchanged. Refusing an empty
  // one stops a caller from silently degrading its own CSRF protection.
  if (state === "" || state.length > 512) {
    emitAudit("auth.exchange_request", "invalid_state", { ip: clientIp(c) });
    return c.json({ error: "invalid_state" }, 400);
  }
  const origin = redirectOrigin(redirectUri);
  const registered = [...getOidcClients().values()].includes(redirectUri);
  if (redirectUri === "" || !registered || origin === null || !getAllowedOrigins().includes(origin)) {
    emitAudit("auth.exchange_request", "invalid_redirect_uri", { ip: clientIp(c) });
    return c.json({ error: "invalid_redirect_uri" }, 400);
  }
  const session = cookieSession(c);
  if (session === null) {
    emitAudit("auth.exchange_request", "unauthorized", { ip: clientIp(c) });
    return c.json({ error: "unauthorized" }, 401);
  }
  const code = productExchangeStore.issueForRedirect(
    session.userId,
    session.sessionId,
    audience,
    PRODUCT_INTENT,
    redirectUri,
    state,
    PRODUCT_EXCHANGE_TTL_SECONDS,
  );
  const sep = redirectUri.includes("?") ? "&" : "?";
  const location =
    `${redirectUri}${sep}code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`;
  emitAudit("auth.exchange_request", "ok", { userId: session.userId, ip: clientIp(c) });
  return c.redirect(location, 302);
});

oidcRoutes.post("/exchange/token", async (c) => {
  const gateExchange = await limitedAsync(c, "exchange"); if (gateExchange !== null) return gateExchange;
  let body: unknown;
  try { body = await c.req.json(); } catch {
    emitAudit("auth.exchange_token", "invalid_request", { ip: clientIp(c) });
    return c.json({ error: "invalid_request" }, 400);
  }
  const request = typeof body === "object" && body !== null ? body : {};
  const code = "code" in request ? request["code"] : undefined;
  const audience = "audience" in request ? request["audience"] : undefined;
  const intent = "intent" in request ? request["intent"] : undefined;
  if (typeof code !== "string" || code === "" || (audience !== "tokenpanel" && audience !== "libre") || intent !== PRODUCT_INTENT) {
    emitAudit("auth.exchange_token", "invalid_grant", { ip: clientIp(c) });
    return c.json({ error: "invalid_grant" }, 400);
  }
  // A code minted through /exchange/redirect carries a redirect+state binding and
  // must present them; without them, fall back to the non-browser binding-free
  // path, which refuses bound codes outright.
  const redirectUri = "redirect_uri" in request ? request["redirect_uri"] : "";
  const state = "state" in request ? request["state"] : "";
  const exchange = typeof redirectUri === "string" && redirectUri !== ""
    ? productExchangeStore.consumeForRedirect(
        code, audience, PRODUCT_INTENT, redirectUri,
        typeof state === "string" ? state : "",
      )
    : productExchangeStore.consume(code, audience, PRODUCT_INTENT);
  if (exchange === null) {
    emitAudit("auth.exchange_token", "invalid_grant", { ip: clientIp(c) });
    return c.json({ error: "invalid_grant" }, 400);
  }
  const session = sessionStore.findById(exchange.sessionId);
  if (session === undefined || session.revoked || session.expiresAt <= Date.now() || session.userId !== exchange.userId) {
    emitAudit("auth.exchange_token", "invalid_grant", { userId: exchange.userId, ip: clientIp(c) });
    return c.json({ error: "invalid_grant" }, 400);
  }
  // The consuming product provisions its own profile and needs the verified
  // address to do so. The assertion stays server-to-server and short-lived.
  const exchangedUser = userStore.findById(exchange.userId);
  const exchangeKeys = getJwtRotationKeys();
  const token = signAccess({
    sub: exchange.userId, sid: exchange.sessionId, iss: getIssuer(), aud: exchange.audience, intent: exchange.intent,
    ...(exchangedUser === undefined ? {} : { email: exchangedUser.email }),
  }, exchangeKeys.current, PRODUCT_EXCHANGE_TTL_SECONDS, { kid: exchangeKeys.currentKid });
  emitAudit("auth.exchange_token", "ok", { userId: exchange.userId, ip: clientIp(c) });
  return c.json({ access_token: token, token_type: "Bearer", expires_in: PRODUCT_EXCHANGE_TTL_SECONDS });
});
