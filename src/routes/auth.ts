// ALcore Auth Repo C — identity-only auth routes.
// register / login / logout / refresh (rotating) / me / verify request+consume
// / reset request+consume / Google link callback (verified-sub STUB).
// Identity-only: no customers/billing/balance/usage/keys/subs anywhere.

import { Hono } from "hono";
import type { Context } from "hono";
import { setCookie, deleteCookie, getCookie } from "hono/cookie";
import { getGoogleClientId, getGoogleRedirectUri, getJwtSecret, getIssuer } from "../config";
import {
  hashPassword,
  verifyPassword,
  randomToken,
  hashToken,
  signAccess,
  verifyAccess,
  mintPurposeToken,
  verifyPurposeToken,
  JwtError,
  TokenError,
} from "../lib/crypto";
import { googleStateStore, userStore, sessionStore } from "../lib/store";
import { GoogleCredentialError, GoogleUpstreamError, verifyGoogleCredential } from "../lib/google";
import type { Session } from "../lib/store";
import { authRateLimit } from "../lib/ratelimit";
import { deliverPurposeMail } from "../lib/mail";

export const ACCESS_TTL_SECONDS = 900; // short-lived access (15 min)
export const REFRESH_TTL_MS = 30 * 24 * 3600 * 1000; // rotating refresh (30 d)
const VERIFY_TTL_SECONDS = 24 * 3600;
const RESET_TTL_SECONDS = 3600;

// Timing-oracle mitigation for unknown emails: run the same argon2 verify
// path as a real password check so 401 latency does not reveal existence.
const DUMMY_HASH = await Bun.password.hash("no-such-user-timing-dummy", {
  algorithm: "argon2id",
});

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const INVALID_CREDENTIALS = { error: "invalid_credentials" };

function clientIp(c: Context): string {
  const fwd = c.req.header("x-forwarded-for");
  const first = fwd === undefined ? "" : fwd.split(",")[0]?.trim() ?? "";
  return first === "" ? "local" : first;
}

function limited(c: Context, scope: string): boolean {
  const r = authRateLimit(`${scope}:${clientIp(c)}`);
  if (!r.ok) {
    c.header("Retry-After", String(Math.max(1, Math.ceil(r.retryAfterMs / 1000))));
    return true;
  }
  return false;
}

async function readJson(c: Context): Promise<Record<string, unknown> | null> {
  try {
    const body: unknown = await c.req.json();
    return typeof body === "object" && body !== null ? (body as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}

function esc(v: string): string {
  return v.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

// Mail clients and security scanners only ever issue GET, so a link mailed to a
// user cannot target a POST-only route -- that combination 404s and makes the
// account unverifiable. Consuming on GET is not the fix either: scanners prefetch
// links and would burn the token before the recipient clicks. GET renders an
// interstitial; only the POST consumes.
function purposePage(heading: string, message: string, fields: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(heading)}</title>
<style>
body{font:16px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;margin:0;padding:2rem 1rem;background:#f6f7f9;color:#111}
main{max-width:26rem;margin:0 auto;background:#fff;padding:1.5rem;border:1px solid #e3e5e8;border-radius:.5rem}
h1{font-size:1.25rem;margin:0 0 .5rem}
p{margin:0 0 1rem;color:#444}
label{display:block;margin:.75rem 0 .25rem;font-weight:600;font-size:.875rem}
input{width:100%;padding:.6rem .7rem;font-size:1rem;border:1px solid #c9cdd2;border-radius:.375rem;box-sizing:border-box}
button{margin-top:1rem;width:100%;padding:.65rem;font-size:1rem;font-weight:600;color:#fff;background:#111;border:0;border-radius:.375rem;cursor:pointer}
button:hover{background:#333}
</style>
</head>
<body><main><h1>${esc(heading)}</h1><p>${esc(message)}</p>
<form method="post">${fields}<button type="submit">Continue</button></form>
</main></body>
</html>`;
}

// The interstitial form posts application/x-www-form-urlencoded, while API
// clients post JSON. Both must reach the same handler.
async function readPurposeBody(c: Context): Promise<{ token: string; newPassword: string }> {
  const type = c.req.header("content-type") ?? "";
  if (type.includes("application/x-www-form-urlencoded") || type.includes("multipart/form-data")) {
    const form = await c.req.parseBody();
    return { token: str(form["token"]), newPassword: str(form["newPassword"]) };
  }
  const body = await readJson(c);
  return { token: str(body?.["token"]), newPassword: str(body?.["newPassword"]) };
}

function bearer(c: Context): string {
  const h = c.req.header("authorization") ?? "";
  const m = /^Bearer (.+)$/.exec(h.trim());
  return m?.[1] === undefined ? "" : (m[1] as string).trim();
}

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: "Bearer";
  expires_in: number;
}

function issuePair(userId: string): { pair: TokenPair; session: Session } {
  const secret = getJwtSecret();
  const refresh = randomToken(32);
  const sessionId = crypto.randomUUID();
  const access = signAccess({ sub: userId, sid: sessionId, iss: getIssuer(), aud: "auth", intent: "session" }, secret, ACCESS_TTL_SECONDS);
  const session = sessionStore.createWithId(sessionId, userId, hashToken(refresh), REFRESH_TTL_MS);
  return {
    session,
    pair: { access_token: access, refresh_token: refresh, token_type: "Bearer", expires_in: ACCESS_TTL_SECONDS },
  };
}

function setAuthCookies(c: Context, pair: TokenPair): void {
  const base = { httpOnly: true, secure: true, sameSite: "Strict" as const, path: "/" };
  setCookie(c, "alcore_at", pair.access_token, { ...base, maxAge: ACCESS_TTL_SECONDS });
  setCookie(c, "alcore_rt", pair.refresh_token, {
    ...base,
    maxAge: Math.floor(REFRESH_TTL_MS / 1000),
  });
}

function clearAuthCookies(c: Context): void {
  deleteCookie(c, "alcore_at", { path: "/" });
  deleteCookie(c, "alcore_rt", { path: "/" });
}

function userView(userId: string): { id: string; email: string; emailVerified: boolean } | null {
  const u = userStore.findById(userId);
  return u === undefined ? null : { id: u.id, email: u.email, emailVerified: u.emailVerified };
}

export const authRoutes = new Hono();

// POST /auth/register → Auth user (opaque string id, stable for todos 11-14).
authRoutes.post("/register", async (c) => {
  if (limited(c, "register")) return c.json({ error: "rate_limited" }, 429);
  const body = await readJson(c);
  const email = str(body?.["email"]).trim().toLowerCase();
  const password = str(body?.["password"]);
  if (!EMAIL_RE.test(email)) return c.json({ error: "invalid_email" }, 400);
  if (password.length < 8) return c.json({ error: "weak_password" }, 400);
  if (userStore.findByEmail(email) !== undefined) {
    // Intentional 409 (client needs the outcome to finish signup); login and
    // verify/reset-request surfaces stay non-enumerating (always-401 / always-200).
    return c.json({ error: "email_taken" }, 409);
  }
  const user = userStore.create(email, await hashPassword(password));
  const { pair } = issuePair(user.id);
  setAuthCookies(c, pair);
  return c.json({ id: user.id, email: user.email, emailVerified: user.emailVerified, ...pair }, 201);
});

// POST /auth/login — identical 401 shape for unknown email vs bad password.
authRoutes.post("/login", async (c) => {
  if (limited(c, "login")) return c.json({ error: "rate_limited" }, 429);
  const body = await readJson(c);
  const email = str(body?.["email"]).trim().toLowerCase();
  const password = str(body?.["password"]);
  const user = EMAIL_RE.test(email) ? userStore.findByEmail(email) : undefined;
  if (user === undefined || user.passwordHash === null) {
    await verifyPassword(password === "" ? "x" : password, DUMMY_HASH);
    return c.json(INVALID_CREDENTIALS, 401);
  }
  if (!(await verifyPassword(password, user.passwordHash))) {
    return c.json(INVALID_CREDENTIALS, 401);
  }
  const { pair } = issuePair(user.id);
  setAuthCookies(c, pair);
  return c.json({ ...pair, user: { id: user.id, email: user.email, emailVerified: user.emailVerified } });
});

// POST /auth/refresh — single-use rotating refresh; reuse → revoke + 401.
authRoutes.post("/refresh", async (c) => {
  if (limited(c, "refresh")) return c.json({ error: "rate_limited" }, 429);
  const body = await readJson(c);
  const presented = str(body?.["refresh_token"]) || getCookie(c, "alcore_rt") || "";
  if (presented === "") return c.json({ error: "invalid_grant" }, 401);
  const digest = hashToken(presented);
  const session = sessionStore.findByRefreshHash(digest);
  if (session === undefined || session.revoked || session.expiresAt <= Date.now()) {
    return c.json({ error: "invalid_grant" }, 401);
  }
  // Reuse of an already-rotated token = theft signal: revoke the session.
  if (sessionStore.isReusedHash(session, digest)) {
    sessionStore.revoke(session);
    return c.json({ error: "invalid_grant" }, 401);
  }
  const next = randomToken(32);
  sessionStore.rotate(session, hashToken(next));
  const secret = getJwtSecret();
  const access = signAccess(
    { sub: session.userId, sid: session.id, iss: getIssuer(), aud: "auth", intent: "session" },
    secret,
    ACCESS_TTL_SECONDS,
  );
  const pair: TokenPair = {
    access_token: access,
    refresh_token: next,
    token_type: "Bearer",
    expires_in: ACCESS_TTL_SECONDS,
  };
  setAuthCookies(c, pair);
  return c.json(pair);
});

// POST /auth/logout — revoke by refresh_token or Bearer session.
authRoutes.post("/logout", async (c) => {
  const body = await readJson(c);
  const byRefresh = str(body?.["refresh_token"]);
  if (byRefresh !== "") {
    const s = sessionStore.findByRefreshHash(hashToken(byRefresh));
    if (s !== undefined) sessionStore.revoke(s);
    clearAuthCookies(c);
    return c.json({ ok: true });
  }
  const token = bearer(c);
  if (token === "") return c.json({ error: "unauthorized" }, 401);
  try {
    const payload = verifyAccess(token, getJwtSecret(), getIssuer(), "auth", "session");
    const s = sessionStore.findById(payload.sid);
    if (s !== undefined) sessionStore.revoke(s);
  } catch (e) {
    if (!(e instanceof JwtError)) throw e;
    return c.json({ error: "unauthorized" }, 401);
  }
  clearAuthCookies(c);
  return c.json({ ok: true });
});

// GET /auth/me — Bearer access → user view.
authRoutes.get("/me", async (c) => {
  const token = bearer(c);
  if (token === "") return c.json({ error: "unauthorized" }, 401);
  try {
    const payload = verifyAccess(token, getJwtSecret(), getIssuer(), "auth", "session");
    const view = userView(payload.sub);
    if (view === null) return c.json({ error: "unauthorized" }, 401);
    return c.json(view);
  } catch (e) {
    if (!(e instanceof JwtError)) throw e;
    return c.json({ error: "unauthorized" }, 401);
  }
});

// POST /auth/verify/request — always 200 (no enumeration).
authRoutes.post("/verify/request", async (c) => {
  if (limited(c, "verify")) return c.json({ error: "rate_limited" }, 429);
  const body = await readJson(c);
  const email = str(body?.["email"]).trim().toLowerCase();
  const user = EMAIL_RE.test(email) ? userStore.findByEmail(email) : undefined;
  if (user !== undefined) {
    // Deliver the minted token; the HTTP surface never reveals existence.
    void deliverPurposeMail(
      "verify",
      user.email,
      mintPurposeToken(getJwtSecret(), "verify", user.id, VERIFY_TTL_SECONDS)
    );
  }
  return c.json({ ok: true });
});

// GET /verify/consume — interstitial only; the token is consumed by the POST
// below. Reached by clicking the link in the verification email.
authRoutes.get("/verify/consume", (c) => {
  const token = c.req.query("token") ?? "";
  return c.html(
    purposePage(
      "Confirm your email",
      "Confirm to finish verifying your address.",
      `<input type="hidden" name="token" value="${esc(token)}">`,
    ),
  );
});

// POST /auth/verify/consume — accepts JSON or a form post (see readPurposeBody).
authRoutes.post("/verify/consume", async (c) => {
  const { token } = await readPurposeBody(c);
  try {
    const { userId } = verifyPurposeToken(getJwtSecret(), "verify", token);
    const user = userStore.findById(userId);
    if (user === undefined) return c.json({ error: "invalid_token" }, 400);
    userStore.setVerified(userId);
    return c.json({ ok: true });
  } catch (e) {
    if (!(e instanceof TokenError)) throw e;
    return c.json({ error: "invalid_token" }, 400);
  }
});

// POST /auth/reset/request — always 200 (no enumeration).
authRoutes.post("/reset/request", async (c) => {
  if (limited(c, "reset")) return c.json({ error: "rate_limited" }, 429);
  const body = await readJson(c);
  const email = str(body?.["email"]).trim().toLowerCase();
  const user = EMAIL_RE.test(email) ? userStore.findByEmail(email) : undefined;
  if (user !== undefined) {
    void deliverPurposeMail(
      "reset",
      user.email,
      mintPurposeToken(getJwtSecret(), "reset", user.id, RESET_TTL_SECONDS)
    );
  }
  return c.json({ ok: true });
});

// GET /auth/reset/consume — interstitial only; the POST below sets the password
// and consumes the token, so a link scanner cannot invalidate the reset.
authRoutes.get("/reset/consume", (c) => {
  const token = c.req.query("token") ?? "";
  return c.html(
    purposePage(
      "Choose a new password",
      "Set a new password to finish resetting your account.",
      `<input type="hidden" name="token" value="${esc(token)}">
<label for="newPassword">New password (8 characters or more)</label>
<input id="newPassword" name="newPassword" type="password" minlength="8" autocomplete="new-password" required>`,
    ),
  );
});

// POST /auth/reset/consume — sets new password, revokes all sessions.
authRoutes.post("/reset/consume", async (c) => {
  const { token, newPassword } = await readPurposeBody(c);
  if (newPassword.length < 8) return c.json({ error: "weak_password" }, 400);
  try {
    const { userId } = verifyPurposeToken(getJwtSecret(), "reset", token);
    const user = userStore.findById(userId);
    if (user === undefined) return c.json({ error: "invalid_token" }, 400);
    userStore.setPasswordHash(userId, await hashPassword(newPassword));
    sessionStore.revokeAllForUser(userId);
    return c.json({ ok: true });
  } catch (e) {
    if (!(e instanceof TokenError)) throw e;
    return c.json({ error: "invalid_token" }, 400);
  }
});

authRoutes.get("/google/config", (c) => c.json({ clientId: getGoogleClientId() }));

authRoutes.post("/google/verify", async (c) => {
  if (limited(c, "google-verify")) return c.json({ error: "rate_limited" }, 429);
  const body = await readJson(c);
  const idToken = str(body?.["idToken"]);
  if (idToken === "" || new TextEncoder().encode(idToken).byteLength > 8192) {
    return c.json(INVALID_CREDENTIALS, 401);
  }
  if (getGoogleClientId() === "") return c.json({ error: "google_not_configured" }, 503);
  let profile;
  try {
    profile = await verifyGoogleCredential(idToken);
  } catch (error) {
    if (error instanceof GoogleCredentialError) return c.json(INVALID_CREDENTIALS, 401);
    if (error instanceof GoogleUpstreamError) return c.json({ error: "upstream_unavailable" }, 502);
    throw error;
  }
  const existing = userStore.findByProviderSub("google", profile.subject);
  const emailUser = userStore.findByEmail(profile.email);
  if (existing !== undefined && emailUser !== undefined && existing.id !== emailUser.id) {
    return c.json({ error: "identity_conflict" }, 409);
  }
  const user = existing ?? emailUser ?? userStore.create(profile.email, null);
  userStore.setVerified(user.id);
  if (userStore.linkIdentity(user.id, "google", profile.subject) === "owned_by_other_user") {
    return c.json({ error: "identity_conflict" }, 409);
  }
  const { pair } = issuePair(user.id);
  setAuthCookies(c, pair);
  return c.json({ access_token: pair.access_token });
});

authRoutes.get("/google/start", (c) => {
  const clientId = getGoogleClientId();
  if (clientId === "") return c.json({ error: "google_not_configured" }, 503);
  const state = randomToken(24);
  const nonce = randomToken(24);
  googleStateStore.issue(state, nonce, Math.floor(Date.now() / 1000) + 300);
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.search = new URLSearchParams({
    client_id: clientId,
    redirect_uri: getGoogleRedirectUri(),
    response_type: "code",
    scope: "openid email profile",
    state,
    nonce,
    prompt: "select_account",
  }).toString();
  setCookie(c, "alcore_google_state", state, {
    httpOnly: true, secure: true, sameSite: "Lax", path: "/auth/google/callback", maxAge: 300,
  });
  return c.redirect(url.toString(), 302);
});

authRoutes.get("/google/callback", async (c) => {
  if (limited(c, "google")) return c.json({ error: "rate_limited" }, 429);
  if (c.req.query("error") !== undefined) return c.json({ error: "google_oauth_error" }, 400);
  const state = c.req.query("state") ?? "";
  const code = c.req.query("code") ?? "";
  const expectedState = getCookie(c, "alcore_google_state") ?? "";
  if (state === "" || code === "" || state !== expectedState) {
    deleteCookie(c, "alcore_google_state", { path: "/auth/google/callback" });
    return c.json({ error: "invalid_google_state" }, 400);
  }
  const transaction = googleStateStore.consume(state);
  deleteCookie(c, "alcore_google_state", { path: "/auth/google/callback" });
  if (transaction === null) return c.json({ error: "invalid_google_state" }, 400);
  const clientId = getGoogleClientId();
  const clientSecret = (process.env["GOOGLE_CLIENT_SECRET"] ?? "").trim();
  if (clientId === "" || clientSecret === "") return c.json({ error: "google_not_configured" }, 503);
  let tokenResponse: Response;
  try {
    tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: getGoogleRedirectUri(),
      grant_type: "authorization_code",
    }),
    signal: AbortSignal.timeout(10_000),
    });
  } catch {
    return c.json({ error: "upstream_unavailable" }, 503);
  }
  if (!tokenResponse.ok) return c.json({ error: "invalid_google_credential" }, 401);
  let tokenBody: unknown;
  try {
    tokenBody = await tokenResponse.json();
  } catch {
    return c.json({ error: "upstream_unavailable" }, 503);
  }
  if (typeof tokenBody !== "object" || tokenBody === null || typeof (tokenBody as Record<string, unknown>)["id_token"] !== "string") return c.json({ error: "invalid_google_credential" }, 401);
  let profile;
  try {
    profile = await verifyGoogleCredential(
      String((tokenBody as Record<string, unknown>)["id_token"]),
      transaction.nonce,
    );
  } catch (error) {
    if (error instanceof GoogleCredentialError) return c.json({ error: "invalid_google_credential" }, 401);
    if (error instanceof GoogleUpstreamError) return c.json({ error: "upstream_unavailable" }, 503);
    throw error;
  }
  const existing = userStore.findByProviderSub("google", profile.subject);
  const emailUser = userStore.findByEmail(profile.email);
  if (existing !== undefined && emailUser !== undefined && existing.id !== emailUser.id) {
    return c.json({ error: "identity_conflict" }, 409);
  }
  const user = existing ?? emailUser ?? userStore.create(profile.email, null);
  userStore.setVerified(user.id);
  const linkResult = userStore.linkIdentity(user.id, "google", profile.subject);
  if (linkResult === "owned_by_other_user") return c.json({ error: "identity_conflict" }, 409);
  const { pair } = issuePair(user.id);
  setAuthCookies(c, pair);
  return c.json({ ...pair, user: { id: user.id, email: user.email, emailVerified: true } });
});
