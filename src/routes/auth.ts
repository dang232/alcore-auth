// ALcore Auth Repo C — identity-only auth routes.
// register / login / logout / refresh (rotating) / me / verify request+consume
// / reset request+consume / Google authorization-code callback (RS256/JWKS
// verification per todo 35; no query-param identity is ever honored).
// Identity-only: no customers/billing/balance/usage/keys/subs anywhere.

import { Hono } from "hono";
import type { Context } from "hono";
import { setCookie, deleteCookie, getCookie } from "hono/cookie";
import { getGoogleClientId, getGoogleRedirectUri, getJwtSecret, getIssuer, getJwtRotationKeys } from "../config";
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
import { googleStateStore, markPurposeConsumed, userStore, sessionStore } from "../lib/store";
import { verifyPasswordCompat } from "../lib/legacy-password";
import { emitAudit } from "../lib/audit";
import { GoogleCredentialError, GoogleUpstreamError, verifyGoogleCredential } from "../lib/google";
import type { Session } from "../lib/store";
import { limitedAsync as throttleGuard } from "../lib/ratelimit";
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

async function limitedAsync(c: Context, scope: string): Promise<Response | null> {
  const g = await throttleGuard(scope, clientIp(c));
  if (!g.limited) return null;
  c.header("Retry-After", String(g.retryAfterSec));
  return c.json(g.body, g.status as 429 | 503);
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

// Task 38 one-use purpose tokens: verify the stateless HMAC, then atomically
// mark sha256(purpose:token) consumed. Replay finds the mark and fails as
// invalid_token — same shape as a bad token, so no oracle. Null on any failure.
function consumePurposeOnce(secret: string, purpose: "verify" | "reset", token: string): { userId: string } | null {
  try {
    const { userId } = verifyPurposeToken(secret, purpose, token);
    if (!markPurposeConsumed(hashToken(`${purpose}:${token}`))) return null;
    return { userId };
  } catch (e) {
    if (e instanceof TokenError) return null;
    throw e;
  }
}

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: "Bearer";
  expires_in: number;
}

function issuePair(userId: string): { pair: TokenPair; session: Session } {
  const keys = getJwtRotationKeys();
  const refresh = randomToken(32);
  const sessionId = crypto.randomUUID();
  const access = signAccess({ sub: userId, sid: sessionId, iss: getIssuer(), aud: "auth", intent: "session" }, keys.current, ACCESS_TTL_SECONDS, { kid: keys.currentKid });
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
  const gateRegister = await limitedAsync(c, "register"); if (gateRegister !== null) return gateRegister;
  const body = await readJson(c);
  const email = str(body?.["email"]).trim().toLowerCase();
  const password = str(body?.["password"]);
  if (!EMAIL_RE.test(email)) {
    emitAudit("auth.register", "invalid_email", { ip: clientIp(c) });
    return c.json({ error: "invalid_email" }, 400);
  }
  if (password.length < 8) {
    emitAudit("auth.register", "weak_password", { ip: clientIp(c) });
    return c.json({ error: "weak_password" }, 400);
  }
  if (userStore.findByEmail(email) !== undefined) {
    // Intentional 409 (client needs the outcome to finish signup); login and
    // verify/reset-request surfaces stay non-enumerating (always-401 / always-200).
    emitAudit("auth.register", "email_taken", { ip: clientIp(c) });
    return c.json({ error: "email_taken" }, 409);
  }
  const user = userStore.create(email, await hashPassword(password));
  const { pair } = issuePair(user.id);
  setAuthCookies(c, pair);
  emitAudit("auth.register", "ok", { userId: user.id, ip: clientIp(c) });
  return c.json({ id: user.id, email: user.email, emailVerified: user.emailVerified, ...pair }, 201);
});

// POST /auth/login — identical 401 shape for unknown email vs bad password.
authRoutes.post("/login", async (c) => {
  const gateLogin = await limitedAsync(c, "login"); if (gateLogin !== null) return gateLogin;
  const body = await readJson(c);
  const email = str(body?.["email"]).trim().toLowerCase();
  const password = str(body?.["password"]);
  const user = EMAIL_RE.test(email) ? userStore.findByEmail(email) : undefined;
  if (user === undefined || user.passwordHash === null) {
    await verifyPassword(password === "" ? "x" : password, DUMMY_HASH);
    emitAudit("auth.login_failed", "invalid_credentials", { ip: clientIp(c) });
    return c.json(INVALID_CREDENTIALS, 401);
  }
  // Controlled bcrypt-compat path (task 43): legacy `$2*` hashes verify here
  // in Auth ONLY, then are REPLACED by a canonical Argon2id hash in a single
  // write. Wrong passwords never rehash; unsupported records fail closed with
  // the identical 401 shape (reset flow is the recovery path). No bcrypt hash
  // is ever stored canonically and nothing is dual-written.
  const compat = await verifyPasswordCompat(password, user.passwordHash);
  if (compat === "reset-required") {
    emitAudit("auth.login_reset_required", "reset_required", { userId: user.id, ip: clientIp(c) });
    return c.json(INVALID_CREDENTIALS, 401);
  }
  if (compat === "fail") {
    emitAudit("auth.login_failed", "invalid_credentials", { userId: user.id, ip: clientIp(c) });
    return c.json(INVALID_CREDENTIALS, 401);
  }
  if (compat === "legacy-ok") {
    userStore.setPasswordHash(user.id, await hashPassword(password));
    emitAudit("auth.password_rehash", "ok", { userId: user.id, ip: clientIp(c) });
  }
  const { pair } = issuePair(user.id);
  setAuthCookies(c, pair);
  emitAudit("auth.login", "ok", { userId: user.id, ip: clientIp(c) });
  return c.json({ ...pair, user: { id: user.id, email: user.email, emailVerified: user.emailVerified } });
});

// POST /auth/refresh — atomic single-use rotation; reuse → family revoke + 401.
authRoutes.post("/refresh", async (c) => {
  const gateRefresh = await limitedAsync(c, "refresh"); if (gateRefresh !== null) return gateRefresh;
  const body = await readJson(c);
  const presented = str(body?.["refresh_token"]) || getCookie(c, "alcore_rt") || "";
  if (presented === "") {
    emitAudit("auth.refresh", "invalid_grant", { ip: clientIp(c) });
    return c.json({ error: "invalid_grant" }, 401);
  }
  const digest = hashToken(presented);
  const session = sessionStore.findByRefreshHash(digest);
  if (session !== undefined && !session.revoked && session.expiresAt > Date.now()) {
    const next = randomToken(32);
    if (sessionStore.rotate(session, hashToken(next))) {
      const keys = getJwtRotationKeys();
      const access = signAccess(
        { sub: session.userId, sid: session.id, iss: getIssuer(), aud: "auth", intent: "session" },
        keys.current,
        ACCESS_TTL_SECONDS,
        { kid: keys.currentKid },
      );
      const pair: TokenPair = {
        access_token: access,
        refresh_token: next,
        token_type: "Bearer",
        expires_in: ACCESS_TTL_SECONDS,
      };
      setAuthCookies(c, pair);
      emitAudit("auth.refresh", "ok", { userId: session.userId, ip: clientIp(c) });
      return c.json(pair);
    }
  }
  // Lost the rotation race, or presented an already-rotated token: either way
  // the digest is now a reuse signal — revoke the whole family (theft signal).
  const reuse = sessionStore.findByRefreshOrPrevHash(digest);
  if (reuse !== undefined && sessionStore.isReusedHash(reuse, digest)) {
    sessionStore.revokeAllForUser(reuse.userId);
    emitAudit("auth.refresh_reuse", "invalid_grant", { userId: reuse.userId, ip: clientIp(c) });
  } else {
    emitAudit("auth.refresh", "invalid_grant", { ip: clientIp(c) });
  }
  return c.json({ error: "invalid_grant" }, 401);
});

// POST /auth/logout — revoke by refresh_token or Bearer session.
authRoutes.post("/logout", async (c) => {
  const body = await readJson(c);
  const byRefresh = str(body?.["refresh_token"]);
  if (byRefresh !== "") {
    const s = sessionStore.findByRefreshHash(hashToken(byRefresh));
    if (s !== undefined) {
      sessionStore.revoke(s);
      emitAudit("auth.logout", "ok", { userId: s.userId, ip: clientIp(c) });
    } else {
      emitAudit("auth.logout", "unknown_session", { ip: clientIp(c) });
    }
    clearAuthCookies(c);
    return c.json({ ok: true });
  }
  const token = bearer(c);
  if (token === "") {
    emitAudit("auth.logout", "unauthorized", { ip: clientIp(c) });
    return c.json({ error: "unauthorized" }, 401);
  }
  try {
    const payload = verifyAccess(token, getJwtRotationKeys(), getIssuer(), "auth", "session");
    const s = sessionStore.findById(payload.sid);
    if (s !== undefined) sessionStore.revoke(s);
    emitAudit("auth.logout", "ok", { userId: payload.sub, ip: clientIp(c) });
  } catch (e) {
    if (!(e instanceof JwtError)) throw e;
    emitAudit("auth.logout", "unauthorized", { ip: clientIp(c) });
    return c.json({ error: "unauthorized" }, 401);
  }
  clearAuthCookies(c);
  return c.json({ ok: true });
});

// GET /auth/me — Bearer access → user view.
authRoutes.get("/me", async (c) => {
  const token = bearer(c);
  if (token === "") {
    emitAudit("auth.session_read", "unauthorized", { ip: clientIp(c) });
    return c.json({ error: "unauthorized" }, 401);
  }
  try {
    const payload = verifyAccess(token, getJwtRotationKeys(), getIssuer(), "auth", "session");
    const view = userView(payload.sub);
    if (view === null) {
      emitAudit("auth.session_read", "unauthorized", { ip: clientIp(c) });
      return c.json({ error: "unauthorized" }, 401);
    }
    emitAudit("auth.session_read", "ok", { userId: payload.sub, ip: clientIp(c) });
    return c.json(view);
  } catch (e) {
    if (!(e instanceof JwtError)) throw e;
    emitAudit("auth.session_read", "unauthorized", { ip: clientIp(c) });
    return c.json({ error: "unauthorized" }, 401);
  }
});

// Session revocation contract (task 36b): JSON only, never sets cookies.
function requireLiveSession(c: Context): { userId: string; sessionId: string } | null {
  const token = bearer(c);
  if (token === "") return null;
  try {
    const payload = verifyAccess(token, getJwtRotationKeys(), getIssuer(), "auth", "session");
    const s = sessionStore.findById(payload.sid);
    if (s === undefined || s.revoked || s.expiresAt <= Date.now()) return null;
    if (s.userId !== payload.sub) return null;
    if (userStore.findById(payload.sub) === undefined) return null;
    return { userId: payload.sub, sessionId: payload.sid };
  } catch (e) {
    if (!(e instanceof JwtError)) throw e;
    return null;
  }
}

// GET /auth/sessions — list the caller's non-revoked sessions.
authRoutes.get("/sessions", async (c) => {
  const caller = requireLiveSession(c);
  if (caller === null) {
    emitAudit("auth.session_list", "unauthorized", { ip: clientIp(c) });
    return c.json({ error: "unauthorized" }, 401);
  }
  const sessions = sessionStore.listActiveForUser(caller.userId).map((s) => ({
    id: s.id,
    createdAt: s.createdAt,
    expiresAt: s.expiresAt,
    current: s.id === caller.sessionId,
  }));
  emitAudit("auth.session_list", "ok", { userId: caller.userId, ip: clientIp(c) });
  return c.json({ sessions });
});

// DELETE /auth/sessions/:id — revoke one of the caller's sessions by id.
authRoutes.delete("/sessions/:id", async (c) => {
  const caller = requireLiveSession(c);
  if (caller === null) {
    emitAudit("auth.session_revoke", "unauthorized", { ip: clientIp(c) });
    return c.json({ error: "unauthorized" }, 401);
  }
  const id = c.req.param("id");
  if (id === "" || sessionStore.findById(id)?.userId !== caller.userId) {
    emitAudit("auth.session_revoke", "session_not_found", { userId: caller.userId, ip: clientIp(c) });
    return c.json({ error: "session_not_found" }, 404);
  }
  sessionStore.revokeByIdForUser(id, caller.userId);
  if (id === caller.sessionId) clearAuthCookies(c);
  emitAudit("auth.session_revoke", "ok", { userId: caller.userId, ip: clientIp(c) });
  return c.json({ ok: true });
});

// POST /auth/change — authenticated password change.
// Requires a live session (same requireLiveSession gate as GET
// /auth/sessions). Wrong currentPassword → identical 401
// invalid_credentials (same shape as login: no enumeration signal).
// New-password strength reuses the register/reset rule (min length 8 →
// weak_password); no new rule is invented here.
// Session semantic (chosen): revoke-ALL-including-current + mint fresh.
// On success the hash is rotated to Argon2id, revokeAllForUser kills every
// session for the user INCLUDING the caller's, then a fresh pair is issued
// and set as cookies — the caller stays signed in on exactly one new
// session while all other sessions (and replays of old refresh tokens)
// 401. Tests below pin exactly this behavior.
authRoutes.post("/change", async (c) => {
  const caller = requireLiveSession(c);
  if (caller === null) {
    emitAudit("auth.password_change", "unauthorized", { ip: clientIp(c) });
    return c.json({ error: "unauthorized" }, 401);
  }
  const body = await readJson(c);
  const currentPassword = str(body?.["currentPassword"]);
  const newPassword = str(body?.["newPassword"]);
  if (newPassword.length < 8) {
    emitAudit("auth.password_change", "weak_password", { userId: caller.userId, ip: clientIp(c) });
    return c.json({ error: "weak_password" }, 400);
  }
  const user = userStore.findById(caller.userId);
  if (user === undefined || user.passwordHash === null) {
    // Google-only (or otherwise passwordless) account: run the same argon2
    // verify path as a real check so 401 latency reveals nothing.
    await verifyPassword(currentPassword === "" ? "x" : currentPassword, DUMMY_HASH);
    emitAudit("auth.password_change", "invalid_credentials", { userId: caller.userId, ip: clientIp(c) });
    return c.json(INVALID_CREDENTIALS, 401);
  }
  // Same compat path as login: a legacy-bcrypt current password verifies and
  // is then replaced by the new Argon2id hash below (single write); wrong or
  // unsupported current passwords fail with the identical 401 shape.
  const changeCompat = await verifyPasswordCompat(currentPassword, user.passwordHash);
  if (changeCompat !== "argon2-ok" && changeCompat !== "legacy-ok") {
    if (changeCompat === "reset-required") {
      emitAudit("auth.password_change", "reset_required", { userId: caller.userId, ip: clientIp(c) });
    } else {
      emitAudit("auth.password_change", "invalid_credentials", { userId: caller.userId, ip: clientIp(c) });
    }
    return c.json(INVALID_CREDENTIALS, 401);
  }
  userStore.setPasswordHash(caller.userId, await hashPassword(newPassword));
  sessionStore.revokeAllForUser(caller.userId);
  const { pair } = issuePair(caller.userId);
  setAuthCookies(c, pair);
  emitAudit("auth.password_change", "ok", { userId: caller.userId, ip: clientIp(c) });
  return c.json({ ok: true, ...pair });
});

// POST /auth/verify/request — always 200 (no enumeration).
authRoutes.post("/verify/request", async (c) => {
  const gateVerify = await limitedAsync(c, "verify"); if (gateVerify !== null) return gateVerify;
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
  emitAudit("auth.verify_request", "ok", { ip: clientIp(c) });
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
// Throttle-gated under the shared auth:verify bucket (task 38 decision): the
// consume path is a public unauthenticated token-guessing surface exactly like
// the request path, so it shares the request path's budget and fail-closed
// semantics. One-use via consumePurposeOnce: replay → invalid_token.
authRoutes.post("/verify/consume", async (c) => {
  const gateVerifyConsume = await limitedAsync(c, "verify"); if (gateVerifyConsume !== null) return gateVerifyConsume;
  const { token } = await readPurposeBody(c);
  const hit = consumePurposeOnce(getJwtSecret(), "verify", token);
  if (hit === null) {
    emitAudit("auth.verify_consume", "invalid_token", { ip: clientIp(c) });
    return c.json({ error: "invalid_token" }, 400);
  }
  const user = userStore.findById(hit.userId);
  if (user === undefined) {
    emitAudit("auth.verify_consume", "invalid_token", { ip: clientIp(c) });
    return c.json({ error: "invalid_token" }, 400);
  }
  userStore.setVerified(hit.userId);
  emitAudit("auth.verify_consume", "ok", { userId: hit.userId, ip: clientIp(c) });
  return c.json({ ok: true });
});

// POST /auth/reset/request — always 200 (no enumeration).
authRoutes.post("/reset/request", async (c) => {
  const gateReset = await limitedAsync(c, "reset"); if (gateReset !== null) return gateReset;
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
  emitAudit("auth.reset_request", "ok", { ip: clientIp(c) });
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
// Throttle-gated under the shared auth:reset bucket (task 38 decision, same
// rationale as verify/consume). One-use via consumePurposeOnce.
authRoutes.post("/reset/consume", async (c) => {
  const gateResetConsume = await limitedAsync(c, "reset"); if (gateResetConsume !== null) return gateResetConsume;
  const { token, newPassword } = await readPurposeBody(c);
  if (newPassword.length < 8) {
    emitAudit("auth.reset_consume", "weak_password", { ip: clientIp(c) });
    return c.json({ error: "weak_password" }, 400);
  }
  const hit = consumePurposeOnce(getJwtSecret(), "reset", token);
  if (hit === null) {
    emitAudit("auth.reset_consume", "invalid_token", { ip: clientIp(c) });
    return c.json({ error: "invalid_token" }, 400);
  }
  const user = userStore.findById(hit.userId);
  if (user === undefined) {
    emitAudit("auth.reset_consume", "invalid_token", { ip: clientIp(c) });
    return c.json({ error: "invalid_token" }, 400);
  }
  userStore.setPasswordHash(hit.userId, await hashPassword(newPassword));
  sessionStore.revokeAllForUser(hit.userId);
  emitAudit("auth.reset_consume", "ok", { userId: hit.userId, ip: clientIp(c) });
  return c.json({ ok: true });
});

authRoutes.get("/google/config", (c) => c.json({ clientId: getGoogleClientId() }));

authRoutes.post("/google/verify", async (c) => {
  const gateGoogleVerify = await limitedAsync(c, "google-verify"); if (gateGoogleVerify !== null) return gateGoogleVerify;
  const body = await readJson(c);
  const idToken = str(body?.["idToken"]);
  if (idToken === "" || new TextEncoder().encode(idToken).byteLength > 8192) {
    emitAudit("auth.oauth_callback", "invalid_credentials", { ip: clientIp(c) });
    return c.json(INVALID_CREDENTIALS, 401);
  }
  if (getGoogleClientId() === "") {
    emitAudit("auth.oauth_callback", "google_not_configured", { ip: clientIp(c) });
    return c.json({ error: "google_not_configured" }, 503);
  }
  let profile;
  try {
    profile = await verifyGoogleCredential(idToken);
  } catch (error) {
    if (error instanceof GoogleCredentialError) {
      emitAudit("auth.oauth_callback", "invalid_credentials", { ip: clientIp(c) });
      return c.json(INVALID_CREDENTIALS, 401);
    }
    if (error instanceof GoogleUpstreamError) {
      emitAudit("auth.oauth_callback", "upstream_unavailable", { ip: clientIp(c) });
      return c.json({ error: "upstream_unavailable" }, 502);
    }
    throw error;
  }
  const existing = userStore.findByProviderSub("google", profile.subject);
  const emailUser = userStore.findByEmail(profile.email);
  if (existing !== undefined && emailUser !== undefined && existing.id !== emailUser.id) {
    emitAudit("auth.identity_conflict", "identity_conflict", { ip: clientIp(c) });
    return c.json({ error: "identity_conflict" }, 409);
  }
  const user = existing ?? emailUser ?? userStore.create(profile.email, null);
  userStore.setVerified(user.id);
  if (userStore.linkIdentity(user.id, "google", profile.subject) === "owned_by_other_user") {
    emitAudit("auth.identity_conflict", "identity_conflict", { ip: clientIp(c) });
    return c.json({ error: "identity_conflict" }, 409);
  }
  const { pair } = issuePair(user.id);
  setAuthCookies(c, pair);
  emitAudit("auth.oauth_callback", "ok", { userId: user.id, ip: clientIp(c) });
  return c.json({ access_token: pair.access_token });
});

authRoutes.get("/google/start", (c) => {
  const clientId = getGoogleClientId();
  if (clientId === "") {
    emitAudit("auth.oauth_start", "google_not_configured", { ip: clientIp(c) });
    return c.json({ error: "google_not_configured" }, 503);
  }
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
  emitAudit("auth.oauth_start", "ok", { ip: clientIp(c) });
  return c.redirect(url.toString(), 302);
});

authRoutes.get("/google/callback", async (c) => {
  const gateGoogle = await limitedAsync(c, "google"); if (gateGoogle !== null) return gateGoogle;
  if (c.req.query("error") !== undefined) {
    emitAudit("auth.oauth_callback", "google_oauth_error", { ip: clientIp(c) });
    return c.json({ error: "google_oauth_error" }, 400);
  }
  const state = c.req.query("state") ?? "";
  const code = c.req.query("code") ?? "";
  const expectedState = getCookie(c, "alcore_google_state") ?? "";
  if (state === "" || code === "" || state !== expectedState) {
    deleteCookie(c, "alcore_google_state", { path: "/auth/google/callback" });
    emitAudit("auth.oauth_callback", "invalid_google_state", { ip: clientIp(c) });
    return c.json({ error: "invalid_google_state" }, 400);
  }
  const transaction = googleStateStore.consume(state);
  deleteCookie(c, "alcore_google_state", { path: "/auth/google/callback" });
  if (transaction === null) {
    emitAudit("auth.oauth_callback", "invalid_google_state", { ip: clientIp(c) });
    return c.json({ error: "invalid_google_state" }, 400);
  }
  const clientId = getGoogleClientId();
  const clientSecret = (process.env["GOOGLE_CLIENT_SECRET"] ?? "").trim();
  if (clientId === "" || clientSecret === "") {
    emitAudit("auth.oauth_callback", "google_not_configured", { ip: clientIp(c) });
    return c.json({ error: "google_not_configured" }, 503);
  }
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
    emitAudit("auth.oauth_callback", "upstream_unavailable", { ip: clientIp(c) });
    return c.json({ error: "upstream_unavailable" }, 503);
  }
  if (!tokenResponse.ok) {
    emitAudit("auth.oauth_callback", "invalid_google_credential", { ip: clientIp(c) });
    return c.json({ error: "invalid_google_credential" }, 401);
  }
  let tokenBody: unknown;
  try {
    tokenBody = await tokenResponse.json();
  } catch {
    emitAudit("auth.oauth_callback", "upstream_unavailable", { ip: clientIp(c) });
    return c.json({ error: "upstream_unavailable" }, 503);
  }
  if (typeof tokenBody !== "object" || tokenBody === null || typeof (tokenBody as Record<string, unknown>)["id_token"] !== "string") {
    emitAudit("auth.oauth_callback", "invalid_google_credential", { ip: clientIp(c) });
    return c.json({ error: "invalid_google_credential" }, 401);
  }
  let profile;
  try {
    profile = await verifyGoogleCredential(
      String((tokenBody as Record<string, unknown>)["id_token"]),
      transaction.nonce,
    );
  } catch (error) {
    if (error instanceof GoogleCredentialError) {
      emitAudit("auth.oauth_callback", "invalid_google_credential", { ip: clientIp(c) });
      return c.json({ error: "invalid_google_credential" }, 401);
    }
    if (error instanceof GoogleUpstreamError) {
      emitAudit("auth.oauth_callback", "upstream_unavailable", { ip: clientIp(c) });
      return c.json({ error: "upstream_unavailable" }, 503);
    }
    throw error;
  }
  const existing = userStore.findByProviderSub("google", profile.subject);
  const emailUser = userStore.findByEmail(profile.email);
  if (existing !== undefined && emailUser !== undefined && existing.id !== emailUser.id) {
    emitAudit("auth.identity_conflict", "identity_conflict", { ip: clientIp(c) });
    return c.json({ error: "identity_conflict" }, 409);
  }
  const user = existing ?? emailUser ?? userStore.create(profile.email, null);
  userStore.setVerified(user.id);
  const linkResult = userStore.linkIdentity(user.id, "google", profile.subject);
  if (linkResult === "owned_by_other_user") {
    emitAudit("auth.identity_conflict", "identity_conflict", { ip: clientIp(c) });
    return c.json({ error: "identity_conflict" }, 409);
  }
  const { pair } = issuePair(user.id);
  setAuthCookies(c, pair);
  emitAudit("auth.oauth_callback", "ok", { userId: user.id, ip: clientIp(c) });
  return c.json({ ...pair, user: { id: user.id, email: user.email, emailVerified: true } });
});
