// ALcore Auth Repo C — identity-only auth routes.
// register / login / logout / refresh (rotating) / me / verify request+consume
// / reset request+consume / Google link callback (verified-sub STUB).
// Identity-only: no customers/billing/balance/usage/keys/subs anywhere.

import { Hono } from "hono";
import type { Context } from "hono";
import { setCookie, deleteCookie, getCookie } from "hono/cookie";
import { getJwtSecret, getIssuer } from "../config";
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
import { userStore, sessionStore } from "../lib/store";
import type { Session } from "../lib/store";
import { authRateLimit } from "../lib/ratelimit";

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
  const session = sessionStore.create(userId, hashToken(refresh), REFRESH_TTL_MS);
  const access = signAccess({ sub: userId, sid: session.id, iss: getIssuer() }, secret, ACCESS_TTL_SECONDS);
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
  return c.json({ id: user.id, email: user.email, emailVerified: user.emailVerified }, 201);
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
    { sub: session.userId, sid: session.id, iss: getIssuer() },
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
    const payload = verifyAccess(token, getJwtSecret(), getIssuer());
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
    const payload = verifyAccess(token, getJwtSecret(), getIssuer());
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
    // Prod sends this token by email; the HTTP surface never reveals existence.
    void mintPurposeToken(getJwtSecret(), "verify", user.id, VERIFY_TTL_SECONDS);
  }
  return c.json({ ok: true });
});

// POST /auth/verify/consume
authRoutes.post("/verify/consume", async (c) => {
  const body = await readJson(c);
  try {
    const { userId } = verifyPurposeToken(getJwtSecret(), "verify", str(body?.["token"]));
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
    void mintPurposeToken(getJwtSecret(), "reset", user.id, RESET_TTL_SECONDS);
  }
  return c.json({ ok: true });
});

// POST /auth/reset/consume — sets new password, revokes all sessions.
authRoutes.post("/reset/consume", async (c) => {
  const body = await readJson(c);
  const next = str(body?.["newPassword"]);
  if (next.length < 8) return c.json({ error: "weak_password" }, 400);
  try {
    const { userId } = verifyPurposeToken(getJwtSecret(), "reset", str(body?.["token"]));
    const user = userStore.findById(userId);
    if (user === undefined) return c.json({ error: "invalid_token" }, 400);
    userStore.setPasswordHash(userId, await hashPassword(next));
    sessionStore.revokeAllForUser(userId);
    return c.json({ ok: true });
  } catch (e) {
    if (!(e instanceof TokenError)) throw e;
    return c.json({ error: "invalid_token" }, 400);
  }
});

// GET /auth/google/callback — verified-sub STUB.
// Prod MUST verify Google ID tokens server-side; this stub trusts `sub`
// (+ `email`) query params so the link/no-dupe contract is provable without
// live Google. Same (provider, sub) always returns the SAME user id.
authRoutes.get("/google/callback", async (c) => {
  if (limited(c, "google")) return c.json({ error: "rate_limited" }, 429);
  const sub = (c.req.query("sub") ?? "").trim();
  const email = (c.req.query("email") ?? "").trim().toLowerCase();
  if (sub === "") return c.json({ error: "missing_sub" }, 400);
  const existing = userStore.findByProviderSub("google", sub);
  if (existing !== undefined) {
    const { pair } = issuePair(existing.id);
    setAuthCookies(c, pair);
    c.header("x-auth-reused", "true");
    return c.json({ ...pair, user: { id: existing.id, email: existing.email } });
  }
  // Verified-email match links to the existing password user (link-row).
  const byEmail = EMAIL_RE.test(email) ? userStore.findByEmail(email) : undefined;
  const target = byEmail ?? userStore.create(EMAIL_RE.test(email) ? email : `google-${sub}@stub.local`, null);
  if (byEmail === undefined) userStore.setVerified(target.id);
  else userStore.setVerified(target.id);
  userStore.linkIdentity(target.id, "google", sub);
  const { pair } = issuePair(target.id);
  setAuthCookies(c, pair);
  return c.json({ ...pair, user: { id: target.id, email: target.email } });
});
