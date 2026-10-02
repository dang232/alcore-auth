// Task 38 — Auth lifecycle, audit, and browser handoff contract suite.
//
// Contract-first: every acceptance bullet in plan todo 38 gets happy + failure
// cases here. Behavior of record lives in the neighboring suites (auth,
// exchange-redirect, mail, rotation, persistence, throttle); this file pins
// only the lifecycle/audit/handoff gaps those suites leave open:
//  - audit emission per transition (auth.* events, no secrets in rows)
//  - PKCE S256 on /oidc/authorize + /oidc/token (plain rejected)
//  - one-use verify/reset purpose tokens (replay → invalid_token)
//  - consume-path throttle gating (verify/consume + reset/consume share the
//    request-path buckets, fail closed)
//  - exact cookie flags, client isolation, generic errors, no-JWT-in-URL.
//
// Dummy secrets only. Self-isolating: stores + buckets + audit cleared per
// test, OIDC env saved/restored (bun shares one process across test files).

process.env["JWT_SECRET"] = "test-only-dummy-secret-0123456789abcdef";
process.env["ALLOW_WEAK_JWT_SECRET"] = "1";
process.env["NODE_ENV"] = "test";

const ENV_KEYS = ["AUTH_ISSUER", "AUTH_OIDC_CLIENTS", "AUTH_ALLOWED_ORIGINS"] as const;
const ENV_BACKUP = new Map<string, string | undefined>(ENV_KEYS.map((k) => [k, process.env[k]]));

const LIBRE_CLIENT = "libre";
const PANEL_CLIENT = "tokenpanel";
const LIBRE_REDIRECT = "https://web.alcore.io.vn/auth/callback";
const PANEL_REDIRECT = "https://portal.alcore.io.vn/auth/callback";

function applyTask38Env(): void {
  process.env["AUTH_ISSUER"] = "https://auth.alcore.io.vn";
  process.env["AUTH_OIDC_CLIENTS"] = `${LIBRE_CLIENT}=${LIBRE_REDIRECT},${PANEL_CLIENT}=${PANEL_REDIRECT}`;
  process.env["AUTH_ALLOWED_ORIGINS"] = "https://web.alcore.io.vn,https://portal.alcore.io.vn";
}

function restoreEnv(): void {
  for (const [k, v] of ENV_BACKUP) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
}

import { describe, test, expect, beforeEach, afterAll } from "bun:test";
import { app } from "../src/index";
import { getJwtSecret } from "../src/config";
import { mintPurposeToken, pkceS256Challenge } from "../src/lib/crypto";
import { resetRateLimitsForTests, resetThrottleConnForTests } from "../src/lib/ratelimit";
import { resetStoresForTests, userStore } from "../src/lib/store";
import { clearAuditForTests, listAuditForTests } from "../src/lib/audit";
import { resetGoogleJwksCacheForTests } from "../src/lib/google";
import { baseGoogleClaims, createGoogleTestRig, TEST_GOOGLE_CLIENT_ID } from "./google-jwks-helper";

resetStoresForTests();
clearAuditForTests();

beforeEach(() => {
  resetStoresForTests();
  clearAuditForTests();
  resetRateLimitsForTests();
  resetThrottleConnForTests();
  resetGoogleJwksCacheForTests();
  applyTask38Env();
});

afterAll(() => {
  restoreEnv();
});

async function post(path: string, body: unknown, headers: Record<string, string> = {}): Promise<Response> {
  return app.request(path, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

async function authed(path: string, token: string, init?: RequestInit): Promise<Response> {
  return app.request(path, { ...init, headers: { authorization: `Bearer ${token}`, ...(init?.headers ?? {}) } });
}

async function registerLogin(email: string, password: string): Promise<{ id: string; access_token: string; refresh_token: string }> {
  const reg = await post("/auth/register", { email, password });
  expect(reg.status).toBe(201);
  const login = await post("/auth/login", { email, password });
  expect(login.status).toBe(200);
  const body = (await login.json()) as { access_token: string; refresh_token: string };
  const me = (await authed("/auth/me", body.access_token).then((r) => r.json())) as { id: string };
  return { id: me.id, ...body };
}

function auditEvents(): Array<{ event: string; outcome: string }> {
  return listAuditForTests().map((r) => ({ event: r.event, outcome: r.outcome }));
}

function saw(event: string, outcome: string): boolean {
  return auditEvents().some((r) => r.event === event && r.outcome === outcome);
}

describe("registration lifecycle", () => {
  test("register → 201 with session pair + auth.register ok", async () => {
    const res = await post("/auth/register", { email: "lh-reg1@example.com", password: "s3cret-pass" });
    expect(res.status).toBe(201);
    const body = (await res.json()) as Record<string, unknown>;
    expect(typeof body["id"]).toBe("string");
    expect(body["email"]).toBe("lh-reg1@example.com");
    expect(body["emailVerified"]).toBe(false);
    expect(body["token_type"]).toBe("Bearer");
    expect(body["expires_in"]).toBe(900);
    expect(typeof body["access_token"]).toBe("string");
    expect(typeof body["refresh_token"]).toBe("string");
    expect(saw("auth.register", "ok")).toBe(true);
  });

  test("register rejects bad email / weak password / taken email with audit", async () => {
    expect((await post("/auth/register", { email: "not-an-email", password: "s3cret-pass" })).status).toBe(400);
    expect((await post("/auth/register", { email: "lh-reg2@example.com", password: "short" })).status).toBe(400);
    expect((await post("/auth/register", { email: "lh-reg2@example.com", password: "s3cret-pass" })).status).toBe(201);
    const taken = await post("/auth/register", { email: "lh-reg2@example.com", password: "s3cret-pass" });
    expect(taken.status).toBe(409);
    expect(await taken.json()).toEqual({ error: "email_taken" });
    const outcomes = auditEvents().filter((r) => r.event === "auth.register").map((r) => r.outcome);
    expect(outcomes).toContain("invalid_email");
    expect(outcomes).toContain("weak_password");
    expect(outcomes).toContain("email_taken");
    expect(outcomes).toContain("ok");
  });
});

describe("login + exact cookie flags + generic errors", () => {
  test("login mints exact cookie flags and identical 401s leak nothing", async () => {
    await post("/auth/register", { email: "lh-login1@example.com", password: "s3cret-pass" });
    const res = await post("/auth/login", { email: "lh-login1@example.com", password: "s3cret-pass" });
    expect(res.status).toBe(200);
    const cookies = res.headers.getSetCookie();
    const at = cookies.find((v) => v.startsWith("alcore_at=")) ?? "";
    const rt = cookies.find((v) => v.startsWith("alcore_rt=")) ?? "";
    for (const cookie of [at, rt]) {
      expect(cookie).toContain("HttpOnly");
      expect(cookie).toContain("Secure");
      expect(cookie).toContain("SameSite=Strict");
      expect(cookie).toContain("Path=/");
    }
    expect(at).toContain("Max-Age=900");
    expect(rt).toContain("Max-Age=2592000");
    const unknown = await post("/auth/login", { email: "lh-nobody@example.com", password: "s3cret-pass" });
    const wrong = await post("/auth/login", { email: "lh-login1@example.com", password: "wrong-pass" });
    expect(unknown.status).toBe(401);
    const unknownBody = await unknown.json();
    expect(unknownBody).toEqual(await wrong.json());
    expect(unknownBody).toEqual({ error: "invalid_credentials" });
    expect(saw("auth.login", "ok")).toBe(true);
    expect(auditEvents().filter((r) => r.event === "auth.login_failed").length).toBe(2);
  });

  test("GET /auth/me reads the session and audits session_read", async () => {
    const { access_token } = await registerLogin("lh-me1@example.com", "s3cret-pass");
    const me = await authed("/auth/me", access_token);
    expect(me.status).toBe(200);
    expect((await me.json()) as Record<string, unknown>).toMatchObject({ email: "lh-me1@example.com" });
    const bad = await authed("/auth/me", "not-a-token");
    expect(bad.status).toBe(401);
    expect(saw("auth.session_read", "ok")).toBe(true);
    expect(saw("auth.session_read", "unauthorized")).toBe(true);
  });
});

describe("refresh rotation + reuse family revoke + logout", () => {
  test("reuse revokes the whole family and audits refresh_reuse", async () => {
    const first = await registerLogin("lh-reuse1@example.com", "s3cret-pass");
    const secondLogin = await post("/auth/login", { email: "lh-reuse1@example.com", password: "s3cret-pass" });
    const second = (await secondLogin.json()) as { refresh_token: string; access_token: string };
    const r1 = await post("/auth/refresh", { refresh_token: first.refresh_token });
    expect(r1.status).toBe(200);
    const reuse = await post("/auth/refresh", { refresh_token: first.refresh_token });
    expect(reuse.status).toBe(401);
    expect(await reuse.json()).toEqual({ error: "invalid_grant" });
    // Family revoke: the sibling session's refresh is dead too.
    expect((await post("/auth/refresh", { refresh_token: second.refresh_token })).status).toBe(401);
    // Revocation is enforced on session-bound surfaces. GET /auth/me stays a
    // stateless JWT read by design (pinned by the rotation overlap suite: it
    // must 200 for previous-key tokens), so the proof uses /auth/sessions.
    expect((await authed("/auth/sessions", second.access_token)).status).toBe(401);
    expect(saw("auth.refresh", "ok")).toBe(true);
    expect(saw("auth.refresh_reuse", "invalid_grant")).toBe(true);
  });

  test("logout revokes, clears cookies, and audits; bare logout 401s", async () => {
    const { refresh_token } = await registerLogin("lh-logout1@example.com", "s3cret-pass");
    const out = await post("/auth/logout", { refresh_token });
    expect(out.status).toBe(200);
    expect(await out.json()).toEqual({ ok: true });
    const cleared = out.headers.getSetCookie().join("; ");
    expect(cleared).toContain("alcore_at=");
    expect(cleared).toContain("alcore_rt=");
    expect((await post("/auth/refresh", { refresh_token })).status).toBe(401);
    const bare = await post("/auth/logout", {});
    expect(bare.status).toBe(401);
    expect(saw("auth.logout", "ok")).toBe(true);
    expect(saw("auth.logout", "unauthorized")).toBe(true);
  });
});

describe("verification one-use + non-enumeration", () => {
  test("request always 200 identical; consume verifies once, replay 400", async () => {
    const known = await post("/auth/verify/request", { email: "lh-v1@example.com" });
    await post("/auth/register", { email: "lh-v1@example.com", password: "s3cret-pass" });
    const a = await post("/auth/verify/request", { email: "lh-v1@example.com" });
    const b = await post("/auth/verify/request", { email: "lh-ghost@example.com" });
    expect(a.status).toBe(200);
    expect(await a.text()).toBe(await b.text());
    const user = userStore.findByEmail("lh-v1@example.com");
    expect(user).toBeDefined();
    const token = mintPurposeToken(getJwtSecret(), "verify", user!.id, 3600);
    expect((await post("/auth/verify/consume", { token })).status).toBe(200);
    expect(userStore.findByEmail("lh-v1@example.com")?.emailVerified).toBe(true);
    const replay = await post("/auth/verify/consume", { token });
    expect(replay.status).toBe(400);
    expect(await replay.json()).toEqual({ error: "invalid_token" });
    expect(saw("auth.verify_request", "ok")).toBe(true);
    expect(saw("auth.verify_consume", "ok")).toBe(true);
    expect(saw("auth.verify_consume", "invalid_token")).toBe(true);
    expect(known.status).toBe(200);
  });
});

describe("reset one-use + session revoke + non-enumeration", () => {
  test("request identical bodies; consume rotates + revokes all; replay 400", async () => {
    await post("/auth/register", { email: "lh-r1@example.com", password: "old-pass-123" });
    const a = await post("/auth/reset/request", { email: "lh-r1@example.com" });
    const b = await post("/auth/reset/request", { email: "lh-ghost2@example.com" });
    expect(a.status).toBe(200);
    expect(await a.text()).toBe(await b.text());
    const login = await post("/auth/login", { email: "lh-r1@example.com", password: "old-pass-123" });
    expect(login.status).toBe(200);
    const lbody = (await login.json()) as { access_token: string; refresh_token: string };
    const s = { ...(await (await authed("/auth/me", lbody.access_token)).json() as { id: string }), ...lbody };
    const token = mintPurposeToken(getJwtSecret(), "reset", s.id, 3600);
    expect((await post("/auth/reset/consume", { token, newPassword: "new-pass-456" })).status).toBe(200);
    expect((await post("/auth/login", { email: "lh-r1@example.com", password: "old-pass-123" })).status).toBe(401);
    expect((await post("/auth/login", { email: "lh-r1@example.com", password: "new-pass-456" })).status).toBe(200);
    // All pre-reset sessions revoked (proven on session-bound surfaces;
    // /auth/me is a stateless JWT read by design, see the refresh test note).
    expect((await authed("/auth/sessions", s.access_token)).status).toBe(401);
    expect((await post("/auth/refresh", { refresh_token: s.refresh_token })).status).toBe(401);
    // One-use: replay rejected.
    const replay = await post("/auth/reset/consume", { token, newPassword: "another-789" });
    expect(replay.status).toBe(400);
    expect(await replay.json()).toEqual({ error: "invalid_token" });
    const weak = await post("/auth/reset/consume", { token: "v1.reset.x.1.bad", newPassword: "short" });
    expect(weak.status).toBe(400);
    expect(saw("auth.reset_request", "ok")).toBe(true);
    expect(saw("auth.reset_consume", "ok")).toBe(true);
    expect(saw("auth.reset_consume", "invalid_token")).toBe(true);
  });
});

describe("password change lifecycle", () => {
  test("change rotates + audits; wrong/weak/anon rejected", async () => {
    const s = await registerLogin("lh-ch1@example.com", "old-pass-123");
    const change = (token: string, body: unknown) =>
      app.request("/auth/change", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
        body: JSON.stringify(body),
      });
    expect((await change(s.access_token, { currentPassword: "old-pass-123", newPassword: "short" })).status).toBe(400);
    const wrong = await change(s.access_token, { currentPassword: "nope", newPassword: "new-pass-456" });
    expect(wrong.status).toBe(401);
    expect(await wrong.json()).toEqual({ error: "invalid_credentials" });
    const ok = await change(s.access_token, { currentPassword: "old-pass-123", newPassword: "new-pass-456" });
    expect(ok.status).toBe(200);
    expect((await post("/auth/login", { email: "lh-ch1@example.com", password: "new-pass-456" })).status).toBe(200);
    expect((await change("", { currentPassword: "x", newPassword: "new-pass-456" })).status).toBe(401);
    expect(saw("auth.password_change", "ok")).toBe(true);
    expect(saw("auth.password_change", "invalid_credentials")).toBe(true);
    expect(saw("auth.password_change", "weak_password")).toBe(true);
    expect(saw("auth.password_change", "unauthorized")).toBe(true);
  });
});

describe("session listing + revocation", () => {
  test("list flags current; revoke other kills only it; revoke foreign 404s", async () => {
    const first = await registerLogin("lh-sess1@example.com", "s3cret-pass");
    const secondLogin = await post("/auth/login", { email: "lh-sess1@example.com", password: "s3cret-pass" });
    const second = (await secondLogin.json()) as { access_token: string };
    const listed = (await (await authed("/auth/sessions", first.access_token)).json()) as {
      sessions: Array<{ id: string; current: boolean }>;
    };
    // register mints 1 session + each login mints 1 → 3 live sessions here.
    expect(listed.sessions).toHaveLength(3);
    expect(listed.sessions.filter((s) => s.current)).toHaveLength(1);
    // Revoke the second login's own session: resolve its id from its own
    // listing (current=true there), delete via the first token.
    const secondListed = (await (await authed("/auth/sessions", second.access_token)).json()) as {
      sessions: Array<{ id: string; current: boolean }>;
    };
    const secondId = secondListed.sessions.find((s) => s.current)!.id;
    const del = await app.request(`/auth/sessions/${secondId}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${first.access_token}` },
    });
    expect(del.status).toBe(200);
    expect((await authed("/auth/sessions", second.access_token)).status).toBe(401);
    expect((await authed("/auth/sessions", first.access_token)).status).toBe(200);
    // Foreign session id → 404, never 401-oracle difference beyond the code.
    const alien = await registerLogin("lh-sess2@example.com", "s3cret-pass");
    const alienList = (await (await authed("/auth/sessions", alien.access_token)).json()) as {
      sessions: Array<{ id: string }>;
    };
    const cross = await app.request(`/auth/sessions/${alienList.sessions[0]!.id}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${first.access_token}` },
    });
    expect(cross.status).toBe(404);
    expect(await cross.json()).toEqual({ error: "session_not_found" });
    const anon = await app.request(`/auth/sessions/${secondId}`, { method: "DELETE" });
    expect(anon.status).toBe(401);
    expect(saw("auth.session_list", "ok")).toBe(true);
    expect(saw("auth.session_revoke", "ok")).toBe(true);
    expect(saw("auth.session_revoke", "session_not_found")).toBe(true);
    expect(saw("auth.session_revoke", "unauthorized")).toBe(true);
  });
});

describe("PKCE S256 on OIDC code flow", () => {
  const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const challenge = pkceS256Challenge(verifier);

  async function session(email: string): Promise<string> {
    return (await registerLogin(email, "s3cret-pass")).access_token;
  }

  test("S256 happy path: challenge → code → verifier → 200 + audit", async () => {
    const token = await session("lh-pkce1@example.com");
    const auth = await app.request(
      `/oidc/authorize?response_type=code&client_id=${LIBRE_CLIENT}&redirect_uri=${encodeURIComponent(LIBRE_REDIRECT)}&state=s1&code_challenge=${challenge}&code_challenge_method=S256`,
      { headers: { authorization: `Bearer ${token}` } },
    );
    expect(auth.status).toBe(302);
    const code = new URL(auth.headers.get("location") ?? "https://invalid").searchParams.get("code") ?? "";
    expect(code).not.toBe("");
    const t = await post("/oidc/token", {
      grant_type: "authorization_code",
      code,
      redirect_uri: LIBRE_REDIRECT,
      client_id: LIBRE_CLIENT,
      code_verifier: verifier,
    });
    expect(t.status).toBe(200);
    expect(saw("auth.oidc_authorize", "ok")).toBe(true);
    expect(saw("auth.oidc_token", "ok")).toBe(true);
  });

  test("plain method rejected; challenge without method rejected", async () => {
    const token = await session("lh-pkce2@example.com");
    const plain = await app.request(
      `/oidc/authorize?response_type=code&client_id=${LIBRE_CLIENT}&redirect_uri=${encodeURIComponent(LIBRE_REDIRECT)}&code_challenge=${challenge}&code_challenge_method=plain`,
      { headers: { authorization: `Bearer ${token}` } },
    );
    expect(plain.status).toBe(400);
    expect(await plain.json()).toEqual({ error: "invalid_pkce_method" });
    const noMethod = await app.request(
      `/oidc/authorize?response_type=code&client_id=${LIBRE_CLIENT}&redirect_uri=${encodeURIComponent(LIBRE_REDIRECT)}&code_challenge=${challenge}`,
      { headers: { authorization: `Bearer ${token}` } },
    );
    expect(noMethod.status).toBe(400);
    expect(await noMethod.json()).toEqual({ error: "invalid_pkce_method" });
    expect(saw("auth.oidc_authorize", "invalid_pkce_method")).toBe(true);
  });

  test("wrong or missing verifier → invalid_grant and the code is NOT burned", async () => {
    const token = await session("lh-pkce3@example.com");
    const auth = await app.request(
      `/oidc/authorize?response_type=code&client_id=${LIBRE_CLIENT}&redirect_uri=${encodeURIComponent(LIBRE_REDIRECT)}&code_challenge=${challenge}&code_challenge_method=S256`,
      { headers: { authorization: `Bearer ${token}` } },
    );
    const code = new URL(auth.headers.get("location") ?? "https://invalid").searchParams.get("code") ?? "";
    const wrong = await post("/oidc/token", {
      grant_type: "authorization_code",
      code,
      redirect_uri: LIBRE_REDIRECT,
      client_id: LIBRE_CLIENT,
      code_verifier: `${verifier}tampered`,
    });
    expect(wrong.status).toBe(400);
    expect(await wrong.json()).toEqual({ error: "invalid_grant" });
    const missing = await post("/oidc/token", {
      grant_type: "authorization_code",
      code,
      redirect_uri: LIBRE_REDIRECT,
      client_id: LIBRE_CLIENT,
    });
    expect(missing.status).toBe(400);
    // Correct verifier still redeems: failed attempts never consumed the code.
    const good = await post("/oidc/token", {
      grant_type: "authorization_code",
      code,
      redirect_uri: LIBRE_REDIRECT,
      client_id: LIBRE_CLIENT,
      code_verifier: verifier,
    });
    expect(good.status).toBe(200);
    expect(saw("auth.oidc_token", "invalid_grant")).toBe(true);
  });

  test("legacy code without PKCE still exchanges (backward compatible)", async () => {
    const token = await session("lh-pkce4@example.com");
    const auth = await app.request(
      `/oidc/authorize?response_type=code&client_id=${LIBRE_CLIENT}&redirect_uri=${encodeURIComponent(LIBRE_REDIRECT)}`,
      { headers: { authorization: `Bearer ${token}` } },
    );
    expect(auth.status).toBe(302);
    const code = new URL(auth.headers.get("location") ?? "https://invalid").searchParams.get("code") ?? "";
    expect(
      (await post("/oidc/token", { grant_type: "authorization_code", code, redirect_uri: LIBRE_REDIRECT, client_id: LIBRE_CLIENT })).status,
    ).toBe(200);
  });
});

describe("client isolation + open redirect + no-JWT-in-URL", () => {
  test("unknown client / URI mismatch rejected as JSON, never a redirect", async () => {
    const token = (await registerLogin("lh-iso1@example.com", "s3cret-pass")).access_token;
    const unknown = await app.request(
      `/oidc/authorize?response_type=code&client_id=nope&redirect_uri=${encodeURIComponent(LIBRE_REDIRECT)}`,
      { headers: { authorization: `Bearer ${token}` } },
    );
    expect(unknown.status).toBe(400);
    expect(await unknown.json()).toEqual({ error: "invalid_redirect_uri" });
    expect(unknown.headers.get("location")).toBeNull();
    for (const evil of [
      "https://evil.example.com/auth/callback",
      "https://web.alcore.io.vn.evil.example/auth/callback",
      "http://web.alcore.io.vn/auth/callback",
    ]) {
      const res = await app.request(
        `/oidc/authorize?response_type=code&client_id=${LIBRE_CLIENT}&redirect_uri=${encodeURIComponent(evil)}`,
        { headers: { authorization: `Bearer ${token}` } },
      );
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: "invalid_redirect_uri" });
    }
    expect(saw("auth.oidc_authorize", "invalid_redirect_uri")).toBe(true);
  });

  test("code minted for libre cannot redeem as tokenpanel (both directions)", async () => {
    const token = (await registerLogin("lh-iso2@example.com", "s3cret-pass")).access_token;
    const auth = await app.request(
      `/oidc/authorize?response_type=code&client_id=${LIBRE_CLIENT}&redirect_uri=${encodeURIComponent(LIBRE_REDIRECT)}`,
      { headers: { authorization: `Bearer ${token}` } },
    );
    const code = new URL(auth.headers.get("location") ?? "https://invalid").searchParams.get("code") ?? "";
    const cross = await post("/oidc/token", {
      grant_type: "authorization_code",
      code,
      redirect_uri: PANEL_REDIRECT,
      client_id: PANEL_CLIENT,
    });
    expect(cross.status).toBe(400);
    expect(await cross.json()).toEqual({ error: "invalid_grant" });
    expect(saw("auth.oidc_token", "invalid_grant")).toBe(true);
  });

  test("authorize + exchange redirects carry opaque codes only — no JWT, no fragment", async () => {
    const { access_token } = await registerLogin("lh-nourl1@example.com", "s3cret-pass");
    const auth = await app.request(
      `/oidc/authorize?response_type=code&client_id=${LIBRE_CLIENT}&redirect_uri=${encodeURIComponent(LIBRE_REDIRECT)}&state=st1`,
      { headers: { authorization: `Bearer ${access_token}` } },
    );
    const loc = auth.headers.get("location") ?? "";
    expect(loc.includes(access_token)).toBe(false);
    for (const needle of ["eyJ", "access_token", "refresh_token", "alcore_at", "#"]) {
      expect(loc.includes(needle)).toBe(false);
    }
    const redir = await app.request(
      `/oidc/exchange/redirect?${new URLSearchParams({ audience: "libre", redirect_uri: LIBRE_REDIRECT, state: "st2" }).toString()}`,
      { redirect: "manual", headers: { cookie: `alcore_at=${access_token}` } },
    );
    expect(redir.status).toBe(302);
    const loc2 = redir.headers.get("location") ?? "";
    expect(loc2.includes(access_token)).toBe(false);
    for (const needle of ["eyJ", "access_token", "refresh_token", "alcore_at", "#"]) {
      expect(loc2.includes(needle)).toBe(false);
    }
    expect(saw("auth.exchange_request", "ok")).toBe(true);
  });

  test("exchange/redirect rejects evil URIs and wrong audience as JSON", async () => {
    const { access_token } = await registerLogin("lh-nourl2@example.com", "s3cret-pass");
    const jar = { cookie: `alcore_at=${access_token}` };
    const evil = await app.request(
      `/oidc/exchange/redirect?${new URLSearchParams({ audience: "libre", redirect_uri: "https://evil.example.com/cb", state: "s" }).toString()}`,
      { redirect: "manual", headers: jar },
    );
    expect(evil.status).toBe(400);
    expect(await evil.json()).toEqual({ error: "invalid_redirect_uri" });
    const aud = await app.request(
      `/oidc/exchange/redirect?${new URLSearchParams({ audience: "intruder", redirect_uri: LIBRE_REDIRECT, state: "s" }).toString()}`,
      { redirect: "manual", headers: jar },
    );
    expect(aud.status).toBe(400);
    expect(saw("auth.exchange_request", "invalid_redirect_uri")).toBe(true);
    expect(saw("auth.exchange_request", "invalid_audience")).toBe(true);
  });
});

describe("OAuth generic errors + conflict audit", () => {
  test("oversized idToken → generic invalid_credentials; unconfigured → 503", async () => {
    delete process.env["GOOGLE_CLIENT_ID"];
    expect(await (await app.request("/auth/google/config")).json()).toEqual({ clientId: "" });
    expect((await post("/auth/google/verify", { idToken: "x".repeat(8193) })).status).toBe(401);
    expect(await (await post("/auth/google/verify", { idToken: "x".repeat(8193) })).json()).toEqual({
      error: "invalid_credentials",
    });
    expect((await post("/auth/google/verify", { idToken: "placeholder" })).status).toBe(503);
    expect(saw("auth.oauth_callback", "invalid_credentials")).toBe(true);
    expect(saw("auth.oauth_callback", "google_not_configured")).toBe(true);
  });

  test("google start 302s with state cookie; verify links + conflicts 409 audited", async () => {
    const oldId = process.env["GOOGLE_CLIENT_ID"];
    process.env["GOOGLE_CLIENT_ID"] = TEST_GOOGLE_CLIENT_ID;
    const rig = createGoogleTestRig();
    const token = rig.mintIdToken(baseGoogleClaims({ sub: "lh-oauth-1", email: "lh-oauth1@example.com" }));
    const { restore } = rig.installFetch(token);
    try {
      const start = await app.request("/auth/google/start");
      expect(start.status).toBe(302);
      expect(start.headers.getSetCookie().some((v) => v.startsWith("alcore_google_state=") && v.includes("HttpOnly"))).toBe(true);
      const res = await post("/auth/google/verify", { idToken: token });
      expect(res.status).toBe(200);
      expect(saw("auth.oauth_start", "ok")).toBe(true);
      expect(saw("auth.oauth_callback", "ok")).toBe(true);
    } finally {
      restore();
      if (oldId === undefined) delete process.env["GOOGLE_CLIENT_ID"];
      else process.env["GOOGLE_CLIENT_ID"] = oldId;
    }
    // Conflict: same subject owned by another user → auditable 409.
    const owner = userStore.create("lh-owner@example.com", null);
    const other = userStore.create("lh-other@example.com", null);
    userStore.linkIdentity(owner.id, "google", "lh-conflict-sub");
    const rig2 = createGoogleTestRig();
    const tok2 = rig2.mintIdToken(baseGoogleClaims({ sub: "lh-conflict-sub", email: other.email }));
    const inst2 = rig2.installFetch(tok2);
    const oldId2 = process.env["GOOGLE_CLIENT_ID"];
    process.env["GOOGLE_CLIENT_ID"] = TEST_GOOGLE_CLIENT_ID;
    try {
      const res = await post("/auth/google/verify", { idToken: tok2 });
      expect(res.status).toBe(409);
      expect(await res.json()).toEqual({ error: "identity_conflict" });
      expect(saw("auth.identity_conflict", "identity_conflict")).toBe(true);
    } finally {
      inst2.restore();
      if (oldId2 === undefined) delete process.env["GOOGLE_CLIENT_ID"];
      else process.env["GOOGLE_CLIENT_ID"] = oldId2;
    }
  });
});

describe("audit trail integrity", () => {
  test("full lifecycle emits per-transition events with no secret material", async () => {
    const s = await registerLogin("lh-audit1@example.com", "s3cret-pass");
    await post("/auth/refresh", { refresh_token: s.refresh_token });
    await post("/auth/logout", { refresh_token: s.refresh_token });
    const events = auditEvents().map((r) => r.event);
    for (const need of ["auth.register", "auth.login", "auth.refresh", "auth.logout"]) {
      expect(events).toContain(need);
    }
    for (const row of listAuditForTests()) {
      const flat = JSON.stringify(row);
      expect(flat).not.toContain(s.access_token);
      expect(flat).not.toContain(s.refresh_token);
      expect(flat).not.toContain("s3cret-pass");
      expect(flat).not.toContain("test-only-dummy-secret");
    }
    expect(listAuditForTests().every((r) => typeof r.at === "string" && r.at.length > 0)).toBe(true);
  });
});

describe("consume-path throttle gating (task 38 decision)", () => {
  test("verify/consume shares the auth:verify budget and fails closed with 429", async () => {
    for (let i = 0; i < 30; i++) {
      const res = await post("/auth/verify/consume", { token: "v1.verify.nope.1.bad" });
      expect(res.status).toBe(400);
    }
    const over = await post("/auth/verify/consume", { token: "v1.verify.nope.1.bad" });
    expect(over.status).toBe(429);
    expect(await over.json()).toEqual({ error: "rate_limited" });
    expect(over.headers.get("Retry-After")).not.toBeNull();
  });

  test("reset/consume shares the auth:reset budget and fails closed with 429", async () => {
    for (let i = 0; i < 30; i++) {
      const res = await post("/auth/reset/consume", { token: "v1.reset.nope.1.bad", newPassword: "new-pass-456" });
      expect(res.status).toBe(400);
    }
    const over = await post("/auth/reset/consume", { token: "v1.reset.nope.1.bad", newPassword: "new-pass-456" });
    expect(over.status).toBe(429);
    expect(await over.json()).toEqual({ error: "rate_limited" });
    expect(over.headers.get("Retry-After")).not.toBeNull();
  });
});
