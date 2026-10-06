// ALcore Auth Repo C — bun test suite (identity-only acceptance).
// Assumes dummy secrets only: JWT_SECRET + ALLOW_WEAK_JWT_SECRET=1 are set
// below before any request is made (config reads env lazily per request).

process.env["JWT_SECRET"] = "test-only-dummy-secret-0123456789abcdef";
process.env["ALLOW_WEAK_JWT_SECRET"] = "1";
process.env["NODE_ENV"] = "test";

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { join } from "node:path";
import { app } from "../src/index";
import { getJwtRotationKeys, getJwtSecret } from "../src/config";
import { mintPurposeToken, signAccess, verifyAccess } from "../src/lib/crypto";
import { createRateLimiter, resetRateLimitsForTests, resetThrottleConnForTests } from "../src/lib/ratelimit";
import { googleStateStore, resetStoresForTests, userStore } from "../src/lib/store";
import { getIssuer } from "../src/config";
import { resetSignupOtpsForTests } from "../src/lib/otp";
import { resetMailSender, setMailSender, type MailMessage } from "../src/lib/mail";
import { baseGoogleClaims, createGoogleTestRig, TEST_GOOGLE_CLIENT_ID } from "./google-jwks-helper";

await resetStoresForTests();

const sent: MailMessage[] = [];

beforeEach(() => {
  sent.length = 0;
  resetMailSender();
  setMailSender(async (message) => {
    sent.push(message);
    return "delivered";
  });
  resetSignupOtpsForTests();
  resetRateLimitsForTests();
  resetThrottleConnForTests();
});

afterEach(() => {
  resetMailSender();
});

/** Pull the 6-digit code out of the mailed body (it travels as token=<code>). */
function mailedCode(message: MailMessage): string {
  const viaToken = /token=(\d{6})/.exec(message.text)?.[1];
  if (viaToken !== undefined) return viaToken;
  return /\d{6}/.exec(message.text)?.[0] ?? "";
}

/** Register (202 pending) then verify the mailed OTP, returning the session pair. */
async function registerVerify(email: string, password: string): Promise<{ access_token: string; refresh_token: string }> {
  const reg = await post("/auth/register", { email, password });
  expect(reg.status).toBe(202);
  const code = mailedCode(sent.find((m) => m.to === email) as MailMessage);
  expect(code).toMatch(/^\d{6}$/);
  const verify = await post("/auth/verify-otp", { email, code });
  expect(verify.status).toBe(200);
  const pair = (await verify.json()) as { access_token: string; refresh_token: string };
  expect(typeof pair.access_token).toBe("string");
  expect(typeof pair.refresh_token).toBe("string");
  return pair;
}

async function post(path: string, body: unknown, headers: Record<string, string> = {}): Promise<Response> {
  return app.request(path, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

async function authed(path: string, token: string): Promise<Response> {
  return app.request(path, { headers: { authorization: `Bearer ${token}` } });
}

describe("register + login", () => {
  test("POST /auth/register creates an Auth user with a string id", async () => {
    const res = await post("/auth/register", { email: "alice@example.com", password: "s3cret-pass" });
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ pending: true, otpRequired: true, email: "alice@example.com" });
    expect(res.headers.getSetCookie().some((v) => v.startsWith("alcore_at="))).toBe(false);
    expect(res.headers.getSetCookie().some((v) => v.startsWith("alcore_rt="))).toBe(false);
    const code = mailedCode(sent.find((m) => m.to === "alice@example.com") as MailMessage);
    expect(code).toMatch(/^\d{6}$/);
    const verify = await post("/auth/verify-otp", { email: "alice@example.com", code });
    expect(verify.status).toBe(200);
    const pair = (await verify.json()) as { access_token: string; refresh_token: string };
    const me = (await (await authed("/auth/me", pair.access_token)).json()) as { id: string; email: string };
    expect(typeof me.id).toBe("string");
    expect(me.id.length).toBeGreaterThan(0);
    expect(me.email).toBe("alice@example.com");
  });

  test("login: unknown email and wrong password give identical 401 (no enumeration)", async () => {
    const a = await post("/auth/login", { email: "nobody@example.com", password: "s3cret-pass" });
    const b = await post("/auth/login", { email: "alice@example.com", password: "wrong-pass" });
    expect(a.status).toBe(401);
    expect(b.status).toBe(401);
    expect(await a.json()).toEqual(await b.json());
  });

  test("login success mints short access + rotating refresh with hardened cookies", async () => {
    const res = await post("/auth/login", { email: "alice@example.com", password: "s3cret-pass" });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { access_token: string; refresh_token: string; expires_in: number };
    expect(typeof body.access_token).toBe("string");
    expect(typeof body.refresh_token).toBe("string");
    expect(body.expires_in).toBeLessThanOrEqual(900);
    const setCookies = res.headers.getSetCookie();
    expect(setCookies.some((v) => v.startsWith("alcore_at=") && v.includes("HttpOnly") && v.includes("Secure") && v.includes("SameSite=Strict"))).toBe(true);
    expect(setCookies.some((v) => v.startsWith("alcore_rt=") && v.includes("HttpOnly") && v.includes("Secure") && v.includes("SameSite=Strict"))).toBe(true);
    const me = await authed("/auth/me", body.access_token);
    expect(me.status).toBe(200);
  });
});

describe("refresh rotation + logout", () => {
  test("refresh rotates; old refresh is rejected (reuse -> 401)", async () => {
    await registerVerify("bob@example.com", "s3cret-pass");
    const login = await post("/auth/login", { email: "bob@example.com", password: "s3cret-pass" });
    expect(login.status).toBe(200);
    const first = (await login.json()) as { refresh_token: string };
    const r1 = await post("/auth/refresh", { refresh_token: first.refresh_token });
    expect(r1.status).toBe(200);
    const second = (await r1.json()) as { refresh_token: string };
    expect(second.refresh_token).not.toBe(first.refresh_token);
    const reuse = await post("/auth/refresh", { refresh_token: first.refresh_token });
    expect(reuse.status).toBe(401);
  });

  test("logout revokes the session (refresh rejected after)", async () => {
    await registerVerify("carol@example.com", "s3cret-pass");
    const login = await post("/auth/login", { email: "carol@example.com", password: "s3cret-pass" });
    expect(login.status).toBe(200);
    const pair = (await login.json()) as { access_token: string; refresh_token: string };
    const out = await post("/auth/logout", { refresh_token: pair.refresh_token });
    expect(out.status).toBe(200);
    const after = await post("/auth/refresh", { refresh_token: pair.refresh_token });
    expect(after.status).toBe(401);
  });
});

describe("verify + reset (no enumeration)", () => {
  test("verify request is always 200; consume marks verified", async () => {
    const unknown = await post("/auth/verify/request", { email: "ghost@example.com" });
    expect(unknown.status).toBe(200);
    expect(await unknown.json()).toEqual({ ok: true });
    await registerVerify("dave@example.com", "s3cret-pass");
    const known = await post("/auth/verify/request", { email: "dave@example.com" });
    expect(known.status).toBe(200);
    expect(await known.json()).toEqual({ ok: true });
    const bad = await post("/auth/verify/consume", { token: "v1.verify.nope.1.bad" });
    expect(bad.status).toBe(400);
    const login = await post("/auth/login", { email: "dave@example.com", password: "s3cret-pass" });
    const { access_token } = (await login.json()) as { access_token: string };
    const me = (await (await authed("/auth/me", access_token)).json()) as { id: string };
    const token = mintPurposeToken(getJwtSecret(), "verify", me.id, 3600);
    const consume = await post("/auth/verify/consume", { token });
    expect(consume.status).toBe(200);
    const me2 = (await (await authed("/auth/me", access_token)).json()) as { emailVerified: boolean };
    expect(me2.emailVerified).toBe(true);
  });

  test("reset request is always 200; consume rotates password and revokes sessions", async () => {
    const unknown = await post("/auth/reset/request", { email: "ghost2@example.com" });
    expect(unknown.status).toBe(200);
    await registerVerify("erin@example.com", "old-pass-123");
    const login = await post("/auth/login", { email: "erin@example.com", password: "old-pass-123" });
    const { access_token } = (await login.json()) as { access_token: string };
    const me = (await (await authed("/auth/me", access_token)).json()) as { id: string };
    const token = mintPurposeToken(getJwtSecret(), "reset", me.id, 3600);
    const consume = await post("/auth/reset/consume", { token, newPassword: "new-pass-456" });
    expect(consume.status).toBe(200);
    expect((await post("/auth/login", { email: "erin@example.com", password: "old-pass-123" })).status).toBe(401);
    expect((await post("/auth/login", { email: "erin@example.com", password: "new-pass-456" })).status).toBe(200);
  });
});

// The emailed links are GET URLs, so the GET surface is the one users actually
// hit. These cover it explicitly: the interstitial must render, must NOT consume
// (link scanners prefetch GET), and the form post must do the consuming.
describe("purpose links reached by GET (as emailed)", () => {
  async function postForm(path: string, fields: Record<string, string>): Promise<Response> {
    return app.request(path, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(fields).toString(),
    });
  }

  async function registerAndId(email: string, password: string): Promise<string> {
    const reg = await post("/auth/register", { email, password });
    expect(reg.status).toBe(202);
    const code = mailedCode(sent.find((m) => m.to === email) as MailMessage);
    expect(code).toMatch(/^\d{6}$/);
    const verify = await post("/auth/verify-otp", { email, code });
    expect(verify.status).toBe(200);
    const { access_token } = (await verify.json()) as { access_token: string };
    const me = (await (await authed("/auth/me", access_token)).json()) as { id: string };
    return me.id;
  }

  test("GET /auth/verify/consume renders HTML instead of 404", async () => {
    const id = await registerAndId("getlink1@example.com", "s3cret-pass");
    const token = mintPurposeToken(getJwtSecret(), "verify", id, 3600);
    const res = await app.request(`/auth/verify/consume?token=${encodeURIComponent(token)}`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
    const html = await res.text();
    expect(html).toContain("<form");
    expect(html).toContain('name="token"');
  });

  test("GET does not consume the token, so a link scanner cannot burn it", async () => {
    const id = await registerAndId("getlink2@example.com", "s3cret-pass");
    const token = mintPurposeToken(getJwtSecret(), "verify", id, 3600);
    const before = await userStore.findById(id);
    await app.request(`/auth/verify/consume?token=${encodeURIComponent(token)}`);
    const after = await userStore.findById(id);
    expect(after?.emailVerified).toBe(before?.emailVerified);
    // The token survived GET untouched: consuming it via POST still works.
    expect((await post("/auth/verify/consume", { token })).status).toBe(200);
  });

  test("the emailed form post verifies the account", async () => {
    const id = await registerAndId("getlink3@example.com", "s3cret-pass");
    const token = mintPurposeToken(getJwtSecret(), "verify", id, 3600);
    await app.request(`/auth/verify/consume?token=${encodeURIComponent(token)}`);
    const res = await postForm("/auth/verify/consume", { token });
    expect(res.status).toBe(200);
    expect((await userStore.findById(id))?.emailVerified).toBe(true);
  });

  test("GET /auth/reset/consume renders a password form instead of 404", async () => {
    const id = await registerAndId("getlink4@example.com", "old-pass-123");
    const token = mintPurposeToken(getJwtSecret(), "reset", id, 3600);
    const res = await app.request(`/auth/reset/consume?token=${encodeURIComponent(token)}`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('name="newPassword"');
    expect(html).toContain('type="password"');
  });

  test("GET /auth/reset/consume does not consume the token or change the password", async () => {
    const id = await registerAndId("getlink5@example.com", "old-pass-123");
    const token = mintPurposeToken(getJwtSecret(), "reset", id, 3600);
    await app.request(`/auth/reset/consume?token=${encodeURIComponent(token)}`);
    expect((await post("/auth/login", { email: "getlink5@example.com", password: "old-pass-123" })).status).toBe(200);
    expect((await post("/auth/reset/consume", { token, newPassword: "new-pass-456" })).status).toBe(200);
  });

  test("the emailed reset form post sets the new password", async () => {
    const id = await registerAndId("getlink6@example.com", "old-pass-123");
    const token = mintPurposeToken(getJwtSecret(), "reset", id, 3600);
    await app.request(`/auth/reset/consume?token=${encodeURIComponent(token)}`);
    const res = await postForm("/auth/reset/consume", { token, newPassword: "new-pass-456" });
    expect(res.status).toBe(200);
    expect((await post("/auth/login", { email: "getlink6@example.com", password: "old-pass-123" })).status).toBe(401);
    expect((await post("/auth/login", { email: "getlink6@example.com", password: "new-pass-456" })).status).toBe(200);
  });

  test("the interstitial escapes a hostile token instead of reflecting it raw", async () => {
    const res = await app.request(`/auth/verify/consume?token=${encodeURIComponent('"><script>alert(1)</script>')}`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
  });
});

describe("Google OAuth", () => {
  test("public config exposes an empty client id and verify fails closed without configuration", async () => {
    delete process.env["GOOGLE_CLIENT_ID"];
    const config = await app.request("/auth/google/config");
    expect(await config.json()).toEqual({ clientId: "" });
    const verify = await post("/auth/google/verify", { idToken: "placeholder" });
    expect(verify.status).toBe(503);
    expect(await verify.json()).toEqual({ error: "google_not_configured" });
  });

  test("verify rejects oversized ID tokens", async () => {
    process.env["GOOGLE_CLIENT_ID"] = "test-client.apps.googleusercontent.com";
    const res = await post("/auth/google/verify", { idToken: "x".repeat(8193) });
    expect(res.status).toBe(401);
  });

  test("verify creates or links a user and issues a session", async () => {
    const oldClientId = process.env["GOOGLE_CLIENT_ID"];
    process.env["GOOGLE_CLIENT_ID"] = TEST_GOOGLE_CLIENT_ID;
    const rig = createGoogleTestRig();
    const token = rig.mintIdToken(baseGoogleClaims({ sub: "google-verify-sub", email: "google-verify@example.com" }));
    const { restore } = rig.installFetch(token);
    try {
      const res = await post("/auth/google/verify", { idToken: token });
      expect(res.status).toBe(200);
      const body = (await res.json()) as { access_token: string };
      const user = await userStore.findByEmail("google-verify@example.com");
      expect(user).toBeDefined();
      expect(verifyAccess(body.access_token, getJwtRotationKeys(), getIssuer(), "auth", "session").sub)
        .toBe(user === undefined ? "missing-user" : user.id);
      const linkedUser = await userStore.findByProviderSub("google", "google-verify-sub");
      expect(linkedUser?.id).toBe(user?.id);
    } finally {
      restore();
      if (oldClientId === undefined) delete process.env["GOOGLE_CLIENT_ID"];
      else process.env["GOOGLE_CLIENT_ID"] = oldClientId;
    }
  });

  test("verify maps upstream failures to 502", async () => {
    const originalFetch = globalThis.fetch;
    const oldClientId = process.env["GOOGLE_CLIENT_ID"];
    process.env["GOOGLE_CLIENT_ID"] = "test-client.apps.googleusercontent.com";
    // Structurally valid token so verification reaches the JWKS fetch, which
    // then fails: JWKS transport failure is the only 502 path (todo 35).
    const rig = createGoogleTestRig();
    const token = rig.mintIdToken(baseGoogleClaims({ sub: "upstream-sub", email: "upstream@example.com" }));
    globalThis.fetch = mockFetch(async () => { throw new Error("network down"); });
    try {
      const res = await post("/auth/google/verify", { idToken: token });
      expect(res.status).toBe(502);
      expect(await res.json()).toEqual({ error: "upstream_unavailable" });
    } finally {
      globalThis.fetch = originalFetch;
      if (oldClientId === undefined) delete process.env["GOOGLE_CLIENT_ID"];
      else process.env["GOOGLE_CLIENT_ID"] = oldClientId;
    }
  });

  test("callback rejects caller-supplied identity fields without valid state", async () => {
    const res = await app.request("/auth/google/callback?sub=google-sub-1&email=gina@example.com");
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid_google_state" });
  });

  test("start redirects to Google and sets short-lived state cookie", async () => {
    const oldClientId = process.env["GOOGLE_CLIENT_ID"];
    try {
      process.env["GOOGLE_CLIENT_ID"] = "test-client.apps.googleusercontent.com";
      const res = await app.request("/auth/google/start");
      expect(res.status).toBe(302);
      const target = new URL(res.headers.get("location") ?? "https://invalid");
      expect(target.origin).toBe("https://accounts.google.com");
      expect(target.searchParams.get("client_id")).toBe(process.env["GOOGLE_CLIENT_ID"]);
      expect(target.searchParams.get("state")).not.toBe("");
      expect(target.searchParams.get("nonce")).not.toBe("");
      expect(res.headers.getSetCookie().some((cookie) => cookie.startsWith("alcore_google_state=") && cookie.includes("HttpOnly") && cookie.includes("Secure"))).toBe(true);
    } finally {
      if (oldClientId === undefined) delete process.env["GOOGLE_CLIENT_ID"];
      else process.env["GOOGLE_CLIENT_ID"] = oldClientId;
    }
  });

  async function callbackWithFetch(
    responder: (nonce: string) => typeof globalThis.fetch,
    callback: (state: string, nonce: string) => Promise<Response>,
  ): Promise<Response> {
    const originalFetch = globalThis.fetch;
    const oldClientId = process.env["GOOGLE_CLIENT_ID"];
    const oldClientSecret = process.env["GOOGLE_CLIENT_SECRET"];
    process.env["GOOGLE_CLIENT_ID"] = "test-client.apps.googleusercontent.com";
    process.env["GOOGLE_CLIENT_SECRET"] = "test-client-secret";
    const state = `state-${crypto.randomUUID()}`;
    const nonce = `nonce-${crypto.randomUUID()}`;
    try {
      globalThis.fetch = responder(nonce);
      await googleStateStore.issue(state, nonce, Math.floor(Date.now() / 1000) + 300);
      return await callback(state, nonce);
    } finally {
      globalThis.fetch = originalFetch;
      if (oldClientId === undefined) delete process.env["GOOGLE_CLIENT_ID"];
      else process.env["GOOGLE_CLIENT_ID"] = oldClientId;
      if (oldClientSecret === undefined) delete process.env["GOOGLE_CLIENT_SECRET"];
      else process.env["GOOGLE_CLIENT_SECRET"] = oldClientSecret;
    }
  }

  function response(status: number, body: unknown): Response {
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  }

  function mockFetch(handler: (input: RequestInfo | URL) => Promise<Response>): typeof globalThis.fetch {
    return Object.assign(handler, { preconnect: globalThis.fetch.preconnect });
  }

  function successfulGoogleFetch(nonce: string): typeof globalThis.fetch {
    // JWKS contract (todo 35): the token endpoint returns a signed ID token;
    // verification happens locally against the served key set.
    const rig = createGoogleTestRig();
    const token = rig.mintIdToken(baseGoogleClaims({
      nonce,
      sub: "google-user-1",
      email: "google@example.com",
    }));
    return mockFetch(async (input) => {
      if (String(input).includes("/certs")) {
        return response(200, rig.jwksBody);
      }
      return response(200, { id_token: token });
    });
  }

  async function performCallback(state: string, withCookie = true): Promise<Response> {
    const cookie = withCookie ? `alcore_google_state=${state}` : "";
    return app.request(`/auth/google/callback?state=${encodeURIComponent(state)}&code=test-code`, {
      headers: { cookie },
    });
  }

  test("valid Google callback creates user, identity, and session", async () => {
    const res = await callbackWithFetch(
      (nonce) => successfulGoogleFetch(nonce),
      async (state) => performCallback(state),
    );
    expect(res.status).toBe(200);
    expect((await res.json()).user.email).toBe("google@example.com");
  });

  test("verified Google email links to existing user", async () => {
    const user = await userStore.create("link@example.com", "password-hash");
    const linkRig = createGoogleTestRig();
    const res = await callbackWithFetch((nonce) => {
      const token = linkRig.mintIdToken(baseGoogleClaims({
        nonce, sub: "google-linked", email: "link@example.com",
      }));
      return mockFetch(async (input) => {
        if (String(input).includes("/certs")) return response(200, linkRig.jwksBody);
        return response(200, { id_token: token });
      });
    }, async (state) => performCallback(state));
    expect(res.status).toBe(200);
    expect((await res.json()).user.id).toBe(user.id);
  });

  test("callback returns 409 when Google identity belongs to another user", async () => {
    const owner = await userStore.create("owner@example.com", null);
    const another = await userStore.create("other@example.com", null);
    await userStore.linkIdentity(owner.id, "google", "google-conflict");
    const conflictRig = createGoogleTestRig();
    const res = await callbackWithFetch((nonce) => {
      const token = conflictRig.mintIdToken(baseGoogleClaims({
        nonce, sub: "google-conflict", email: another.email,
      }));
      return mockFetch(async (input) => {
        if (String(input).includes("/certs")) return response(200, conflictRig.jwksBody);
        return response(200, { id_token: token });
      });
    }, async (state) => performCallback(state));
    expect(res.status).toBe(409);
    expect(await res.json()).toEqual({ error: "identity_conflict" });
  });

  test("callback rejects replayed or invalid state", async () => {
    const res = await callbackWithFetch(() => mockFetch(async () => response(200, { id_token: "x" })), async (validState) => {
      await performCallback(validState);
      return performCallback(validState);
    });
    expect(res.status).toBe(400);
  });

  test("callback maps Google upstream failures to 503", async () => {
    const res = await callbackWithFetch(() => mockFetch(async () => { throw new Error("network down"); }), async (state) => performCallback(state));
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "upstream_unavailable" });
  });

  test("callback keeps invalid Google credentials at 401", async () => {
    const badRig = createGoogleTestRig();
    const res = await callbackWithFetch(() => mockFetch(async (input) => {
      if (String(input).includes("/certs")) return response(200, badRig.jwksBody);
      return response(200, { id_token: "not-a-jwt" });
    }), async (state) => performCallback(state));
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid_google_credential" });
  });
});

describe("OIDC code flow", () => {
  const redirectUri = "http://localhost:3000/callback";
  const clientId = "test-client";

  async function getSessionToken(email: string): Promise<string> {
    const reg = await post("/auth/register", { email, password: "s3cret-pass" });
    expect(reg.status).toBe(202);
    const code = mailedCode(sent.find((m) => m.to === email) as MailMessage);
    expect(code).toMatch(/^\d{6}$/);
    const verify = await post("/auth/verify-otp", { email, code });
    expect(verify.status).toBe(200);
    const body: unknown = await verify.json();
    if (typeof body !== "object" || body === null || !("access_token" in body) || typeof body.access_token !== "string") {
      throw new Error("verify did not return an access token");
    }
    return body.access_token;
  }

  function configureOidc(): void {
    process.env["AUTH_OIDC_CLIENTS"] = `${clientId}=${redirectUri}`;
  }

  test("authorize -> code -> server-side exchange; replay -> 400; no JWT in URL", async () => {
    configureOidc();
    const access_token = await getSessionToken("ivan@example.com");
    const auth = await app.request(
      `/oidc/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&state=s123`,
      { headers: { authorization: `Bearer ${access_token}` } },
    );
    expect(auth.status).toBe(302);
    const location = auth.headers.get("location") ?? "";
    expect(location.startsWith(redirectUri)).toBe(true);
    expect(location).toContain("code=");
    expect(location).not.toContain("eyJ");
    const code = new URL(location).searchParams.get("code") ?? "";
    expect(code.length).toBeGreaterThan(0);
    expect(location).not.toContain("access_token");
    expect(location).not.toContain("refresh_token");
    const t1 = await post("/oidc/token", {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
    });
    expect(t1.status).toBe(200);
    const replay = await post("/oidc/token", {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
    });
    expect(replay.status).toBe(400);
    expect(await replay.json()).toEqual({ error: "invalid_grant" });
  });

  test("authorize rejects unregistered clients and URI mismatch", async () => {
    configureOidc();
    const token = await getSessionToken("oidc-unknown@example.com");
    const unknown = await app.request(`/oidc/authorize?response_type=code&client_id=unknown&redirect_uri=${encodeURIComponent(redirectUri)}`, { headers: { authorization: `Bearer ${token}` } });
    const mismatch = await app.request(`/oidc/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(`${redirectUri}/evil`)}`, { headers: { authorization: `Bearer ${token}` } });
    expect(unknown.status).toBe(400);
    expect(mismatch.status).toBe(400);
  });

  test("OIDC code remains bound to the client that requested it", async () => {
    configureOidc();
    process.env["AUTH_OIDC_CLIENTS"] += ",other-client=http://localhost:3000/other";
    const token = await getSessionToken("oidc-binding@example.com");
    const auth = await app.request(`/oidc/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}`, { headers: { authorization: `Bearer ${token}` } });
    const code = new URL(auth.headers.get("location") ?? "https://invalid").searchParams.get("code") ?? "";
    const exchange = await post("/oidc/token", { grant_type: "authorization_code", code, redirect_uri: "http://localhost:3000/other", client_id: "other-client" });
    expect(exchange.status).toBe(400);
  });

  test("product exchange issues aud+intent assertion, rejects wrong intent, and consumes code once", async () => {
    const token = await getSessionToken("exchange@example.com");
    const wrongIntent = await post("/oidc/exchange", { audience: "tokenpanel", intent: "other" }, { authorization: `Bearer ${token}` });
    expect(wrongIntent.status).toBe(400);
    const invalidIntentExchange = await post("/oidc/exchange/token", { code: "unissued", audience: "tokenpanel", intent: "other" });
    expect(invalidIntentExchange.status).toBe(400);
    const issued = await post("/oidc/exchange", { audience: "tokenpanel", intent: "product_exchange" }, { authorization: `Bearer ${token}` });
    expect(issued.status).toBe(200);
    const issuedBody: unknown = await issued.json();
    if (typeof issuedBody !== "object" || issuedBody === null || !("code" in issuedBody) || typeof issuedBody.code !== "string") {
      throw new Error("exchange did not return a code");
    }
    const code = issuedBody.code;
    expect(code).not.toContain(".");
    const exchanged = await post("/oidc/exchange/token", { code, audience: "tokenpanel", intent: "product_exchange" });
    expect(exchanged.status).toBe(200);
    const exchangedBody: unknown = await exchanged.json();
    if (typeof exchangedBody !== "object" || exchangedBody === null || !("access_token" in exchangedBody) || typeof exchangedBody.access_token !== "string") {
      throw new Error("exchange did not return an assertion");
    }
    const assertion = exchangedBody.access_token;
    const claims = verifyAccess(assertion, getJwtRotationKeys(), getIssuer(), "tokenpanel", "product_exchange");
    expect(claims.sub).toBe((await userStore.findByEmail("exchange@example.com"))?.id ?? "");
    expect(claims.email).toBe("exchange@example.com");
    expect(claims.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(() => verifyAccess(assertion, getJwtRotationKeys(), getIssuer(), "libre")).toThrow();
    const replay = await post("/oidc/exchange/token", { code, audience: "tokenpanel", intent: "product_exchange" });
    expect(replay.status).toBe(400);
  });
});

describe("guards", () => {
  test("rate limiter factory rejects over-limit keys", () => {
    const check = createRateLimiter(60_000, 2);
    expect(check("k").ok).toBe(true);
    expect(check("k").ok).toBe(true);
    expect(check("k").ok).toBe(false);
  });

  test("prod boot without JWT_SECRET fails fast naming the variable", () => {
    const proc = Bun.spawnSync([process.execPath, "src/index.ts"], {
      cwd: join(import.meta.dir, ".."),
      env: {
        ...process.env,
        NODE_ENV: "production",
        JWT_SECRET: "",
        ALLOW_WEAK_JWT_SECRET: "",
        AUTH_PORT: "8082",
      },
    });
    expect(proc.exitCode).not.toBe(0);
    const stderr = proc.stderr.toString();
    expect(stderr).toContain("JWT_SECRET");
  });
});

describe("change password (POST /auth/change)", () => {
  async function change(
    token: string,
    body: unknown,
  ): Promise<Response> {
    return app.request("/auth/change", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
  }

  async function registerAndLogin(email: string, password: string): Promise<{ access_token: string; refresh_token: string }> {
    const reg = await post("/auth/register", { email, password });
    expect(reg.status).toBe(202);
    const code = mailedCode(sent.find((m) => m.to === email) as MailMessage);
    expect(code).toMatch(/^\d{6}$/);
    const verify = await post("/auth/verify-otp", { email, code });
    expect(verify.status).toBe(200);
    return (await verify.json()) as { access_token: string; refresh_token: string };
  }

  test("happy path: change works, new password logs in, old password 401s", async () => {
    const pair = await registerAndLogin("changepw1@example.com", "old-pass-123");
    const res = await change(pair.access_token, { currentPassword: "old-pass-123", newPassword: "new-pass-456" });
    expect(res.status).toBe(200);
    expect((await res.json()) as Record<string, unknown>).toMatchObject({ ok: true });
    expect((await post("/auth/login", { email: "changepw1@example.com", password: "old-pass-123" })).status).toBe(401);
    expect((await post("/auth/login", { email: "changepw1@example.com", password: "new-pass-456" })).status).toBe(200);
  });

  test("wrong current password → identical 401, session and password unchanged", async () => {
    const pair = await registerAndLogin("changepw2@example.com", "old-pass-123");
    const res = await change(pair.access_token, { currentPassword: "not-the-password", newPassword: "new-pass-456" });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid_credentials" });
    // No session change: the caller's session still lists, and the old
    // password still logs in while the attempted new one does not.
    expect((await authed("/auth/sessions", pair.access_token)).status).toBe(200);
    expect((await post("/auth/login", { email: "changepw2@example.com", password: "old-pass-123" })).status).toBe(200);
    expect((await post("/auth/login", { email: "changepw2@example.com", password: "new-pass-456" })).status).toBe(401);
  });

  test("success revokes ALL sessions incl. current, minting exactly one fresh session", async () => {
    const first = await registerAndLogin("changepw3@example.com", "old-pass-123");
    const secondLogin = await post("/auth/login", { email: "changepw3@example.com", password: "old-pass-123" });
    const second = (await secondLogin.json()) as { access_token: string; refresh_token: string };
    const res = await change(first.access_token, { currentPassword: "old-pass-123", newPassword: "new-pass-456" });
    expect(res.status).toBe(200);
    const fresh = (await res.json()) as { access_token: string; refresh_token: string };
    // Both pre-change sessions are dead: gated surface rejects them, and
    // both refresh tokens are rejected.
    expect((await authed("/auth/sessions", first.access_token)).status).toBe(401);
    expect((await authed("/auth/sessions", second.access_token)).status).toBe(401);
    expect((await post("/auth/refresh", { refresh_token: first.refresh_token })).status).toBe(401);
    expect((await post("/auth/refresh", { refresh_token: second.refresh_token })).status).toBe(401);
    // The minted pair is the single live session.
    const listed = await authed("/auth/sessions", fresh.access_token);
    expect(listed.status).toBe(200);
    const sessions = ((await listed.json()) as { sessions: unknown[] }).sessions;
    expect(sessions).toHaveLength(1);
    expect((await post("/auth/refresh", { refresh_token: fresh.refresh_token })).status).toBe(200);
  });

  test("weak new password rejected by the same rule as register (min 8)", async () => {
    const pair = await registerAndLogin("changepw4@example.com", "old-pass-123");
    const res = await change(pair.access_token, { currentPassword: "old-pass-123", newPassword: "short" });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "weak_password" });
    expect((await post("/auth/login", { email: "changepw4@example.com", password: "old-pass-123" })).status).toBe(200);
  });

  test("unauthenticated change → 401 unauthorized", async () => {
    expect((await change("", { currentPassword: "x", newPassword: "new-pass-456" })).status).toBe(401);
    const bogus = await change("not-a-token", { currentPassword: "x", newPassword: "new-pass-456" });
    expect(bogus.status).toBe(401);
    expect(await bogus.json()).toEqual({ error: "unauthorized" });
  });
});
