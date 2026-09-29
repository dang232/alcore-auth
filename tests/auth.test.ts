// ALcore Auth Repo C — bun test suite (identity-only acceptance).
// Assumes dummy secrets only: JWT_SECRET + ALLOW_WEAK_JWT_SECRET=1 are set
// below before any request is made (config reads env lazily per request).

process.env["JWT_SECRET"] = "test-only-dummy-secret-0123456789abcdef";
process.env["ALLOW_WEAK_JWT_SECRET"] = "1";
process.env["NODE_ENV"] = "test";

import { describe, test, expect } from "bun:test";
import { join } from "node:path";
import { app } from "../src/index";
import { getJwtSecret } from "../src/config";
import { mintPurposeToken, signAccess, verifyAccess } from "../src/lib/crypto";
import { createRateLimiter } from "../src/lib/ratelimit";
import { googleStateStore, resetStoresForTests, userStore } from "../src/lib/store";
import { getIssuer } from "../src/config";

resetStoresForTests();

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
    expect(res.status).toBe(201);
    const body = (await res.json()) as { id: string; email: string };
    expect(typeof body.id).toBe("string");
    expect(body.id.length).toBeGreaterThan(0);
    expect(body.email).toBe("alice@example.com");
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
    await post("/auth/register", { email: "bob@example.com", password: "s3cret-pass" });
    const login = await post("/auth/login", { email: "bob@example.com", password: "s3cret-pass" });
    const first = (await login.json()) as { refresh_token: string };
    const r1 = await post("/auth/refresh", { refresh_token: first.refresh_token });
    expect(r1.status).toBe(200);
    const second = (await r1.json()) as { refresh_token: string };
    expect(second.refresh_token).not.toBe(first.refresh_token);
    const reuse = await post("/auth/refresh", { refresh_token: first.refresh_token });
    expect(reuse.status).toBe(401);
  });

  test("logout revokes the session (refresh rejected after)", async () => {
    await post("/auth/register", { email: "carol@example.com", password: "s3cret-pass" });
    const login = await post("/auth/login", { email: "carol@example.com", password: "s3cret-pass" });
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
    await post("/auth/register", { email: "dave@example.com", password: "s3cret-pass" });
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
    await post("/auth/register", { email: "erin@example.com", password: "old-pass-123" });
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
    const originalFetch = globalThis.fetch;
    const oldClientId = process.env["GOOGLE_CLIENT_ID"];
    process.env["GOOGLE_CLIENT_ID"] = "test-client.apps.googleusercontent.com";
    globalThis.fetch = mockFetch(async () => response(200, {
      aud: "test-client.apps.googleusercontent.com", iss: "accounts.google.com",
      exp: String(Math.floor(Date.now() / 1000) + 300), sub: "google-verify-sub",
      email: "google-verify@example.com", email_verified: true,
    }));
    try {
      const res = await post("/auth/google/verify", { idToken: "mock-id-token" });
      expect(res.status).toBe(200);
      const body = (await res.json()) as { access_token: string };
      const user = userStore.findByEmail("google-verify@example.com");
      expect(user).toBeDefined();
      expect(verifyAccess(body.access_token, getJwtSecret(), getIssuer(), "auth", "session").sub)
        .toBe(user === undefined ? "missing-user" : user.id);
      const linkedUser = userStore.findByProviderSub("google", "google-verify-sub");
      expect(linkedUser?.id).toBe(user?.id);
    } finally {
      globalThis.fetch = originalFetch;
      if (oldClientId === undefined) delete process.env["GOOGLE_CLIENT_ID"];
      else process.env["GOOGLE_CLIENT_ID"] = oldClientId;
    }
  });

  test("verify maps upstream failures to 502", async () => {
    const originalFetch = globalThis.fetch;
    const oldClientId = process.env["GOOGLE_CLIENT_ID"];
    process.env["GOOGLE_CLIENT_ID"] = "test-client.apps.googleusercontent.com";
    globalThis.fetch = mockFetch(async () => { throw new Error("network down"); });
    try {
      const res = await post("/auth/google/verify", { idToken: "mock-id-token" });
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
      googleStateStore.issue(state, nonce, Math.floor(Date.now() / 1000) + 300);
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
    return mockFetch(async (input) => {
      if (String(input).includes("/tokeninfo?")) {
        return response(200, {
          aud: "test-client.apps.googleusercontent.com",
          iss: "https://accounts.google.com",
          nonce,
          exp: String(Math.floor(Date.now() / 1000) + 300),
          sub: "google-user-1",
          email: "google@example.com",
          email_verified: true,
        });
      }
      return response(200, { id_token: "test-id-token" });
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
    const user = userStore.create("link@example.com", "password-hash");
    const res = await callbackWithFetch((nonce) => mockFetch(async (input) => {
      if (String(input).includes("/tokeninfo?")) return response(200, {
        aud: "test-client.apps.googleusercontent.com", iss: "accounts.google.com", nonce,
        exp: String(Math.floor(Date.now() / 1000) + 300), sub: "google-linked", email: "link@example.com", email_verified: true,
      });
      return response(200, { id_token: "test-id-token" });
    }), async (state) => performCallback(state));
    expect(res.status).toBe(200);
    expect((await res.json()).user.id).toBe(user.id);
  });

  test("callback returns 409 when Google identity belongs to another user", async () => {
    const owner = userStore.create("owner@example.com", null);
    const another = userStore.create("other@example.com", null);
    userStore.linkIdentity(owner.id, "google", "google-conflict");
    const res = await callbackWithFetch((nonce) => mockFetch(async (input) => {
      if (String(input).includes("/tokeninfo?")) return response(200, {
        aud: "test-client.apps.googleusercontent.com", iss: "accounts.google.com", nonce,
        exp: String(Math.floor(Date.now() / 1000) + 300), sub: "google-conflict", email: another.email, email_verified: true,
      });
      return response(200, { id_token: "test-id-token" });
    }), async (state) => performCallback(state));
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
    const res = await callbackWithFetch(() => mockFetch(async () => response(401, {})), async (state) => performCallback(state));
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid_google_credential" });
  });
});

describe("OIDC code flow", () => {
  const redirectUri = "http://localhost:3000/callback";
  const clientId = "test-client";

  async function getSessionToken(email: string): Promise<string> {
    await post("/auth/register", { email, password: "s3cret-pass" });
    const login = await post("/auth/login", { email, password: "s3cret-pass" });
    const body: unknown = await login.json();
    if (typeof body !== "object" || body === null || !("access_token" in body) || typeof body.access_token !== "string") {
      throw new Error("login did not return an access token");
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
    const claims = verifyAccess(assertion, getJwtSecret(), getIssuer(), "tokenpanel", "product_exchange");
    expect(claims.sub).toBe(userStore.findByEmail("exchange@example.com")?.id ?? "");
    expect(claims.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(() => verifyAccess(assertion, getJwtSecret(), getIssuer(), "libre")).toThrow();
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
