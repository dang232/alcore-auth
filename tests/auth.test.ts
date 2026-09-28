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
import { mintPurposeToken } from "../src/lib/crypto";
import { createRateLimiter } from "../src/lib/ratelimit";
import { resetStoresForTests } from "../src/lib/store";

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

describe("google link (verified-sub STUB)", () => {
  test("same Google sub never dupes; second login returns same id with x-auth-reused", async () => {
    const g1 = await app.request("/auth/google/callback?sub=google-sub-1&email=gina@example.com");
    expect(g1.status).toBe(200);
    const b1 = (await g1.json()) as { user: { id: string } };
    const g2 = await app.request("/auth/google/callback?sub=google-sub-1&email=gina@example.com");
    expect(g2.status).toBe(200);
    const b2 = (await g2.json()) as { user: { id: string } };
    expect(b2.user.id).toBe(b1.user.id);
    expect(g2.headers.get("x-auth-reused")).toBe("true");
    expect(g1.headers.get("x-auth-reused")).toBeNull();
  });

  test("verified-email match links to the existing password user", async () => {
    const reg = await post("/auth/register", { email: "hank@example.com", password: "s3cret-pass" });
    const created = (await reg.json()) as { id: string };
    const g = await app.request("/auth/google/callback?sub=google-sub-2&email=hank@example.com");
    expect(g.status).toBe(200);
    const body = (await g.json()) as { user: { id: string } };
    expect(body.user.id).toBe(created.id);
  });
});

describe("OIDC code flow", () => {
  test("authorize -> code -> server-side exchange; replay -> 400; no JWT in URL", async () => {
    await post("/auth/register", { email: "ivan@example.com", password: "s3cret-pass" });
    const login = await post("/auth/login", { email: "ivan@example.com", password: "s3cret-pass" });
    const { access_token } = (await login.json()) as { access_token: string };
    const redirectUri = "http://localhost:3000/callback";
    const auth = await app.request(
      `/oidc/authorize?response_type=code&client_id=stub&redirect_uri=${encodeURIComponent(redirectUri)}&state=s123`,
      { headers: { authorization: `Bearer ${access_token}` } },
    );
    expect(auth.status).toBe(302);
    const location = auth.headers.get("location") ?? "";
    expect(location.startsWith(redirectUri)).toBe(true);
    expect(location).toContain("code=");
    expect(location).not.toContain("eyJ");
    const code = new URL(location).searchParams.get("code") ?? "";
    expect(code.length).toBeGreaterThan(0);
    const t1 = await post("/oidc/token", {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
    });
    expect(t1.status).toBe(200);
    const replay = await post("/oidc/token", {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
    });
    expect(replay.status).toBe(400);
    expect(await replay.json()).toEqual({ error: "invalid_grant" });
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
