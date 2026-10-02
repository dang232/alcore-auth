// Task 36b — rotation/revocation semantics (overlap, atomic rotate, sessions).
// Persistence half lives in tests/persistence-rotation.test.ts (36a, untouched).
//
// Dummy secrets only. Shares one :memory: DB per bun process, so every row
// uses a task36b- unique key and a dedicated x-forwarded-for IP per test to
// stay out of the shared in-memory throttle budgets (incl. task-37's lane).
process.env["JWT_SECRET"] = "test-only-dummy-secret-0123456789abcdef";
process.env["ALLOW_WEAK_JWT_SECRET"] = "1";
process.env["NODE_ENV"] = "test";

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { app } from "../src/index";
import { getIssuer } from "../src/config";
import { hashToken, signAccess, verifyAccess } from "../src/lib/crypto";
import { resetRateLimitsForTests, resetThrottleConnForTests } from "../src/lib/ratelimit";
import { sessionStore, userStore } from "../src/lib/store";

const TAG = "task36b";
const PREV = "test-only-previous-secret-abcdef0123456789";
const CUR_KID = "k9";
const PREV_KID = "k8";

let ipSeq = 0;
function freshIp(): string {
  ipSeq += 1;
  return `10.36.11.${ipSeq}`;
}

async function post(path: string, body: unknown, ip: string, bearer?: string): Promise<Response> {
  const headers: Record<string, string> = { "content-type": "application/json", "x-forwarded-for": ip };
  if (bearer !== undefined) headers["authorization"] = `Bearer ${bearer}`;
  return app.request(path, { method: "POST", headers, body: JSON.stringify(body) });
}

async function get(path: string, ip: string, bearer?: string): Promise<Response> {
  const headers: Record<string, string> = { "x-forwarded-for": ip };
  if (bearer !== undefined) headers["authorization"] = `Bearer ${bearer}`;
  return app.request(path, { headers });
}

async function del(path: string, ip: string, bearer?: string): Promise<Response> {
  const headers: Record<string, string> = { "x-forwarded-for": ip };
  if (bearer !== undefined) headers["authorization"] = `Bearer ${bearer}`;
  return app.request(path, { method: "DELETE", headers });
}

async function register(ip: string, email: string): Promise<{ id: string; access: string; refresh: string }> {
  const res = await post("/auth/register", { email, password: "s3cret-pass" }, ip);
  expect(res.status).toBe(201);
  const body = (await res.json()) as { id: string; access_token: string; refresh_token: string };
  return { id: body.id, access: body.access_token, refresh: body.refresh_token };
}

async function login(ip: string, email: string): Promise<{ access: string; refresh: string }> {
  const res = await post("/auth/login", { email, password: "s3cret-pass" }, ip);
  expect(res.status).toBe(200);
  const body = (await res.json()) as { access_token: string; refresh_token: string };
  return { access: body.access_token, refresh: body.refresh_token };
}

beforeEach(() => {
  resetRateLimitsForTests();
  resetThrottleConnForTests();
});

afterEach(() => {
  delete process.env["JWT_SECRET_PREVIOUS"];
  delete process.env["JWT_SECRET_KID"];
  delete process.env["JWT_SECRET_PREVIOUS_KID"];
  delete process.env["AUTH_OIDC_CLIENTS"];
});

function enableOverlap(): void {
  process.env["JWT_SECRET_PREVIOUS"] = PREV;
  process.env["JWT_SECRET_KID"] = CUR_KID;
  process.env["JWT_SECRET_PREVIOUS_KID"] = PREV_KID;
}

describe("kid overlap (unit)", () => {
  test("signAccess stamps kid; verifyAccess accepts current+previous set, strict without previous", () => {
    const claims = { sub: "u1", sid: "s1", iss: getIssuer(), aud: "auth", intent: "session" };
    const cur = "test-only-dummy-secret-0123456789abcdef";
    const withKid = signAccess(claims, cur, 900, { kid: CUR_KID });
    const header = JSON.parse(Buffer.from(withKid.split(".")[0] as string, "base64url").toString("utf8")) as { kid: string };
    expect(header.kid).toBe(CUR_KID);
    expect(verifyAccess(withKid, { current: cur, currentKid: CUR_KID }, getIssuer(), "auth", "session").sub).toBe("u1");
    const prevSigned = signAccess(claims, PREV, 900, { kid: PREV_KID });
    expect(
      verifyAccess(prevSigned, { current: cur, currentKid: CUR_KID, previous: PREV, previousKid: PREV_KID }, getIssuer(), "auth", "session").sub,
    ).toBe("u1");
    expect(() => verifyAccess(prevSigned, { current: cur, currentKid: CUR_KID }, getIssuer(), "auth", "session")).toThrow();
    expect(() => verifyAccess(signAccess(claims, cur, 900, { kid: "nope" }), { current: cur, currentKid: CUR_KID }, getIssuer(), "auth", "session")).toThrow();
  });
});

describe("kid overlap (HTTP)", () => {
  test("previous-signed token 200 on /auth/me during overlap, 401 after retirement", async () => {
    const ip = freshIp();
    enableOverlap();
    const user = await register(ip, `${TAG}-overlap@example.com`);
    const prevToken = signAccess(
      { sub: user.id, sid: "overlap-sid", iss: getIssuer(), aud: "auth", intent: "session" },
      PREV, 900, { kid: PREV_KID },
    );
    expect((await get("/auth/me", ip, prevToken)).status).toBe(200);
    expect((await get("/auth/me", ip, user.access)).status).toBe(200);
    delete process.env["JWT_SECRET_PREVIOUS"];
    delete process.env["JWT_SECRET_PREVIOUS_KID"];
    const retired = signAccess(
      { sub: user.id, sid: "overlap-sid", iss: getIssuer(), aud: "auth", intent: "session" },
      PREV, 900, { kid: PREV_KID },
    );
    expect((await get("/auth/me", ip, retired)).status).toBe(401);
    expect((await get("/auth/me", ip, user.access)).status).toBe(200);
  });

  test("wrong-kid / unknown-kid tokens 401", async () => {
    const ip = freshIp();
    const user = await register(ip, `${TAG}-wrongkid@example.com`);
    const bad = signAccess(
      { sub: user.id, sid: "x", iss: getIssuer(), aud: "auth", intent: "session" },
      "test-only-dummy-secret-0123456789abcdef", 900, { kid: "unknown-kid" },
    );
    expect((await get("/auth/me", ip, bad)).status).toBe(401);
  });
});

describe("kid overlap (OIDC)", () => {
  const OIDC_CLIENT = "task36b-client";
  const OIDC_REDIRECT = "http://localhost:3000/callback";

  function kidOf(token: string): string {
    return (JSON.parse(Buffer.from(token.split(".")[0] as string, "base64url").toString("utf8")) as { kid: string }).kid;
  }

  function payloadOf(token: string): { sub: string; sid: string } {
    return JSON.parse(Buffer.from(token.split(".")[1] as string, "base64url").toString("utf8")) as { sub: string; sid: string };
  }

  function configureOidc(): void {
    process.env["AUTH_OIDC_CLIENTS"] = `${OIDC_CLIENT}=${OIDC_REDIRECT}`;
  }

  function authorizeUrl(): string {
    return `/oidc/authorize?response_type=code&client_id=${OIDC_CLIENT}&redirect_uri=${encodeURIComponent(OIDC_REDIRECT)}&state=s123`;
  }

  function redirectUrl(): string {
    return `/oidc/exchange/redirect?audience=tokenpanel&redirect_uri=${encodeURIComponent(OIDC_REDIRECT)}&state=s123`;
  }

  function prevSessionToken(sub: string, sid: string): string {
    return signAccess(
      { sub, sid, iss: getIssuer(), aud: "auth", intent: "session" },
      PREV, 900, { kid: PREV_KID },
    );
  }

  function unknownKidToken(sub: string, sid: string): string {
    return signAccess(
      { sub, sid, iss: getIssuer(), aud: "auth", intent: "session" },
      "test-only-dummy-secret-0123456789abcdef", 900, { kid: "unknown-kid" },
    );
  }

  test("previous-signed token verifies on OIDC bearer + cookie + exchange paths during overlap", async () => {
    const ip = freshIp();
    enableOverlap();
    configureOidc();
    const user = await register(ip, `${TAG}-oidc-overlap@example.com`);
    const { sub, sid } = payloadOf(user.access);
    const prevToken = prevSessionToken(sub, sid);
    // Bearer path: authorize 302s (a 401 here would mean the previous kid was rejected).
    expect((await get(authorizeUrl(), ip, prevToken)).status).toBe(302);
    // Cookie path: exchange/redirect 302s on the same previous-signed session.
    const cookieRes = await app.request(redirectUrl(), {
      headers: { cookie: `alcore_at=${prevToken}`, "x-forwarded-for": ip },
    });
    expect(cookieRes.status).toBe(302);
    // Exchange path: POST /oidc/exchange mints a code (200) for the previous kid.
    expect((await post("/oidc/exchange", { audience: "tokenpanel", intent: "product_exchange" }, ip, prevToken)).status).toBe(200);
  });

  test("unknown-kid token 401s on OIDC bearer + cookie + exchange paths", async () => {
    const ip = freshIp();
    enableOverlap();
    configureOidc();
    const user = await register(ip, `${TAG}-oidc-unknownkid@example.com`);
    const { sub, sid } = payloadOf(user.access);
    const bad = unknownKidToken(sub, sid);
    expect((await get(authorizeUrl(), ip, bad)).status).toBe(401);
    const cookieRes = await app.request(redirectUrl(), {
      headers: { cookie: `alcore_at=${bad}`, "x-forwarded-for": ip },
    });
    expect(cookieRes.status).toBe(401);
    expect((await post("/oidc/exchange", { audience: "tokenpanel", intent: "product_exchange" }, ip, bad)).status).toBe(401);
  });

  test("/oidc/token + /exchange/token responses carry kid of current key", async () => {
    const ip = freshIp();
    enableOverlap();
    configureOidc();
    const user = await register(ip, `${TAG}-oidc-kid@example.com`);
    const auth = await get(authorizeUrl(), ip, user.access);
    expect(auth.status).toBe(302);
    const code = new URL(auth.headers.get("location") ?? "https://invalid").searchParams.get("code") ?? "";
    expect(code).not.toBe("");
    const t1 = await post("/oidc/token", {
      grant_type: "authorization_code",
      code,
      redirect_uri: OIDC_REDIRECT,
      client_id: OIDC_CLIENT,
    }, ip);
    expect(t1.status).toBe(200);
    expect(kidOf(((await t1.json()) as { access_token: string }).access_token)).toBe(CUR_KID);
    const issued = await post("/oidc/exchange", { audience: "tokenpanel", intent: "product_exchange" }, ip, user.access);
    expect(issued.status).toBe(200);
    const xcode = ((await issued.json()) as { code: string }).code;
    const redeemed = await post("/oidc/exchange/token", { code: xcode, audience: "tokenpanel", intent: "product_exchange" }, ip);
    expect(redeemed.status).toBe(200);
    expect(kidOf(((await redeemed.json()) as { access_token: string }).access_token)).toBe(CUR_KID);
  });
});

describe("atomic refresh rotation", () => {
  test("stale in-memory session loses CAS (deterministic lost-race unit)", async () => {
    const created = await userStore.create(`${TAG}-cas-user@example.com`, null);
    const first = await sessionStore.create(created.id, hashToken(`${TAG}-cas-first`), 3600_000);
    const staleView = await sessionStore.findById(first.id);
    expect(staleView !== undefined).toBe(true);
    expect(await sessionStore.rotate(first, hashToken(`${TAG}-cas-second`))).toBe(true);
    expect(await sessionStore.rotate(staleView ?? first, hashToken(`${TAG}-cas-third`))).toBe(false);
    expect((await sessionStore.findById(first.id))?.refreshHash).toBe(hashToken(`${TAG}-cas-second`));
  });

  test("concurrent double-refresh yields exactly one winner; loser revokes family", async () => {
    const ip = freshIp();
    const user = await register(ip, `${TAG}-race@example.com`);
    const attempts = await Promise.all(
      Array.from({ length: 8 }, () => post("/auth/refresh", { refresh_token: user.refresh }, ip)),
    );
    const won = attempts.filter((r) => r.status === 200);
    const lost = attempts.filter((r) => r.status === 401);
    expect(won.length).toBe(1);
    expect(lost.length).toBe(7);
    const winner = (await (won[0] as Response).json()) as { refresh_token: string };
    expect(winner.refresh_token).not.toBe(user.refresh);
    const after = await post("/auth/refresh", { refresh_token: winner.refresh_token }, ip);
    expect(after.status).toBe(401);
  });

  test("reuse of an old refresh revokes the whole family", async () => {
    const ip = freshIp();
    await register(ip, `${TAG}-family@example.com`);
    const s1 = await login(ip, `${TAG}-family@example.com`);
    const s2 = await login(ip, `${TAG}-family@example.com`);
    const rotated = (await (await post("/auth/refresh", { refresh_token: s1.refresh }, ip)).json()) as { refresh_token: string };
    expect(rotated.refresh_token).not.toBe(s1.refresh);
    expect((await post("/auth/refresh", { refresh_token: s1.refresh }, ip)).status).toBe(401);
    expect((await post("/auth/refresh", { refresh_token: s2.refresh }, ip)).status).toBe(401);
    expect((await post("/auth/refresh", { refresh_token: rotated.refresh_token }, ip)).status).toBe(401);
  });
});

describe("session list + revoke-by-id", () => {
  test("GET /auth/sessions lists non-revoked sessions with current flag; no cookies set", async () => {
    const ip = freshIp();
    const first = await register(ip, `${TAG}-sessions@example.com`);
    const second = await login(ip, `${TAG}-sessions@example.com`);
    const res = await get("/auth/sessions", ip, first.access);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { sessions: Array<{ id: string; createdAt: number; expiresAt: number; current: boolean }> };
    expect(body.sessions.length).toBe(2);
    const mine = body.sessions.filter((s) => s.current);
    const other = body.sessions.filter((s) => !s.current);
    expect(mine.length).toBe(1);
    expect(other.length).toBe(1);
    expect(typeof other[0]?.id).toBe("string");
    expect(res.headers.getSetCookie()).toEqual([]);
    void second;
  });

  test("DELETE /auth/sessions/:id revokes that session; its refresh 401s; unknown id 404", async () => {
    const ip = freshIp();
    const first = await register(ip, `${TAG}-revoke@example.com`);
    const second = await login(ip, `${TAG}-revoke@example.com`);
    const list = (await (await get("/auth/sessions", ip, first.access)).json()) as { sessions: Array<{ id: string; current: boolean }> };
    const otherId = list.sessions.filter((s) => !s.current)[0]?.id ?? "";
    expect(otherId).not.toBe("");
    const gone = await del("/auth/sessions/definitely-not-a-session", ip, first.access);
    expect(gone.status).toBe(404);
    expect(((await gone.json()) as { error: string }).error).toBe("session_not_found");
    const kill = await del(`/auth/sessions/${otherId}`, ip, first.access);
    expect(kill.status).toBe(200);
    expect((await post("/auth/refresh", { refresh_token: second.refresh }, ip)).status).toBe(401);
    const remaining = (await (await get("/auth/sessions", ip, first.access)).json()) as { sessions: Array<{ id: string }> };
    expect(remaining.sessions.some((s) => s.id === otherId)).toBe(false);
    expect(remaining.sessions.length).toBe(1);
  });

  test("cannot revoke another user's session (404); unauthenticated list/revoke 401", async () => {
    const ipA = freshIp();
    const ipB = freshIp();
    const a = await register(ipA, `${TAG}-victim@example.com`);
    const b = await register(ipB, `${TAG}-attacker@example.com`);
    const victimList = (await (await get("/auth/sessions", ipA, a.access)).json()) as { sessions: Array<{ id: string }> };
    const victimId = victimList.sessions[0]?.id ?? "";
    expect((await del(`/auth/sessions/${victimId}`, ipB, b.access)).status).toBe(404);
    expect((await get("/auth/sessions", ipA)).status).toBe(401);
    expect((await del(`/auth/sessions/${victimId}`, ipB)).status).toBe(401);
  });
});
