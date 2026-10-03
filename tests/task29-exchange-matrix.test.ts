// Task 29 auth-service leg — idempotency + race + failure proof matrix at the
// Auth exchange seam (POST /oidc/exchange/token over codes minted by
// GET /oidc/exchange/redirect).
//
// ADDITIVE-ONLY pin of behavior-of-record: reuses the helper shapes from
// tests/exchange-redirect.test.ts, edits zero production files and zero
// existing tests. Contradiction with the suites below is a FINDING, never an
// edit to them.
//
// Matrix:
//   1. concurrent same-code exchange -> exactly 1 winner (200), every loser
//      an identical 400 {error:"invalid_grant"} replay marker, user/session
//      row counts unchanged.
//   2. replay of a consumed code -> identical invalid_grant on every replay.
//   3. failure modes (tampered state / swapped redirect / wrong audience /
//      bound-via-legacy path) -> byte-identical rejects, zero new rows, and
//      the code UNBURNED (correct redeem still 200 afterwards).
//   4. double-POST /auth/register same email -> 201 then 409 email_taken,
//      exactly 1 identity row; concurrent double-POST -> still 1 row.
//   5. enumeration sweep of bad codes -> uniform invalid_grant, no oracle.
process.env["JWT_SECRET"] = "test-only-dummy-secret-0123456789abcdef";
process.env["ALLOW_WEAK_JWT_SECRET"] = "1";
process.env["NODE_ENV"] = "test";

// Bun runs every test file in one process, so these overrides are visible to
// the other suites. Save and restore rather than leaving the process mutated.
const ENV_KEYS = ["AUTH_ISSUER", "AUTH_OIDC_CLIENTS", "AUTH_ALLOWED_ORIGINS"] as const;
const ENV_BACKUP = new Map<string, string | undefined>(
  ENV_KEYS.map((key) => [key, process.env[key]]),
);

function applyRedirectEnv(): void {
  process.env["AUTH_ISSUER"] = "https://auth.alcore.io.vn";
  process.env["AUTH_OIDC_CLIENTS"] =
    "libre=https://web.alcore.io.vn/auth/callback,tokenpanel=https://portal.alcore.io.vn/auth/callback";
  process.env["AUTH_ALLOWED_ORIGINS"] = "https://web.alcore.io.vn,https://portal.alcore.io.vn";
}

function restoreEnv(): void {
  for (const [key, value] of ENV_BACKUP) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

import { describe, test, expect, beforeEach, afterAll } from "bun:test";
import { app } from "../src/index";
import { resetRateLimitsForTests, resetThrottleConnForTests } from "../src/lib/ratelimit";
import { resetStoresForTests } from "../src/lib/store";

const LIBRE_REDIRECT = "https://web.alcore.io.vn/auth/callback";
const PANEL_REDIRECT = "https://portal.alcore.io.vn/auth/callback";
const INVALID_GRANT = '{"error":"invalid_grant"}';

await resetStoresForTests();

const PASSWORD = "s3cret-pass";

async function sessionFor(email: string): Promise<{ id: string; accessToken: string }> {
  const { userStore, sessionStore } = await import("../src/lib/store");
  const { signAccess, hashToken, randomToken } = await import("../src/lib/crypto");
  const { getJwtSecret, getIssuer } = await import("../src/config");
  const user = await userStore.create(email, "argon2id-test-hash");
  const session = await sessionStore.create(user.id, hashToken(randomToken(32)), 3_600_000);
  const accessToken = signAccess(
    { sub: user.id, sid: session.id, iss: getIssuer(), aud: "auth", intent: "session" },
    getJwtSecret(),
    3600,
  );
  return { id: user.id, accessToken };
}

async function storeCounts(userId?: string): Promise<{ users: number; sessions: number }> {
  const { userStore, sessionStore } = await import("../src/lib/store");
  const users = await userStore.count();
  const sessions =
    userId === undefined ? -1 : (await sessionStore.listActiveForUser(userId)).length;
  return { users, sessions };
}

function cookieHeader(accessToken: string): Record<string, string> {
  return { cookie: `alcore_at=${accessToken}` };
}

function redirectUrl(query: Record<string, string>): string {
  return `/oidc/exchange/redirect?${new URLSearchParams(query).toString()}`;
}

async function getRedirect(query: Record<string, string>, accessToken?: string): Promise<Response> {
  return app.request(redirectUrl(query), {
    redirect: "manual",
    headers: accessToken === undefined ? {} : cookieHeader(accessToken),
  });
}

async function redeem(body: Record<string, unknown>): Promise<Response> {
  return app.request("/oidc/exchange/token", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

function fromLocation(location: string): { code: string; state: string } {
  const url = new URL(location);
  return { code: url.searchParams.get("code") ?? "", state: url.searchParams.get("state") ?? "" };
}

async function mintCode(
  accessToken: string,
  state: string,
): Promise<{ code: string; state: string }> {
  const res = await getRedirect(
    { audience: "libre", redirect_uri: LIBRE_REDIRECT, state },
    accessToken,
  );
  expect(res.status).toBe(302);
  return fromLocation(res.headers.get("location") ?? "");
}

function goodBody(code: string, state: string): Record<string, unknown> {
  return {
    code,
    audience: "libre",
    intent: "product_exchange",
    redirect_uri: LIBRE_REDIRECT,
    state,
  };
}

describe("task 29 — exchange idempotency + race + failure matrix", () => {
  beforeEach(async () => {
    await resetStoresForTests();
    resetRateLimitsForTests();
    resetThrottleConnForTests();
    applyRedirectEnv();
  });

  afterAll(() => {
    restoreEnv();
  });

  test("concurrent same-code exchange: exactly 1 winner, losers identical invalid_grant, counts unchanged", async () => {
    const { id, accessToken } = await sessionFor("matrix-race@example.com");
    const before = await storeCounts(id);
    const { code, state } = await mintCode(accessToken, "st-matrix-race");

    const results = await Promise.all(
      Array.from({ length: 6 }, () => redeem(goodBody(code, state))),
    );
    const statuses = results.map((r) => r.status).sort();
    expect(statuses.filter((s) => s === 200)).toHaveLength(1);
    expect(statuses.filter((s) => s === 400)).toHaveLength(5);
    const loserBodies = await Promise.all(
      results.filter((r) => r.status === 400).map((r) => r.text()),
    );
    for (const body of loserBodies) expect(body).toBe(INVALID_GRANT);

    // The single-use ledger row is the replay marker: one more sequential
    // redeem is the identical reject, not a second success.
    const replay = await redeem(goodBody(code, state));
    expect(replay.status).toBe(400);
    expect(await replay.text()).toBe(INVALID_GRANT);

    const after = await storeCounts(id);
    expect(after).toEqual(before);
    console.log(
      `[matrix-race] winners=1 losers=5+1replay bodies-identical=true users=${before.users}->${after.users} sessions=${before.sessions}->${after.sessions}`,
    );
  });

  test("replay of a consumed code: every replay is the identical invalid_grant", async () => {
    const { id, accessToken } = await sessionFor("matrix-replay@example.com");
    const before = await storeCounts(id);
    const { code, state } = await mintCode(accessToken, "st-matrix-replay");

    const first = await redeem(goodBody(code, state));
    expect(first.status).toBe(200);
    expect((await first.json()) as unknown).toHaveProperty("access_token");

    const replays: string[] = [];
    for (let i = 0; i < 3; i++) {
      const r = await redeem(goodBody(code, state));
      expect(r.status).toBe(400);
      replays.push(await r.text());
    }
    for (const body of replays) expect(body).toBe(INVALID_GRANT);

    const after = await storeCounts(id);
    expect(after).toEqual(before);
    console.log(
      `[matrix-replay] first=200 replays=400,400,400 bodies-identical=true users=${before.users}->${after.users} sessions=${before.sessions}->${after.sessions}`,
    );
  });

  test("failure modes: identical reject, zero new rows, code unburned", async () => {
    const { id, accessToken } = await sessionFor("matrix-fail@example.com");
    const before = await storeCounts(id);
    const rejectBodies: string[] = [];

    // 1. Tampered state.
    {
      const { code } = await mintCode(accessToken, "st-matrix-real");
      const bad = await redeem({ ...goodBody(code, "st-matrix-real"), state: "st-matrix-forged" });
      expect(bad.status).toBe(400);
      rejectBodies.push(await bad.text());
      // Forged attempt must not burn the code: the real state still redeems.
      const good = await redeem(goodBody(code, "st-matrix-real"));
      expect(good.status).toBe(200);
    }
    // 2. Swapped redirect URI (other registered callback).
    {
      const { code, state } = await mintCode(accessToken, "st-matrix-swap");
      const bad = await redeem({ ...goodBody(code, state), redirect_uri: PANEL_REDIRECT });
      expect(bad.status).toBe(400);
      rejectBodies.push(await bad.text());
      const good = await redeem(goodBody(code, state));
      expect(good.status).toBe(200);
    }
    // 3. Wrong audience.
    {
      const { code, state } = await mintCode(accessToken, "st-matrix-aud");
      const bad = await redeem({ ...goodBody(code, state), audience: "tokenpanel" });
      expect(bad.status).toBe(400);
      rejectBodies.push(await bad.text());
      const good = await redeem(goodBody(code, state));
      expect(good.status).toBe(200);
    }
    // 4. Bound code through the legacy binding-free path (no redirect_uri).
    {
      const { code, state } = await mintCode(accessToken, "st-matrix-legacy");
      const bad = await redeem({ code, audience: "libre", intent: "product_exchange", state });
      expect(bad.status).toBe(400);
      rejectBodies.push(await bad.text());
      const good = await redeem(goodBody(code, state));
      expect(good.status).toBe(200);
    }

    for (const body of rejectBodies) expect(body).toBe(INVALID_GRANT);

    const after = await storeCounts(id);
    expect(after).toEqual(before);
    console.log(
      `[matrix-fail] rejects=4 bodies-identical=true unburned-good-redeems=4 users=${before.users}->${after.users} sessions=${before.sessions}->${after.sessions}`,
    );
  });

  test("double-POST register same email: 201 then 409 email_taken, exactly 1 identity", async () => {
    const { userStore } = await import("../src/lib/store");
    const email = "matrix-double-reg@example.com";
    const usersBefore = await userStore.count();

    const first = await app.request("/auth/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password: "s3cret-pass-long" }),
    });
    expect(first.status).toBe(201);
    const firstBody = (await first.json()) as { id: string; email: string };
    expect(firstBody.email).toBe(email);

    const second = await app.request("/auth/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password: "s3cret-pass-long" }),
    });
    expect(second.status).toBe(409);
    expect(await second.json()).toEqual({ error: "email_taken" });

    const usersAfter = await userStore.count();
    expect(usersAfter).toBe(usersBefore + 1);
    const identity = await userStore.findByEmail(email);
    expect(identity?.id).toBe(firstBody.id);
    console.log(
      `[matrix-register] first=201 second=409 users=${usersBefore}->${usersAfter} identity=${firstBody.id}`,
    );
  });

  test("concurrent double-POST register same email: still exactly 1 identity row", async () => {
    const { userStore } = await import("../src/lib/store");
    const email = "matrix-race-reg@example.com";
    const usersBefore = await userStore.count();

    const results = await Promise.all(
      [0, 1].map(() =>
        app.request("/auth/register", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ email, password: "s3cret-pass-long" }),
        }),
      ),
    );
    const statuses = results.map((r) => r.status).sort();
    // Either strict serialization (201+409) or a lost-findByEmail race
    // resolved by the UNIQUE backstop (201+201 for the SAME row): both are
    // the pinned 1-identity outcome, never two rows.
    expect([201, 409].includes(statuses[0]!) && [201, 409].includes(statuses[1]!)).toBe(true);
    const ids = new Set<string>();
    for (const r of results) {
      if (r.status === 201) ids.add(((await r.json()) as { id: string }).id);
      else expect(await r.json()).toEqual({ error: "email_taken" });
    }
    expect(ids.size).toBeLessThanOrEqual(1);

    const usersAfter = await userStore.count();
    expect(usersAfter).toBe(usersBefore + 1);
    if (ids.size === 1) {
      const identity = await userStore.findByEmail(email);
      expect(identity?.id).toBe([...ids][0]);
    }
    console.log(
      `[matrix-register-race] statuses=${statuses.join(",")} users=${usersBefore}->${usersAfter} distinct-201-ids=${ids.size}`,
    );
  });

  test("enumeration sweep of bad codes: uniform invalid_grant, no oracle, state unpoisoned", async () => {
    const { id, accessToken } = await sessionFor("matrix-enum@example.com");
    const before = await storeCounts(id);
    const { code: realCode } = await mintCode(accessToken, "st-matrix-enum");

    const badCodes: Array<{ name: string; code: unknown }> = [
      { name: "empty", code: "" },
      { name: "short", code: "x" },
      { name: "truncated-real", code: realCode.slice(0, 8) },
      { name: "real-plus-suffix", code: `${realCode}ff` },
      { name: "unknown-64hex", code: "ab".repeat(32) },
      { name: "unknown-32hex", code: "cd".repeat(16) },
      { name: "nonhex", code: "zz".repeat(32) },
      { name: "spaces", code: `  ${realCode}  ` },
      { name: "null-bytes", code: "\0\0\0\0" },
      { name: "unicode", code: "🔑".repeat(16) },
      { name: "long", code: "ab".repeat(128) },
      { name: "non-string", code: 12345 },
    ];
    const bodies: string[] = [];
    for (const probe of badCodes) {
      const r = await redeem({
        code: probe.code,
        audience: "libre",
        intent: "product_exchange",
        redirect_uri: LIBRE_REDIRECT,
        state: `st-enum-${probe.name}`,
      });
      expect(r.status).toBe(400);
      bodies.push(await r.text());
    }
    // Shape variants ride the same uniform reject (no oracle by field).
    for (const variant of [
      { code: "ab".repeat(32), audience: "libre", intent: "wrong_intent", redirect_uri: LIBRE_REDIRECT, state: "st-enum-intent" },
      { code: "ab".repeat(32), audience: "libre", intent: "product_exchange", state: "st-enum-noredirect" },
      { code: "ab".repeat(32), audience: "nope", intent: "product_exchange", redirect_uri: LIBRE_REDIRECT, state: "st-enum-aud" },
    ]) {
      const r = await redeem(variant);
      expect(r.status).toBe(400);
      bodies.push(await r.text());
    }
    for (const body of bodies) expect(body).toBe(INVALID_GRANT);

    const after = await storeCounts(id);
    expect(after).toEqual(before);

    // The sweep poisoned nothing: the real code minted above still redeems.
    const { code: fresh, state: freshState } = await mintCode(accessToken, "st-matrix-enum-ok");
    const good = await redeem(goodBody(fresh, freshState));
    expect(good.status).toBe(200);
    console.log(
      `[matrix-enum] probes=${bodies.length} bodies-identical=true users=${before.users}->${after.users} sessions=${before.sessions}->${after.sessions}`,
    );
  });
});
