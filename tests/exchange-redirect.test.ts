// Browser handoff: GET /oidc/exchange/redirect mints a single-use product code
// from the HttpOnly session cookie, and POST /oidc/exchange/token redeems it.
//
// The property under test is that a browser can complete Auth-owns-identity
// login WITHOUT JavaScript ever seeing a session token, while every bypass
// attempt (unauthenticated, wrong audience, unregistered redirect, tampered
// state, replay, wrong audience at redemption) is refused.
process.env["JWT_SECRET"] = "test-only-dummy-secret-0123456789abcdef";
process.env["ALLOW_WEAK_JWT_SECRET"] = "1";
process.env["NODE_ENV"] = "test";

// Bun runs every test file in one process, so these overrides are visible to the
// other suites. Save and restore rather than leaving the process mutated:
// AUTH_ISSUER in particular must keep its https:// form, since purposeLink builds
// issuer-scoped URLs that mail.test.ts asserts on.
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

import { describe, test, expect, beforeEach, afterAll, setSystemTime } from "bun:test";
import { app } from "../src/index";
import { resetStoresForTests } from "../src/lib/store";

const LIBRE_REDIRECT = "https://web.alcore.io.vn/auth/callback";
const PANEL_REDIRECT = "https://portal.alcore.io.vn/auth/callback";

resetStoresForTests();

const PASSWORD = "s3cret-pass";

/**
 * Registers a user and returns its Auth id plus the raw session JWT.
 *
 * Mints the session directly through the store rather than POSTing /auth/login:
 * the shared authRateLimit bucket is 30 requests per IP per 60s across the whole
 * suite, and going through the HTTP login route for every case would exhaust it
 * and make later suites fail with unrelated 401/429s.
 */
async function sessionFor(email: string): Promise<{ id: string; accessToken: string }> {
  const { userStore, sessionStore } = await import("../src/lib/store");
  const { signAccess, hashToken, randomToken } = await import("../src/lib/crypto");
  const { getJwtSecret, getIssuer } = await import("../src/config");
  const user = userStore.create(email, "argon2id-test-hash");
  const session = sessionStore.create(user.id, hashToken(randomToken(32)), 3_600_000);
  const accessToken = signAccess(
    { sub: user.id, sid: session.id, iss: getIssuer(), aud: "auth", intent: "session" },
    getJwtSecret(),
    3600,
  );
  return { id: user.id, accessToken };
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

/** Extracts code + state from a 302 Location header. */
function fromLocation(location: string): { code: string; state: string } {
  const url = new URL(location);
  return { code: url.searchParams.get("code") ?? "", state: url.searchParams.get("state") ?? "" };
}

describe("GET /oidc/exchange/redirect — browser handoff", () => {
  beforeEach(() => {
    resetStoresForTests();
    applyRedirectEnv();
  });

  afterAll(() => {
    restoreEnv();
  });

  test("a cookie-authenticated session gets a 302 carrying an opaque code and the same state", async () => {
    const { accessToken } = await sessionFor("handoff1@example.com");
    const res = await getRedirect(
      { audience: "libre", redirect_uri: LIBRE_REDIRECT, state: "st-abc" },
      accessToken,
    );
    expect(res.status).toBe(302);
    const location = res.headers.get("location") ?? "";
    expect(location.startsWith(`${LIBRE_REDIRECT}?`)).toBe(true);
    const { code, state } = fromLocation(location);
    expect(code).not.toBe("");
    expect(state).toBe("st-abc");
  });

  test("the redirect never leaks a session or access token in the URL", async () => {
    const { accessToken } = await sessionFor("handoff-leak@example.com");
    const res = await getRedirect(
      { audience: "libre", redirect_uri: LIBRE_REDIRECT, state: "st-leak" },
      accessToken,
    );
    const location = res.headers.get("location") ?? "";
    // The session JWT must not appear anywhere in the redirect target.
    expect(location.includes(accessToken)).toBe(false);
    expect(location.includes("eyJ")).toBe(false);
    expect(location).not.toContain("access_token");
    expect(location).not.toContain("alcore_at");
  });

  test("rejects an unauthenticated request with no cookie", async () => {
    const res = await getRedirect({ audience: "libre", redirect_uri: LIBRE_REDIRECT, state: "st-none" });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized" });
  });

  test("rejects a garbage cookie rather than minting a code", async () => {
    const res = await getRedirect(
      { audience: "libre", redirect_uri: LIBRE_REDIRECT, state: "st-garbage" },
      "not-a-jwt",
    );
    expect(res.status).toBe(401);
  });

  test("rejects a Bearer token in place of the cookie, so JS cannot drive this", async () => {
    const { accessToken } = await sessionFor("handoff-bearer@example.com");
    const res = await app.request(
      redirectUrl({ audience: "libre", redirect_uri: LIBRE_REDIRECT, state: "st-bearer" }),
      { redirect: "manual", headers: { authorization: `Bearer ${accessToken}` } },
    );
    expect(res.status).toBe(401);
  });

  test("rejects an unregistered audience", async () => {
    const { accessToken } = await sessionFor("handoff-aud@example.com");
    const res = await getRedirect(
      { audience: "someoneelse", redirect_uri: LIBRE_REDIRECT, state: "st-aud" },
      accessToken,
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid_audience" });
  });

  test("rejects an unregistered redirect URI (open-redirect guard)", async () => {
    const { accessToken } = await sessionFor("handoff-redirect@example.com");
    for (const evil of [
      "https://evil.example.com/auth/callback",
      "https://web.alcore.io.vn/auth/callback/../../evil",
      "http://web.alcore.io.vn/auth/callback",
      "https://web.alcore.io.vn.evil.example/auth/callback",
    ]) {
      const res = await getRedirect({ audience: "libre", redirect_uri: evil, state: "st-evil" }, accessToken);
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: "invalid_redirect_uri" });
    }
  });

  test("refuses a redirect whose origin is not in AUTH_ALLOWED_ORIGINS even if registered", async () => {
    const { accessToken } = await sessionFor("handoff-origin@example.com");
    // Registered in AUTH_OIDC_CLIENTS but deliberately absent from allowed origins.
    process.env["AUTH_OIDC_CLIENTS"] =
      "libre=https://web.alcore.io.vn/auth/callback,stray=https://stray.example.com/auth/callback";
    const res = await getRedirect(
      { audience: "libre", redirect_uri: "https://stray.example.com/auth/callback", state: "st-stray" },
      accessToken,
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid_redirect_uri" });
    process.env["AUTH_OIDC_CLIENTS"] =
      "libre=https://web.alcore.io.vn/auth/callback,tokenpanel=https://portal.alcore.io.vn/auth/callback";
  });

  test("refuses a missing or empty state so a caller cannot skip CSRF binding", async () => {
    const { accessToken } = await sessionFor("handoff-state@example.com");
    const missing = await app.request(
      `/oidc/exchange/redirect?${new URLSearchParams({ audience: "libre", redirect_uri: LIBRE_REDIRECT }).toString()}`,
      { redirect: "manual", headers: cookieHeader(accessToken) },
    );
    expect(missing.status).toBe(400);
    expect(await missing.json()).toEqual({ error: "invalid_state" });
    const empty = await getRedirect({ audience: "libre", redirect_uri: LIBRE_REDIRECT, state: "" }, accessToken);
    expect(empty.status).toBe(400);
    expect(await empty.json()).toEqual({ error: "invalid_state" });
  });

  test("rejects an over-long state rather than reflecting it into a URL", async () => {
    const { accessToken } = await sessionFor("handoff-longstate@example.com");
    const res = await getRedirect(
      { audience: "libre", redirect_uri: LIBRE_REDIRECT, state: "x".repeat(513) },
      accessToken,
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid_state" });
  });

  test("a minted code redeems once and cannot be replayed", async () => {
    const { accessToken } = await sessionFor("handoff-replay@example.com");
    const res = await getRedirect(
      { audience: "libre", redirect_uri: LIBRE_REDIRECT, state: "st-replay" },
      accessToken,
    );
    const { code, state } = fromLocation(res.headers.get("location") ?? "");
    const first = await redeem({ code, audience: "libre", intent: "product_exchange", redirect_uri: LIBRE_REDIRECT, state });
    expect(first.status).toBe(200);
    const second = await redeem({ code, audience: "libre", intent: "product_exchange", redirect_uri: LIBRE_REDIRECT, state });
    expect(second.status).toBe(400);
    expect(await second.json()).toEqual({ error: "invalid_grant" });
  });

  test("redemption refuses a tampered state", async () => {
    const { accessToken } = await sessionFor("handoff-tamper@example.com");
    const res = await getRedirect(
      { audience: "libre", redirect_uri: LIBRE_REDIRECT, state: "st-real" },
      accessToken,
    );
    const { code } = fromLocation(res.headers.get("location") ?? "");
    const bad = await redeem({ code, audience: "libre", intent: "product_exchange", redirect_uri: LIBRE_REDIRECT, state: "st-forged" });
    expect(bad.status).toBe(400);
    expect(await bad.json()).toEqual({ error: "invalid_grant" });
    // The real state still works: a forged attempt must not consume the code.
    const good = await redeem({ code, audience: "libre", intent: "product_exchange", redirect_uri: LIBRE_REDIRECT, state: "st-real" });
    expect(good.status).toBe(200);
  });

  test("redemption refuses a different registered redirect URI", async () => {
    const { accessToken } = await sessionFor("handoff-swap@example.com");
    const res = await getRedirect(
      { audience: "libre", redirect_uri: LIBRE_REDIRECT, state: "st-swap" },
      accessToken,
    );
    const { code, state } = fromLocation(res.headers.get("location") ?? "");
    const bad = await redeem({ code, audience: "libre", intent: "product_exchange", redirect_uri: PANEL_REDIRECT, state });
    expect(bad.status).toBe(400);
  });

  test("redemption refuses the wrong audience", async () => {
    const { accessToken } = await sessionFor("handoff-wrongaud@example.com");
    const res = await getRedirect(
      { audience: "libre", redirect_uri: LIBRE_REDIRECT, state: "st-wrongaud" },
      accessToken,
    );
    const { code, state } = fromLocation(res.headers.get("location") ?? "");
    const bad = await redeem({ code, audience: "tokenpanel", intent: "product_exchange", redirect_uri: LIBRE_REDIRECT, state });
    expect(bad.status).toBe(400);
  });

  test("a bound code cannot be redeemed through the legacy binding-free path", async () => {
    const { accessToken } = await sessionFor("handoff-legacy@example.com");
    const res = await getRedirect(
      { audience: "libre", redirect_uri: LIBRE_REDIRECT, state: "st-legacy" },
      accessToken,
    );
    const { code } = fromLocation(res.headers.get("location") ?? "");
    // No redirect_uri at all: must be refused, not silently downgraded.
    const bad = await redeem({ code, audience: "libre", intent: "product_exchange" });
    expect(bad.status).toBe(400);
    expect(await bad.json()).toEqual({ error: "invalid_grant" });
  });

  test("the redeemed assertion is product-scoped and short-lived, not a session token", async () => {
    const { accessToken, id } = await sessionFor("handoff-assert@example.com");
    const res = await getRedirect(
      { audience: "libre", redirect_uri: LIBRE_REDIRECT, state: "st-assert" },
      accessToken,
    );
    const { code, state } = fromLocation(res.headers.get("location") ?? "");
    const redeemed = await redeem({ code, audience: "libre", intent: "product_exchange", redirect_uri: LIBRE_REDIRECT, state });
    const { access_token: assertion, expires_in } = (await redeemed.json()) as {
      access_token: string;
      expires_in: number;
    };
    expect(expires_in).toBe(60);
    const payload = JSON.parse(atob(assertion.split(".")[1] ?? "e30")) as {
      aud: string; intent: string; sub: string; email: string;
    };
    expect(payload.aud).toBe("libre");
    expect(payload.intent).toBe("product_exchange");
    expect(payload.sub).toBe(id);
    expect(payload.email).toBe("handoff-assert@example.com");
    // Critically: it must NOT be usable as an Auth session token.
    const escalate = await app.request("/auth/me", { headers: { authorization: `Bearer ${assertion}` } });
    expect(escalate.status).toBe(401);
  });

  test("concurrent redemption of the same code yields exactly one winner", async () => {
    const { accessToken } = await sessionFor("handoff-race@example.com");
    const res = await getRedirect(
      { audience: "libre", redirect_uri: LIBRE_REDIRECT, state: "st-race" },
      accessToken,
    );
    const { code, state } = fromLocation(res.headers.get("location") ?? "");
    const body = { code, audience: "libre", intent: "product_exchange", redirect_uri: LIBRE_REDIRECT, state };
    const results = await Promise.all(Array.from({ length: 5 }, () => redeem(body)));
    const statuses = results.map((r) => r.status).sort();
    expect(statuses.filter((s) => s === 200)).toHaveLength(1);
    expect(statuses.filter((s) => s === 400)).toHaveLength(4);
  });

  test("a revoked session cannot mint a new code", async () => {
    const { accessToken } = await sessionFor("handoff-revoked@example.com");
    const { sessionStore } = await import("../src/lib/store");
    const { verifyAccess } = await import("../src/lib/crypto");
    const { getJwtSecret, getIssuer } = await import("../src/config");
    const payload = verifyAccess(accessToken, getJwtSecret(), getIssuer(), "auth", "session");
    const live = sessionStore.findById(payload.sid);
    expect(live).toBeDefined();
    sessionStore.revoke(live!);
    const res = await getRedirect(
      { audience: "libre", redirect_uri: LIBRE_REDIRECT, state: "st-revoked" },
      accessToken,
    );
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized" });
  });

  test("an expired code is refused even with the correct redirect and state", async () => {
    const { accessToken } = await sessionFor("handoff-expired@example.com");
    const res = await getRedirect(
      { audience: "libre", redirect_uri: LIBRE_REDIRECT, state: "st-expired" },
      accessToken,
    );
    const { code, state } = fromLocation(res.headers.get("location") ?? "");
    // Confirm the code is live before ageing it, so a 400 below proves expiry
    // rather than some unrelated rejection.
    const live = await redeem({
      code, audience: "libre", intent: "product_exchange", redirect_uri: LIBRE_REDIRECT, state,
    });
    expect(live.status).toBe(200);
    const fresh = await getRedirect(
      { audience: "libre", redirect_uri: LIBRE_REDIRECT, state: "st-expired-b" },
      accessToken,
    );
    const { code: code2, state: state2 } = fromLocation(fresh.headers.get("location") ?? "");
    setSystemTime(new Date(Date.now() + 61_000));
    try {
      const expired = await redeem({
        code: code2, audience: "libre", intent: "product_exchange", redirect_uri: LIBRE_REDIRECT, state: state2,
      });
      expect(expired.status).toBe(400);
      expect(await expired.json()).toEqual({ error: "invalid_grant" });
    } finally {
      setSystemTime();
    }
  });
});
