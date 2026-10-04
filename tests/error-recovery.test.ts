// Error-page recovery (ux-smooth frictions R6, R8, R34, R35).
//
// Every case asserts the fail-closed contract first (status + JSON shape for
// API callers are byte-identical), then the browser recovery affordance:
//   R6  — exchangeRedirectError HTML gains a per-error "Restart sign-in"
//         deep-link preserving redirect_uri/state, plus a request-id.
//   R8  — bare 400 invalid_google_state maps to a restart page for browser
//         HTML (with the sign-in panel auto-restart hook contract), while the
//         Google state stays single-use with its 300s TTL.
//   R34 — invalid_redirect_uri page echoes the client + attempted redirect +
//         support URL; the allowlist stays operator-manual (no endpoint edits).
//   R35 — expired/replayed verify/reset tokens render a "Resend link" form
//         posting to the existing always-200 /auth/verify|reset/request
//         endpoints (no new endpoints were needed); the old link never revives.
process.env["JWT_SECRET"] = "test-only-dummy-secret-0123456789abcdef";
process.env["ALLOW_WEAK_JWT_SECRET"] = "1";
process.env["NODE_ENV"] = "test";

// Same one-process warning as exchange-redirect.test.ts: save and restore.
const ENV_KEYS = [
  "AUTH_ISSUER",
  "AUTH_OIDC_CLIENTS",
  "AUTH_ALLOWED_ORIGINS",
  "AUTH_SUPPORT_URL",
  "GOOGLE_CLIENT_ID",
] as const;
const ENV_BACKUP = new Map<string, string | undefined>(
  ENV_KEYS.map((key) => [key, process.env[key]]),
);

function applyEnv(): void {
  process.env["AUTH_ISSUER"] = "https://auth.alcore.io.vn";
  process.env["AUTH_OIDC_CLIENTS"] =
    "libre=https://web.alcore.io.vn/auth/callback,tokenpanel=https://portal.alcore.io.vn/auth/callback";
  process.env["AUTH_ALLOWED_ORIGINS"] = "https://web.alcore.io.vn,https://portal.alcore.io.vn";
  delete process.env["AUTH_SUPPORT_URL"];
  // R8 replay test needs the pre-JWKS gate: with no client id the callback
  // stops at google_not_configured AFTER consuming a valid state, which is
  // what lets the second attempt prove single-use without network access.
  process.env["GOOGLE_CLIENT_ID"] = "";
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

await resetStoresForTests();

async function sessionFor(email: string): Promise<string> {
  const { userStore, sessionStore } = await import("../src/lib/store");
  const { signAccess, hashToken, randomToken } = await import("../src/lib/crypto");
  const { getJwtSecret, getIssuer } = await import("../src/config");
  const user = await userStore.create(email, "argon2id-test-hash");
  const session = await sessionStore.create(user.id, hashToken(randomToken(32)), 3_600_000);
  return signAccess(
    { sub: user.id, sid: session.id, iss: getIssuer(), aud: "auth", intent: "session" },
    getJwtSecret(),
    3600,
  );
}

function redirectUrl(query: Record<string, string>): string {
  return `/oidc/exchange/redirect?${new URLSearchParams(query).toString()}`;
}

describe("error-page recovery (R6/R8/R34/R35)", () => {
  beforeEach(async () => {
    await resetStoresForTests();
    resetRateLimitsForTests();
    resetThrottleConnForTests();
    applyEnv();
  });

  afterAll(() => {
    restoreEnv();
  });

  test("R6: invalid_state HTML preserves redirect_uri/state in a Restart link + request-id; JSON unchanged", async () => {
    const accessToken = await sessionFor("r6-state@example.com");
    const query = { audience: "libre", redirect_uri: LIBRE_REDIRECT, state: "st-r6" };
    const api = await app.request(redirectUrl({ ...query, state: "" }), {
      redirect: "manual",
      headers: { cookie: `alcore_at=${accessToken}` },
    });
    expect(api.status).toBe(400);
    expect(await api.json()).toEqual({ error: "invalid_state" });

    const page = await app.request(redirectUrl({ ...query, state: "" }), {
      redirect: "manual",
      headers: { cookie: `alcore_at=${accessToken}`, accept: "text/html" },
    });
    expect(page.status).toBe(400);
    const html = await page.text();
    expect(html).toContain("Restart sign-in");
    expect(html).toContain(`redirect_uri=${encodeURIComponent(LIBRE_REDIRECT)}`);
    expect(html).toContain("request ");
    expect(html).not.toContain('{"error"');
  });

  test("R6: unauthorized HTML keeps a retry deep-link for after login", async () => {
    const page = await app.request(
      redirectUrl({ audience: "libre", redirect_uri: LIBRE_REDIRECT, state: "st-login" }),
      { redirect: "manual", headers: { accept: "text/html" } },
    );
    expect(page.status).toBe(401);
    const html = await page.text();
    expect(html).toContain("Restart sign-in");
    expect(html).toContain(`state=st-login`);
    expect(html).toContain("Return to login");
  });

  test("R34: invalid_redirect_uri HTML echoes client + redirect + support URL and NO restart link", async () => {
    const evil = "https://evil.example.com/auth/callback";
    const page = await app.request(
      redirectUrl({ audience: "libre", redirect_uri: evil, state: "st-r34" }),
      { redirect: "manual", headers: { accept: "text/html" } },
    );
    expect(page.status).toBe(400);
    const html = await page.text();
    // Ticket context: client id, attempted target, support URL, request id.
    expect(html).toContain("libre");
    expect(html).toContain(evil);
    expect(html).toContain("https://alcore.io.vn/support");
    expect(html).toContain("request ");
    // Open-redirect guard: the unvalidated URI must not become a link target.
    expect(html).not.toContain("Restart sign-in");
    expect(html).not.toContain(`href=\"${evil}`);
  });

  test("R8: invalid_google_state keeps its JSON shape, HTML gets restart page + panel hook", async () => {
    const api = await app.request("/auth/google/callback?state=nope&code=nope");
    expect(api.status).toBe(400);
    expect(await api.json()).toEqual({ error: "invalid_google_state" });

    const page = await app.request("/auth/google/callback?state=nope&code=nope", {
      headers: { accept: "text/html" },
    });
    expect(page.status).toBe(400);
    const html = await page.text();
    expect(html).toContain('data-auth-error="invalid_google_state"');
    expect(html).toContain('id="auth-restart"');
    expect(html).toContain('href="/auth/google/start"');
  });

  test("R8: a consumed Google state stays single-use (first use valid-then-503, replay 400)", async () => {
    const { googleStateStore } = await import("../src/lib/store");
    const state = "r8-single-use-state";
    await googleStateStore.issue(state, "r8-nonce", Math.floor(Date.now() / 1000) + 300);
    const cookie = `alcore_google_state=${state}`;
    const target = `/auth/google/callback?${new URLSearchParams({ state, code: "auth-code-x" }).toString()}`;

    const first = await app.request(target, { headers: { cookie } });
    // State was valid and consumed exactly once: the request proceeds past
    // the state gate and stops at the (unset) Google config, not at state.
    expect(first.status).toBe(503);
    expect(await first.json()).toEqual({ error: "google_not_configured" });

    resetRateLimitsForTests();
    const replay = await app.request(target, {
      headers: { cookie, accept: "text/html" },
    });
    expect(replay.status).toBe(400);
    expect(await replay.text()).toContain('data-auth-error="invalid_google_state"');
  });

  test("R35: verify invalid_token keeps JSON, HTML renders resend form to /auth/verify/request", async () => {
    const api = await app.request("/auth/verify/consume", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: "garbage-token" }),
    });
    expect(api.status).toBe(400);
    expect(await api.json()).toEqual({ error: "invalid_token" });

    const page = await app.request("/auth/verify/consume", {
      method: "POST",
      headers: { "content-type": "application/json", accept: "text/html" },
      body: JSON.stringify({ token: "garbage-token" }),
    });
    expect(page.status).toBe(400);
    const html = await page.text();
    expect(html).toContain('action="/auth/verify/request"');
    expect(html).toContain('id="auth-resend"');

    // The resend target accepts the form post and stays non-enumerating.
    resetRateLimitsForTests();
    const resend = await app.request("/auth/verify/request", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ email: "nobody-here@example.com" }).toString(),
    });
    expect(resend.status).toBe(200);
    expect(await resend.json()).toEqual({ ok: true });
  });

  test("R35: reset invalid_token keeps JSON, HTML renders resend form to /auth/reset/request", async () => {
    const api = await app.request("/auth/reset/consume", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: "garbage-token", newPassword: "brand-new-pass" }),
    });
    expect(api.status).toBe(400);
    expect(await api.json()).toEqual({ error: "invalid_token" });

    const page = await app.request("/auth/reset/consume", {
      method: "POST",
      headers: { "content-type": "application/json", accept: "text/html" },
      body: JSON.stringify({ token: "garbage-token", newPassword: "brand-new-pass" }),
    });
    expect(page.status).toBe(400);
    expect(await page.text()).toContain('action="/auth/reset/request"');

    resetRateLimitsForTests();
    const resend = await app.request("/auth/reset/request", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ email: "nobody-here@example.com" }).toString(),
    });
    expect(resend.status).toBe(200);
    expect(await resend.json()).toEqual({ ok: true });
  });
});
