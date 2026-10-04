// Committed portal-callback OIDC default (portal half of auth-only login).
//
// Prod compose passes AUTH_OIDC_CLIENTS through empty, which used to parse to
// an empty map — so /oidc/exchange/redirect and /auth/google/start failed
// closed with invalid_redirect_uri for the portal callback and the portal
// Auth login could never complete in prod. With AUTH_OIDC_CLIENTS empty the
// code default must still register the portal callback, while unregistered
// (evil) URIs keep failing closed and an explicit AUTH_OIDC_CLIENTS keeps
// parsing exactly as before.
process.env["JWT_SECRET"] = "test-only-dummy-secret-0123456789abcdef";
process.env["ALLOW_WEAK_JWT_SECRET"] = "1";
process.env["NODE_ENV"] = "test";

// Same shared-process caveat as exchange-redirect.test.ts: save and restore,
// and always drive env through applyDefaultEnv() in beforeEach.
const ENV_KEYS = ["AUTH_ISSUER", "AUTH_OIDC_CLIENTS", "AUTH_ALLOWED_ORIGINS"] as const;
const ENV_BACKUP = new Map<string, string | undefined>(
  ENV_KEYS.map((key) => [key, process.env[key]]),
);

/** Prod-compose shape: both OIDC clients and allowed origins unset/empty. */
function applyDefaultEnv(): void {
  process.env["AUTH_ISSUER"] = "https://auth.alcore.io.vn";
  delete process.env["AUTH_OIDC_CLIENTS"];
  delete process.env["AUTH_ALLOWED_ORIGINS"];
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
import { getOidcClients } from "../src/config";

const PORTAL_REDIRECT = "https://alcore.io.vn/portal/auth/callback";

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

describe("committed portal OIDC client default", () => {
  beforeEach(async () => {
    await resetStoresForTests();
    resetRateLimitsForTests();
    resetThrottleConnForTests();
    applyDefaultEnv();
  });

  afterAll(() => {
    restoreEnv();
  });

  test("empty AUTH_OIDC_CLIENTS still registers the portal callback (code default)", () => {
    expect(getOidcClients().get("tokenpanel")).toBe(PORTAL_REDIRECT);
    process.env["AUTH_OIDC_CLIENTS"] = "   ";
    expect(getOidcClients().get("tokenpanel")).toBe(PORTAL_REDIRECT);
  });

  test("explicit AUTH_OIDC_CLIENTS still parses and replaces the default", () => {
    process.env["AUTH_OIDC_CLIENTS"] =
      "libre=https://web.alcore.io.vn/auth/callback";
    const clients = getOidcClients();
    expect(clients.get("libre")).toBe("https://web.alcore.io.vn/auth/callback");
    expect(clients.has("tokenpanel")).toBe(false);
  });

  test("exchange/redirect accepts the default-registered portal callback", async () => {
    const accessToken = await sessionFor("portal-default@example.com");
    const res = await app.request(
      `/oidc/exchange/redirect?${new URLSearchParams({
        audience: "tokenpanel",
        redirect_uri: PORTAL_REDIRECT,
        state: "st-portal",
      }).toString()}`,
      { redirect: "manual", headers: { cookie: `alcore_at=${accessToken}` } },
    );
    expect(res.status).toBe(302);
    const location = res.headers.get("location") ?? "";
    expect(location.startsWith(`${PORTAL_REDIRECT}?`)).toBe(true);
    expect(new URL(location).searchParams.get("state")).toBe("st-portal");
  });

  test("unregistered evil URIs still fail closed with defaults active", async () => {
    const accessToken = await sessionFor("portal-evil@example.com");
    for (const evil of [
      "https://evil.example.com/portal/auth/callback",
      "https://alcore.io.vn.evil.example/portal/auth/callback",
      "http://alcore.io.vn/portal/auth/callback",
      "https://alcore.io.vn/portal/auth/callback/../../evil",
    ]) {
      const res = await app.request(
        `/oidc/exchange/redirect?${new URLSearchParams({
          audience: "tokenpanel",
          redirect_uri: evil,
          state: "st-evil",
        }).toString()}`,
        { redirect: "manual", headers: { cookie: `alcore_at=${accessToken}` } },
      );
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: "invalid_redirect_uri" });
    }
  });
});
