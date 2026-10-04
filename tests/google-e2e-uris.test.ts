// Google return-URI pinning: code defaults in src/config.ts must accept every
// real product Google handoff through validateGoogleReturnHandoff
// (src/routes/auth.ts), which runs BEFORE the Google 302 on GET
// /auth/google/start. Unknown URIs must still 400.
//
// Pinned defaults:
//   libre        → https://web.alcore.io.vn/auth/alcore/callback (prod Libre)
//   libre-local  → http://localhost:3000/auth/alcore/callback   (self-host Libre)
//   tokenpanel   → https://alcore.io.vn/portal/auth/callback     (portal)
// An explicit AUTH_OIDC_CLIENTS replaces (not merges) these defaults.

process.env["JWT_SECRET"] = "test-only-dummy-secret-0123456789abcdef";
process.env["ALLOW_WEAK_JWT_SECRET"] = "1";
process.env["NODE_ENV"] = "test";

const ENV_KEYS = [
  "AUTH_ISSUER",
  "AUTH_OIDC_CLIENTS",
  "AUTH_ALLOWED_ORIGINS",
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
] as const;
const ENV_BACKUP = new Map<string, string | undefined>(
  ENV_KEYS.map((k) => [k, process.env[k]]),
);

// Code defaults under test: no AUTH_OIDC_CLIENTS override, default origins
// (which already allow https://web.alcore.io.vn, https://alcore.io.vn and
// http://localhost:3000), Google configured so /start reaches handoff
// validation instead of 503 google_not_configured.
function applyDefaultsEnv(): void {
  process.env["AUTH_ISSUER"] = "https://auth.alcore.io.vn";
  delete process.env["AUTH_OIDC_CLIENTS"];
  delete process.env["AUTH_ALLOWED_ORIGINS"];
  process.env["GOOGLE_CLIENT_ID"] = "test-client.apps.googleusercontent.com";
  process.env["GOOGLE_CLIENT_SECRET"] = "test-client-secret";
}

function restoreEnv(): void {
  for (const [k, v] of ENV_BACKUP) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
}

import { describe, test, expect, beforeEach, afterAll } from "bun:test";
import { app } from "../src/index";
import { resetRateLimitsForTests, resetThrottleConnForTests } from "../src/lib/ratelimit";
import { resetStoresForTests } from "../src/lib/store";
import { getOidcClients } from "../src/config";

await resetStoresForTests();

beforeEach(async () => {
  await resetStoresForTests();
  resetRateLimitsForTests();
  resetThrottleConnForTests();
  applyDefaultsEnv();
});

afterAll(() => {
  restoreEnv();
});

const LIBRE_RETURN = "https://web.alcore.io.vn/auth/alcore/callback";
const LIBRE_LOCAL_RETURN = "http://localhost:3000/auth/alcore/callback";
const PORTAL_RETURN = "https://alcore.io.vn/portal/auth/callback";

function startUrl(audience: string, redirectUri: string): string {
  const q = new URLSearchParams({ audience, redirect_uri: redirectUri, state: "e2e-state-123" });
  return `/auth/google/start?${q.toString()}`;
}

describe("google return-URI defaults", () => {
  test("defaults register the exact Libre prod return URI", () => {
    expect([...getOidcClients().values()]).toContain(LIBRE_RETURN);
  });

  test("libre prod return URI passes handoff validation (302, not 400)", async () => {
    const res = await app.request(startUrl("libre", LIBRE_RETURN));
    expect(res.status).toBe(302);
    expect(res.headers.get("location") ?? "").toContain("accounts.google.com");
  });

  test("portal return URI still passes handoff validation (302, not 400)", async () => {
    const res = await app.request(startUrl("tokenpanel", PORTAL_RETURN));
    expect(res.status).toBe(302);
    expect(res.headers.get("location") ?? "").toContain("accounts.google.com");
  });

  test("self-host Libre return URI passes handoff validation (302, not 400)", async () => {
    const res = await app.request(startUrl("libre", LIBRE_LOCAL_RETURN));
    expect(res.status).toBe(302);
    expect(res.headers.get("location") ?? "").toContain("accounts.google.com");
  });

  test("unknown return URI is rejected (400 invalid_request)", async () => {
    const res = await app.request(startUrl("libre", "https://evil.example/callback"));
    expect(res.status).toBe(400);
  });
});
