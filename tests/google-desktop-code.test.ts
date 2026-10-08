// Desktop loopback Google code exchange (POST /auth/google/desktop-code).
//
// The desktop loopback server captures the authorization code in the SYSTEM
// browser and redeems it here, where the confidential client secret lives.
// redirect_uri MUST be the loopback callback form
// (http://127.0.0.1:<port>/auth/desktop-google/callback, localhost alias
// allowed); the production https callback keeps working through its own
// untouched endpoints. Dummy secrets only; Google itself is never reached:
// the token endpoint is stubbed and the ID token comes from the shared JWKS
// rig.

process.env["JWT_SECRET"] = "test-only-dummy-secret-0123456789abcdef";
process.env["ALLOW_WEAK_JWT_SECRET"] = "1";
process.env["NODE_ENV"] = "test";

const ENV_KEYS = [
  "AUTH_ISSUER",
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
] as const;
const ENV_BACKUP = new Map<string, string | undefined>(
  ENV_KEYS.map((k) => [k, process.env[k]]),
);

function applyEnv(): void {
  process.env["AUTH_ISSUER"] = "https://auth.alcore.io.vn";
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
import { resetGoogleJwksCacheForTests } from "../src/lib/google";
import { baseGoogleClaims, createGoogleTestRig } from "./google-jwks-helper";

await resetStoresForTests();

beforeEach(async () => {
  await resetStoresForTests();
  resetRateLimitsForTests();
  resetThrottleConnForTests();
  resetGoogleJwksCacheForTests();
  applyEnv();
});

afterAll(() => {
  restoreEnv();
});

const LOOPBACK = "http://127.0.0.1:57123/auth/desktop-google/callback";

async function postDesktopCode(body: Record<string, unknown>): Promise<Response> {
  return app.request("/auth/google/desktop-code", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

// Stubs the Google token endpoint with the given id_token, serves the rig
// JWKS, and captures the token request body for redirect/verifier assertions.
function installTokenFetch(rig: ReturnType<typeof createGoogleTestRig>, idToken: string): {
  restore: () => void;
  tokenBody: () => string;
} {
  const originalFetch = globalThis.fetch;
  let captured = "";
  const mocked = Object.assign(
    (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/certs")) {
        return new Response(JSON.stringify(rig.jwksBody), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url.includes("oauth2.googleapis.com/token")) {
        captured = String(init?.body ?? "");
        return new Response(JSON.stringify({ id_token: idToken }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(JSON.stringify({}), { status: 404 });
    }) as typeof globalThis.fetch,
    { preconnect: globalThis.fetch.preconnect },
  );
  globalThis.fetch = mocked;
  return { restore: () => { globalThis.fetch = originalFetch; }, tokenBody: () => captured };
}

describe("POST /auth/google/desktop-code", () => {
  test("rejects the production https callback and other non-loopback URIs", async () => {
    for (const redirect_uri of [
      "https://auth.alcore.io.vn/auth/google/callback",
      "https://web.alcore.io.vn/auth/desktop-google/callback",
      "http://127.0.0.1:57123/other/path",
      "http://example.com/auth/desktop-google/callback",
      "",
    ]) {
      const res = await postDesktopCode({ code: "some-code", redirect_uri });
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: "invalid_request" });
    }
  });

  test("rejects missing code and malformed verifier", async () => {
    const noCode = await postDesktopCode({ redirect_uri: LOOPBACK });
    expect(noCode.status).toBe(400);
    const badVerifier = await postDesktopCode({
      code: "some-code",
      redirect_uri: LOOPBACK,
      code_verifier: "too-short",
    });
    expect(badVerifier.status).toBe(400);
    expect(await badVerifier.json()).toEqual({ error: "invalid_request" });
  });

  test("fails closed without client secret configured", async () => {
    delete process.env["GOOGLE_CLIENT_SECRET"];
    const res = await postDesktopCode({ code: "some-code", redirect_uri: LOOPBACK });
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "google_not_configured" });
  });

  test("exchanges a loopback code for a live session pair", async () => {
    const rig = createGoogleTestRig();
    const nonce = "desktop-nonce-1";
    const token = rig.mintIdToken(baseGoogleClaims({ nonce }));
    const fetchCtl = installTokenFetch(rig, token);
    try {
      const res = await postDesktopCode({
        code: "loopback-code-1",
        redirect_uri: LOOPBACK,
        code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        nonce,
      });
      expect(res.status).toBe(200);
      const pair = (await res.json()) as { access_token?: unknown };
      expect(typeof pair.access_token).toBe("string");
      // The token request reused the exact loopback redirect_uri and the
      // PKCE verifier (never the secret, which stays server-side).
      const sent = new URLSearchParams(fetchCtl.tokenBody());
      expect(sent.get("redirect_uri")).toBe(LOOPBACK);
      expect(sent.get("code_verifier")).toBe("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
      expect(sent.get("client_secret")).toBe("test-client-secret");
      // The pair is a live session: /auth/me answers for it.
      const me = await app.request("/auth/me", {
        headers: { authorization: `Bearer ${pair.access_token}` },
      });
      expect(me.status).toBe(200);
      expect(await me.json()).toMatchObject({ email: "test-user@example.com", emailVerified: true });
    } finally {
      fetchCtl.restore();
    }
  });

  test("accepts the localhost alias with any port", async () => {
    const rig = createGoogleTestRig();
    const token = rig.mintIdToken(baseGoogleClaims({}));
    const fetchCtl = installTokenFetch(rig, token);
    try {
      const res = await postDesktopCode({
        code: "loopback-code-2",
        redirect_uri: "http://localhost:9/auth/desktop-google/callback",
      });
      expect(res.status).toBe(200);
      expect(new URLSearchParams(fetchCtl.tokenBody()).get("redirect_uri")).toBe(
        "http://localhost:9/auth/desktop-google/callback",
      );
    } finally {
      fetchCtl.restore();
    }
  });

  test("rejects a nonce mismatch and a refused token exchange", async () => {
    const rig = createGoogleTestRig();
    const mismatched = rig.mintIdToken(baseGoogleClaims({ nonce: "other-nonce" }));
    const fetchCtl = installTokenFetch(rig, mismatched);
    try {
      const res = await postDesktopCode({
        code: "loopback-code-3",
        redirect_uri: LOOPBACK,
        nonce: "desktop-nonce-1",
      });
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ error: "invalid_google_credential" });
    } finally {
      fetchCtl.restore();
    }
    const originalFetch = globalThis.fetch;
    globalThis.fetch = Object.assign(
      (async (_input: RequestInfo | URL) => new Response("bad", { status: 400 })) as typeof globalThis.fetch,
      { preconnect: globalThis.fetch.preconnect },
    );
    try {
      const res = await postDesktopCode({ code: "loopback-code-4", redirect_uri: LOOPBACK });
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ error: "invalid_google_credential" });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
