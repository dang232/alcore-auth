// Google callback success path (no return handoff) + restart resume.
//
// (1) Success without a return-handoff cookie must stop emitting readable
// tokens to browsers: Accept: text/html gets a friendly signed-in card (same
// visual style as the fail pages, links to the product surfaces, ZERO
// token/user values in the body); API callers keep byte-identical JSON
// (proven with an exact-string assertion).
// (2) Restart resume: a product handoff that fails validation persists its
// triple in a short-lived HttpOnly cookie; the bare restart link (zero
// params, as rendered on every fail page) consumes it and re-enters the
// validated-handoff branch with a FRESH Google state (302 to
// accounts.google.com + return cookie set). Absent/invalid cookie keeps
// today's bare behavior. Google itself is never reached: start 302s are
// asserted on the Location header, callback success via the shared JWKS rig.
//
// Dummy secrets only. Code defaults active (no AUTH_OIDC_CLIENTS /
// AUTH_ALLOWED_ORIGINS overrides), so `libre →
// https://web.alcore.io.vn/auth/alcore/callback` validates.

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

function applyEnv(): void {
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
import { resetStoresForTests, googleStateStore } from "../src/lib/store";
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

const LIBRE_RETURN = "https://web.alcore.io.vn/auth/alcore/callback";
const HANDOFF_STATE = "e2e-handoff-state-1";

function startUrl(audience: string, redirectUri: string, state: string): string {
  return `/auth/google/start?${new URLSearchParams({ audience, redirect_uri: redirectUri, state }).toString()}`;
}

function cookieValue(setCookies: string[], name: string): string | null {
  const found = setCookies.find((v) => v.startsWith(`${name}=`));
  if (found === undefined) return null;
  return (found.slice(name.length + 1).split(";")[0] ?? "").trim();
}

function decodeTriple(raw: string): { audience: string; redirect_uri: string; state: string } {
  try {
    return JSON.parse(raw) as { audience: string; redirect_uri: string; state: string };
  } catch {
    return JSON.parse(decodeURIComponent(raw)) as { audience: string; redirect_uri: string; state: string };
  }
}

function response(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

// Drives GET /auth/google/callback to success WITHOUT reaching Google: a
// fresh single-use state is issued directly, fetch answers the token
// endpoint with a nonce-bound ID token and serves the rig JWKS.
async function callbackSuccess(opts: {
  email: string;
  sub: string;
  acceptHtml: boolean;
  returnCookie?: string;
}): Promise<Response> {
  const state = `e2e-cb-${crypto.randomUUID()}`;
  const nonce = `e2e-nonce-${crypto.randomUUID()}`;
  await googleStateStore.issue(state, nonce, Math.floor(Date.now() / 1000) + 300);
  const rig = createGoogleTestRig();
  const token = rig.mintIdToken(baseGoogleClaims({ nonce, sub: opts.sub, email: opts.email }));
  const originalFetch = globalThis.fetch;
  const mocked = Object.assign(
    (async (input: RequestInfo | URL) => {
      if (String(input).includes("/certs")) return response(200, rig.jwksBody);
      return response(200, { id_token: token });
    }) as typeof globalThis.fetch,
    { preconnect: globalThis.fetch.preconnect },
  );
  globalThis.fetch = mocked;
  try {
    const cookies = [`alcore_google_state=${state}`];
    if (opts.returnCookie !== undefined) cookies.push(opts.returnCookie);
    return await app.request(
      `/auth/google/callback?state=${encodeURIComponent(state)}&code=e2e-code`,
      {
        headers: {
          cookie: cookies.join("; "),
          accept: opts.acceptHtml ? "text/html" : "application/json",
        },
      },
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
}

describe("google start: valid handoff reaches Google without Google", () => {
  test("valid-handoff start 302s to accounts.google.com with return + resume cookies", async () => {
    const res = await app.request(startUrl("libre", LIBRE_RETURN, HANDOFF_STATE));
    expect(res.status).toBe(302);
    expect(res.headers.get("location") ?? "").toContain("accounts.google.com");
    const set = res.headers.getSetCookie();
    expect(cookieValue(set, "alcore_google_state")).not.toBeNull();
    const ret = cookieValue(set, "alcore_google_return");
    const resume = cookieValue(set, "alcore_google_resume");
    expect(ret).not.toBeNull();
    expect(resume).not.toBeNull();
    expect(decodeTriple(ret!)).toEqual({ audience: "libre", redirect_uri: LIBRE_RETURN, state: HANDOFF_STATE });
    expect(decodeTriple(resume!)).toEqual({ audience: "libre", redirect_uri: LIBRE_RETURN, state: HANDOFF_STATE });
    // Resume cookie is scoped to the restart path with a short TTL.
    const resumeEntry = set.find((v) => v.startsWith("alcore_google_resume=")) ?? "";
    expect(resumeEntry).toContain("HttpOnly");
    expect(resumeEntry).toContain("Path=/auth/google/start");
    expect(resumeEntry).toContain("Max-Age=300");
  });
});

describe("google start: failed handoff then restart resumes the product flow", () => {
  test("failed product handoff then restart 302s to accounts.google.com carrying a valid handoff", async () => {
    // Failed product handoff: unknown URI, byte-identical JSON for APIs.
    const bad = await app.request(startUrl("libre", "https://evil.example/callback", "st-evil"));
    expect(bad.status).toBe(400);
    expect(await bad.text()).toBe(JSON.stringify({ error: "invalid_request" }));

    // Valid handoff start: 302 + resume cookie persists the triple.
    const good = await app.request(startUrl("libre", LIBRE_RETURN, HANDOFF_STATE));
    expect(good.status).toBe(302);
    const goodSet = good.headers.getSetCookie();
    const goodState = cookieValue(goodSet, "alcore_google_state") ?? "";
    expect(goodState).not.toBe("");
    const resume = cookieValue(goodSet, "alcore_google_resume");
    expect(resume).not.toBeNull();

    // Bare restart link (zero params) consumes the resume cookie: fresh
    // Google state, 302 to Google, return cookie re-armed with the handoff.
    const restart = await app.request("/auth/google/start", {
      headers: { cookie: `alcore_google_resume=${resume}` },
    });
    expect(restart.status).toBe(302);
    expect(restart.headers.get("location") ?? "").toContain("accounts.google.com");
    const restartSet = restart.headers.getSetCookie();
    const freshState = cookieValue(restartSet, "alcore_google_state") ?? "";
    expect(freshState).not.toBe("");
    expect(freshState).not.toBe(goodState);
    const rearmed = cookieValue(restartSet, "alcore_google_return");
    expect(rearmed).not.toBeNull();
    expect(decodeTriple(rearmed!)).toEqual({ audience: "libre", redirect_uri: LIBRE_RETURN, state: HANDOFF_STATE });
  });

  test("restart with an invalid resume cookie keeps bare behavior (302, no handoff)", async () => {
    const restart = await app.request("/auth/google/start", {
      headers: {
        cookie: `alcore_google_resume=${encodeURIComponent(JSON.stringify({ audience: "libre", redirect_uri: "https://evil.example/callback", state: "st-evil" }))}`,
      },
    });
    expect(restart.status).toBe(302);
    expect(restart.headers.get("location") ?? "").toContain("accounts.google.com");
    expect(cookieValue(restart.headers.getSetCookie(), "alcore_google_return")).toBeNull();
  });

  test("bare start with no cookies keeps today's behavior (302, state only)", async () => {
    const res = await app.request("/auth/google/start");
    expect(res.status).toBe(302);
    expect(res.headers.get("location") ?? "").toContain("accounts.google.com");
    const set = res.headers.getSetCookie();
    expect(cookieValue(set, "alcore_google_state")).not.toBeNull();
    expect(cookieValue(set, "alcore_google_return")).toBeNull();
    expect(set.some((v) => v.startsWith("alcore_google_resume="))).toBe(false);
  });
});

describe("google callback success without return handoff", () => {
  test("browser gets a friendly signed-in page with zero token/user values", async () => {
    const email = "e2e-cb-html@example.com";
    const sub = "e2e-cb-sub-html-1";
    const res = await callbackSuccess({ email, sub, acceptHtml: true });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type") ?? "").toContain("text/html");
    const html = await res.text();
    expect(html).toContain('href="https://web.alcore.io.vn"');
    expect(html).toContain('href="https://alcore.io.vn"');
    for (const needle of ["access_token", "refresh_token", "eyJ", email, sub, "alcore_at", "alcore_rt"]) {
      expect(html.includes(needle)).toBe(false);
    }
    // Session is still established via HttpOnly cookies.
    const set = res.headers.getSetCookie();
    expect((cookieValue(set, "alcore_at") ?? "").length).toBeGreaterThan(0);
    expect((cookieValue(set, "alcore_rt") ?? "").length).toBeGreaterThan(0);
  });

  test("API caller keeps byte-identical token JSON", async () => {
    const res = await callbackSuccess({ email: "e2e-cb-json@example.com", sub: "e2e-cb-sub-json-1", acceptHtml: false });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type") ?? "").toContain("application/json");
    const raw = await res.text();
    const body = JSON.parse(raw) as {
      access_token: string;
      refresh_token: string;
      token_type: string;
      expires_in: number;
      user: { id: string; email: string; emailVerified: boolean };
    };
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBe(900);
    expect(body.user).toEqual({ id: body.user.id, email: "e2e-cb-json@example.com", emailVerified: true });
    expect(raw).toBe(
      JSON.stringify({
        access_token: body.access_token,
        refresh_token: body.refresh_token,
        token_type: "Bearer",
        expires_in: 900,
        user: { id: body.user.id, email: body.user.email, emailVerified: true },
      }),
    );
  });

  test("google state stays single-use (replay rejected)", async () => {
    const state = `e2e-replay-${crypto.randomUUID()}`;
    const nonce = `e2e-replay-nonce-${crypto.randomUUID()}`;
    await googleStateStore.issue(state, nonce, Math.floor(Date.now() / 1000) + 300);
    const rig = createGoogleTestRig();
    const token = rig.mintIdToken(baseGoogleClaims({ nonce, sub: "e2e-replay-sub", email: "e2e-replay@example.com" }));
    const originalFetch = globalThis.fetch;
    globalThis.fetch = Object.assign(
      (async (input: RequestInfo | URL) => {
        if (String(input).includes("/certs")) return response(200, rig.jwksBody);
        return response(200, { id_token: token });
      }) as typeof globalThis.fetch,
      { preconnect: globalThis.fetch.preconnect },
    );
    try {
      const target = `/auth/google/callback?state=${encodeURIComponent(state)}&code=e2e-code`;
      const jar = `alcore_google_state=${state}`;
      const first = await app.request(target, { headers: { cookie: jar } });
      expect(first.status).toBe(200);
      const replay = await app.request(target, { headers: { cookie: jar } });
      expect(replay.status).toBe(400);
      expect(await replay.text()).toBe(JSON.stringify({ error: "invalid_google_state" }));
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
