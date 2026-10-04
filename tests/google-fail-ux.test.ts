// Google-OAuth fail-path UX: every browser navigation renders the friendly
// error-page style with a back-to-login link, API callers keep byte-identical
// JSON. Covers every fail path in src/routes/auth.ts Google start/callback:
// start google_not_configured / invalid_request, callback google_oauth_error,
// invalid_google_state (no params, no code, mismatch, replay), callback
// google_not_configured, upstream_unavailable (fetch throw), 
// invalid_google_credential (token !ok + bad id_token), identity_conflict,
// trailing invalid_request (bad return handoff). Dummy states/secrets only.

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

function applyEnv(configured: boolean): void {
  process.env["AUTH_ISSUER"] = "https://auth.alcore.io.vn";
  process.env["AUTH_OIDC_CLIENTS"] =
    "libre=https://web.alcore.io.vn/auth/callback,tokenpanel=https://portal.alcore.io.vn/auth/callback";
  process.env["AUTH_ALLOWED_ORIGINS"] = "https://web.alcore.io.vn,https://portal.alcore.io.vn";
  if (configured) {
    process.env["GOOGLE_CLIENT_ID"] = "test-client.apps.googleusercontent.com";
    process.env["GOOGLE_CLIENT_SECRET"] = "test-client-secret";
  } else {
    delete process.env["GOOGLE_CLIENT_ID"];
    delete process.env["GOOGLE_CLIENT_SECRET"];
  }
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
import { resetStoresForTests, googleStateStore, userStore } from "../src/lib/store";
import { resetGoogleJwksCacheForTests } from "../src/lib/google";
import { baseGoogleClaims, createGoogleTestRig } from "./google-jwks-helper";

await resetStoresForTests();

beforeEach(async () => {
  await resetStoresForTests();
  resetRateLimitsForTests();
  resetThrottleConnForTests();
  resetGoogleJwksCacheForTests();
});

afterAll(() => {
  restoreEnv();
});

const LOGIN_HREF = "https://web.alcore.io.vn/login";
const RESTART_HREF = "/auth/google/start";

function expectFriendlyHtml(html: string, code: string): void {
  expect(html).toContain(`data-auth-error="${code}"`);
  expect(html).toContain('id="auth-restart"');
  expect(html).toContain(`href="${RESTART_HREF}"`);
  expect(html).toContain(LOGIN_HREF);
  expect(html).toContain(`<code>${code}</code>`);
  expect(html).not.toContain('{"error"');
}

async function expectJsonByteIdentical(res: Response, code: string, status: number): Promise<void> {
  expect(res.status).toBe(status);
  const raw = await res.text();
  expect(raw).toBe(JSON.stringify({ error: code }));
  expect(res.headers.get("content-type") ?? "").toContain("application/json");
}

async function expectHtmlPage(res: Response, code: string, status: number): Promise<string> {
  expect(res.status).toBe(status);
  expect(res.headers.get("content-type") ?? "").toContain("text/html");
  const html = await res.text();
  expectFriendlyHtml(html, code);
  return html;
}

function mockFetch(handler: (input: RequestInfo | URL) => Promise<Response>): typeof globalThis.fetch {
  return Object.assign(handler, { preconnect: globalThis.fetch.preconnect });
}

function jsonRes(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("google fail UX: start", () => {
  test("start google_not_configured: JSON byte-identical, HTML friendly", async () => {
    applyEnv(false);
    const api = await app.request("/auth/google/start");
    await expectJsonByteIdentical(api, "google_not_configured", 503);

    resetRateLimitsForTests();
    const page = await app.request("/auth/google/start", { headers: { accept: "text/html" } });
    await expectHtmlPage(page, "google_not_configured", 503);
  });

  test("start invalid_request (bad handoff): JSON byte-identical, HTML friendly", async () => {
    applyEnv(true);
    const bad = `/auth/google/start?${new URLSearchParams({
      audience: "libre",
      redirect_uri: "https://evil.example.com/auth/callback",
      state: "st-evil",
    }).toString()}`;
    const api = await app.request(bad);
    await expectJsonByteIdentical(api, "invalid_request", 400);

    resetRateLimitsForTests();
    const page = await app.request(bad, { headers: { accept: "text/html" } });
    await expectHtmlPage(page, "invalid_request", 400);
  });

  test("start with no params still 302s when configured (success, not a fail path)", async () => {
    applyEnv(true);
    const res = await app.request("/auth/google/start", { redirect: "manual" });
    expect(res.status).toBe(302);
    expect((res.headers.get("location") ?? "").startsWith("https://accounts.google.com/")).toBe(true);
  });
});

describe("google fail UX: callback provider + state", () => {
  test("callback ?error=access_denied: JSON byte-identical, HTML friendly", async () => {
    applyEnv(true);
    const target = "/auth/google/callback?error=access_denied&state=x";
    const api = await app.request(target);
    await expectJsonByteIdentical(api, "google_oauth_error", 400);

    resetRateLimitsForTests();
    const page = await app.request(target, { headers: { accept: "text/html" } });
    await expectHtmlPage(page, "google_oauth_error", 400);
  });

  test("callback no params: JSON byte-identical, HTML friendly (headline: no raw JSON in tab)", async () => {
    applyEnv(true);
    const api = await app.request("/auth/google/callback");
    await expectJsonByteIdentical(api, "invalid_google_state", 400);

    resetRateLimitsForTests();
    const page = await app.request("/auth/google/callback", { headers: { accept: "text/html" } });
    await expectHtmlPage(page, "invalid_google_state", 400);
  });

  test("callback state without code + cookie mismatch: JSON + HTML", async () => {
    applyEnv(true);
    const apiNoCode = await app.request("/auth/google/callback?state=only-state");
    await expectJsonByteIdentical(apiNoCode, "invalid_google_state", 400);

    resetRateLimitsForTests();
    const pageMismatch = await app.request("/auth/google/callback?state=a&code=b", {
      headers: { accept: "text/html", cookie: "alcore_google_state=other" },
    });
    await expectHtmlPage(pageMismatch, "invalid_google_state", 400);
  });

  test("callback state replay stays single-use: replay JSON + replay HTML", async () => {
    applyEnv(false);
    const s1 = "ux-replay-json-state";
    await googleStateStore.issue(s1, "ux-replay-json-nonce", Math.floor(Date.now() / 1000) + 300);
    const t1 = `/auth/google/callback?${new URLSearchParams({ state: s1, code: "code-1" }).toString()}`;
    const first = await app.request(t1, { headers: { cookie: `alcore_google_state=${s1}` } });
    expect(first.status).toBe(503);
    expect(await first.json()).toEqual({ error: "google_not_configured" });

    resetRateLimitsForTests();
    const replayJson = await app.request(t1, { headers: { cookie: `alcore_google_state=${s1}` } });
    await expectJsonByteIdentical(replayJson, "invalid_google_state", 400);

    resetRateLimitsForTests();
    const s2 = "ux-replay-html-state";
    await googleStateStore.issue(s2, "ux-replay-html-nonce", Math.floor(Date.now() / 1000) + 300);
    const t2 = `/auth/google/callback?${new URLSearchParams({ state: s2, code: "code-2" }).toString()}`;
    const first2 = await app.request(t2, { headers: { cookie: `alcore_google_state=${s2}` } });
    expect(first2.status).toBe(503);

    resetRateLimitsForTests();
    const replayHtml = await app.request(t2, {
      headers: { cookie: `alcore_google_state=${s2}`, accept: "text/html" },
    });
    await expectHtmlPage(replayHtml, "invalid_google_state", 400);
  });
});

describe("google fail UX: callback config + upstream + credential", () => {
  test("callback google_not_configured (valid state): JSON + HTML", async () => {
    applyEnv(false);
    const state = "ux-unconfigured-state";
    await googleStateStore.issue(state, "ux-unconfigured-nonce", Math.floor(Date.now() / 1000) + 300);
    const target = `/auth/google/callback?${new URLSearchParams({ state, code: "code-x" }).toString()}`;
    const api = await app.request(target, { headers: { cookie: `alcore_google_state=${state}` } });
    await expectJsonByteIdentical(api, "google_not_configured", 503);

    resetRateLimitsForTests();
    const s2 = "ux-unconfigured-html";
    await googleStateStore.issue(s2, "ux-unconfigured-nonce-2", Math.floor(Date.now() / 1000) + 300);
    const t2 = `/auth/google/callback?${new URLSearchParams({ state: s2, code: "code-x" }).toString()}`;
    const page = await app.request(t2, {
      headers: { cookie: `alcore_google_state=${s2}`, accept: "text/html" },
    });
    await expectHtmlPage(page, "google_not_configured", 503);
  });

  test("callback upstream_unavailable (fetch throw): JSON + HTML", async () => {
    applyEnv(true);
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = mockFetch(async () => { throw new Error("network down"); });
      const s1 = "ux-upstream-json";
      await googleStateStore.issue(s1, "ux-upstream-n1", Math.floor(Date.now() / 1000) + 300);
      const t1 = `/auth/google/callback?${new URLSearchParams({ state: s1, code: "c1" }).toString()}`;
      const api = await app.request(t1, { headers: { cookie: `alcore_google_state=${s1}` } });
      await expectJsonByteIdentical(api, "upstream_unavailable", 503);

      resetRateLimitsForTests();
      resetGoogleJwksCacheForTests();
      const s2 = "ux-upstream-html";
      await googleStateStore.issue(s2, "ux-upstream-n2", Math.floor(Date.now() / 1000) + 300);
      const t2 = `/auth/google/callback?${new URLSearchParams({ state: s2, code: "c2" }).toString()}`;
      const page = await app.request(t2, {
        headers: { cookie: `alcore_google_state=${s2}`, accept: "text/html" },
      });
      await expectHtmlPage(page, "upstream_unavailable", 503);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("callback invalid_google_credential (token !ok): JSON + HTML", async () => {
    applyEnv(true);
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = mockFetch(async () => jsonRes(400, { error: "bad" }));
      const s1 = "ux-cred-json";
      await googleStateStore.issue(s1, "ux-cred-n1", Math.floor(Date.now() / 1000) + 300);
      const t1 = `/auth/google/callback?${new URLSearchParams({ state: s1, code: "c1" }).toString()}`;
      const api = await app.request(t1, { headers: { cookie: `alcore_google_state=${s1}` } });
      await expectJsonByteIdentical(api, "invalid_google_credential", 401);

      resetRateLimitsForTests();
      const s2 = "ux-cred-html";
      await googleStateStore.issue(s2, "ux-cred-n2", Math.floor(Date.now() / 1000) + 300);
      const t2 = `/auth/google/callback?${new URLSearchParams({ state: s2, code: "c2" }).toString()}`;
      const page = await app.request(t2, {
        headers: { cookie: `alcore_google_state=${s2}`, accept: "text/html" },
      });
      await expectHtmlPage(page, "invalid_google_credential", 401);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("callback invalid_google_credential (bad id_token body): JSON + HTML", async () => {
    applyEnv(true);
    const rig = createGoogleTestRig();
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = mockFetch(async (input) => {
        if (String(input).includes("/certs")) return jsonRes(200, rig.jwksBody);
        return jsonRes(200, { id_token: "not-a-jwt" });
      });
      const s1 = "ux-badtoken-json";
      await googleStateStore.issue(s1, "ux-badtoken-n1", Math.floor(Date.now() / 1000) + 300);
      const t1 = `/auth/google/callback?${new URLSearchParams({ state: s1, code: "c1" }).toString()}`;
      const api = await app.request(t1, { headers: { cookie: `alcore_google_state=${s1}` } });
      await expectJsonByteIdentical(api, "invalid_google_credential", 401);

      resetRateLimitsForTests();
      resetGoogleJwksCacheForTests();
      const s2 = "ux-badtoken-html";
      await googleStateStore.issue(s2, "ux-badtoken-n2", Math.floor(Date.now() / 1000) + 300);
      const t2 = `/auth/google/callback?${new URLSearchParams({ state: s2, code: "c2" }).toString()}`;
      const page = await app.request(t2, {
        headers: { cookie: `alcore_google_state=${s2}`, accept: "text/html" },
      });
      await expectHtmlPage(page, "invalid_google_credential", 401);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

describe("google fail UX: callback conflict + trailing handoff", () => {
  async function conflictFetch(nonce: string): Promise<typeof globalThis.fetch> {
    const rig = createGoogleTestRig();
    const token = rig.mintIdToken(baseGoogleClaims({ nonce, sub: "ux-conflict-sub", email: "ux-other@example.com" }));
    return mockFetch(async (input) => {
      if (String(input).includes("/certs")) return jsonRes(200, rig.jwksBody);
      return jsonRes(200, { id_token: token });
    });
  }

  test("callback identity_conflict: JSON + HTML", async () => {
    applyEnv(true);
    const owner = await userStore.create("ux-owner@example.com", null);
    await userStore.create("ux-other@example.com", null);
    await userStore.linkIdentity(owner.id, "google", "ux-conflict-sub");

    const originalFetch = globalThis.fetch;
    try {
      const s1 = "ux-conflict-json";
      const n1 = "ux-conflict-n1";
      await googleStateStore.issue(s1, n1, Math.floor(Date.now() / 1000) + 300);
      globalThis.fetch = await conflictFetch(n1);
      const t1 = `/auth/google/callback?${new URLSearchParams({ state: s1, code: "c1" }).toString()}`;
      const api = await app.request(t1, { headers: { cookie: `alcore_google_state=${s1}` } });
      await expectJsonByteIdentical(api, "identity_conflict", 409);

      resetRateLimitsForTests();
      resetGoogleJwksCacheForTests();
      const s2 = "ux-conflict-html";
      const n2 = "ux-conflict-n2";
      await googleStateStore.issue(s2, n2, Math.floor(Date.now() / 1000) + 300);
      globalThis.fetch = await conflictFetch(n2);
      const t2 = `/auth/google/callback?${new URLSearchParams({ state: s2, code: "c2" }).toString()}`;
      const page = await app.request(t2, {
        headers: { cookie: `alcore_google_state=${s2}`, accept: "text/html" },
      });
      await expectHtmlPage(page, "identity_conflict", 409);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("callback trailing invalid_request (bad return cookie): JSON + HTML", async () => {
    applyEnv(true);
    async function runOne(wantHtml: boolean): Promise<Response> {
      const rig = createGoogleTestRig();
      const state = `ux-trail-${wantHtml ? "html" : "json"}-${Math.random().toString(36).slice(2, 7)}`;
      const nonce = `ux-trail-n-${Math.random().toString(36).slice(2, 7)}`;
      await googleStateStore.issue(state, nonce, Math.floor(Date.now() / 1000) + 300);
      const token = rig.mintIdToken(baseGoogleClaims({ nonce, sub: `ux-trail-sub-${state}`, email: `${state}@example.com` }));
      const originalFetch = globalThis.fetch;
      globalThis.fetch = mockFetch(async (input) => {
        if (String(input).includes("/certs")) return jsonRes(200, rig.jwksBody);
        return jsonRes(200, { id_token: token });
      });
      try {
        const badReturn = encodeURIComponent(JSON.stringify({ audience: "bogus", redirect_uri: "https://evil.example.com", state: "x" }));
        const target = `/auth/google/callback?${new URLSearchParams({ state, code: "code-ok" }).toString()}`;
        return await app.request(target, {
          headers: {
            cookie: `alcore_google_state=${state}; alcore_google_return=${badReturn}`,
            ...(wantHtml ? { accept: "text/html" } : {}),
          },
        });
      } finally {
        globalThis.fetch = originalFetch;
      }
    }
    const api = await runOne(false);
    await expectJsonByteIdentical(api, "invalid_request", 400);

    resetRateLimitsForTests();
    resetGoogleJwksCacheForTests();
    const page = await runOne(true);
    await expectHtmlPage(page, "invalid_request", 400);
  });
});
