// ALcore Auth Repo C — todo 35 contract tests: production JWKS verification.
// Mocked rotating JWKS (throwaway RSA pair per rig) + authorization-code flow.
// Dummy values only; no real Google keys, tokens, secrets, or PII.

process.env["JWT_SECRET"] = "test-only-dummy-secret-0123456789abcdef";
process.env["ALLOW_WEAK_JWT_SECRET"] = "1";
process.env["NODE_ENV"] = "test";
process.env["GOOGLE_CLIENT_ID"] = "test-client.apps.googleusercontent.com";
process.env["GOOGLE_CLIENT_SECRET"] = "test-client-secret";

import { describe, test, expect, beforeEach } from "bun:test";
import { app } from "../src/index";
import { getGoogleRedirectUri } from "../src/config";
import { resetRateLimitsForTests, resetThrottleConnForTests } from "../src/lib/ratelimit";
import { googleStateStore, resetStoresForTests, userStore } from "../src/lib/store";
import { baseGoogleClaims, createGoogleTestRig, TEST_GOOGLE_CLIENT_ID } from "./google-jwks-helper";

await resetStoresForTests();

beforeEach(() => {
  resetRateLimitsForTests();
  resetThrottleConnForTests();
});

async function post(path: string, body: unknown, headers: Record<string, string> = {}): Promise<Response> {
  return app.request(path, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

function uniqueEmail(tag: string): string {
  return `t35-${tag}-${Math.random().toString(36).slice(2, 10)}@example.com`;
}

function uniqueSub(tag: string): string {
  return `t35-${tag}-${Math.random().toString(36).slice(2, 10)}`;
}

describe("todo35: JWKS happy path resolves one identity", () => {
  test("mocked rotating JWKS + valid code returns one Auth user", async () => {
    const rig = createGoogleTestRig();
    const email = uniqueEmail("happy");
    const sub = uniqueSub("happy");
    const token = rig.mintIdToken(baseGoogleClaims({ email, sub }));
    const { restore } = rig.installFetch(token);
    try {
      const res = await post("/auth/google/verify", { idToken: token });
      expect(res.status).toBe(200);
      const body = (await res.json()) as { access_token: string };
      expect(typeof body.access_token).toBe("string");
      const user = await userStore.findByEmail(email);
      expect(user?.emailVerified).toBe(true);
      expect((await userStore.findByProviderSub("google", sub))?.id).toBe(user?.id);
    } finally {
      restore();
    }
  });

  test("same subject re-login returns the same user id (no dupe)", async () => {
    const rig = createGoogleTestRig();
    const sub = uniqueSub("relogin");
    const first = rig.mintIdToken(baseGoogleClaims({ email: uniqueEmail("relogin-a"), sub }));
    const second = rig.mintIdToken(baseGoogleClaims({ email: uniqueEmail("relogin-b"), sub }));
    const { restore } = rig.installFetch(first);
    try {
      const r1 = await post("/auth/google/verify", { idToken: first });
      expect(r1.status).toBe(200);
      const id1 = (await userStore.findByProviderSub("google", sub))?.id ?? "";
      const secondRig = rig.installFetch(second);
      const r2 = await post("/auth/google/verify", { idToken: second });
      secondRig.restore();
      expect(r2.status).toBe(200);
      expect((await userStore.findByProviderSub("google", sub))?.id).toBe(id1);
    } finally {
      restore();
    }
  });

  test("valid Google callback (authorization-code flow) mints a session with nonce binding", async () => {
    const rig = createGoogleTestRig();
    const nonce = `nonce-${crypto.randomUUID()}`;
    const email = uniqueEmail("cb");
    const token = rig.mintIdToken(baseGoogleClaims({ email, nonce, sub: uniqueSub("cb") }));
    const { restore } = rig.installFetch(token);
    try {
      const state = `st-${crypto.randomUUID()}`;
      await googleStateStore.issue(state, nonce, Math.floor(Date.now() / 1000) + 300);
      const res = await app.request(
        `/auth/google/callback?state=${encodeURIComponent(state)}&code=test-code`,
        { headers: { cookie: `alcore_google_state=${state}` } },
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as { user: { id: string; emailVerified: boolean } };
      expect(body.user.emailVerified).toBe(true);
      expect(body.user.id).toBe((await userStore.findByEmail(email))?.id ?? "");
    } finally {
      restore();
    }
  });

  test("callback sends the exact configured redirect_uri to the token endpoint", async () => {
    const rig = createGoogleTestRig();
    const nonce = `nonce-${crypto.randomUUID()}`;
    const token = rig.mintIdToken(baseGoogleClaims({ email: uniqueEmail("redir"), nonce, sub: uniqueSub("redir") }));
    const originalFetch = globalThis.fetch;
    let seenRedirectUri = "";
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/certs")) {
        return new Response(JSON.stringify(rig.jwksBody), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      const body = String(init?.body ?? "");
      seenRedirectUri = new URLSearchParams(body).get("redirect_uri") ?? "";
      return new Response(JSON.stringify({ id_token: token }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof globalThis.fetch;
    try {
      const state = `st-${crypto.randomUUID()}`;
      await googleStateStore.issue(state, nonce, Math.floor(Date.now() / 1000) + 300);
      const res = await app.request(
        `/auth/google/callback?state=${encodeURIComponent(state)}&code=test-code`,
        { headers: { cookie: `alcore_google_state=${state}` } },
      );
      expect(res.status).toBe(200);
      expect(seenRedirectUri).toBe(getGoogleRedirectUri());
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

describe("todo35: conflicts are auditable 409s, never silent merges", () => {
  test("different-email same-sub conflict returns 409 identity_conflict", async () => {
    const rig = createGoogleTestRig();
    const owner = await userStore.create(uniqueEmail("owner"), null);
    await userStore.linkIdentity(owner.id, "google", "conflict-sub-35");
    const otherEmail = uniqueEmail("other");
    await userStore.create(otherEmail, null);
    const token = rig.mintIdToken(baseGoogleClaims({ sub: "conflict-sub-35", email: otherEmail }));
    const { restore } = rig.installFetch(token);
    try {
      const res = await post("/auth/google/verify", { idToken: token });
      expect(res.status).toBe(409);
      expect(await res.json()).toEqual({ error: "identity_conflict" });
      // Neither row was merged: owner keeps the subject, other keeps no link.
      expect((await userStore.findByProviderSub("google", "conflict-sub-35"))?.id).toBe(owner.id);
    } finally {
      restore();
    }
  });
});

describe("todo35: adversarial negatives fail closed with generic errors", () => {
  test("unknown kid forces a JWKS refresh then rejects with generic invalid_credentials", async () => {
    const rig = createGoogleTestRig();
    // Signed by the rig key but advertising an unknown kid: signature checks
    // against nothing, so the verifier must refresh and then fail closed.
    const token = rig.mintIdToken(baseGoogleClaims({ email: uniqueEmail("kid") }), { kid: "unknown-kid-zzz" });
    const { restore, jwksHits } = rig.installFetch(token);
    try {
      const res = await post("/auth/google/verify", { idToken: token });
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ error: "invalid_credentials" });
      expect(jwksHits()).toBeGreaterThanOrEqual(2);
    } finally {
      restore();
    }
  });

  test("wrong issuer is rejected generically", async () => {
    const rig = createGoogleTestRig();
    const token = rig.mintIdToken(baseGoogleClaims({ iss: "https://evil.example.com", email: uniqueEmail("iss") }));
    const { restore } = rig.installFetch(token);
    try {
      const res = await post("/auth/google/verify", { idToken: token });
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ error: "invalid_credentials" });
    } finally {
      restore();
    }
  });

  test("wrong audience is rejected generically", async () => {
    const rig = createGoogleTestRig();
    const token = rig.mintIdToken(baseGoogleClaims({ aud: "other-client.apps.googleusercontent.com", email: uniqueEmail("aud") }));
    const { restore } = rig.installFetch(token);
    try {
      const res = await post("/auth/google/verify", { idToken: token });
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ error: "invalid_credentials" });
    } finally {
      restore();
    }
  });

  test("expired token is rejected generically", async () => {
    const rig = createGoogleTestRig();
    const token = rig.mintIdToken(
      baseGoogleClaims({ exp: Math.floor(Date.now() / 1000) - 60, email: uniqueEmail("exp") }),
    );
    const { restore } = rig.installFetch(token);
    try {
      const res = await post("/auth/google/verify", { idToken: token });
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ error: "invalid_credentials" });
    } finally {
      restore();
    }
  });

  test("far-future iat is rejected generically", async () => {
    const rig = createGoogleTestRig();
    const token = rig.mintIdToken(
      baseGoogleClaims({ iat: Math.floor(Date.now() / 1000) + 3600, email: uniqueEmail("iat") }),
    );
    const { restore } = rig.installFetch(token);
    try {
      const res = await post("/auth/google/verify", { idToken: token });
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ error: "invalid_credentials" });
    } finally {
      restore();
    }
  });

  test("tampered signature is rejected generically", async () => {
    const rig = createGoogleTestRig();
    const good = rig.mintIdToken(baseGoogleClaims({ email: uniqueEmail("sig") }));
    // Tamper the FIRST char of the signature segment: all six of its bits are
    // signature data, so any flip changes the decoded bytes deterministically.
    // (Flipping the LAST char is a ~25% no-op: a 256-byte RSA signature is 342
    // base64url chars, and swaps within A-P leave the final byte identical, so
    // the "tampered" token still verifies and the test flakes 200 vs 401.)
    const segs = good.split(".");
    const sig = segs[2] ?? "";
    const tampered = `${segs[0]}.${segs[1]}.${sig[0] === "A" ? "B" : "A"}${sig.slice(1)}`;
    const { restore } = rig.installFetch(tampered);
    try {
      const res = await post("/auth/google/verify", { idToken: tampered });
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ error: "invalid_credentials" });
    } finally {
      restore();
    }
  });

  test("alg=none is rejected without a JWKS call", async () => {
    const rig = createGoogleTestRig();
    const token = rig.mintIdToken(baseGoogleClaims({ email: uniqueEmail("none") }), { alg: "none" });
    const { restore, jwksHits } = rig.installFetch(token);
    try {
      const res = await post("/auth/google/verify", { idToken: token });
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ error: "invalid_credentials" });
      expect(jwksHits()).toBe(0);
    } finally {
      restore();
    }
  });

  test("missing kid is rejected without a JWKS call", async () => {
    const rig = createGoogleTestRig();
    const claims = baseGoogleClaims({ email: uniqueEmail("nokid") });
    const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" }), "utf8").toString("base64url");
    const payload = Buffer.from(JSON.stringify(claims), "utf8").toString("base64url");
    const { restore, jwksHits } = rig.installFetch(`${header}.${payload}.bogus`);
    try {
      const res = await post("/auth/google/verify", { idToken: `${header}.${payload}.bogus` });
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ error: "invalid_credentials" });
      expect(jwksHits()).toBe(0);
    } finally {
      restore();
    }
  });

  test("unverified email is rejected generically", async () => {
    const rig = createGoogleTestRig();
    const token = rig.mintIdToken(baseGoogleClaims({ email_verified: false, email: uniqueEmail("unv") }));
    const { restore } = rig.installFetch(token);
    try {
      const res = await post("/auth/google/verify", { idToken: token });
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ error: "invalid_credentials" });
    } finally {
      restore();
    }
  });

  test("nonce mismatch on the callback is rejected as invalid_google_credential", async () => {
    const rig = createGoogleTestRig();
    const token = rig.mintIdToken(baseGoogleClaims({ email: uniqueEmail("nonce"), nonce: "wrong-nonce" }));
    const { restore } = rig.installFetch(token);
    try {
      const state = `st-${crypto.randomUUID()}`;
      const nonce = `nonce-${crypto.randomUUID()}`;
      await googleStateStore.issue(state, nonce, Math.floor(Date.now() / 1000) + 300);
      const res = await app.request(
        `/auth/google/callback?state=${encodeURIComponent(state)}&code=test-code`,
        { headers: { cookie: `alcore_google_state=${state}` } },
      );
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ error: "invalid_google_credential" });
    } finally {
      restore();
    }
  });

  test("replayed state is rejected and the transaction stays single-use", async () => {
    const rig = createGoogleTestRig();
    const nonce = `nonce-${crypto.randomUUID()}`;
    const token = rig.mintIdToken(baseGoogleClaims({ email: uniqueEmail("replay"), nonce, sub: uniqueSub("replay") }));
    const { restore } = rig.installFetch(token);
    try {
      const state = `st-${crypto.randomUUID()}`;
      await googleStateStore.issue(state, nonce, Math.floor(Date.now() / 1000) + 300);
      const url = `/auth/google/callback?state=${encodeURIComponent(state)}&code=test-code`;
      const first = await app.request(url, { headers: { cookie: `alcore_google_state=${state}` } });
      expect(first.status).toBe(200);
      const second = await app.request(url, { headers: { cookie: `alcore_google_state=${state}` } });
      expect(second.status).toBe(400);
      expect(await second.json()).toEqual({ error: "invalid_google_state" });
    } finally {
      restore();
    }
  });

  test("unregistered OIDC callback fails closed without redirecting", async () => {
    process.env["AUTH_OIDC_CLIENTS"] = `test-client=http://localhost:3000/callback`;
    const email = uniqueEmail("cbx");
    await post("/auth/register", { email, password: "s3cret-pass" });
    const login = (await (await post("/auth/login", { email, password: "s3cret-pass" })).json()) as {
      access_token: string;
    };
    const evil = await app.request(
      `/oidc/authorize?response_type=code&client_id=test-client&redirect_uri=${encodeURIComponent("http://localhost:3000/callback/evil")}`,
      { headers: { authorization: `Bearer ${login.access_token}` } },
    );
    expect(evil.status).toBe(400);
    expect(await evil.json()).toEqual({ error: "invalid_redirect_uri" });
    expect(evil.headers.get("location")).toBeNull();
  });

  test("JWKS outage maps to 502 upstream_unavailable, never a bypass", async () => {
    const rig = createGoogleTestRig();
    const token = rig.mintIdToken(baseGoogleClaims({ email: uniqueEmail("outage"), sub: uniqueSub("outage") }));
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      if (String(input).includes("/certs")) {
        return new Response("down", { status: 503 });
      }
      return new Response(JSON.stringify({}), { status: 404 });
    }) as typeof globalThis.fetch;
    try {
      const res = await post("/auth/google/verify", { idToken: token });
      expect(res.status).toBe(502);
      expect(await res.json()).toEqual({ error: "upstream_unavailable" });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("client id constant matches the configured test audience", () => {
    expect(process.env["GOOGLE_CLIENT_ID"]).toBe(TEST_GOOGLE_CLIENT_ID);
  });
});
