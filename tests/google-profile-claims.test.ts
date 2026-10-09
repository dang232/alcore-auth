// Google verified profile pass-through at login completion (task 32).
//
// Products own profiles: auth never stores name/picture (no tables, no
// columns). The signature-verified claims are handed to the completing
// client ONCE, in the Google login completion payload, so the product can
// provision its own profile. Present-when-verified, omitted-when-unverified
// (never forged): the `profile` key appears only for usable values taken
// from the already-received, signature-verified token.
//
// Covers all three auth.ts Google completion payloads: POST
// /auth/google/verify, POST /auth/google/desktop-code, and GET
// /auth/google/callback (JSON API caller). The browser callback card keeps
// zero profile values (session travels in HttpOnly cookies only). Dummy
// fixture tokens only via the shared JWKS rig; Google is never reached.

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
import { googleStateStore, resetStoresForTests, userStore } from "../src/lib/store";
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

const PROFILE_NAME = "Ada Lovelace";
const PROFILE_PICTURE = "https://lh3.googleusercontent.com/a/fixture-avatar-1";
const LOOPBACK = "http://127.0.0.1:57123/auth/desktop-google/callback";

async function post(path: string, body: unknown): Promise<Response> {
  return app.request(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

function installBoth(rig: ReturnType<typeof createGoogleTestRig>, idToken: string): { restore: () => void } {
  const originalFetch = globalThis.fetch;
  const mocked = Object.assign(
    (async (input: RequestInfo | URL) => {
      if (String(input).includes("/certs")) {
        return new Response(JSON.stringify(rig.jwksBody), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ id_token: idToken }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof globalThis.fetch,
    { preconnect: globalThis.fetch.preconnect },
  );
  globalThis.fetch = mocked;
  return { restore: () => { globalThis.fetch = originalFetch; } };
}

describe("google profile pass-through: POST /auth/google/verify", () => {
  test("verified name+picture are carried once in the completion payload", async () => {
    const rig = createGoogleTestRig();
    const email = `prof-verify-${crypto.randomUUID()}@example.com`;
    const token = rig.mintIdToken(
      baseGoogleClaims({ email, sub: `prof-verify-${crypto.randomUUID()}`, name: PROFILE_NAME, picture: PROFILE_PICTURE }),
    );
    const { restore } = rig.installFetch(token);
    try {
      const res = await post("/auth/google/verify", { idToken: token });
      expect(res.status).toBe(200);
      const body = (await res.json()) as Record<string, unknown>;
      expect(typeof body["access_token"]).toBe("string");
      expect(body["profile"]).toEqual({ name: PROFILE_NAME, picture: PROFILE_PICTURE });
    } finally {
      restore();
    }
  });

  test("profile key omitted when the verified token carries no profile claims", async () => {
    const rig = createGoogleTestRig();
    const token = rig.mintIdToken(baseGoogleClaims({}));
    const { restore } = rig.installFetch(token);
    try {
      const res = await post("/auth/google/verify", { idToken: token });
      expect(res.status).toBe(200);
      const body = (await res.json()) as Record<string, unknown>;
      expect("profile" in body).toBe(false);
      expect(Object.keys(body)).toEqual(["access_token"]);
    } finally {
      restore();
    }
  });

  test("malformed profile claims are omitted, never forged", async () => {
    const rig = createGoogleTestRig();
    const token = rig.mintIdToken(
      baseGoogleClaims({ name: 12345, picture: "http://insecure.example/avatar.png" }),
    );
    const { restore } = rig.installFetch(token);
    try {
      const res = await post("/auth/google/verify", { idToken: token });
      expect(res.status).toBe(200);
      const body = (await res.json()) as Record<string, unknown>;
      expect("profile" in body).toBe(false);
    } finally {
      restore();
    }
  });

  test("partial claims pass through partially (valid name, empty picture)", async () => {
    const rig = createGoogleTestRig();
    const token = rig.mintIdToken(baseGoogleClaims({ name: PROFILE_NAME, picture: "" }));
    const { restore } = rig.installFetch(token);
    try {
      const res = await post("/auth/google/verify", { idToken: token });
      expect(res.status).toBe(200);
      const body = (await res.json()) as Record<string, unknown>;
      expect(body["profile"]).toEqual({ name: PROFILE_NAME });
    } finally {
      restore();
    }
  });

  test("auth stores no profile state for a profile-carrying login", async () => {
    const rig = createGoogleTestRig();
    const email = `prof-stored-${crypto.randomUUID()}@example.com`;
    const sub = `prof-stored-${crypto.randomUUID()}`;
    const token = rig.mintIdToken(
      baseGoogleClaims({ email, sub, name: PROFILE_NAME, picture: PROFILE_PICTURE }),
    );
    const { restore } = rig.installFetch(token);
    try {
      const res = await post("/auth/google/verify", { idToken: token });
      expect(res.status).toBe(200);
      const user = await userStore.findByEmail(email);
      expect(user).not.toBeUndefined();
      expect("name" in (user as object)).toBe(false);
      expect("picture" in (user as object)).toBe(false);
      // Identity linkage itself is intact (WHO semantics untouched).
      expect((await userStore.findByProviderSub("google", sub))?.id).toBe(user?.id);
    } finally {
      restore();
    }
  });
});

describe("google profile pass-through: POST /auth/google/desktop-code", () => {
  test("verified name+picture are carried in the desktop exchange payload", async () => {
    const rig = createGoogleTestRig();
    const nonce = `prof-dt-${crypto.randomUUID()}`;
    const token = rig.mintIdToken(
      baseGoogleClaims({ nonce, name: PROFILE_NAME, picture: PROFILE_PICTURE }),
    );
    const ctl = installBoth(rig, token);
    try {
      const res = await post("/auth/google/desktop-code", {
        code: "profile-code-1",
        redirect_uri: LOOPBACK,
        nonce,
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as Record<string, unknown>;
      expect(typeof body["access_token"]).toBe("string");
      expect(body["profile"]).toEqual({ name: PROFILE_NAME, picture: PROFILE_PICTURE });
    } finally {
      ctl.restore();
    }
  });

  test("profile key omitted when the desktop token carries no profile claims", async () => {
    const rig = createGoogleTestRig();
    const token = rig.mintIdToken(baseGoogleClaims({}));
    const ctl = installBoth(rig, token);
    try {
      const res = await post("/auth/google/desktop-code", {
        code: "profile-code-2",
        redirect_uri: LOOPBACK,
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as Record<string, unknown>;
      expect("profile" in body).toBe(false);
      // Desktop login also mints the user-scoped IDE pair (task 38); the
      // profile key stays omitted while user_token is present.
      expect(Object.keys(body).sort()).toEqual(["access_token", "user_token"]);
    } finally {
      ctl.restore();
    }
  });
});

describe("google profile pass-through: GET /auth/google/callback", () => {
  test("API caller receives verified profile alongside the unchanged user view", async () => {
    const rig = createGoogleTestRig();
    const nonce = `prof-cb-${crypto.randomUUID()}`;
    const email = `prof-cb-${crypto.randomUUID()}@example.com`;
    const token = rig.mintIdToken(
      baseGoogleClaims({ nonce, email, name: PROFILE_NAME, picture: PROFILE_PICTURE }),
    );
    const state = `prof-cb-${crypto.randomUUID()}`;
    await googleStateStore.issue(state, nonce, Math.floor(Date.now() / 1000) + 300);
    const ctl = installBoth(rig, token);
    try {
      const res = await app.request(
        `/auth/google/callback?state=${encodeURIComponent(state)}&code=profile-code`,
        { headers: { cookie: `alcore_google_state=${state}` } },
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        user: { id: string; email: string; emailVerified: boolean };
        profile: { name: string; picture: string };
      };
      // WHO semantics untouched: the user view keeps exactly its fields.
      expect(Object.keys(body.user).sort()).toEqual(["email", "emailVerified", "id"]);
      expect(body.user.email).toBe(email);
      expect(body.user.emailVerified).toBe(true);
      expect(body.profile).toEqual({ name: PROFILE_NAME, picture: PROFILE_PICTURE });
    } finally {
      ctl.restore();
    }
  });

  test("API caller keeps the exact key shape when no profile claims were verified", async () => {
    const rig = createGoogleTestRig();
    const nonce = `prof-cb2-${crypto.randomUUID()}`;
    const token = rig.mintIdToken(baseGoogleClaims({ nonce }));
    const state = `prof-cb2-${crypto.randomUUID()}`;
    await googleStateStore.issue(state, nonce, Math.floor(Date.now() / 1000) + 300);
    const ctl = installBoth(rig, token);
    try {
      const res = await app.request(
        `/auth/google/callback?state=${encodeURIComponent(state)}&code=profile-code`,
        { headers: { cookie: `alcore_google_state=${state}` } },
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as Record<string, unknown>;
      expect("profile" in body).toBe(false);
      expect(Object.keys(body).sort()).toEqual(
        ["access_token", "expires_in", "refresh_token", "token_type", "user"],
      );
    } finally {
      ctl.restore();
    }
  });

  test("browser success card carries zero profile values (session in cookies only)", async () => {
    const rig = createGoogleTestRig();
    const nonce = `prof-cb3-${crypto.randomUUID()}`;
    const token = rig.mintIdToken(
      baseGoogleClaims({ nonce, name: PROFILE_NAME, picture: PROFILE_PICTURE }),
    );
    const state = `prof-cb3-${crypto.randomUUID()}`;
    await googleStateStore.issue(state, nonce, Math.floor(Date.now() / 1000) + 300);
    const ctl = installBoth(rig, token);
    try {
      const res = await app.request(
        `/auth/google/callback?state=${encodeURIComponent(state)}&code=profile-code`,
        {
          headers: {
            cookie: `alcore_google_state=${state}`,
            accept: "text/html",
          },
        },
      );
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html.includes(PROFILE_NAME)).toBe(false);
      expect(html.includes(PROFILE_PICTURE)).toBe(false);
    } finally {
      ctl.restore();
    }
  });
});
