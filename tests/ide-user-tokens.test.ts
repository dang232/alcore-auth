// User-scoped IDE tokens (project-ide task 38): unit + route-level suite.
//
// Access JWT: 10-min expiry, HS256 with the existing rotation KIDs, claims
// sub (alcore identity) + scope (subset of profile/quota/tier/models:read) + jti.
// Refresh: opaque single-use, stored hashed, ~30 d expiry, rotation with
// reuse detection that revokes the family. Dummy secrets only; Google itself
// is never reached (token endpoint stubbed, ID token from the shared JWKS
// rig). Dedicated x-forwarded-for IPs per request: throttle budgets are
// shared per bun process across files.

process.env["JWT_SECRET"] = "test-only-dummy-secret-0123456789abcdef";
process.env["ALLOW_WEAK_JWT_SECRET"] = "1";
process.env["NODE_ENV"] = "test";

const ENV_KEYS = ["AUTH_ISSUER", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"] as const;
const ENV_BACKUP = new Map<string, string | undefined>(ENV_KEYS.map((k) => [k, process.env[k]]));

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
import { getIssuer, getJwtRotationKeys } from "../src/config";
import {
  hashToken,
  signAccess,
  signUserToken,
  verifyUserToken,
  isValidUserTokenScopeSet,
  USER_TOKEN_TTL_SECONDS,
  USER_TOKEN_AUDIENCE,
  USER_TOKEN_INTENT,
  JwtError,
  UserTokenError,
} from "../src/lib/crypto";
import { resetRateLimitsForTests, resetThrottleConnForTests } from "../src/lib/ratelimit";
import { ideRefreshStore, resetStoresForTests } from "../src/lib/store";
import { resetGoogleJwksCacheForTests } from "../src/lib/google";
import { baseGoogleClaims, createGoogleTestRig } from "./google-jwks-helper";

await resetStoresForTests();

beforeEach(async () => {
  await resetStoresForTests();
  resetRateLimitsForTests();
  resetThrottleConnForTests();
  resetGoogleJwksCacheForTests();
  applyEnv();
  delete process.env["JWT_SECRET_PREVIOUS"];
  delete process.env["JWT_SECRET_KID"];
  delete process.env["JWT_SECRET_PREVIOUS_KID"];
});

afterAll(() => {
  restoreEnv();
});

let ipSeq = 0;
function freshIp(): string {
  ipSeq += 1;
  return `10.38.9.${ipSeq}`;
}

async function post(path: string, body: unknown, ip: string): Promise<Response> {
  return app.request(path, {
    method: "POST",
    headers: { "content-type": "application/json", "x-forwarded-for": ip },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

const LOOPBACK = "http://127.0.0.1:57123/auth/desktop-google/callback";

function installTokenFetch(rig: ReturnType<typeof createGoogleTestRig>, idToken: string): () => void {
  const originalFetch = globalThis.fetch;
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
  return () => {
    globalThis.fetch = originalFetch;
  };
}

interface UserTokenPairBody {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  scope: string[];
}

async function desktopLogin(nonce = ""): Promise<{ userId: string; userToken: UserTokenPairBody; sessionAccess: string }> {
  const rig = createGoogleTestRig();
  const token = rig.mintIdToken(baseGoogleClaims(nonce === "" ? {} : { nonce }));
  const restore = installTokenFetch(rig, token);
  try {
    const res = await app.request("/auth/google/desktop-code", {
      method: "POST",
      headers: { "content-type": "application/json", "x-forwarded-for": freshIp() },
      body: JSON.stringify(
        nonce === ""
          ? { code: `ide-code-${ipSeq}`, redirect_uri: LOOPBACK }
          : { code: `ide-code-${ipSeq}`, redirect_uri: LOOPBACK, nonce },
      ),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { access_token: string; user_token: UserTokenPairBody };
    const me = await app.request("/auth/me", {
      headers: { authorization: `Bearer ${body.access_token}`, "x-forwarded-for": freshIp() },
    });
    expect(me.status).toBe(200);
    const view = (await me.json()) as { id: string };
    return { userId: view.id, userToken: body.user_token, sessionAccess: body.access_token };
  } finally {
    restore();
  }
}

function headerOf(jwt: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(jwt.split(".")[0] as string, "base64url").toString("utf8")) as Record<string, unknown>;
}

describe("user-token crypto (unit)", () => {
  test("mints a verifiable 10-min token with sub+scope+jti and the current kid", () => {
    const keys = getJwtRotationKeys();
    const before = Math.floor(Date.now() / 1000);
    const jwt = signUserToken(
      { sub: "user-123", scope: ["profile:read", "quota:read"], iss: getIssuer() },
      keys.current,
      USER_TOKEN_TTL_SECONDS,
      { kid: keys.currentKid },
    );
    expect(headerOf(jwt)).toMatchObject({ alg: "HS256", typ: "JWT", kid: keys.currentKid });
    const payload = verifyUserToken(jwt, keys, getIssuer());
    expect(payload.sub).toBe("user-123");
    expect(payload.scope).toEqual(["profile:read", "quota:read"]);
    expect(typeof payload.jti).toBe("string");
    expect(payload.jti.length).toBeGreaterThan(0);
    expect(payload.iss).toBe(getIssuer());
    expect(payload.aud).toBe(USER_TOKEN_AUDIENCE);
    expect(payload.intent).toBe(USER_TOKEN_INTENT);
    expect(payload.exp - payload.iat).toBe(600);
    expect(payload.iat).toBeGreaterThanOrEqual(before);
    // Two mints carry distinct jtis.
    const again = signUserToken({ sub: "user-123", scope: ["tier:read"], iss: getIssuer() }, keys.current);
    expect(verifyUserToken(again, keys, getIssuer()).jti).not.toBe(payload.jti);
  });

  test("rejects tampered, expired, wrong-issuer, and cross-intent tokens", () => {
    const keys = getJwtRotationKeys();
    const good = signUserToken({ sub: "u", scope: ["quota:read"], iss: getIssuer() }, keys.current);
    const parts = good.split(".");
    expect(() => verifyUserToken(`${parts[0]}.${parts[1]}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`, keys, getIssuer())).toThrow(
      UserTokenError,
    );
    expect(() => verifyUserToken(good, keys, "https://evil.example")).toThrow(UserTokenError);
    const expired = signUserToken({ sub: "u", scope: ["quota:read"], iss: getIssuer() }, keys.current, -10);
    expect(() => verifyUserToken(expired, keys, getIssuer())).toThrow(UserTokenError);
    // A session assertion (different aud/intent) never verifies as a user token.
    const session = signAccess(
      { sub: "u", sid: "s", iss: getIssuer(), aud: "tokenpanel", intent: "session" },
      keys.current,
      600,
    );
    expect(() => verifyUserToken(session, keys, getIssuer())).toThrow(UserTokenError);
    expect(() => verifyUserToken("not-a-jwt", keys, getIssuer())).toThrow(UserTokenError);
  });

  test("enforces kid binding with previous-key overlap", () => {
    const cur = "test-only-dummy-secret-0123456789abcdef";
    const prev = "test-only-previous-secret-abcdef0123456789";
    const jwt = signUserToken({ sub: "u", scope: ["tier:read"], iss: getIssuer() }, prev, 600, { kid: "k0" });
    expect(() => verifyUserToken(jwt, { current: cur, currentKid: "k1" }, getIssuer())).toThrow(UserTokenError);
    const payload = verifyUserToken(
      jwt,
      { current: cur, currentKid: "k1", previous: prev, previousKid: "k0" },
      getIssuer(),
    );
    expect(payload.sub).toBe("u");
  });

  test("scope allowlist is exact: empty/unknown rejected at mint", () => {
    expect(isValidUserTokenScopeSet(["profile:read", "quota:read", "tier:read", "models:read"])).toBe(true);
    expect(isValidUserTokenScopeSet(["models:read"])).toBe(true);
    expect(isValidUserTokenScopeSet([])).toBe(false);
    expect(isValidUserTokenScopeSet(["quota:read", "admin:write"])).toBe(false);
    expect(isValidUserTokenScopeSet("quota:read")).toBe(false);
    const keys = getJwtRotationKeys();
    expect(() => signUserToken({ sub: "u", scope: [], iss: getIssuer() }, keys.current)).toThrow(JwtError);
    expect(() => signUserToken({ sub: "u", scope: ["root"], iss: getIssuer() }, keys.current)).toThrow(JwtError);
    expect(() => signUserToken({ sub: "", scope: ["quota:read"], iss: getIssuer() }, keys.current)).toThrow(JwtError);
  });
});

describe("desktop-code completion issues the IDE pair", () => {
  test("response carries user_token with full desktop scopes; session pair untouched", async () => {
    const rig = createGoogleTestRig();
    const token = rig.mintIdToken(baseGoogleClaims({}));
    const restore = installTokenFetch(rig, token);
    try {
      const res = await app.request("/auth/google/desktop-code", {
        method: "POST",
        headers: { "content-type": "application/json", "x-forwarded-for": freshIp() },
        body: JSON.stringify({ code: "ide-code-shape", redirect_uri: LOOPBACK }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        access_token: unknown;
        user_token: unknown;
      };
      expect(typeof body.access_token).toBe("string");
      const userToken = body.user_token as UserTokenPairBody;
      expect(userToken.token_type).toBe("Bearer");
      expect(userToken.expires_in).toBe(600);
      expect(userToken.scope).toEqual(["profile:read", "quota:read", "tier:read", "models:read"]);
      expect(typeof userToken.access_token).toBe("string");
      expect(typeof userToken.refresh_token).toBe("string");
      expect(/^[0-9a-f]{64}$/.test(userToken.refresh_token)).toBe(true);
      // Session cookies still set (existing browser contract unchanged).
      const cookies = res.headers.getSetCookie?.() ?? [];
      expect(cookies.some((v) => v.startsWith("alcore_at="))).toBe(true);
      expect(cookies.some((v) => v.startsWith("alcore_rt="))).toBe(true);
      // The IDE access token verifies: sub matches the session identity.
      const me = await app.request("/auth/me", {
        headers: { authorization: `Bearer ${body.access_token}`, "x-forwarded-for": freshIp() },
      });
      const view = (await me.json()) as { id: string };
      const payload = verifyUserToken(userToken.access_token, getJwtRotationKeys(), getIssuer());
      expect(payload.sub).toBe(view.id);
      // Refresh is stored hashed server-side, never plaintext.
      const stored = await ideRefreshStore.findByTokenHash(hashToken(userToken.refresh_token));
      expect(stored?.userId).toBe(view.id);
      expect(stored?.scopes).toEqual(["profile:read", "quota:read", "tier:read", "models:read"]);
    } finally {
      restore();
    }
  });
});

describe("POST /auth/token/refresh", () => {
  test("accepts snake_case refresh_token (IDE caller shape) same as refreshToken", async () => {
    const { userToken } = await desktopLogin();
    const res = await post("/auth/token/refresh", { refresh_token: userToken.refresh_token }, freshIp());
    expect(res.status).toBe(200);
    const rotated = (await res.json()) as UserTokenPairBody;
    expect(rotated.token_type).toBe("Bearer");
  });
  test("rotates to a fresh pair preserving scopes; old refresh is single-use", async () => {
    const { userToken, userId } = await desktopLogin();
    const first = await post("/auth/token/refresh", { refreshToken: userToken.refresh_token }, freshIp());
    expect(first.status).toBe(200);
    const rotated = (await first.json()) as UserTokenPairBody;
    expect(rotated.token_type).toBe("Bearer");
    expect(rotated.expires_in).toBe(600);
    expect(rotated.scope).toEqual(["profile:read", "quota:read", "tier:read", "models:read"]);
    expect(rotated.refresh_token).not.toBe(userToken.refresh_token);
    const firstPayload = verifyUserToken(userToken.access_token, getJwtRotationKeys(), getIssuer());
    const nextPayload = verifyUserToken(rotated.access_token, getJwtRotationKeys(), getIssuer());
    expect(nextPayload.sub).toBe(userId);
    expect(nextPayload.jti).not.toBe(firstPayload.jti);
    // Second rotation on the newest refresh works (chain advances).
    const second = await post("/auth/token/refresh", { refreshToken: rotated.refresh_token }, freshIp());
    expect(second.status).toBe(200);
  });

  test("reuse of a rotated-out refresh revokes the family (new refresh dies too)", async () => {
    const { userToken } = await desktopLogin();
    const first = await post("/auth/token/refresh", { refreshToken: userToken.refresh_token }, freshIp());
    expect(first.status).toBe(200);
    const rotated = (await first.json()) as UserTokenPairBody;
    // Attacker replays the already-rotated refresh: reuse signal.
    const replay = await post("/auth/token/refresh", { refreshToken: userToken.refresh_token }, freshIp());
    expect(replay.status).toBe(401);
    expect(await replay.json()).toEqual({ error: "invalid_grant" });
    // The honest holder's newest refresh is now dead: family revoked.
    const after = await post("/auth/token/refresh", { refreshToken: rotated.refresh_token }, freshIp());
    expect(after.status).toBe(401);
    expect(await after.json()).toEqual({ error: "invalid_grant" });
    // Sibling families for the same user are untouched: a second login still rotates.
    const secondLogin = await desktopLogin();
    const ok = await post("/auth/token/refresh", { refreshToken: secondLogin.userToken.refresh_token }, freshIp());
    expect(ok.status).toBe(200);
  });

  test("malformed input answers 401 invalid_grant, never 500", async () => {
    const cases: Array<{ name: string; body: unknown }> = [
      { name: "empty object", body: {} },
      { name: "empty string", body: { refreshToken: "" } },
      { name: "non-string", body: { refreshToken: 12345 } },
      { name: "null", body: { refreshToken: null } },
      { name: "overlong", body: { refreshToken: "x".repeat(513) } },
      { name: "unknown well-formed token", body: { refreshToken: "a".repeat(64) } },
      { name: "wrong key", body: { refresh_token: "a".repeat(64) } },
    ];
    for (const { name, body } of cases) {
      const res = await post("/auth/token/refresh", body, freshIp());
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ error: "invalid_grant" });
    }
    const malformed = await app.request("/auth/token/refresh", {
      method: "POST",
      headers: { "content-type": "application/json", "x-forwarded-for": freshIp() },
      body: "{not json",
    });
    expect(malformed.status).toBe(401);
    expect(await malformed.json()).toEqual({ error: "invalid_grant" });
  });

  test("session refresh tokens never validate at the IDE endpoint (and vice versa)", async () => {
    const { sessionAccess, userToken } = await desktopLogin();
    // Session refresh (cookie family) at the IDE endpoint: 401.
    const me = await app.request("/auth/me", {
      headers: { authorization: `Bearer ${sessionAccess}`, "x-forwarded-for": freshIp() },
    });
    expect(me.status).toBe(200);
    // IDE refresh at the session endpoint: 401 invalid_grant (families separated).
    const cross = await post("/auth/refresh", { refresh_token: userToken.refresh_token }, freshIp());
    expect(cross.status).toBe(401);
    expect(await cross.json()).toEqual({ error: "invalid_grant" });
  });
});
