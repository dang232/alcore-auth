// Pull-lazy provision contract pins (unified-auth-core todo 10).
// Auth is who-only: register/exchange mint identity + Auth proof, products
// pull. This file pins the Auth side — proof shapes, fail-closed rejects,
// and the no-push-source guarantee — without touching product code.

process.env["JWT_SECRET"] = "test-only-dummy-secret-0123456789abcdef";
process.env["ALLOW_WEAK_JWT_SECRET"] = "1";
process.env["NODE_ENV"] = "test";

import { describe, test, expect, beforeEach } from "bun:test";
import { app } from "../src/index";
import { resetRateLimitsForTests, resetThrottleConnForTests } from "../src/lib/ratelimit";
import { resetStoresForTests, userStore, sessionStore, productExchangeStore } from "../src/lib/store";
import { getIssuer, getJwtRotationKeys, getJwtSecret } from "../src/config";
import { hashToken, randomToken, signAccess, verifyAccess } from "../src/lib/crypto";
import { buildProvisionKey } from "../src/lib/provision-hook";

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

/** Direct store session (zero HTTP): the shared rate bucket is suite-wide,
 *  so only the calls under test go through HTTP. Mirrors
 *  exchange-redirect.test.ts sessionFor. */
async function sessionFor(email: string): Promise<{ id: string; sessionId: string; accessToken: string }> {
  const user = await userStore.create(email, "argon2id-test-hash");
  const session = await sessionStore.create(user.id, hashToken(randomToken(32)), 3_600_000);
  const accessToken = signAccess(
    { sub: user.id, sid: session.id, iss: getIssuer(), aud: "auth", intent: "session" },
    getJwtSecret(),
    3600,
  );
  return { id: user.id, sessionId: session.id, accessToken };
}

describe("pull contract: register mints identity-only proof", () => {
  test("201 carries id + session pair and zero product/business fields", async () => {
    const res = await post("/auth/register", { email: "pull-reg@example.com", password: "s3cret-pass" });
    expect(res.status).toBe(201);
    const body = (await res.json()) as Record<string, unknown>;
    expect(typeof body["id"]).toBe("string");
    expect(body["email"]).toBe("pull-reg@example.com");
    expect(typeof body["access_token"]).toBe("string");
    for (const banned of ["customerId", "customer", "package", "balance", "entitlement", "subscription"]) {
      expect(body[banned]).toBeUndefined();
    }
    const me = await app.request("/auth/me", {
      headers: { authorization: `Bearer ${String(body["access_token"])}` },
    });
    expect(me.status).toBe(200);
    const view = (await me.json()) as { id: string; email: string; emailVerified: boolean };
    expect(view.id).toBe(String(body["id"]));
    expect(view.email).toBe("pull-reg@example.com");
  });
});

describe("pull contract: exchange code redeems to product-scoped proof", () => {
  test("code -> access_token with aud=product intent=product_exchange sub+email", async () => {
    const { id, accessToken } = await sessionFor("pull-ex@example.com");
    const ex = await post(
      "/oidc/exchange",
      { audience: "libre", intent: "product_exchange" },
      { authorization: `Bearer ${accessToken}` },
    );
    expect(ex.status).toBe(200);
    const { code, expires_in } = (await ex.json()) as { code: string; expires_in: number };
    expect(typeof code).toBe("string");
    expect(expires_in).toBe(60);
    const rd = await post("/oidc/exchange/token", {
      code,
      audience: "libre",
      intent: "product_exchange",
    });
    expect(rd.status).toBe(200);
    const token = (await rd.json()) as { access_token: string; token_type: string; expires_in: number };
    expect(token.token_type).toBe("Bearer");
    expect(token.expires_in).toBe(60);
    const payload = verifyAccess(token.access_token, getJwtRotationKeys(), getIssuer(), "libre", "product_exchange");
    expect(payload.sub).toBe(id);
    expect(payload.email).toBe("pull-ex@example.com");
  });
});

describe("pull contract: adversarial redeems fail closed", () => {
  test("tampered / swapped-audience / wrong-intent / replay -> identical invalid_grant", async () => {
    const { id, sessionId } = await sessionFor("pull-adv@example.com");
    const shapes: Array<Record<string, unknown>> = [];
    async function redeem(body: Record<string, unknown>): Promise<Response> {
      return post("/oidc/exchange/token", body);
    }
    // Tampered code.
    const c1 = await productExchangeStore.issue(id, sessionId, "libre", "product_exchange", 60);
    void c1;
    const t1 = await redeem({ code: `${c1.slice(0, -2)}xx`, audience: "libre", intent: "product_exchange" });
    expect(t1.status).toBe(400);
    shapes.push((await t1.json()) as Record<string, unknown>);
    // Swapped audience at redeem (minted libre, redeemed tokenpanel).
    const c2 = await productExchangeStore.issue(id, sessionId, "libre", "product_exchange", 60);
    const t2 = await redeem({ code: c2, audience: "tokenpanel", intent: "product_exchange" });
    expect(t2.status).toBe(400);
    shapes.push((await t2.json()) as Record<string, unknown>);
    // Wrong intent.
    const c3 = await productExchangeStore.issue(id, sessionId, "libre", "product_exchange", 60);
    const t3 = await redeem({ code: c3, audience: "libre", intent: "session" });
    expect(t3.status).toBe(400);
    shapes.push((await t3.json()) as Record<string, unknown>);
    // Replay: consume once (ok), consume again (reject).
    const c4 = await productExchangeStore.issue(id, sessionId, "libre", "product_exchange", 60);
    const ok = await redeem({ code: c4, audience: "libre", intent: "product_exchange" });
    expect(ok.status).toBe(200);
    const t4 = await redeem({ code: c4, audience: "libre", intent: "product_exchange" });
    expect(t4.status).toBe(400);
    shapes.push((await t4.json()) as Record<string, unknown>);
    for (const s of shapes) expect(s).toEqual({ error: "invalid_grant" });
  });

  test("unauthenticated exchange -> 401; google/callback without state -> 400", async () => {
    const noAuth = await post("/oidc/exchange", { audience: "libre", intent: "product_exchange" });
    expect(noAuth.status).toBe(401);
    const cb = await app.request("/auth/google/callback?state=nope&code=nope");
    expect(cb.status).toBe(400);
    expect((await cb.json()) as unknown).toEqual({ error: "invalid_google_state" });
  });
});

describe("pull contract: who-only source guarantees", () => {
  test("canonical provision key derivation is stable", () => {
    expect(buildProvisionKey("usr_abc")).toBe("customer-provision:usr_abc");
  });

  test("push-client config is gone from Auth config", async () => {
    const config = await import("../src/config");
    expect("getProvisionConfig" in config).toBe(false);
  });

  test("provision-hook (Auth's only provision module) performs zero fetch()", async () => {
    const src = await Bun.file(new URL("../src/lib/provision-hook.ts", import.meta.url)).text();
    expect(src).not.toMatch(/fetch\s*\(/);
    expect(src).not.toMatch(/TOKENPANEL_PROVISION_URL/);
  });
});
