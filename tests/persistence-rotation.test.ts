// Task 36a — durable Auth persistence (persistence half ONLY).
// Rotation/revocation semantics land in the next run (task 36b); this file
// proves every identity table writes through SQLite and re-reads back, plus
// the identity-only boundary. bun test uses :memory: (NODE_ENV=test); the
// REAL kill-9 file-backed restart proof lives in .omo/research/task36/.
//
// Dummy secrets only. No resetStoresForTests() here: files may share one
// :memory: DB, so every row uses a task36a- unique key instead.
process.env["JWT_SECRET"] = "test-only-dummy-secret-0123456789abcdef";
process.env["ALLOW_WEAK_JWT_SECRET"] = "1";
process.env["NODE_ENV"] = "test";

import { describe, test, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { hashToken } from "../src/lib/crypto";
import {
  googleStateStore,
  oidcStore,
  productExchangeStore,
  sessionStore,
  userStore,
} from "../src/lib/store";

const TAG = "task36a";

describe("durable users", () => {
  test("create → findByEmail (case-insensitive) → findById round-trips through SQLite", async () => {
    const email = `${TAG}-user@example.com`;
    const created = await userStore.create(email, "hashed-placeholder");
    expect(typeof created.id).toBe("string");
    const byEmail = await userStore.findByEmail(email.toUpperCase());
    expect(byEmail?.id).toBe(created.id);
    expect((await userStore.findById(created.id))?.email).toBe(email);
  });

  test("duplicate create returns the existing row (no dupe identity)", async () => {
    const email = `${TAG}-dupe@example.com`;
    const first = await userStore.create(email, null);
    const second = await userStore.create(email.toUpperCase(), null);
    expect(second.id).toBe(first.id);
  });
});

describe("durable provider identities", () => {
  test("link → findByProviderSub; rival link is owned_by_other_user", async () => {
    const owner = await userStore.create(`${TAG}-owner@example.com`, null);
    const rival = await userStore.create(`${TAG}-rival@example.com`, null);
    expect(await userStore.linkIdentity(owner.id, "google", `${TAG}-sub-1`)).toBe("linked");
    expect((await userStore.findByProviderSub("google", `${TAG}-sub-1`))?.id).toBe(owner.id);
    expect(await userStore.linkIdentity(owner.id, "google", `${TAG}-sub-1`)).toBe("already_linked");
    expect(await userStore.linkIdentity(rival.id, "google", `${TAG}-sub-1`)).toBe("owned_by_other_user");
  });
});

describe("durable sessions", () => {
  test("create → findByRefreshHash; rotate persists new hash + prevHashes on fresh re-read", async () => {
    const user = await userStore.create(`${TAG}-sess@example.com`, null);
    const first = "rt-first";
    const session = await sessionStore.create(user.id, hashToken(first), 30 * 24 * 3600 * 1000);
    expect((await sessionStore.findByRefreshHash(hashToken(first)))?.id).toBe(session.id);
    await sessionStore.rotate(session, hashToken("rt-second"));
    const fresh = await sessionStore.findById(session.id);
    expect(fresh?.refreshHash).toBe(hashToken("rt-second"));
    expect(fresh !== undefined && sessionStore.isReusedHash(fresh, hashToken(first))).toBe(true);
    expect((await sessionStore.findByRefreshHash(hashToken("rt-second")))?.id).toBe(session.id);
  });

  test("revoke + revokeAllForUser persist on fresh re-read (user-scoped)", async () => {
    const user = await userStore.create(`${TAG}-revoke@example.com`, null);
    const other = await userStore.create(`${TAG}-revoke-other@example.com`, null);
    const s1 = await sessionStore.create(user.id, hashToken(`${TAG}-r1`), 3600_000);
    const s2 = await sessionStore.create(user.id, hashToken(`${TAG}-r2`), 3600_000);
    const s3 = await sessionStore.create(other.id, hashToken(`${TAG}-r3`), 3600_000);
    await sessionStore.revoke(s1);
    expect((await sessionStore.findById(s1.id))?.revoked).toBe(true);
    await sessionStore.revokeAllForUser(user.id);
    expect((await sessionStore.findById(s2.id))?.revoked).toBe(true);
    expect((await sessionStore.findById(s3.id))?.revoked).toBe(false);
  });
});

describe("durable codes", () => {
  test("oidc codes are single-use through the store", async () => {
    const user = await userStore.create(`${TAG}-oidc@example.com`, null);
    const issued = await oidcStore.issue(user.id, "https://web.alcore.io.vn/cb", "web", 60);
    expect((await oidcStore.consume(issued.code, "https://web.alcore.io.vn/cb", "web"))?.userId).toBe(user.id);
    expect(await oidcStore.consume(issued.code, "https://web.alcore.io.vn/cb", "web")).toBeNull();
  });

  test("product exchange codes are single-use; redirect-bound codes refuse the binding-free path", async () => {
    const user = await userStore.create(`${TAG}-exch@example.com`, null);
    const session = await sessionStore.create(user.id, hashToken(`${TAG}-exch-rt`), 3600_000);
    const plain = await productExchangeStore.issue(user.id, session.id, "tokenpanel", "product_exchange", 60);
    expect((await productExchangeStore.consume(plain, "tokenpanel", "product_exchange"))?.userId).toBe(user.id);
    expect(await productExchangeStore.consume(plain, "tokenpanel", "product_exchange")).toBeNull();
    const bound = await productExchangeStore.issueForRedirect(
      user.id, session.id, "libre", "product_exchange",
      "https://web.alcore.io.vn/cb", `${TAG}-state`, 60,
    );
    expect(await productExchangeStore.consume(bound, "libre", "product_exchange")).toBeNull();
    const got = await productExchangeStore.consumeForRedirect(
      bound, "libre", "product_exchange", "https://web.alcore.io.vn/cb", `${TAG}-state`,
    );
    expect(got?.userId).toBe(user.id);
    expect(await productExchangeStore.consumeForRedirect(
      bound, "libre", "product_exchange", "https://web.alcore.io.vn/cb", `${TAG}-state`,
    )).toBeNull();
  });
});

describe("durable browser transactions", () => {
  test("google oauth state is single-use through the store", async () => {
    await googleStateStore.issue(`${TAG}-state-1`, `${TAG}-nonce-1`, Math.floor(Date.now() / 1000) + 300);
    expect((await googleStateStore.consume(`${TAG}-state-1`))?.nonce).toBe(`${TAG}-nonce-1`);
    expect(await googleStateStore.consume(`${TAG}-state-1`)).toBeNull();
  });
});

describe("identity-only boundary", () => {
  test("store.ts owns no business tables or entities", () => {
    const src = readFileSync(new URL("../src/lib/store.ts", import.meta.url), "utf8");
    const tables = [...src.matchAll(/CREATE TABLE IF NOT EXISTS (\w+)/g)].map((m) => m[1]);
    expect(tables.sort()).toEqual(
      [
        "consumed_purpose_tokens",
        "google_states",
        "oidc_codes",
        "product_exchange_codes",
        "product_exchange_redirects",
        "provider_identities",
        "sessions",
        "users",
      ].sort(),
    );
    const stripped = src.replace(/\/\/.*/g, "");
    for (const token of [
      "customer", "billing", "balance", "usage", "subscription",
      "api_key", "entitlement", "topup", "recharge", "redeem", "budget",
    ]) {
      // Word-boundary: doc English like "redeemed" is not a business entity.
      expect(new RegExp(`\\b${token}\\b`, "i").test(stripped)).toBe(false);
    }
  });
});
