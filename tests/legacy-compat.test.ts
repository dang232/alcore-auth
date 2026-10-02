// ALcore Auth Repo C — task 43 legacy bcrypt-compat suite (Auth-only).
// Proves: correct bcrypt password logs in and yields exactly one canonical
// Argon2id hash (single write, no dual storage); wrong password fails with
// zero rehash; malformed/unsupported records fail closed with the reset path;
// products never store password hashes (source gate lives in the task-43
// proof script, not here). Assumes dummy secrets only (see auth.test.ts).

process.env["JWT_SECRET"] = "test-only-dummy-secret-0123456789abcdef";
process.env["ALLOW_WEAK_JWT_SECRET"] = "1";
process.env["NODE_ENV"] = "test";

import { describe, test, expect, beforeEach } from "bun:test";
import { app } from "../src/index";
import { getJwtSecret } from "../src/config";
import { mintPurposeToken } from "../src/lib/crypto";
import { classifyStoredHash, verifyPasswordCompat } from "../src/lib/legacy-password";
import { resetRateLimitsForTests, resetThrottleConnForTests } from "../src/lib/ratelimit";
import { resetStoresForTests, userStore } from "../src/lib/store";
import { clearAuditForTests, listAuditForTests } from "../src/lib/audit";

await resetStoresForTests();

beforeEach(() => {
  resetRateLimitsForTests();
  resetThrottleConnForTests();
  clearAuditForTests();
});

async function post(path: string, body: unknown, headers: Record<string, string> = {}): Promise<Response> {
  return app.request(path, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

/** Legacy-shaped fixture: real bcrypt `$2b$` hash (Libre bcryptjs format). */
async function legacyHash(plain: string): Promise<string> {
  return Bun.password.hash(plain, { algorithm: "bcrypt", cost: 4 });
}

async function seedLegacyUser(email: string, plain: string): Promise<string> {
  const id = crypto.randomUUID();
  await userStore.createWithId(id, email, await legacyHash(plain), true);
  return id;
}

describe("classifyStoredHash", () => {
  test("argon2id / legacy-bcrypt / reset-required partition is exact", async () => {
    expect(classifyStoredHash("$argon2id$v=19$m=65536,t=3,p=4$abc")).toBe("argon2id");
    expect(classifyStoredHash(await legacyHash("pw"))).toBe("legacy-bcrypt");
    expect(classifyStoredHash("$2a$12$" + "A".repeat(53))).toBe("legacy-bcrypt");
    expect(classifyStoredHash("$2y$12$" + "A".repeat(53))).toBe("legacy-bcrypt");
    expect(classifyStoredHash("not-a-hash")).toBe("reset-required");
    expect(classifyStoredHash("")).toBe("reset-required");
    expect(classifyStoredHash("$2b$12$short")).toBe("reset-required");
    expect(classifyStoredHash("$argon2i$v=19$m=4096,t=3,p=1$abc")).toBe("reset-required");
  });

  test("verifyPasswordCompat never throws and never grants on malformed input", async () => {
    expect(await verifyPasswordCompat("x", "not-a-hash")).toBe("reset-required");
    expect(await verifyPasswordCompat("x", "")).toBe("reset-required");
    const argon = await Bun.password.hash("correct-pw", { algorithm: "argon2id" });
    expect(await verifyPasswordCompat("correct-pw", argon)).toBe("argon2-ok");
    expect(await verifyPasswordCompat("wrong-pw", argon)).toBe("fail");
    const legacy = await legacyHash("legacy-pw-1");
    expect(await verifyPasswordCompat("legacy-pw-1", legacy)).toBe("legacy-ok");
    expect(await verifyPasswordCompat("wrong-pw", legacy)).toBe("fail");
  });
});

describe("legacy bcrypt login rehash (Auth-only, single write)", () => {
  test("correct bcrypt password logs in and yields exactly one Argon2id hash", async () => {
    const id = await seedLegacyUser("legacy1@example.com", "Legacy-Pw-1!");
    const before = (await userStore.findById(id))?.passwordHash ?? "";
    expect(before.startsWith("$2b$")).toBe(true);

    const res = await post("/auth/login", { email: "legacy1@example.com", password: "Legacy-Pw-1!" });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { access_token: string; user: { id: string } };
    expect(typeof body.access_token).toBe("string");
    expect(body.user.id).toBe(id);

    // Exactly one stored hash, now canonical Argon2id — the bcrypt value is
    // REPLACED, never kept alongside (no dual storage).
    const after = (await userStore.findById(id))?.passwordHash ?? "";
    expect(after.startsWith("$argon2id$")).toBe(true);
    expect(after).not.toBe(before);
    expect(listAuditForTests().some((r) => r.event === "auth.password_rehash" && r.outcome === "ok" && r.userId === id)).toBe(true);

    // The rehashed account logs in again through the canonical path.
    const again = await post("/auth/login", { email: "legacy1@example.com", password: "Legacy-Pw-1!" });
    expect(again.status).toBe(200);
    expect((await userStore.findById(id))?.passwordHash).toBe(after);
  });

  test("wrong password fails with zero rehash and identical 401 shape", async () => {
    const id = await seedLegacyUser("legacy2@example.com", "Legacy-Pw-2!");
    const before = (await userStore.findById(id))?.passwordHash ?? "";

    const bad = await post("/auth/login", { email: "legacy2@example.com", password: "Wrong-Pw-xyz" });
    expect(bad.status).toBe(401);
    const unknown = await post("/auth/login", { email: "nobody-here@example.com", password: "Wrong-Pw-xyz" });
    expect(unknown.status).toBe(401);
    expect(await bad.json()).toEqual(await unknown.json());

    expect((await userStore.findById(id))?.passwordHash).toBe(before);
    expect(listAuditForTests().some((r) => r.event === "auth.password_rehash")).toBe(false);
  });

  test("malformed hash fails closed: no access, no rehash, reset-required audit", async () => {
    const id = crypto.randomUUID();
    await userStore.createWithId(id, "broken@example.com", "not-a-bcrypt-hash", true);

    const res = await post("/auth/login", { email: "broken@example.com", password: "anything-at-all" });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid_credentials" });
    expect((await userStore.findById(id))?.passwordHash).toBe("not-a-bcrypt-hash");
    expect(listAuditForTests().some((r) => r.event === "auth.login_reset_required" && r.userId === id)).toBe(true);
  });

  test("reset-required account recovers through the password-reset flow only", async () => {
    const id = crypto.randomUUID();
    await userStore.createWithId(id, "resetme@example.com", "corrupted-record", true);

    const denied = await post("/auth/login", { email: "resetme@example.com", password: "whatever-123" });
    expect(denied.status).toBe(401);

    const token = mintPurposeToken(getJwtSecret(), "reset", id, 3600);
    const consume = await post("/auth/reset/consume", { token, newPassword: "Fresh-Pass-99" });
    expect(consume.status).toBe(200);

    const login = await post("/auth/login", { email: "resetme@example.com", password: "Fresh-Pass-99" });
    expect(login.status).toBe(200);
    expect(((await userStore.findById(id))?.passwordHash ?? "").startsWith("$argon2id$")).toBe(true);
  });

  test("password change accepts a legacy current password and canonicalizes", async () => {
    const id = await seedLegacyUser("legacy3@example.com", "Legacy-Pw-3!");
    const login = await post("/auth/login", { email: "legacy3@example.com", password: "Legacy-Pw-3!" });
    expect(login.status).toBe(200);
    // First login already rehashed; re-seed legacy shape to pin the change path.
    await userStore.setPasswordHash(id, await legacyHash("Legacy-Pw-3!"));
    const { access_token } = (await login.json()) as { access_token: string };

    const change = await post(
      "/auth/change",
      { currentPassword: "Legacy-Pw-3!", newPassword: "Brand-New-44!" },
      { authorization: `Bearer ${access_token}` },
    );
    expect(change.status).toBe(200);
    expect(((await userStore.findById(id))?.passwordHash ?? "").startsWith("$argon2id$")).toBe(true);
  });
});
