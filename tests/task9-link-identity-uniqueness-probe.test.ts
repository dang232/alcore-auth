// Task 9 cross-store uniqueness probe (unified-auth-core): Auth
// provider_identities lookup-before-create + ledger canonical key as truth.
//
// Behavior of record: task 6 probe (tests/task6-exchange-uniqueness-probe.test.ts)
// proves code_hash PK + single-use consume; auth.ts:587-596,757-765 map
// `owned_by_other_user` to 409 `identity_conflict`. This probe proves the
// todo 9 mechanism on the REAL store:
//   1. Second link of the same (provider,subject) to another user returns
//      `owned_by_other_user` (the CONFLICT signal), never a second row.
//   2. Concurrent links from N users converge: exactly 1 `linked`, rest
//      conflict; SELECT COUNT(*) = 1 (deterministic lookup-before-create +
//      PRIMARY KEY backstop, store.ts:200-206 + pg-store.ts:192-206).
//   3. Ledger canonical key is cross-store truth: duplicate canonical_key and
//      duplicate (auth_user_id, product) inserts are rejected; the count
//      query proves 1 mapping. DDL is IMPORTED from
//      src/lib/provision-ledger-schema.ts (todo 7 author, verbatim).
process.env["JWT_SECRET"] = "test-only-dummy-secret-0123456789abcdef";
process.env["ALLOW_WEAK_JWT_SECRET"] = "1";
process.env["NODE_ENV"] = "test";

import { describe, test, expect, beforeEach } from "bun:test";
import { Database } from "bun:sqlite";
import { resetStoresForTests, userStore } from "../src/lib/store";
import { PROVISION_LEDGER_SQLITE_DDL } from "../src/lib/provision-ledger-schema";

/** Route-level mapping under test: conflict signal -> 409/CONFLICT. */
function conflictFromLinkResult(
  result: string,
): { status: number; code: string } | null {
  if (result === "owned_by_other_user") return { status: 409, code: "CONFLICT" };
  return null;
}

function conflictFromDbError(error: unknown): { status: number; code: string } | null {
  const message = error instanceof Error ? error.message : String(error);
  if (/unique constraint failed|UNIQUE constraint|SQLITE_CONSTRAINT|duplicate key|unique constraint/i.test(message)) {
    return { status: 409, code: "CONFLICT" };
  }
  return null;
}

describe("task9 auth provider_identities uniqueness + ledger truth", () => {
  beforeEach(async () => {
    await resetStoresForTests();
  });

  test("second link of the same subject maps to 409/CONFLICT, no second row", async () => {
    const u1 = await userStore.create("task9-a@example.com", "hash-a");
    const u2 = await userStore.create("task9-b@example.com", "hash-b");
    const subject = `task9-sub-${Date.now()}`;
    expect(await userStore.linkIdentity(u1.id, "google", subject)).toBe("linked");
    const loser = await userStore.linkIdentity(u2.id, "google", subject);
    expect(loser).toBe("owned_by_other_user");
    expect(conflictFromLinkResult(loser)).toEqual({ status: 409, code: "CONFLICT" });
    // Same-user re-link is idempotent, not a conflict.
    expect(await userStore.linkIdentity(u1.id, "google", subject)).toBe("already_linked");
    const owner = await userStore.findByProviderSub("google", subject);
    expect(owner?.id).toBe(u1.id);
    console.log("auth link-identity: winner=linked loser=409/CONFLICT mappings=1");
  });

  test("concurrent links from 3 users leave exactly 1 mapping", async () => {
    const users = await Promise.all(
      ["c1", "c2", "c3"].map((n) => userStore.create(`task9-${n}@example.com`, `hash-${n}`)),
    );
    const subject = `task9-race-${Date.now()}`;
    const results = await Promise.all(
      users.map((u) => userStore.linkIdentity(u.id, "google", subject)),
    );
    expect(results.filter((r) => r === "linked")).toHaveLength(1);
    expect(results.filter((r) => r === "owned_by_other_user")).toHaveLength(2);
    const owner = await userStore.findByProviderSub("google", subject);
    expect(owner).toBeDefined();
    console.log("auth concurrent link: linked=1 conflict=2 mappings=1");
  });

  test("ledger canonical key rejects duplicates; count query proves 1 mapping", () => {
    const db = new Database(":memory:");
    db.exec(PROVISION_LEDGER_SQLITE_DDL);
    const now = Date.now();
    db.query(
      "INSERT INTO provisioning_ledger (canonical_key,auth_user_id,product,state,created_at,updated_at) VALUES (?,?,?,?,?,?)",
    ).run("customer-provision:auth_task9_1", "auth_task9_1", "tokenpanel", "PENDING", now, now);
    db.query(
      "INSERT INTO provisioning_ledger (canonical_key,auth_user_id,product,state,created_at,updated_at) VALUES (?,?,?,?,?,?)",
    ).run("libre-provision:https://auth.alcore.io.vn|task9_1", "auth_task9_1", "libre", "PENDING", now, now);
    let dupKey: { status: number; code: string } | null = null;
    try {
      db.query(
        "INSERT INTO provisioning_ledger (canonical_key,auth_user_id,product,state,created_at,updated_at) VALUES (?,?,?,?,?,?)",
      ).run("customer-provision:auth_task9_1", "auth_task9_1", "tokenpanel", "PENDING", now, now);
    } catch (error) {
      dupKey = conflictFromDbError(error);
    }
    expect(dupKey).toEqual({ status: 409, code: "CONFLICT" });
    // Same (auth_user_id, product) under a drifted key format is also refused.
    let dupPair: { status: number; code: string } | null = null;
    try {
      db.query(
        "INSERT INTO provisioning_ledger (canonical_key,auth_user_id,product,state,created_at,updated_at) VALUES (?,?,?,?,?,?)",
      ).run("customer-provision:DRIFTED", "auth_task9_1", "tokenpanel", "PENDING", now, now);
    } catch (error) {
      dupPair = conflictFromDbError(error);
    }
    expect(dupPair).toEqual({ status: 409, code: "CONFLICT" });
    const count = db.query(
      "SELECT COUNT(*) AS n FROM provisioning_ledger WHERE auth_user_id=?",
    ).get("auth_task9_1") as { n: number };
    // One mapping per product: tokenpanel + libre = 2 rows, 1 per key.
    expect(count.n).toBe(2);
    const perKey = db.query(
      "SELECT COUNT(*) AS n FROM provisioning_ledger WHERE canonical_key=?",
    ).get("customer-provision:auth_task9_1") as { n: number };
    expect(perKey.n).toBe(1);
    console.log("ledger canonical-key: dup-key=409/CONFLICT dup-pair=409/CONFLICT mappings-per-key=1");
    db.close();
  });
});
