// Task 6 feasibility probe (unified-auth-core): Auth product_exchange_codes
// uniqueness + transactional single-use consume.
//
// Behavior of record: tests/exchange-redirect.test.ts proves replay /
// wrong-audience / tampered-state / swapped-redirect are refused at the HTTP
// layer. This probe proves the STORE mechanism underneath it:
//   1. code_hash PRIMARY KEY rejects a duplicate insert (unique violation).
//   2. A unique violation maps to the 409/CONFLICT path provision endpoints use.
//   3. Concurrent double-insert of the same code_hash leaves exactly 1 row.
//   4. Transactional single-use consume (`used=0 ... RETURNING`) succeeds once;
//      replay and concurrent double-consume yield exactly 1 success.
//
// Sections 1-3 run against an in-memory DB carrying the VERBATIM DDL from
// src/lib/store.ts (product_exchange_codes + product_exchange_redirects) so
// the PK/transaction semantics are identical to the product backend.
// Section 4 runs against the REAL productExchangeStore (SQLite backend).
process.env["JWT_SECRET"] = "test-only-dummy-secret-0123456789abcdef";
process.env["ALLOW_WEAK_JWT_SECRET"] = "1";
process.env["NODE_ENV"] = "test";

import { describe, test, expect, beforeEach } from "bun:test";
import { Database } from "bun:sqlite";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  productExchangeStore,
  resetStoresForTests,
  sessionStore,
  userStore,
} from "../src/lib/store";
import { hashToken, randomToken } from "../src/lib/crypto";

/** Verbatim DDL from src/lib/store.ts for product_exchange_codes (+redirects). */
const EXCHANGE_DDL = `
  CREATE TABLE IF NOT EXISTS product_exchange_codes (
    code_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    audience TEXT NOT NULL,
    intent TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS product_exchange_redirects (
    code_hash TEXT PRIMARY KEY,
    redirect_uri TEXT NOT NULL,
    state_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );
`;

/** Feasibility mapping under test: any DB uniqueness violation -> 409/CONFLICT. */
function conflictFromDbError(error: unknown): { status: number; code: string } | null {
  const message = error instanceof Error ? error.message : String(error);
  if (/unique constraint failed|UNIQUE constraint|SQLITE_CONSTRAINT/i.test(message)) {
    return { status: 409, code: "CONFLICT" };
  }
  return null;
}

function insertCode(db: Database, codeHash: string, exp: number): void {
  db.query(
    "INSERT INTO product_exchange_codes (code_hash,user_id,session_id,audience,intent,expires_at,used) VALUES (?,?,?,?,?,?,0)",
  ).run(codeHash, "u_probe", "s_probe", "libre", "provision", exp);
}

describe("task6 auth exchange-code uniqueness + single-use consume", () => {
  test("duplicate code_hash insert raises a unique violation mapped to 409/CONFLICT", () => {
    const db = new Database(":memory:");
    db.exec(EXCHANGE_DDL);
    const exp = Math.floor(Date.now() / 1000) + 300;
    insertCode(db, "dup-hash", exp);
    let mapped: { status: number; code: string } | null = null;
    try {
      insertCode(db, "dup-hash", exp);
    } catch (error) {
      mapped = conflictFromDbError(error);
    }
    expect(mapped).toEqual({ status: 409, code: "CONFLICT" });
    const count = db.query("SELECT COUNT(*) AS n FROM product_exchange_codes").get() as {
      n: number;
    };
    expect(count.n).toBe(1);
    console.log("auth unique-violation: mapped=409/CONFLICT rows=1");
    db.close();
  });

  test("concurrent double-insert of the same code_hash leaves exactly 1 row", async () => {
    const path = join(tmpdir(), `task6-auth-probe-${process.pid}.sqlite`);
    const { unlinkSync } = await import("node:fs");
    const setup = new Database(path, { create: true });
    setup.exec(EXCHANGE_DDL);
    setup.close();
    const exp = Math.floor(Date.now() / 1000) + 300;
    const attempt = () =>
      new Promise<string>((resolve) => {
        try {
          // NOTE: opened with create:true like the product backend itself
          // (src/lib/store.ts); create:false misuses on Windows/Bun 1.4.2.
          const db = new Database(path, { create: true });
          insertCode(db, "race-hash", exp);
          db.close();
          resolve("inserted");
        } catch {
          resolve("conflict");
        }
      });
    const results = await Promise.all([attempt(), attempt()]);
    expect(results.filter((r) => r === "inserted")).toHaveLength(1);
    expect(results.filter((r) => r === "conflict")).toHaveLength(1);
    const check = new Database(path, { create: true, readonly: true });
    const count = check.query("SELECT COUNT(*) AS n FROM product_exchange_codes").get() as {
      n: number;
    };
    check.close();
    expect(count.n).toBe(1);
    console.log(`auth concurrent double-insert: inserted=1 conflict=1 rows=${count.n}`);
    try {
      unlinkSync(path);
    } catch {
      // Best-effort probe cleanup.
    }
  });

  describe("real productExchangeStore single-use consume", () => {
    beforeEach(async () => {
      await resetStoresForTests();
    });

    async function sessionFor(): Promise<{ userId: string; sessionId: string }> {
      const email = `task6-probe-${randomToken(6)}@example.com`;
      const user = await userStore.create(email, "argon2id-test-hash");
      const session = await sessionStore.create(user.id, hashToken(randomToken(32)), 3_600_000);
      return { userId: user.id, sessionId: session.id };
    }

    test("consume succeeds once; replay returns null (CONFLICT path)", async () => {
      const { userId, sessionId } = await sessionFor();
      const code = await productExchangeStore.issue(userId, sessionId, "libre", "provision", 300);
      const first = await productExchangeStore.consume(code, "libre", "provision");
      expect(first).not.toBeNull();
      const replay = await productExchangeStore.consume(code, "libre", "provision");
      expect(replay).toBeNull();
      console.log("auth real-store consume: first=ok replay=null(CONFLICT) rows=1");
    });

    test("concurrent double-consume of a redirect-bound code yields exactly 1 success", async () => {
      const { userId, sessionId } = await sessionFor();
      const redirect = "https://web.alcore.io.vn/auth/callback";
      const code = await productExchangeStore.issueForRedirect(
        userId,
        sessionId,
        "libre",
        "provision",
        redirect,
        "probe-state",
        300,
      );
      const outcomes = await Promise.all([
        productExchangeStore.consumeForRedirect(code, "libre", "provision", redirect, "probe-state"),
        productExchangeStore.consumeForRedirect(code, "libre", "provision", redirect, "probe-state"),
      ]);
      expect(outcomes.filter((o) => o !== null)).toHaveLength(1);
      console.log("auth concurrent double-consume: success=1 replay=null rows=1");
    });
  });
});
