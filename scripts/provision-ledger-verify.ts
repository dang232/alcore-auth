// Provisioning ledger verify probe (unified-auth-core todo 7).
// Usage: bun scripts/provision-ledger-verify.ts
// Exercises the ledger DDL on BOTH backends and prints full outputs:
//   1. SQLite :memory: via PROVISION_LEDGER_SQLITE_DDL (same string store.ts
//      applies to the file DB at import).
//   2. PGlite (real PG engine) via pg-schema-002-provisioning-ledger.sql
//      (same file pg-migrate.ts and tests/pg-setup.ts apply).
// Happy path: UNPROVISIONED default (row absence) -> PENDING insert ->
// PROVISIONED transition, plus FAILED/CONFLICT lifecycle walks.
// Adversarial: duplicate canonical key rejected, non-PENDING insert
// rejected, illegal transitions (PROVISIONED->anything, CONFLICT->
// PROVISIONED, FAILED->PROVISIONED direct) rejected.
// Exit non-zero on any failed assertion.
import { Database } from "bun:sqlite";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";
import { PROVISION_LEDGER_SQLITE_DDL } from "../src/lib/provision-ledger-schema";

let failures = 0;

function check(name: string, cond: boolean, detail: string): void {
  console.log(`${cond ? "PASS" : "FAIL"} ${name} :: ${detail}`);
  if (!cond) failures += 1;
}

interface Ledger {
  readonly label: string;
  countFor(authUserId: string, product: string): number;
  insert(key: string, authUserId: string, product: string, state: string, now: number): void;
  transition(key: string, state: string, now: number): void;
  getState(key: string): string | null;
}

function sqliteLedger(): Ledger {
  const db = new Database(":memory:");
  db.exec(PROVISION_LEDGER_SQLITE_DDL);
  const countStmt = db.query("SELECT COUNT(*) AS c FROM provisioning_ledger WHERE auth_user_id=? AND product=?");
  const getStmt = db.query("SELECT state FROM provisioning_ledger WHERE canonical_key=?");
  const insertStmt = db.query(
    "INSERT INTO provisioning_ledger (canonical_key,auth_user_id,product,state,created_at,updated_at) VALUES (?,?,?,?,?,?)",
  );
  const updateStmt = db.query("UPDATE provisioning_ledger SET state=?,updated_at=? WHERE canonical_key=?");
  type Row = Record<string, unknown>;
  return {
    label: "sqlite",
    countFor: (authUserId, product) => Number((countStmt.get(authUserId, product) as Row)["c"]),
    insert: (key, authUserId, product, state, now) => {
      insertStmt.run(key, authUserId, product, state, now, now);
    },
    transition: (key, state, now) => {
      const res = updateStmt.run(state, now, key);
      if (res.changes !== 1) throw new Error(`sqlite: transition ${key} -> ${state} touched ${res.changes} rows`);
    },
    getState: (key) => {
      const row = getStmt.get(key) as Row | null;
      return row === null ? null : String(row["state"]);
    },
  };
}

async function expectThrow(name: string, fn: () => void | Promise<void>, want: RegExp): Promise<void> {
  try {
    await fn();
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    check(name, want.test(msg), `rejected as required: ${msg.slice(0, 160)}`);
    return;
  }
  check(name, false, "STATEMENT SUCCEEDED BUT MUST HAVE BEEN REJECTED");
}

function runSyncSuite(ledger: Ledger): void {
  const { label } = ledger;
  const now = Date.now();
  const tpKey = "customer-provision:auth_user_tp1";
  const libreKey = "libre-provision:https://auth.alcore.io.vn|google-oauth2-123";

  // 1. UNPROVISIONED default: untouched product has no row.
  check(`${label}:unprovisioned-default`, ledger.countFor("auth_user_tp1", "tokenpanel") === 0,
    `SELECT COUNT(*)=${ledger.countFor("auth_user_tp1", "tokenpanel")} for untouched auth_user_id -> UNPROVISIONED`);
  check(`${label}:unprovisioned-libre`, ledger.getState(libreKey) === null,
    `SELECT state for untouched libre key -> NULL (UNPROVISIONED, never-contacted)`);

  // 2. Happy path: PENDING insert -> PROVISIONED transition.
  ledger.insert(tpKey, "auth_user_tp1", "tokenpanel", "PENDING", now);
  check(`${label}:insert-pending`, ledger.getState(tpKey) === "PENDING",
    `INSERT canonical_key=${tpKey} state=PENDING -> SELECT state=${ledger.getState(tpKey)}`);
  ledger.transition(tpKey, "PROVISIONED", now + 1);
  check(`${label}:pending-to-provisioned`, ledger.getState(tpKey) === "PROVISIONED",
    `UPDATE -> PROVISIONED, SELECT state=${ledger.getState(tpKey)}`);

  // 3. FAILED lifecycle: PENDING -> FAILED -> PENDING (retry) -> PROVISIONED.
  ledger.insert(libreKey, "google-oauth2-123", "libre", "PENDING", now);
  ledger.transition(libreKey, "FAILED", now + 1);
  check(`${label}:pending-to-failed`, ledger.getState(libreKey) === "FAILED",
    `second-product-down path: state=${ledger.getState(libreKey)}`);
  ledger.transition(libreKey, "PENDING", now + 2);
  ledger.transition(libreKey, "PROVISIONED", now + 3);
  check(`${label}:failed-retry-provisioned`, ledger.getState(libreKey) === "PROVISIONED",
    `retry same key converges: state=${ledger.getState(libreKey)}, count still 1 row per key`);

  // 4. CONFLICT lifecycle: PENDING -> CONFLICT -> PENDING (admin re-drive).
  const cKey = "customer-provision:auth_user_conf1";
  ledger.insert(cKey, "auth_user_conf1", "tokenpanel", "PENDING", now);
  ledger.transition(cKey, "CONFLICT", now + 1);
  check(`${label}:pending-to-conflict`, ledger.getState(cKey) === "CONFLICT",
    `email-collision path: state=${ledger.getState(cKey)}`);
  ledger.transition(cKey, "PENDING", now + 2);
  check(`${label}:conflict-to-pending`, ledger.getState(cKey) === "PENDING",
    `admin re-drive: state=${ledger.getState(cKey)}`);
}

async function runSyncAdversarial(ledger: Ledger): Promise<void> {
  const { label } = ledger;
  const now = Date.now();
  await expectThrow(`${label}:adversarial-duplicate-key`,
    () => ledger.insert("customer-provision:auth_user_tp1", "auth_user_tp1", "tokenpanel", "PENDING", now),
    /UNIQUE constraint failed|duplicate key/i);
  await expectThrow(`${label}:adversarial-direct-provisioned-insert`,
    () => ledger.insert("customer-provision:sneaky1", "sneaky1", "tokenpanel", "PROVISIONED", now),
    /must start at PENDING/i);
  await expectThrow(`${label}:adversarial-provisioned-to-pending`,
    () => ledger.transition("customer-provision:auth_user_tp1", "PENDING", now),
    /illegal state transition/i);
  await expectThrow(`${label}:adversarial-provisioned-to-failed`,
    () => ledger.transition("customer-provision:auth_user_tp1", "FAILED", now),
    /illegal state transition/i);
  const heldConflict = "customer-provision:auth_user_conf2";
  ledger.insert(heldConflict, "auth_user_conf2", "tokenpanel", "PENDING", now);
  ledger.transition(heldConflict, "CONFLICT", now + 1);
  await expectThrow(`${label}:adversarial-conflict-to-provisioned`,
    () => ledger.transition(heldConflict, "PROVISIONED", now + 2),
    /illegal state transition/i);
  const fKey = "customer-provision:auth_user_fail1";
  ledger.insert(fKey, "auth_user_fail1", "tokenpanel", "PENDING", now);
  ledger.transition(fKey, "FAILED", now + 1);
  await expectThrow(`${label}:adversarial-failed-to-provisioned-direct`,
    () => ledger.transition(fKey, "PROVISIONED", now + 2),
    /illegal state transition/i);
  await expectThrow(`${label}:adversarial-duplicate-user-product`,
    () => ledger.insert("customer-provision:auth_user_tp1X", "auth_user_tp1", "tokenpanel", "PENDING", now),
    /UNIQUE constraint failed|duplicate key/i);
}

// --- SQLite (synchronous) ---
console.log("--- backend: sqlite (:memory:) ---");
const lite = sqliteLedger();
runSyncSuite(lite);
await runSyncAdversarial(lite);

// --- PostgreSQL via PGlite (async, same assertions, same SQL file prod uses) ---
console.log("--- backend: postgres (PGlite, pg-schema-002 file) ---");
const pg = new PGlite();
await pg.exec(readFileSync(join(import.meta.dir, "..", "src", "lib", "pg-schema.sql"), "utf8"));
await pg.exec(readFileSync(join(import.meta.dir, "..", "src", "lib", "pg-schema-002-provisioning-ledger.sql"), "utf8"));
type PgRow = Record<string, unknown>;
const q = async (text: string, params: unknown[] = []): Promise<PgRow[]> =>
  ((await pg.query(text, params)).rows ?? []) as PgRow[];
{
  const now = Date.now();
  const countFor = async (authUserId: string, product: string): Promise<number> =>
    Number((await q("SELECT COUNT(*) AS c FROM provisioning_ledger WHERE auth_user_id=$1 AND product=$2",
      [authUserId, product]))[0]?.["c"] ?? -1);
  const getState = async (key: string): Promise<string | null> => {
    const rows = await q("SELECT state FROM provisioning_ledger WHERE canonical_key=$1", [key]);
    const row = rows[0];
    return row === undefined ? null : String(row["state"]);
  };
  const insert = async (key: string, authUserId: string, product: string, state: string, t: number): Promise<void> => {
    await q("INSERT INTO provisioning_ledger (canonical_key,auth_user_id,product,state,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6)",
      [key, authUserId, product, state, t, t]);
  };
  const transition = async (key: string, state: string, t: number): Promise<void> => {
    const rows = await q("UPDATE provisioning_ledger SET state=$1,updated_at=$2 WHERE canonical_key=$3 RETURNING canonical_key",
      [state, t, key]);
    if (rows.length !== 1) throw new Error(`pglite: transition ${key} -> ${state} touched ${rows.length} rows`);
  };
  const tpKey = "customer-provision:auth_user_tp1";
  const libreKey = "libre-provision:https://auth.alcore.io.vn|google-oauth2-123";
  check("postgres(pglite):unprovisioned-default", (await countFor("auth_user_tp1", "tokenpanel")) === 0,
    `SELECT COUNT(*)=${await countFor("auth_user_tp1", "tokenpanel")} for untouched auth_user_id -> UNPROVISIONED`);
  check("postgres(pglite):unprovisioned-libre", (await getState(libreKey)) === null,
    `SELECT state for untouched libre key -> NULL (UNPROVISIONED, never-contacted)`);
  await insert(tpKey, "auth_user_tp1", "tokenpanel", "PENDING", now);
  check("postgres(pglite):insert-pending", (await getState(tpKey)) === "PENDING",
    `INSERT canonical_key=${tpKey} state=PENDING -> SELECT state=${await getState(tpKey)}`);
  await transition(tpKey, "PROVISIONED", now + 1);
  check("postgres(pglite):pending-to-provisioned", (await getState(tpKey)) === "PROVISIONED",
    `UPDATE -> PROVISIONED, SELECT state=${await getState(tpKey)}`);
  await insert(libreKey, "google-oauth2-123", "libre", "PENDING", now);
  await transition(libreKey, "FAILED", now + 1);
  check("postgres(pglite):pending-to-failed", (await getState(libreKey)) === "FAILED",
    `second-product-down path: state=${await getState(libreKey)}`);
  await transition(libreKey, "PENDING", now + 2);
  await transition(libreKey, "PROVISIONED", now + 3);
  check("postgres(pglite):failed-retry-provisioned", (await getState(libreKey)) === "PROVISIONED",
    `retry same key converges: state=${await getState(libreKey)}`);
  const cKey = "customer-provision:auth_user_conf1";
  await insert(cKey, "auth_user_conf1", "tokenpanel", "PENDING", now);
  await transition(cKey, "CONFLICT", now + 1);
  check("postgres(pglite):pending-to-conflict", (await getState(cKey)) === "CONFLICT",
    `email-collision path: state=${await getState(cKey)}`);
  await transition(cKey, "PENDING", now + 2);
  check("postgres(pglite):conflict-to-pending", (await getState(cKey)) === "PENDING",
    `admin re-drive: state=${await getState(cKey)}`);
  await expectThrow("postgres(pglite):adversarial-duplicate-key",
    () => insert(tpKey, "auth_user_tp1", "tokenpanel", "PENDING", now),
    /duplicate key|UNIQUE constraint failed/i);
  await expectThrow("postgres(pglite):adversarial-direct-provisioned-insert",
    () => insert("customer-provision:sneaky1", "sneaky1", "tokenpanel", "PROVISIONED", now),
    /must start at PENDING/i);
  await expectThrow("postgres(pglite):adversarial-provisioned-to-pending",
    () => transition(tpKey, "PENDING", now),
    /illegal state transition/i);
  await expectThrow("postgres(pglite):adversarial-provisioned-to-failed",
    () => transition(tpKey, "FAILED", now),
    /illegal state transition/i);
  const heldConflict = "customer-provision:auth_user_conf2";
  await insert(heldConflict, "auth_user_conf2", "tokenpanel", "PENDING", now);
  await transition(heldConflict, "CONFLICT", now + 1);
  await expectThrow("postgres(pglite):adversarial-conflict-to-provisioned",
    () => transition(heldConflict, "PROVISIONED", now + 2),
    /illegal state transition/i);
  const fKey = "customer-provision:auth_user_fail1";
  await insert(fKey, "auth_user_fail1", "tokenpanel", "PENDING", now);
  await transition(fKey, "FAILED", now + 1);
  await expectThrow("postgres(pglite):adversarial-failed-to-provisioned-direct",
    () => transition(fKey, "PROVISIONED", now + 2),
    /illegal state transition/i);
  await expectThrow("postgres(pglite):adversarial-duplicate-user-product",
    () => insert("customer-provision:auth_user_tp1X", "auth_user_tp1", "tokenpanel", "PENDING", now),
    /duplicate key|UNIQUE constraint failed/i);
}

if (failures > 0) {
  console.error(`provision-ledger-verify: ${failures} FAILURE(S)`);
  process.exit(1);
}
console.log("provision-ledger-verify: all assertions passed on sqlite + postgres(pglite)");
