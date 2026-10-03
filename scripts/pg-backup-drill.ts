// F0 proof: backup/restore drill on a scratch backend (PGlite by default,
// or DATABASE_URL with --database-url). Seeds representative identity rows
// through the REAL repository interface, snapshots, wipes, restores, and
// asserts row-for-row parity. Exit non-zero on any mismatch.
// Logs counts + digest prefixes only; never secret values.
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createPgStores, pgliteConn, bunSqlConn, type PgConn, type PgRow } from "../src/lib/pg-store";
import { hashToken } from "../src/lib/crypto";
import {
  AUTH_TABLES,
  formatParity,
  parityReport,
  readTable,
  restoreFromFile,
  snapshotToFile,
  type AuthTable,
} from "./lib/pg-ops";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
}

let conn: PgConn;
let close: () => Promise<void>;
const explicitUrl = arg("--database-url") ?? (process.env["DATABASE_URL"] ?? "").trim();
if (explicitUrl !== "") {
  const live = bunSqlConn(explicitUrl);
  conn = live;
  close = () => live.close();
} else {
  const { PGlite } = await import("@electric-sql/pglite");
  const { readFileSync } = await import("node:fs");
  const db = new PGlite();
  conn = pgliteConn(db);
  close = () => db.close();
  const schema = readFileSync(join(import.meta.dir, "..", "src", "lib", "pg-schema.sql"), "utf8");
  await db.exec(schema);
  const schema002 = readFileSync(join(import.meta.dir, "..", "src", "lib", "pg-schema-002-provisioning-ledger.sql"), "utf8");
  await db.exec(schema002);
}

try {
  const stores = createPgStores(conn);
  // Seed: users (password + passwordless/OAuth), sessions, codes, ledger, states.
  const alice = await stores.userStore.create("drill-alice@example.com", "argon2id-test-hash");
  const bob = await stores.userStore.create("drill-bob@example.com", null);
  await stores.userStore.setVerified(alice.id);
  await stores.userStore.linkIdentity(bob.id, "google", "drill-sub-1");
  const s1 = await stores.sessionStore.create(alice.id, hashToken("drill-rt-1"), 3600_000);
  const s2 = await stores.sessionStore.create(alice.id, hashToken("drill-rt-2"), 3600_000);
  await stores.sessionStore.rotate(s1, hashToken("drill-rt-1b"));
  await stores.sessionStore.revoke(s2);
  const oidc = await stores.oidcStore.issue(alice.id, "https://web.alcore.io.vn/cb", "web", 600);
  void oidc;
  const plain = await stores.productExchangeStore.issue(alice.id, s1.id, "tokenpanel", "product_exchange", 600);
  void plain;
  const bound = await stores.productExchangeStore.issueForRedirect(
    alice.id, s1.id, "libre", "product_exchange", "https://web.alcore.io.vn/cb", "drill-state", 600,
  );
  void bound;
  await stores.purposeLedger.markPurposeConsumed(hashToken("drill-purpose-token"));
  await stores.googleStateStore.issue("drill-state-1", "drill-nonce-1", Math.floor(Date.now() / 1000) + 300);

  const snapPath = join(tmpdir(), `auth-drill-${Date.now()}.auth-snapshot.json`);
  const before = await snapshotToFile(conn, snapPath);
  const countsBefore = [...before].map(([t, r]) => `${t}=${r.length}`).join(" ");
  console.log(`drill: seeded snapshot: ${countsBefore}`);

  await stores.resetStoresForTests();
  const wiped = new Map<AuthTable, PgRow[]>();
  for (const t of AUTH_TABLES) wiped.set(t, await readTable(conn, t));
  const wipedTotal = [...wiped.values()].reduce((a, r) => a + r.length, 0);
  console.log(`drill: after wipe total rows: ${wipedTotal}`);
  if (wipedTotal !== 0) {
    console.error("drill: WIPE FAILED — rows remain after reset");
    process.exit(2);
  }

  const { unlinkSync } = await import("node:fs");
  const after = await restoreFromFile(conn, snapPath);
  unlinkSync(snapPath);
  const report = parityReport(before, after);
  for (const line of formatParity(report, "snapshot", "restored")) console.log(`drill: ${line}`);
  if (!report.ok) {
    console.error("drill: RESTORE PARITY FAILED");
    process.exit(2);
  }
  console.log("drill: BACKUP/RESTORE DRILL PASS — snapshot, wipe, restore, parity all green");
} finally {
  await close();
}
