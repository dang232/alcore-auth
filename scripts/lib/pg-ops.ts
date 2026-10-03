// F0 operator library: snapshot / restore / parity over any PgConn.
// Shared by scripts/pg-snapshot.ts, pg-restore.ts, pg-backup-drill.ts and
// backfill-sqlite-to-pg.ts so the drill and the cutover assert identically.
//
// Log-safety: parity reports carry table COUNTS + sha256 DIGESTS only.
// Snapshots (*.auth-snapshot.json) DO contain secret material
// (password_hash, refresh_hash, live codes) — chmod 600, never commit, never
// paste into logs. See docs/auth-postgres-cutover.md.

import { createHash } from "node:crypto";
import { chmodSync, readFileSync, writeFileSync } from "node:fs";
import type { PgConn, PgRow } from "../../src/lib/pg-store";

export const AUTH_TABLES = [
  "users",
  "provider_identities",
  "sessions",
  "oidc_codes",
  "consumed_purpose_tokens",
  "product_exchange_codes",
  "product_exchange_redirects",
  "google_states",
  "provisioning_ledger",
] as const;

export type AuthTable = (typeof AUTH_TABLES)[number];

/** Canonical comparable projection per table. Secret-bearing values enter
 *  only as sha256 digests (opaque refresh hashes, password hashes, live
 *  codes/nonces); everything else is normalized to strings so SQLite
 *  integers and PG bigint/text compare equal. */
export function canonicalRow(table: AuthTable, row: PgRow): string {
  const s = (v: unknown): string => (v === null || v === undefined ? "" : String(v));
  const n = (v: unknown): string => String(Number(v ?? 0));
  const h = (v: unknown): string => createHash("sha256").update(s(v), "utf8").digest("hex");
  switch (table) {
    case "users":
      return JSON.stringify([s(row["id"]), s(row["email"]).toLowerCase(), h(row["password_hash"]), n(row["email_verified"]), s(row["created_at"])]);
    case "provider_identities":
      return JSON.stringify([s(row["provider"]), s(row["subject"]), s(row["user_id"])]);
    case "sessions":
      return JSON.stringify([s(row["id"]), s(row["user_id"]), h(row["refresh_hash"]), h(row["previous_hashes"]), n(row["created_at"]), n(row["expires_at"]), n(row["revoked"])]);
    case "oidc_codes":
      return JSON.stringify([h(row["code"]), s(row["user_id"]), s(row["redirect_uri"]), s(row["client_id"]), s(row["code_challenge"]), s(row["code_challenge_method"]), n(row["expires_at"]), n(row["used"])]);
    case "consumed_purpose_tokens":
      return JSON.stringify([s(row["token_hash"]), n(row["consumed_at"])]);
    case "product_exchange_codes":
      return JSON.stringify([s(row["code_hash"]), s(row["user_id"]), s(row["session_id"]), s(row["audience"]), s(row["intent"]), n(row["expires_at"]), n(row["used"])]);
    case "product_exchange_redirects":
      return JSON.stringify([s(row["code_hash"]), s(row["redirect_uri"]), s(row["state_hash"]), n(row["expires_at"])]);
    case "google_states":
      return JSON.stringify([h(row["state"]), h(row["nonce"]), n(row["expires_at"])]);
    case "provisioning_ledger":
      return JSON.stringify([s(row["canonical_key"]), s(row["auth_user_id"]), s(row["product"]), s(row["state"]), n(row["created_at"]), n(row["updated_at"])]);
  }
}

export function tableDigest(rows: PgRow[], table: AuthTable): string {
  const Canon = rows.map((r) => canonicalRow(table, r)).sort();
  return createHash("sha256").update(JSON.stringify(Canon), "utf8").digest("hex");
}

export async function readTable(conn: PgConn, table: AuthTable): Promise<PgRow[]> {
  return conn.query<PgRow>(`SELECT * FROM ${table}`);
}

export interface ParityReport {
  readonly ok: boolean;
  readonly tables: Readonly<Record<string, { counts: [number, number]; digests: [string, string] }>>;
}

export function parityReport(left: Map<AuthTable, PgRow[]>, right: Map<AuthTable, PgRow[]>): ParityReport {
  const tables: Record<string, { counts: [number, number]; digests: [string, string] }> = {};
  let ok = true;
  for (const table of AUTH_TABLES) {
    const l = left.get(table) ?? [];
    const r = right.get(table) ?? [];
    const dl = tableDigest(l, table);
    const dr = tableDigest(r, table);
    const match = l.length === r.length && dl === dr;
    if (!match) ok = false;
    tables[table] = { counts: [l.length, r.length], digests: [dl, dr] };
  }
  return { ok, tables };
}

/** One log-safe line per table: counts + 12-char digest prefixes (enough to
 *  eyeball equality, useless for reconstructing anything). */
export function formatParity(report: ParityReport, leftName: string, rightName: string): string[] {
  return (Object.entries(report.tables) as Array<[string, { counts: [number, number]; digests: [string, string] }]>).map(
    ([table, t]) =>
      `${t.counts[0] === t.counts[1] && t.digests[0] === t.digests[1] ? "MATCH " : "DIFF   "}${table}: ${leftName}=${t.counts[0]} ${rightName}=${t.counts[1]} digests ${t.digests[0].slice(0, 12)}/${t.digests[1].slice(0, 12)}`,
  );
}

export interface SnapshotFile {
  readonly version: 1;
  readonly exportedAt: string;
  readonly tables: Record<AuthTable, PgRow[]>;
}

export async function snapshotToFile(conn: PgConn, outPath: string): Promise<Map<AuthTable, PgRow[]>> {
  const tables = {} as Record<AuthTable, PgRow[]>;
  const byTable = new Map<AuthTable, PgRow[]>();
  for (const table of AUTH_TABLES) {
    const rows = await readTable(conn, table);
    tables[table] = rows;
    byTable.set(table, rows);
  }
  const file: SnapshotFile = { version: 1, exportedAt: new Date().toISOString(), tables };
  writeFileSync(outPath, JSON.stringify(file));
  chmodSync(outPath, 0o600);
  return byTable;
}

const RESTORE_ORDER: AuthTable[] = [
  "users",
  "provider_identities",
  "sessions",
  "product_exchange_codes",
  "product_exchange_redirects",
  "oidc_codes",
  "consumed_purpose_tokens",
  "google_states",
  "provisioning_ledger",
];

export async function restoreFromFile(conn: PgConn, inPath: string): Promise<Map<AuthTable, PgRow[]>> {
  const file = JSON.parse(readFileSync(inPath, "utf8")) as SnapshotFile;
  if (file.version !== 1) throw new Error(`unsupported snapshot version ${(file as { version: unknown }).version}`);
  await conn.transaction(async (tx) => {
    await tx.query(`TRUNCATE ${AUTH_TABLES.join(", ")} CASCADE`);
    for (const table of RESTORE_ORDER) {
      const rows = file.tables[table] ?? [];
      for (const row of rows) {
        const cols = Object.keys(row);
        const placeholders = cols.map((_, i) => `$${i + 1}`).join(",");
        await tx.query(
          `INSERT INTO ${table} (${cols.join(",")}) VALUES (${placeholders})`,
          cols.map((c) => row[c]),
        );
      }
    }
  });
  const byTable = new Map<AuthTable, PgRow[]>();
  for (const table of AUTH_TABLES) byTable.set(table, await readTable(conn, table));
  return byTable;
}
