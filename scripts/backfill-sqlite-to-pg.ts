// F0 operator: SQLite → PostgreSQL backfill + parity gate.
// Usage:
//   bun scripts/backfill-sqlite-to-pg.ts --sqlite ./data/auth.sqlite
//   DATABASE_URL=postgres://... bun scripts/backfill-sqlite-to-pg.ts [--sqlite path] [--apply-schema]
// Idempotent reruns (INSERT ... ON CONFLICT DO NOTHING). Exits non-zero when
// the parity gate fails — the cutover MUST NOT proceed on DIFF.
// Logs counts + digest prefixes only; never secret values.
import { Database } from "bun:sqlite";
import { existsSync } from "node:fs";
import type { PgRow } from "../src/lib/pg-store";
import { connectPg } from "./lib/connect";
import {
  AUTH_TABLES,
  formatParity,
  parityReport,
  type AuthTable,
} from "./lib/pg-ops";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
}

const sqlitePath = arg("--sqlite") ?? (process.env["AUTH_DATABASE_PATH"] ?? "./data/auth.sqlite").trim();
if (!existsSync(sqlitePath)) {
  console.error(`backfill: sqlite file not found: ${sqlitePath}`);
  process.exit(1);
}

const lite = new Database(sqlitePath, { readonly: true, strict: true });
const { conn, close, label } = await connectPg();
console.log(`backfill: backend=${label}`);
try {
  if (process.argv.includes("--apply-schema")) {
    const { readFileSync } = await import("node:fs");
    const { join } = await import("node:path");
    const raw = readFileSync(join(import.meta.dir, "..", "src", "lib", "pg-schema.sql"), "utf8");
    const statements = raw.split("\n").filter((l) => !l.trimStart().startsWith("--")).join("\n").split(";").map((s) => s.trim()).filter((s) => s !== "");
    await conn.transaction(async (tx) => {
      for (const stmt of statements) await tx.query(stmt);
      await tx.query("INSERT INTO schema_migrations (version, applied_at) VALUES ($1,$2) ON CONFLICT(version) DO NOTHING", ["001", new Date().toISOString()]);
    });
    console.log("backfill: schema ensured (001)");
  }

  const left = new Map<AuthTable, PgRow[]>();
  const right = new Map<AuthTable, PgRow[]>();
  for (const table of AUTH_TABLES) {
    const rows = lite.query(`SELECT * FROM ${table}`).all() as PgRow[];
    left.set(table, rows);
    let copied = 0;
    for (const row of rows) {
      const cols = Object.keys(row);
      const placeholders = cols.map((_, i) => `$${i + 1}`).join(",");
      await conn.query(
        `INSERT INTO ${table} (${cols.join(",")}) VALUES (${placeholders}) ON CONFLICT DO NOTHING`,
        cols.map((c) => row[c]),
      );
      copied++;
    }
    // ON CONFLICT DO NOTHING has no target — works for every PK here
    // because every auth table's conflict target IS its primary key.
    const pgRows = await conn.query<PgRow>(`SELECT * FROM ${table}`);
    right.set(table, pgRows);
    console.log(`backfill: ${table}: sqlite=${rows.length} copied-attempts=${copied} pg=${pgRows.length}`);
  }

  const report = parityReport(left, right);
  for (const line of formatParity(report, "sqlite", "pg")) console.log(`parity: ${line}`);
  if (!report.ok) {
    console.error("backfill: PARITY GATE FAILED — do not cut over");
    process.exit(2);
  }
  console.log("backfill: PARITY OK — cutover gate passed");
} finally {
  await close();
  lite.close();
}
