// F0 operator: restore PostgreSQL auth state from a snapshot file.
// Usage: DATABASE_URL=postgres://... bun scripts/pg-restore.ts --in ./auth-backup-YYYYMMDD.auth-snapshot.json
// TRUNCATEs all auth tables (CASCADE) then re-inserts verbatim. Operator must
// hold a fresh snapshot first (pg-snapshot.ts) and confirm the parity report
// printed here before re-enabling traffic. Only counts + digests print.
import type { PgRow } from "../src/lib/pg-store";
import { connectPg } from "./lib/connect";
import { AUTH_TABLES, formatParity, parityReport, restoreFromFile, type AuthTable } from "./lib/pg-ops";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
}

const input = arg("--in");
if (input === undefined) {
  console.error("pg-restore: --in is required");
  process.exit(1);
}

const { conn, close, label } = await connectPg();
console.log(`pg-restore: backend=${label}`);
try {
  const { readFileSync } = await import("node:fs");
  const want = JSON.parse(readFileSync(input, "utf8")) as { tables: Record<AuthTable, PgRow[]> };
  const wantMap = new Map<AuthTable, PgRow[]>(
    AUTH_TABLES.map((t) => [t, want.tables[t] ?? []] as [AuthTable, PgRow[]]),
  );
  const gotMap = await restoreFromFile(conn, input);
  const report = parityReport(wantMap, gotMap);
  for (const line of formatParity(report, "snapshot", "pg")) console.log(`restore-parity: ${line}`);
  if (!report.ok) {
    console.error("pg-restore: RESTORE PARITY FAILED — investigate before traffic");
    process.exit(2);
  }
  console.log("pg-restore: RESTORE OK — snapshot and database agree row-for-row");
} finally {
  await close();
}
