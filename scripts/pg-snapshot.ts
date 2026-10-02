// F0 operator: snapshot PostgreSQL auth state to a local file.
// Usage: DATABASE_URL=postgres://... bun scripts/pg-snapshot.ts --out ./auth-backup-YYYYMMDD.auth-snapshot.json
// SECRET MATERIAL: the file contains password_hash / refresh_hash / live
// codes. chmod 600 is applied; never commit, never paste into logs/chat.
// Only counts are printed here.
import { connectPg } from "./lib/connect";
import { snapshotToFile } from "./lib/pg-ops";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
}

const out = arg("--out");
if (out === undefined) {
  console.error("pg-snapshot: --out is required");
  process.exit(1);
}

const { conn, close, label } = await connectPg();
console.log(`pg-snapshot: backend=${label}`);
try {
  const byTable = await snapshotToFile(conn, out);
  let total = 0;
  for (const [table, rows] of byTable) {
    console.log(`pg-snapshot: ${table}: ${rows.length} rows`);
    total += rows.length;
  }
  console.log(`pg-snapshot: wrote ${total} rows to snapshot (chmod 600)`);
} finally {
  await close();
}
