// F0 operator: apply PostgreSQL schema migration 001 (transactional).
// Usage: DATABASE_URL=postgres://... bun scripts/pg-migrate.ts
// Idempotent (IF NOT EXISTS + schema_migrations guard). Records 001 once
// applied. SafeMigrate-style: versioned file, transactional, explicit down
// lives as comments in src/lib/pg-schema.sql (retire-only, never live).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { connectPg } from "./lib/connect";

const schemaPath = join(import.meta.dir, "..", "src", "lib", "pg-schema.sql");
const raw = readFileSync(schemaPath, "utf8");
const statements = raw
  .split("\n")
  .filter((line) => !line.trimStart().startsWith("--"))
  .join("\n")
  .split(";")
  .map((s) => s.trim())
  .filter((s) => s !== "");

const { conn, close, label } = await connectPg();
console.log(`pg-migrate: backend=${label}`);
try {
  const applied = await conn.query<{ version: string }>(
    "SELECT version FROM schema_migrations WHERE version=$1",
    ["001"],
  ).catch(() => [] as Array<{ version: string }>);
  if (applied.length === 1) {
    console.log("pg-migrate: 001 already applied — nothing to do");
  } else {
    await conn.transaction(async (tx) => {
      for (const stmt of statements) await tx.query(stmt);
      await tx.query("INSERT INTO schema_migrations (version, applied_at) VALUES ($1,$2) ON CONFLICT(version) DO NOTHING", [
        "001",
        new Date().toISOString(),
      ]);
    });
    console.log(`pg-migrate: applied 001 (${statements.length} statements)`);
  }
} finally {
  await close();
}
