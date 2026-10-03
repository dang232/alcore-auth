// F0 operator: apply PostgreSQL schema migrations (transactional).
// Usage: DATABASE_URL=postgres://... bun scripts/pg-migrate.ts
// Idempotent (IF NOT EXISTS + schema_migrations guard per version).
// SafeMigrate-style: versioned files, transactional, explicit downs live as
// comments in each src/lib/pg-schema*.sql file (retire-only, never live).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { connectPg } from "./lib/connect";

const VERSIONS = [
  { version: "001", file: "pg-schema.sql" },
  { version: "002", file: "pg-schema-002-provisioning-ledger.sql" },
] as const;

/**
 * Split a migration script into statements. Aware of dollar-quoted function
 * bodies (002 trigger guard): semicolons inside $$...$$ never split, and
 * the CREATE TRIGGER lines after the body split normally. Line comments
 * (-- ...) are stripped only outside dollar-quoted blocks.
 */
function splitStatements(raw: string): string[] {
  const withoutComments: string[] = [];
  let inDollar = false;
  for (const line of raw.split("\n")) {
    const trimmed = line.trimStart();
    if (!inDollar && trimmed.startsWith("--")) continue;
    const opens = (line.match(/\$\$/g) ?? []).length;
    if (opens % 2 === 1) inDollar = !inDollar;
    withoutComments.push(line);
  }
  const statements: string[] = [];
  let current = "";
  inDollar = false;
  const parts = withoutComments.join("\n").split("$$");
  // Even indices (0,2,4..) are outside dollar quotes; odd indices are bodies.
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i] as string;
    if (i % 2 === 1) {
      current += `$$${part}$$`;
    } else {
      for (const stmt of part.split(";")) {
        const trimmed = (current + stmt).trim();
        current = "";
        if (trimmed !== "") statements.push(trimmed);
      }
    }
  }
  const tail = current.trim();
  if (tail !== "") statements.push(tail);
  return statements;
}

const { conn, close, label } = await connectPg();
console.log(`pg-migrate: backend=${label}`);
try {
  for (const { version, file } of VERSIONS) {
    const applied = await conn.query<{ version: string }>(
      "SELECT version FROM schema_migrations WHERE version=$1",
      [version],
    ).catch(() => [] as Array<{ version: string }>);
    if (applied.length === 1) {
      console.log(`pg-migrate: ${version} already applied — nothing to do`);
      continue;
    }
    const raw = readFileSync(join(import.meta.dir, "..", "src", "lib", file), "utf8");
    const statements = splitStatements(raw);
    await conn.transaction(async (tx) => {
      for (const stmt of statements) await tx.query(stmt);
      await tx.query("INSERT INTO schema_migrations (version, applied_at) VALUES ($1,$2) ON CONFLICT(version) DO NOTHING", [
        version,
        new Date().toISOString(),
      ]);
    });
    console.log(`pg-migrate: applied ${version} (${statements.length} statements)`);
  }
} finally {
  await close();
}
