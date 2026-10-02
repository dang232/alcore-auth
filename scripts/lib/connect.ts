// F0 operator helper: connect to PostgreSQL via Bun.SQL (DATABASE_URL) or,
// with --pglite, an in-process PGlite (real PG engine, scratch only).
// The --pglite path exists so cutover SQL is provable on boxes without a
// Docker daemon; production/VPS always uses DATABASE_URL (Bun.SQL).
import { join } from "node:path";
import { bunSqlConn, pgliteConn, type PgConn } from "../../src/lib/pg-store";

export interface LiveConn {
  readonly conn: PgConn;
  readonly close: () => Promise<void>;
  readonly label: string;
}

export async function connectPg(argv: string[] = process.argv): Promise<LiveConn> {
  const flag = (name: string): string | undefined => {
    const i = argv.indexOf(name);
    return i === -1 ? undefined : argv[i + 1];
  };
  if (argv.includes("--pglite")) {
    const { PGlite } = await import("@electric-sql/pglite");
    const { readFileSync } = await import("node:fs");
    const db = new PGlite();
    const schema = readFileSync(join(import.meta.dir, "..", "..", "src", "lib", "pg-schema.sql"), "utf8");
    await db.exec(schema);
    return { conn: pgliteConn(db), close: () => db.close(), label: "pglite" };
  }
  const url = flag("--database-url") ?? (process.env["DATABASE_URL"] ?? "").trim();
  if (url === "") {
    console.error("DATABASE_URL (or --database-url, or --pglite) is required (value never logged)");
    process.exit(1);
  }
  const live = bunSqlConn(url);
  return { conn: live, close: () => live.close(), label: "postgres" };
}
