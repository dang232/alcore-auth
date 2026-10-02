// F0 proof harness: run the ENTIRE auth suite against PostgreSQL semantics.
// Usage: bun test --preload ./tests/pg-setup.ts
// Creates one in-process PGlite (real PG engine), applies 001, and injects it
// process-wide BEFORE any suite imports the store. Every existing test file
// then runs unmodified against PG — pass counts must match the SQLite run.
// Sets F0_PG_PRELOAD so tests/pg-backend.test.ts reuses this backend instead
// of minting its own.
process.env["JWT_SECRET"] = "test-only-dummy-secret-0123456789abcdef";
process.env["ALLOW_WEAK_JWT_SECRET"] = "1";
process.env["NODE_ENV"] = "test";

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";
import { pgliteConn } from "../src/lib/pg-store";
import { __setPgConnForTests } from "../src/lib/store";

const db = new PGlite();
const schema = readFileSync(join(import.meta.dir, "..", "src", "lib", "pg-schema.sql"), "utf8");
await db.exec(schema);
__setPgConnForTests(pgliteConn(db));
process.env["F0_PG_PRELOAD"] = "1";
console.log("[f0] pg-setup: PGlite 001 applied, process-wide PG backend active");
