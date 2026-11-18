import { describe, expect, test } from "bun:test";

import { splitStatements } from "../scripts/lib/split-statements";

describe("pg migration statement splitter", () => {
  test("splits plain statements and drops comments and blanks", () => {
    const statements = splitStatements("-- leading note\nCREATE TABLE a (id int);\n\nCREATE INDEX b ON a (id);\n");
    expect(statements).toEqual(["CREATE TABLE a (id int)", "CREATE INDEX b ON a (id)"]);
  });

  test("keeps a dollar-quoted function body whole", () => {
    const raw = [
      "CREATE OR REPLACE FUNCTION guard() RETURNS trigger AS $$",
      "BEGIN",
      "  IF NEW.state != 'PENDING' THEN RAISE EXCEPTION 'no'; END IF;",
      "  RETURN NEW;",
      "END;",
      "$$ LANGUAGE plpgsql;",
      "CREATE TRIGGER t BEFORE INSERT ON ledger FOR EACH ROW EXECUTE FUNCTION guard();",
    ].join("\n");
    const statements = splitStatements(raw);
    expect(statements).toHaveLength(2);
    expect(statements[0]).toContain("$$");
    expect(statements[0]).toContain("RAISE EXCEPTION");
    expect(statements[0]?.endsWith("plpgsql")).toBe(true);
    expect(statements[1]?.startsWith("CREATE TRIGGER")).toBe(true);
  });

  test("keeps a tagged body and quoted semicolons whole", () => {
    const raw = "DO $body$ BEGIN PERFORM 1; END $body$;\nINSERT INTO t VALUES ('a;b');";
    const statements = splitStatements(raw);
    expect(statements).toHaveLength(2);
    expect(statements[0]).toContain("END $body$");
    expect(statements[1]).toBe("INSERT INTO t VALUES ('a;b')");
  });
});
