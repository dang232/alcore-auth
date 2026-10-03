-- ALcore Auth Repo C — PostgreSQL schema migration 002 (unified-auth-core todo 7).
--
-- Provisioning ledger (host decision: Auth store — see
-- src/lib/provision-ledger-schema.ts header for host/key/state/TTL/access).
-- SQLite twin: PROVISION_LEDGER_SQLITE_DDL in that module (same table, same
-- guards as SQLite triggers). This file is the 002 UP; the DOWN is the
-- commented block at the end (retire-only, never run against live data —
-- terminal ledger rows are identity audit and are retained).
--
-- Apply: bun scripts/pg-migrate.ts (DATABASE_URL, transactional, records
-- 002 in schema_migrations). Proof harness: tests/pg-setup.ts execs this
-- file after 001.

CREATE TABLE IF NOT EXISTS provisioning_ledger (
  canonical_key TEXT PRIMARY KEY CHECK (char_length(canonical_key) BETWEEN 1 AND 256),
  auth_user_id TEXT NOT NULL CHECK (char_length(auth_user_id) BETWEEN 1 AND 128),
  product TEXT NOT NULL CHECK (product IN ('tokenpanel','libre')),
  state TEXT NOT NULL CHECK (state IN ('PENDING','PROVISIONED','FAILED','CONFLICT')),
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  UNIQUE (auth_user_id, product)
);
CREATE INDEX IF NOT EXISTS provisioning_ledger_user_idx ON provisioning_ledger (auth_user_id);

-- New rows must start at PENDING; UNPROVISIONED lives as row absence.
-- PROVISIONED is terminal; FAILED/CONFLICT re-drive through PENDING only.
CREATE OR REPLACE FUNCTION provisioning_ledger_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.state != 'PENDING' THEN
      RAISE EXCEPTION 'provisioning_ledger: new rows must start at PENDING (UNPROVISIONED lives as row absence)';
    END IF;
  ELSIF TG_OP = 'UPDATE' THEN
    IF NOT (
      (OLD.state = 'PENDING' AND NEW.state IN ('PROVISIONED','FAILED','CONFLICT')) OR
      (OLD.state = 'FAILED' AND NEW.state IN ('PENDING','CONFLICT')) OR
      (OLD.state = 'CONFLICT' AND NEW.state = 'PENDING')
    ) THEN
      RAISE EXCEPTION 'provisioning_ledger: illegal state transition % -> %', OLD.state, NEW.state;
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS provisioning_ledger_insert_guard ON provisioning_ledger;
CREATE TRIGGER provisioning_ledger_insert_guard
BEFORE INSERT ON provisioning_ledger
FOR EACH ROW EXECUTE FUNCTION provisioning_ledger_guard();

DROP TRIGGER IF EXISTS provisioning_ledger_transition_guard ON provisioning_ledger;
CREATE TRIGGER provisioning_ledger_transition_guard
BEFORE UPDATE OF state ON provisioning_ledger
FOR EACH ROW EXECUTE FUNCTION provisioning_ledger_guard();

-- DOWN (retire-only; never run against live data — terminal rows are audit):
-- DROP TRIGGER IF EXISTS provisioning_ledger_transition_guard ON provisioning_ledger;
-- DROP TRIGGER IF EXISTS provisioning_ledger_insert_guard ON provisioning_ledger;
-- DROP FUNCTION IF EXISTS provisioning_ledger_guard();
-- DROP TABLE IF EXISTS provisioning_ledger;
-- DELETE FROM schema_migrations WHERE version = '002';
