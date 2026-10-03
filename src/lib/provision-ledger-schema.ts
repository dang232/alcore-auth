// ALcore Auth Repo C — provisioning ledger DDL (unified-auth-core todo 7).
//
// Host decision: the ledger lives in the Auth store (SQLite fallback +
// managed PostgreSQL), NOT in TokenPanel Mongo or Libre. Rationale:
//  - Both products already contact Auth at pull time (proof verification),
//    so the ledger is readable exactly where the pull happens — no new
//    cross-service database access, no new infra (plan Must-NOT-Have).
//  - TokenPanel Mongo stays product-scoped (customers/conflicts/business);
//    a Libre row there would mix product concerns. Libre dual SQLite/PG
//    migrations stay untouched.
//  - Auth stays who-only: Auth makes zero outbound calls and performs zero
//    ledger writes. Products report their own rows via inbound pull
//    endpoints (todos 10-13 wire the writers); this module is schema only.
//
// Canonical key (opaque, 1-128 chars of identity + product prefix):
//  - TokenPanel rows: `customer-provision:{authUserId}` (same derivation as
//    provision-hook.ts buildProvisionKey — the key IS the idempotency key).
//  - Libre rows: `libre-provision:{issuer|sub}` (canonical Auth subject per
//    normalizeAuthSubject; the Libre id itself is never a key).
//
// States: UNPROVISIONED is NEVER stored — absence of a row for an
// (auth_user_id, product) pair IS the UNPROVISIONED default (never
// contacted). Stored states: PENDING -> PROVISIONED | FAILED | CONFLICT;
// FAILED -> PENDING (safe retry, same key) | CONFLICT; CONFLICT -> PENDING
// (admin re-drive after manual review); PROVISIONED is terminal
// (re-provision is an idempotent no-op, not a transition). New rows must
// start at PENDING. Both triggers below enforce this at the DB layer, so a
// bare `if(!exists)create` without the state machine cannot corrupt it.
//
// Contents: opaque ids + state + timestamps only. NEVER passwords, password
// hashes, Auth sessions, refresh tokens, or emails (audit joins use the
// existing hashed-audit helpers in the products).
//
// Retention/TTL: no DB-level expiry (identity audit must survive; no cron
// infra per plan). PENDING older than 24h is treated as FAILED-by-timeout by
// readers; terminal rows (PROVISIONED/CONFLICT) are retained indefinitely.
// Access: admin-role-only for cross-product reads; each product writes only
// its own product rows via Auth-proofed pull endpoints (enforced in route
// code by todos 10-13, recorded here as the rule).
//
// Engine note: this string is the SQLite author. The PostgreSQL twin is
// src/lib/pg-schema-002-provisioning-ledger.sql (same table, same guards as
// a plpgsql trigger). The verify probe scripts/provision-ledger-verify.ts
// exercises both.

export const PROVISION_LEDGER_SQLITE_DDL = `
CREATE TABLE IF NOT EXISTS provisioning_ledger (
  canonical_key TEXT PRIMARY KEY CHECK(length(canonical_key) BETWEEN 1 AND 256),
  auth_user_id TEXT NOT NULL CHECK(length(auth_user_id) BETWEEN 1 AND 128),
  product TEXT NOT NULL CHECK(product IN ('tokenpanel','libre')),
  state TEXT NOT NULL CHECK(state IN ('PENDING','PROVISIONED','FAILED','CONFLICT')),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(auth_user_id, product)
);
CREATE INDEX IF NOT EXISTS provisioning_ledger_user_idx ON provisioning_ledger(auth_user_id);
CREATE TRIGGER IF NOT EXISTS provisioning_ledger_insert_pending
BEFORE INSERT ON provisioning_ledger
FOR EACH ROW
WHEN (NEW.state != 'PENDING')
BEGIN
  SELECT RAISE(ABORT, 'provisioning_ledger: new rows must start at PENDING (UNPROVISIONED lives as row absence)');
END;
CREATE TRIGGER IF NOT EXISTS provisioning_ledger_transition_guard
BEFORE UPDATE OF state ON provisioning_ledger
FOR EACH ROW
WHEN (NOT (
  (OLD.state = 'PENDING' AND NEW.state IN ('PROVISIONED','FAILED','CONFLICT')) OR
  (OLD.state = 'FAILED' AND NEW.state IN ('PENDING','CONFLICT')) OR
  (OLD.state = 'CONFLICT' AND NEW.state = 'PENDING')
))
BEGIN
  SELECT RAISE(ABORT, 'provisioning_ledger: illegal state transition');
END;
`;
