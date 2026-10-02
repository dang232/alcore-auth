-- ALcore Auth Repo C — PostgreSQL schema migration 001 (F0).
--
-- Mirrors the SQLite DDL in src/lib/store.ts table-for-table, with two
-- engine-driven deltas (both behavior-preserving):
--   1. Case-insensitive email uniqueness is `UNIQUE (lower(email))` instead
--      of SQLite `COLLATE NOCASE` (PostgreSQL has no NOCASE collation; CITEXT
--      is deliberately NOT required so this applies on managed instances
--      without superuser extensions).
--   2. Integer flag columns (email_verified, revoked, used) stay SMALLINT
--      0/1 — identical read/write semantics to the SQLite store, zero
--      adapter branching on truthiness.
--
-- Style precedent: AlRepo SafeMigrate (versioned file, transactional apply,
-- explicit down). This file is the UP; the DOWN is the commented block at
-- the end (drops in reverse dependency order).
--
-- Apply: bun scripts/pg-migrate.ts (DATABASE_URL, transactional, records
-- 001 in schema_migrations). Rollback of DATA is the SQLite snapshot +
-- config flip documented in docs/auth-postgres-cutover.md — this DOWN only
-- drops empty/retired tables, never a live backend.

CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  password_hash TEXT,
  email_verified SMALLINT NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_idx ON users (lower(email));

CREATE TABLE IF NOT EXISTS provider_identities (
  provider TEXT NOT NULL,
  subject TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (provider, subject)
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  refresh_hash TEXT NOT NULL UNIQUE,
  previous_hashes TEXT NOT NULL DEFAULT '[]',
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  revoked SMALLINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id);

CREATE TABLE IF NOT EXISTS oidc_codes (
  code TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  client_id TEXT NOT NULL DEFAULT '',
  code_challenge TEXT NOT NULL DEFAULT '',
  code_challenge_method TEXT NOT NULL DEFAULT '',
  expires_at BIGINT NOT NULL,
  used SMALLINT NOT NULL DEFAULT 0
);

-- One-use ledger for verify/reset purpose tokens. Keyed by hash, never token.
CREATE TABLE IF NOT EXISTS consumed_purpose_tokens (
  token_hash TEXT PRIMARY KEY,
  consumed_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS product_exchange_codes (
  code_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  audience TEXT NOT NULL,
  intent TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  used SMALLINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS product_exchange_redirects (
  code_hash TEXT PRIMARY KEY,
  redirect_uri TEXT NOT NULL,
  state_hash TEXT NOT NULL,
  expires_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS google_states (
  state TEXT PRIMARY KEY,
  nonce TEXT NOT NULL,
  expires_at BIGINT NOT NULL
);

-- DOWN (retire-only; never run against a live backend — cutover rollback is
-- the SQLite snapshot + AUTH_STORE_BACKEND flip, see runbook):
-- DROP TABLE IF EXISTS google_states;
-- DROP TABLE IF EXISTS product_exchange_redirects;
-- DROP TABLE IF EXISTS product_exchange_codes;
-- DROP TABLE IF EXISTS consumed_purpose_tokens;
-- DROP TABLE IF EXISTS oidc_codes;
-- DROP TABLE IF EXISTS sessions;
-- DROP TABLE IF EXISTS provider_identities;
-- DROP TABLE IF EXISTS users;
-- DELETE FROM schema_migrations WHERE version = '001';
