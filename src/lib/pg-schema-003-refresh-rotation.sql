-- ALcore Auth Repo C — PostgreSQL schema migration 003 (refresh reuse grace).
--
-- The refresh routes rotate a single-use opaque token. Reuse of a rotated-out
-- token used to revoke the family unconditionally, which also fires for a
-- client race (two holders of the same token, a force quit between rotation and
-- persist). Distinguishing a race from theft needs the rotation timestamp:
-- authenticated rotation for both families now records WHEN the previous hash
-- was rotated out, and reuse inside a short grace window rotates again instead
-- of revoking.
--
-- Idempotent: ALTER ... ADD COLUMN IF NOT EXISTS. Existing rows read 0, which
-- means "no recorded rotation" and keeps the old revoke-on-reuse policy for
-- tokens issued before this migration.
--
-- Apply: bun scripts/pg-migrate.ts (DATABASE_URL; transactional; records 003 in
-- schema_migrations).
--
-- DOWN (retire-only; never run against a live backend):
-- ALTER TABLE ide_refresh_tokens DROP COLUMN IF EXISTS rotated_at;
-- ALTER TABLE sessions DROP COLUMN IF EXISTS rotated_at;
-- DELETE FROM schema_migrations WHERE version = '003';

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS rotated_at BIGINT NOT NULL DEFAULT 0;
ALTER TABLE ide_refresh_tokens ADD COLUMN IF NOT EXISTS rotated_at BIGINT NOT NULL DEFAULT 0;
