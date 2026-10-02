// ALcore Auth Repo C — legacy bcrypt compatibility verifier (task 43).
//
// OWNER: auth-service (Auth owns ALL credential verification; products MUST
// never verify or store passwords — see docs/auth/OWNERSHIP.md).
//
// REMOVAL CONDITION: delete this module (and its test) once the zero-runtime
// legacy proof (plan todo 50) shows zero `$2*` password_hash values in Auth
// storage for 14 consecutive days AND every migration snapshot confirms each
// legacy record was rehashed-or-reset. Grep-gate for removal:
// zero `legacy-password` / `LEGACY_BCRYPT` hits outside this file + its test.
//
// Design (locked decisions: no bcrypt hash copy, no dual-write):
// - Canonical Auth storage is Argon2id ONLY (`$argon2id$`, via Bun.password).
// - A stored `$2a$`/`$2b$`/`$2y$` hash is NEVER canonical: on a successful
//   login the route verifies it here, then REPLACES it with a fresh Argon2id
//   hash in a single write (verify-then-rehash). No dual storage, no copy.
// - `Bun.password.verify` already verifies bcrypt (proven task 43: real
//   bcryptjs `$2b$` hashes verify true/false correctly, `$2a$`/`$2y$`
//   variants included), so this module needs ZERO new dependencies.
// - Anything that is neither Argon2id nor recognized bcrypt is
//   `reset-required`: login fails closed (generic 401, no oracle) and the
//   account recovers only through the password-reset flow (which needs no
//   old password). Malformed input never grants access — verify throws are
//   caught and treated as failure, never as success.

/** Bcrypt modular-crypt shape: `$2a|$2b|$2y$` + 2-digit cost + 53-char body. */
const LEGACY_BCRYPT_RE = /^\$2[aby]\$\d{2}\$[\./A-Za-z0-9]{53}$/;

export type StoredHashKind = "argon2id" | "legacy-bcrypt" | "reset-required";

/** Classify a stored `password_hash` without touching secrets. */
export function classifyStoredHash(storedHash: string): StoredHashKind {
  if (storedHash.startsWith("$argon2id$")) return "argon2id";
  if (LEGACY_BCRYPT_RE.test(storedHash)) return "legacy-bcrypt";
  return "reset-required";
}

export type CompatOutcome = "argon2-ok" | "legacy-ok" | "fail" | "reset-required";

/**
 * Verify a password against a stored hash through the controlled compat path.
 * - `argon2-ok`: canonical path, no migration work needed.
 * - `legacy-ok`: caller MUST immediately replace the stored hash with
 *   `hashPassword(plain)` (single write) and audit `auth.password_rehash`.
 * - `fail`: wrong password — caller MUST NOT rehash, MUST NOT grant access.
 * - `reset-required`: unsupported/malformed record — caller fails closed
 *   (generic 401) and audits `auth.login_reset_required`; recovery is the
 *   password-reset flow only. Never throws on attacker-controlled input.
 */
export async function verifyPasswordCompat(plain: string, storedHash: string): Promise<CompatOutcome> {
  const kind = classifyStoredHash(storedHash);
  if (kind === "reset-required") return "reset-required";
  try {
    const ok = await Bun.password.verify(plain, storedHash);
    if (!ok) return "fail";
    return kind === "argon2id" ? "argon2-ok" : "legacy-ok";
  } catch {
    // Bun throws UnsupportedAlgorithm on malformed hashes: fail closed.
    return "fail";
  }
}
