// ALcore Auth Repo C — identity stores with pluggable backend (F0).
//
// SQLite below is the BATTLE-TESTED fallback/test backend (file-backed
// ./data/auth.sqlite + WAL + auth-data volume; durable single-node, task36
// restart proof). The target topology is managed PostgreSQL
// (src/lib/pg-store.ts over Bun's built-in SQL client, DATABASE_URL).
//
// Backend selection (src/config.ts): AUTH_STORE_BACKEND=postgres (+ required
// DATABASE_URL) answers every repository call from PostgreSQL; anything else
// answers from SQLite. Tests may inject a query connection via
// __setPgConnForTests (PGlite proof harness) which takes precedence.
//
// Interface contract: the exported stores implement src/lib/auth-models.ts
// (same names, args, return shapes — Promise-based because PG I/O is async;
// SQLite answers synchronously under the hood). Routes import these stable
// names and observe zero behavior change across backends. Rollback = config
// flip back to SQLite (cutover runbook in docs/auth-postgres-cutover.md).

import { Database } from "bun:sqlite";
import { createHash } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { getAuthDatabasePath, getAuthStoreBackend, getDatabaseUrl, nodeEnv } from "../config";
import { verifyPkceS256 } from "./crypto";
import type {
  GoogleStateStore,
  OidcCode,
  OidcStore,
  ProductAudience,
  ProductExchangeCode,
  ProductExchangeStore,
  Session,
  SessionStore,
  User,
  UserStore,
} from "./auth-models";
import { bunSqlConn, createPgStores, type PgConn, type PgStores } from "./pg-store";
import { PROVISION_LEDGER_SQLITE_DDL } from "./provision-ledger-schema";

export type {
  GoogleStateStore,
  IdentityLinkResult,
  OidcCode,
  OidcStore,
  ProductAudience,
  ProductExchangeCode,
  ProductExchangeStore,
  Session,
  SessionStore,
  User,
  UserStore,
} from "./auth-models";

type Row = Record<string, unknown>;

const configuredPath = getAuthDatabasePath();
const filename = configuredPath === ":memory:" ? configuredPath : resolve(configuredPath);
if (filename !== ":memory:") mkdirSync(dirname(filename), { recursive: true });
const db = new Database(filename, { strict: true, create: true, readwrite: true });
db.run("PRAGMA journal_mode = WAL");
db.run("PRAGMA foreign_keys = ON");
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT,
    email_verified INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
  );
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
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS oidc_codes (
    code TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    client_id TEXT NOT NULL DEFAULT '',
    code_challenge TEXT NOT NULL DEFAULT '',
    code_challenge_method TEXT NOT NULL DEFAULT '',
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
  );
  -- One-use ledger for verify/reset purpose tokens (task 38). Purpose tokens
  -- are stateless HMAC; this table is what makes consumption single-use: the
  -- route marks sha256(purpose:token) here inside the consume handler, and a
  -- replay finds the row already present. Keyed by hash, never the token.
  CREATE TABLE IF NOT EXISTS consumed_purpose_tokens (
    token_hash TEXT PRIMARY KEY,
    consumed_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS product_exchange_codes (
    code_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    audience TEXT NOT NULL,
    intent TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
  );
  -- Browser-issued product codes additionally bind the exact callback URI, so a
  -- code minted for one registered redirect cannot be replayed at another. Empty
  -- on codes issued by the non-browser POST /oidc/exchange path, which has no
  -- redirect and keeps that caller working unchanged.
  CREATE TABLE IF NOT EXISTS product_exchange_redirects (
    code_hash TEXT PRIMARY KEY,
    redirect_uri TEXT NOT NULL,
    state_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS google_states (
    state TEXT PRIMARY KEY,
    nonce TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id);
`);
// Provisioning ledger (unified-auth-core todo 7): pull-lazy per-product state
// machine. DDL author is provision-ledger-schema.ts; applied here so every
// backend (file SQLite, :memory: tests) carries it from import time.
db.exec(PROVISION_LEDGER_SQLITE_DDL);
if (!db.query("PRAGMA table_info(oidc_codes)").all().some((column) => {
  return typeof column === "object" && column !== null && "name" in column && column.name === "client_id";
})) {
  db.run("ALTER TABLE oidc_codes ADD COLUMN client_id TEXT NOT NULL DEFAULT ''");
}
// Task 38 PKCE columns for pre-existing file DBs (fresh DBs get them from CREATE TABLE above).
for (const pkceColumn of ["code_challenge", "code_challenge_method"] as const) {
  const present = (db.query("PRAGMA table_info(oidc_codes)").all() as Row[]).some((column) => column["name"] === pkceColumn);
  if (!present) db.run(`ALTER TABLE oidc_codes ADD COLUMN ${pkceColumn} TEXT NOT NULL DEFAULT ''`);
}

function userFromRow(row: Row | null): User | undefined {
  if (row === null) return undefined;
  return {
    id: String(row["id"]),
    email: String(row["email"]),
    passwordHash: typeof row["password_hash"] === "string" ? row["password_hash"] : null,
    emailVerified: Number(row["email_verified"]) === 1,
    createdAt: String(row["created_at"]),
  };
}

function sessionFromRow(row: Row | null): Session | undefined {
  if (row === null) return undefined;
  return {
    id: String(row["id"]),
    userId: String(row["user_id"]),
    refreshHash: String(row["refresh_hash"]),
    prevHashes: new Set(JSON.parse(String(row["previous_hashes"])) as string[]),
    createdAt: Number(row["created_at"]),
    expiresAt: Number(row["expires_at"]),
    revoked: Number(row["revoked"]) === 1,
  };
}

const sqliteUserStore = {
  create(email: string, passwordHash: string | null): User {
    const user: User = {
      id: crypto.randomUUID(),
      email,
      passwordHash,
      emailVerified: false,
      createdAt: new Date().toISOString(),
    };
    try {
      db.query("INSERT INTO users (id,email,password_hash,email_verified,created_at) VALUES (?,?,?,?,?)").run(
        user.id, user.email, user.passwordHash, 0, user.createdAt,
      );
      return user;
    } catch (error) {
      if (error instanceof Error && error.message.includes("UNIQUE constraint failed: users.email")) {
        const existing = this.findByEmail(email);
        if (existing !== undefined) return existing;
      }
      throw error;
    }
  },
  createWithId(id: string, email: string, passwordHash: string | null, emailVerified: boolean): User {
    const user: User = {
      id, email, passwordHash, emailVerified, createdAt: new Date().toISOString(),
    };
    db.query("INSERT INTO users (id,email,password_hash,email_verified,created_at) VALUES (?,?,?,?,?)").run(
      user.id, user.email, user.passwordHash, user.emailVerified ? 1 : 0, user.createdAt,
    );
    return user;
  },
  findByEmail(email: string): User | undefined {
    return userFromRow(db.query("SELECT * FROM users WHERE email = ? COLLATE NOCASE").get(email) as Row | null);
  },
  findByProviderSub(provider: string, sub: string): User | undefined {
    return userFromRow(db.query("SELECT users.* FROM provider_identities JOIN users ON users.id=provider_identities.user_id WHERE provider=? AND subject=?").get(provider, sub) as Row | null);
  },
  linkIdentity(userId: string, provider: string, sub: string): "linked" | "already_linked" | "owned_by_other_user" {
    const existing = db.query("SELECT user_id FROM provider_identities WHERE provider=? AND subject=?").get(provider, sub) as Row | null;
    if (existing !== null) return String(existing["user_id"]) === userId ? "already_linked" : "owned_by_other_user";
    const result = db.query("INSERT INTO provider_identities (provider,subject,user_id) VALUES (?,?,?) ON CONFLICT(provider,subject) DO NOTHING").run(provider, sub, userId);
    if (result.changes === 1) return "linked";
    const owner = db.query("SELECT user_id FROM provider_identities WHERE provider=? AND subject=?").get(provider, sub) as Row | null;
    return owner !== null && String(owner["user_id"]) === userId ? "already_linked" : "owned_by_other_user";
  },
  findById(id: string): User | undefined {
    return userFromRow(db.query("SELECT * FROM users WHERE id = ?").get(id) as Row | null);
  },
  findByIdAndPasswordHash(id: string, passwordHash: string): User | undefined {
    return userFromRow(db.query("SELECT * FROM users WHERE id=? AND password_hash=?").get(id, passwordHash) as Row | null);
  },
  setVerified(id: string): void {
    db.query("UPDATE users SET email_verified=1 WHERE id=?").run(id);
  },
  setPasswordHash(id: string, hash: string): void {
    db.query("UPDATE users SET password_hash=? WHERE id=?").run(hash, id);
  },
  count(): number {
    return Number((db.query("SELECT COUNT(*) AS c FROM users").get() as Row)["c"]);
  },
};

const sqliteSessionStore = {
  create(userId: string, refreshHash: string, ttlMs: number): Session {
    const now = Date.now();
    const session: Session = {
      id: crypto.randomUUID(), userId, refreshHash,
      prevHashes: new Set<string>(), createdAt: now,
      expiresAt: now + ttlMs, revoked: false,
    };
    db.query("INSERT INTO sessions (id,user_id,refresh_hash,previous_hashes,created_at,expires_at,revoked) VALUES (?,?,?,?,?,?,0)").run(
      session.id, session.userId, session.refreshHash, "[]", session.createdAt, session.expiresAt,
    );
    return session;
  },
  createWithId(id: string, userId: string, refreshHash: string, ttlMs: number): Session {
    const now = Date.now();
    const session: Session = {
      id, userId, refreshHash, prevHashes: new Set<string>(),
      createdAt: now, expiresAt: now + ttlMs, revoked: false,
    };
    db.query("INSERT INTO sessions (id,user_id,refresh_hash,previous_hashes,created_at,expires_at,revoked) VALUES (?,?,?,?,?,?,0)").run(
      session.id, session.userId, session.refreshHash, "[]", session.createdAt, session.expiresAt,
    );
    return session;
  },
  findById(id: string): Session | undefined {
    return sessionFromRow(db.query("SELECT * FROM sessions WHERE id=?").get(id) as Row | null);
  },
  findByRefreshHash(hash: string): Session | undefined {
    return sessionFromRow(db.query("SELECT * FROM sessions WHERE refresh_hash=?").get(hash) as Row | null);
  },
  findByRefreshOrPrevHash(hash: string): Session | undefined {
    const live = db.query("SELECT * FROM sessions WHERE refresh_hash=?").get(hash) as Row | null;
    if (live !== null) return sessionFromRow(live);
    return sessionFromRow(db.query("SELECT * FROM sessions WHERE previous_hashes LIKE ?").get(`%${hash}%`) as Row | null);
  },
  /**
   * Atomic compare-and-swap rotation: the single UPDATE only wins when the
   * row still holds the presented hash and is not revoked, so two concurrent
   * refreshes with the same token yield exactly one winner (mirrors the
   * oidcStore.consume `UPDATE ... used=0 RETURNING` pattern). Returns true
   * on win; on loss the in-memory session is left untouched.
   */
  rotate(session: Session, nextHash: string): boolean {
    const merged = [...session.prevHashes, session.refreshHash];
    const row = db.query(
      "UPDATE sessions SET refresh_hash=?,previous_hashes=? WHERE id=? AND refresh_hash=? AND revoked=0 RETURNING id",
    ).get(nextHash, JSON.stringify(merged), session.id, session.refreshHash) as Row | null;
    if (row === null) return false;
    session.prevHashes.add(session.refreshHash);
    session.refreshHash = nextHash;
    return true;
  },
  isReusedHash(session: Session, hash: string): boolean {
    return session.prevHashes.has(hash);
  },
  revoke(session: Session): void {
    session.revoked = true;
    db.query("UPDATE sessions SET revoked=1 WHERE id=?").run(session.id);
  },
  revokeAllForUser(userId: string): void {
    db.query("UPDATE sessions SET revoked=1 WHERE user_id=? AND revoked=0").run(userId);
  },
  listActiveForUser(userId: string): Session[] {
    return (db.query("SELECT * FROM sessions WHERE user_id=? AND revoked=0 ORDER BY created_at ASC").all(userId) as Row[])
      .map((row) => sessionFromRow(row))
      .filter((s): s is Session => s !== undefined);
  },
  revokeByIdForUser(id: string, userId: string): boolean {
    const result = db.query("UPDATE sessions SET revoked=1 WHERE id=? AND user_id=? AND revoked=0").run(id, userId);
    return result.changes === 1;
  },
};

const sqliteOidcStore = {
  issue(
    userId: string,
    redirectUri: string,
    clientId: string,
    ttlSeconds: number,
    pkce?: { readonly challenge: string; readonly method: string },
  ): OidcCode {
    const record: OidcCode = {
      code: randomHex(16), userId, redirectUri, clientId,
      exp: Math.floor(Date.now() / 1000) + ttlSeconds, used: false,
      codeChallenge: pkce?.challenge ?? "",
      codeChallengeMethod: pkce?.method ?? "",
    };
    db.query("INSERT INTO oidc_codes (code,user_id,redirect_uri,client_id,code_challenge,code_challenge_method,expires_at,used) VALUES (?,?,?,?,?,?,?,0)").run(
      record.code, record.userId, record.redirectUri, record.clientId,
      record.codeChallenge, record.codeChallengeMethod, record.exp,
    );
    return record;
  },
  consume(code: string, redirectUri: string, clientId: string, verifier?: string): OidcCode | null {
    // PKCE-bound codes require the matching verifier; the check happens BEFORE
    // the single-use UPDATE so a wrong verifier never burns the code. Codes
    // issued without a challenge keep the legacy path (verifier ignored).
    const peek = db.query("SELECT code_challenge FROM oidc_codes WHERE code=?").get(code) as Row | null;
    if (peek !== null) {
      const challenge = String(peek["code_challenge"] ?? "");
      if (challenge !== "") {
        if (verifier === undefined || verifier === "" || !verifyPkceS256(verifier, challenge)) return null;
      }
    }
    const row = db.query("UPDATE oidc_codes SET used=1 WHERE code=? AND redirect_uri=? AND client_id=? AND expires_at>? AND used=0 RETURNING code,user_id,redirect_uri,client_id,code_challenge,code_challenge_method,expires_at").get(
      code, redirectUri, clientId, Math.floor(Date.now() / 1000),
    ) as Row | null;
    if (row === null) return null;
    return {
      code: String(row["code"]), userId: String(row["user_id"]),
      redirectUri: String(row["redirect_uri"]), clientId: String(row["client_id"]), exp: Number(row["expires_at"]), used: true,
      codeChallenge: String(row["code_challenge"] ?? ""),
      codeChallengeMethod: String(row["code_challenge_method"] ?? ""),
    };
  },
};

/** Single-use ledger for verify/reset purpose tokens (task 38). Returns true
 *  on first use; false when the token hash is already recorded (replay). */
function sqliteMarkPurposeConsumed(tokenHash: string): boolean {
  try {
    const result = db.query(
      "INSERT INTO consumed_purpose_tokens (token_hash,consumed_at) VALUES (?,?) ON CONFLICT(token_hash) DO NOTHING",
    ).run(tokenHash, Date.now());
    return result.changes === 1;
  } catch {
    return false;
  }
}

const sqliteProductExchangeStore = {
  issue(userId: string, sessionId: string, audience: ProductAudience, intent: string, ttlSeconds: number): string {
    const code = randomHex(32);
    const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
    db.query("INSERT INTO product_exchange_codes (code_hash,user_id,session_id,audience,intent,expires_at,used) VALUES (?,?,?,?,?,?,0)").run(
      hashExchangeCode(code), userId, sessionId, audience, intent, exp,
    );
    return code;
  },
  /**
   * Browser-initiated issue. The code is bound to the exact redirect URI and to
   * the caller's state value, so redemption must present both. Backed by a single
   * transaction: the redirect-binding row is written in the same transaction that
   * marks the code used, which is what makes concurrent redemption safe.
   */
  issueForRedirect(
    userId: string,
    sessionId: string,
    audience: ProductAudience,
    intent: string,
    redirectUri: string,
    state: string,
    ttlSeconds: number,
  ): string {
    const code = randomHex(32);
    const codeHash = hashExchangeCode(code);
    const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
    db.transaction(() => {
      db.query("INSERT INTO product_exchange_codes (code_hash,user_id,session_id,audience,intent,expires_at,used) VALUES (?,?,?,?,?,?,0)").run(
        codeHash, userId, sessionId, audience, intent, exp,
      );
      db.query("INSERT INTO product_exchange_redirects (code_hash,redirect_uri,state_hash,expires_at) VALUES (?,?,?,?)").run(
        codeHash, redirectUri, hashExchangeState(state), exp,
      );
    })();
    return code;
  },
  /**
   * Legacy non-browser redemption. Refuses any code that carries a redirect
   * binding: a browser-issued code must be redeemed through
   * `consumeForRedirect` so its redirect and state are actually verified, and
   * this path has no way to check them.
   */
  consume(code: string, audience: ProductAudience, intent: string): ProductExchangeCode | null {
    const codeHash = hashExchangeCode(code);
    const bound = db.query("SELECT 1 FROM product_exchange_redirects WHERE code_hash=?").get(codeHash);
    if (bound !== null) return null;
    const row = db.query("UPDATE product_exchange_codes SET used=1 WHERE code_hash=? AND audience=? AND intent=? AND expires_at>? AND used=0 RETURNING user_id,session_id,audience,intent,expires_at").get(
      codeHash, audience, intent, Math.floor(Date.now() / 1000),
    ) as Row | null;
    if (row === null) return null;
    return {
      code, userId: String(row["user_id"]), sessionId: String(row["session_id"]),
      audience,
      intent: String(row["intent"]), exp: Number(row["expires_at"]),
    };
  },
  /**
   * Single-use redemption for browser-issued codes. Verifies the redirect binding
   * and state inside the same transaction that marks the code used, so a replayed
   * code fails on `used=0` even when the redirect binding is still present.
   * `state` may be empty only for callers that present the redirect without one.
   */
  consumeForRedirect(
    code: string,
    audience: ProductAudience,
    intent: string,
    redirectUri: string,
    state: string,
  ): ProductExchangeCode | null {
    const codeHash = hashExchangeCode(code);
    const now = Math.floor(Date.now() / 1000);
    return db.transaction((): ProductExchangeCode | null => {
      const binding = db.query(
        "SELECT redirect_uri,state_hash FROM product_exchange_redirects WHERE code_hash=? AND expires_at>?",
      ).get(codeHash, now) as Row | null;
      if (binding === null) return null;
      if (String(binding["redirect_uri"]) !== redirectUri) return null;
      if (state !== "" && String(binding["state_hash"]) !== hashExchangeState(state)) return null;
      const row = db.query(
        "UPDATE product_exchange_codes SET used=1 WHERE code_hash=? AND audience=? AND intent=? AND expires_at>? AND used=0 RETURNING user_id,session_id,audience,intent,expires_at",
      ).get(codeHash, audience, intent, now) as Row | null;
      if (row === null) return null;
      db.query("DELETE FROM product_exchange_redirects WHERE code_hash=?").run(codeHash);
      return {
        code, userId: String(row["user_id"]), sessionId: String(row["session_id"]),
        audience,
        intent: String(row["intent"]), exp: Number(row["expires_at"]),
      };
    })() ?? null;
  },
};

function hashExchangeState(state: string): string {
  return createHash("sha256").update(state).digest("hex");
}

function hashExchangeCode(code: string): string {
  return createHash("sha256").update(code).digest("hex");
}

const sqliteGoogleStateStore = {
  issue(state: string, nonce: string, exp: number): void {
    db.query("DELETE FROM google_states WHERE expires_at <= ?").run(Math.floor(Date.now() / 1000));
    db.query("INSERT INTO google_states(state,nonce,expires_at) VALUES (?,?,?)").run(state, nonce, exp);
  },
  consume(state: string): { nonce: string } | null {
    const row = db.query("DELETE FROM google_states WHERE state=? AND expires_at>? RETURNING nonce").get(
      state, Math.floor(Date.now() / 1000),
    ) as Row | null;
    return row === null ? null : { nonce: String(row["nonce"]) };
  },
};

function sqliteResetStoresForTests(): void {
  db.run("DELETE FROM provisioning_ledger");
  db.run("DELETE FROM consumed_purpose_tokens");
  db.run("DELETE FROM product_exchange_redirects");
  db.run("DELETE FROM google_states");
  db.run("DELETE FROM oidc_codes");
  db.run("DELETE FROM product_exchange_codes");
  db.run("DELETE FROM sessions");
  db.run("DELETE FROM provider_identities");
  db.run("DELETE FROM users");
}

// ---------------------------------------------------------------------------
// F0 backend delegation. The SQLite objects above stay the fallback; the
// PostgreSQL objects come from createPgStores. Every exported store answers
// from exactly one backend per call, chosen by usePostgres().
// ---------------------------------------------------------------------------

let testPgConn: PgConn | null = null;
let pgCache: PgStores | null = null;

/**
 * Test-only: inject a query connection (PGlite harness) so the whole suite
 * can run against PostgreSQL semantics in-process. Takes precedence over
 * AUTH_STORE_BACKEND. Pass null to restore env-based selection.
 */
export function __setPgConnForTests(conn: PgConn | null): void {
  pgCache = null;
  testPgConn = conn;
}

function pgStores(): PgStores {
  if (pgCache === null) pgCache = createPgStores(testPgConn ?? bunSqlConn(getDatabaseUrl()));
  return pgCache;
}

function usePostgres(): boolean {
  if (testPgConn !== null) return true;
  try {
    return getAuthStoreBackend() === "postgres";
  } catch {
    return false;
  }
}

export const userStore: UserStore = {
  create: (email, passwordHash) =>
    usePostgres() ? pgStores().userStore.create(email, passwordHash) : Promise.resolve(sqliteUserStore.create(email, passwordHash)),
  createWithId: (id, email, passwordHash, emailVerified) =>
    usePostgres()
      ? pgStores().userStore.createWithId(id, email, passwordHash, emailVerified)
      : Promise.resolve(sqliteUserStore.createWithId(id, email, passwordHash, emailVerified)),
  findByEmail: (email) =>
    usePostgres() ? pgStores().userStore.findByEmail(email) : Promise.resolve(sqliteUserStore.findByEmail(email)),
  findByProviderSub: (provider, sub) =>
    usePostgres()
      ? pgStores().userStore.findByProviderSub(provider, sub)
      : Promise.resolve(sqliteUserStore.findByProviderSub(provider, sub)),
  linkIdentity: (userId, provider, sub) =>
    usePostgres()
      ? pgStores().userStore.linkIdentity(userId, provider, sub)
      : Promise.resolve(sqliteUserStore.linkIdentity(userId, provider, sub)),
  findById: (id) =>
    usePostgres() ? pgStores().userStore.findById(id) : Promise.resolve(sqliteUserStore.findById(id)),
  findByIdAndPasswordHash: (id, passwordHash) =>
    usePostgres()
      ? pgStores().userStore.findByIdAndPasswordHash(id, passwordHash)
      : Promise.resolve(sqliteUserStore.findByIdAndPasswordHash(id, passwordHash)),
  setVerified: (id) =>
    usePostgres() ? pgStores().userStore.setVerified(id) : Promise.resolve(sqliteUserStore.setVerified(id)),
  setPasswordHash: (id, hash) =>
    usePostgres() ? pgStores().userStore.setPasswordHash(id, hash) : Promise.resolve(sqliteUserStore.setPasswordHash(id, hash)),
  count: () =>
    usePostgres() ? pgStores().userStore.count() : Promise.resolve(sqliteUserStore.count()),
};

export const sessionStore: SessionStore = {
  create: (userId, refreshHash, ttlMs) =>
    usePostgres()
      ? pgStores().sessionStore.create(userId, refreshHash, ttlMs)
      : Promise.resolve(sqliteSessionStore.create(userId, refreshHash, ttlMs)),
  createWithId: (id, userId, refreshHash, ttlMs) =>
    usePostgres()
      ? pgStores().sessionStore.createWithId(id, userId, refreshHash, ttlMs)
      : Promise.resolve(sqliteSessionStore.createWithId(id, userId, refreshHash, ttlMs)),
  findById: (id) =>
    usePostgres() ? pgStores().sessionStore.findById(id) : Promise.resolve(sqliteSessionStore.findById(id)),
  findByRefreshHash: (hash) =>
    usePostgres()
      ? pgStores().sessionStore.findByRefreshHash(hash)
      : Promise.resolve(sqliteSessionStore.findByRefreshHash(hash)),
  findByRefreshOrPrevHash: (hash) =>
    usePostgres()
      ? pgStores().sessionStore.findByRefreshOrPrevHash(hash)
      : Promise.resolve(sqliteSessionStore.findByRefreshOrPrevHash(hash)),
  rotate: (session, nextHash) =>
    usePostgres()
      ? pgStores().sessionStore.rotate(session, nextHash)
      : Promise.resolve(sqliteSessionStore.rotate(session, nextHash)),
  isReusedHash: (session, hash) =>
    // Pure in-memory predicate — identical on both backends by construction.
    sqliteSessionStore.isReusedHash(session, hash),
  revoke: (session) =>
    usePostgres() ? pgStores().sessionStore.revoke(session) : Promise.resolve(sqliteSessionStore.revoke(session)),
  revokeAllForUser: (userId) =>
    usePostgres()
      ? pgStores().sessionStore.revokeAllForUser(userId)
      : Promise.resolve(sqliteSessionStore.revokeAllForUser(userId)),
  listActiveForUser: (userId) =>
    usePostgres()
      ? pgStores().sessionStore.listActiveForUser(userId)
      : Promise.resolve(sqliteSessionStore.listActiveForUser(userId)),
  revokeByIdForUser: (id, userId) =>
    usePostgres()
      ? pgStores().sessionStore.revokeByIdForUser(id, userId)
      : Promise.resolve(sqliteSessionStore.revokeByIdForUser(id, userId)),
};

export const oidcStore: OidcStore = {
  issue: (userId, redirectUri, clientId, ttlSeconds, pkce) =>
    usePostgres()
      ? pgStores().oidcStore.issue(userId, redirectUri, clientId, ttlSeconds, pkce)
      : Promise.resolve(sqliteOidcStore.issue(userId, redirectUri, clientId, ttlSeconds, pkce)),
  consume: (code, redirectUri, clientId, verifier) =>
    usePostgres()
      ? pgStores().oidcStore.consume(code, redirectUri, clientId, verifier)
      : Promise.resolve(sqliteOidcStore.consume(code, redirectUri, clientId, verifier)),
};

/** Single-use ledger for verify/reset purpose tokens (task 38). Returns true
 *  on first use; false when the token hash is already recorded (replay). */
export function markPurposeConsumed(tokenHash: string): Promise<boolean> {
  return usePostgres()
    ? pgStores().purposeLedger.markPurposeConsumed(tokenHash)
    : Promise.resolve(sqliteMarkPurposeConsumed(tokenHash));
}

export const productExchangeStore: ProductExchangeStore = {
  issue: (userId, sessionId, audience, intent, ttlSeconds) =>
    usePostgres()
      ? pgStores().productExchangeStore.issue(userId, sessionId, audience, intent, ttlSeconds)
      : Promise.resolve(sqliteProductExchangeStore.issue(userId, sessionId, audience, intent, ttlSeconds)),
  issueForRedirect: (userId, sessionId, audience, intent, redirectUri, state, ttlSeconds) =>
    usePostgres()
      ? pgStores().productExchangeStore.issueForRedirect(userId, sessionId, audience, intent, redirectUri, state, ttlSeconds)
      : Promise.resolve(
        sqliteProductExchangeStore.issueForRedirect(userId, sessionId, audience, intent, redirectUri, state, ttlSeconds),
      ),
  consume: (code, audience, intent) =>
    usePostgres()
      ? pgStores().productExchangeStore.consume(code, audience, intent)
      : Promise.resolve(sqliteProductExchangeStore.consume(code, audience, intent)),
  consumeForRedirect: (code, audience, intent, redirectUri, state) =>
    usePostgres()
      ? pgStores().productExchangeStore.consumeForRedirect(code, audience, intent, redirectUri, state)
      : Promise.resolve(
        sqliteProductExchangeStore.consumeForRedirect(code, audience, intent, redirectUri, state),
      ),
};

export const googleStateStore: GoogleStateStore = {
  issue: (state, nonce, exp) =>
    usePostgres()
      ? pgStores().googleStateStore.issue(state, nonce, exp)
      : Promise.resolve(sqliteGoogleStateStore.issue(state, nonce, exp)),
  consume: (state) =>
    usePostgres()
      ? pgStores().googleStateStore.consume(state)
      : Promise.resolve(sqliteGoogleStateStore.consume(state)),
};

function randomHex(bytes: number): string {
  const buffer = new Uint8Array(bytes);
  crypto.getRandomValues(buffer);
  let hex = "";
  for (const byte of buffer) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

export function resetStoresForTests(): Promise<void> {
  if (usePostgres()) return pgStores().resetStoresForTests();
  sqliteResetStoresForTests();
  return Promise.resolve();
}

if (nodeEnv() === "test") void resetStoresForTests();
