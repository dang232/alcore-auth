import { Database } from "bun:sqlite";
import { createHash } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { getAuthDatabasePath, nodeEnv } from "../config";

export interface User {
  readonly id: string;
  readonly email: string;
  readonly passwordHash: string | null;
  readonly emailVerified: boolean;
  readonly createdAt: string;
}

export interface Session {
  readonly id: string;
  readonly userId: string;
  refreshHash: string;
  prevHashes: Set<string>;
  readonly createdAt: number;
  readonly expiresAt: number;
  revoked: boolean;
}

export interface OidcCode {
  readonly code: string;
  readonly userId: string;
  readonly redirectUri: string;
  readonly clientId: string;
  readonly exp: number;
  used: boolean;
}

type ProductAudience = "tokenpanel" | "libre";

export interface ProductExchangeCode {
  readonly code: string;
  readonly userId: string;
  readonly sessionId: string;
  readonly audience: ProductAudience;
  readonly intent: string;
  readonly exp: number;
}

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
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
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
  CREATE TABLE IF NOT EXISTS google_states (
    state TEXT PRIMARY KEY,
    nonce TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id);
`);
if (!db.query("PRAGMA table_info(oidc_codes)").all().some((column) => {
  return typeof column === "object" && column !== null && "name" in column && column.name === "client_id";
})) {
  db.run("ALTER TABLE oidc_codes ADD COLUMN client_id TEXT NOT NULL DEFAULT ''");
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

export const userStore = {
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
};

export const sessionStore = {
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
  rotate(session: Session, nextHash: string): void {
    session.prevHashes.add(session.refreshHash);
    session.refreshHash = nextHash;
    db.query("UPDATE sessions SET refresh_hash=?,previous_hashes=? WHERE id=? AND revoked=0").run(
      nextHash, JSON.stringify([...session.prevHashes]), session.id,
    );
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
};

export const oidcStore = {
  issue(userId: string, redirectUri: string, clientId: string, ttlSeconds: number): OidcCode {
    const record: OidcCode = {
      code: randomHex(16), userId, redirectUri, clientId,
      exp: Math.floor(Date.now() / 1000) + ttlSeconds, used: false,
    };
    db.query("INSERT INTO oidc_codes (code,user_id,redirect_uri,client_id,expires_at,used) VALUES (?,?,?,?,?,0)").run(
      record.code, record.userId, record.redirectUri, record.clientId, record.exp,
    );
    return record;
  },
  consume(code: string, redirectUri: string, clientId: string): OidcCode | null {
    const row = db.query("UPDATE oidc_codes SET used=1 WHERE code=? AND redirect_uri=? AND client_id=? AND expires_at>? AND used=0 RETURNING code,user_id,redirect_uri,client_id,expires_at").get(
      code, redirectUri, clientId, Math.floor(Date.now() / 1000),
    ) as Row | null;
    if (row === null) return null;
    return {
      code: String(row["code"]), userId: String(row["user_id"]),
      redirectUri: String(row["redirect_uri"]), clientId: String(row["client_id"]), exp: Number(row["expires_at"]), used: true,
    };
  },
};

export const productExchangeStore = {
  issue(userId: string, sessionId: string, audience: ProductAudience, intent: string, ttlSeconds: number): string {
    const code = randomHex(32);
    const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
    db.query("INSERT INTO product_exchange_codes (code_hash,user_id,session_id,audience,intent,expires_at,used) VALUES (?,?,?,?,?,?,0)").run(
      hashExchangeCode(code), userId, sessionId, audience, intent, exp,
    );
    return code;
  },
  consume(code: string, audience: ProductAudience, intent: string): ProductExchangeCode | null {
    const row = db.query("UPDATE product_exchange_codes SET used=1 WHERE code_hash=? AND audience=? AND intent=? AND expires_at>? AND used=0 RETURNING user_id,session_id,audience,intent,expires_at").get(
      hashExchangeCode(code), audience, intent, Math.floor(Date.now() / 1000),
    ) as Row | null;
    if (row === null) return null;
    return {
      code, userId: String(row["user_id"]), sessionId: String(row["session_id"]),
      audience,
      intent: String(row["intent"]), exp: Number(row["expires_at"]),
    };
  },
};

function hashExchangeCode(code: string): string {
  return createHash("sha256").update(code).digest("hex");
}

export const googleStateStore = {
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

function randomHex(bytes: number): string {
  const buffer = new Uint8Array(bytes);
  crypto.getRandomValues(buffer);
  let hex = "";
  for (const byte of buffer) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

export function resetStoresForTests(): void {
  db.run("DELETE FROM google_states");
  db.run("DELETE FROM oidc_codes");
  db.run("DELETE FROM product_exchange_codes");
  db.run("DELETE FROM sessions");
  db.run("DELETE FROM provider_identities");
  db.run("DELETE FROM users");
}

if (nodeEnv() === "test") resetStoresForTests();
