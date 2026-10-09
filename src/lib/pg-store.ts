// ALcore Auth Repo C — PostgreSQL repository backend (F0 target topology).
//
// Same repository interface as src/lib/store.ts (SQLite fallback), over a
// minimal query connection. Production client is Bun's built-in SQL
// (bunSqlConn — zero new prod dependencies; AlRepo is MongoDB so the
// monorepo offers no pg client precedent, and heavy ORMs are banned by the
// lane). Tests/proof use pgliteConn (real PostgreSQL engine, in-process;
// chosen because this dev box has no Docker daemon for a scratch server).
//
// SQL is strictly standard (RETURNING + ON CONFLICT + lower() uniqueness,
// no extensions) so statements proven here run unchanged on managed PG.
// Detection never relies on driver rowCount (drivers differ); every
// write that needs an outcome uses RETURNING and inspects rows.
//
// Invariants preserved from the SQLite store: Argon2id hashes opaque,
// single-use codes via UPDATE...used=0 RETURNING, atomic CAS rotate,
// reuse-family revoke, PKCE-before-burn, hash-keyed single-use ledgers,
// case-insensitive email identity, audit stays in the in-memory ring
// (emission only — persistence/export is a later SECURITY-AUDIT row).

import { createHash } from "node:crypto";
import { SQL } from "bun";
import { hashEqual, verifyPkceS256 } from "./crypto";
import type {
  GoogleStateStore,
  IdeRefreshRecord,
  IdeRefreshStore,
  IdentityLinkResult,
  OidcCode,
  OidcStore,
  ProductAudience,
  ProductExchangeCode,
  ProductExchangeStore,
  PurposeLedger,
  Session,
  SessionStore,
  User,
  UserStore,
} from "./auth-models";

export type PgRow = Record<string, unknown>;

export interface PgTx {
  query<T = PgRow>(text: string, params?: unknown[]): Promise<T[]>;
}

export interface PgConn extends PgTx {
  transaction<T>(fn: (tx: PgTx) => Promise<T>): Promise<T>;
}

/** Production adapter over Bun's built-in SQL client (DATABASE_URL). */
export function bunSqlConn(url: string): PgConn & { close(): Promise<void> } {
  const sql = new SQL(url);
  const toRows = (raw: unknown): PgRow[] =>
    (Array.isArray(raw) ? raw : []) as PgRow[];
  const txShape = (executor: Pick<InstanceType<typeof SQL>, "unsafe">): PgTx => ({
    query: async <T = PgRow>(text: string, params: unknown[] = []): Promise<T[]> =>
      toRows(await executor.unsafe(text, params)) as T[],
  });
  const base = txShape(sql);
  return {
    query: base.query,
    transaction: <T>(fn: (tx: PgTx) => Promise<T>): Promise<T> =>
      sql.begin(async (tx) => fn(txShape(tx))),
    close: () => sql.close(),
  };
}

/** Minimal structural PGlite shape (dev/proof only — never imported by prod). */
export interface PGliteLike {
  query: (text: string, params?: unknown[]) => Promise<{ rows: unknown[] }>;
  transaction: <T>(fn: (tx: { query: (text: string, params?: unknown[]) => Promise<{ rows: unknown[] }> }) => Promise<T>) => Promise<T>;
}

/** Test/proof adapter over an in-process PGlite (real PG engine). */
export function pgliteConn(db: PGliteLike): PgConn {
  const shape = (executor: {
    query: (text: string, params?: unknown[]) => Promise<{ rows: unknown[] }>;
  }): PgTx => ({
    query: async <T = PgRow>(text: string, params: unknown[] = []): Promise<T[]> =>
      ((await executor.query(text, params)).rows ?? []) as T[],
  });
  const base = shape(db);
  return {
    query: base.query,
    transaction: <T>(fn: (tx: PgTx) => Promise<T>): Promise<T> =>
      db.transaction(async (tx) => fn(shape(tx))),
  };
}

function userFromRow(row: PgRow | undefined): User | undefined {
  if (row === undefined) return undefined;
  return {
    id: String(row["id"]),
    email: String(row["email"]),
    passwordHash: typeof row["password_hash"] === "string" ? row["password_hash"] : null,
    emailVerified: Number(row["email_verified"]) === 1,
    createdAt: String(row["created_at"]),
  };
}

function sessionFromRow(row: PgRow | undefined): Session | undefined {
  if (row === undefined) return undefined;
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

function isUniqueViolation(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return false;
  const code = (error as Record<string, unknown>)["code"];
  if (code === 23505 || code === "23505") return true;
  const msg = error instanceof Error ? error.message : String(error);
  return /duplicate key|UNIQUE constraint failed/i.test(msg);
}

function hashExchangeState(state: string): string {
  return createHash("sha256").update(state).digest("hex");
}

function hashExchangeCode(code: string): string {
  return createHash("sha256").update(code).digest("hex");
}

function randomHex(bytes: number): string {
  const buffer = new Uint8Array(bytes);
  crypto.getRandomValues(buffer);
  let hex = "";
  for (const byte of buffer) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

export interface PgStores {
  readonly userStore: UserStore;
  readonly sessionStore: SessionStore;
  readonly ideRefreshStore: IdeRefreshStore;
  readonly oidcStore: OidcStore;
  readonly productExchangeStore: ProductExchangeStore;
  readonly googleStateStore: GoogleStateStore;
  readonly purposeLedger: PurposeLedger;
  resetStoresForTests(): Promise<void>;
}

export function createPgStores(conn: PgConn): PgStores {
  const userStore: UserStore = {
    async create(email, passwordHash): Promise<User> {
      const user: User = {
        id: crypto.randomUUID(),
        email,
        passwordHash,
        emailVerified: false,
        createdAt: new Date().toISOString(),
      };
      try {
        await conn.query(
          "INSERT INTO users (id,email,password_hash,email_verified,created_at) VALUES ($1,$2,$3,0,$4)",
          [user.id, user.email, user.passwordHash, user.createdAt],
        );
        return user;
      } catch (error) {
        if (isUniqueViolation(error)) {
          const existing = await this.findByEmail(email);
          if (existing !== undefined) return existing;
        }
        throw error;
      }
    },
    async createWithId(id, email, passwordHash, emailVerified): Promise<User> {
      const user: User = {
        id, email, passwordHash, emailVerified, createdAt: new Date().toISOString(),
      };
      await conn.query(
        "INSERT INTO users (id,email,password_hash,email_verified,created_at) VALUES ($1,$2,$3,$4,$5)",
        [user.id, user.email, user.passwordHash, user.emailVerified ? 1 : 0, user.createdAt],
      );
      return user;
    },
    async findByEmail(email): Promise<User | undefined> {
      const rows = await conn.query<PgRow>("SELECT * FROM users WHERE lower(email)=lower($1)", [email]);
      return userFromRow(rows[0]);
    },
    async findByProviderSub(provider, sub): Promise<User | undefined> {
      const rows = await conn.query<PgRow>(
        "SELECT users.* FROM provider_identities JOIN users ON users.id=provider_identities.user_id WHERE provider=$1 AND subject=$2",
        [provider, sub],
      );
      return userFromRow(rows[0]);
    },
    async linkIdentity(userId, provider, sub): Promise<IdentityLinkResult> {
      const inserted = await conn.query<PgRow>(
        "INSERT INTO provider_identities (provider,subject,user_id) VALUES ($1,$2,$3) ON CONFLICT(provider,subject) DO NOTHING RETURNING user_id",
        [provider, sub, userId],
      );
      if (inserted.length === 1) return "linked";
      const owner = await conn.query<PgRow>(
        "SELECT user_id FROM provider_identities WHERE provider=$1 AND subject=$2",
        [provider, sub],
      );
      const ownerId = owner[0] === undefined ? null : String(owner[0]["user_id"]);
      return ownerId === userId ? "already_linked" : "owned_by_other_user";
    },
    async findById(id): Promise<User | undefined> {
      const rows = await conn.query<PgRow>("SELECT * FROM users WHERE id=$1", [id]);
      return userFromRow(rows[0]);
    },
    async findByIdAndPasswordHash(id, passwordHash): Promise<User | undefined> {
      const rows = await conn.query<PgRow>("SELECT * FROM users WHERE id=$1 AND password_hash=$2", [id, passwordHash]);
      return userFromRow(rows[0]);
    },
    async setVerified(id): Promise<void> {
      await conn.query("UPDATE users SET email_verified=1 WHERE id=$1", [id]);
    },
    async setPasswordHash(id, hash): Promise<void> {
      await conn.query("UPDATE users SET password_hash=$1 WHERE id=$2", [hash, id]);
    },
    async count(): Promise<number> {
      const rows = await conn.query<PgRow>("SELECT COUNT(*) AS c FROM users");
      return Number(rows[0]?.["c"] ?? 0);
    },
  };

  const sessionStore: SessionStore = {
    async create(userId, refreshHash, ttlMs): Promise<Session> {
      const now = Date.now();
      const session: Session = {
        id: crypto.randomUUID(), userId, refreshHash,
        prevHashes: new Set<string>(), createdAt: now,
        expiresAt: now + ttlMs, revoked: false,
      };
      await conn.query(
        "INSERT INTO sessions (id,user_id,refresh_hash,previous_hashes,created_at,expires_at,revoked) VALUES ($1,$2,$3,$4,$5,$6,0)",
        [session.id, session.userId, session.refreshHash, "[]", session.createdAt, session.expiresAt],
      );
      return session;
    },
    async createWithId(id, userId, refreshHash, ttlMs): Promise<Session> {
      const now = Date.now();
      const session: Session = {
        id, userId, refreshHash, prevHashes: new Set<string>(),
        createdAt: now, expiresAt: now + ttlMs, revoked: false,
      };
      await conn.query(
        "INSERT INTO sessions (id,user_id,refresh_hash,previous_hashes,created_at,expires_at,revoked) VALUES ($1,$2,$3,$4,$5,$6,0)",
        [session.id, session.userId, session.refreshHash, "[]", session.createdAt, session.expiresAt],
      );
      return session;
    },
    async findById(id): Promise<Session | undefined> {
      const rows = await conn.query<PgRow>("SELECT * FROM sessions WHERE id=$1", [id]);
      return sessionFromRow(rows[0]);
    },
    async findByRefreshHash(hash): Promise<Session | undefined> {
      const rows = await conn.query<PgRow>("SELECT * FROM sessions WHERE refresh_hash=$1", [hash]);
      return sessionFromRow(rows[0]);
    },
    async findByRefreshOrPrevHash(hash): Promise<Session | undefined> {
      const live = await conn.query<PgRow>("SELECT * FROM sessions WHERE refresh_hash=$1", [hash]);
      if (live[0] !== undefined) return sessionFromRow(live[0]);
      const prev = await conn.query<PgRow>("SELECT * FROM sessions WHERE previous_hashes LIKE $1", [`%${hash}%`]);
      return sessionFromRow(prev[0]);
    },
    async rotate(session, nextHash): Promise<boolean> {
      const merged = [...session.prevHashes, session.refreshHash];
      const rows = await conn.query<PgRow>(
        "UPDATE sessions SET refresh_hash=$1,previous_hashes=$2 WHERE id=$3 AND refresh_hash=$4 AND revoked=0 RETURNING id",
        [nextHash, JSON.stringify(merged), session.id, session.refreshHash],
      );
      if (rows.length === 0) return false;
      session.prevHashes.add(session.refreshHash);
      session.refreshHash = nextHash;
      return true;
    },
    isReusedHash(session, hash): boolean {
      return session.prevHashes.has(hash);
    },
    async revoke(session): Promise<void> {
      session.revoked = true;
      await conn.query("UPDATE sessions SET revoked=1 WHERE id=$1", [session.id]);
    },
    async revokeAllForUser(userId): Promise<void> {
      await conn.query("UPDATE sessions SET revoked=1 WHERE user_id=$1 AND revoked=0", [userId]);
    },
    async listActiveForUser(userId): Promise<Session[]> {
      const rows = await conn.query<PgRow>(
        "SELECT * FROM sessions WHERE user_id=$1 AND revoked=0 ORDER BY created_at ASC",
        [userId],
      );
      return rows
        .map((row) => sessionFromRow(row))
        .filter((s): s is Session => s !== undefined);
    },
    async revokeByIdForUser(id, userId): Promise<boolean> {
      const rows = await conn.query<PgRow>(
        "UPDATE sessions SET revoked=1 WHERE id=$1 AND user_id=$2 AND revoked=0 RETURNING id",
        [id, userId],
      );
      return rows.length === 1;
    },
  };

function ideRefreshFromRow(row: PgRow | undefined): IdeRefreshRecord | undefined {
  if (row === undefined) return undefined;
  let scopes: string[] = [];
  try {
    const parsed: unknown = JSON.parse(String(row["scopes"]));
    if (Array.isArray(parsed)) scopes = parsed.filter((s): s is string => typeof s === "string");
  } catch {
    scopes = [];
  }
  return {
    familyId: String(row["family_id"]),
    userId: String(row["user_id"]),
    tokenHash: String(row["token_hash"]),
    prevHashes: new Set(JSON.parse(String(row["previous_hashes"])) as string[]),
    scopes,
    createdAt: Number(row["created_at"]),
    expiresAt: Number(row["expires_at"]),
    revoked: Number(row["revoked"]) === 1,
  };
}

  const oidcStore: OidcStore = {
    async issue(userId, redirectUri, clientId, ttlSeconds, pkce): Promise<OidcCode> {
      const record: OidcCode = {
        code: randomHex(16), userId, redirectUri, clientId,
        exp: Math.floor(Date.now() / 1000) + ttlSeconds, used: false,
        codeChallenge: pkce?.challenge ?? "",
        codeChallengeMethod: pkce?.method ?? "",
      };
      await conn.query(
        "INSERT INTO oidc_codes (code,user_id,redirect_uri,client_id,code_challenge,code_challenge_method,expires_at,used) VALUES ($1,$2,$3,$4,$5,$6,$7,0)",
        [record.code, record.userId, record.redirectUri, record.clientId,
          record.codeChallenge, record.codeChallengeMethod, record.exp],
      );
      return record;
    },
    async consume(code, redirectUri, clientId, verifier): Promise<OidcCode | null> {
      // PKCE-bound codes require the matching verifier BEFORE the single-use
      // UPDATE so a wrong verifier never burns the code (same order as SQLite).
      const peek = await conn.query<PgRow>("SELECT code_challenge FROM oidc_codes WHERE code=$1", [code]);
      if (peek[0] !== undefined) {
        const challenge = String(peek[0]["code_challenge"] ?? "");
        if (challenge !== "") {
          if (verifier === undefined || verifier === "" || !verifyPkceS256(verifier, challenge)) return null;
        }
      }
      const rows = await conn.query<PgRow>(
        "UPDATE oidc_codes SET used=1 WHERE code=$1 AND redirect_uri=$2 AND client_id=$3 AND expires_at>$4 AND used=0 RETURNING code,user_id,redirect_uri,client_id,code_challenge,code_challenge_method,expires_at",
        [code, redirectUri, clientId, Math.floor(Date.now() / 1000)],
      );
      const row = rows[0];
      if (row === undefined) return null;
      return {
        code: String(row["code"]), userId: String(row["user_id"]),
        redirectUri: String(row["redirect_uri"]), clientId: String(row["client_id"]),
        exp: Number(row["expires_at"]), used: true,
        codeChallenge: String(row["code_challenge"] ?? ""),
        codeChallengeMethod: String(row["code_challenge_method"] ?? ""),
      };
    },
  };

  const ideRefreshStore: IdeRefreshStore = {
    async issue(userId, tokenHash, scopes, ttlMs): Promise<IdeRefreshRecord> {
      const now = Date.now();
      const record: IdeRefreshRecord = {
        familyId: crypto.randomUUID(),
        userId,
        tokenHash,
        prevHashes: new Set<string>(),
        scopes: [...scopes],
        createdAt: now,
        expiresAt: now + ttlMs,
        revoked: false,
      };
      await conn.query(
        "INSERT INTO ide_refresh_tokens (family_id,user_id,token_hash,previous_hashes,scopes,created_at,expires_at,revoked) VALUES ($1,$2,$3,$4,$5,$6,$7,0)",
        [record.familyId, record.userId, record.tokenHash, "[]", JSON.stringify(record.scopes), record.createdAt, record.expiresAt],
      );
      return record;
    },
    async findByTokenHash(hash): Promise<IdeRefreshRecord | undefined> {
      const rows = await conn.query<PgRow>("SELECT * FROM ide_refresh_tokens WHERE token_hash=$1", [hash]);
      return ideRefreshFromRow(rows[0]);
    },
    async findByTokenOrPrevHash(hash): Promise<IdeRefreshRecord | undefined> {
      const live = await conn.query<PgRow>("SELECT * FROM ide_refresh_tokens WHERE token_hash=$1", [hash]);
      if (live[0] !== undefined) return ideRefreshFromRow(live[0]);
      const prev = await conn.query<PgRow>("SELECT * FROM ide_refresh_tokens WHERE previous_hashes LIKE $1", [`%${hash}%`]);
      for (const row of prev) {
        const record = ideRefreshFromRow(row);
        if (record !== undefined) {
          let hit = false;
          for (const candidate of record.prevHashes) {
            if (hashEqual(candidate, hash)) hit = true;
          }
          if (hit) return record;
        }
      }
      return undefined;
    },
    async rotate(record, nextHash): Promise<boolean> {
      const merged = [...record.prevHashes, record.tokenHash];
      const rows = await conn.query<PgRow>(
        "UPDATE ide_refresh_tokens SET token_hash=$1,previous_hashes=$2 WHERE family_id=$3 AND token_hash=$4 AND revoked=0 RETURNING family_id",
        [nextHash, JSON.stringify(merged), record.familyId, record.tokenHash],
      );
      if (rows.length === 0) return false;
      record.prevHashes.add(record.tokenHash);
      record.tokenHash = nextHash;
      return true;
    },
    isReusedHash(record, hash): boolean {
      let hit = false;
      for (const prev of record.prevHashes) {
        if (hashEqual(prev, hash)) hit = true;
      }
      return hit;
    },
    async revokeFamily(familyId): Promise<void> {
      await conn.query("UPDATE ide_refresh_tokens SET revoked=1 WHERE family_id=$1", [familyId]);
    },
  };

  const purposeLedger: PurposeLedger = {
    async markPurposeConsumed(tokenHash): Promise<boolean> {
      try {
        const rows = await conn.query<PgRow>(
          "INSERT INTO consumed_purpose_tokens (token_hash,consumed_at) VALUES ($1,$2) ON CONFLICT(token_hash) DO NOTHING RETURNING token_hash",
          [tokenHash, Date.now()],
        );
        return rows.length === 1;
      } catch {
        return false;
      }
    },
  };

  const productExchangeStore: ProductExchangeStore = {
    async issue(userId, sessionId, audience, intent, ttlSeconds): Promise<string> {
      const code = randomHex(32);
      const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
      await conn.query(
        "INSERT INTO product_exchange_codes (code_hash,user_id,session_id,audience,intent,expires_at,used) VALUES ($1,$2,$3,$4,$5,$6,0)",
        [hashExchangeCode(code), userId, sessionId, audience, intent, exp],
      );
      return code;
    },
    async issueForRedirect(userId, sessionId, audience, intent, redirectUri, state, ttlSeconds): Promise<string> {
      const code = randomHex(32);
      const codeHash = hashExchangeCode(code);
      const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
      await conn.transaction(async (tx) => {
        await tx.query(
          "INSERT INTO product_exchange_codes (code_hash,user_id,session_id,audience,intent,expires_at,used) VALUES ($1,$2,$3,$4,$5,$6,0)",
          [codeHash, userId, sessionId, audience, intent, exp],
        );
        await tx.query(
          "INSERT INTO product_exchange_redirects (code_hash,redirect_uri,state_hash,expires_at) VALUES ($1,$2,$3,$4)",
          [codeHash, redirectUri, hashExchangeState(state), exp],
        );
      });
      return code;
    },
    async consume(code, audience, intent): Promise<ProductExchangeCode | null> {
      const codeHash = hashExchangeCode(code);
      // Redirect-bound codes refuse the binding-free path (same rule as SQLite).
      const bound = await conn.query<PgRow>("SELECT 1 FROM product_exchange_redirects WHERE code_hash=$1", [codeHash]);
      if (bound.length > 0) return null;
      const rows = await conn.query<PgRow>(
        "UPDATE product_exchange_codes SET used=1 WHERE code_hash=$1 AND audience=$2 AND intent=$3 AND expires_at>$4 AND used=0 RETURNING user_id,session_id,audience,intent,expires_at",
        [codeHash, audience, intent, Math.floor(Date.now() / 1000)],
      );
      const row = rows[0];
      if (row === undefined) return null;
      return {
        code, userId: String(row["user_id"]), sessionId: String(row["session_id"]),
        audience,
        intent: String(row["intent"]), exp: Number(row["expires_at"]),
      };
    },
    async consumeForRedirect(code, audience, intent, redirectUri, state): Promise<ProductExchangeCode | null> {
      const codeHash = hashExchangeCode(code);
      const now = Math.floor(Date.now() / 1000);
      return conn.transaction(async (tx): Promise<ProductExchangeCode | null> => {
        const bindings = await tx.query<PgRow>(
          "SELECT redirect_uri,state_hash FROM product_exchange_redirects WHERE code_hash=$1 AND expires_at>$2",
          [codeHash, now],
        );
        const binding = bindings[0];
        if (binding === undefined) return null;
        if (String(binding["redirect_uri"]) !== redirectUri) return null;
        if (state !== "" && String(binding["state_hash"]) !== hashExchangeState(state)) return null;
        const rows = await tx.query<PgRow>(
          "UPDATE product_exchange_codes SET used=1 WHERE code_hash=$1 AND audience=$2 AND intent=$3 AND expires_at>$4 AND used=0 RETURNING user_id,session_id,audience,intent,expires_at",
          [codeHash, audience, intent, now],
        );
        const row = rows[0];
        if (row === undefined) return null;
        await tx.query("DELETE FROM product_exchange_redirects WHERE code_hash=$1", [codeHash]);
        return {
          code, userId: String(row["user_id"]), sessionId: String(row["session_id"]),
          audience,
          intent: String(row["intent"]), exp: Number(row["expires_at"]),
        };
      });
    },
  };

  const googleStateStore: GoogleStateStore = {
    async issue(state, nonce, exp): Promise<void> {
      await conn.query("DELETE FROM google_states WHERE expires_at <= $1", [Math.floor(Date.now() / 1000)]);
      await conn.query("INSERT INTO google_states(state,nonce,expires_at) VALUES ($1,$2,$3)", [state, nonce, exp]);
    },
    async consume(state): Promise<{ nonce: string } | null> {
      const rows = await conn.query<PgRow>(
        "DELETE FROM google_states WHERE state=$1 AND expires_at>$2 RETURNING nonce",
        [state, Math.floor(Date.now() / 1000)],
      );
      const row = rows[0];
      return row === undefined ? null : { nonce: String(row["nonce"]) };
    },
  };

  async function resetStoresForTests(): Promise<void> {
    await conn.query("DELETE FROM ide_refresh_tokens");
    await conn.query("DELETE FROM provisioning_ledger");
    await conn.query("DELETE FROM consumed_purpose_tokens");
    await conn.query("DELETE FROM product_exchange_redirects");
    await conn.query("DELETE FROM google_states");
    await conn.query("DELETE FROM oidc_codes");
    await conn.query("DELETE FROM product_exchange_codes");
    await conn.query("DELETE FROM sessions");
    await conn.query("DELETE FROM provider_identities");
    await conn.query("DELETE FROM users");
  }

  return { userStore, sessionStore, ideRefreshStore, oidcStore, productExchangeStore, googleStateStore, purposeLedger, resetStoresForTests };
}
