// ALcore Auth Repo C — shared identity models + repository interfaces (F0).
//
// F0 moves Auth state from file-backed SQLite to managed PostgreSQL while
// keeping ONE repository interface: src/lib/store.ts (SQLite, fallback/test)
// and src/lib/pg-store.ts (PostgreSQL, target topology) both implement these
// interfaces. Routes import the stable names from ../lib/store and must not
// depend on which backend answers.
//
// Async by contract: SQLite answers synchronously under the hood but the
// interface is Promise-based because PostgreSQL I/O is inherently async.
// Same method names, same arguments, same return shapes — only awaited.
//
// Identity-only boundary (task 36a gate, enforced on BOTH backends): users,
// provider_identities, sessions, oidc_codes, consumed_purpose_tokens,
// product_exchange_codes (+redirect bindings), google_states. No business
// tables or entities (customer/billing/balance/usage/subscription/keys).

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
  readonly codeChallenge: string;
  readonly codeChallengeMethod: string;
}

export type ProductAudience = "tokenpanel" | "libre";

export interface ProductExchangeCode {
  readonly code: string;
  readonly userId: string;
  readonly sessionId: string;
  readonly audience: ProductAudience;
  readonly intent: string;
  readonly exp: number;
}

export type IdentityLinkResult = "linked" | "already_linked" | "owned_by_other_user";

export interface UserStore {
  create(email: string, passwordHash: string | null): Promise<User>;
  createWithId(id: string, email: string, passwordHash: string | null, emailVerified: boolean): Promise<User>;
  findByEmail(email: string): Promise<User | undefined>;
  findByProviderSub(provider: string, sub: string): Promise<User | undefined>;
  linkIdentity(userId: string, provider: string, sub: string): Promise<IdentityLinkResult>;
  findById(id: string): Promise<User | undefined>;
  findByIdAndPasswordHash(id: string, passwordHash: string): Promise<User | undefined>;
  setVerified(id: string): Promise<void>;
  setPasswordHash(id: string, hash: string): Promise<void>;
  count(): Promise<number>;
}

export interface SessionStore {
  create(userId: string, refreshHash: string, ttlMs: number): Promise<Session>;
  createWithId(id: string, userId: string, refreshHash: string, ttlMs: number): Promise<Session>;
  findById(id: string): Promise<Session | undefined>;
  findByRefreshHash(hash: string): Promise<Session | undefined>;
  findByRefreshOrPrevHash(hash: string): Promise<Session | undefined>;
  /**
   * Atomic compare-and-swap rotation: wins only when the row still holds the
   * presented hash and is not revoked, so two concurrent refreshes yield
   * exactly one winner. Returns true on win; on loss the in-memory session
   * is left untouched.
   */
  rotate(session: Session, nextHash: string): Promise<boolean>;
  isReusedHash(session: Session, hash: string): boolean;
  revoke(session: Session): Promise<void>;
  revokeAllForUser(userId: string): Promise<void>;
  listActiveForUser(userId: string): Promise<Session[]>;
  revokeByIdForUser(id: string, userId: string): Promise<boolean>;
}

export interface OidcStore {
  issue(
    userId: string,
    redirectUri: string,
    clientId: string,
    ttlSeconds: number,
    pkce?: { readonly challenge: string; readonly method: string },
  ): Promise<OidcCode>;
  consume(code: string, redirectUri: string, clientId: string, verifier?: string): Promise<OidcCode | null>;
}

export interface ProductExchangeStore {
  issue(userId: string, sessionId: string, audience: ProductAudience, intent: string, ttlSeconds: number): Promise<string>;
  issueForRedirect(
    userId: string,
    sessionId: string,
    audience: ProductAudience,
    intent: string,
    redirectUri: string,
    state: string,
    ttlSeconds: number,
  ): Promise<string>;
  consume(code: string, audience: ProductAudience, intent: string): Promise<ProductExchangeCode | null>;
  consumeForRedirect(
    code: string,
    audience: ProductAudience,
    intent: string,
    redirectUri: string,
    state: string,
  ): Promise<ProductExchangeCode | null>;
}

export interface GoogleStateStore {
  issue(state: string, nonce: string, exp: number): Promise<void>;
  consume(state: string): Promise<{ nonce: string } | null>;
}

/** Single-use ledger for verify/reset purpose tokens. True on first use. */
export interface PurposeLedger {
  markPurposeConsumed(tokenHash: string): Promise<boolean>;
}
