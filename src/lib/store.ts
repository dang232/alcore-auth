// ALcore Auth Repo C — in-memory identity stores (scaffold only).
// PROD NEEDS PERSISTENT STORE — downstream. All state resets on restart and
// does not span replicas. Identity-only: users, provider links, sessions,
// OIDC codes. Zero customers/billing/balance/usage/keys/subs entities.

export interface User {
  id: string;
  email: string;
  /** null = OAuth-only account (hashless, link-row), never password login. */
  passwordHash: string | null;
  emailVerified: boolean;
  createdAt: string;
}

export interface Session {
  id: string;
  userId: string;
  refreshHash: string;
  prevHashes: Set<string>;
  createdAt: number;
  expiresAt: number;
  revoked: boolean;
}

export interface OidcCode {
  code: string;
  userId: string;
  redirectUri: string;
  exp: number;
  used: boolean;
}

const usersById = new Map<string, User>();
const usersByEmail = new Map<string, User>();
/** UNIQUE (provider, sub) — same Google sub never creates a dupe user. */
const identitiesByProviderSub = new Map<string, string>();
const sessionsById = new Map<string, Session>();
const sessionsByRefreshHash = new Map<string, string>();
const oidcCodes = new Map<string, OidcCode>();

function identityKey(provider: string, sub: string): string {
  return `${provider}:${sub}`;
}

export const userStore = {
  create(email: string, passwordHash: string | null): User {
    const now = new Date().toISOString();
    const user: User = {
      id: crypto.randomUUID(),
      email,
      passwordHash,
      emailVerified: false,
      createdAt: now,
    };
    usersById.set(user.id, user);
    usersByEmail.set(email, user);
    return user;
  },
  findByEmail(email: string): User | undefined {
    return usersByEmail.get(email);
  },
  findById(id: string): User | undefined {
    return usersById.get(id);
  },
  setVerified(id: string): void {
    const u = usersById.get(id);
    if (u) u.emailVerified = true;
  },
  setPasswordHash(id: string, hash: string): void {
    const u = usersById.get(id);
    if (u) u.passwordHash = hash;
  },
  findByProviderSub(provider: string, sub: string): User | undefined {
    const id = identitiesByProviderSub.get(identityKey(provider, sub));
    return id === undefined ? undefined : usersById.get(id);
  },
  linkIdentity(userId: string, provider: string, sub: string): void {
    identitiesByProviderSub.set(identityKey(provider, sub), userId);
  },
};

export const sessionStore = {
  create(userId: string, refreshHash: string, ttlMs: number): Session {
    const now = Date.now();
    const session: Session = {
      id: crypto.randomUUID(),
      userId,
      refreshHash,
      prevHashes: new Set<string>(),
      createdAt: now,
      expiresAt: now + ttlMs,
      revoked: false,
    };
    sessionsById.set(session.id, session);
    sessionsByRefreshHash.set(refreshHash, session.id);
    return session;
  },
  findById(id: string): Session | undefined {
    return sessionsById.get(id);
  },
  findByRefreshHash(hash: string): Session | undefined {
    const id = sessionsByRefreshHash.get(hash);
    return id === undefined ? undefined : sessionsById.get(id);
  },
  /** Rotate to a new refresh hash; the old hash becomes reuse-detectable. */
  rotate(session: Session, nextHash: string): void {
    sessionsByRefreshHash.delete(session.refreshHash);
    session.prevHashes.add(session.refreshHash);
    session.refreshHash = nextHash;
    sessionsByRefreshHash.set(nextHash, session.id);
  },
  isReusedHash(session: Session, hash: string): boolean {
    return session.prevHashes.has(hash);
  },
  revoke(session: Session): void {
    session.revoked = true;
    sessionsByRefreshHash.delete(session.refreshHash);
  },
  revokeAllForUser(userId: string): void {
    for (const s of sessionsById.values()) {
      if (s.userId === userId && !s.revoked) {
        sessionsById.get(s.id) !== undefined && this.revoke(s);
      }
    }
  },
};

export const oidcStore = {
  issue(userId: string, redirectUri: string, ttlSeconds: number): OidcCode {
    const rec: OidcCode = {
      code: randomHex(16),
      userId,
      redirectUri,
      exp: Math.floor(Date.now() / 1000) + ttlSeconds,
      used: false,
    };
    oidcCodes.set(rec.code, rec);
    return rec;
  },
  /** Single-use consume: marks used before returning. Null = invalid/replayed. */
  consume(code: string, redirectUri: string): OidcCode | null {
    const rec = oidcCodes.get(code);
    if (!rec) return null;
    if (rec.used) return null;
    if (rec.redirectUri !== redirectUri) return null;
    if (rec.exp <= Math.floor(Date.now() / 1000)) {
      oidcCodes.delete(code);
      return null;
    }
    rec.used = true;
    return rec;
  },
};

function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  let hex = "";
  for (const b of buf) hex += b.toString(16).padStart(2, "0");
  return hex;
}

/** Test-only isolation helper (in-memory stores are per-process). */
export function resetStoresForTests(): void {
  usersById.clear();
  usersByEmail.clear();
  identitiesByProviderSub.clear();
  sessionsById.clear();
  sessionsByRefreshHash.clear();
  oidcCodes.clear();
}
