// Task 37 unit scope: Redis auth:* throttle via an in-test fake with atomic
// script semantics. No servers spawned; live two-instance + outage proofs are
// the next run. Dummy values only, no secrets.
import { describe, expect, test } from "bun:test";
import {
  THROTTLE_LUA,
  checkAuthThrottle,
  createRateLimiter,
  createRedisRateLimiter,
  scopeToBucket,
  throttleBackendKind,
  type ThrottleConn,
} from "../src/lib/ratelimit";

/** Single-threaded fake: incrWithTtl is one indivisible step, matching the
 *  Lua script's atomicity (INCR + PEXPIRE-on-first + PTTL). */
function makeFake(opts: { dead?: boolean; poisonError?: unknown } = {}): ThrottleConn & {
  keys: string[];
  store: Map<string, { count: number; resetAt: number }>;
} {
  const store = new Map<string, { count: number; resetAt: number }>();
  const keys: string[] = [];
  return {
    keys,
    store,
    async incrWithTtl(key: string, windowMs: number) {
      if (opts.dead) throw opts.poisonError ?? new Error("ECONNREFUSED 127.0.0.1:6379");
      keys.push(key);
      const now = Date.now();
      const b = store.get(key);
      if (b === undefined || now >= b.resetAt) {
        store.set(key, { count: 1, resetAt: now + windowMs });
        return { count: 1, ttlMs: windowMs };
      }
      b.count += 1;
      return { count: b.count, ttlMs: Math.max(0, b.resetAt - now) };
    },
  };
}

describe("scopeToBucket: contract-exact auth:* buckets", () => {
  test("every live call-site scope maps to its API-CONTRACT bucket", () => {
    expect(scopeToBucket("register")).toBe("auth:register");
    expect(scopeToBucket("login")).toBe("auth:login");
    expect(scopeToBucket("refresh")).toBe("auth:refresh");
    expect(scopeToBucket("verify")).toBe("auth:verify");
    expect(scopeToBucket("reset")).toBe("auth:reset");
    expect(scopeToBucket("google")).toBe("auth:oauth");
    expect(scopeToBucket("google-verify")).toBe("auth:oauth");
    expect(scopeToBucket("oidc")).toBe("auth:oidc");
    expect(scopeToBucket("exchange")).toBe("auth:exchange");
    expect(scopeToBucket("exchange-redirect")).toBe("auth:exchange");
  });
  test("unknown scopes stay inside auth:, never bare or product-owned", () => {
    const b = scopeToBucket("session-write");
    expect(b.startsWith("auth:")).toBe(true);
  });
});

describe("throttleBackendKind: existing env keys, no config.ts edits", () => {
  test("redis only when THROTTLE_BACKEND=redis AND REDIS_URL set", () => {
    expect(throttleBackendKind({ THROTTLE_BACKEND: "redis", REDIS_URL: "redis://localhost:6379" })).toBe("redis");
    expect(throttleBackendKind({ THROTTLE_BACKEND: "redis" })).toBe("memory");
    expect(throttleBackendKind({ REDIS_URL: "redis://localhost:6379" })).toBe("memory");
    expect(throttleBackendKind({})).toBe("memory");
    expect(throttleBackendKind({ THROTTLE_BACKEND: "memory", REDIS_URL: "redis://localhost:6379" })).toBe("memory");
  });
});

describe("Redis limiter over shared backend (two-instance model)", () => {
  test("two limiter instances share one counter; 31st request denied with Retry-After", async () => {
    const fake = makeFake();
    const a = createRedisRateLimiter(fake, 60_000, 30);
    const b = createRedisRateLimiter(fake, 60_000, 30);
    for (let i = 0; i < 15; i++) {
      expect((await a("auth:login:10.0.0.9")).ok).toBe(true);
      expect((await b("auth:login:10.0.0.9")).ok).toBe(true);
    }
    const over = await a("auth:login:10.0.0.9");
    expect(over.ok).toBe(false);
    expect(over.retryAfterMs).toBeGreaterThan(0);
    expect(over.unavailable).toBeUndefined();
  });
  test("every key written is auth:-namespaced; product namespaces untouched", async () => {
    const fake = makeFake();
    await checkAuthThrottle(fake, "login", "10.0.0.9");
    await checkAuthThrottle(fake, "register", "10.0.0.9");
    await checkAuthThrottle(fake, "reset", "10.0.0.9");
    await checkAuthThrottle(fake, "google", "10.0.0.9");
    await checkAuthThrottle(fake, "oidc", "10.0.0.9");
    await checkAuthThrottle(fake, "exchange", "10.0.0.9");
    expect(fake.keys.length).toBeGreaterThan(0);
    for (const k of fake.keys) expect(k.startsWith("auth:")).toBe(true);
    expect(fake.keys).toContain("auth:login:10.0.0.9");
    expect(fake.keys).toContain("auth:register:10.0.0.9");
    expect(fake.keys).toContain("auth:oauth:10.0.0.9");
  });
  test("restart keeps budget: new limiter over same backend retains counts", async () => {
    const fake = makeFake();
    const before = createRedisRateLimiter(fake, 60_000, 30);
    for (let i = 0; i < 30; i++) await before("auth:refresh:10.0.0.7");
    const afterRestart = createRedisRateLimiter(fake, 60_000, 30);
    const r = await afterRestart("auth:refresh:10.0.0.7");
    expect(r.ok).toBe(false);
  });
  test("memory path resets on restart (documented TARGET deviation, non-prod only)", () => {
    const fresh = createRateLimiter(60_000, 30);
    for (let i = 0; i < 30; i++) fresh("login:10.0.0.7");
    expect(fresh("login:10.0.0.7").ok).toBe(false);
    const restarted = createRateLimiter(60_000, 30);
    expect(restarted("login:10.0.0.7").ok).toBe(true);
  });
});

describe("fail-closed on Redis outage", () => {
  test("dead backend denies with unavailable flag, never throws, no secret leak", async () => {
    const secretUrl = "redis://:dummy-secret-9f8@redis.internal:6379/0";
    const fake = makeFake({ dead: true, poisonError: new Error(`connect ${secretUrl}`) });
    const limit = createRedisRateLimiter(fake, 60_000, 30);
    const r = await limit("auth:login:10.0.0.8");
    expect(r.ok).toBe(false);
    expect(r.unavailable).toBe(true);
    expect(r.retryAfterMs).toBeGreaterThan(0);
    expect(JSON.stringify(r)).not.toContain("dummy-secret-9f8");
    expect(JSON.stringify(r)).not.toContain("redis.internal");
  });
  test("mid-flight outage: allowed-then-dead flips to closed, never open", async () => {
    const fake = makeFake();
    const limit = createRedisRateLimiter(fake, 60_000, 30);
    expect((await limit("auth:verify:10.0.0.8")).ok).toBe(true);
    const dead = makeFake({ dead: true });
    const closedLimit = createRedisRateLimiter(dead, 60_000, 30);
    for (let i = 0; i < 40; i++) {
      const r = await closedLimit("auth:verify:10.0.0.8");
      expect(r.ok).toBe(false);
      expect(r.unavailable).toBe(true);
    }
  });
});

describe("Lua script shape (atomicity contract)", () => {
  test("single script does INCR + conditional PEXPIRE + PTTL", () => {
    expect(THROTTLE_LUA).toContain("INCR");
    expect(THROTTLE_LUA).toContain("PEXPIRE");
    expect(THROTTLE_LUA).toContain("PTTL");
  });
});
