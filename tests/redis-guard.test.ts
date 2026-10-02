// Task 37 guard slice: shared async limitedAsync() over memory + Redis.
// Fake style mirrors redis-throttle.test.ts (atomic single-step fake).
// No servers spawned; dummy values only, no secrets.
import { describe, expect, test } from "bun:test";
import {
  authRateLimit,
  limitedAsync,
  resetRateLimitsForTests,
  resetThrottleConnForTests,
  type ThrottleConn,
} from "../src/lib/ratelimit";

function makeFake(opts: { dead?: boolean; poisonError?: unknown } = {}): ThrottleConn & {
  keys: string[];
} {
  const store = new Map<string, { count: number; resetAt: number }>();
  const keys: string[] = [];
  return {
    keys,
    async incrWithTtl(key: string, windowMs: number) {
      if (opts.dead === true) throw opts.poisonError ?? new Error("ECONNREFUSED 127.0.0.1:6379");
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

function forceMemoryEnv(): () => void {
  const tb = process.env["THROTTLE_BACKEND"];
  const ru = process.env["REDIS_URL"];
  delete process.env["THROTTLE_BACKEND"];
  delete process.env["REDIS_URL"];
  return () => {
    if (tb !== undefined) process.env["THROTTLE_BACKEND"] = tb;
    if (ru !== undefined) process.env["REDIS_URL"] = ru;
  };
}

describe("limitedAsync memory parity with sync authRateLimit", () => {
  test("fresh ip allowed; 31st denied 429 rate_limited, matching sync verdict", async () => {
    const restore = forceMemoryEnv();
    try {
      resetRateLimitsForTests();
      resetThrottleConnForTests();
      const ip = "10.9.0.1";
      const scope = "guardparity";
      const first = await limitedAsync(scope, ip);
      expect(first.limited).toBe(false);
      expect(first.status).toBe(200);
      expect(first.retryAfterSec).toBe(0);
      resetRateLimitsForTests();
      for (let i = 0; i < 30; i++) {
        const r = await limitedAsync(scope, ip);
        expect(r.limited).toBe(false);
      }
      const over = await limitedAsync(scope, ip);
      expect(over.limited).toBe(true);
      expect(over.status).toBe(429);
      expect(over.retryAfterSec).toBeGreaterThanOrEqual(1);
      expect(over.body).toEqual({ error: "rate_limited" });
      expect(JSON.stringify(over)).not.toContain("REDIS_URL");
      const sync = authRateLimit(`${scope}:${ip}`);
      expect(sync.ok).toBe(false);
      expect(over.retryAfterSec).toBe(Math.max(1, Math.ceil(sync.retryAfterMs / 1000)));
    } finally {
      restore();
      resetRateLimitsForTests();
      resetThrottleConnForTests();
    }
  });
});

describe("limitedAsync redis-unavailable fails closed 503", () => {
  test("dead backend denies 503 throttle_unavailable, never throws, no secret leak", async () => {
    resetRateLimitsForTests();
    resetThrottleConnForTests();
    const secretUrl = "redis://:dummy-secret-7g2@redis.internal:6379/0";
    const dead = makeFake({ dead: true, poisonError: new Error(`connect ${secretUrl}`) });
    let r;
    try {
      r = await limitedAsync("login", "10.9.0.2", dead);
    } catch {
      expect.unreachable("limitedAsync must never throw");
    }
    expect(r.limited).toBe(true);
    expect(r.status).toBe(503);
    expect(r.retryAfterSec).toBeGreaterThanOrEqual(1);
    expect(r.body).toEqual({ error: "throttle_unavailable" });
    expect(JSON.stringify(r)).not.toContain("dummy-secret-7g2");
    expect(JSON.stringify(r)).not.toContain("redis.internal");
    resetThrottleConnForTests();
  });
});

describe("limitedAsync redis over-limit denies 429", () => {
  test("31st request denied 429 rate_limited with auth:-namespaced key", async () => {
    resetRateLimitsForTests();
    resetThrottleConnForTests();
    const fake = makeFake();
    const ip = "10.9.0.3";
    for (let i = 0; i < 30; i++) {
      const r = await limitedAsync("login", ip, fake);
      expect(r.limited).toBe(false);
      expect(r.status).toBe(200);
    }
    const over = await limitedAsync("login", ip, fake);
    expect(over.limited).toBe(true);
    expect(over.status).toBe(429);
    expect(over.retryAfterSec).toBeGreaterThanOrEqual(1);
    expect(over.body).toEqual({ error: "rate_limited" });
    expect(JSON.stringify(over)).not.toContain("REDIS_URL");
    expect(fake.keys.length).toBeGreaterThan(0);
    for (const k of fake.keys) expect(k.startsWith("auth:")).toBe(true);
    expect(fake.keys).toContain(`auth:login:${ip}`);
    resetThrottleConnForTests();
  });
});
