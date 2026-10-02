// ALcore Auth Repo C — per-process in-memory throttle buckets keyed by
// client IP + route scope. Mirrors AlRepo apps/api/src/lib/throttle.ts:
// counters reset on restart and do not span replicas.

export interface RateLimitResult {
  ok: boolean;
  retryAfterMs: number;
}

export interface RateLimiter {
  (key: string, now?: number): RateLimitResult;
  /** Test-only: empties all throttle buckets (mirrors resetStoresForTests). */
  clear(): void;
}

export function createRateLimiter(
  windowMs: number,
  max: number,
): RateLimiter {
  const buckets = new Map<string, { count: number; resetAt: number }>();
  const limit = (key: string, now: number = Date.now()): RateLimitResult => {
    const b = buckets.get(key);
    if (b === undefined || now >= b.resetAt) {
      buckets.set(key, { count: 1, resetAt: now + windowMs });
      return { ok: true, retryAfterMs: 0 };
    }
    if (b.count < max) {
      b.count += 1;
      return { ok: true, retryAfterMs: 0 };
    }
    return { ok: false, retryAfterMs: b.resetAt - now };
  };
  limit.clear = (): void => {
    buckets.clear();
  };
  return limit;
}

/** Shared auth-surface limiter: 30 requests / 60s per IP per scope. */
export const authRateLimit = createRateLimiter(60_000, 30);

/** Test-only: resets the shared auth limiter buckets (mirrors
 *  resetStoresForTests in store.ts). No production behavior change. */
export function resetRateLimitsForTests(): void {
  authRateLimit.clear();
}

// ---------------------------------------------------------------------------
// Task 37 — centralized Redis throttle (unit scope; route wiring is next run).
// API-CONTRACT.md rate_limit.bucket names, all under the `auth:` namespace so
// product counters (TokenPanel rate_limit_counters, Libre coordination keys)
// can never collide. Route call-site scopes map to buckets via scopeToBucket.
// ---------------------------------------------------------------------------

/** Contract-exact bucket for a route call-site scope. Unknown scopes stay
 *  inside `auth:` (never bare, never product-owned). */
export function scopeToBucket(scope: string): string {
  switch (scope) {
    case "register":
      return "auth:register";
    case "login":
      return "auth:login";
    case "refresh":
      return "auth:refresh";
    case "verify":
      return "auth:verify";
    case "reset":
      return "auth:reset";
    case "google":
    case "google-verify":
      return "auth:oauth";
    case "oidc":
      return "auth:oidc";
    case "exchange":
    case "exchange-redirect":
      return "auth:exchange";
    default:
      return `auth:${scope}`;
  }
}

/** Backend selection reads the platform-standard env keys directly from
 *  process.env: src/config.ts owns no REDIS/THROTTLE keys (task 36 owns
 *  config edits), so this module must not invent a config helper. */
export function throttleBackendKind(
  env: NodeJS.ProcessEnv = process.env,
): "redis" | "memory" {
  if ((env["THROTTLE_BACKEND"] ?? "").trim().toLowerCase() === "redis") {
    if ((env["REDIS_URL"] ?? "").trim() !== "") return "redis";
  }
  return "memory";
}

// NOTE (TARGET deviation, explicit): the "memory" path is the pre-existing
// per-process map above — counters reset on restart and do not span replicas.
// It is kept ONLY for non-production (dev/test, or THROTTLE_BACKEND unset).
// Production MUST set THROTTLE_BACKEND=redis + REDIS_URL; restart durability
// ("restart does not reset budgets") holds only on the Redis path.
//
// S8 reconciliation gate: production must never silently fall back to
// process-local memory. Call resolveThrottleBackend() once at boot (it
// throws naming THROTTLE_BACKEND / REDIS_URL, never their values); outside
// production the memory path stays available with an explicit warning.

/** Production gate for throttle backend selection (S8).
 *
 *  - Non-production (NODE_ENV anything but "production"): returns the
 *    existing throttleBackendKind() selection unchanged (memory stays
 *    available for dev/test ergonomics) and warns when memory is used.
 *  - Production: REQUIRES THROTTLE_BACKEND=redis AND a non-empty REDIS_URL,
 *    otherwise throws naming the missing variable(s). Never throws for
 *    bucket/Lua/fail-closed reasons — those are untouched.
 *  - Never includes secret values in messages (names only). */
export function resolveThrottleBackend(
  env: NodeJS.ProcessEnv = process.env,
  nodeEnvName?: string,
): "redis" | "memory" {
  const node = (nodeEnvName ?? (env["NODE_ENV"] ?? "").trim().toLowerCase()).trim().toLowerCase();
  if (node !== "production") {
    const kind = throttleBackendKind(env);
    if (kind === "memory") {
      console.warn(
        "[auth-service] throttle backend=memory (dev/test only; production requires THROTTLE_BACKEND=redis + REDIS_URL)",
      );
    }
    return kind;
  }
  const backend = (env["THROTTLE_BACKEND"] ?? "").trim().toLowerCase();
  const url = (env["REDIS_URL"] ?? "").trim();
  if (backend !== "redis") {
    throw new Error(
      'THROTTLE_BACKEND must be "redis" in production (process-local memory does not span replicas)',
    );
  }
  if (url === "") {
    throw new Error(
      "REDIS_URL is required in production when THROTTLE_BACKEND=redis (auth throttle must share counts across replicas)",
    );
  }
  return "redis";
}

/** Atomic increment-with-TTL contract (one Lua EVAL on real Redis; the
 *  in-test fake implements identical single-step semantics). */
export interface ThrottleConn {
  incrWithTtl(key: string, windowMs: number): Promise<{ count: number; ttlMs: number }>;
}

/** Atomic Lua: INCR + PEXPIRE-on-first + PTTL in one server-side step, so two
 *  Auth replicas share one counter with no lost-update race. */
export const THROTTLE_LUA = [
  "local c = redis.call('INCR', KEYS[1])",
  "if c == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end",
  "local t = redis.call('PTTL', KEYS[1])",
  "return {c, t}",
].join("\n");

/** Real adapter over Bun's built-in Redis client (zero new dependencies).
 *  Live-server proof is the next run; unit tests inject a fake ThrottleConn. */
export function bunRedisThrottleConn(
  client: {
    eval(script: string, keys: string[], args: Array<string | number>): Promise<unknown>;
  },
): ThrottleConn {
  return {
    async incrWithTtl(key: string, windowMs: number) {
      const raw = (await client.eval(THROTTLE_LUA, [key], [windowMs])) as unknown;
      const pair = Array.isArray(raw) ? (raw as unknown[]) : [];
      return { count: Number(pair[0] ?? NaN), ttlMs: Number(pair[1] ?? -1) };
    },
  };
}

export interface RedisRateLimitResult extends RateLimitResult {
  /** True when the backend was unreachable: caller must deny CLOSED (503 +
   *  Retry-After on auth routes), never fail open to unlimited attempts. */
  unavailable?: boolean;
}

export function createRedisRateLimiter(
  conn: ThrottleConn,
  windowMs: number,
  max: number,
): (key: string) => Promise<RedisRateLimitResult> {
  return async (key: string): Promise<RedisRateLimitResult> => {
    try {
      const { count, ttlMs } = await conn.incrWithTtl(key, windowMs);
      if (!Number.isFinite(count) || count <= max) {
        return { ok: true, retryAfterMs: 0 };
      }
      return { ok: false, retryAfterMs: ttlMs > 0 ? ttlMs : windowMs };
    } catch {
      // Fail CLOSED: deny, never throw, never surface backend details
      // (no REDIS_URL, secret, or stack leaks to the caller).
      return { ok: false, retryAfterMs: 1000, unavailable: true };
    }
  };
}

/** Async convenience: bucket-namespaced key `auth:{scope}:{ip}` + shared
 *  30 req / 60s policy. Route wiring (async limited()) lands next run. */
export function checkAuthThrottle(
  conn: ThrottleConn,
  scope: string,
  ip: string,
): Promise<RedisRateLimitResult> {
  const limit = createRedisRateLimiter(conn, 60_000, 30);
  return limit(`${scopeToBucket(scope)}:${ip}`);
}

// ---------------------------------------------------------------------------
// Task 37 guard slice — shared async throttle helper for route wiring.
// Memory backend → identical verdict to sync `authRateLimit(scope:ip)`.
// Redis backend → one lazy per-process shared conn via bunRedisThrottleConn +
// checkAuthThrottle. Fail CLOSED, never throw, no secrets in body.
// ---------------------------------------------------------------------------

/** Guard verdict: allowed, or denied with an HTTP-ready status + body. */
export interface GuardResult {
  limited: boolean;
  status: 200 | 429 | 503;
  retryAfterSec: number;
  body: Record<string, unknown>;
}

/** Lazy per-process shared Redis conn (one Bun RedisClient per process). */
let sharedThrottleConn: ThrottleConn | null = null;

/** Test-only: drops the cached shared conn (mirrors resetRateLimitsForTests). */
export function resetThrottleConnForTests(): void {
  sharedThrottleConn = null;
}

function getSharedThrottleConn(): ThrottleConn | null {
  try {
    if (sharedThrottleConn !== null) return sharedThrottleConn;
    const url = (process.env["REDIS_URL"] ?? "").trim();
    const BunGlobal = (globalThis as unknown as {
      Bun?: { RedisClient?: new (url?: string) => unknown };
    }).Bun;
    if (url === "" || BunGlobal?.RedisClient === undefined) return null;
    const raw = new BunGlobal.RedisClient(url) as {
      eval(script: string, numkeys: number, ...keysAndArgs: Array<string | number>): Promise<unknown>;
    };
    // Adapt Bun's native eval(script, numkeys, ...keysAndArgs) to the
    // ioredis-shaped eval(script, keys, args) bunRedisThrottleConn expects.
    const shaped = {
      eval: (script: string, keys: string[], args: Array<string | number>): Promise<unknown> =>
        raw.eval(script, keys.length, ...keys, ...args),
    };
    sharedThrottleConn = bunRedisThrottleConn(shaped);
    return sharedThrottleConn;
  } catch {
    return null;
  }
}

/** Shared async throttle guard. Never throws; Redis outage → 503 closed. */
export async function limitedAsync(
  scope: string,
  ip: string,
  injected?: ThrottleConn,
): Promise<GuardResult> {
  try {
    const backend = injected !== undefined ? "redis" : throttleBackendKind();
    if (backend === "memory") {
      // Same key shape as the sync route helper: `scope:ip` (no bucket).
      const r = authRateLimit(`${scope}:${ip}`);
      if (r.ok) return { limited: false, status: 200, retryAfterSec: 0, body: {} };
      return {
        limited: true,
        status: 429,
        retryAfterSec: Math.max(1, Math.ceil(r.retryAfterMs / 1000)),
        body: { error: "rate_limited" },
      };
    }
    const conn = injected ?? getSharedThrottleConn();
    if (conn === null) {
      return {
        limited: true,
        status: 503,
        retryAfterSec: 1,
        body: { error: "throttle_unavailable" },
      };
    }
    const r = await checkAuthThrottle(conn, scope, ip);
    if (r.ok) return { limited: false, status: 200, retryAfterSec: 0, body: {} };
    if (r.unavailable === true) {
      return {
        limited: true,
        status: 503,
        retryAfterSec: Math.max(1, Math.ceil(r.retryAfterMs / 1000)),
        body: { error: "throttle_unavailable" },
      };
    }
    return {
      limited: true,
      status: 429,
      retryAfterSec: Math.max(1, Math.ceil(r.retryAfterMs / 1000)),
      body: { error: "rate_limited" },
    };
  } catch {
    return {
      limited: true,
      status: 503,
      retryAfterSec: 1,
      body: { error: "throttle_unavailable" },
    };
  }
}
