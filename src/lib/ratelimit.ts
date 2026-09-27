// ALcore Auth Repo C — per-process in-memory throttle buckets keyed by
// client IP + route scope. Mirrors AlRepo apps/api/src/lib/throttle.ts:
// counters reset on restart and do not span replicas.

export interface RateLimitResult {
  ok: boolean;
  retryAfterMs: number;
}

export function createRateLimiter(
  windowMs: number,
  max: number,
): (key: string, now?: number) => RateLimitResult {
  const buckets = new Map<string, { count: number; resetAt: number }>();
  return (key: string, now: number = Date.now()): RateLimitResult => {
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
}

/** Shared auth-surface limiter: 30 requests / 60s per IP per scope. */
export const authRateLimit = createRateLimiter(60_000, 30);
