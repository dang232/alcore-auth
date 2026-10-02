// S8: production throttle must REQUIRE Redis (fail-fast), memory stays for dev/test only.
// Dummy values only, no secrets, no servers spawned.
import { describe, expect, test } from "bun:test";
import { resolveThrottleBackend, throttleBackendKind } from "../src/lib/ratelimit";

describe("S8 resolveThrottleBackend: production requires Redis", () => {
  test("prod without THROTTLE_BACKEND=redis throws naming it", async () => {
    expect(() => resolveThrottleBackend({ NODE_ENV: "production", REDIS_URL: "redis://localhost:6379" })).toThrow(
      "THROTTLE_BACKEND",
    );
  });
  test("prod with THROTTLE_BACKEND=redis but no REDIS_URL throws naming it", async () => {
    expect(() => resolveThrottleBackend({ NODE_ENV: "production", THROTTLE_BACKEND: "redis" })).toThrow("REDIS_URL");
  });
  test("prod with neither set throws naming THROTTLE_BACKEND (first missing gate)", async () => {
    expect(() => resolveThrottleBackend({ NODE_ENV: "production" })).toThrow("THROTTLE_BACKEND");
  });
  test("prod with both set returns redis", async () => {
    expect(
      resolveThrottleBackend({
        NODE_ENV: "production",
        THROTTLE_BACKEND: "redis",
        REDIS_URL: "redis://localhost:6379",
      }),
    ).toBe("redis");
  });
  test("prod error messages never echo secret values", async () => {
    const secretUrl = "redis://:dummy-secret-s8@redis.internal:6379/0";
    let msg = "";
    try {
      resolveThrottleBackend({ NODE_ENV: "production", THROTTLE_BACKEND: "memory", REDIS_URL: secretUrl });
    } catch (err) {
      msg = err instanceof Error ? err.message : String(err);
    }
    expect(msg).toContain("THROTTLE_BACKEND");
    expect(msg).not.toContain("dummy-secret-s8");
    expect(msg).not.toContain("redis.internal");
  });
});

describe("S8 resolveThrottleBackend: dev/test ergonomics preserved", () => {
  test("non-prod without Redis returns memory (legacy selection untouched)", async () => {
    expect(resolveThrottleBackend({ NODE_ENV: "development" })).toBe("memory");
    expect(resolveThrottleBackend({ NODE_ENV: "test" })).toBe("memory");
    expect(resolveThrottleBackend({})).toBe("memory");
  });
  test("non-prod with both set still returns redis", async () => {
    expect(
      resolveThrottleBackend({
        NODE_ENV: "development",
        THROTTLE_BACKEND: "redis",
        REDIS_URL: "redis://localhost:6379",
      }),
    ).toBe("redis");
  });
  test("throttleBackendKind legacy behavior unchanged (S8 touches only the prod gate)", async () => {
    expect(throttleBackendKind({ THROTTLE_BACKEND: "redis", REDIS_URL: "redis://localhost:6379" })).toBe("redis");
    expect(throttleBackendKind({ THROTTLE_BACKEND: "redis" })).toBe("memory");
    expect(throttleBackendKind({})).toBe("memory");
  });
});
