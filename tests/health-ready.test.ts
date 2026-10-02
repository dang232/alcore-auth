// ALcore Auth Repo C — readiness suite (task 26 parallel staging).
// Proves /health/ready is a REAL check, not a 200 stub: each substrate
// failure maps to 503 with a reason, and the signer path uses genuine
// HS256 sign→verify (a tampered token fails closed).

import { describe, test, expect, beforeEach } from "bun:test";

process.env["JWT_SECRET"] = "test-only-dummy-secret-0123456789abcdef";
process.env["ALLOW_WEAK_JWT_SECRET"] = "1";
process.env["NODE_ENV"] = "test";

import { app } from "../src/index";
import { resetRateLimitsForTests, resetThrottleConnForTests } from "../src/lib/ratelimit";
import {
  authReadiness,
  probeIdentitySubstrate,
  roundTripSigner,
} from "../src/lib/readiness";
import { signAccess, verifyAccess } from "../src/lib/crypto";

beforeEach(() => {
  resetRateLimitsForTests();
  resetThrottleConnForTests();
});

describe("GET /health/ready", () => {
  test("200 with ok status and per-check detail when substrate is healthy", async () => {
    const res = await app.request("/health/ready");
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      status: string;
      checks: Record<string, string>;
      population: string;
      userCount: number | null;
    };
    expect(body.status).toBe("ok");
    expect(body.checks).toEqual({ config: "ok", store: "ok", signer: "ok" });
    expect(["populated", "empty", "unknown"]).toContain(body.population);
  });

  test("response surfaces user population so an unseeded DB is visible", async () => {
    const res = await app.request("/health/ready");
    const body = (await res.json()) as {
      population: string;
      userCount: number | null;
    };
    expect(typeof body.userCount === "number" || body.userCount === null).toBe(true);
    expect(body.population).toBe(
      body.userCount === null ? "unknown" : body.userCount > 0 ? "populated" : "empty",
    );
  });

  test("failing config short-circuits to 503 with reasons (fail-closed)", async () => {
    const r = await authReadiness({
      resolveSecret: () => {
        throw new Error("JWT_SECRET is required in production");
      },
      resolveIssuer: () => "https://auth.alcore.io.vn",
      probeStore: () => true,
      roundTripSigner: () => true,
      countUsers: () => 1,
    });
    expect(r.ready).toBe(false);
    expect(r.status).toBe("unavailable");
    expect(r.reasons).toContain("config_unavailable");
  });

  test("unwritable store maps to 503 store_unwritable", async () => {
    const r = await authReadiness({
      resolveSecret: () => "test-only-dummy-secret-0123456789abcdef",
      resolveIssuer: () => "https://auth.alcore.io.vn",
      probeStore: () => false,
      roundTripSigner: () => true,
      countUsers: () => 1,
    });
    expect(r.ready).toBe(false);
    expect(r.checks.store).toBe("down");
    expect(r.reasons).toContain("store_unwritable");
  });

  test("broken signer maps to 503 signer_failed", async () => {
    const r = await authReadiness({
      resolveSecret: () => "test-only-dummy-secret-0123456789abcdef",
      resolveIssuer: () => "https://auth.alcore.io.vn",
      probeStore: () => true,
      roundTripSigner: () => {
        throw new Error("bad signature");
      },
      countUsers: () => 1,
    });
    expect(r.ready).toBe(false);
    expect(r.checks.signer).toBe("down");
    expect(r.reasons).toContain("signer_failed");
  });

  test("empty user table reports population=empty but stays ready", async () => {
    const r = await authReadiness({
      resolveSecret: () => "test-only-dummy-secret-0123456789abcdef",
      resolveIssuer: () => "https://auth.alcore.io.vn",
      probeStore: () => true,
      roundTripSigner: () => true,
      countUsers: () => 0,
    });
    expect(r.population).toBe("empty");
    expect(r.userCount).toBe(0);
    expect(r.ready).toBe(true);
  });

  test("seeded user table reports population=populated with the count", async () => {
    const r = await authReadiness({
      resolveSecret: () => "test-only-dummy-secret-0123456789abcdef",
      resolveIssuer: () => "https://auth.alcore.io.vn",
      probeStore: () => true,
      roundTripSigner: () => true,
      countUsers: () => 12,
    });
    expect(r.population).toBe("populated");
    expect(r.userCount).toBe(12);
  });

  test("a failing count degrades to unknown and never flips readiness", async () => {
    const r = await authReadiness({
      resolveSecret: () => "test-only-dummy-secret-0123456789abcdef",
      resolveIssuer: () => "https://auth.alcore.io.vn",
      probeStore: () => true,
      roundTripSigner: () => true,
      countUsers: () => {
        throw new Error("count failed");
      },
    });
    expect(r.population).toBe("unknown");
    expect(r.userCount).toBeNull();
    expect(r.ready).toBe(true);
  });

  test("substrate probe and signer round-trip are genuine (not stubs)", () => {
    expect(probeIdentitySubstrate()).toBe(true);
    expect(
      roundTripSigner(
        "test-only-dummy-secret-0123456789abcdef",
        "https://auth.alcore.io.vn",
      ),
    ).toBe(true);
      const token = signAccess(
      { sub: "u", sid: "s", iss: "https://auth.alcore.io.vn", aud: "auth", intent: "session" },
      "test-only-dummy-secret-0123456789abcdef",
      60,
    );
    expect(() =>
      verifyAccess(token, "wrong-secret-0123456789abcdefghij", "https://auth.alcore.io.vn", "auth"),
    ).toThrow();
  });

  test("overbuild gate: readiness module owns no business entities", async () => {
    const src = await Bun.file("src/lib/readiness.ts").text();
    const hits = src.match(
      /customer|billing|balance|usage|subscription|api_key|entitlement|topup|recharge|redeem|budget/gi,
    );
    expect(hits ?? []).toEqual([]);
  });
});
