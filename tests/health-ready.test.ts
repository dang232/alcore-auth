// ALcore Auth Repo C — readiness suite (task 26 parallel staging).
// Proves /health/ready is a REAL check, not a 200 stub: each substrate
// failure maps to 503 with a reason, and the signer path uses genuine
// HS256 sign→verify (a tampered token fails closed).

import { describe, test, expect } from "bun:test";

process.env["JWT_SECRET"] = "test-only-dummy-secret-0123456789abcdef";
process.env["ALLOW_WEAK_JWT_SECRET"] = "1";
process.env["NODE_ENV"] = "test";

import { app } from "../src/index";
import {
  authReadiness,
  probeIdentitySubstrate,
  roundTripSigner,
} from "../src/lib/readiness";
import { signAccess, verifyAccess } from "../src/lib/crypto";

describe("GET /health/ready", () => {
  test("200 with ok status and per-check detail when substrate is healthy", async () => {
    const res = await app.request("/health/ready");
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      status: string;
      checks: Record<string, string>;
    };
    expect(body.status).toBe("ok");
    expect(body.checks).toEqual({ config: "ok", store: "ok", signer: "ok" });
  });

  test("failing config short-circuits to 503 with reasons (fail-closed)", () => {
    const r = authReadiness({
      resolveSecret: () => {
        throw new Error("JWT_SECRET is required in production");
      },
      resolveIssuer: () => "https://auth.alcore.io.vn",
      probeStore: () => true,
      roundTripSigner: () => true,
    });
    expect(r.ready).toBe(false);
    expect(r.status).toBe("unavailable");
    expect(r.reasons).toContain("config_unavailable");
  });

  test("unwritable store maps to 503 store_unwritable", () => {
    const r = authReadiness({
      resolveSecret: () => "test-only-dummy-secret-0123456789abcdef",
      resolveIssuer: () => "https://auth.alcore.io.vn",
      probeStore: () => false,
      roundTripSigner: () => true,
    });
    expect(r.ready).toBe(false);
    expect(r.checks.store).toBe("down");
    expect(r.reasons).toContain("store_unwritable");
  });

  test("broken signer maps to 503 signer_failed", () => {
    const r = authReadiness({
      resolveSecret: () => "test-only-dummy-secret-0123456789abcdef",
      resolveIssuer: () => "https://auth.alcore.io.vn",
      probeStore: () => true,
      roundTripSigner: () => {
        throw new Error("bad signature");
      },
    });
    expect(r.ready).toBe(false);
    expect(r.checks.signer).toBe("down");
    expect(r.reasons).toContain("signer_failed");
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
      { sub: "u", sid: "s", iss: "https://auth.alcore.io.vn" },
      "test-only-dummy-secret-0123456789abcdef",
      60,
    );
    expect(() =>
      verifyAccess(token, "wrong-secret-0123456789abcdefghij", "https://auth.alcore.io.vn"),
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
