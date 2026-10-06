// ALcore Auth Repo C — signup OTP suite (src/lib/otp.ts).

process.env["JWT_SECRET"] = "test-only-dummy-secret-0123456789abcdef";
process.env["ALLOW_WEAK_JWT_SECRET"] = "1";
process.env["NODE_ENV"] = "test";

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import {
  __setOtpPendingStoreForTests,
  expireSignupOtpForTests,
  issueSignupOtp,
  otpPersistenceKind,
  resetOtpRedisForTests,
  resetSignupOtpsForTests,
  sendSignupOtp,
  verifySignupOtp,
  type OtpPendingStore,
  type SignupOtpRecord,
} from "../src/lib/otp";
import {
  resetMailSender,
  setMailSender,
  type MailMessage,
} from "../src/lib/mail";
import { resetStoresForTests } from "../src/lib/store";

const sent: MailMessage[] = [];

beforeEach(async () => {
  sent.length = 0;
  resetMailSender();
  __setOtpPendingStoreForTests(null);
  resetOtpRedisForTests();
  resetSignupOtpsForTests();
  await resetStoresForTests();
});

afterEach(() => {
  resetMailSender();
});

describe("signup OTP", () => {
  test("happy path: 6-digit code is mailed and verifies once", async () => {
    setMailSender(async (message) => {
      sent.push(message);
      return "delivered";
    });
    const code = await issueSignupOtp("user-happy", "happy@example.com");
    expect(code).toMatch(/^\d{6}$/);

    expect(await sendSignupOtp("happy@example.com", code)).toBe("delivered");
    expect(sent).toHaveLength(1);
    expect(sent[0]?.to).toBe("happy@example.com");
    expect(sent[0]?.text).toContain(code);

    expect(await verifySignupOtp("user-happy", code)).toBe(true);
  });

  test("wrong code does not verify and does not burn the real code", async () => {
    const code = await issueSignupOtp("user-wrong", "wrong@example.com");
    const wrong = code === "000000" ? "000001" : "000000";
    expect(await verifySignupOtp("user-wrong", wrong)).toBe(false);
    expect(await verifySignupOtp("user-wrong", code)).toBe(true);
  });

  test("expired code is rejected", async () => {
    const code = await issueSignupOtp("user-expired", "expired@example.com");
    expireSignupOtpForTests("user-expired");
    expect(await verifySignupOtp("user-expired", code)).toBe(false);
  });

  test("reuse of a consumed code is rejected", async () => {
    const code = await issueSignupOtp("user-reuse", "reuse@example.com");
    expect(await verifySignupOtp("user-reuse", code)).toBe(true);
    expect(await verifySignupOtp("user-reuse", code)).toBe(false);
  });

  test("resend inside the cooldown window is rejected", async () => {
    await issueSignupOtp("user-cooldown", "cooldown@example.com");
    await expect(issueSignupOtp("user-cooldown", "cooldown@example.com")).rejects.toThrow(
      /cooldown/i
    );
  });
});

/**
 * Map-backed OtpPendingStore: stands in for Redis (same async contract, an
 * external owner — it survives resetSignupOtpsForTests, exactly like a
 * server-side keyspace survives a process restart). TTL is intentionally not
 * enforced: the record's expiresAt stays the arbiter under test, matching
 * how verify() decides on the real path.
 */
class MapOtpPendingStore implements OtpPendingStore {
  private readonly records = new Map<string, SignupOtpRecord>();

  async get(userId: string): Promise<SignupOtpRecord | undefined> {
    return this.records.get(userId);
  }

  async set(userId: string, record: SignupOtpRecord): Promise<void> {
    this.records.set(userId, { ...record });
  }

  async del(userId: string): Promise<void> {
    this.records.delete(userId);
  }

  /** Stand-in for expireSignupOtpForTests, which only reaches the fallback. */
  expireNow(userId: string): void {
    const record = this.records.get(userId);
    if (record !== undefined) record.expiresAt = Date.now() - 1;
  }
}

/**
 * Simulated restart: drop every byte of process-local OTP state while the
 * external store keeps its records — the Redis path must not notice.
 */
function simulateRestart(): void {
  resetSignupOtpsForTests();
  resetOtpRedisForTests();
}

describe("signup OTP persistence (Redis path)", () => {
  let fake: MapOtpPendingStore;

  beforeEach(() => {
    fake = new MapOtpPendingStore();
    __setOtpPendingStoreForTests(fake);
  });

  afterEach(() => {
    __setOtpPendingStoreForTests(null);
    resetOtpRedisForTests();
  });

  test("code verifies after a simulated store restart, exactly once", async () => {
    const code = await issueSignupOtp("user-restart", "restart@example.com");
    expect(otpPersistenceKind()).toBe("redis");
    simulateRestart();
    expect(await verifySignupOtp("user-restart", code)).toBe(true);
    // Single-use ledger behavior unchanged: replay is rejected.
    expect(await verifySignupOtp("user-restart", code)).toBe(false);
  });

  test("resend cooldown survives a simulated restart", async () => {
    await issueSignupOtp("user-restart-cool", "restart-cool@example.com");
    simulateRestart();
    await expect(
      issueSignupOtp("user-restart-cool", "restart-cool@example.com"),
    ).rejects.toThrow(/cooldown/i);
  });

  test("wrong code on the Redis path does not burn the real code", async () => {
    const code = await issueSignupOtp("user-restart-wrong", "restart-wrong@example.com");
    simulateRestart();
    const wrong = code === "000000" ? "000001" : "000000";
    expect(await verifySignupOtp("user-restart-wrong", wrong)).toBe(false);
    expect(await verifySignupOtp("user-restart-wrong", code)).toBe(true);
  });

  test("expired record is rejected on the Redis path", async () => {
    const code = await issueSignupOtp("user-restart-exp", "restart-exp@example.com");
    fake.expireNow("user-restart-exp");
    expect(await verifySignupOtp("user-restart-exp", code)).toBe(false);
  });
});

describe("signup OTP fallback (no Redis configured)", () => {
  test("restart wipes un-consumed codes on the memory fallback", async () => {
    const savedBackend = process.env["THROTTLE_BACKEND"];
    const savedUrl = process.env["REDIS_URL"];
    delete process.env["THROTTLE_BACKEND"];
    delete process.env["REDIS_URL"];
    try {
      resetOtpRedisForTests();
      expect(otpPersistenceKind()).toBe("memory");
      const code = await issueSignupOtp("user-fallback", "fallback@example.com");
      simulateRestart();
      expect(await verifySignupOtp("user-fallback", code)).toBe(false);
    } finally {
      if (savedBackend !== undefined) process.env["THROTTLE_BACKEND"] = savedBackend;
      if (savedUrl !== undefined) process.env["REDIS_URL"] = savedUrl;
      resetOtpRedisForTests();
    }
  });
});
