// ALcore Auth Repo C — signup OTP suite (src/lib/otp.ts).

process.env["JWT_SECRET"] = "test-only-dummy-secret-0123456789abcdef";
process.env["ALLOW_WEAK_JWT_SECRET"] = "1";
process.env["NODE_ENV"] = "test";

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import {
  expireSignupOtpForTests,
  issueSignupOtp,
  resetSignupOtpsForTests,
  sendSignupOtp,
  verifySignupOtp,
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
