// ALcore Auth Repo C — OTP gate route suite (POST /auth/register pending,
// POST /auth/verify-otp, POST /auth/login verified-gate, POST /auth/otp-resend).
// Assumes dummy secrets only: JWT_SECRET + ALLOW_WEAK_JWT_SECRET=1 are set
// below before any request is made (config reads env lazily per request).

process.env["JWT_SECRET"] = "test-only-dummy-secret-0123456789abcdef";
process.env["ALLOW_WEAK_JWT_SECRET"] = "1";
process.env["NODE_ENV"] = "test";

import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { app } from "../src/index";
import { resetRateLimitsForTests, resetThrottleConnForTests } from "../src/lib/ratelimit";
import { resetStoresForTests, userStore } from "../src/lib/store";
import { expireSignupOtpForTests, resetSignupOtpsForTests } from "../src/lib/otp";
import { resetMailSender, setMailSender, type MailMessage } from "../src/lib/mail";

const sent: MailMessage[] = [];

beforeEach(async () => {
  sent.length = 0;
  resetMailSender();
  setMailSender(async (message) => {
    sent.push(message);
    return "delivered";
  });
  resetRateLimitsForTests();
  resetThrottleConnForTests();
  resetSignupOtpsForTests();
  await resetStoresForTests();
});

afterEach(() => {
  resetMailSender();
});

async function post(path: string, body: unknown): Promise<Response> {
  return app.request(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

/** Pull the 6-digit code out of the mailed body (it travels as token=<code>). */
function mailedCode(message: MailMessage): string {
  const viaToken = /token=(\d{6})/.exec(message.text)?.[1];
  if (viaToken !== undefined) return viaToken;
  return /\d{6}/.exec(message.text)?.[0] ?? "";
}

function wrongCode(real: string): string {
  return real === "000000" ? "000001" : "000000";
}

describe("OTP gate", () => {
  test("register-pending: 202 {pending:true,email}, no session pair, user unverified", async () => {
    const res = await post("/auth/register", { email: "otp-pending@example.com", password: "s3cret-pass" });
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ pending: true, email: "otp-pending@example.com" });
    const cookies = res.headers.getSetCookie();
    expect(cookies.some((v) => v.startsWith("alcore_at="))).toBe(false);
    expect(cookies.some((v) => v.startsWith("alcore_rt="))).toBe(false);
    const user = await userStore.findByEmail("otp-pending@example.com");
    expect(user?.emailVerified).toBe(false);
    expect(sent).toHaveLength(1);
    expect(sent[0]?.to).toBe("otp-pending@example.com");
    expect(mailedCode(sent[0] as MailMessage)).toMatch(/^\d{6}$/);
  });

  test("verify-ok-then-login: correct code verifies, mints a pair, login works after", async () => {
    await post("/auth/register", { email: "otp-verify@example.com", password: "s3cret-pass" });
    const code = mailedCode(sent[0] as MailMessage);
    const verify = await post("/auth/verify-otp", { email: "otp-verify@example.com", code });
    expect(verify.status).toBe(200);
    const pair = (await verify.json()) as { access_token: string; refresh_token: string; user: { emailVerified: boolean } };
    expect(typeof pair.access_token).toBe("string");
    expect(typeof pair.refresh_token).toBe("string");
    expect(pair.user.emailVerified).toBe(true);
    expect((await userStore.findByEmail("otp-verify@example.com"))?.emailVerified).toBe(true);
    // Single-use: the same code never verifies twice.
    expect((await post("/auth/verify-otp", { email: "otp-verify@example.com", code })).status).toBe(400);
    const login = await post("/auth/login", { email: "otp-verify@example.com", password: "s3cret-pass" });
    expect(login.status).toBe(200);
  });

  test("wrong-code: 400 invalid_code and the real code still works", async () => {
    await post("/auth/register", { email: "otp-wrong@example.com", password: "s3cret-pass" });
    const code = mailedCode(sent[0] as MailMessage);
    const bad = await post("/auth/verify-otp", { email: "otp-wrong@example.com", code: wrongCode(code) });
    expect(bad.status).toBe(400);
    expect(await bad.json()).toEqual({ error: "invalid_code" });
    expect((await post("/auth/verify-otp", { email: "otp-wrong@example.com", code })).status).toBe(200);
  });

  test("expired-code: 400 after the code passes expiry", async () => {
    await post("/auth/register", { email: "otp-expired@example.com", password: "s3cret-pass" });
    const code = mailedCode(sent[0] as MailMessage);
    const user = await userStore.findByEmail("otp-expired@example.com");
    expireSignupOtpForTests(user?.id ?? "missing-user");
    const res = await post("/auth/verify-otp", { email: "otp-expired@example.com", code });
    expect(res.status).toBe(400);
  });

  test("unverified-login: correct password still 403 email_not_verified until verified", async () => {
    await post("/auth/register", { email: "otp-unverified@example.com", password: "s3cret-pass" });
    const denied = await post("/auth/login", { email: "otp-unverified@example.com", password: "s3cret-pass" });
    expect(denied.status).toBe(403);
    expect(await denied.json()).toEqual({ error: "email_not_verified" });
    // Wrong password keeps the identical 401 shape (no verification oracle).
    const badPass = await post("/auth/login", { email: "otp-unverified@example.com", password: "wrong-pass" });
    expect(badPass.status).toBe(401);
    expect(await badPass.json()).toEqual({ error: "invalid_credentials" });
  });

  test("resend-cooldown: immediate resend is 200 with no new mail; unknown email same 200", async () => {
    await post("/auth/register", { email: "otp-resend@example.com", password: "s3cret-pass" });
    expect(sent).toHaveLength(1);
    const resend = await post("/auth/otp-resend", { email: "otp-resend@example.com" });
    expect(resend.status).toBe(200);
    expect(await resend.json()).toEqual({ ok: true });
    expect(sent).toHaveLength(1);
    const unknown = await post("/auth/otp-resend", { email: "otp-nobody@example.com" });
    expect(unknown.status).toBe(200);
    expect(await unknown.json()).toEqual({ ok: true });
    expect(sent).toHaveLength(1);
  });

  test("Google-user login unaffected: passwordHash null still 401, never 403", async () => {
    await userStore.create("otp-google@example.com", null);
    const res = await post("/auth/login", { email: "otp-google@example.com", password: "s3cret-pass" });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "invalid_credentials" });
  });
});
