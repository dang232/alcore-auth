// ALcore Auth Repo C — signup OTP core library.
//
// Issues short-lived 6-digit signup codes and verifies them single-use.
// Only the sha256 hash of a code is ever stored (10-minute expiry); a
// per-user resend cooldown stops code-request spam. Successful verification
// is recorded in the existing consumed_purpose_tokens ledger
// (src/lib/store.ts) so a consumed code can never verify twice, even across
// restarts. Delivery goes through the existing mail seam
// (src/lib/mail.ts) with purpose "signup-otp".

import { createHash, randomInt, randomUUID } from "node:crypto";
import { deliverPurposeMail, type MailOutcome } from "./mail";
import { markPurposeConsumed } from "./store";

/** Signup codes live for 10 minutes after issue. */
export const SIGNUP_OTP_TTL_MS = 10 * 60 * 1000;

/** A user must wait this long between code issues (resend cooldown). */
export const SIGNUP_OTP_RESEND_COOLDOWN_MS = 60 * 1000;

interface SignupOtpRecord {
  readonly codeHash: string;
  readonly ledgerKey: string;
  readonly email: string;
  expiresAt: number;
  cooldownUntil: number;
}

const pending = new Map<string, SignupOtpRecord>();

function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function hashesEqualHex(a: string, b: string): boolean {
  // Constant-time compare over the hex digests (fixed length by
  // construction) so a wrong code learns nothing from timing.
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * Issue a fresh 6-digit signup code for a user. Stores only the sha256 hash
 * alongside a 10-minute expiry. Throws when called inside the resend
 * cooldown window; issuing after the cooldown replaces any earlier code.
 */
export async function issueSignupOtp(userId: string, email: string): Promise<string> {
  const now = Date.now();
  const existing = pending.get(userId);
  if (existing !== undefined && now < existing.cooldownUntil) {
    throw new Error("signup OTP resend cooldown: try again later");
  }
  const code = String(randomInt(0, 1_000_000)).padStart(6, "0");
  pending.set(userId, {
    codeHash: sha256Hex(code),
    // Random per-issuance id so two issues with the same 6-digit code never
    // share a ledger entry; the stored code hash stays the only secret.
    ledgerKey: sha256Hex(`signup-otp:${userId}:${randomUUID()}`),
    email,
    expiresAt: now + SIGNUP_OTP_TTL_MS,
    cooldownUntil: now + SIGNUP_OTP_RESEND_COOLDOWN_MS,
  });
  return code;
}

/**
 * Verify a signup code single-use. Returns false for unknown users, wrong
 * codes, expired codes, and replays of an already-consumed code. A verified
 * code is recorded in the consumed_purpose_tokens ledger and forgotten, so
 * verification wins exactly once.
 */
export async function verifySignupOtp(userId: string, code: string): Promise<boolean> {
  const record = pending.get(userId);
  if (record === undefined) return false;
  if (Date.now() >= record.expiresAt) {
    pending.delete(userId);
    return false;
  }
  // Wrong codes leave the record in place so the real code stays usable
  // until it expires; they must never touch the consume ledger.
  if (!hashesEqualHex(sha256Hex(code), record.codeHash)) return false;
  pending.delete(userId);
  return markPurposeConsumed(record.ledgerKey);
}

/**
 * Deliver a signup code through the existing mail seam (purpose
 * "signup-otp"). The transport is swapped in tests via setMailSender.
 */
export async function sendSignupOtp(email: string, code: string): Promise<MailOutcome> {
  // deliverPurposeMail's purpose union only names the route-owned purposes;
  // mail.ts is out of scope here, so the new purpose passes through at
  // runtime (the cast is compile-time only) and lands in the message body.
  const purpose = "signup-otp" as unknown as "verify";
  return deliverPurposeMail(purpose, email, code);
}

/** Test-only: drop all pending codes (ledger rows are cleared separately). */
export function resetSignupOtpsForTests(): void {
  pending.clear();
}

/** Test-only: force a user's pending code past expiry without waiting. */
export function expireSignupOtpForTests(userId: string): void {
  const record = pending.get(userId);
  if (record !== undefined) record.expiresAt = Date.now() - 1;
}
