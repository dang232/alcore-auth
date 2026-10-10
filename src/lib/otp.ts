// ALcore Auth Repo C — signup OTP core library.
//
// Issues short-lived 6-digit signup codes and verifies them single-use.
// Only the sha256 hash of a code is ever stored (10-minute expiry); a
// per-user resend cooldown stops code-request spam. Successful verification
// is recorded in the existing consumed_purpose_tokens ledger
// (src/lib/store.ts) so a consumed code can never verify twice, even across
// restarts. Delivery goes through the existing mail seam
// (src/lib/mail.ts) with purpose "signup-otp".
//
// Pending-record durability: records live in Redis (SET with PX, one key per
// user under the `auth:` namespace) whenever a Redis backend is configured —
// the same THROTTLE_BACKEND=redis + REDIS_URL pair that arms the throttle
// Redis path (src/lib/ratelimit.ts) — and fall back to the process-local Map
// otherwise, so dev/test work with zero new infra. Single-use safety never
// depends on the pending store: the consume ledger stays the arbiter, so a
// verify that races a restart still wins exactly once.

import { createHash, randomInt, randomUUID } from "node:crypto";
import { deliverPurposeMail, type MailOutcome } from "./mail";
import { throttleBackendKind } from "./ratelimit";
import { markPurposeConsumed } from "./store";

/** Signup codes live for 10 minutes after issue. */
export const SIGNUP_OTP_TTL_MS = 10 * 60 * 1000;

/** A user must wait this long between code issues (resend cooldown). */
export const SIGNUP_OTP_RESEND_COOLDOWN_MS = 60 * 1000;

/** Pending-record shape shared by both backends (hash only, never a code). */
export interface SignupOtpRecord {
  readonly codeHash: string;
  readonly ledgerKey: string;
  readonly email: string;
  expiresAt: number;
  cooldownUntil: number;
}

/**
 * Pending-OTP storage contract. The in-memory fallback implements it over the
 * module Map; the Redis path over one `auth:signup-otp:{userId}` key with PX.
 * Tests inject a Map-backed fake to prove restart survival without a server.
 */
export interface OtpPendingStore {
  get(userId: string): Promise<SignupOtpRecord | undefined>;
  set(userId: string, record: SignupOtpRecord, ttlMs: number): Promise<void>;
  del(userId: string): Promise<void>;
}

/** Process-local fallback: identical semantics to the pre-Redis Map. */
const pending = new Map<string, SignupOtpRecord>();

const memoryPendingStore: OtpPendingStore = {
  get: (userId) => Promise.resolve(pending.get(userId)),
  set: (userId, record) => {
    pending.set(userId, record);
    return Promise.resolve();
  },
  del: (userId) => {
    pending.delete(userId);
    return Promise.resolve();
  },
};

/** Redis keys stay inside `auth:` so product counters can never collide. */
const OTP_REDIS_KEY_PREFIX = "auth:signup-otp:";

function otpRedisKey(userId: string): string {
  return `${OTP_REDIS_KEY_PREFIX}${userId}`;
}

function parseOtpRecord(raw: string | null): SignupOtpRecord | undefined {
  if (raw === null) return undefined;
  try {
    const value = JSON.parse(raw) as Partial<SignupOtpRecord>;
    if (
      typeof value.codeHash !== "string" ||
      typeof value.ledgerKey !== "string" ||
      typeof value.email !== "string" ||
      typeof value.expiresAt !== "number" ||
      typeof value.cooldownUntil !== "number"
    ) {
      return undefined;
    }
    return {
      codeHash: value.codeHash,
      ledgerKey: value.ledgerKey,
      email: value.email,
      expiresAt: value.expiresAt,
      cooldownUntil: value.cooldownUntil,
    };
  } catch {
    return undefined;
  }
}

/** Structural Bun RedisClient surface used here (mirrors ratelimit.ts). */
interface OtpRedisClient {
  get(key: string): Promise<string | null>;
  send(command: string, args: string[]): Promise<unknown>;
  del(key: string): Promise<unknown>;
}

function redisPendingStore(client: OtpRedisClient): OtpPendingStore {
  return {
    get: async (userId) => parseOtpRecord(await client.get(otpRedisKey(userId))),
    set: async (userId, record, ttlMs) => {
      // Single SET with PX so the record self-expires server-side; the
      // stored expiresAt stays the arbiter so clock skew can only shorten.
      await client.send("SET", [
        otpRedisKey(userId),
        JSON.stringify(record),
        "PX",
        String(Math.max(1, Math.floor(ttlMs))),
      ]);
    },
    del: async (userId) => {
      await client.del(otpRedisKey(userId));
    },
  };
}

/** Lazy per-process shared Redis client (one Bun RedisClient per process). */
let sharedOtpRedis: OtpRedisClient | null = null;

/** Test-only: drops the cached shared client (mirrors resetThrottleConnForTests). */
export function resetOtpRedisForTests(): void {
  sharedOtpRedis = null;
}

function getSharedOtpRedis(): OtpRedisClient | null {
  try {
    if (sharedOtpRedis !== null) return sharedOtpRedis;
    const url = (process.env["REDIS_URL"] ?? "").trim();
    const BunGlobal = (globalThis as unknown as {
      Bun?: { RedisClient?: new (url?: string) => unknown };
    }).Bun;
    if (url === "" || BunGlobal?.RedisClient === undefined) return null;
    sharedOtpRedis = new BunGlobal.RedisClient(url) as unknown as OtpRedisClient;
    return sharedOtpRedis;
  } catch {
    return null;
  }
}

let injectedPendingStore: OtpPendingStore | null = null;

/**
 * Test-only: inject a pending-OTP store (Map-backed fake). The injected store
 * survives resetSignupOtpsForTests — which drops only the process-local map —
 * so a test can simulate a restart and prove the code still verifies.
 */
export function __setOtpPendingStoreForTests(store: OtpPendingStore | null): void {
  injectedPendingStore = store;
}

/** Where pending OTPs live right now: external Redis or process memory. */
export function otpPersistenceKind(): "redis" | "memory" {
  if (injectedPendingStore !== null) return "redis";
  if (throttleBackendKind() !== "redis") return "memory";
  return getSharedOtpRedis() === null ? "memory" : "redis";
}

function activePendingStore(): OtpPendingStore {
  if (injectedPendingStore !== null) return injectedPendingStore;
  if (throttleBackendKind() === "redis") {
    const client = getSharedOtpRedis();
    if (client !== null) return redisPendingStore(client);
  }
  return memoryPendingStore;
}

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
  const store = activePendingStore();
  const now = Date.now();
  const existing = await store.get(userId);
  if (existing !== undefined && now < existing.cooldownUntil) {
    throw new Error("signup OTP resend cooldown: try again later");
  }
  const code = String(randomInt(0, 1_000_000)).padStart(6, "0");
  const record: SignupOtpRecord = {
    codeHash: sha256Hex(code),
    // Random per-issuance id so two issues with the same 6-digit code never
    // share a ledger entry; the stored code hash stays the only secret.
    ledgerKey: sha256Hex(`signup-otp:${userId}:${randomUUID()}`),
    email,
    expiresAt: now + SIGNUP_OTP_TTL_MS,
    cooldownUntil: now + SIGNUP_OTP_RESEND_COOLDOWN_MS,
  };
  await store.set(userId, record, Math.max(1, record.expiresAt - Date.now()));
  return code;
}

/**
 * Verify a signup code single-use. Returns false for unknown users, wrong
 * codes, expired codes, and replays of an already-consumed code. A verified
 * code is recorded in the consumed_purpose_tokens ledger and forgotten, so
 * verification wins exactly once — the ledger (not the pending store) is
 * the arbiter, which is what keeps concurrent/restart races single-use.
 */
export async function verifySignupOtp(userId: string, code: string): Promise<boolean> {
  const store = activePendingStore();
  const record = await store.get(userId);
  if (record === undefined) return false;
  if (Date.now() >= record.expiresAt) {
    await store.del(userId);
    return false;
  }
  // Wrong codes leave the record in place so the real code stays usable
  // until it expires; they must never touch the consume ledger.
  if (!hashesEqualHex(sha256Hex(code), record.codeHash)) return false;
  await store.del(userId);
  return markPurposeConsumed(record.ledgerKey);
}

/**
 * Deliver a signup code through the existing mail seam (purpose
 * "signup-otp"). The transport is swapped in tests via setMailSender.
 */
export async function sendSignupOtp(email: string, code: string): Promise<MailOutcome> {
  return deliverPurposeMail("signup-otp", email, code);
}

/**
 * Test-only: drop the process-local pending map (ledger rows are cleared
 * separately). An injected/Redis store is intentionally untouched: on the
 * Redis path this call IS the simulated restart — external records survive
 * it, so a code issued before still verifies after.
 */
export function resetSignupOtpsForTests(): void {
  pending.clear();
}

/**
 * Test-only: force a user's pending code past expiry without waiting. Sync
 * by contract (existing callers do not await it), so it reaches only the
 * in-memory fallback; on the Redis path it throws and tests seed expiry
 * through the injected store instead.
 */
export function expireSignupOtpForTests(userId: string): void {
  if (activePendingStore() !== memoryPendingStore) {
    throw new Error(
      "expireSignupOtpForTests only reaches the in-memory fallback (seed expiry through the injected store on the Redis path)",
    );
  }
  const record = pending.get(userId);
  if (record !== undefined) record.expiresAt = Date.now() - 1;
}
