// ALcore Auth Repo C — crypto primitives.
// Mirrors AlRepo apps/api/src/lib/crypto.ts: argon2id via Bun.password,
// sha256 token hashing, HMAC-signed short tokens, hand-rolled HS256 JWT
// (constant-time signature compare). Identity-only payload: no org/role,
// no entitlements — user id is an opaque string, stable for todos 11-14.

import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export async function hashPassword(plain: string): Promise<string> {
  return Bun.password.hash(plain, { algorithm: "argon2id" });
}

export async function verifyPassword(plain: string, hash: string): Promise<boolean> {
  return Bun.password.verify(plain, hash);
}

export function randomToken(bytes = 32): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  let hex = "";
  for (const b of buf) hex += b.toString(16).padStart(2, "0");
  return hex;
}

/** sha256 hex digest — for storing opaque refresh tokens / lookup indexes. */
export function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

export function hmacHex(secret: string, payload: string): string {
  return createHmac("sha256", secret).update(payload, "utf8").digest("hex");
}

// --- HS256 access tokens (short-lived, identity-only) ---

export interface AccessPayload {
  sub: string;
  sid: string;
  iss: string;
  exp: number;
}

export const JWT_ALG = "HS256";
export const JWT_TYP = "JWT";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function b64UrlEncode(input: string | Uint8Array): string {
  const bytes = typeof input === "string" ? encoder.encode(input) : input;
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64UrlDecode(input: string): string {
  const padded = input.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (input.length % 4)) % 4);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return decoder.decode(bytes);
}

function b64UrlDecodeBytes(input: string): Uint8Array {
  const padded = input.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (input.length % 4)) % 4);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function signData(data: string, secret: string): string {
  const sig = createHmac("sha256", encoder.encode(secret)).update(encoder.encode(data)).digest();
  return b64UrlEncode(sig);
}

export function signAccess(
  claims: { sub: string; sid: string; iss: string },
  secret: string,
  ttlSeconds: number,
): string {
  const header = { alg: JWT_ALG, typ: JWT_TYP };
  const now = Math.floor(Date.now() / 1000);
  const payload: AccessPayload = { ...claims, exp: now + ttlSeconds };
  const data = `${b64UrlEncode(JSON.stringify(header))}.${b64UrlEncode(JSON.stringify(payload))}`;
  return `${data}.${signData(data, secret)}`;
}

export class JwtError extends Error {}

export function verifyAccess(token: string, secret: string, expectedIss: string): AccessPayload {
  const parts = token.split(".");
  if (parts.length !== 3) throw new JwtError("malformed jwt");
  const [headerEnc, payloadEnc, sig] = parts as [string, string, string];
  const expected = signData(`${headerEnc}.${payloadEnc}`, secret);
  const a = b64UrlDecodeBytes(sig);
  const b = b64UrlDecodeBytes(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) throw new JwtError("bad signature");
  let header: unknown;
  let payload: unknown;
  try {
    header = JSON.parse(b64UrlDecode(headerEnc));
    payload = JSON.parse(b64UrlDecode(payloadEnc));
  } catch {
    throw new JwtError("malformed jwt");
  }
  if (typeof header !== "object" || header === null || (header as { alg?: unknown }).alg !== JWT_ALG) {
    throw new JwtError("unsupported alg");
  }
  const p = payload as Partial<AccessPayload>;
  if (
    typeof p !== "object" ||
    p === null ||
    typeof p.sub !== "string" ||
    p.sub === "" ||
    typeof p.sid !== "string" ||
    p.sid === "" ||
    typeof p.iss !== "string" ||
    p.iss !== expectedIss ||
    typeof p.exp !== "number"
  ) {
    throw new JwtError("malformed payload");
  }
  if (p.exp <= Math.floor(Date.now() / 1000)) throw new JwtError("expired");
  return p as AccessPayload;
}

// --- Stateless single-purpose tokens (verify / reset), HMAC-signed ---

export type Purpose = "verify" | "reset";

export class TokenError extends Error {}

export function mintPurposeToken(secret: string, purpose: Purpose, userId: string, ttlSeconds: number): string {
  const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
  const payload = `v1.${purpose}.${userId}.${exp}`;
  return `${payload}.${hmacHex(secret, payload)}`;
}

export function verifyPurposeToken(secret: string, expected: Purpose, token: string): { userId: string } {
  const parts = token.split(".");
  if (parts.length !== 5 || parts[0] !== "v1" || parts[1] !== expected) {
    throw new TokenError("invalid token");
  }
  const [, , userId, expRaw, sig] = parts as [string, string, string, string, string];
  if (userId === "") throw new TokenError("invalid token");
  const exp = Number(expRaw);
  if (!Number.isInteger(exp) || exp <= Math.floor(Date.now() / 1000)) {
    throw new TokenError("expired token");
  }
  const payload = `v1.${expected}.${userId}.${expRaw}`;
  const want = hmacHex(secret, payload);
  // Compare hex strings in constant time via sha256 digests (see AlRepo safeHashEqual).
  const da = createHash("sha256").update(sig, "utf8").digest();
  const db = createHash("sha256").update(want, "utf8").digest();
  if (!timingSafeEqual(da, db)) throw new TokenError("invalid token");
  return { userId };
}
