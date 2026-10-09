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
  readonly sub: string;
  readonly sid: string;
  readonly iss: string;
  readonly aud: string;
  readonly exp: number;
  readonly intent: string;
  // Present only on product-exchange assertions, where the consuming product
  // needs the verified address to provision its own profile. Never added to
  // browser session or OIDC assertions.
  readonly email?: string;
}

type ParsedAccessPayload = {
  readonly sub: string;
  readonly sid: string;
  readonly iss: string;
  readonly aud: string;
  readonly exp: number;
  readonly intent: string;
  readonly email?: string;
};

export const JWT_ALG = "HS256";
export const JWT_TYP = "JWT";

/**
 * Overlap key set for HS256 secret rotation (task 36b).
 * Sign ALWAYS with `current`; verify tries `current` first, then `previous`
 * while it is configured. No `previous` configured = strict single-key.
 * `kid` binds a token to the key that signed it: a token carrying an unknown
 * kid rejects even if its signature would verify under a configured secret.
 */
export interface JwtKeySet {
  readonly current: string;
  readonly currentKid: string;
  readonly previous?: string;
  readonly previousKid?: string;
}

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
  claims: Pick<AccessPayload, "sub" | "sid" | "iss" | "aud" | "intent"> & {
    readonly email?: string;
  },
  secret: string,
  ttlSeconds: number,
  opts?: { readonly kid?: string },
): string {
  const header: Record<string, string> =
    opts?.kid === undefined || opts.kid === "" ? { alg: JWT_ALG, typ: JWT_TYP } : { alg: JWT_ALG, typ: JWT_TYP, kid: opts.kid };
  const now = Math.floor(Date.now() / 1000);
  const payload: AccessPayload =
    claims.email === undefined || claims.email === ""
      ? { ...claims, exp: now + ttlSeconds }
      : { ...claims, email: claims.email, exp: now + ttlSeconds };
  const data = `${b64UrlEncode(JSON.stringify(header))}.${b64UrlEncode(JSON.stringify(payload))}`;
  return `${data}.${signData(data, secret)}`;
}

export class JwtError extends Error {}

export function verifyAccess(token: string, secret: string | JwtKeySet, expectedIss: string, expectedAud: string, expectedIntent?: string): AccessPayload {
  const parts = token.split(".");
  if (parts.length !== 3) throw new JwtError("malformed jwt");
  const [headerEnc, payloadEnc, sig] = parts;
  if (headerEnc === undefined || payloadEnc === undefined || sig === undefined) throw new JwtError("malformed jwt");
  let header: unknown;
  let payload: unknown;
  try {
    header = JSON.parse(b64UrlDecode(headerEnc));
    payload = JSON.parse(b64UrlDecode(payloadEnc));
  } catch {
    throw new JwtError("malformed jwt");
  }
  if (typeof header !== "object" || header === null || !("alg" in header) || header.alg !== JWT_ALG) {
    throw new JwtError("unsupported alg");
  }
  const tokenKid = "kid" in header && typeof header.kid === "string" && header.kid !== "" ? header.kid : null;
  const keySet: JwtKeySet =
    typeof secret === "string" ? { current: secret, currentKid: "" } : secret;
  if (tokenKid !== null) {
    const known =
      (keySet.currentKid !== "" && tokenKid === keySet.currentKid) ||
      (keySet.previousKid !== undefined && tokenKid === keySet.previousKid);
    if (!known) throw new JwtError("unknown kid");
  }
  const candidates: string[] =
    tokenKid === null
      ? (keySet.previous === undefined ? [keySet.current] : [keySet.current, keySet.previous])
      : tokenKid === keySet.previousKid && keySet.previous !== undefined
        ? [keySet.previous]
        : [keySet.current];
  const data = `${headerEnc}.${payloadEnc}`;
  const presented = b64UrlDecodeBytes(sig);
  let signatureOk = false;
  for (const candidate of candidates) {
    const expected = b64UrlDecodeBytes(signData(data, candidate));
    if (presented.length === expected.length && timingSafeEqual(presented, expected)) {
      signatureOk = true;
      break;
    }
  }
  if (!signatureOk) throw new JwtError("bad signature");
  if (typeof payload !== "object" || payload === null) throw new JwtError("malformed payload");
  const p = Object.fromEntries(Object.entries(payload));
  if (
    typeof p.sub !== "string" ||
    p.sub === "" ||
    typeof p.sid !== "string" ||
    p.sid === "" ||
    typeof p.iss !== "string" ||
    p.iss !== expectedIss ||
    typeof p.aud !== "string" ||
    p.aud !== expectedAud ||
    typeof p.exp !== "number" ||
    typeof p.intent !== "string" ||
    (expectedIntent !== undefined && p.intent !== expectedIntent)
  ) {
    throw new JwtError("malformed payload");
  }
  if (p.exp <= Math.floor(Date.now() / 1000)) throw new JwtError("expired");
  return {
    sub: p.sub,
    sid: p.sid,
    iss: p.iss,
    aud: p.aud,
    exp: p.exp,
    intent: p.intent,
    ...(typeof p.email === "string" && p.email !== "" ? { email: p.email } : {}),
  } satisfies ParsedAccessPayload;
}

// --- PKCE (RFC 7636, S256 only — task 38) ---
//
// The server enforces S256 when a challenge is presented and rejects `plain`
// outright (no downgrade). Verifier/challenge shape follows RFC 7636 §4.1:
// 43–128 chars of [A-Z a-z 0-9 - . _ ~].

const PKCE_TOKEN_RE = /^[A-Za-z0-9\-._~]{43,128}$/;

/** True when the value is a well-formed PKCE verifier/challenge string. */
export function isValidPkceToken(value: string): boolean {
  return PKCE_TOKEN_RE.test(value);
}

/** S256 code_challenge for a verifier: base64url(sha256(verifier)), no padding. */
export function pkceS256Challenge(verifier: string): string {
  return Buffer.from(createHash("sha256").update(verifier, "utf8").digest()).toString("base64url");
}

/** True when sha256(verifier) matches the stored S256 challenge (constant-time). */
export function verifyPkceS256(verifier: string, challenge: string): boolean {
  const want = pkceS256Challenge(verifier);
  const da = createHash("sha256").update(challenge, "utf8").digest();
  const db = createHash("sha256").update(want, "utf8").digest();
  return da.length === db.length && timingSafeEqual(da, db);
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
  if (!hashEqual(sig, want)) throw new TokenError("invalid token");
  return { userId };
}

/**
 * Constant-time string equality (length + timingSafeEqual on the sha256
 * digests, so unequal lengths do not early-exit with a timing signal).
 * Used for opaque-token digest compares where the caller must not leak
 * which candidate matched (refresh reuse detection, purpose HMACs).
 */
export function hashEqual(a: string, b: string): boolean {
  const da = createHash("sha256").update(a, "utf8").digest();
  const db = createHash("sha256").update(b, "utf8").digest();
  return da.length === db.length && timingSafeEqual(da, db);
}

// --- User-scoped IDE tokens (project-ide task 38) ---
//
// Minted at desktop Google-login completion for the IDE, which stores the
// pair in the OS keychain and presents the access token as
// `Authorization: Bearer <access>` to TokenPanel IDE reads. TokenPanel
// verifies these DIRECTLY with the shared secret set (operator provisions
// AUTH_JWT_SECRET to the same bytes as this service's JWT_SECRET) and the
// existing KIDs: sign ALWAYS with `current`, verify tries current then
// previous while configured, kid-bound exactly like verifyAccess above.
//
// Claims: sub (opaque alcore identity), scope (array subset of
// USER_TOKEN_SCOPES), jti (unique per access token), iss (authority),
// aud tokenpanel (consuming product), intent ide_read (distinct from the
// session/product_exchange/oidc intents so existing verifiers reject these
// fail-closed), exp 10 min, iat. No email, no sid: TokenPanel enforces
// self-only by matching query authUserId == sub server-side.

export const USER_TOKEN_TTL_SECONDS = 600;
export const USER_TOKEN_AUDIENCE = "tokenpanel";
export const USER_TOKEN_INTENT = "ide_read";
export const USER_TOKEN_SCOPES = ["profile:read", "quota:read", "tier:read"] as const;
export type UserTokenScope = (typeof USER_TOKEN_SCOPES)[number];

export interface UserTokenClaims {
  readonly sub: string;
  readonly scope: readonly string[];
  readonly iss: string;
}

export interface UserTokenPayload {
  readonly sub: string;
  readonly scope: string[];
  readonly jti: string;
  readonly iss: string;
  readonly aud: string;
  readonly exp: number;
  readonly iat: number;
  readonly intent: string;
}

/** True when every entry is a known IDE scope (non-empty array). */
export function isValidUserTokenScopeSet(scopes: unknown): scopes is UserTokenScope[] {
  if (!Array.isArray(scopes) || scopes.length === 0) return false;
  const allowed = new Set<string>(USER_TOKEN_SCOPES);
  return scopes.every((s) => typeof s === "string" && allowed.has(s));
}

export function signUserToken(
  claims: UserTokenClaims,
  secret: string,
  ttlSeconds: number = USER_TOKEN_TTL_SECONDS,
  opts?: { readonly kid?: string },
): string {
  if (typeof claims.sub !== "string" || claims.sub === "" || claims.sub.length > 256) {
    throw new JwtError("malformed payload");
  }
  if (typeof claims.iss !== "string" || claims.iss === "") throw new JwtError("malformed payload");
  if (!isValidUserTokenScopeSet(claims.scope)) throw new JwtError("malformed payload");
  const header: Record<string, string> =
    opts?.kid === undefined || opts.kid === ""
      ? { alg: JWT_ALG, typ: JWT_TYP }
      : { alg: JWT_ALG, typ: JWT_TYP, kid: opts.kid };
  const now = Math.floor(Date.now() / 1000);
  const payload: UserTokenPayload = {
    sub: claims.sub,
    scope: [...claims.scope],
    jti: crypto.randomUUID(),
    iss: claims.iss,
    aud: USER_TOKEN_AUDIENCE,
    exp: now + ttlSeconds,
    iat: now,
    intent: USER_TOKEN_INTENT,
  };
  const data = `${b64UrlEncode(JSON.stringify(header))}.${b64UrlEncode(JSON.stringify(payload))}`;
  return `${data}.${signData(data, secret)}`;
}

export class UserTokenError extends Error {}

/**
 * Verify a user-scoped IDE access token against the rotation key set.
 * Throws UserTokenError on ANY defect (callers collapse to 401, no oracle).
 */
export function verifyUserToken(
  token: string,
  secret: string | JwtKeySet,
  expectedIss: string,
): UserTokenPayload {
  const parts = token.split(".");
  if (parts.length !== 3) throw new UserTokenError("malformed jwt");
  const [headerEnc, payloadEnc, sig] = parts;
  if (headerEnc === undefined || payloadEnc === undefined || sig === undefined) {
    throw new UserTokenError("malformed jwt");
  }
  let header: unknown;
  let payload: unknown;
  try {
    header = JSON.parse(b64UrlDecode(headerEnc));
    payload = JSON.parse(b64UrlDecode(payloadEnc));
  } catch {
    throw new UserTokenError("malformed jwt");
  }
  if (typeof header !== "object" || header === null || !("alg" in header) || header.alg !== JWT_ALG) {
    throw new UserTokenError("unsupported alg");
  }
  const tokenKid = "kid" in header && typeof header.kid === "string" && header.kid !== "" ? header.kid : null;
  const keySet: JwtKeySet = typeof secret === "string" ? { current: secret, currentKid: "" } : secret;
  if (tokenKid !== null) {
    const known =
      (keySet.currentKid !== "" && tokenKid === keySet.currentKid) ||
      (keySet.previousKid !== undefined && tokenKid === keySet.previousKid);
    if (!known) throw new UserTokenError("unknown kid");
  }
  const candidates: string[] =
    tokenKid === null
      ? (keySet.previous === undefined ? [keySet.current] : [keySet.current, keySet.previous])
      : tokenKid === keySet.previousKid && keySet.previous !== undefined
        ? [keySet.previous]
        : [keySet.current];
  const data = `${headerEnc}.${payloadEnc}`;
  let presented: Uint8Array;
  try {
    presented = b64UrlDecodeBytes(sig);
  } catch {
    throw new UserTokenError("malformed jwt");
  }
  let signatureOk = false;
  for (const candidate of candidates) {
    let expected: Uint8Array;
    try {
      expected = b64UrlDecodeBytes(signData(data, candidate));
    } catch {
      continue;
    }
    if (presented.length === expected.length && timingSafeEqual(presented, expected)) {
      signatureOk = true;
      break;
    }
  }
  if (!signatureOk) throw new UserTokenError("bad signature");
  if (typeof payload !== "object" || payload === null) throw new UserTokenError("malformed payload");
  const p = payload as Record<string, unknown>;
  if (typeof p["sub"] !== "string" || p["sub"] === "" || (p["sub"] as string).length > 256) {
    throw new UserTokenError("malformed payload");
  }
  if (p["iss"] !== expectedIss) throw new UserTokenError("malformed payload");
  if (p["aud"] !== USER_TOKEN_AUDIENCE) throw new UserTokenError("malformed payload");
  if (p["intent"] !== USER_TOKEN_INTENT) throw new UserTokenError("malformed payload");
  if (typeof p["exp"] !== "number" || !Number.isFinite(p["exp"])) throw new UserTokenError("malformed payload");
  if (typeof p["iat"] !== "number" || !Number.isFinite(p["iat"])) throw new UserTokenError("malformed payload");
  if (!isValidUserTokenScopeSet(p["scope"])) throw new UserTokenError("malformed payload");
  if (typeof p["jti"] !== "string" || p["jti"] === "") throw new UserTokenError("malformed payload");
  if ((p["exp"] as number) <= Math.floor(Date.now() / 1000)) throw new UserTokenError("expired");
  return {
    sub: p["sub"] as string,
    scope: [...(p["scope"] as string[])],
    jti: p["jti"] as string,
    iss: p["iss"] as string,
    aud: USER_TOKEN_AUDIENCE,
    exp: p["exp"] as number,
    iat: p["iat"] as number,
    intent: USER_TOKEN_INTENT,
  };
}
