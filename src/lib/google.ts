// ALcore Auth Repo C — Google ID-token verification (todo 35).
// Production authorization-code verification: RS256 signature checked LOCALLY
// against Google's JWKS (kid-indexed, forced refresh on unknown kid), plus
// issuer, audience, expiry/iat, nonce, and email_verified. No tokeninfo call:
// the tokeninfo endpoint cannot check signatures or kid rotation and costs a
// network round-trip per login (DEVIATION D1 in TARGET-ARCHITECTURE.md §6).
// Fail-closed: any verification failure is GoogleCredentialError (generic
// invalid credential, no enumeration); only transport failure fetching the
// JWKS itself is GoogleUpstreamError. No tokens, secrets, or PII are logged.

import { createPublicKey, createVerify, type KeyObject } from "node:crypto";
import { getGoogleClientId } from "../config";

export interface VerifiedGoogleProfile {
  readonly subject: string;
  readonly email: string;
}

export class GoogleCredentialError extends Error {
  constructor() {
    super("Invalid Google credential");
    this.name = "GoogleCredentialError";
  }
}

export class GoogleUpstreamError extends Error {
  constructor() {
    super("Google verification service unavailable");
    this.name = "GoogleUpstreamError";
  }
}

const GOOGLE_JWKS_URL_DEFAULT = "https://www.googleapis.com/oauth2/v3/certs";
const JWKS_FETCH_TIMEOUT_MS = 5_000;
const JWKS_CACHE_TTL_MS = 5 * 60 * 1000;
const CLOCK_SKEW_MS = 5 * 60 * 1000;

export function getGoogleJwksUrl(): string {
  const raw = (process.env["GOOGLE_JWKS_URL"] ?? "").trim();
  return raw === "" ? GOOGLE_JWKS_URL_DEFAULT : raw;
}

interface JwksCache {
  keys: Map<string, KeyObject>;
  fetchedAt: number;
}

let jwksCache: JwksCache | null = null;

/** Test-only hook: drop the in-memory JWKS cache between cases. */
export function resetGoogleJwksCacheForTests(): void {
  jwksCache = null;
}

function base64UrlDecode(input: string): Buffer {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(normalized, "base64");
}

async function fetchJwks(url: string): Promise<Map<string, KeyObject>> {
  let response: Response;
  try {
    response = await fetch(url, { signal: AbortSignal.timeout(JWKS_FETCH_TIMEOUT_MS) });
  } catch {
    throw new GoogleUpstreamError();
  }
  if (!response.ok) throw new GoogleUpstreamError();
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new GoogleUpstreamError();
  }
  if (typeof body !== "object" || body === null || !Array.isArray((body as { keys?: unknown }).keys)) {
    throw new GoogleUpstreamError();
  }
  const keys = new Map<string, KeyObject>();
  for (const entry of (body as { keys: unknown[] }).keys) {
    if (typeof entry !== "object" || entry === null) continue;
    const jwk = entry as Record<string, unknown>;
    if (jwk["kty"] !== "RSA" || typeof jwk["kid"] !== "string" || jwk["kid"] === "") continue;
    try {
      keys.set(jwk["kid"], createPublicKey({ key: jwk as object, format: "jwk" }));
    } catch {
      // Skip unusable keys; a missing kid fails closed below.
    }
  }
  return keys;
}

async function keyForKid(kid: string): Promise<KeyObject | null> {
  const now = Date.now();
  const url = getGoogleJwksUrl();
  if (jwksCache !== null && now - jwksCache.fetchedAt < JWKS_CACHE_TTL_MS) {
    const hit = jwksCache.keys.get(kid);
    if (hit !== undefined) return hit;
    // Unknown kid on a fresh cache: forced refresh once (rotation), then reject.
    const refreshed = await fetchJwks(url);
    jwksCache = { keys: refreshed, fetchedAt: Date.now() };
    return refreshed.get(kid) ?? null;
  }
  const fresh = await fetchJwks(url);
  jwksCache = { keys: fresh, fetchedAt: Date.now() };
  const hit = fresh.get(kid);
  if (hit !== undefined) return hit;
  // Stale-cache race: one forced refresh before failing closed.
  const refreshed = await fetchJwks(url);
  jwksCache = { keys: refreshed, fetchedAt: Date.now() };
  return refreshed.get(kid) ?? null;
}

export async function verifyGoogleCredential(
  idToken: string,
  expectedNonce: string | undefined = undefined,
): Promise<VerifiedGoogleProfile> {
  const audience = getGoogleClientId();
  if (audience === "") throw new GoogleCredentialError();
  const parts = idToken.split(".");
  if (parts.length !== 3 || parts[0] === "" || parts[1] === "" || parts[2] === "") {
    throw new GoogleCredentialError();
  }
  const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];
  let header: unknown;
  let claims: unknown;
  try {
    header = JSON.parse(base64UrlDecode(encodedHeader).toString("utf8"));
    claims = JSON.parse(base64UrlDecode(encodedPayload).toString("utf8"));
  } catch {
    throw new GoogleCredentialError();
  }
  if (typeof header !== "object" || header === null) throw new GoogleCredentialError();
  const { alg, kid } = header as Record<string, unknown>;
  // Only RS256 with an explicit kid is accepted; alg=none (or anything else)
  // and missing-kid tokens fail closed without a network call.
  if (alg !== "RS256" || typeof kid !== "string" || kid === "") throw new GoogleCredentialError();
  const key = await keyForKid(kid);
  if (key === null) throw new GoogleCredentialError();
  const signature = base64UrlDecode(encodedSignature);
  const verifier = createVerify("RSA-SHA256");
  verifier.update(`${encodedHeader}.${encodedPayload}`, "ascii");
  if (!verifier.verify(key, signature)) throw new GoogleCredentialError();

  if (typeof claims !== "object" || claims === null) throw new GoogleCredentialError();
  const record = claims as Record<string, unknown>;
  const exp = Number(record["exp"]);
  const issuer = record["iss"];
  const emailVerified = record["email_verified"];
  const verified = emailVerified === true || emailVerified === "true";
  const iat = record["iat"];
  const now = Date.now();
  if (
    record["aud"] !== audience ||
    (issuer !== "accounts.google.com" && issuer !== "https://accounts.google.com") ||
    (expectedNonce !== undefined && record["nonce"] !== expectedNonce) ||
    !Number.isFinite(exp) || exp * 1000 <= now ||
    (iat !== undefined && (!Number.isFinite(Number(iat)) || Number(iat) * 1000 > now + CLOCK_SKEW_MS)) ||
    typeof record["sub"] !== "string" || record["sub"] === "" ||
    typeof record["email"] !== "string" || record["email"] === "" ||
    !verified
  ) {
    throw new GoogleCredentialError();
  }
  return { subject: record["sub"] as string, email: (record["email"] as string).trim().toLowerCase() };
}
