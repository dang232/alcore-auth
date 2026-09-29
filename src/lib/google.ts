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

export async function verifyGoogleCredential(
  idToken: string,
  expectedNonce: string | undefined = undefined,
): Promise<VerifiedGoogleProfile> {
  const audience = getGoogleClientId();
  if (audience === "") throw new GoogleCredentialError();
  let response: Response;
  try {
    response = await fetch(
      `https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`,
      { signal: AbortSignal.timeout(5_000) },
    );
  } catch {
    throw new GoogleUpstreamError();
  }
  if (!response.ok) throw new GoogleCredentialError();
  let claims: unknown;
  try {
    claims = await response.json();
  } catch {
    throw new GoogleUpstreamError();
  }
  if (typeof claims !== "object" || claims === null) throw new GoogleUpstreamError();
  const record = claims as Record<string, unknown>;
  const exp = Number(record["exp"]);
  const issuer = record["iss"];
  const emailVerified = record["email_verified"];
  const verified = emailVerified === true || emailVerified === "true";
  if (
    record["aud"] !== audience ||
    (issuer !== "accounts.google.com" && issuer !== "https://accounts.google.com") ||
    (expectedNonce !== undefined && record["nonce"] !== expectedNonce) ||
    !Number.isFinite(exp) || exp * 1000 <= Date.now() ||
    typeof record["sub"] !== "string" || record["sub"].length === 0 ||
    typeof record["email"] !== "string" || record["email"].length === 0 ||
    !verified
  ) throw new GoogleCredentialError();
  return { subject: record["sub"], email: record["email"].trim().toLowerCase() };
}
