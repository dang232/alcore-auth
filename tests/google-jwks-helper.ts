// ALcore Auth Repo C — shared Google JWKS test rig (todo 35).
// Generates a throwaway RSA pair per rig, serves its public half as a JWKS
// body, and mints RS256 ID tokens against it. Dummy values only; never real
// Google keys, tokens, or PII. Resets the verifier JWKS cache on creation so
// cases never leak keys into each other.

import { createSign, generateKeyPairSync, type KeyObject } from "node:crypto";
import { resetGoogleJwksCacheForTests } from "../src/lib/google";

export const TEST_GOOGLE_CLIENT_ID = "test-client.apps.googleusercontent.com";

export interface GoogleTestRig {
  readonly kid: string;
  readonly jwksBody: { keys: Record<string, unknown>[] };
  mintIdToken(claims: Record<string, unknown>, opts?: { kid?: string; alg?: string; key?: KeyObject }): string;
  /**
   * Fetch dispatcher for Google flows: the token endpoint answers with the
   * given id_token, the JWKS URL answers with this rig's key set. Returns the
   * restore function plus a counter of JWKS hits (proves forced refresh).
   */
  installFetch(idTokenForTokenEndpoint: string): { restore: () => void; jwksHits: () => number };
}

function b64urlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

export function createGoogleTestRig(): GoogleTestRig {
  resetGoogleJwksCacheForTests();
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const kid = `test-kid-${Math.random().toString(36).slice(2, 10)}`;
  const jwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
  const jwksBody = { keys: [{ ...jwk, kid, use: "sig", alg: "RS256" }] };

  function mintIdToken(
    claims: Record<string, unknown>,
    opts?: { kid?: string; alg?: string; key?: KeyObject },
  ): string {
    const header = { alg: opts?.alg ?? "RS256", typ: "JWT", kid: opts?.kid ?? kid };
    const signingInput = `${b64urlJson(header)}.${b64urlJson(claims)}`;
    if ((opts?.alg ?? "RS256") === "none") return `${signingInput}.`;
    const signer = createSign("RSA-SHA256");
    signer.update(signingInput, "ascii");
    const signature = signer.sign(opts?.key ?? privateKey).toString("base64url");
    return `${signingInput}.${signature}`;
  }

  function installFetch(idTokenForTokenEndpoint: string): { restore: () => void; jwksHits: () => number } {
    const originalFetch = globalThis.fetch;
    let hits = 0;
    const mocked = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/certs")) {
        hits += 1;
        return new Response(JSON.stringify(jwksBody), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url.includes("oauth2.googleapis.com/token")) {
        return new Response(JSON.stringify({ id_token: idTokenForTokenEndpoint }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(JSON.stringify({}), { status: 404 });
    }) as typeof globalThis.fetch;
    (mocked as unknown as Record<string, unknown>)["preconnect"] = (
      globalThis.fetch as unknown as Record<string, unknown>
    )["preconnect"];
    globalThis.fetch = mocked;
    return { restore: () => { globalThis.fetch = originalFetch; }, jwksHits: () => hits };
  }

  return { kid, jwksBody, mintIdToken, installFetch };
}

/** Base claims every minted test token carries unless overridden. */
export function baseGoogleClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const nowSeconds = Math.floor(Date.now() / 1000);
  return {
    aud: TEST_GOOGLE_CLIENT_ID,
    iss: "https://accounts.google.com",
    exp: nowSeconds + 300,
    iat: nowSeconds - 10,
    sub: "test-subject-1",
    email: "test-user@example.com",
    email_verified: true,
    ...overrides,
  };
}
