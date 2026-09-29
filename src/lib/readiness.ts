// ALcore Auth Repo C — readiness probe (task 26 parallel staging).
// Liveness (GET /health) is process-alive only. Readiness (GET /health/ready)
// verifies the request-critical identity substrate with REAL checks:
//   config — JWT signing secret resolves (fail-closed in prod, todo 6/8);
//   store  — identity substrate accepts a write/read/delete round-trip;
//   signer — HS256 sign→verify round-trip with the resolved secret + issuer
//            (the exact path every login/session/refresh request depends on).
// Auth has no external DB (in-memory by design; persistent store is
// downstream), so there is no mongo-style kill-DB probe here — the fail-closed
// surface is prod boot (exit 1 without JWT_SECRET) plus these per-request
// substrate checks. Responses name variables only, never secret values.

import { getIssuer, getJwtSecret } from "../config";
import { signAccess, verifyAccess } from "./crypto";

export type ProbeOutcome = "ok" | "down";

export interface AuthReadiness {
  readonly ready: boolean;
  readonly status: "ok" | "unavailable";
  readonly checks: Record<"config" | "store" | "signer", ProbeOutcome>;
  readonly reasons: readonly string[];
}

export interface ReadinessDeps {
  readonly resolveSecret: () => string;
  readonly resolveIssuer: () => string;
  readonly probeStore: () => boolean;
  readonly roundTripSigner: (secret: string, issuer: string) => boolean;
}

/** Isolated substrate cells — never in the user/session/OIDC namespaces. */
const probeCells = new Map<string, string>();

export function probeIdentitySubstrate(): boolean {
  const key = `probe:${crypto.randomUUID()}`;
  const nonce = crypto.randomUUID();
  probeCells.set(key, nonce);
  const readBack = probeCells.get(key);
  probeCells.delete(key);
  return readBack === nonce && !probeCells.has(key);
}

export function roundTripSigner(secret: string, issuer: string): boolean {
  const token = signAccess({ sub: "__probe__", sid: "__probe__", iss: issuer, aud: "auth", intent: "session" }, secret, 60);
  const payload = verifyAccess(token, secret, issuer, "auth", "session");
  return payload.sub === "__probe__" && payload.iss === issuer;
}

const defaultDeps: ReadinessDeps = {
  resolveSecret: getJwtSecret,
  resolveIssuer: getIssuer,
  probeStore: probeIdentitySubstrate,
  roundTripSigner,
};

export function authReadiness(deps: ReadinessDeps = defaultDeps): AuthReadiness {
  const checks: Record<"config" | "store" | "signer", ProbeOutcome> = {
    config: "down",
    store: "down",
    signer: "down",
  };
  const reasons: string[] = [];
  let secret = "";
  let issuer = "";
  try {
    secret = deps.resolveSecret();
    issuer = deps.resolveIssuer();
    checks.config = "ok";
  } catch {
    reasons.push("config_unavailable");
  }
  if (checks.config === "ok") {
    try {
      checks.store = deps.probeStore() ? "ok" : "down";
      if (checks.store !== "ok") reasons.push("store_unwritable");
    } catch {
      reasons.push("store_unwritable");
    }
    try {
      checks.signer = deps.roundTripSigner(secret, issuer) ? "ok" : "down";
      if (checks.signer !== "ok") reasons.push("signer_failed");
    } catch {
      reasons.push("signer_failed");
    }
  } else {
    reasons.push("store_skipped", "signer_skipped");
  }
  const ready = checks.config === "ok" && checks.store === "ok" && checks.signer === "ok";
  return { ready, status: ready ? "ok" : "unavailable", checks, reasons };
}
