// Post-register provisioning hook (todo 14) — DOCUMENTATION + key builder.
// Identity-only guard: this module owns NO business logic, creates NO
// customers/billing rows, and is NOT imported by any route. Auth stays
// who-only; TokenPanel owns what-is-owned.
//
// Pull model (preferred — no outbound call from Auth):
//   1. Client POSTs /auth/register → 201 {id, email, emailVerified}.
//   2. The caller (TokenPanel-pull or Libre/BFF-mediated S2S) POSTs the
//      TokenPanel management route /api/management/customers/provision with
//      {authUserId: id, email} and Idempotency-Key: <canonical key below>.
//   3. A timeout retry re-sends the SAME key → TokenPanel returns the
//      EXISTING customer (linked: "existing"), never a second row.
//
// The canonical key is `customer-provision:{auth_user_id}`, derived
// server-side by TokenPanel from authUserId; forwarding it as the
// Idempotency-Key header keeps logs correlatable end-to-end.

export const PROVISION_KEY_PREFIX = "customer-provision:";

/** Canonical provision idempotency key for an Auth user id. */
export function buildProvisionKey(authUserId: string): string {
  return `${PROVISION_KEY_PREFIX}${authUserId}`;
}

/** Shape of the Auth register response this hook consumes (read-only). */
export interface AuthRegisterResult {
  id: string;
  email: string;
  emailVerified: boolean;
}

/**
 * Build the TokenPanel provision request for a fresh register result.
 * Unwired helper — call sites live OUTSIDE Auth (TokenPanel-pull / BFF).
 */
export function provisionRequestFor(
  user: AuthRegisterResult,
  name?: string,
): {
  body: { authUserId: string; email: string; name?: string };
  idempotencyKey: string;
} {
  return {
    body: {
      authUserId: user.id,
      email: user.email.toLowerCase(),
      ...(name !== undefined && name.trim().length > 0
        ? { name: name.trim().slice(0, 160) }
        : {}),
    },
    idempotencyKey: buildProvisionKey(user.id),
  };
}
