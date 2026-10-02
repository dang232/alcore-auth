// ALcore Auth Repo C — audit sink (task 38).
//
// Every Auth state transition emits its API-CONTRACT.md `audit_event` here.
// Identity-only: rows carry outcome + linkage ids only — never tokens,
// passwords, secrets, or PII beyond the opaque user id.
//
// Store: in-memory ring (bounded, no PII growth). Persistence/export cadence
// follows the TokenPanel audit-export pattern per SECURITY-AUDIT.md
// `audit-retention` row; until that export exists, this sink is the
// machine-verifiable emission proof the task-38 suite asserts on.
// Emission never throws into the request path: emit() is total.

export type AuditEvent =
  | "auth.register"
  | "auth.login"
  | "auth.login_failed"
  | "auth.refresh"
  | "auth.refresh_reuse"
  | "auth.logout"
  | "auth.session_read"
  | "auth.session_list"
  | "auth.session_revoke"
  | "auth.password_change"
  | "auth.password_rehash"
  | "auth.login_reset_required"
  | "auth.verify_request"
  | "auth.verify_consume"
  | "auth.reset_request"
  | "auth.reset_consume"
  | "auth.oauth_start"
  | "auth.oauth_callback"
  | "auth.identity_conflict"
  | "auth.oidc_authorize"
  | "auth.oidc_token"
  | "auth.exchange_request"
  | "auth.exchange_token";

export interface AuditRow {
  readonly event: AuditEvent;
  /** "ok" | contract-exact error code (e.g. "invalid_grant"), never a secret. */
  readonly outcome: string;
  readonly userId?: string;
  readonly clientId?: string;
  readonly ip?: string;
  readonly at: string;
}

const MAX_ROWS = 10_000;
let rows: AuditRow[] = [];

export function emitAudit(event: AuditEvent, outcome: string, fields?: { userId?: string; clientId?: string; ip?: string }): void {
  try {
    const row: AuditRow = {
      event,
      outcome: outcome.slice(0, 64),
      ...(fields?.userId !== undefined && fields.userId !== "" ? { userId: fields.userId } : {}),
      ...(fields?.clientId !== undefined && fields.clientId !== "" ? { clientId: fields.clientId } : {}),
      ...(fields?.ip !== undefined && fields.ip !== "" ? { ip: fields.ip } : {}),
      at: new Date().toISOString(),
    };
    rows.push(row);
    if (rows.length > MAX_ROWS) rows = rows.slice(rows.length - MAX_ROWS);
  } catch {
    // Audit must never break authentication.
  }
}

/** Test-only: snapshot rows (redacted by construction — no secrets stored). */
export function listAuditForTests(): AuditRow[] {
  return [...rows];
}

/** Test-only: drop all rows (mirrors resetStoresForTests). */
export function clearAuditForTests(): void {
  rows = [];
}
