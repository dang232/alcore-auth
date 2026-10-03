// ALcore Auth Repo C — runtime config (identity-only).
// Fail-fast JWT_SECRET semantics mirror AlRepo apps/api/src/config/runtime.ts
// parseJwtSecret: the variable NAME is reported, never the value.

export type NodeEnv = "production" | "development" | "test";

export function nodeEnv(): NodeEnv {
  const raw = (process.env["NODE_ENV"] ?? "").trim().toLowerCase();
  if (raw === "production") return "production";
  if (raw === "test") return "test";
  return "development";
}

export const MIN_JWT_SECRET_LEN = 32;
export const DEFAULT_AUTH_PORT = 8082;
export const DEFAULT_BIND_HOST = "127.0.0.1";
export const DEFAULT_AUTH_DATABASE_PATH = "./data/auth.sqlite";

export function getAuthDatabasePath(): string {
  if (nodeEnv() === "test") return ":memory:";
  return (process.env["AUTH_DATABASE_PATH"] ?? DEFAULT_AUTH_DATABASE_PATH).trim();
}

// F0 backend selection. "postgres" answers every repository call from
// managed PostgreSQL (target topology); anything else (default) keeps the
// file-backed SQLite fallback. Case-insensitive, whitespace-tolerant.
export type AuthStoreBackend = "sqlite" | "postgres";

export function getAuthStoreBackend(): AuthStoreBackend {
  return (process.env["AUTH_STORE_BACKEND"] ?? "").trim().toLowerCase() === "postgres"
    ? "postgres"
    : "sqlite";
}

/**
 * PostgreSQL connection string for the postgres backend. Required (fail-fast,
 * naming DATABASE_URL — never its value) exactly when the postgres backend
 * is selected; unread otherwise so SQLite-only deploys need no new secret.
 */
export function getDatabaseUrl(): string {
  const raw = (process.env["DATABASE_URL"] ?? "").trim();
  if (raw === "" && getAuthStoreBackend() === "postgres") {
    throw new Error("DATABASE_URL is required when AUTH_STORE_BACKEND=postgres (use a postgres:// connection string)");
  }
  return raw;
}
export const DEFAULT_ISSUER = "https://auth.alcore.io.vn";

const DEFAULT_ALLOWED_ORIGINS: string[] = [
  "https://web.alcore.io.vn",
  "https://alcore.io.vn",
  "http://localhost:3000",
  "http://localhost:8081",
];

export function getGoogleClientId(): string {
  return (process.env["GOOGLE_CLIENT_ID"] ?? "").trim();
}

export function getGoogleRedirectUri(): string {
  return (process.env["GOOGLE_REDIRECT_URI"] ?? `${getIssuer()}/auth/google/callback`).trim();
}

// NOTE (unified-auth-core todo 10): Auth is who-only and NEVER calls products.
// The former TOKENPANEL_PROVISION_* push-client config was removed here:
// zero references in src/compose, zero fetch() to any product. Products pull
// Auth proof instead — see docs/pull-provision-contract.md.

const SAMPLE_SECRETS = new Set([
  "changeme",
  "secret",
  "password",
  "jwt-secret",
  "dev-secret",
  "test-secret",
  "example-secret",
  "default-secret",
  "replace-me",
]);

function isSampleSecret(raw: string): boolean {
  const v = raw.trim().toLowerCase();
  if (SAMPLE_SECRETS.has(v)) return true;
  return v.includes("changeme") || v.includes("example") || v.includes("replace-me");
}

let cachedEphemeral: string | null = null;

function ephemeralSecret(): string {
  if (cachedEphemeral === null) {
    const buf = new Uint8Array(48);
    crypto.getRandomValues(buf);
    let hex = "";
    for (const b of buf) hex += b.toString(16).padStart(2, "0");
    cachedEphemeral = hex;
    console.warn(
      "[auth-service] JWT_SECRET unset: using ephemeral dev/test secret (sessions do not survive restart)",
    );
  }
  return cachedEphemeral;
}
/** Returns the signing secret, or throws naming JWT_SECRET (never its value). */
export function getJwtSecret(): string {
  const env = nodeEnv();
  const raw = process.env["JWT_SECRET"] ?? "";
  const allowWeak = process.env["ALLOW_WEAK_JWT_SECRET"] === "1";
  if (raw === "") {
    if (env === "production") {
      throw new Error("JWT_SECRET is required in production (use a random 32+ character string)");
    }
    return ephemeralSecret();
  }
  if (!allowWeak && raw.length < MIN_JWT_SECRET_LEN) {
    throw new Error(
      `JWT_SECRET must be at least ${MIN_JWT_SECRET_LEN} characters (set ALLOW_WEAK_JWT_SECRET=1 only for tests)`,
    );
  }
  if (env === "production" && isSampleSecret(raw)) {
    throw new Error(
      "JWT_SECRET rejects known sample/default/weak values in production (generate a random 32+ char secret)",
    );
  }
  return raw;
}

export interface JwtRotationKeys {
  readonly current: string;
  readonly currentKid: string;
  readonly previous?: string;
  readonly previousKid?: string;
}

function checkRotationSecret(name: "JWT_SECRET_PREVIOUS", raw: string, allowWeak: boolean): void {
  if (!allowWeak && raw.length < MIN_JWT_SECRET_LEN) {
    throw new Error(
      `${name} must be at least ${MIN_JWT_SECRET_LEN} characters (set ALLOW_WEAK_JWT_SECRET=1 only for tests)`,
    );
  }
  if (nodeEnv() === "production" && isSampleSecret(raw)) {
    throw new Error(
      `${name} rejects known sample/default/weak values in production (generate a random 32+ char secret)`,
    );
  }
}

export function getJwtRotationKeys(): JwtRotationKeys {
  const current = getJwtSecret();
  const allowWeak = process.env["ALLOW_WEAK_JWT_SECRET"] === "1";
  const currentKid = (process.env["JWT_SECRET_KID"] ?? "").trim() === ""
    ? "k1"
    : (process.env["JWT_SECRET_KID"] ?? "").trim();
  const previousRaw = (process.env["JWT_SECRET_PREVIOUS"] ?? "").trim();
  if (previousRaw === "") return { current, currentKid };
  checkRotationSecret("JWT_SECRET_PREVIOUS", previousRaw, allowWeak);
  const previousKid = (process.env["JWT_SECRET_PREVIOUS_KID"] ?? "").trim() === ""
    ? "k0"
    : (process.env["JWT_SECRET_PREVIOUS_KID"] ?? "").trim();
  return { current, currentKid, previous: previousRaw, previousKid };
}

export function getAuthPort(): number {
  const raw = process.env["AUTH_PORT"] ?? String(DEFAULT_AUTH_PORT);
  if (!/^\d+$/.test(raw)) {
    throw new Error("AUTH_PORT must be a decimal integer 1..65535");
  }
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > 65535) {
    throw new Error("AUTH_PORT must be a decimal integer 1..65535");
  }
  return n;
}

export function getBindHost(): string {
  const raw = (process.env["AUTH_HOST"] ?? "").trim();
  return raw === "" ? DEFAULT_BIND_HOST : raw;
}

export function getIssuer(): string {
  const raw = (process.env["AUTH_ISSUER"] ?? "").trim();
  return raw === "" ? DEFAULT_ISSUER : raw;
}

export function getAllowedOrigins(): string[] {
  const raw = process.env["AUTH_ALLOWED_ORIGINS"] ?? "";
  if (raw.trim() === "") return [...DEFAULT_ALLOWED_ORIGINS];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s !== "");
}

export function getOidcClients(): ReadonlyMap<string, string> {
  const raw = process.env["AUTH_OIDC_CLIENTS"] ?? "";
  return new Map(raw.split(",").flatMap((entry) => {
    const separator = entry.indexOf("=");
    const clientId = entry.slice(0, separator).trim();
    const redirectUri = entry.slice(separator + 1).trim();
    return separator > 0 && redirectUri !== "" ? [[clientId, redirectUri]] : [];
  }));
}

export interface MailConfig {
  readonly host: string;
  readonly port: number;
  readonly username: string;
  readonly password: string;
  readonly from: string;
  readonly secure: boolean;
}

/**
 * Null when SMTP_HOST is unset. Verification and reset stay non-enumerating
 * either way: an unconfigured transport suppresses delivery instead of
 * revealing whether an account exists.
 */
export function getMailConfig(): MailConfig | null {
  const host = (process.env["SMTP_HOST"] ?? "").trim();
  if (host === "") return null;
  const portRaw = (process.env["SMTP_PORT"] ?? "").trim();
  const port = portRaw === "" ? 587 : Number(portRaw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("SMTP_PORT must be a decimal integer 1..65535");
  }
  return {
    host,
    port,
    // SMTP_USER/SMTP_PASS match the platform-wide convention already used by
    // TokenPanel's config fields and generated manifest. SMTP_USERNAME/
    // SMTP_PASSWORD are accepted as aliases so either .env layout works.
    username: (process.env["SMTP_USER"] ?? process.env["SMTP_USERNAME"] ?? "").trim(),
    password: process.env["SMTP_PASS"] ?? process.env["SMTP_PASSWORD"] ?? "",
    from: (process.env["SMTP_FROM"] ?? "").trim(),
    secure: port === 465,
  };
}
