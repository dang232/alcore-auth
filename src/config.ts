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
export const DEFAULT_ISSUER = "https://auth.alcore.io.vn";

const DEFAULT_ALLOWED_ORIGINS: string[] = [
  "https://web.alcore.io.vn",
  "https://alcore.io.vn",
  "http://localhost:3000",
  "http://localhost:8081",
];

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
