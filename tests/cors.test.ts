// ALcore Auth Repo C — CORS matrix suite (VPS staging proof fix).
// Proves the service emits exact-origin ACAO headers for the plan
// triangle (mirror of the todo-9 contract): good origin echoed with
// credentials, evil origin denied, preflight 204 without auth.

process.env["JWT_SECRET"] = "test-only-dummy-secret-0123456789abcdef";
process.env["ALLOW_WEAK_JWT_SECRET"] = "1";
process.env["NODE_ENV"] = "test";

import { describe, test, expect } from "bun:test";
import { app } from "../src/index";
import { getAllowedOrigins } from "../src/config";

const GOOD = "https://web.alcore.io.vn";
const EVIL = "https://evil.example";

describe("CORS matrix", () => {
  test("defaults cover the live triangle origin (code default, no env)", async () => {
    expect(process.env["AUTH_ALLOWED_ORIGINS"] ?? "").toBe("");
    expect(getAllowedOrigins()).toContain(GOOD);
  });

  test("good origin on GET: exact ACAO echo + credentials + Vary, never *", async () => {
    const res = await app.request("/health", { headers: { origin: GOOD } });
    expect(res.status).toBe(200);
    expect(res.headers.get("access-control-allow-origin")).toBe(GOOD);
    expect(res.headers.get("access-control-allow-credentials")).toBe("true");
    expect(res.headers.get("vary")).toMatch(/Origin/);
  });

  test("401s still carry CORS headers (middleware runs before auth)", async () => {
    const res = await app.request("/auth/me", { headers: { origin: GOOD } });
    expect(res.status).toBe(401);
    expect(res.headers.get("access-control-allow-origin")).toBe(GOOD);
    expect(res.headers.get("access-control-allow-credentials")).toBe("true");
  });

  test("evil origin on GET: NO ACAO echo, NO credentials grant", async () => {
    const res = await app.request("/health", { headers: { origin: EVIL } });
    expect(res.status).toBe(200);
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
    expect(res.headers.get("access-control-allow-credentials")).toBeNull();
  });

  test("preflight without token: 204, ACAO echo, Allow-Headers, Max-Age, credentials", async () => {
    const res = await app.request("/auth/login", {
      method: "OPTIONS",
      headers: {
        origin: GOOD,
        "access-control-request-method": "POST",
        "access-control-request-headers": "Authorization, Content-Type",
      },
    });
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBe(GOOD);
    expect(res.headers.get("access-control-allow-credentials")).toBe("true");
    const allowHeaders = res.headers.get("access-control-allow-headers") ?? "";
    expect(allowHeaders).toMatch(/Authorization/);
    expect(allowHeaders).toMatch(/Content-Type/);
    expect(res.headers.get("access-control-max-age")).toBe("600");
    expect(res.headers.get("vary")).toMatch(/Origin/);
  });

  test("preflight from evil origin: 204 with NO ACAO echo, NO credentials grant", async () => {
    const res = await app.request("/auth/login", {
      method: "OPTIONS",
      headers: {
        origin: EVIL,
        "access-control-request-method": "POST",
        "access-control-request-headers": "Authorization, Content-Type",
      },
    });
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
    expect(res.headers.get("access-control-allow-credentials")).toBeNull();
  });

  test("apex allowlist entry still echoed (shared OIDC allowlist read-only)", async () => {
    const res = await app.request("/health", {
      headers: { origin: "https://alcore.io.vn" },
    });
    expect(res.headers.get("access-control-allow-origin")).toBe("https://alcore.io.vn");
  });
});
