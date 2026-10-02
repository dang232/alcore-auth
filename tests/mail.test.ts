// ALcore Auth Repo C — outbound mail suite.
//
// The property under test is not "does SMTP work" but "can delivery ever
// become an account-existence oracle". /auth/verify/request and
// /auth/reset/request promise an always-200 response; a transport that is
// unconfigured, failing, or throwing must not change that, because a
// distinguishable status is exactly what turns those endpoints into an
// enumeration oracle.

import { describe, test, expect, beforeEach, afterEach } from "bun:test";

process.env["JWT_SECRET"] = "test-only-dummy-secret-0123456789abcdef";
process.env["ALLOW_WEAK_JWT_SECRET"] = "1";
process.env["NODE_ENV"] = "test";
delete process.env["SMTP_HOST"];

import { app } from "../src/index";
import {
  deliverPurposeMail,
  purposeLink,
  resetMailSender,
  setMailSender,
  type MailMessage,
} from "../src/lib/mail";
import { userStore } from "../src/lib/store";
import { resetRateLimitsForTests, resetThrottleConnForTests } from "../src/lib/ratelimit";
import { getMailConfig } from "../src/config";

const sent: MailMessage[] = [];

function capturingSender(outcome: "delivered" | "not_configured" | "failed" = "delivered") {
  setMailSender(async (message) => {
    sent.push(message);
    return outcome;
  });
}

describe("getMailConfig credential resolution", () => {
  const CREDENTIAL_KEYS = [
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_USER",
    "SMTP_PASS",
    "SMTP_USERNAME",
    "SMTP_PASSWORD",
    "SMTP_FROM",
  ] as const;

  beforeEach(() => {
    for (const key of CREDENTIAL_KEYS) delete process.env[key];
    process.env["SMTP_HOST"] = "smtp.gmail.com";
  });
  afterEach(() => {
    for (const key of CREDENTIAL_KEYS) delete process.env[key];
  });

  test("reads the platform-wide SMTP_USER / SMTP_PASS spelling", () => {
    process.env["SMTP_USER"] = "user@gmail.com";
    process.env["SMTP_PASS"] = "app-password";
    const config = getMailConfig();
    expect(config?.username).toBe("user@gmail.com");
    expect(config?.password).toBe("app-password");
  });

  test("reads the SMTP_USERNAME / SMTP_PASSWORD alias", () => {
    process.env["SMTP_USERNAME"] = "user@gmail.com";
    process.env["SMTP_PASSWORD"] = "app-password";
    const config = getMailConfig();
    expect(config?.username).toBe("user@gmail.com");
    expect(config?.password).toBe("app-password");
  });

  test("prefers SMTP_USER over the alias when both are present", () => {
    process.env["SMTP_USER"] = "canonical@gmail.com";
    process.env["SMTP_PASS"] = "canonical-pass";
    process.env["SMTP_USERNAME"] = "alias@gmail.com";
    process.env["SMTP_PASSWORD"] = "alias-pass";
    const config = getMailConfig();
    expect(config?.username).toBe("canonical@gmail.com");
    expect(config?.password).toBe("canonical-pass");
  });

  test("an empty password stays empty rather than falling back to a placeholder", () => {
    process.env["SMTP_USER"] = "user@gmail.com";
    const config = getMailConfig();
    expect(config?.username).toBe("user@gmail.com");
    expect(config?.password).toBe("");
  });

  test("defaults to port 587 with implicit STARTTLS, not implicit TLS", () => {
    process.env["SMTP_USER"] = "user@gmail.com";
    expect(getMailConfig()?.port).toBe(587);
    expect(getMailConfig()?.secure).toBe(false);
  });

  test("port 465 opts into implicit TLS", () => {
    process.env["SMTP_PORT"] = "465";
    expect(getMailConfig()?.secure).toBe(true);
  });

  test("a non-numeric port is rejected loudly instead of silently defaulting", () => {
    process.env["SMTP_PORT"] = "not-a-port";
    expect(() => getMailConfig()).toThrow(/SMTP_PORT/);
  });
});

describe("purposeLink", () => {
  test("builds an issuer-scoped consume URL with the token encoded", () => {
    const link = purposeLink("verify", "a b+c=d");
    expect(link).toStartWith("https://auth.alcore.io.vn/auth/verify/consume?token=");
    expect(link).toContain("a%20b%2Bc%3Dd");
  });

  test("reset links to the reset consume path", () => {
    expect(purposeLink("reset", "tok")).toStartWith(
      "https://auth.alcore.io.vn/auth/reset/consume?token="
    );
  });
});

describe("deliverPurposeMail", () => {
  beforeEach(() => {
    sent.length = 0;
    resetMailSender();
  });
  afterEach(() => {
    resetMailSender();
  });

  test("reports not_configured when SMTP_HOST is unset instead of throwing", async () => {
    resetMailSender();
    expect(await deliverPurposeMail("verify", "user@example.com", "tok")).toBe(
      "not_configured"
    );
  });

  test("sends to the requested address with the purpose link in the body", async () => {
    capturingSender();
    const outcome = await deliverPurposeMail("reset", "user@example.com", "reset-tok");
    expect(outcome).toBe("delivered");
    expect(sent).toHaveLength(1);
    expect(sent[0]?.to).toBe("user@example.com");
    expect(sent[0]?.text).toContain("reset/consume?token=reset-tok");
  });

  test("a throwing sender is contained and never escapes to the caller", async () => {
    setMailSender(async () => {
      throw new Error("smtp exploded");
    });
    expect(await deliverPurposeMail("verify", "user@example.com", "tok")).toBe("failed");
  });

  test("an unconfigured transport is distinguishable from a failure", async () => {
    resetMailSender();
    const outcome = await deliverPurposeMail("verify", "user@example.com", "tok");
    // "not_configured" is a different operator action from "failed": the first
    // means SMTP_HOST is unset, the second means credentials were rejected.
    expect(outcome).toBe("not_configured");
  });
});

describe("non-enumeration on the purpose-request endpoints", () => {
  const request = async (route: string, email: string) =>
    app.request(route, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email }),
    });

  beforeEach(() => {
    sent.length = 0;
    resetMailSender();
    resetRateLimitsForTests();
    resetThrottleConnForTests();
  });
  afterEach(() => {
    resetMailSender();
  });

  test("verify/request answers 200 for a real account with mail unconfigured", async () => {
    const user = userStore.create("known@example.com", "hash");
    const res = await request("/auth/verify/request", "known@example.com");
    expect(res.status).toBe(200);
    expect(user.id).not.toBe("");
  });

  test("verify/request answers an identical 200 for an unknown address", async () => {
    const known = await request("/auth/verify/request", "known@example.com");
    const unknown = await request("/auth/verify/request", "nobody@example.com");
    expect(unknown.status).toBe(known.status);
    expect(await unknown.text()).toBe(await known.text());
  });

  test("reset/request answers an identical 200 for known and unknown addresses", async () => {
    const known = await request("/auth/reset/request", "known@example.com");
    const unknown = await request("/auth/reset/request", "nobody@example.com");
    expect(unknown.status).toBe(known.status);
    expect(await unknown.text()).toBe(await known.text());
  });

  test("a delivery failure still leaves the response indistinguishable", async () => {
    setMailSender(async () => "failed");
    const known = await request("/auth/reset/request", "known@example.com");
    const unknown = await request("/auth/reset/request", "nobody@example.com");
    expect(known.status).toBe(unknown.status);
    expect(await unknown.text()).toBe(await known.text());
  });
});