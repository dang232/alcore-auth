// ALcore Auth Repo C — outbound mail (verification + password reset).
//
// Identity-only: this transport exists solely to deliver the purpose tokens
// minted by /auth/verify/request and /auth/reset/request. Nothing else in the
// service sends mail.
//
// Two invariants drive the shape:
//
// 1. NON-ENUMERATION. Both request endpoints always answer 200 regardless of
//    whether an account exists. Delivery therefore must never be the signal —
//    an unconfigured or failing transport reports `sent: false` and the caller
//    still answers 200. Nothing here may throw into the request path in a way
//    that changes the response.
//
// 2. NO SECRET LEAKAGE. Failures log the recipient and the reason class only.
//    Never the SMTP password, never the purpose token.

import { getMailConfig, getIssuer, type MailConfig } from "../config";

export interface MailMessage {
  readonly to: string;
  readonly subject: string;
  readonly text: string;
}

export type MailOutcome = "delivered" | "not_configured" | "failed";

export type MailSender = (message: MailMessage) => Promise<MailOutcome>;

/**
 * Purpose-token links are minted by the routes and delivered here. The token is
 * the only bearer of authority in the message, so the URL is the payload.
 *
 * The signup OTP is the exception: the 6-digit code is typed into the app,
 * never clicked, so its message carries the code in the body with no link.
 */
export function purposeLink(
  purpose: "verify" | "reset",
  token: string
): string {
  return `${getIssuer()}/auth/${purpose}/consume?token=${encodeURIComponent(token)}`;
}

function buildMessage(
  purpose: "verify" | "reset" | "signup-otp",
  email: string,
  token: string
): MailMessage {
  if (purpose === "signup-otp") {
    return {
      to: email,
      subject: "Your Alcore verification code",
      text: [
        "Use this code to finish setting up your account (expires in 10 minutes):",
        "",
        token,
        "",
        "If you did not request this, you can ignore this message.",
      ].join("\n"),
    };
  }
  const link = purposeLink(purpose, token);
  if (purpose === "verify") {
    return {
      to: email,
      subject: "Confirm your email address",
      text: [
        "Confirm this address to finish setting up your account:",
        "",
        link,
        "",
        "If you did not request this, you can ignore this message.",
      ].join("\n"),
    };
  }
  return {
    to: email,
    subject: "Reset your password",
    text: [
      "Use this link to choose a new password:",
      "",
      link,
      "",
      "If you did not request this, nothing changed and you can ignore this message.",
    ].join("\n"),
  };
}

/**
 * Default transport. SMTP is loaded lazily so a deployment that never sends
 * mail does not pay the import cost, and so tests can run with no SMTP server.
 */
export const smtpSender: MailSender = async (message) => {
  let config: MailConfig | null;
  try {
    config = getMailConfig();
  } catch (error) {
    console.error(
      "[auth-service] mail misconfigured:",
      error instanceof Error ? error.message : "unknown"
    );
    return "failed";
  }
  if (config === null) return "not_configured";
  if (config.from === "") {
    console.error("[auth-service] mail misconfigured: SMTP_FROM is required");
    return "failed";
  }

  const { createTransport } = await import("nodemailer");
  const transport = createTransport({
    host: config.host,
    port: config.port,
    secure: config.secure,
    ...(config.username !== ""
      ? { auth: { user: config.username, pass: config.password } }
      : {}),
  });
  try {
    await transport.sendMail({
      from: config.from,
      to: message.to,
      subject: message.subject,
      text: message.text,
    });
    // Log success too. Silence on the happy path made "did it send?" unanswerable
    // from the journal: only failures were recorded, so an operator could not
    // distinguish a delivered message from a transport that was never reached.
    console.log(`[auth-service] mail delivered to ${message.to}`);
    return "delivered";
  } catch (error) {
    console.error(
      "[auth-service] mail delivery failed:",
      error instanceof Error ? error.message : "unknown"
    );
    return "failed";
  }
};

let sender: MailSender = smtpSender;

/** Test seam: swap the transport without touching SMTP or the network. */
export function setMailSender(next: MailSender): void {
  sender = next;
}

export function resetMailSender(): void {
  sender = smtpSender;
}

/**
 * Fire-and-forget by design: the caller answers 200 either way. Rejections are
 * swallowed here so no transport bug can ever turn a non-enumerating endpoint
 * into a 500 that reveals whether the address was real.
 */
export async function deliverPurposeMail(
  purpose: "verify" | "reset" | "signup-otp",
  email: string,
  token: string
): Promise<MailOutcome> {
  try {
    return await sender(buildMessage(purpose, email, token));
  } catch (error) {
    console.error(
      "[auth-service] mail sender threw:",
      error instanceof Error ? error.message : "unknown"
    );
    return "failed";
  }
}