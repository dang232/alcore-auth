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
  /** Optional HTML twin of `text` (inline styles, table-based for mail
   * clients). Transports send both; `text` stays the deliverability-safe
   * fallback and the assertion surface for tests. */
  readonly html?: string | undefined;
}

// Brand signature shared by every outbound message (OTP + verify + reset):
// short, no marketing — transactional mail with promo copy earns complaints
// and loses its protected reputation.
const BRAND_NAME = "ALCORE";
const BRAND_SITE_URL = "https://alcore.io.vn";
const BRAND_SUPPORT_URL = "https://alcore.io.vn/support";

function signatureTextLines(): string[] {
  return [
    "—",
    `Đội ngũ ${BRAND_NAME}`,
    `${BRAND_SITE_URL} · Hỗ trợ: ${BRAND_SUPPORT_URL}`,
  ];
}

function escHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** Table-based HTML shell (renders everywhere, inline styles only). */
function brandHtmlShell(codeOrBody: string, footerNote: string): string {
  return [
    '<!DOCTYPE html><html lang="vi"><body style="margin:0;padding:0;background:#f4f5f7;font-family:Arial,Helvetica,sans-serif;">',
    '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f5f7;padding:24px 0;"><tr><td align="center">',
    '<table role="presentation" width="420" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;padding:32px;">',
    `<tr><td style="font-size:18px;font-weight:bold;color:#111;padding-bottom:8px;">${escHtml(BRAND_NAME)}</td></tr>`,
    codeOrBody,
    `<tr><td style="font-size:12px;color:#888;line-height:1.5;">${footerNote}</td></tr>`,
    "</table>",
    '<table role="presentation" width="420" cellpadding="0" cellspacing="0">',
    `<tr><td style="font-size:11px;color:#999;padding:16px 8px;text-align:center;">Đội ngũ ${escHtml(BRAND_NAME)} &middot; <a href="${BRAND_SITE_URL}" style="color:#999;">${escHtml(BRAND_SITE_URL)}</a> &middot; <a href="${BRAND_SUPPORT_URL}" style="color:#999;">Hỗ trợ</a></td></tr>`,
    "</table>",
    "</td></tr></table></body></html>",
  ].join("");
}

function otpHtml(code: string): string {
  return brandHtmlShell(
    [
      '<tr><td style="font-size:14px;color:#444;line-height:1.5;padding-bottom:20px;">Mã xác thực của bạn (hết hạn sau 10 phút):</td></tr>',
      '<tr><td align="center" style="padding-bottom:20px;">',
      `<div style="font-size:32px;letter-spacing:8px;font-weight:bold;color:#111;background:#f4f5f7;border-radius:6px;padding:14px 24px;display:inline-block;font-family:monospace;">${escHtml(code)}</div>`,
      "</td></tr>",
    ].join(""),
    "Nếu bạn không yêu cầu mã này, hãy bỏ qua email này."
  );
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
    // Scannable in 2-3 seconds: greeting, code on its own line, honest
    // expiry, ignore line, brand signature. Vietnamese-first to match the
    // portal's code-entry screens.
    return {
      to: email,
      subject: `Mã xác thực ${BRAND_NAME} của bạn`,
      text: [
        "Chào bạn,",
        "",
        "Mã xác thực của bạn (hết hạn sau 10 phút):",
        "",
        token,
        "",
        "Nhập mã này vào trang đăng ký/đăng nhập để hoàn tất.",
        "Nếu bạn không yêu cầu mã này, hãy bỏ qua email này.",
        ...signatureTextLines(),
      ].join("\n"),
      html: otpHtml(token),
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
        ...signatureTextLines(),
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
      ...signatureTextLines(),
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
      ...(message.html !== undefined ? { html: message.html } : {}),
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