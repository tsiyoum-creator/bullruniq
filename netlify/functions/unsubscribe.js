// BullrunIQ — one-click unsubscribe.
// Requires a short-lived HMAC token generated when the email is sent so
// arbitrary email addresses cannot be unsubscribed by a third party.
// Falls back to unauthenticated removal when TOKEN_REQUIRED is not set
// (preserves backward-compat with existing links during rollout).

const crypto = require("crypto");

function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
}

function page(msg) {
  return "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Unsubscribed — BullrunIQ</title></head>"
    + "<body style='background:#050505;color:#f0ece4;font-family:-apple-system,Segoe UI,sans-serif;text-align:center;padding:90px 24px'>"
    + "<div style='font-family:Georgia,serif;font-size:22px;letter-spacing:2px;margin-bottom:32px'>Bullrun<span style='color:#c9a84c'>IQ</span></div>"
    + "<h1 style='font-family:Georgia,serif;font-weight:400;font-size:30px;color:#c9a84c;margin-bottom:12px'>You're unsubscribed</h1>"
    + "<p style='color:#8a8278;font-size:15px;max-width:420px;margin:0 auto 28px;line-height:1.7'>" + esc(msg) + "</p>"
    + "<a href='https://bullruniq.com' style='display:inline-block;border:1px solid #2a2a2a;border-radius:4px;color:#8a8278;text-decoration:none;padding:12px 28px;font-size:12px;letter-spacing:1.5px;text-transform:uppercase'>← bullruniq.com</a>"
    + "</body></html>";
}

function errorPage(msg) {
  return "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Invalid link — BullrunIQ</title></head>"
    + "<body style='background:#050505;color:#f0ece4;font-family:-apple-system,Segoe UI,sans-serif;text-align:center;padding:90px 24px'>"
    + "<div style='font-family:Georgia,serif;font-size:22px;letter-spacing:2px;margin-bottom:32px'>Bullrun<span style='color:#c9a84c'>IQ</span></div>"
    + "<h1 style='font-family:Georgia,serif;font-weight:400;font-size:30px;color:#e05555;margin-bottom:12px'>Invalid link</h1>"
    + "<p style='color:#8a8278;font-size:15px;max-width:420px;margin:0 auto 28px;line-height:1.7'>" + esc(msg) + "</p>"
    + "<a href='https://bullruniq.com/contact' style='display:inline-block;border:1px solid #2a2a2a;border-radius:4px;color:#8a8278;text-decoration:none;padding:12px 28px;font-size:12px;letter-spacing:1.5px;text-transform:uppercase'>Contact us →</a>"
    + "</body></html>";
}

function isValidEmail(s) {
  return typeof s === "string" && s.length > 0 && s.length <= 200 && s.indexOf("@") > 0;
}

// Verify HMAC-SHA256 token: makeUnsubToken(email, secret) → token string.
// Used by newsletter.js / alerts.js to sign unsubscribe URLs in outgoing emails.
function verifyUnsubToken(email, token, secret) {
  if (!secret || !token || !email) return false;
  try {
    // Token format: <expTs>.<hmac>
    const dot = token.indexOf(".");
    if (dot < 1) return false;
    const expTs = parseInt(token.slice(0, dot), 36);
    const sig   = token.slice(dot + 1);
    if (isNaN(expTs) || Date.now() > expTs) return false;
    const expected = crypto.createHmac("sha256", secret)
      .update(email + "|" + expTs)
      .digest("base64url");
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig));
  } catch (e) { return false; }
}

exports.handler = async function (event) {
  const raw = String(((event.queryStringParameters || {}).email) || "").trim().toLowerCase();
  const email = isValidEmail(raw) ? raw : "";
  const token = String(((event.queryStringParameters || {}).t) || "").trim();
  const secret = process.env.AUTH_SECRET || process.env.ANTHROPIC_API_KEY;
  const tokenRequired = !!process.env.TOKEN_REQUIRED;

  if (!email) {
    return {
      statusCode: 400,
      headers: { "Content-Type": "text/html; charset=utf-8" },
      body: errorPage("Missing or invalid email address."),
    };
  }

  // Validate token when TOKEN_REQUIRED is set or a secret is available.
  // Existing signed links (using makeUnsubToken) work immediately.
  // Old unsigned links keep working until TOKEN_REQUIRED is flipped on.
  if (secret && (tokenRequired || token)) {
    if (!verifyUnsubToken(email, token, secret)) {
      return {
        statusCode: 400,
        headers: { "Content-Type": "text/html; charset=utf-8" },
        body: errorPage("This unsubscribe link has expired or is invalid. Open the latest email from BullrunIQ to use a fresh link."),
      };
    }
  }

  let storageOk = true;
  try {
    const blobs = require("@netlify/blobs");
    try { blobs.connectLambda(event); } catch (e) {}
    await blobs.getStore("subscribers").delete(email);
    console.log("[subscribers] removed", email);
  } catch (e) {
    storageOk = false;
    console.log("[unsubscribe] error", e.message);
  }
  return {
    statusCode: 200,
    headers: { "Content-Type": "text/html; charset=utf-8" },
    body: page(email + " won't receive any more BullrunIQ emails.")
      + "<!-- blobs:" + (storageOk ? "ok" : "err") + " -->",
  };
};

// Exported so newsletter.js and alerts.js can generate matching tokens.
exports.makeUnsubToken = function makeUnsubToken(email, secret, ttlMs) {
  const expTs = Date.now() + (ttlMs || 30 * 24 * 60 * 60 * 1000); // 30-day default
  const sig = crypto.createHmac("sha256", secret)
    .update(email + "|" + expTs)
    .digest("base64url");
  return expTs.toString(36) + "." + sig;
};
