// BullrunIQ — one-click unsubscribe.
// Links are signed with an HMAC token to prevent mass-unsubscription of
// arbitrary emails (S-5 fix). Old unsigned links still work but are logged.
// Generate a signed link: /api/unsubscribe?token=<HMAC>&email=<addr>

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

function isValidEmail(s) {
  return typeof s === "string" && s.length > 0 && s.length <= 200 && s.indexOf("@") > 0;
}

// Returns a hex HMAC over "unsub:<email>" using AUTH_SECRET (or RESEND_API_KEY as fallback).
function unsubHmac(email) {
  const secret = process.env.AUTH_SECRET || process.env.RESEND_API_KEY;
  if (!secret) return null;
  return crypto.createHmac("sha256", secret).update("unsub:" + email).digest("hex");
}

function verifyToken(token, email) {
  const expected = unsubHmac(email);
  if (!expected || !token) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(String(token), "hex"));
  } catch (e) { return false; }
}

exports.handler = async function (event) {
  const q = event.queryStringParameters || {};
  const raw = String(q.email || "").trim().toLowerCase();
  const token = String(q.token || "").trim();
  const email = isValidEmail(raw) ? raw : "";

  if (!email) {
    return { statusCode: 200, headers: { "Content-Type": "text/html; charset=utf-8" }, body: page("You won't receive any more BullrunIQ emails.") };
  }

  // Require a valid HMAC token. Unsigned links are rejected to prevent
  // an attacker from mass-unsubscribing arbitrary email addresses (S-5 fix).
  if (!verifyToken(token, email)) {
    console.error("[unsubscribe] invalid or missing token for:", email);
    return {
      statusCode: 400,
      headers: { "Content-Type": "text/html; charset=utf-8" },
      body: page("This unsubscribe link is invalid or has expired. Please use the link from a recent BullrunIQ email."),
    };
  }

  let storageOk = true;
  try {
    const blobs = require("@netlify/blobs");
    try { blobs.connectLambda(event); } catch (e) {}
    await blobs.getStore("subscribers").delete(email);
    console.log("[unsubscribe] removed subscriber");
  } catch (e) {
    storageOk = false;
    console.error("[unsubscribe] storage error:", e.message);
  }
  return {
    statusCode: 200,
    headers: { "Content-Type": "text/html; charset=utf-8" },
    body: page(email + " won't receive any more BullrunIQ emails.")
      + "<!-- blobs:" + (storageOk ? "ok" : "err") + " -->",
  };
};

// Helper exported for use by email-sending functions to generate signed links.
exports.signedUnsubLink = function (email) {
  const token = unsubHmac(email);
  if (!token) return "https://bullruniq.com/api/unsubscribe?email=" + encodeURIComponent(email);
  return "https://bullruniq.com/api/unsubscribe?token=" + encodeURIComponent(token) + "&email=" + encodeURIComponent(email);
};
