// BullrunIQ — one-click unsubscribe.

const crypto = require("crypto");

function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
}

function verifyUnsubToken(email, tok) {
  if (!tok) return false;
  const key = process.env.AUTH_SECRET || "briq-unsub-fallback";
  const expected = crypto.createHmac("sha256", key).update("unsub:" + email).digest("base64url");
  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(tok));
  } catch (e) { return false; }
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

exports.handler = async function (event) {
  const qs = event.queryStringParameters || {};
  const raw = String(qs.email || "").trim().toLowerCase();
  const tok = String(qs.tok || "").trim();
  const email = isValidEmail(raw) ? raw : "";

  if (!email || !verifyUnsubToken(email, tok)) {
    return {
      statusCode: 400,
      headers: { "Content-Type": "text/html; charset=utf-8" },
      body: page("Invalid or missing unsubscribe token. Use the link from your BullrunIQ email."),
    };
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
