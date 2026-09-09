// BullrunIQ — one-click unsubscribe.

const { esc, isValidEmail } = require("./_lib");

function page(msg) {
  return "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Unsubscribed — BullrunIQ</title></head>"
    + "<body style='background:#050505;color:#f0ece4;font-family:-apple-system,Segoe UI,sans-serif;text-align:center;padding:90px 24px'>"
    + "<div style='font-family:Georgia,serif;font-size:22px;letter-spacing:2px;margin-bottom:32px'>Bullrun<span style='color:#c9a84c'>IQ</span></div>"
    + "<h1 style='font-family:Georgia,serif;font-weight:400;font-size:30px;color:#c9a84c;margin-bottom:12px'>You're unsubscribed</h1>"
    + "<p style='color:#8a8278;font-size:15px;max-width:420px;margin:0 auto 28px;line-height:1.7'>" + esc(msg) + "</p>"
    + "<a href='https://bullruniq.com' style='display:inline-block;border:1px solid #2a2a2a;border-radius:4px;color:#8a8278;text-decoration:none;padding:12px 28px;font-size:12px;letter-spacing:1.5px;text-transform:uppercase'>← bullruniq.com</a>"
    + "</body></html>";
}

// Simple in-memory rate limit: max 10 unsubscribe requests per IP per minute.
const _ipBurst = new Map();
function ipOk(ip) {
  const now = Date.now();
  const e = _ipBurst.get(ip);
  if (!e || now - e.t > 60000) { _ipBurst.set(ip, { t: now, n: 1 }); return true; }
  e.n++;
  return e.n <= 10;
}

exports.handler = async function (event) {
  const h = event.headers || {};
  const ip = h["x-nf-client-connection-ip"] || (h["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";
  if (!ipOk(ip)) {
    return { statusCode: 429, headers: { "Content-Type": "text/html; charset=utf-8" }, body: page("Too many requests — please wait a moment.") };
  }

  const raw = String(((event.queryStringParameters || {}).email) || "").trim().toLowerCase();
  const email = isValidEmail(raw) ? raw : "";
  let storageOk = true;
  try {
    if (email) {
      const blobs = require("@netlify/blobs");
      try { blobs.connectLambda(event); } catch (e) {}
      await blobs.getStore("subscribers").delete(email);
      console.log("[subscribers] removed", email);
    }
  } catch (e) {
    storageOk = false;
    console.log("[unsubscribe] error", e.message);
  }
  return {
    statusCode: 200,
    headers: { "Content-Type": "text/html; charset=utf-8" },
    body: page(email ? (email + " won't receive any more BullrunIQ emails.") : "You won't receive any more BullrunIQ emails.")
      + "<!-- blobs:" + (storageOk ? "ok" : "err") + " -->",
  };
};
