// BullrunIQ — shared utilities for Netlify functions.
// Centralises: auth helpers, CORS, HTML escaping, Resend send.

const crypto = require("crypto");

function secretKey() {
  if (process.env.AUTH_SECRET) return process.env.AUTH_SECRET;
  if (process.env.ANTHROPIC_API_KEY) {
    return crypto.createHash("sha256").update("briq-auth:" + process.env.ANTHROPIC_API_KEY).digest("hex");
  }
  return null;
}

function verifyToken(tok) {
  try {
    const key = secretKey();
    if (!key || !tok) return null;
    const i = tok.lastIndexOf(".");
    if (i < 1) return null;
    const p = tok.slice(0, i), sig = tok.slice(i + 1);
    const expect = crypto.createHmac("sha256", key).update(p).digest("base64url");
    if (!crypto.timingSafeEqual(Buffer.from(expect), Buffer.from(sig))) return null;
    const raw = Buffer.from(p, "base64url").toString("utf8");
    const j = raw.lastIndexOf("|");
    const email = raw.slice(0, j), exp = parseInt(raw.slice(j + 1), 10);
    if (!email || !exp || Date.now() > exp) return null;
    return email;
  } catch (e) { return null; }
}

async function planFor(email, getStore) {
  try {
    const rec = await getStore("customers").get(email, { type: "json" });
    if (rec && (rec.status === "active" || rec.status === "trialing")) return rec.tier || "pro";
  } catch (e) {}
  return "free";
}

function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
}

// Restricted CORS for authenticated endpoints — only allow the app's own origin.
// Falls back to SITE_URL env var, then the production domain.
function authCors(methods) {
  const origin = process.env.SITE_URL || "https://bullruniq.com";
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": methods || "GET, POST, OPTIONS",
    "Vary": "Origin",
  };
}

async function sendEmail(resendKey, to, subject, html) {
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: "Bearer " + resendKey, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: process.env.NEWSLETTER_FROM || "BullrunIQ <brief@bullruniq.com>",
      to,
      subject,
      html,
    }),
  });
  return r.ok;
}

module.exports = { secretKey, verifyToken, planFor, esc, authCors, sendEmail };
