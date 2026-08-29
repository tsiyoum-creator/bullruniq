// Shared helpers used across BullrunIQ Netlify functions.
// Prefixed with _ so Netlify does not deploy this as a standalone function.

const crypto = require("crypto");

function secretKey() {
  if (process.env.AUTH_SECRET) return process.env.AUTH_SECRET;
  if (process.env.ANTHROPIC_API_KEY) {
    return crypto.createHash("sha256").update("briq-auth:" + process.env.ANTHROPIC_API_KEY).digest("hex");
  }
  return null;
}

function signToken(email, days) {
  const exp = Date.now() + (days || 30) * 864e5;
  const p = Buffer.from(email + "|" + exp).toString("base64url");
  const sig = crypto.createHmac("sha256", secretKey()).update(p).digest("base64url");
  return p + "." + sig;
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

// HTML-escapes a string for safe insertion into email/HTML content.
function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
}

// Signs a short HMAC token for one-click unsubscribe links.
function signUnsub(email) {
  const key = secretKey();
  if (!key) return null;
  return crypto.createHmac("sha256", key).update("unsub:" + String(email)).digest("base64url").slice(0, 20);
}

// Returns true if the unsubscribe token is valid for this email.
function verifyUnsub(email, token) {
  const key = secretKey();
  if (!key || !email || !token) return false;
  const expected = crypto.createHmac("sha256", key).update("unsub:" + String(email)).digest("base64url").slice(0, 20);
  if (expected.length !== token.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(token));
  } catch (e) { return false; }
}

// Builds a signed unsubscribe URL; falls back to unsigned if no key is configured.
function unsubUrl(email) {
  const tok = signUnsub(email);
  return "https://bullruniq.com/api/unsubscribe?email=" + encodeURIComponent(email) + (tok ? "&t=" + tok : "");
}

module.exports = { secretKey, signToken, verifyToken, planFor, esc, signUnsub, verifyUnsub, unsubUrl };
