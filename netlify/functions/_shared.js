// BullrunIQ — shared auth helpers used across Netlify functions.

const crypto = require("crypto");

function secretKey() {
  if (process.env.AUTH_SECRET) return process.env.AUTH_SECRET;
  if (process.env.ANTHROPIC_API_KEY) {
    // Fallback: derive key from Anthropic key when AUTH_SECRET is not explicitly set.
    // Rotating ANTHROPIC_API_KEY logs all users out, so set AUTH_SECRET explicitly.
    console.warn("[auth] AUTH_SECRET env var is not set — deriving from ANTHROPIC_API_KEY. Set AUTH_SECRET to a random 32+ char secret.");
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

// Returns HMAC-SHA256("unsub:<email>", secretKey) as base64url.
// Tokens don't expire — the link lives in an already-delivered email.
function signUnsub(email) {
  const key = secretKey();
  if (!key) return null;
  return crypto.createHmac("sha256", key).update("unsub:" + email).digest("base64url");
}

// Constant-time comparison for unsubscribe token verification.
function verifyUnsub(email, token) {
  const expected = signUnsub(email);
  if (!expected || !token) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(token));
  } catch (e) { return false; }
}

// Build a signed unsubscribe URL for use in email footers.
function unsubUrl(email) {
  const tok = signUnsub(email);
  const base = "https://bullruniq.com/api/unsubscribe?email=" + encodeURIComponent(email);
  return tok ? base + "&tok=" + encodeURIComponent(tok) : base;
}

module.exports = { secretKey, verifyToken, signUnsub, verifyUnsub, unsubUrl };
