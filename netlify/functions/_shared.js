// BullrunIQ — shared auth + response helpers used across Netlify functions.
// Not a function itself (no `handler` export) so Netlify ignores it as a route.

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
    const expectBuf = Buffer.from(crypto.createHmac("sha256", key).update(p).digest("base64url"));
    const sigBuf = Buffer.from(sig);
    // timingSafeEqual requires equal lengths; mismatched lengths = tampered
    if (expectBuf.length !== sigBuf.length) return null;
    if (!crypto.timingSafeEqual(expectBuf, sigBuf)) return null;
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

function json(code, obj, extraHeaders) {
  return {
    statusCode: code,
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", ...extraHeaders },
    body: JSON.stringify(obj),
  };
}

function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

module.exports = { secretKey, signToken, verifyToken, planFor, json, esc };
