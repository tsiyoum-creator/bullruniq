// Shared helpers used by auth.js, sync.js, and generate.js.
// Keep this file free of Netlify Blobs / network calls so it can be required
// in unit tests without side effects.

const crypto = require("crypto");

function secretKey() {
  if (process.env.AUTH_SECRET) return process.env.AUTH_SECRET;
  if (process.env.ANTHROPIC_API_KEY) {
    return crypto
      .createHash("sha256")
      .update("briq-auth:" + process.env.ANTHROPIC_API_KEY)
      .digest("hex");
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
    // timingSafeEqual requires equal-length buffers; wrong-length means bad token
    const eBuf = Buffer.from(expect), sBuf = Buffer.from(sig);
    if (eBuf.length !== sBuf.length) return null;
    if (!crypto.timingSafeEqual(eBuf, sBuf)) return null;
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

function isValidEmail(s) {
  return typeof s === "string" && s.length > 0 && s.length <= 200 && s.indexOf("@") > 0;
}

module.exports = { secretKey, signToken, verifyToken, planFor, isValidEmail };
