// BullrunIQ — shared auth utilities (imported by auth.js, sync.js, generate.js).
// Files prefixed with _ are not deployed as Netlify Functions — helpers only.

const crypto = require("crypto");

function secretKey() {
  if (process.env.AUTH_SECRET) return process.env.AUTH_SECRET;
  if (process.env.ANTHROPIC_API_KEY) {
    return crypto.createHash("sha256").update("briq-auth:" + process.env.ANTHROPIC_API_KEY).digest("hex");
  }
  return null;
}

function signToken(email, days) {
  const key = secretKey();
  const exp = Date.now() + (days || 30) * 864e5;
  const p = Buffer.from(email + "|" + exp).toString("base64url");
  const sig = crypto.createHmac("sha256", key).update(p).digest("base64url");
  return p + "." + sig;
}

// Decodes both sides as base64url before timingSafeEqual so a length-mismatched
// sig (which would cause timingSafeEqual to throw) returns null cleanly rather
// than relying solely on the catch block.
function verifyToken(tok) {
  try {
    const key = secretKey();
    if (!key || !tok) return null;
    const i = tok.lastIndexOf(".");
    if (i < 1) return null;
    const p = tok.slice(0, i), sig = tok.slice(i + 1);
    const expect = crypto.createHmac("sha256", key).update(p).digest("base64url");
    const eBuf = Buffer.from(expect, "base64url");
    const sBuf = Buffer.from(sig, "base64url");
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
  } catch (e) {
    console.log("[planFor] error:", e.message);
  }
  return "free";
}

module.exports = { secretKey, signToken, verifyToken, planFor };
