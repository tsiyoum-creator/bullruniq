// BullrunIQ — shared auth helpers (imported by auth.js, sync.js, generate.js).
// Prefixed with _ so Netlify does not treat this file as a function handler.

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
  if (!key) throw new Error("AUTH_SECRET not configured — cannot sign token");
  const exp = Date.now() + (days || 30) * 864e5;
  const p = Buffer.from(email + "|" + exp).toString("base64url");
  const sig = crypto.createHmac("sha256", key).update(p).digest("base64url");
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

function json(code, obj, extraHeaders) {
  return { statusCode: code, headers: { "Content-Type": "application/json", ...(extraHeaders || {}) }, body: JSON.stringify(obj) };
}

function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
}

// Fetch all blobs across pagination pages. Returns a flat array of keys.
async function listAllKeys(store) {
  const keys = [];
  let cursor;
  do {
    const page = await store.list(cursor ? { cursor } : undefined);
    for (const b of (page.blobs || [])) keys.push(b.key);
    cursor = page.cursor;
  } while (cursor);
  return keys;
}

module.exports = { secretKey, signToken, verifyToken, planFor, json, esc, listAllKeys };
