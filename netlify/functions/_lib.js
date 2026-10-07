// BullrunIQ — shared auth helpers (imported by auth.js, sync.js, generate.js).
// Prefixed with _ so Netlify does not treat this file as a function handler.

const crypto = require("crypto");

function secretKey() {
  if (process.env.AUTH_SECRET) return process.env.AUTH_SECRET;
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
  } catch (e) {
    console.log("[planFor] storage error for", email, "—", e.message);
  }
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

// Returns an HMAC-signed unsubscribe token for the given email so unsubscribe
// links cannot be forged to remove arbitrary users from the subscriber list.
function signUnsub(email) {
  const key = secretKey();
  if (!key) return null;
  return crypto.createHmac("sha256", key).update("unsub:" + email).digest("base64url");
}

// Verifies an unsubscribe token produced by signUnsub(). Returns true if valid.
function verifyUnsub(email, token) {
  const key = secretKey();
  if (!key || !token) return false;
  const expected = crypto.createHmac("sha256", key).update("unsub:" + email).digest("base64url");
  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(token));
  } catch (e) { return false; }
}

// Shared plan limits — single source of truth for both generate.js and sync.js.
const PLAN_DAILY_CAPS = { free: 50, pro: 500, elite: 1000, advisor: 2000 };
const PLAN_TOKEN_CAPS = { free: 800, pro: 1500, elite: 2000, advisor: 3000 };

module.exports = { secretKey, signToken, verifyToken, planFor, json, esc, listAllKeys, signUnsub, verifyUnsub, PLAN_DAILY_CAPS, PLAN_TOKEN_CAPS };
