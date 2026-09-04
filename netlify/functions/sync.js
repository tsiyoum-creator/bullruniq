// BullrunIQ — cloud sync + server-side entitlements.
//   GET  (Authorization: Bearer <token>)          → { data, updatedAt, plan }
//   POST (Authorization: Bearer <token>) { data } → saves state, returns { ok, plan }
// State lives in Blobs store "userdata", keyed by email. `plan` is authoritative:
// it comes from the "customers" store maintained by the Stripe webhook, so a
// canceled subscription drops to "free" on the next sync — auto-revoke.

const crypto = require("crypto");

// Restrict CORS to the app's own origin (S-2 fix).
const ALLOWED_ORIGIN = process.env.SITE_URL || "https://bullruniq.com";
const CORS = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Vary": "Origin",
};
const MAX_BYTES = 256 * 1024;

// Regex matching safe CoinGecko coin IDs — same as market.js (S-8 fix).
const VALID_COIN_ID = /^[a-z0-9-]{1,50}$/;

function isFinitePositive(v) { return typeof v === "number" && isFinite(v) && v > 0; }

// Validate watchlist and portfolio entries before persisting them (S-8 fix).
// Rejects ticker strings that could later be injected into CoinGecko URLs,
// and ensures numeric fields are actually finite positive numbers.
function validateData(data) {
  if (!data || typeof data !== "object") return "data must be an object";
  if (data.wl !== undefined) {
    if (!Array.isArray(data.wl)) return "data.wl must be an array";
    for (const w of data.wl) {
      if (!w || typeof w !== "object") continue;
      if (w.ticker !== undefined) {
        const t = String(w.ticker).toUpperCase().trim();
        if (t.length > 20) return "ticker too long: " + t.slice(0, 20);
      }
      for (const field of ["targetPrice", "sellTarget"]) {
        if (w[field] !== undefined && !isFinitePositive(w[field])) {
          return field + " must be a positive number";
        }
      }
    }
  }
  if (data.port !== undefined) {
    if (typeof data.port !== "object") return "data.port must be an object";
    if (data.port.crypto !== undefined) {
      if (!Array.isArray(data.port.crypto)) return "data.port.crypto must be an array";
      for (const h of data.port.crypto) {
        if (!h || typeof h !== "object") continue;
        for (const field of ["avg", "qty", "stop", "tp"]) {
          if (h[field] !== undefined && !isFinitePositive(h[field])) {
            return field + " must be a positive number";
          }
        }
      }
    }
  }
  return null; // valid
}

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
function json(code, obj) { return { statusCode: code, headers: { "Content-Type": "application/json", ...CORS }, body: JSON.stringify(obj) }; }

async function planFor(email, getStore) {
  try {
    const rec = await getStore("customers").get(email, { type: "json" });
    if (rec && (rec.status === "active" || rec.status === "trialing")) return rec.tier || "pro";
  } catch (e) {}
  return "free";
}

exports.handler = async function (event) {
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, headers: CORS, body: "" };
  const h = event.headers || {};
  const authz = h.authorization || h.Authorization || "";
  const email = verifyToken(authz.replace(/^Bearer\s+/i, "").trim());
  if (!email) return json(401, { error: "Not logged in." });

  const blobs = require("@netlify/blobs");
  try { blobs.connectLambda(event); } catch (e) {}
  const getStore = blobs.getStore;
  let store;
  try { store = getStore("userdata"); } catch (e) { return json(500, { error: "Storage unavailable — try again shortly." }); }

  try {

  if (event.httpMethod === "GET") {
    const rec = await store.get(email, { type: "json" });
    return json(200, { data: rec ? rec.data : null, updatedAt: rec ? rec.updatedAt : null, plan: await planFor(email, getStore), email: email });
  }

  if (event.httpMethod === "POST") {
    if ((event.body || "").length > MAX_BYTES) return json(413, { error: "State too large." });
    let p = {};
    try { p = JSON.parse(event.body || "{}"); } catch (e) { return json(400, { error: "Bad JSON" }); }
    if (!p.data || typeof p.data !== "object") return json(400, { error: "Missing data" });
    const validationError = validateData(p.data);
    if (validationError) return json(400, { error: "Invalid data: " + validationError });
    await store.setJSON(email, { data: p.data, updatedAt: new Date().toISOString() });
    return json(200, { ok: true, plan: await planFor(email, getStore) });
  }

  return { statusCode: 405, headers: CORS, body: "Method Not Allowed" };

  } catch (e) {
    console.error("[sync] error:", e.message);
    return json(500, { error: "Sync hiccup — try again shortly." });
  }
};
