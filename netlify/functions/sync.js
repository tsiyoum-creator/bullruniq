// BullrunIQ — cloud sync + server-side entitlements.
//   GET  (Authorization: Bearer <token>)          → { data, updatedAt, plan }
//   POST (Authorization: Bearer <token>) { data } → saves state, returns { ok, plan }
// State lives in Blobs store "userdata", keyed by email. `plan` is authoritative:
// it comes from the "customers" store maintained by the Stripe webhook, so a
// canceled subscription drops to "free" on the next sync — auto-revoke.

const { verifyToken, planFor, json } = require("./_lib");

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};
const MAX_BYTES = 256 * 1024;

function validateUserData(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) return false;
  // Validate cash fields
  if (data.cash !== undefined) {
    if (typeof data.cash !== "number" || !isFinite(data.cash) || data.cash < 0 || data.cash > 1e9) return false;
  }
  if (data.cashApy !== undefined) {
    if (typeof data.cashApy !== "number" || !isFinite(data.cashApy) || data.cashApy < 0 || data.cashApy > 100) return false;
  }
  // Validate portfolio crypto holdings if present
  if (data.port && data.port.crypto !== undefined) {
    if (!Array.isArray(data.port.crypto)) return false;
    if (data.port.crypto.length > 200) return false;
    for (const h of data.port.crypto) {
      if (!h || typeof h !== "object") return false;
      if (h.ticker && typeof h.ticker !== "string") return false;
      if (h.ticker && h.ticker.length > 20) return false;
      if (h.ticker && !/^[A-Za-z0-9._-]{1,20}$/.test(h.ticker)) return false;
      if (h.qty !== undefined && typeof h.qty !== "number") return false;
      if (h.avg !== undefined && typeof h.avg !== "number") return false;
      if (h.stop !== undefined && typeof h.stop !== "number") return false;
      if (h.tp !== undefined && typeof h.tp !== "number") return false;
    }
  }
  // Validate watchlist if present
  if (data.wl !== undefined) {
    if (!Array.isArray(data.wl)) return false;
    if (data.wl.length > 100) return false;
    for (const w of data.wl) {
      if (!w || typeof w !== "object") return false;
      if (w.ticker && typeof w.ticker !== "string") return false;
      if (w.ticker && w.ticker.length > 20) return false;
      if (w.ticker && !/^[A-Za-z0-9._-]{1,20}$/.test(w.ticker)) return false;
      if (w.targetPrice !== undefined && typeof w.targetPrice !== "number") return false;
      if (w.sellTarget !== undefined && typeof w.sellTarget !== "number") return false;
    }
  }
  return true;
}

function jsonCors(code, obj) { return json(code, obj, CORS); }

exports.handler = async function (event) {
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, headers: CORS, body: "" };
  const h = event.headers || {};
  const authz = h.authorization || h.Authorization || "";
  const email = verifyToken(authz.replace(/^Bearer\s+/i, "").trim());
  if (!email) return jsonCors(401, { error: "Not logged in." });

  const blobs = require("@netlify/blobs");
  try { blobs.connectLambda(event); } catch (e) {}
  const getStore = blobs.getStore;
  let store;
  try { store = getStore("userdata"); } catch (e) { return jsonCors(500, { error: "Storage unavailable — try again shortly." }); }

  try {

  if (event.httpMethod === "GET") {
    const rec = await store.get(email, { type: "json" });
    return jsonCors(200, { data: rec ? rec.data : null, updatedAt: rec ? rec.updatedAt : null, plan: await planFor(email, getStore), email: email });
  }

  if (event.httpMethod === "POST") {
    if ((event.body || "").length > MAX_BYTES) return jsonCors(413, { error: "State too large." });
    let p = {};
    try { p = JSON.parse(event.body || "{}"); } catch (e) { return jsonCors(400, { error: "Bad JSON" }); }
    if (!p.data || typeof p.data !== "object") return jsonCors(400, { error: "Missing data" });
    if (!validateUserData(p.data)) return jsonCors(400, { error: "Invalid data structure" });
    await store.setJSON(email, { data: p.data, updatedAt: new Date().toISOString() });
    return jsonCors(200, { ok: true, plan: await planFor(email, getStore) });
  }

  return { statusCode: 405, headers: CORS, body: "Method Not Allowed" };

  } catch (e) {
    console.log("[sync] error:", e.message);
    return jsonCors(500, { error: "Sync hiccup — try again shortly." });
  }
};
