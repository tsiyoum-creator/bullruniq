// BullrunIQ — cloud sync + server-side entitlements.
//   GET  (Authorization: Bearer <token>)          → { data, updatedAt, plan }
//   POST (Authorization: Bearer <token>) { data } → saves state, returns { ok, plan }
// State lives in Blobs store "userdata", keyed by email. `plan` is authoritative:
// it comes from the "customers" store maintained by the Stripe webhook, so a
// canceled subscription drops to "free" on the next sync — auto-revoke.

const { verifyToken, planFor, json } = require("./_utils");

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};
const MAX_BYTES = 256 * 1024;

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
    const rawBody = event.body || "";
    if (Buffer.byteLength(rawBody, "utf8") > MAX_BYTES) return jsonCors(413, { error: "State too large." });
    let p = {};
    try { p = JSON.parse(rawBody); } catch (e) { return jsonCors(400, { error: "Bad JSON" }); }
    if (!p.data || typeof p.data !== "object" || Array.isArray(p.data)) return jsonCors(400, { error: "Missing or invalid data" });
    await store.setJSON(email, { data: p.data, updatedAt: new Date().toISOString() });
    return jsonCors(200, { ok: true, plan: await planFor(email, getStore) });
  }

  return { statusCode: 405, headers: CORS, body: "Method Not Allowed" };

  } catch (e) {
    console.log("[sync] error:", e.message);
    return jsonCors(500, { error: "Sync hiccup — try again shortly." });
  }
};
