// BullrunIQ — cloud sync + server-side entitlements.
//   GET  (Authorization: Bearer <token>)          → { data, updatedAt, plan }
//   POST (Authorization: Bearer <token>) { data } → saves state, returns { ok, plan }
// State lives in Blobs store "userdata", keyed by email. `plan` is authoritative:
// it comes from the "customers" store maintained by the Stripe webhook, so a
// canceled subscription drops to "free" on the next sync — auto-revoke.

const { verifyToken, planFor } = require("./_auth");

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};
const MAX_BYTES = 256 * 1024;
const DAILY_SYNC_CAP = 500;

function json(code, obj) { return { statusCode: code, headers: { "Content-Type": "application/json", ...CORS }, body: JSON.stringify(obj) }; }

async function dailySyncOk(email, store) {
  try {
    const today = new Date().toISOString().slice(0, 10);
    const key = "sync-rate:" + email + ":" + today;
    const cur = (await store.get(key, { type: "json" })) || { count: 0 };
    if (cur.count >= DAILY_SYNC_CAP) return false;
    cur.count++;
    await store.setJSON(key, cur);
    return true;
  } catch (e) { return true; }
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

    let rateStore;
    try { rateStore = getStore("ai-usage"); } catch (e) {}
    if (rateStore && !(await dailySyncOk(email, rateStore))) {
      return json(429, { error: "Too many sync requests today — try again tomorrow." });
    }

    await store.setJSON(email, { data: p.data, updatedAt: new Date().toISOString() });
    return json(200, { ok: true, plan: await planFor(email, getStore) });
  }

  return { statusCode: 405, headers: CORS, body: "Method Not Allowed" };

  } catch (e) {
    console.log("[sync] error:", e.message);
    return json(500, { error: "Sync hiccup — try again shortly." });
  }
};
