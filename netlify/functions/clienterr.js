// BullrunIQ — client error sink (/api/clienterr).
//
// Why: the app had 95 empty catch blocks. Failures happened and told nobody —
// not the user, not the operator. The client now reports the operationally
// important ones here so someone can actually see them after the fact.
//
// Deliberately small. This is a sink, not an observability platform:
//   · the client samples (max 5 reports per page load) so this is never a firehose
//   · bodies are hard-capped and truncated server-side; a client cannot be trusted
//   · a rolling window of the most recent N errors is kept, then overwritten
//   · storage failure fails OPEN and silently — an error reporter that breaks
//     the page, or that errors about erroring, is worse than no reporter
//
// Read them back with: GET /api/clienterr?key=<OPS_READ_KEY>

const MAX_KEEP = 200;         // rolling window
const MAX_BODY = 4096;        // bytes accepted
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
  "Content-Type": "application/json",
};

function clip(v, n) {
  return typeof v === "string" ? v.slice(0, n) : "";
}

exports.handler = async function (event) {
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, headers: CORS, body: "" };

  const blobs = require("@netlify/blobs");
  try { blobs.connectLambda(event); } catch (e) { /* (a) local/dev without Blobs — handled below */ }
  let store = null;
  try { store = blobs.getStore("opserrors"); } catch (e) { /* (a) see fail-open note above */ }

  // ── Operator read ──
  if (event.httpMethod === "GET") {
    const key = (event.queryStringParameters || {}).key || "";
    const expected = process.env.OPS_READ_KEY || "";
    if (!expected || key !== expected) {
      return { statusCode: 404, headers: CORS, body: JSON.stringify({ error: "not found" }) };
    }
    if (!store) return { statusCode: 200, headers: CORS, body: JSON.stringify({ errors: [], note: "storage unavailable" }) };
    let rec = null;
    try { rec = await store.get("recent", { type: "json" }); }
    catch (e) { return { statusCode: 200, headers: CORS, body: JSON.stringify({ errors: [], note: "read failed: " + e.message }) }; }
    const errs = (rec && rec.errors) || [];
    // Summarise by context so a repeating failure is obvious at a glance.
    const byCtx = {};
    errs.forEach(function (x) { byCtx[x.ctx] = (byCtx[x.ctx] || 0) + 1; });
    return {
      statusCode: 200, headers: CORS,
      body: JSON.stringify({ count: errs.length, byContext: byCtx, errors: errs.slice(0, 50) }, null, 2),
    };
  }

  if (event.httpMethod !== "POST") {
    return { statusCode: 405, headers: CORS, body: JSON.stringify({ error: "method not allowed" }) };
  }

  const raw = event.body || "";
  if (raw.length > MAX_BODY) {
    return { statusCode: 413, headers: CORS, body: JSON.stringify({ error: "too large" }) };
  }

  let b = null;
  try { b = JSON.parse(raw); } catch (e) {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: "bad json" }) };
  }
  if (!b || typeof b !== "object") {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: "bad body" }) };
  }

  const entry = {
    ctx: clip(b.ctx, 120) || "unknown",
    msg: clip(b.msg, 300),
    path: clip(b.path, 120),
    ua: clip(b.ua, 160),
    at: typeof b.at === "number" ? b.at : Date.now(),
    ip: (event.headers && (event.headers["x-nf-client-connection-ip"] || "")).slice(0, 45),
  };

  if (!store) {
    // Fail open. The report is lost but the client is never penalised for it.
    console.log("[clienterr] no store; dropping:", entry.ctx, entry.msg);
    return { statusCode: 202, headers: CORS, body: JSON.stringify({ ok: true, stored: false }) };
  }

  try {
    const rec = (await store.get("recent", { type: "json" })) || { errors: [] };
    rec.errors.unshift(entry);
    if (rec.errors.length > MAX_KEEP) rec.errors.length = MAX_KEEP;
    await store.setJSON("recent", rec);
  } catch (e) {
    // Never surface a reporting failure to the page.
    console.log("[clienterr] store failed:", e.message);
    return { statusCode: 202, headers: CORS, body: JSON.stringify({ ok: true, stored: false }) };
  }

  console.log("[clienterr]", entry.ctx, "-", entry.msg);
  return { statusCode: 202, headers: CORS, body: JSON.stringify({ ok: true, stored: true }) };
};
