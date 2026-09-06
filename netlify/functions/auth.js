// BullrunIQ — passwordless login (magic 6-digit code, no external auth service).
//   POST {action:"request", email}        → emails a 6-digit code (Resend), valid 15 min
//   POST {action:"verify",  email, code}  → returns a signed 30-day token + plan
// Token: base64url(email|exp) + "." + HMAC-SHA256 signature.
// Secret: AUTH_SECRET env var, else derived from ANTHROPIC_API_KEY (zero extra config;
// rotating that key just logs everyone out, which is safe).

const crypto = require("crypto");

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function secretKey() {
  if (process.env.AUTH_SECRET) return process.env.AUTH_SECRET;
  if (process.env.ANTHROPIC_API_KEY) {
    return crypto.createHash("sha256").update("briq-auth:" + process.env.ANTHROPIC_API_KEY).digest("hex");
  }
  return null;
}
function signToken(email, days) {
  const key = secretKey();
  if (!key) throw new Error("Auth secret not configured");
  const exp = Date.now() + (days || 30) * 864e5;
  const p = Buffer.from(email + "|" + exp).toString("base64url");
  const sig = crypto.createHmac("sha256", key).update(p).digest("base64url");
  return p + "." + sig;
}
function sha(s) { return crypto.createHash("sha256").update(s).digest("hex"); }
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
  if (event.httpMethod !== "POST") return { statusCode: 405, headers: CORS, body: "Method Not Allowed" };
  if (!secretKey()) return json(500, { error: "Auth not configured on server." });

  let p = {};
  try { p = JSON.parse(event.body || "{}"); } catch (e) {}
  const action = p.action;
  const email = String(p.email || "").trim().toLowerCase();
  if (!email || email.indexOf("@") < 1 || email.length > 200) return json(400, { error: "Enter a valid email." });

  const blobs = require("@netlify/blobs");
  try { blobs.connectLambda(event); } catch (e) {}
  const getStore = blobs.getStore;
  let store;
  try { store = getStore("auth"); } catch (e) { return json(500, { error: "Storage unavailable — try again shortly." }); }

  try {

  if (action === "request") {
    const RESEND = process.env.RESEND_API_KEY;
    if (!RESEND) return json(500, { error: "Email login isn't enabled yet (server needs RESEND_API_KEY)." });
    const prev = await store.get(email, { type: "json" });
    if (prev && prev.sent >= 3 && Date.now() < prev.exp) return json(429, { error: "Too many codes requested — try again in a few minutes." });
    const code = String(crypto.randomInt(100000, 1000000));
    await store.setJSON(email, {
      hash: sha(email + ":" + code),
      exp: Date.now() + 15 * 60000,
      tries: 0,
      sent: (prev && Date.now() < prev.exp ? (prev.sent || 1) : 0) + 1,
    });
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: "Bearer " + RESEND, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: process.env.NEWSLETTER_FROM || "BullrunIQ <brief@bullruniq.com>",
        to: email,
        subject: code + " is your BullrunIQ login code",
        html: "<!doctype html><html><head><meta charset='utf-8'></head><body style='margin:0;background:#050505;padding:40px 24px;font-family:-apple-system,Segoe UI,sans-serif;text-align:center'>"
          + "<div style='font-family:Georgia,serif;font-size:20px;letter-spacing:2px;color:#f0ece4;margin-bottom:28px'>Bullrun<span style='color:#c9a84c'>IQ</span></div>"
          + "<div style='color:#8a8278;font-size:14px;margin-bottom:16px'>Your login code — valid for 15 minutes:</div>"
          + "<div style='font-family:Georgia,serif;font-size:42px;letter-spacing:10px;color:#c9a84c'>" + code + "</div>"
          + "<div style='color:#5c574e;font-size:11px;margin-top:28px'>If you didn't request this, you can ignore this email.</div>"
          + "</body></html>",
      }),
    });
    if (!r.ok) return json(502, { error: "Couldn't send the email — try again." });
    return json(200, { ok: true });
  }

  if (action === "verify") {
    const code = String(p.code || "").trim().replace(/\s/g, "");
    if (!/^\d{6}$/.test(code)) return json(400, { error: "Enter the 6-digit code from the email." });
    const rec = await store.get(email, { type: "json" });
    if (!rec || Date.now() > rec.exp) return json(400, { error: "Code expired — request a new one." });
    if (rec.tries >= 5) return json(429, { error: "Too many attempts — request a new code." });
    if (sha(email + ":" + code) !== rec.hash) {
      rec.tries = (rec.tries || 0) + 1;
      await store.setJSON(email, rec);
      return json(400, { error: "Wrong code — check the email and try again." });
    }
    await store.delete(email);
    const plan = await planFor(email, getStore);
    try {
      const subs = getStore("subscribers");
      if (!(await subs.get(email, { type: "json" }))) {
        await subs.setJSON(email, { email: email, source: "account", joinedAt: new Date().toISOString() });
      }
    } catch (e) {}
    return json(200, { token: signToken(email, 30), email: email, plan: plan });
  }

  return json(400, { error: "Unknown action" });

  } catch (e) {
    console.log("[auth] error:", e.message);
    return json(500, { error: "Login service hiccup — try again shortly." });
  }
};
