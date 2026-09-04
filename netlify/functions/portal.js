// BullrunIQ — "Manage subscription" entry point.
// Generates a customer-specific Stripe Billing Portal session so users land
// directly in their own portal (B-1 fix — the old code redirected everyone to
// the same static URL, which required Stripe login from scratch every time).
// Auth: Bearer token via Authorization header OR `?token=` query param (the
// latter supports browser <a href> links without JS fetch).

const crypto = require("crypto");

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

exports.handler = async function (event) {
  const secret = process.env.STRIPE_SECRET_KEY;
  const origin = process.env.SITE_URL || "https://bullruniq.com";
  const fallback = process.env.STRIPE_PORTAL_URL || (origin + "/contact");

  if (!secret) {
    return { statusCode: 302, headers: { Location: fallback }, body: "" };
  }

  // Accept token from Authorization header or query param (for plain browser links).
  const q = event.queryStringParameters || {};
  const h = event.headers || {};
  const rawToken = q.token || (h.authorization || h.Authorization || "").replace(/^Bearer\s+/i, "").trim();
  const email = verifyToken(rawToken);

  if (!email) {
    return { statusCode: 302, headers: { Location: origin + "/platform?error=login" }, body: "" };
  }

  // Look up the Stripe customer ID stored by the webhook.
  const blobs = require("@netlify/blobs");
  try { blobs.connectLambda(event); } catch (e) {}
  let customerId;
  try {
    const rec = await blobs.getStore("customers").get(email, { type: "json" });
    customerId = rec && rec.customer;
  } catch (e) { console.error("[portal] customer lookup failed:", e.message); }

  if (!customerId) {
    // User has no Stripe record — they are on the free plan.
    return { statusCode: 302, headers: { Location: origin + "/platform?upgrade=needed" }, body: "" };
  }

  // Create a customer-specific portal session.
  const params = new URLSearchParams();
  params.append("customer", customerId);
  params.append("return_url", origin + "/platform");

  try {
    const r = await fetch("https://api.stripe.com/v1/billing_portal/sessions", {
      method: "POST",
      headers: {
        Authorization: "Bearer " + secret,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params.toString(),
    });
    const data = await r.json();
    if (!r.ok || !data.url) {
      console.error("[portal] Stripe portal session error:", r.status, data && data.error && data.error.message);
      return { statusCode: 302, headers: { Location: fallback }, body: "" };
    }
    return { statusCode: 302, headers: { Location: data.url }, body: "" };
  } catch (err) {
    console.error("[portal] error:", err.message);
    return { statusCode: 302, headers: { Location: fallback }, body: "" };
  }
};
