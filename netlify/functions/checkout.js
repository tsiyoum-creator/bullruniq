// BullrunIQ — Stripe Checkout session creator

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const PRICE_ENV = {
  pro: "STRIPE_PRICE_PRO",
  elite: "STRIPE_PRICE_ELITE",
  advisor: "STRIPE_PRICE_ADVISOR",
};

exports.handler = async function (event) {
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, headers: CORS, body: "" };
  if (event.httpMethod !== "POST") return { statusCode: 405, headers: CORS, body: "Method Not Allowed" };

  const SECRET = process.env.STRIPE_SECRET_KEY;

  let payload = {};
  try { payload = JSON.parse(event.body || "{}"); } catch (e) {}
  const tier = String(payload.tier || "").toLowerCase();
  const rawEmail = payload.email ? String(payload.email).trim().toLowerCase().slice(0, 200) : "";
  const email = rawEmail && rawEmail.indexOf("@") > 0 ? rawEmail : "";

  if (!SECRET) {
    return { statusCode: 200, headers: { "Content-Type": "application/json", ...CORS }, body: JSON.stringify({ configured: false }) };
  }

  const priceEnvName = PRICE_ENV[tier];
  const priceId = priceEnvName ? process.env[priceEnvName] : null;
  if (!priceId) {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: "Unknown or unconfigured tier: " + tier }) };
  }

  const origin = process.env.SITE_URL || (event.headers && (event.headers.origin || ("https://" + event.headers.host))) || "https://bullruniq.com";

  const params = new URLSearchParams();
  params.append("mode", "subscription");
  params.append("line_items[0][price]", priceId);
  params.append("line_items[0][quantity]", "1");
  params.append("allow_promotion_codes", "true");
  params.append("success_url", origin + "/platform?upgrade=success&tier=" + tier);
  params.append("cancel_url", origin + "/platform?upgrade=cancel");
  if (email) params.append("customer_email", email);
  params.append("metadata[tier]", tier);

  try {
    const r = await fetch("https://api.stripe.com/v1/checkout/sessions", {
      method: "POST",
      headers: {
        Authorization: "Bearer " + SECRET,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params.toString(),
    });
    const data = await r.json();
    if (!r.ok) {
      return { statusCode: r.status, headers: CORS, body: JSON.stringify({ error: (data.error && data.error.message) || "Stripe error" }) };
    }
    return { statusCode: 200, headers: { "Content-Type": "application/json", ...CORS }, body: JSON.stringify({ configured: true, url: data.url }) };
  } catch (err) {
    return { statusCode: 502, headers: CORS, body: JSON.stringify({ error: err.message }) };
  }
};
