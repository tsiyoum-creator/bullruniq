// BullrunIQ — capture form submissions into a durable subscriber list.

const MAX_BODY_BYTES = 4096;
const SAFE_STRING = /^[A-Za-z0-9 _.@+-]{0,100}$/;

exports.handler = async function (event) {
  try {
    // Reject oversized payloads before parsing
    if ((event.body || "").length > MAX_BODY_BYTES) {
      console.log("[subscribers] oversized payload rejected");
      return { statusCode: 200, body: "err" };
    }
    const blobs = require("@netlify/blobs");
    try { blobs.connectLambda(event); } catch (e) {}
    const getStore = blobs.getStore;
    const body = JSON.parse(event.body || "{}");
    const payload = body.payload || {};
    const data = payload.data || {};
    const email = String(data.email || "").trim().toLowerCase().slice(0, 200);
    if (!email || email.indexOf("@") < 1) return { statusCode: 200, body: "no email" };

    const form = String(payload.form_name || data["form-name"] || "").slice(0, 80);
    if (form === "contact" || form === "contact-form") {
      console.log("[subscribers] skipped contact-form submission from", email);
      return { statusCode: 200, body: "skipped" };
    }
    // Sanitize optional fields — reject strings with unexpected characters
    const source = String(form || data.source || "waitlist").slice(0, 80);
    const rawTier = String(data.tier || "").slice(0, 20);
    const tier = SAFE_STRING.test(rawTier) ? rawTier : null;

    const store = getStore("subscribers");
    const existing = await store.get(email, { type: "json" });
    if (!existing) {
      await store.setJSON(email, {
        email: email,
        source: source,
        tier: tier || null,
        joinedAt: new Date().toISOString(),
      });
      console.log("[subscribers] added", email, "via", source);
    }
    return { statusCode: 200, body: "ok" };
  } catch (e) {
    console.log("[subscribers] error", e.message);
    return { statusCode: 200, body: "err" };
  }
};
