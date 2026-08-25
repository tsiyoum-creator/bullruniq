// BullrunIQ — capture form submissions into a durable subscriber list.

exports.handler = async function (event) {
  try {
    const blobs = require("@netlify/blobs");
    try { blobs.connectLambda(event); } catch (e) {}
    const getStore = blobs.getStore;
    const body = JSON.parse(event.body || "{}");
    const payload = body.payload || {};
    const data = payload.data || {};
    const email = String(data.email || "").trim().toLowerCase();
    if (!email || email.indexOf("@") < 1) return { statusCode: 200, body: "no email" };

    const form = payload.form_name || data["form-name"] || "";
    if (form === "contact" || form === "contact-form") {
      console.log("[subscribers] skipped contact-form submission from", email);
      return { statusCode: 200, body: "skipped" };
    }
    const store = getStore("subscribers");
    const existing = await store.get(email, { type: "json" });
    if (!existing) {
      await store.setJSON(email, {
        email: email,
        source: form || data.source || "waitlist",
        tier: data.tier || null,
        joinedAt: new Date().toISOString(),
      });
      console.log("[subscribers] added", email, "via", form);
    }
    return { statusCode: 200, body: "ok" };
  } catch (e) {
    console.log("[subscribers] error", e.message);
    return { statusCode: 200, body: "err" };
  }
};
