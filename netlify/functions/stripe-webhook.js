// BullrunIQ — Stripe webhook.

const crypto = require("crypto");

function verifyStripe(rawBody, sigHeader, secret) {
  if (!sigHeader || !secret) return false;
  const parts = {};
  String(sigHeader).split(",").forEach(function (kv) {
    const i = kv.indexOf("=");
    if (i > 0) parts[kv.slice(0, i).trim()] = kv.slice(i + 1).trim();
  });
  if (!parts.t || !parts.v1) return false;
  const signed = parts.t + "." + rawBody;
  const expected = crypto.createHmac("sha256", secret).update(signed, "utf8").digest("hex");
  try {
    const expBuf = Buffer.from(expected);
    const gotBuf = Buffer.from(parts.v1);
    if (expBuf.length !== gotBuf.length) return false;
    if (!crypto.timingSafeEqual(expBuf, gotBuf)) return false;
  } catch (e) { return false; }
  const age = Math.abs(Math.floor(Date.now() / 1000) - parseInt(parts.t, 10));
  return age <= 300;
}

exports.handler = async function (event) {
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) {
    console.log("[stripe-webhook] STRIPE_WEBHOOK_SECRET not set — skipping");
    return { statusCode: 200, body: "not configured" };
  }
  const raw = event.isBase64Encoded ? Buffer.from(event.body || "", "base64").toString("utf8") : (event.body || "");
  const h = event.headers || {};
  const sig = h["stripe-signature"] || h["Stripe-Signature"];
  if (!verifyStripe(raw, sig, secret)) {
    return { statusCode: 400, body: "invalid signature" };
  }

  let evt;
  try { evt = JSON.parse(raw); } catch (e) { return { statusCode: 400, body: "bad json" }; }

  try {
    const blobs = require("@netlify/blobs");
    try { blobs.connectLambda(event); } catch (e) {}
    const getStore = blobs.getStore;
    const customers = getStore("customers");
    const obj = (evt.data && evt.data.object) || {};

    async function emailForCustomer(cid) {
      if (!cid) return null;
      const ptr = await customers.get("cid:" + cid, { type: "json" });
      return ptr && ptr.email ? ptr.email : null;
    }
    async function setStatus(cid, status, tier) {
      const email = await emailForCustomer(cid);
      if (!email) return;
      const rec = (await customers.get(email, { type: "json" })) || { email: email };
      rec.status = status;
      rec.updatedAt = new Date().toISOString();
      if (tier) rec.tier = tier;
      await customers.setJSON(email, rec);
      console.log("[stripe-webhook] " + email + " -> " + status + (tier ? " (" + tier + ")" : ""));
    }

    if (evt.type === "checkout.session.completed") {
      const email = ((obj.customer_details && obj.customer_details.email) || obj.customer_email || "").toLowerCase();
      const cid = obj.customer || null;
      if (email) {
        await customers.setJSON(email, {
          email: email,
          tier: (obj.metadata && obj.metadata.tier) || "pro",
          customer: cid,
          subscription: obj.subscription || null,
          status: "active",
          updatedAt: new Date().toISOString(),
        });
        if (cid) await customers.setJSON("cid:" + cid, { email: email });
        try {
          const subs = getStore("subscribers");
          if (!(await subs.get(email, { type: "json" }))) {
            await subs.setJSON(email, { email: email, source: "customer", joinedAt: new Date().toISOString() });
          }
        } catch (e) {}
        console.log("[stripe-webhook] new customer " + email);
      }
    } else if (evt.type === "customer.subscription.deleted") {
      await setStatus(obj.customer, "canceled");
    } else if (evt.type === "customer.subscription.updated") {
      const priceId = obj.items && obj.items.data && obj.items.data[0] && obj.items.data[0].price && obj.items.data[0].price.id;
      let tier;
      if (priceId) {
        if (priceId === process.env.STRIPE_PRICE_ADVISOR) tier = "advisor";
        else if (priceId === process.env.STRIPE_PRICE_ELITE) tier = "elite";
        else if (priceId === process.env.STRIPE_PRICE_PRO) tier = "pro";
      }
      await setStatus(obj.customer, obj.status || "active", tier);
    } else if (evt.type === "invoice.payment_failed") {
      await setStatus(obj.customer, "past_due");
    } else if (evt.type === "invoice.paid") {
      await setStatus(obj.customer, "active");
    }
  } catch (e) {
    console.log("[stripe-webhook] handler error:", e.message);
  }

  return { statusCode: 200, body: "ok" };
};
