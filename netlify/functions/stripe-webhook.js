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
    if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(parts.v1))) return false;
  } catch (e) { return false; }
  const age = Math.abs(Math.floor(Date.now() / 1000) - parseInt(parts.t, 10));
  return age <= 300;
}

exports.handler = async function (event) {
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) {
    console.error("[stripe-webhook] STRIPE_WEBHOOK_SECRET not set — rejecting so Stripe retries");
    return { statusCode: 500, body: "webhook secret not configured" };
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
        // Merge with existing record so an upgrade doesn't lose prior subscription data.
        const existing = (await customers.get(email, { type: "json" })) || { email: email };
        const updated = Object.assign({}, existing, {
          email: email,
          tier: (obj.metadata && obj.metadata.tier) || existing.tier || "pro",
          customer: cid || existing.customer,
          subscription: obj.subscription || existing.subscription,
          status: "active",
          updatedAt: new Date().toISOString(),
        });
        await customers.setJSON(email, updated);
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
      // Notify the user so they can update their payment method before losing access.
      try {
        const RESEND = process.env.RESEND_API_KEY;
        const FROM = process.env.NEWSLETTER_FROM || "BullrunIQ <brief@bullruniq.com>";
        const failedEmail = await emailForCustomer(obj.customer);
        if (RESEND && failedEmail) {
          await fetch("https://api.resend.com/emails", {
            method: "POST",
            headers: { Authorization: "Bearer " + RESEND, "Content-Type": "application/json" },
            body: JSON.stringify({
              from: FROM,
              to: failedEmail,
              subject: "⚠️ BullrunIQ — payment failed, update your card to keep access",
              html: "<!doctype html><html><head><meta charset='utf-8'></head><body style='margin:0;background:#050505;padding:40px 24px;font-family:-apple-system,Segoe UI,sans-serif;text-align:center'>"
                + "<div style='font-family:Georgia,serif;font-size:20px;letter-spacing:2px;color:#f0ece4;margin-bottom:28px'>Bullrun<span style='color:#c9a84c'>IQ</span></div>"
                + "<div style='font-size:12px;letter-spacing:2px;text-transform:uppercase;color:#e05555;margin-bottom:10px'>⚠️ Payment failed</div>"
                + "<div style='font-family:Georgia,serif;font-size:26px;color:#f0ece4;margin-bottom:16px'>Your subscription payment failed</div>"
                + "<div style='color:#8a8278;font-size:15px;line-height:1.7;max-width:420px;margin:0 auto 22px'>Your BullrunIQ subscription could not be renewed. Update your payment method to maintain access to AI analysis, price alerts, and cloud sync.</div>"
                + "<a href='https://bullruniq.com/api/portal' style='display:inline-block;background:#c9a84c;color:#000;text-decoration:none;border-radius:4px;padding:14px 32px;font-size:13px;font-weight:600;letter-spacing:1px;text-transform:uppercase'>Update payment method →</a>"
                + "<div style='color:#5c574e;font-size:11px;margin-top:28px'>If you have questions, reply to this email or visit bullruniq.com</div>"
                + "</body></html>",
            }),
          });
          console.log("[stripe-webhook] payment-failed email sent to customer of " + obj.customer);
        }
      } catch (emailErr) {
        console.log("[stripe-webhook] payment-failed email error:", emailErr.message);
      }
    } else if (evt.type === "invoice.paid") {
      await setStatus(obj.customer, "active");
    }
  } catch (e) {
    console.error("[stripe-webhook] handler error:", e.message);
    // Return 500 so Stripe retries the event; don't swallow storage failures silently.
    return { statusCode: 500, body: "handler error" };
  }

  return { statusCode: 200, body: "ok" };
};
