# Turn on revenue — Stripe setup (≈20 min)

The checkout function (`netlify/functions/checkout.js`) is already built. You just need to
create the products in Stripe and paste 4 keys into Netlify. Do it in **Test mode** first,
then flip to **Live**.

## 1. Create the 3 products (Test mode)
Stripe Dashboard → toggle **Test mode** (top-right) → **Product catalog → Add product**.
Create three, each with a **Recurring · Monthly · USD** price:

| Product name | Price | Billing |
|---|---|---|
| BullrunIQ Pro | $29 | Monthly recurring |
| BullrunIQ Elite | $79 | Monthly recurring |
| BullrunIQ Advisor | $299 | Monthly recurring |

After saving each, open it and **copy the Price ID** (looks like `price_1AbC…`) — not the product ID.

## 2. Get your secret key
Developers → **API keys** → copy the **Secret key** (`sk_test_…` in Test mode).

## 3. Add 4 env vars in Netlify
Site configuration → **Environment variables** → add:

```
STRIPE_SECRET_KEY     = sk_test_…
STRIPE_PRICE_PRO      = price_…   (the $29 price)
STRIPE_PRICE_ELITE    = price_…   (the $79 price)
STRIPE_PRICE_ADVISOR  = price_…   (the $299 price)
```

Then **Deploys → Trigger deploy** (env vars only apply after a redeploy).

## 4. Test the flow
Go to `/platform` → **⚡ Go Pro** → **Get Pro →**. It should redirect to Stripe Checkout.
Pay with the test card:

```
Card    4242 4242 4242 4242
Expiry  any future date    CVC any 3 digits    ZIP any
```

Complete → you're sent back to `/platform?upgrade=success&tier=pro` and the app flips to Pro
(unlimited AI). ✅ If you instead see the email-capture fallback, the env vars aren't set/applied yet.

## 5. Go live
1. Switch Stripe to **Live mode** and recreate the 3 products (live Price IDs are different).
2. Copy your **live** secret key (`sk_live_…`) and the **live** Price IDs.
3. Update the same 4 Netlify env vars with the live values → redeploy.
4. Activate your Stripe account (business details + bank for payouts) and enable the
   **Customer Portal** (Settings → Billing → Customer portal) so customers can cancel.

## 6. Webhook + Customer Portal (~10 min, do right after go-live)
The functions are already deployed (`stripe-webhook.js`, `portal.js`) — just connect them:

1. **Webhook:** Stripe → Developers → **Webhooks → Add endpoint**
   - URL: `https://bullruniq.com/api/stripe-webhook`
   - Events: `checkout.session.completed`, `customer.subscription.updated`,
     `customer.subscription.deleted`, `invoice.payment_failed`
   - Copy the **Signing secret** (`whsec_…`) → Netlify env `STRIPE_WEBHOOK_SECRET`
2. **Customer Portal:** Stripe → Settings → Billing → **Customer portal** → Activate.
   Copy the portal **login link** (`https://billing.stripe.com/p/login/…`) → Netlify env `STRIPE_PORTAL_URL`
3. Redeploy.

You now get: every sale/cancel/failed payment recorded to a customer list
(Netlify → Blobs → `customers`), paying customers auto-added to the newsletter,
and a working **Manage subscription** button in the app's Settings tab.

---

## One remaining honest caveat
**Plan is per-browser (no accounts).** "Pro" is stored in the browser, so a user who pays on their
phone won't show as Pro on their laptop, and in-app access isn't auto-revoked on cancel (the
webhook records it, but nothing enforces it client-side yet). The clean fix is lightweight
accounts + a server-side entitlement check — the customer list this webhook builds is exactly
the foundation for that. Ask when you want it built.
