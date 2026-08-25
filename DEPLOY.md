# BullrunIQ — Deploy & setup

Site files live at the repo **root** (flat layout). `netlify.toml` serves the root
and bundles the functions in `netlify/functions/`.

## Connect to Netlify (Git deploy)
1. Netlify → **Add new site → Import from Git → GitHub** → pick `tsiyoum-creator/bullruniq`
   (or, on the existing site: **Site configuration → Build & deploy → Link repository**).
2. Build command: **leave empty**. Publish directory: **`.`** (netlify.toml already sets this).
3. Deploy. Functions deploy automatically.

## Environment variables (Site settings → Environment variables)
| Variable | For | Notes |
|---|---|---|
| `ANTHROPIC_API_KEY` | **All AI** | From console.anthropic.com. Used server-side so users don't need their own key. |
| `STRIPE_SECRET_KEY` | Paid plans | `sk_live_…`/`sk_test_…`. Until set, "Get Pro" captures the email as a lead. |
| `STRIPE_PRICE_PRO` | Pro $29/mo | Stripe Price ID `price_…` |
| `STRIPE_PRICE_ELITE` | Elite $79/mo | Stripe Price ID |
| `STRIPE_PRICE_ADVISOR` | Advisor $299/mo | Stripe Price ID |
| `SITE_URL` | optional | e.g. `https://bullruniq.com` |
| `STRIPE_WEBHOOK_SECRET` | Billing lifecycle | `whsec_…` from the webhook endpoint (see STRIPE_SETUP.md §6). Records sales/cancels to the customer list. |
| `STRIPE_PORTAL_URL` | Manage subscription | Stripe Customer Portal login link (`https://billing.stripe.com/p/login/…`). |
| `RESEND_API_KEY` | Daily Brief email **+ login codes** | `re_…` from resend.com. Until set, the newsletter no-ops and email sign-in shows "not enabled yet". |
| `AUTH_SECRET` | optional | Random string for signing login tokens. Defaults to a hash of `ANTHROPIC_API_KEY` (rotating that key just logs everyone out). |
| `NEWSLETTER_FROM` | optional | e.g. `BullrunIQ <brief@bullruniq.com>` (default). Must be a Resend-verified domain. |

Redeploy after changing env vars.

## Daily Brief newsletter
- Every waitlist signup is auto-saved to a subscriber list (Netlify Blobs, via `submission-created`) — this works immediately, no setup.
- `newsletter` is a **scheduled** function (daily 13:00 UTC ≈ 8–9am ET, set in `netlify.toml`). It generates a market brief with Claude and emails all subscribers via **Resend**.
- To turn on sending: sign up at **resend.com**, verify your domain (bullruniq.com), add `RESEND_API_KEY` (+ optional `NEWSLETTER_FROM`), and redeploy. Test by triggering the `newsletter` function from Netlify → Functions.
- Every email has a one-click unsubscribe (`/api/unsubscribe`).

## Price alerts (scheduled)
- `alerts` runs every 30 min: for each **signed-in** user it checks synced watchlist targets
  against live CoinGecko prices and emails when within 2% (re-arms after price moves 5% away).
- Needs `RESEND_API_KEY` (same as newsletter/login). Crypto tickers only.

## Where things show up
- **Waitlist / contact / Pro signups** → Netlify → **Forms** (`waitlist`, `contact`, `tier-signup`).
- **Analytics** → Netlify → **Functions → track** logs (`[analytics] …`).

## What's in v3
Secure AI proxy (`netlify/functions/generate.js`), real waitlist capture, full SEO/OG,
legal pages, Stripe checkout (`checkout.js`), a new **Signals** tab (per-holding buy/sell
levels), upgraded models, and security headers.

> The other apps in this repo (`riley-kane.html`, `trading-bot.html`, `lead-tracker.html`,
> `best-bet.html`, `app.js`, `style.css`) are untouched by v3.
