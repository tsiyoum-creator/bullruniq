// BullrunIQ — server-side price alerts (scheduled, see netlify.toml).
// Reads every synced user's watchlist + holdings (Blobs "userdata", written by
// sync.js), batch-fetches live prices from CoinGecko, and emails via Resend when:
//   • BUY alert: watchlist price comes within 2% below their buy target.
//   • SELL alert: watchlist price rises to or above their sellTarget.
//   • STOP alert: a holding falls to/below its stop-loss (portfolio guard).
//   • TP alert: a holding rises to/above its take-profit (portfolio guard).
// server*Alerted flags with ~5% hysteresis prevent repeat emails.
// Crypto tickers only — stock quotes would need per-user broker keys server-side.
// No-ops gracefully until RESEND_API_KEY is set.

const MAX_EMAILS_PER_RUN = 20; // stay well inside Resend free tier

const CGMAP = { BTC:"bitcoin", ETH:"ethereum", SOL:"solana", BNB:"binancecoin", XRP:"ripple", ADA:"cardano", DOGE:"dogecoin", AVAX:"avalanche-2", DOT:"polkadot", MATIC:"matic-network", LINK:"chainlink", LTC:"litecoin", NEAR:"near", APT:"aptos", SHIB:"shiba-inu", UNI:"uniswap", ATOM:"cosmos", TRX:"tron", OP:"optimism", ARB:"arbitrum", SUI:"sui", INJ:"injective-protocol", PEPE:"pepe", WIF:"dogwifcoin", TON:"the-open-network", XLM:"stellar", HBAR:"hedera-hashgraph", QNT:"quant-network", AERO:"aerodrome-finance", ALGO:"algorand", VET:"vechain", FIL:"filecoin", ICP:"internet-computer", RENDER:"render-token", FTM:"fantom", CRO:"crypto-com-chain", LDO:"lido-dao", RUNE:"thorchain", SAND:"the-sandbox", MANA:"decentraland", AXS:"axie-infinity", GALA:"gala", IMX:"immutable-x", BLUR:"blur", SEI:"sei-network", ONDO:"ondo-finance", JUP:"jupiter-exchange-solana", PYTH:"pyth-network", JTO:"jito-governance-token", BONK:"bonk", STRK:"starknet", TAO:"bittensor", ETHFI:"ether-fi", ENA:"ethena", FLOKI:"floki" };

// Allowlist for CoinGecko coin IDs — prevents injection into the price-fetch URL (S-4).
const VALID_COIN_ID = /^[a-z0-9-]{1,50}$/;

function coinId(ticker) {
  const mapped = CGMAP[String(ticker).toUpperCase()];
  if (mapped) return mapped;
  const fallback = String(ticker).toLowerCase().trim();
  return VALID_COIN_ID.test(fallback) ? fallback : null;
}

function fp(v) { return v >= 1000 ? "$" + v.toLocaleString("en-US", { maximumFractionDigits: 2 }) : v >= 1 ? "$" + v.toFixed(2) : "$" + v.toFixed(6); }
function pct(v) { return (v >= 0 ? "+" : "") + v.toFixed(1) + "%"; }
function esc(s) { return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#x27;"); }

function buyAlertHtml(w, price, email) {
  const name = esc(w.name || w.ticker);
  const ticker = esc(w.ticker);
  return "<!doctype html><html><head><meta charset='utf-8'></head><body style='margin:0;background:#050505;padding:40px 24px;font-family:-apple-system,Segoe UI,sans-serif;text-align:center'>"
    + "<div style='font-family:Georgia,serif;font-size:20px;letter-spacing:2px;color:#f0ece4;margin-bottom:24px'>Bullrun<span style='color:#c9a84c'>IQ</span></div>"
    + "<div style='font-size:12px;letter-spacing:2px;text-transform:uppercase;color:#4ade80;margin-bottom:10px'>🎯 Buy zone alert</div>"
    + "<div style='font-family:Georgia,serif;font-size:30px;color:#f0ece4;margin-bottom:8px'>" + ticker + " is at your buy zone</div>"
    + "<div style='color:#8a8278;font-size:15px;line-height:1.7;max-width:400px;margin:0 auto 22px'>" + name + " is now <b style='color:#c9a84c'>" + fp(price) + "</b> — within 2% of your target of <b style='color:#c9a84c'>" + fp(w.targetPrice) + "</b>.</div>"
    + "<a href='https://bullruniq.com/platform' style='display:inline-block;background:#c9a84c;color:#000;text-decoration:none;border-radius:4px;padding:14px 32px;font-size:13px;font-weight:600;letter-spacing:1px;text-transform:uppercase'>Open your command center →</a>"
    + "<div style='border-top:1px solid #1a1a1a;margin-top:32px;padding-top:16px;font-size:11px;color:#5c574e;line-height:1.6;max-width:420px;margin-left:auto;margin-right:auto'>Educational alert, not financial advice. You get these because you set a price target in BullrunIQ.<br><a href='https://bullruniq.com/api/unsubscribe?email=" + encodeURIComponent(email) + "' style='color:#8a8278'>Unsubscribe from all emails</a></div>"
    + "</body></html>";
}

function sellAlertHtml(w, price, gainPct, email) {
  const name = esc(w.name || w.ticker);
  const ticker = esc(w.ticker);
  return "<!doctype html><html><head><meta charset='utf-8'></head><body style='margin:0;background:#050505;padding:40px 24px;font-family:-apple-system,Segoe UI,sans-serif;text-align:center'>"
    + "<div style='font-family:Georgia,serif;font-size:20px;letter-spacing:2px;color:#f0ece4;margin-bottom:24px'>Bullrun<span style='color:#c9a84c'>IQ</span></div>"
    + "<div style='font-size:12px;letter-spacing:2px;text-transform:uppercase;color:#e05555;margin-bottom:10px'>💰 Profit-taking signal</div>"
    + "<div style='font-family:Georgia,serif;font-size:30px;color:#f0ece4;margin-bottom:8px'>" + ticker + " hit your sell target</div>"
    + "<div style='color:#8a8278;font-size:15px;line-height:1.7;max-width:400px;margin:0 auto 12px'>" + name + " is now <b style='color:#c9a84c'>" + fp(price) + "</b> — reached your profit target of <b style='color:#c9a84c'>" + fp(w.sellTarget) + "</b>.</div>"
    + (gainPct !== null ? "<div style='font-size:13px;color:#4ade80;margin-bottom:22px'>Up <b>" + pct(gainPct) + "</b> from your buy target of " + fp(w.targetPrice) + "</div>" : "<div style='margin-bottom:22px'></div>")
    + "<a href='https://bullruniq.com/platform' style='display:inline-block;background:#e05555;color:#fff;text-decoration:none;border-radius:4px;padding:14px 32px;font-size:13px;font-weight:600;letter-spacing:1px;text-transform:uppercase'>Review your position →</a>"
    + "<div style='border-top:1px solid #1a1a1a;margin-top:32px;padding-top:16px;font-size:11px;color:#5c574e;line-height:1.6;max-width:420px;margin-left:auto;margin-right:auto'>Educational alert, not financial advice. You get these because you set a sell target in BullrunIQ.<br><a href='https://bullruniq.com/api/unsubscribe?email=" + encodeURIComponent(email) + "' style='color:#8a8278'>Unsubscribe from all emails</a></div>"
    + "</body></html>";
}

function stopAlertHtml(h, price, email) {
  const name = esc(h.name || h.ticker);
  const ticker = esc(h.ticker);
  const lossPct = h.avg > 0 ? ((price - h.avg) / h.avg * 100) : null;
  return "<!doctype html><html><head><meta charset='utf-8'></head><body style='margin:0;background:#050505;padding:40px 24px;font-family:-apple-system,Segoe UI,sans-serif;text-align:center'>"
    + "<div style='font-family:Georgia,serif;font-size:20px;letter-spacing:2px;color:#f0ece4;margin-bottom:24px'>Bullrun<span style='color:#c9a84c'>IQ</span></div>"
    + "<div style='font-size:12px;letter-spacing:2px;text-transform:uppercase;color:#e05555;margin-bottom:10px'>⛔ Stop-loss triggered</div>"
    + "<div style='font-family:Georgia,serif;font-size:30px;color:#f0ece4;margin-bottom:8px'>" + ticker + " fell below your stop</div>"
    + "<div style='color:#8a8278;font-size:15px;line-height:1.7;max-width:400px;margin:0 auto 12px'>" + name + " is now <b style='color:#e05555'>" + fp(price) + "</b> — below the stop-loss you set at <b style='color:#c9a84c'>" + fp(h.stop) + "</b>.</div>"
    + (lossPct !== null ? "<div style='font-size:13px;color:#e05555;margin-bottom:22px'>Position is at <b>" + pct(lossPct) + "</b> vs your avg buy of " + fp(h.avg) + "</div>" : "<div style='margin-bottom:22px'></div>")
    + "<a href='https://bullruniq.com/platform' style='display:inline-block;background:#e05555;color:#fff;text-decoration:none;border-radius:4px;padding:14px 32px;font-size:13px;font-weight:600;letter-spacing:1px;text-transform:uppercase'>Review the position now →</a>"
    + "<div style='border-top:1px solid #1a1a1a;margin-top:32px;padding-top:16px;font-size:11px;color:#5c574e;line-height:1.6;max-width:420px;margin-left:auto;margin-right:auto'>Educational alert, not financial advice. You get these because you set a stop-loss in BullrunIQ.<br><a href='https://bullruniq.com/api/unsubscribe?email=" + encodeURIComponent(email) + "' style='color:#8a8278'>Unsubscribe from all emails</a></div>"
    + "</body></html>";
}

function tpAlertHtml(h, price, email) {
  const name = esc(h.name || h.ticker);
  const ticker = esc(h.ticker);
  const gainPct = h.avg > 0 ? ((price - h.avg) / h.avg * 100) : null;
  const value = price * (h.qty || 0);
  return "<!doctype html><html><head><meta charset='utf-8'></head><body style='margin:0;background:#050505;padding:40px 24px;font-family:-apple-system,Segoe UI,sans-serif;text-align:center'>"
    + "<div style='font-family:Georgia,serif;font-size:20px;letter-spacing:2px;color:#f0ece4;margin-bottom:24px'>Bullrun<span style='color:#c9a84c'>IQ</span></div>"
    + "<div style='font-size:12px;letter-spacing:2px;text-transform:uppercase;color:#4ade80;margin-bottom:10px'>🎯 Take-profit reached</div>"
    + "<div style='font-family:Georgia,serif;font-size:30px;color:#f0ece4;margin-bottom:8px'>" + ticker + " hit your target</div>"
    + "<div style='color:#8a8278;font-size:15px;line-height:1.7;max-width:400px;margin:0 auto 12px'>" + name + " is now <b style='color:#c9a84c'>" + fp(price) + "</b> — at the take-profit you set at <b style='color:#c9a84c'>" + fp(h.tp) + "</b>." + (value > 0 ? " Your position is worth <b style='color:#f0ece4'>" + fp(value) + "</b>." : "") + "</div>"
    + (gainPct !== null ? "<div style='font-size:13px;color:#4ade80;margin-bottom:22px'>Up <b>" + pct(gainPct) + "</b> from your avg buy of " + fp(h.avg) + " — consider locking some in</div>" : "<div style='margin-bottom:22px'></div>")
    + "<a href='https://bullruniq.com/platform' style='display:inline-block;background:#c9a84c;color:#000;text-decoration:none;border-radius:4px;padding:14px 32px;font-size:13px;font-weight:600;letter-spacing:1px;text-transform:uppercase'>Take some profit →</a>"
    + "<div style='border-top:1px solid #1a1a1a;margin-top:32px;padding-top:16px;font-size:11px;color:#5c574e;line-height:1.6;max-width:420px;margin-left:auto;margin-right:auto'>Educational alert, not financial advice. You get these because you set a take-profit in BullrunIQ.<br><a href='https://bullruniq.com/api/unsubscribe?email=" + encodeURIComponent(email) + "' style='color:#8a8278'>Unsubscribe from all emails</a></div>"
    + "</body></html>";
}

exports.handler = async function (event) {
  const RESEND = process.env.RESEND_API_KEY;
  if (!RESEND) { console.log("[alerts] skipped — RESEND_API_KEY not set"); return { statusCode: 200, body: "not configured" }; }

  const blobs = require("@netlify/blobs");
  try { blobs.connectLambda(event); } catch (e) {}
  let store, users = [];
  try {
    store = blobs.getStore("userdata");
    users = ((await store.list()).blobs || []).map(function (b) { return b.key; });
  } catch (e) { console.error("[alerts] storage error:", e.message); return { statusCode: 200, body: "storage error" }; }
  if (!users.length) return { statusCode: 200, body: "no users" };

  // Load each user's state; collect crypto coin IDs that have any target.
  // coinId() validates each ticker against CGMAP then a regex — invalid
  // strings are dropped rather than injected into the CoinGecko URL (S-4 fix).
  const recs = {};
  const ids = new Set();
  for (const email of users) {
    try {
      const rec = await store.get(email, { type: "json" });
      const wlist = rec && rec.data && Array.isArray(rec.data.wl) ? rec.data.wl : [];
      const hold = rec && rec.data && rec.data.port && Array.isArray(rec.data.port.crypto) ? rec.data.port.crypto : [];
      const hasWl = wlist.some(function (w) { return w && (w.targetPrice || w.sellTarget); });
      const hasHold = hold.some(function (h) { return h && (h.stop || h.tp); });
      if (hasWl || hasHold) {
        recs[email] = rec;
        wlist.forEach(function (w) {
          if (w && (w.targetPrice || w.sellTarget)) {
            const id = coinId(w.ticker);
            if (id) ids.add(id);
          }
        });
        hold.forEach(function (h) {
          if (h && (h.stop || h.tp)) {
            const id = coinId(h.ticker);
            if (id) ids.add(id);
          }
        });
      }
    } catch (e) { console.error("[alerts] error loading user state:", e.message); }
  }
  if (!ids.size) return { statusCode: 200, body: "no targets" };

  // One batched price call — all coin IDs are validated above (S-4 fix).
  let prices = {};
  try {
    const cgHeaders = { "User-Agent": "BullrunIQ/1.0 (+https://bullruniq.com)" };
    if (process.env.COINGECKO_API_KEY) cgHeaders["x-cg-pro-api-key"] = process.env.COINGECKO_API_KEY;
    const r = await fetch("https://api.coingecko.com/api/v3/simple/price?ids=" + [...ids].join(",") + "&vs_currencies=usd", { headers: cgHeaders });
    prices = await r.json();
  } catch (e) { console.error("[alerts] price fetch failed:", e.message); return { statusCode: 200, body: "price error" }; }

  let sent = 0;
  for (const email of Object.keys(recs)) {
    const rec = recs[email];
    let changed = false;

    // ── Portfolio guard: stop-loss / take-profit on actual holdings ──
    const hold = rec.data.port && Array.isArray(rec.data.port.crypto) ? rec.data.port.crypto : [];
    for (const h of hold) {
      if (!h || (!h.stop && !h.tp)) continue;
      const id = coinId(h.ticker);
      if (!id) continue;
      const p = prices[id] && prices[id].usd;
      if (!p) continue;

      if (h.stop && p <= h.stop && !h.serverStopAlerted && sent < MAX_EMAILS_PER_RUN) {
        try {
          const r = await fetch("https://api.resend.com/emails", {
            method: "POST",
            headers: { Authorization: "Bearer " + RESEND, "Content-Type": "application/json" },
            body: JSON.stringify({
              from: process.env.NEWSLETTER_FROM || "BullrunIQ <brief@bullruniq.com>",
              to: email,
              subject: "⛔ " + h.ticker + " fell below your stop-loss — now " + fp(p),
              html: stopAlertHtml(h, p, email),
            }),
          });
          if (r.ok) { sent++; h.serverStopAlerted = true; changed = true; console.log("[alerts] stop " + h.ticker + " @ " + p); }
          else { console.error("[alerts] resend error for stop alert:", r.status); }
        } catch (e) { console.error("[alerts] stop email send failed:", e.message); }
      } else if (h.stop && p >= h.stop * 1.05 && h.serverStopAlerted) {
        h.serverStopAlerted = false; changed = true; // re-arm once price recovers 5% above the stop
      }

      if (h.tp && p >= h.tp && !h.serverTpAlerted && sent < MAX_EMAILS_PER_RUN) {
        try {
          const r = await fetch("https://api.resend.com/emails", {
            method: "POST",
            headers: { Authorization: "Bearer " + RESEND, "Content-Type": "application/json" },
            body: JSON.stringify({
              from: process.env.NEWSLETTER_FROM || "BullrunIQ <brief@bullruniq.com>",
              to: email,
              subject: "🎯 " + h.ticker + " hit your take-profit — now " + fp(p),
              html: tpAlertHtml(h, p, email),
            }),
          });
          if (r.ok) { sent++; h.serverTpAlerted = true; changed = true; console.log("[alerts] tp " + h.ticker + " @ " + p); }
          else { console.error("[alerts] resend error for tp alert:", r.status); }
        } catch (e) { console.error("[alerts] tp email send failed:", e.message); }
      } else if (h.tp && p < h.tp * 0.95 && h.serverTpAlerted) {
        h.serverTpAlerted = false; changed = true; // re-arm once price retraces 5% below the target
      }
    }

    for (const w of rec.data.wl || []) {
      if (!w) continue;
      const id = coinId(w.ticker);
      if (!id) continue;
      const p = prices[id] && prices[id].usd;
      if (!p) continue; // unknown ticker / stock — skip

      // BUY alert: price must be BELOW the buy target and within 2% of it (B-4 fix).
      // Using signed distance (not abs) so a price above the target never fires.
      if (w.targetPrice) {
        const dist = (w.targetPrice - p) / p * 100; // positive means price is below target
        if (dist >= 0 && dist < 2 && !w.serverAlerted && sent < MAX_EMAILS_PER_RUN) {
          try {
            const r = await fetch("https://api.resend.com/emails", {
              method: "POST",
              headers: { Authorization: "Bearer " + RESEND, "Content-Type": "application/json" },
              body: JSON.stringify({
                from: process.env.NEWSLETTER_FROM || "BullrunIQ <brief@bullruniq.com>",
                to: email,
                subject: "🎯 " + w.ticker + " hit your buy zone — now " + fp(p),
                html: buyAlertHtml(w, p, email),
              }),
            });
            if (r.ok) { sent++; w.serverAlerted = true; changed = true; console.log("[alerts] buy " + w.ticker + " @ " + p); }
            else { console.error("[alerts] resend error for buy alert:", r.status); }
          } catch (e) { console.error("[alerts] buy email send failed:", e.message); }
        } else if (Math.abs(dist) >= 5 && w.serverAlerted) {
          w.serverAlerted = false; changed = true; // re-arm once price moves 5%+ away
        }
      }

      // SELL alert: price at or above the sell target (profit-taking signal)
      if (w.sellTarget && p >= w.sellTarget && !w.serverSellAlerted && sent < MAX_EMAILS_PER_RUN) {
        const gainPct = w.targetPrice ? ((w.sellTarget - w.targetPrice) / w.targetPrice * 100) : null;
        try {
          const r = await fetch("https://api.resend.com/emails", {
            method: "POST",
            headers: { Authorization: "Bearer " + RESEND, "Content-Type": "application/json" },
            body: JSON.stringify({
              from: process.env.NEWSLETTER_FROM || "BullrunIQ <brief@bullruniq.com>",
              to: email,
              subject: "💰 " + w.ticker + " hit your sell target — now " + fp(p),
              html: sellAlertHtml(w, p, gainPct, email),
            }),
          });
          if (r.ok) { sent++; w.serverSellAlerted = true; changed = true; console.log("[alerts] sell " + w.ticker + " @ " + p); }
          else { console.error("[alerts] resend error for sell alert:", r.status); }
        } catch (e) { console.error("[alerts] sell email send failed:", e.message); }
      } else if (w.sellTarget && p < w.sellTarget * 0.95 && w.serverSellAlerted) {
        w.serverSellAlerted = false; changed = true; // re-arm once price retraces 5%
      }
    }
    if (changed) {
      try { await store.setJSON(email, rec); }
      catch (e) { console.error("[alerts] state write failed:", e.message); }
    }
  }
  console.log("[alerts] done — " + sent + " email(s) sent across " + Object.keys(recs).length + " user(s)");
  return { statusCode: 200, body: "sent " + sent };
};
