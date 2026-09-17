// BullrunIQ — server-side price alerts (scheduled, see netlify.toml).
// Reads every synced user's watchlist + holdings (Blobs "userdata", written by
// sync.js), batch-fetches live prices from CoinGecko, and emails via Resend when:
//   • BUY alert: watchlist price comes within 2% of their buy target (from above).
//   • SELL alert: watchlist price rises to or above their sellTarget.
//   • STOP alert: a holding falls to/below its stop-loss (portfolio guard).
//   • TP alert: a holding rises to/above its take-profit (portfolio guard).
// server*Alerted flags with ~5% hysteresis prevent repeat emails.
// Crypto tickers only — stock quotes would need per-user broker keys server-side.
// No-ops gracefully until RESEND_API_KEY is set.

const { fp, pct, esc } = require("./_shared");

const MAX_EMAILS_PER_RUN = 20; // stay well inside Resend free tier

const CGMAP = {
  BTC:"bitcoin", ETH:"ethereum", SOL:"solana", BNB:"binancecoin", XRP:"ripple",
  ADA:"cardano", DOGE:"dogecoin", AVAX:"avalanche-2", DOT:"polkadot", MATIC:"matic-network",
  LINK:"chainlink", LTC:"litecoin", NEAR:"near", APT:"aptos", SHIB:"shiba-inu",
  UNI:"uniswap", ATOM:"cosmos", TRX:"tron", OP:"optimism", ARB:"arbitrum",
  SUI:"sui", INJ:"injective-protocol", PEPE:"pepe", WIF:"dogwifcoin", TON:"the-open-network",
  XLM:"stellar", HBAR:"hedera-hashgraph", QNT:"quant-network", AERO:"aerodrome-finance",
  ALGO:"algorand", VET:"vechain", FIL:"filecoin", ICP:"internet-computer",
  RENDER:"render-token", FTM:"fantom", CRO:"crypto-com-chain", LDO:"lido-dao",
  RUNE:"thorchain", SAND:"the-sandbox", MANA:"decentraland", AXS:"axie-infinity",
  GALA:"gala", IMX:"immutable-x", BLUR:"blur", SEI:"sei-network", ONDO:"ondo-finance",
  JUP:"jupiter-exchange-solana", PYTH:"pyth-network", JTO:"jito-governance-token",
  BONK:"bonk", STRK:"starknet", TAO:"bittensor", ETHFI:"ether-fi", ENA:"ethena",
  FLOKI:"floki",
  // Additional tokens added 2026-09
  POL:"polygon-ecosystem-token", PENGU:"pudgy-penguins", TRUMP:"official-trump",
  FARTCOIN:"fartcoin", AI16Z:"ai16z", VIRTUAL:"virtual-protocol",
  POPCAT:"popcat", MEW:"cat-in-a-dogs-world", BRETT:"brett",
  MOG:"mog-coin", NEIRO:"neiro-ethereum", PNUT:"peanut-the-squirrel",
  MORPHO:"morpho", EIGEN:"eigenlayer", SAFE:"safe-token",
  W:"wormhole", JUP2:"jupiter-exchange-solana", PYUSD:"paypal-usd",
  CBBTC:"coinbase-wrapped-btc", WBTC:"wrapped-bitcoin", STETH:"lido-staked-ether",
  USDC:"usd-coin", USDT:"tether",
};

function emailTemplate({ icon, badgeColor, badge, title, bodyHtml, buttonText, buttonColor, buttonTextColor, email }) {
  const unsub = "https://bullruniq.com/api/unsubscribe?email=" + encodeURIComponent(email);
  return "<!doctype html><html><head><meta charset='utf-8'></head><body style='margin:0;background:#050505;padding:40px 24px;font-family:-apple-system,Segoe UI,sans-serif;text-align:center'>"
    + "<div style='font-family:Georgia,serif;font-size:20px;letter-spacing:2px;color:#f0ece4;margin-bottom:24px'>Bullrun<span style='color:#c9a84c'>IQ</span></div>"
    + "<div style='font-size:12px;letter-spacing:2px;text-transform:uppercase;color:" + badgeColor + ";margin-bottom:10px'>" + icon + " " + badge + "</div>"
    + "<div style='font-family:Georgia,serif;font-size:30px;color:#f0ece4;margin-bottom:8px'>" + title + "</div>"
    + bodyHtml
    + "<a href='https://bullruniq.com/platform' style='display:inline-block;background:" + buttonColor + ";color:" + buttonTextColor + ";text-decoration:none;border-radius:4px;padding:14px 32px;font-size:13px;font-weight:600;letter-spacing:1px;text-transform:uppercase'>" + buttonText + "</a>"
    + "<div style='border-top:1px solid #1a1a1a;margin-top:32px;padding-top:16px;font-size:11px;color:#5c574e;line-height:1.6;max-width:420px;margin-left:auto;margin-right:auto'>Educational alert, not financial advice.<br><a href='" + unsub + "' style='color:#8a8278'>Unsubscribe from all emails</a></div>"
    + "</body></html>";
}

function buyAlertHtml(w, price, email) {
  return emailTemplate({
    icon: "🎯", badgeColor: "#4ade80", badge: "Buy zone alert",
    title: esc(w.ticker) + " is at your buy zone",
    bodyHtml: "<div style='color:#8a8278;font-size:15px;line-height:1.7;max-width:400px;margin:0 auto 22px'>"
      + esc(w.name || w.ticker) + " is now <b style='color:#c9a84c'>" + fp(price) + "</b> — within 2% of your target of <b style='color:#c9a84c'>" + fp(w.targetPrice) + "</b>.</div>",
    buttonText: "Open your command center →", buttonColor: "#c9a84c", buttonTextColor: "#000",
    email,
  });
}

function sellAlertHtml(w, price, gainPct, email) {
  const gainLine = gainPct !== null
    ? "<div style='font-size:13px;color:#4ade80;margin-bottom:22px'>Up <b>" + pct(gainPct) + "</b> from your buy target of " + fp(w.targetPrice) + "</div>"
    : "<div style='margin-bottom:22px'></div>";
  return emailTemplate({
    icon: "💰", badgeColor: "#e05555", badge: "Profit-taking signal",
    title: esc(w.ticker) + " hit your sell target",
    bodyHtml: "<div style='color:#8a8278;font-size:15px;line-height:1.7;max-width:400px;margin:0 auto 12px'>"
      + esc(w.name || w.ticker) + " is now <b style='color:#c9a84c'>" + fp(price) + "</b> — reached your profit target of <b style='color:#c9a84c'>" + fp(w.sellTarget) + "</b>.</div>" + gainLine,
    buttonText: "Review your position →", buttonColor: "#e05555", buttonTextColor: "#fff",
    email,
  });
}

function stopAlertHtml(h, price, email) {
  const lossPct = h.avg > 0 ? ((price - h.avg) / h.avg * 100) : null;
  const lossLine = lossPct !== null
    ? "<div style='font-size:13px;color:#e05555;margin-bottom:22px'>Position is at <b>" + pct(lossPct) + "</b> vs your avg buy of " + fp(h.avg) + "</div>"
    : "<div style='margin-bottom:22px'></div>";
  return emailTemplate({
    icon: "⛔", badgeColor: "#e05555", badge: "Stop-loss triggered",
    title: esc(h.ticker) + " fell below your stop",
    bodyHtml: "<div style='color:#8a8278;font-size:15px;line-height:1.7;max-width:400px;margin:0 auto 12px'>"
      + esc(h.name || h.ticker) + " is now <b style='color:#e05555'>" + fp(price) + "</b> — below the stop-loss you set at <b style='color:#c9a84c'>" + fp(h.stop) + "</b>.</div>" + lossLine,
    buttonText: "Review the position now →", buttonColor: "#e05555", buttonTextColor: "#fff",
    email,
  });
}

function tpAlertHtml(h, price, email) {
  const gainPct = h.avg > 0 ? ((price - h.avg) / h.avg * 100) : null;
  const value = price * (h.qty || 0);
  const valueStr = value > 0 ? " Your position is worth <b style='color:#f0ece4'>" + fp(value) + "</b>." : "";
  // Suggest selling 25% at first TP as a partial profit-lock
  const partialQty = h.qty > 0 ? (h.qty * 0.25).toFixed(4) : null;
  const partialNote = partialQty
    ? "<div style='font-size:12px;color:#8a8278;margin-bottom:22px'>Consider locking in gains by selling ~25% (" + partialQty + " " + esc(h.ticker) + ") now and letting the rest ride.</div>"
    : "<div style='margin-bottom:22px'></div>";
  const gainLine = gainPct !== null
    ? "<div style='font-size:13px;color:#4ade80;margin-bottom:8px'>Up <b>" + pct(gainPct) + "</b> from your avg buy of " + fp(h.avg) + "</div>" + partialNote
    : partialNote;
  return emailTemplate({
    icon: "🎯", badgeColor: "#4ade80", badge: "Take-profit reached",
    title: esc(h.ticker) + " hit your target",
    bodyHtml: "<div style='color:#8a8278;font-size:15px;line-height:1.7;max-width:400px;margin:0 auto 12px'>"
      + esc(h.name || h.ticker) + " is now <b style='color:#c9a84c'>" + fp(price) + "</b> — at the take-profit you set at <b style='color:#c9a84c'>" + fp(h.tp) + "</b>." + valueStr + "</div>" + gainLine,
    buttonText: "Take some profit →", buttonColor: "#c9a84c", buttonTextColor: "#000",
    email,
  });
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
  } catch (e) { console.log("[alerts] storage error:", e.message); return { statusCode: 200, body: "storage error" }; }
  if (!users.length) return { statusCode: 200, body: "no users" };

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
            ids.add(CGMAP[String(w.ticker).toUpperCase()] || String(w.ticker).toLowerCase());
          }
        });
        hold.forEach(function (h) {
          if (h && (h.stop || h.tp)) {
            ids.add(CGMAP[String(h.ticker).toUpperCase()] || String(h.ticker).toLowerCase());
          }
        });
      }
    } catch (e) {}
  }
  if (!ids.size) return { statusCode: 200, body: "no targets" };

  // One batched price call
  let prices = {};
  try {
    const r = await fetch("https://api.coingecko.com/api/v3/simple/price?ids=" + [...ids].join(",") + "&vs_currencies=usd");
    prices = await r.json();
  } catch (e) { console.log("[alerts] price fetch failed:", e.message); return { statusCode: 200, body: "price error" }; }

  let sent = 0;
  const FROM = process.env.NEWSLETTER_FROM || "BullrunIQ <brief@bullruniq.com>";

  async function sendEmail(to, subject, html) {
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: "Bearer " + RESEND, "Content-Type": "application/json" },
      body: JSON.stringify({ from: FROM, to, subject, html }),
    });
    if (!r.ok) {
      const err = await r.text().catch(() => r.status);
      console.log("[alerts] resend error for", to, ":", err);
    }
    return r.ok;
  }

  for (const email of Object.keys(recs)) {
    const rec = recs[email];
    let changed = false;

    // ── Portfolio guard: stop-loss / take-profit on actual holdings ──
    const hold = rec.data && rec.data.port && Array.isArray(rec.data.port.crypto) ? rec.data.port.crypto : [];
    for (const h of hold) {
      if (!h || (!h.stop && !h.tp)) continue;
      const id = CGMAP[String(h.ticker).toUpperCase()] || String(h.ticker).toLowerCase();
      const p = prices[id] && prices[id].usd;
      if (!p) continue;

      if (h.stop && p <= h.stop && !h.serverStopAlerted && sent < MAX_EMAILS_PER_RUN) {
        try {
          if (await sendEmail(email, "⛔ " + h.ticker + " fell below your stop-loss — now " + fp(p), stopAlertHtml(h, p, email))) {
            sent++; h.serverStopAlerted = true; changed = true;
            console.log("[alerts] stop", email, h.ticker, "@", p);
          }
        } catch (e) { console.log("[alerts] stop email error:", e.message); }
      } else if (h.stop && p >= h.stop * 1.05 && h.serverStopAlerted) {
        h.serverStopAlerted = false; changed = true;
      }

      if (h.tp && p >= h.tp && !h.serverTpAlerted && sent < MAX_EMAILS_PER_RUN) {
        try {
          if (await sendEmail(email, "🎯 " + h.ticker + " hit your take-profit — now " + fp(p), tpAlertHtml(h, p, email))) {
            sent++; h.serverTpAlerted = true; changed = true;
            console.log("[alerts] tp", email, h.ticker, "@", p);
          }
        } catch (e) { console.log("[alerts] tp email error:", e.message); }
      } else if (h.tp && p < h.tp * 0.95 && h.serverTpAlerted) {
        h.serverTpAlerted = false; changed = true;
      }
    }

    for (const w of (rec.data && rec.data.wl) || []) {
      if (!w) continue;
      const id = CGMAP[String(w.ticker).toUpperCase()] || String(w.ticker).toLowerCase();
      const p = prices[id] && prices[id].usd;
      if (!p) continue;

      // BUY alert: price approaching from above (still above target, within 2%)
      if (w.targetPrice) {
        const dist = (w.targetPrice - p) / p * 100;
        // Only fire when price is still above target (dist > 0) and within 2% of it
        if (dist > 0 && dist < 2 && !w.serverAlerted && sent < MAX_EMAILS_PER_RUN) {
          try {
            if (await sendEmail(email, "🎯 " + w.ticker + " hit your buy zone — now " + fp(p), buyAlertHtml(w, p, email))) {
              sent++; w.serverAlerted = true; changed = true;
              console.log("[alerts] buy", email, w.ticker, "@", p);
            }
          } catch (e) { console.log("[alerts] buy email error:", e.message); }
        } else if (Math.abs(dist) >= 5 && w.serverAlerted) {
          w.serverAlerted = false; changed = true;
        }
      }

      // SELL alert: price at or above the sell target (profit-taking signal)
      if (w.sellTarget && p >= w.sellTarget && !w.serverSellAlerted && sent < MAX_EMAILS_PER_RUN) {
        const gainPct = w.targetPrice ? ((w.sellTarget - w.targetPrice) / w.targetPrice * 100) : null;
        try {
          if (await sendEmail(email, "💰 " + w.ticker + " hit your sell target — now " + fp(p), sellAlertHtml(w, p, gainPct, email))) {
            sent++; w.serverSellAlerted = true; changed = true;
            console.log("[alerts] sell", email, w.ticker, "@", p);
          }
        } catch (e) { console.log("[alerts] sell email error:", e.message); }
      } else if (w.sellTarget && p < w.sellTarget * 0.95 && w.serverSellAlerted) {
        w.serverSellAlerted = false; changed = true;
      }
    }
    if (changed) { try { await store.setJSON(email, rec); } catch (e) {} }
  }
  console.log("[alerts] done —", sent, "email(s) sent across", Object.keys(recs).length, "user(s)");
  return { statusCode: 200, body: "sent " + sent };
};
