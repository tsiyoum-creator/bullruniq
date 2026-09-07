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

const { esc, fp, pct, emailLayout } = require("./lib/utils");

const MAX_EMAILS_PER_RUN = 20; // stay well inside Resend free tier

const CGMAP = { BTC:"bitcoin", ETH:"ethereum", SOL:"solana", BNB:"binancecoin", XRP:"ripple", ADA:"cardano", DOGE:"dogecoin", AVAX:"avalanche-2", DOT:"polkadot", MATIC:"matic-network", LINK:"chainlink", LTC:"litecoin", NEAR:"near", APT:"aptos", SHIB:"shiba-inu", UNI:"uniswap", ATOM:"cosmos", TRX:"tron", OP:"optimism", ARB:"arbitrum", SUI:"sui", INJ:"injective-protocol", PEPE:"pepe", WIF:"dogwifcoin", TON:"the-open-network", XLM:"stellar", HBAR:"hedera-hashgraph", QNT:"quant-network", AERO:"aerodrome-finance", ALGO:"algorand", VET:"vechain", FIL:"filecoin", ICP:"internet-computer", RENDER:"render-token", FTM:"fantom", CRO:"crypto-com-chain", LDO:"lido-dao", RUNE:"thorchain", SAND:"the-sandbox", MANA:"decentraland", AXS:"axie-infinity", GALA:"gala", IMX:"immutable-x", BLUR:"blur", SEI:"sei-network", ONDO:"ondo-finance", JUP:"jupiter-exchange-solana", PYTH:"pyth-network", JTO:"jito-governance-token", BONK:"bonk", STRK:"starknet", TAO:"bittensor", ETHFI:"ether-fi", ENA:"ethena", FLOKI:"floki" };

function buyAlertHtml(w, price, email) {
  const name = esc(w.name || w.ticker);
  const ticker = esc(w.ticker);
  const safeBody = "<div style='color:#8a8278;font-size:15px;line-height:1.7;max-width:400px;margin:0 auto 22px'>"
    + name + " is now <b style='color:#c9a84c'>" + fp(price) + "</b>"
    + " — within 2% of your target of <b style='color:#c9a84c'>" + fp(w.targetPrice) + "</b>."
    + "</div>";
  return emailLayout({
    badge: "🎯 Buy zone alert", badgeColor: "#4ade80",
    safeTitle: ticker + " is at your buy zone",
    safeBody,
    ctaLabel: "Open your command center →",
    reason: "you set a price target in BullrunIQ",
    email,
  });
}

function sellAlertHtml(w, price, gainPct, email) {
  const name = esc(w.name || w.ticker);
  const ticker = esc(w.ticker);
  const gainLine = gainPct !== null
    ? "<div style='font-size:13px;color:#4ade80;margin-bottom:22px'>Up <b>" + pct(gainPct) + "</b> from your buy target of " + fp(w.targetPrice) + "</div>"
    : "<div style='margin-bottom:22px'></div>";
  const safeBody = "<div style='color:#8a8278;font-size:15px;line-height:1.7;max-width:400px;margin:0 auto 12px'>"
    + name + " is now <b style='color:#c9a84c'>" + fp(price) + "</b>"
    + " — reached your profit target of <b style='color:#c9a84c'>" + fp(w.sellTarget) + "</b>."
    + "</div>" + gainLine;
  return emailLayout({
    badge: "💰 Profit-taking signal", badgeColor: "#e05555",
    safeTitle: ticker + " hit your sell target",
    safeBody,
    ctaLabel: "Review your position →", ctaBg: "#e05555", ctaFg: "#fff",
    reason: "you set a sell target in BullrunIQ",
    email,
  });
}

function stopAlertHtml(h, price, email) {
  const name = esc(h.name || h.ticker);
  const ticker = esc(h.ticker);
  const lossPct = h.avg > 0 ? ((price - h.avg) / h.avg * 100) : null;
  const lossLine = lossPct !== null
    ? "<div style='font-size:13px;color:#e05555;margin-bottom:22px'>Position is at <b>" + pct(lossPct) + "</b> vs your avg buy of " + fp(h.avg) + "</div>"
    : "<div style='margin-bottom:22px'></div>";
  const safeBody = "<div style='color:#8a8278;font-size:15px;line-height:1.7;max-width:400px;margin:0 auto 12px'>"
    + name + " is now <b style='color:#e05555'>" + fp(price) + "</b>"
    + " — below the stop-loss you set at <b style='color:#c9a84c'>" + fp(h.stop) + "</b>."
    + "</div>" + lossLine;
  return emailLayout({
    badge: "⛔ Stop-loss triggered", badgeColor: "#e05555",
    safeTitle: ticker + " fell below your stop",
    safeBody,
    ctaLabel: "Review the position now →", ctaBg: "#e05555", ctaFg: "#fff",
    reason: "you set a stop-loss in BullrunIQ",
    email,
  });
}

function tpAlertHtml(h, price, email) {
  const name = esc(h.name || h.ticker);
  const ticker = esc(h.ticker);
  const gainPct = h.avg > 0 ? ((price - h.avg) / h.avg * 100) : null;
  const value = price * (h.qty || 0);
  // Suggest a staged exit: sell 25–33% here, keep the rest for higher targets.
  const ladderSuggestion = gainPct !== null && gainPct >= 50
    ? " Consider taking 25–33% off the table now and letting the rest ride with a raised stop."
    : " Consider locking in some gains.";
  const gainLine = gainPct !== null
    ? "<div style='font-size:13px;color:#4ade80;margin-bottom:22px'>Up <b>" + pct(gainPct) + "</b> from your avg buy of " + fp(h.avg) + " —" + esc(ladderSuggestion) + "</div>"
    : "<div style='margin-bottom:22px'></div>";
  const valueLine = value > 0 ? " Your position is worth <b style='color:#f0ece4'>" + fp(value) + "</b>." : "";
  const safeBody = "<div style='color:#8a8278;font-size:15px;line-height:1.7;max-width:400px;margin:0 auto 12px'>"
    + name + " is now <b style='color:#c9a84c'>" + fp(price) + "</b>"
    + " — at the take-profit you set at <b style='color:#c9a84c'>" + fp(h.tp) + "</b>." + valueLine
    + "</div>" + gainLine;
  return emailLayout({
    badge: "🎯 Take-profit reached", badgeColor: "#4ade80",
    safeTitle: ticker + " hit your target",
    safeBody,
    ctaLabel: "Take some profit →",
    reason: "you set a take-profit in BullrunIQ",
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

  // Load each user's state; collect crypto tickers that have any target
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
            const cgId = CGMAP[String(w.ticker).toUpperCase()];
            if (cgId) ids.add(cgId); // only add if we have a known mapping
          }
        });
        hold.forEach(function (h) {
          if (h && (h.stop || h.tp)) {
            const cgId = CGMAP[String(h.ticker).toUpperCase()];
            if (cgId) ids.add(cgId);
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
  for (const email of Object.keys(recs)) {
    const rec = recs[email];
    let changed = false;

    // ── Portfolio guard: stop-loss / take-profit on actual holdings ──
    const hold = rec.data.port && Array.isArray(rec.data.port.crypto) ? rec.data.port.crypto : [];
    for (const h of hold) {
      if (!h || (!h.stop && !h.tp)) continue;
      const id = CGMAP[String(h.ticker).toUpperCase()];
      if (!id) continue; // skip tickers not in CGMAP — no price available
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
          if (r.ok) { sent++; h.serverStopAlerted = true; changed = true; console.log("[alerts] stop " + email + " " + h.ticker + " @ " + p); }
        } catch (e) {}
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
          if (r.ok) { sent++; h.serverTpAlerted = true; changed = true; console.log("[alerts] tp " + email + " " + h.ticker + " @ " + p); }
        } catch (e) {}
      } else if (h.tp && p < h.tp * 0.95 && h.serverTpAlerted) {
        h.serverTpAlerted = false; changed = true; // re-arm once price retraces 5% below the target
      }
    }

    for (const w of rec.data.wl || []) {
      if (!w) continue;
      const id = CGMAP[String(w.ticker).toUpperCase()];
      if (!id) continue; // skip tickers not in CGMAP — no price available
      const p = prices[id] && prices[id].usd;
      if (!p) continue;

      // BUY alert: price within 2% below the buy target (approaching from above)
      if (w.targetPrice) {
        const dist = Math.abs((w.targetPrice - p) / p * 100);
        if (dist < 2 && p <= w.targetPrice * 1.02 && !w.serverAlerted && sent < MAX_EMAILS_PER_RUN) {
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
            if (r.ok) { sent++; w.serverAlerted = true; changed = true; console.log("[alerts] buy " + email + " " + w.ticker + " @ " + p); }
          } catch (e) {}
        } else if (dist >= 5 && w.serverAlerted) {
          w.serverAlerted = false; changed = true; // re-arm once price moves away
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
          if (r.ok) { sent++; w.serverSellAlerted = true; changed = true; console.log("[alerts] sell " + email + " " + w.ticker + " @ " + p); }
        } catch (e) {}
      } else if (w.sellTarget && p < w.sellTarget * 0.95 && w.serverSellAlerted) {
        w.serverSellAlerted = false; changed = true; // re-arm once price retraces 5%
      }
    }
    if (changed) { try { await store.setJSON(email, rec); } catch (e) {} }
  }
  console.log("[alerts] done — " + sent + " email(s) sent across " + Object.keys(recs).length + " user(s)");
  return { statusCode: 200, body: "sent " + sent };
};
