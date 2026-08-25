// BullrunIQ — server-side price alerts (scheduled).

const MAX_EMAILS_PER_RUN = 20;

const CGMAP = { BTC:"bitcoin", ETH:"ethereum", SOL:"solana", BNB:"binancecoin", XRP:"ripple", ADA:"cardano", DOGE:"dogecoin", AVAX:"avalanche-2", DOT:"polkadot", MATIC:"matic-network", LINK:"chainlink", LTC:"litecoin", NEAR:"near", APT:"aptos", SHIB:"shiba-inu", UNI:"uniswap", ATOM:"cosmos", TRX:"tron", OP:"optimism", ARB:"arbitrum", SUI:"sui", INJ:"injective-protocol", PEPE:"pepe", WIF:"dogwifcoin", TON:"the-open-network", XLM:"stellar", HBAR:"hedera-hashgraph", QNT:"quant-network", AERO:"aerodrome-finance", ALGO:"algorand", VET:"vechain", FIL:"filecoin", ICP:"internet-computer", RENDER:"render-token", FTM:"fantom", CRO:"crypto-com-chain", LDO:"lido-dao", RUNE:"thorchain", SAND:"the-sandbox", MANA:"decentraland", AXS:"axie-infinity", GALA:"gala", IMX:"immutable-x", BLUR:"blur", SEI:"sei-network", ONDO:"ondo-finance", JUP:"jupiter-exchange-solana", PYTH:"pyth-network", JTO:"jito-governance-token", BONK:"bonk", STRK:"starknet", TAO:"bittensor", ETHFI:"ether-fi", ENA:"ethena", FLOKI:"floki" };

function fp(v) { return v >= 1000 ? "$" + v.toLocaleString("en-US", { maximumFractionDigits: 2 }) : v >= 1 ? "$" + v.toFixed(2) : "$" + v.toFixed(6); }
function pct(v) { return (v >= 0 ? "+" : "") + v.toFixed(1) + "%"; }
function esc(s) { return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }

function buyAlertHtml(w, price, email) {
  const name = esc(w.name || w.ticker);
  const ticker = esc(w.ticker);
  return "<!doctype html><html><head><meta charset='utf-8'></head><body style='margin:0;background:#050505;padding:40px 24px;font-family:-apple-system,Segoe UI,sans-serif;text-align:center'>"
    + "<div style='font-family:Georgia,serif;font-size:20px;letter-spacing:2px;color:#f0ece4;margin-bottom:24px'>Bullrun<span style='color:#c9a84c'>IQ</span></div>"
    + "<div style='font-size:12px;letter-spacing:2px;text-transform:uppercase;color:#4ade80;margin-bottom:10px'>🎯 Buy zone alert</div>"
    + "<div style='font-family:Georgia,serif;font-size:30px;color:#f0ece4;margin-bottom:8px'>" + ticker + " is at your buy zone</div>"
    + "<div style='color:#8a8278;font-size:15px;line-height:1.7;max-width:400px;margin:0 auto 22px'>" + name + " is now <b style='color:#c9a84c'>" + fp(price) + "</b> — within 2% of your target of <b style='color:#c9a84c'>" + fp(w.targetPrice) + "</b>.</div>"
    + "<a href='https://bullruniq.com/platform' style='display:inline-block;background:#c9a84c;color:#000;text-decoration:none;border-radius:4px;padding:14px 32px;font-size:13px;font-weight:600;letter-spacing:1px;text-transform:uppercase'>Open your command center →</a>"
    + "<div style='border-top:1px solid #1a1a1a;margin-top:32px;padding-top:16px;font-size:11px;color:#5c574e;line-height:1.6;max-width:420px;margin-left:auto;margin-right:auto'>Educational alert, not financial advice.<br><a href='https://bullruniq.com/api/unsubscribe?email=" + encodeURIComponent(email) + "' style='color:#8a8278'>Unsubscribe from all emails</a></div>"
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
    + "<div style='border-top:1px solid #1a1a1a;margin-top:32px;padding-top:16px;font-size:11px;color:#5c574e;line-height:1.6;max-width:420px;margin-left:auto;margin-right:auto'>Educational alert, not financial advice.<br><a href='https://bullruniq.com/api/unsubscribe?email=" + encodeURIComponent(email) + "' style='color:#8a8278'>Unsubscribe from all emails</a></div>"
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
  } catch (e) { console.log("[alerts] storage error:", e.message); return { statusCode: 200, body: "storage error" }; }
  if (!users.length) return { statusCode: 200, body: "no users" };

  const recs = {};
  const ids = new Set();
  for (const email of users) {
    try {
      const rec = await store.get(email, { type: "json" });
      const wlist = rec && rec.data && Array.isArray(rec.data.wl) ? rec.data.wl : [];
      if (wlist.some(function (w) { return w && (w.targetPrice || w.sellTarget); })) {
        recs[email] = rec;
        wlist.forEach(function (w) {
          if (w && (w.targetPrice || w.sellTarget)) {
            ids.add(CGMAP[String(w.ticker).toUpperCase()] || String(w.ticker).toLowerCase());
          }
        });
      }
    } catch (e) {}
  }
  if (!ids.size) return { statusCode: 200, body: "no targets" };

  let prices = {};
  try {
    const r = await fetch("https://api.coingecko.com/api/v3/simple/price?ids=" + [...ids].join(",") + "&vs_currencies=usd");
    prices = await r.json();
  } catch (e) { console.log("[alerts] price fetch failed:", e.message); return { statusCode: 200, body: "price error" }; }

  let sent = 0;
  for (const email of Object.keys(recs)) {
    const rec = recs[email];
    let changed = false;
    for (const w of rec.data.wl) {
      if (!w) continue;
      const id = CGMAP[String(w.ticker).toUpperCase()] || String(w.ticker).toLowerCase();
      const p = prices[id] && prices[id].usd;
      if (!p) continue;

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
            if (r.ok) { sent++; w.serverAlerted = true; changed = true; }
          } catch (e) {}
        } else if (dist >= 5 && w.serverAlerted) {
          w.serverAlerted = false; changed = true;
        }
      }

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
          if (r.ok) { sent++; w.serverSellAlerted = true; changed = true; }
        } catch (e) {}
      } else if (w.sellTarget && p < w.sellTarget * 0.95 && w.serverSellAlerted) {
        w.serverSellAlerted = false; changed = true;
      }
    }
    if (changed) { try { await store.setJSON(email, rec); } catch (e) {} }
  }
  console.log("[alerts] done — " + sent + " email(s) sent");
  return { statusCode: 200, body: "sent " + sent };
};
