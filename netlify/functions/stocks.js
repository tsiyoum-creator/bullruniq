// BullrunIQ — real-time stock quote proxy (/api/stocks).
//
// Serves live US equity quotes from Finnhub using a SERVER-held key, so every
// user gets real-time prices without supplying their own. This exists because
// the client-side fallback (Alpha Vantage free tier) is 15-20 minutes delayed
// and capped at 25 requests/day — past that cap it silently returns nothing and
// the UI keeps showing a stale price with no indication it has gone cold.
//
//   GET /api/stocks?symbols=IREN,AAPL
//     → { configured: true, quotes: { IREN: { price, change24, at, src, ... } } }
//
// When FINNHUB_API_KEY is unset the handler returns { configured: false } and an
// empty quote set, which tells the client to fall back to the user's own keys.

const TTL_MS = 60000; // Finnhub free tier is real-time; 60s cache is plenty
const MAX_SYMBOLS = 25;
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Content-Type": "application/json",
  "Cache-Control": "public, max-age=30",
};

// Tickers are uppercase alnum with optional dot/hyphen (BRK.B, RDS-A).
// Anything else is dropped rather than forwarded upstream.
function validateSymbols(raw) {
  const seen = new Set();
  return String(raw || "").toUpperCase().split(",")
    .map(function (s) { return s.trim(); })
    .filter(function (s) { return /^[A-Z][A-Z0-9.\-]{0,9}$/.test(s); })
    .filter(function (s) { if (seen.has(s)) return false; seen.add(s); return true; })
    .slice(0, MAX_SYMBOLS);
}

// Finnhub /quote → { c: current, d: change, dp: pct, h, l, o, pc: prevClose, t }
// c === 0 means "no data for this symbol" (unknown ticker, or non-US listing).
function normalizeQuote(d, symbol) {
  if (!d || typeof d.c !== "number" || !(d.c > 0)) return null;
  const pct = typeof d.dp === "number" && isFinite(d.dp)
    ? d.dp
    : (d.pc > 0 ? (d.c - d.pc) / d.pc * 100 : 0);
  return {
    symbol: symbol,
    price: d.c,
    change24: +pct.toFixed(2),
    open: d.o, high: d.h, low: d.l, prevClose: d.pc,
    at: Date.now(),
    src: "finnhub",
  };
}

function json(code, obj) {
  return { statusCode: code, headers: CORS, body: JSON.stringify(obj) };
}

exports.handler = async function (event) {
  const KEY = process.env.FINNHUB_API_KEY;
  const symbols = validateSymbols((event.queryStringParameters || {}).symbols);

  if (!symbols.length) return json(400, { error: "pass symbols=AAPL,IREN" });
  // No server key → tell the client to use its own. Not an error.
  if (!KEY) return json(200, { configured: false, quotes: {} });

  const blobs = require("@netlify/blobs");
  try { blobs.connectLambda(event); } catch (e) {}
  let cache = null;
  try { cache = blobs.getStore("cache"); } catch (e) {}

  const quotes = {};
  const misses = [];

  // Serve what we can from cache first — quotes are shared across all users.
  if (cache) {
    await Promise.allSettled(symbols.map(async function (sym) {
      try {
        const c = await cache.get("stk:" + sym, { type: "json" });
        if (c && c.at && Date.now() - c.at < TTL_MS) quotes[sym] = c;
        else misses.push(sym);
      } catch (e) { misses.push(sym); }
    }));
  } else {
    misses.push.apply(misses, symbols);
  }

  if (!misses.length) return json(200, { configured: true, quotes: quotes });

  // Fetch the rest in parallel. Finnhub free allows 60 req/min and MAX_SYMBOLS
  // caps a single request at 25, so one burst stays inside the limit.
  await Promise.allSettled(misses.map(async function (sym) {
    try {
      const r = await fetch(
        "https://finnhub.io/api/v1/quote?symbol=" + encodeURIComponent(sym) + "&token=" + encodeURIComponent(KEY),
        { headers: { "User-Agent": "BullrunIQ/1.0 (+https://bullruniq.com)" } }
      );
      if (!r.ok) {
        console.log("[stocks] " + sym + " upstream " + r.status);
        return;
      }
      const q = normalizeQuote(await r.json(), sym);
      if (!q) return;
      quotes[sym] = q;
      if (cache) { try { await cache.setJSON("stk:" + sym, q); } catch (e) {} }
    } catch (e) {
      console.log("[stocks] " + sym + " fetch failed: " + e.message);
    }
  }));

  return json(200, { configured: true, quotes: quotes });
};
