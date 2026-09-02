// BullrunIQ — market data proxy (/api/market).

const TTL_MS = 10 * 60000;
const CORS = { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json", "Cache-Control": "public, max-age=120" };
const CG_BASE = "https://api.coingecko.com/api/v3";
const UA = { "User-Agent": "BullrunIQ/1.0 (+https://bullruniq.com)" };
const FETCH_TIMEOUT_MS = 8000;

function fetchWithTimeout(url, opts) {
  const ac = new AbortController();
  const timer = setTimeout(function () { ac.abort(); }, FETCH_TIMEOUT_MS);
  return fetch(url, { ...opts, signal: ac.signal }).finally(function () { clearTimeout(timer); });
}

async function fetchJson(url) {
  const r = await fetchWithTimeout(url, { headers: UA });
  const data = await r.json();
  if (!r.ok) throw new Error("upstream " + r.status);
  return data;
}

exports.handler = async function (event) {
  const q = event.queryStringParameters || {};
  let upstream, key, ttl = TTL_MS, transform;

  if (q.kind === "top50") {
    upstream = CG_BASE + "/coins/markets?vs_currency=usd&order=market_cap_desc&per_page=50&page=1&sparkline=false&price_change_percentage=30d,200d,1y";
    key = "mkt:top50";
  } else if (q.kind === "top100") {
    upstream = CG_BASE + "/coins/markets?vs_currency=usd&order=market_cap_desc&per_page=100&page=1&sparkline=false&price_change_percentage=30d,200d,1y";
    key = "mkt:top100";
  } else if (q.kind === "gainers" || q.kind === "losers") {
    upstream = CG_BASE + "/coins/markets?vs_currency=usd&order=market_cap_desc&per_page=250&page=1&sparkline=false&price_change_percentage=24h";
    key = "mkt:top250";
    const isGainers = q.kind === "gainers";
    transform = function (data) {
      if (!Array.isArray(data)) return data;
      return data
        .filter(function (c) { return c.price_change_percentage_24h != null; })
        .sort(function (a, b) {
          return isGainers
            ? b.price_change_percentage_24h - a.price_change_percentage_24h
            : a.price_change_percentage_24h - b.price_change_percentage_24h;
        })
        .slice(0, 20);
    };
  } else if (q.kind === "trending") {
    upstream = CG_BASE + "/search/trending";
    key = "mkt:trending";
    ttl = 30 * 60000;
    transform = function (data) {
      const coins = (data && data.coins) || [];
      return coins.slice(0, 15).map(function (c) {
        const i = c.item || {};
        return { id: i.id, symbol: (i.symbol || "").toUpperCase(), name: i.name, market_cap_rank: i.market_cap_rank, thumb: i.thumb, price_btc: i.price_btc, score: i.score };
      });
    };
  } else if (q.kind === "global") {
    // Total crypto market cap, BTC dominance, and ETH dominance — useful for cycle timing.
    upstream = CG_BASE + "/global";
    key = "mkt:global";
    ttl = 15 * 60000;
    transform = function (data) {
      const d = (data && data.data) || {};
      return {
        total_market_cap_usd: d.total_market_cap && d.total_market_cap.usd,
        total_volume_24h_usd: d.total_volume && d.total_volume.usd,
        btc_dominance: d.market_cap_percentage && d.market_cap_percentage.btc,
        eth_dominance: d.market_cap_percentage && d.market_cap_percentage.eth,
        active_cryptocurrencies: d.active_cryptocurrencies,
        market_cap_change_percentage_24h: d.market_cap_change_percentage_24h_usd,
        updated_at: d.updated_at,
      };
    };
  } else if (q.kind === "fear") {
    // Fear & Greed index (0–100) from alternative.me — cycle sentiment indicator.
    upstream = "https://api.alternative.me/fng/?limit=7";
    key = "mkt:fear";
    ttl = 30 * 60000;
    transform = function (data) {
      const entries = (data && data.data) || [];
      return entries.map(function (e) {
        return { value: parseInt(e.value, 10), label: e.value_classification, timestamp: e.timestamp };
      });
    };
  } else if (q.ids) {
    const ids = String(q.ids).toLowerCase().split(",")
      .map(function (s) { return s.trim(); })
      .filter(function (s) { return /^[a-z0-9-]{1,50}$/.test(s); })
      .slice(0, 25);
    if (!ids.length) return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: "no valid ids" }) };
    upstream = CG_BASE + "/coins/markets?vs_currency=usd&ids=" + ids.join(",") + "&sparkline=false&price_change_percentage=30d,200d,1y";
    key = "mkt:ids:" + ids.sort().join(",");
  } else {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: "pass kind=top50|top100|gainers|losers|trending|global|fear or ids=..." }) };
  }

  const blobs = require("@netlify/blobs");
  try { blobs.connectLambda(event); } catch (e) {}
  let cache = null;
  try { cache = blobs.getStore("cache"); } catch (e) {}

  if (cache) {
    try {
      const c = await cache.get(key, { type: "json" });
      if (c && Date.now() - c.at < ttl) {
        const payload = transform ? transform(c.data) : c.data;
        return { statusCode: 200, headers: CORS, body: JSON.stringify(payload) };
      }
    } catch (e) {}
  }

  try {
    const data = await fetchJson(upstream);
    if (cache) { try { await cache.setJSON(key, { at: Date.now(), data: data }); } catch (e) {} }
    const payload = transform ? transform(data) : data;
    return { statusCode: 200, headers: CORS, body: JSON.stringify(payload) };
  } catch (err) {
    if (cache) {
      try {
        const c = await cache.get(key, { type: "json" });
        if (c) {
          const payload = transform ? transform(c.data) : c.data;
          return { statusCode: 200, headers: CORS, body: JSON.stringify(payload) };
        }
      } catch (e) {}
    }
    return { statusCode: 502, headers: CORS, body: JSON.stringify({ error: "market data unavailable" }) };
  }
};
