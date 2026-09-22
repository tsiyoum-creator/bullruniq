// BullrunIQ — market data proxy (/api/market).

const TTL_MS = 10 * 60000;
const CORS = { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json", "Cache-Control": "public, max-age=120" };
const CG_BASE = "https://api.coingecko.com/api/v3";
const UA = { "User-Agent": "BullrunIQ/1.0 (+https://bullruniq.com)" };

async function fetchJson(url, headers) {
  const r = await fetch(url, { headers: headers || UA });
  if (!r.ok) throw new Error("upstream " + r.status);
  return r.json();
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
  } else if (q.kind === "fear_greed") {
    // Fear & Greed index + BTC dominance snapshot for dashboard widgets
    upstream = "https://api.alternative.me/fng/?limit=7";
    key = "mkt:fear_greed";
    ttl = 60 * 60000; // hourly — index updates once per day
    transform = function (data) {
      if (!data || !Array.isArray(data.data)) return data;
      return {
        current: data.data[0],
        history: data.data,
      };
    };
  } else if (q.kind === "dominance") {
    upstream = CG_BASE + "/global";
    key = "mkt:dominance";
    ttl = 30 * 60000;
    transform = function (data) {
      const d = (data && data.data) || {};
      return {
        btc_dominance: d.market_cap_percentage && d.market_cap_percentage.btc,
        eth_dominance: d.market_cap_percentage && d.market_cap_percentage.eth,
        total_market_cap_usd: d.total_market_cap && d.total_market_cap.usd,
        total_volume_24h_usd: d.total_volume && d.total_volume.usd,
        active_cryptocurrencies: d.active_cryptocurrencies,
        updated_at: d.updated_at,
      };
    };
  } else if (q.kind === "sectors") {
    // Sector rotation snapshot: representative tokens for major crypto sectors
    const SECTOR_IDS = [
      // Layer 1s
      "bitcoin", "ethereum", "solana", "avalanche-2", "near", "aptos", "sui",
      // Layer 2s / scaling
      "arbitrum", "optimism", "zksync", "starknet",
      // DeFi
      "uniswap", "aave", "curve-dao-token", "maker", "pendle",
      // AI
      "bittensor", "render-token",
      // Memes
      "dogecoin", "shiba-inu", "dogwifcoin", "pepe",
      // Infrastructure
      "chainlink", "the-graph", "pyth-network",
    ].join(",");
    upstream = CG_BASE + "/coins/markets?vs_currency=usd&ids=" + SECTOR_IDS + "&sparkline=false&price_change_percentage=7d,30d";
    key = "mkt:sectors";
    ttl = 15 * 60000;
    transform = function (data) {
      if (!Array.isArray(data)) return data;
      const sectors = {
        layer1: { label: "Layer 1", coins: [] },
        layer2: { label: "Layer 2 / Scaling", coins: [] },
        defi: { label: "DeFi", coins: [] },
        ai: { label: "AI & Compute", coins: [] },
        meme: { label: "Meme", coins: [] },
        infra: { label: "Infrastructure", coins: [] },
      };
      const SECTOR_MAP = {
        "bitcoin": "layer1", "ethereum": "layer1", "solana": "layer1", "avalanche-2": "layer1",
        "near": "layer1", "aptos": "layer1", "sui": "layer1",
        "arbitrum": "layer2", "optimism": "layer2", "zksync": "layer2", "starknet": "layer2",
        "uniswap": "defi", "aave": "defi", "curve-dao-token": "defi", "maker": "defi", "pendle": "defi",
        "bittensor": "ai", "render-token": "ai",
        "dogecoin": "meme", "shiba-inu": "meme", "dogwifcoin": "meme", "pepe": "meme",
        "chainlink": "infra", "the-graph": "infra", "pyth-network": "infra",
      };
      data.forEach(function (c) {
        const sectorKey = SECTOR_MAP[c.id] || "layer1";
        if (sectors[sectorKey]) {
          sectors[sectorKey].coins.push({
            id: c.id, symbol: (c.symbol || "").toUpperCase(), name: c.name,
            price: c.current_price,
            change7d: c.price_change_percentage_7d_in_currency,
            change30d: c.price_change_percentage_30d_in_currency,
            marketCap: c.market_cap,
          });
        }
      });
      return Object.fromEntries(
        Object.entries(sectors).map(function ([k, v]) {
          const avg7d = v.coins.length
            ? v.coins.reduce(function (s, c) { return s + (c.change7d || 0); }, 0) / v.coins.length
            : null;
          const avg30d = v.coins.length
            ? v.coins.reduce(function (s, c) { return s + (c.change30d || 0); }, 0) / v.coins.length
            : null;
          return [k, { ...v, avg7d: avg7d, avg30d: avg30d }];
        })
      );
    };
  } else if (q.kind === "ath_nearby") {
    // Coins trading within 20% of their all-time high — key distribution zone during a bull run.
    // A coin in this band has historically been a profit-taking signal; approaching ATH with volume
    // is the strongest short-term sell trigger tracked by this app.
    upstream = CG_BASE + "/coins/markets?vs_currency=usd&order=market_cap_desc&per_page=250&page=1&sparkline=false&price_change_percentage=30d";
    key = "mkt:top250_ath";
    ttl = 15 * 60000;
    transform = function (data) {
      if (!Array.isArray(data)) return data;
      return data
        .filter(function (c) {
          // ath_change_percentage is ≤ 0 (e.g. -15 means 15% below ATH)
          return typeof c.ath_change_percentage === "number" && c.ath_change_percentage >= -20;
        })
        .map(function (c) {
          return {
            id: c.id,
            symbol: (c.symbol || "").toUpperCase(),
            name: c.name,
            price: c.current_price,
            ath: c.ath,
            ath_change_pct: c.ath_change_percentage,
            market_cap: c.market_cap,
            change_30d: c.price_change_percentage_30d_in_currency,
          };
        })
        .sort(function (a, b) { return b.ath_change_pct - a.ath_change_pct; });
    };
  } else if (q.kind === "volume_leaders") {
    // Volume leaders: tokens with the highest 24h volume / market cap ratio.
    // A spike here (>50%) often precedes a large directional move.
    upstream = CG_BASE + "/coins/markets?vs_currency=usd&order=market_cap_desc&per_page=250&page=1&sparkline=false&price_change_percentage=24h";
    key = "mkt:top250";
    transform = function (data) {
      if (!Array.isArray(data)) return data;
      return data
        .filter(function (c) { return c.market_cap > 0 && c.total_volume > 0; })
        .map(function (c) {
          return {
            id: c.id,
            symbol: (c.symbol || "").toUpperCase(),
            name: c.name,
            price: c.current_price,
            market_cap: c.market_cap,
            volume_24h: c.total_volume,
            volume_mcap_ratio: c.total_volume / c.market_cap,
            change_24h: c.price_change_percentage_24h,
          };
        })
        .sort(function (a, b) { return b.volume_mcap_ratio - a.volume_mcap_ratio; })
        .slice(0, 20);
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
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: "pass kind=top50|top100|gainers|losers|trending|fear_greed|dominance|sectors|volume_leaders|ath_nearby or ids=..." }) };
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

  // fear_greed uses alternative.me which doesn't need auth headers
  const fetchHeaders = (q.kind === "fear_greed") ? {} : UA;

  try {
    const data = await fetchJson(upstream, fetchHeaders);
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
