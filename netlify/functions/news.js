// BullrunIQ — market news feed (/api/news).

const TTL_MS = 15 * 60000;
const CORS = { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json", "Cache-Control": "public, max-age=300" };

function decodeEntities(s) {
  return String(s)
    .replace(/<!\[CDATA\[|\]\]>/g, "")
    .replace(/&#(\d+);/g, function (_, n) { return String.fromCharCode(+n); })
    .replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#039;|&apos;/g, "'")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&nbsp;/g, " ").trim();
}
function parseRss(xml, source) {
  const items = [];
  const chunks = String(xml).split(/<item[\s>]/).slice(1, 12);
  for (const c of chunks) {
    const t = (c.match(/<title>([\s\S]*?)<\/title>/) || [])[1];
    const l = (c.match(/<link>([\s\S]*?)<\/link>/) || [])[1];
    const d = (c.match(/<pubDate>([\s\S]*?)<\/pubDate>/) || [])[1];
    if (t && l) {
      const at = d ? new Date(d).getTime() : Date.now();
      const url = decodeEntities(l);
      if (!/^https?:\/\//i.test(url)) continue;
      items.push({ t: decodeEntities(t).slice(0, 160), u: url, s: source, at: isNaN(at) ? Date.now() : at });
    }
  }
  return items;
}
async function fetchFeed(url, source) {
  try {
    const r = await fetch(url, { headers: { "User-Agent": "BullrunIQ/1.0 (+https://bullruniq.com)" } });
    if (!r.ok) return [];
    return parseRss(await r.text(), source);
  } catch (e) { return []; }
}

// Score a headline against a set of ticker strings. Returns the count of matches (0 = no match).
function scoreByTickers(title, tickers) {
  const lower = title.toLowerCase();
  return tickers.reduce(function (n, tk) { return n + (lower.includes(tk.toLowerCase()) ? 1 : 0); }, 0);
}

exports.handler = async function (event) {
  const blobs = require("@netlify/blobs");
  try { blobs.connectLambda(event); } catch (e) {}
  let cache = null;
  try { cache = blobs.getStore("cache"); } catch (e) {}

  // Optional ?tickers=BTC,ETH,SOL — filters/re-ranks by portfolio relevance.
  // Only alphanumeric + dot/hyphen tickers accepted to prevent injection.
  const qp = (event.queryStringParameters || {});
  const rawTickers = qp.tickers ? String(qp.tickers).slice(0, 200) : "";
  const tickers = rawTickers
    ? rawTickers.split(",").map(function (t) { return t.trim(); }).filter(function (t) { return /^[A-Za-z0-9._-]{1,20}$/.test(t); })
    : [];

  if (cache) {
    try {
      const c = await cache.get("news", { type: "json" });
      if (c && Date.now() - c.fetchedAt < TTL_MS) {
        const items = tickers.length ? rankByTickers(c.items, tickers) : c.items;
        return { statusCode: 200, headers: CORS, body: JSON.stringify({ items, cached: true }) };
      }
    } catch (e) {}
  }

  const results = await Promise.allSettled([
    fetchFeed("https://www.coindesk.com/arc/outboundfeeds/rss/", "CoinDesk"),
    fetchFeed("https://cointelegraph.com/rss", "Cointelegraph"),
    fetchFeed("https://thedefiant.io/feed", "The Defiant"),
    fetchFeed("https://decrypt.co/feed", "Decrypt"),
    fetchFeed("https://cryptoslate.com/feed/", "CryptoSlate"),
  ]);
  const seen = new Set();
  let items = results.filter(function (r) { return r.status === "fulfilled"; })
    .flatMap(function (r) { return r.value; })
    .sort(function (a, b) { return b.at - a.at; })
    .filter(function (item) { if (seen.has(item.u)) return false; seen.add(item.u); return true; })
    .slice(0, 40);

  if (!items.length && cache) {
    try {
      const c = await cache.get("news", { type: "json" });
      if (c) {
        const staleItems = tickers.length ? rankByTickers(c.items, tickers) : c.items;
        return { statusCode: 200, headers: CORS, body: JSON.stringify({ items: staleItems, stale: true }) };
      }
    } catch (e) {}
  }

  if (items.length && cache) {
    try { await cache.setJSON("news", { items: items, fetchedAt: Date.now() }); } catch (e) {}
  }

  const finalItems = tickers.length ? rankByTickers(items, tickers) : items.slice(0, 20);
  return { statusCode: 200, headers: CORS, body: JSON.stringify({ items: finalItems }) };
};

// Re-sort items so ticker-matched headlines bubble to the top, preserving recency within each tier.
function rankByTickers(items, tickers) {
  const scored = items.map(function (item) {
    return { item, score: scoreByTickers(item.t, tickers) };
  });
  scored.sort(function (a, b) {
    if (b.score !== a.score) return b.score - a.score;
    return b.item.at - a.item.at;
  });
  return scored.slice(0, 20).map(function (x) { return x.item; });
}
