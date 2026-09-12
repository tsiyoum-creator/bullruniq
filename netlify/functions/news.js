// BullrunIQ — market news feed (/api/news).

const TTL_MS = 15 * 60000;
const CORS = { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json", "Cache-Control": "public, max-age=300" };

const FEEDS = [
  { url: "https://www.coindesk.com/arc/outboundfeeds/rss/", source: "CoinDesk" },
  { url: "https://cointelegraph.com/rss", source: "Cointelegraph" },
  { url: "https://decrypt.co/feed", source: "Decrypt" },
  { url: "https://bitcoinmagazine.com/.rss/full/", source: "Bitcoin Magazine" },
];

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
    const desc = (c.match(/<description>([\s\S]*?)<\/description>/) || [])[1];
    if (t && l) {
      const at = d ? new Date(d).getTime() : Date.now();
      const url = decodeEntities(l).trim();
      if (!/^https?:\/\//i.test(url)) continue;
      const snippet = desc
        ? decodeEntities(desc).replace(/<[^>]+>/g, "").trim().slice(0, 200)
        : "";
      items.push({
        t: decodeEntities(t).slice(0, 160),
        u: url,
        s: source,
        at: isNaN(at) ? Date.now() : at,
        d: snippet || undefined,
      });
    }
  }
  return items;
}

async function fetchFeed(url, source) {
  try {
    const r = await fetch(url, { headers: { "User-Agent": "BullrunIQ/1.0 (+https://bullruniq.com)" }, signal: AbortSignal.timeout(8000) });
    if (!r.ok) return [];
    return parseRss(await r.text(), source);
  } catch (e) { return []; }
}

exports.handler = async function (event) {
  const blobs = require("@netlify/blobs");
  try { blobs.connectLambda(event); } catch (e) {}
  let cache = null;
  try { cache = blobs.getStore("cache"); } catch (e) {}

  if (cache) {
    try {
      const c = await cache.get("news", { type: "json" });
      if (c && Date.now() - c.fetchedAt < TTL_MS) {
        return { statusCode: 200, headers: CORS, body: JSON.stringify({ items: c.items, cached: true }) };
      }
    } catch (e) {}
  }

  const results = await Promise.allSettled(FEEDS.map(function (f) { return fetchFeed(f.url, f.source); }));
  let items = results
    .filter(function (r) { return r.status === "fulfilled"; })
    .flatMap(function (r) { return r.value; })
    .sort(function (a, b) { return b.at - a.at; })
    .slice(0, 20);

  if (!items.length && cache) {
    try {
      const c = await cache.get("news", { type: "json" });
      if (c) return { statusCode: 200, headers: CORS, body: JSON.stringify({ items: c.items, stale: true }) };
    } catch (e) {}
  }

  if (items.length && cache) {
    try { await cache.setJSON("news", { items: items, fetchedAt: Date.now() }); } catch (e) {}
  }
  return { statusCode: 200, headers: CORS, body: JSON.stringify({ items: items }) };
};
