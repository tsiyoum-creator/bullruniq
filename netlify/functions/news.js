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

  const results = await Promise.allSettled([
    fetchFeed("https://www.coindesk.com/arc/outboundfeeds/rss/", "CoinDesk"),
    fetchFeed("https://cointelegraph.com/rss", "Cointelegraph"),
  ]);
  let items = results.filter(function (r) { return r.status === "fulfilled"; })
    .flatMap(function (r) { return r.value; })
    .sort(function (a, b) { return b.at - a.at; })
    .slice(0, 14);

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
