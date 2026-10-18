// Unit tests for BullrunIQ pure utility functions.
// Run with: node tests/unit.test.js

const crypto = require("crypto");

let passed = 0, failed = 0;
function assert(condition, label) {
  if (condition) { console.log("  ✓ " + label); passed++; }
  else { console.error("  ✗ FAIL: " + label); failed++; }
}
function approx(a, b, eps) { return Math.abs(a - b) <= (eps || 0.001); }

// ─────────────────────────────────────────────────────────────────────────────
// stripe-webhook: verifyStripe
// ─────────────────────────────────────────────────────────────────────────────

function verifyStripe(rawBody, sigHeader, secret) {
  if (!sigHeader || !secret) return false;
  const parts = {};
  String(sigHeader).split(",").forEach(function (kv) {
    const i = kv.indexOf("=");
    if (i > 0) parts[kv.slice(0, i).trim()] = kv.slice(i + 1).trim();
  });
  if (!parts.t || !parts.v1) return false;
  const signed = parts.t + "." + rawBody;
  const expected = crypto.createHmac("sha256", secret).update(signed, "utf8").digest("hex");
  try {
    if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(parts.v1))) return false;
  } catch (e) { return false; }
  const age = Math.abs(Math.floor(Date.now() / 1000) - parseInt(parts.t, 10));
  return age <= 300;
}

console.log("\n--- stripe-webhook: verifyStripe ---");
{
  const secret = "whsec_test_secret";
  const body = '{"type":"checkout.session.completed"}';
  const ts = String(Math.floor(Date.now() / 1000));
  const sig = crypto.createHmac("sha256", secret).update(ts + "." + body, "utf8").digest("hex");
  const header = "t=" + ts + ",v1=" + sig;

  assert(verifyStripe(body, header, secret) === true, "valid signature accepted");
  assert(verifyStripe(body, header, "wrong_secret") === false, "wrong secret rejected");
  assert(verifyStripe(body + "tampered", header, secret) === false, "tampered body rejected");
  assert(verifyStripe(body, null, secret) === false, "missing header rejected");
  assert(verifyStripe(body, header, null) === false, "missing secret rejected");
  assert(verifyStripe(body, "t=12345,v1=badhex", secret) === false, "bad signature rejected");
  assert(verifyStripe(body, "v1=" + sig, secret) === false, "missing t field rejected");
  assert(verifyStripe(body, "t=" + ts, secret) === false, "missing v1 field rejected");

  // Stale timestamp (> 5 min old)
  const oldTs = String(Math.floor(Date.now() / 1000) - 400);
  const oldSig = crypto.createHmac("sha256", secret).update(oldTs + "." + body, "utf8").digest("hex");
  const oldHeader = "t=" + oldTs + ",v1=" + oldSig;
  assert(verifyStripe(body, oldHeader, secret) === false, "replay attack (stale timestamp) rejected");
}

// ─────────────────────────────────────────────────────────────────────────────
// alerts: regimeLadderRungs
// ─────────────────────────────────────────────────────────────────────────────

function regimeLadderRungs(regime) {
  if (regime === "longend" || regime === "squeeze") return [15, 30, 60, 100];
  if (regime === "liquidity" || regime === "fiscdom") return [25, 50, 100, 200];
  return [25, 50, 100, 200];
}

console.log("\n--- alerts: regimeLadderRungs ---");
{
  assert(JSON.stringify(regimeLadderRungs("longend")) === JSON.stringify([15, 30, 60, 100]), "longend regime: tighter rungs");
  assert(JSON.stringify(regimeLadderRungs("squeeze")) === JSON.stringify([15, 30, 60, 100]), "squeeze regime: tighter rungs");
  assert(JSON.stringify(regimeLadderRungs("liquidity")) === JSON.stringify([25, 50, 100, 200]), "liquidity regime: standard rungs");
  assert(JSON.stringify(regimeLadderRungs("fiscdom")) === JSON.stringify([25, 50, 100, 200]), "fiscdom regime: standard rungs");
  assert(JSON.stringify(regimeLadderRungs("deflation")) === JSON.stringify([25, 50, 100, 200]), "deflation regime: default rungs");
  assert(JSON.stringify(regimeLadderRungs("unknown")) === JSON.stringify([25, 50, 100, 200]), "unknown regime: default rungs");
  assert(JSON.stringify(regimeLadderRungs(undefined)) === JSON.stringify([25, 50, 100, 200]), "undefined regime: default rungs");
}

// ─────────────────────────────────────────────────────────────────────────────
// alerts: computeLadder
// ─────────────────────────────────────────────────────────────────────────────

function computeLadder(avg, qty, price, regime) {
  if (!avg || avg <= 0 || !qty || qty <= 0) return null;
  const gainPct = (price - avg) / avg * 100;
  if (gainPct < 10) return null;
  const rungs = regimeLadderRungs(regime).map(function (pc) {
    const ladderPrice = avg * (1 + pc / 100);
    return { pct: pc, price: ladderPrice, qty: qty * 0.25, hit: price >= ladderPrice };
  });
  return { gainPct: gainPct, rungs: rungs, hits: rungs.filter(function (r) { return r.hit; }) };
}

console.log("\n--- alerts: computeLadder ---");
{
  // Below 10% gain → null
  assert(computeLadder(100, 10, 105, "liquidity") === null, "gain < 10% returns null");
  assert(computeLadder(100, 10, 109.9, "liquidity") === null, "gain exactly 9.9% returns null");

  // Exactly at 10% gain → ladder computed (10 >= 10 is a boundary — verify)
  const at10 = computeLadder(100, 10, 110, "liquidity");
  assert(at10 !== null, "gain = 10% returns ladder");
  assert(approx(at10.gainPct, 10), "gainPct correct at 10%");
  assert(at10.hits.length === 0, "no rungs hit at exactly 10% gain");

  // 60% gain, standard regime: first two rungs hit (+25%, +50%)
  const at60 = computeLadder(100, 8, 160, "liquidity");
  assert(at60 !== null, "60% gain returns ladder");
  assert(at60.hits.length === 2, "two rungs hit at 60% gain (liquidity)");
  assert(at60.rungs[0].hit && at60.rungs[1].hit, "rungs 0+1 hit at 60%");
  assert(!at60.rungs[2].hit && !at60.rungs[3].hit, "rungs 2+3 not hit at 60%");
  assert(approx(at60.rungs[0].price, 125), "rung 0 price = avg * 1.25");
  assert(approx(at60.rungs[0].qty, 2), "rung qty = total * 0.25");

  // Tight regime (longend): 60% gain → hits rungs at 15%, 30%, 60% but not 100%
  const tight60 = computeLadder(100, 8, 160, "longend");
  assert(tight60.hits.length === 3, "three rungs hit at 60% gain (longend)");

  // Invalid inputs
  assert(computeLadder(0, 10, 100, "liquidity") === null, "avg=0 returns null");
  assert(computeLadder(-1, 10, 100, "liquidity") === null, "avg<0 returns null");
  assert(computeLadder(100, 0, 100, "liquidity") === null, "qty=0 returns null");
  assert(computeLadder(100, -1, 100, "liquidity") === null, "qty<0 returns null");
  assert(computeLadder(null, 10, 100, "liquidity") === null, "null avg returns null");
}

// ─────────────────────────────────────────────────────────────────────────────
// alerts: shouldResetLadder
// ─────────────────────────────────────────────────────────────────────────────

function shouldResetLadder(avg, price, prevHits) {
  if (!prevHits) return false;
  if (!avg || avg <= 0) return false;
  const gainPct = (price - avg) / avg * 100;
  return gainPct < 10;
}

console.log("\n--- alerts: shouldResetLadder ---");
{
  assert(shouldResetLadder(100, 105, 2) === true, "price at +5% with hits → reset");
  assert(shouldResetLadder(100, 109, 2) === true, "price at +9% with hits → reset");
  assert(shouldResetLadder(100, 110, 2) === false, "price at +10% with hits → no reset");
  assert(shouldResetLadder(100, 150, 2) === false, "price at +50% with hits → no reset");
  assert(shouldResetLadder(100, 105, 0) === false, "no prior hits → never reset");
  assert(shouldResetLadder(100, 105, null) === false, "null prevHits → never reset");
  assert(shouldResetLadder(0, 105, 2) === false, "avg=0 → no reset");
  assert(shouldResetLadder(null, 105, 2) === false, "null avg → no reset");
}

// ─────────────────────────────────────────────────────────────────────────────
// sync: validateUserData
// ─────────────────────────────────────────────────────────────────────────────

function validateUserData(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) return false;
  if (data.cash !== undefined) {
    if (typeof data.cash !== "number" || !isFinite(data.cash) || data.cash < 0 || data.cash > 1e9) return false;
  }
  if (data.cashApy !== undefined) {
    if (typeof data.cashApy !== "number" || !isFinite(data.cashApy) || data.cashApy < 0 || data.cashApy > 100) return false;
  }
  if (data.port && data.port.crypto !== undefined) {
    if (!Array.isArray(data.port.crypto)) return false;
    if (data.port.crypto.length > 200) return false;
    for (const h of data.port.crypto) {
      if (!h || typeof h !== "object") return false;
      if (h.ticker && typeof h.ticker !== "string") return false;
      if (h.ticker && h.ticker.length > 20) return false;
      if (h.ticker && !/^[A-Za-z0-9._-]{1,20}$/.test(h.ticker)) return false;
      if (h.name !== undefined && (typeof h.name !== "string" || h.name.length > 100)) return false;
      if (h.qty !== undefined && (typeof h.qty !== "number" || !isFinite(h.qty) || h.qty < 0)) return false;
      if (h.avg !== undefined && (typeof h.avg !== "number" || !isFinite(h.avg) || h.avg < 0)) return false;
      if (h.stop !== undefined && (typeof h.stop !== "number" || !isFinite(h.stop) || h.stop < 0)) return false;
      if (h.tp !== undefined && (typeof h.tp !== "number" || !isFinite(h.tp) || h.tp < 0)) return false;
    }
  }
  if (data.wl !== undefined) {
    if (!Array.isArray(data.wl)) return false;
    if (data.wl.length > 100) return false;
    for (const w of data.wl) {
      if (!w || typeof w !== "object") return false;
      if (w.ticker && typeof w.ticker !== "string") return false;
      if (w.ticker && w.ticker.length > 20) return false;
      if (w.ticker && !/^[A-Za-z0-9._-]{1,20}$/.test(w.ticker)) return false;
      if (w.name !== undefined && (typeof w.name !== "string" || w.name.length > 100)) return false;
      if (w.targetPrice !== undefined && (typeof w.targetPrice !== "number" || !isFinite(w.targetPrice) || w.targetPrice < 0)) return false;
      if (w.sellTarget !== undefined && (typeof w.sellTarget !== "number" || !isFinite(w.sellTarget) || w.sellTarget < 0)) return false;
    }
  }
  return true;
}

console.log("\n--- sync: validateUserData ---");
{
  assert(validateUserData({}) === true, "empty object valid");
  assert(validateUserData(null) === false, "null rejected");
  assert(validateUserData([]) === false, "array rejected");
  assert(validateUserData("string") === false, "string rejected");

  // cash
  assert(validateUserData({ cash: 0 }) === true, "cash=0 valid");
  assert(validateUserData({ cash: 50000 }) === true, "cash=50000 valid");
  assert(validateUserData({ cash: -1 }) === false, "negative cash rejected");
  assert(validateUserData({ cash: 1e10 }) === false, "cash > 1e9 rejected");
  assert(validateUserData({ cash: NaN }) === false, "NaN cash rejected");
  assert(validateUserData({ cash: Infinity }) === false, "Infinity cash rejected");
  assert(validateUserData({ cash: "1000" }) === false, "string cash rejected");

  // cashApy
  assert(validateUserData({ cashApy: 5 }) === true, "cashApy=5 valid");
  assert(validateUserData({ cashApy: 0 }) === true, "cashApy=0 valid");
  assert(validateUserData({ cashApy: 100 }) === true, "cashApy=100 valid");
  assert(validateUserData({ cashApy: -0.1 }) === false, "negative cashApy rejected");
  assert(validateUserData({ cashApy: 101 }) === false, "cashApy > 100 rejected");

  // portfolio crypto
  assert(validateUserData({ port: { crypto: [] } }) === true, "empty crypto array valid");
  assert(validateUserData({ port: { crypto: [{ ticker: "BTC", qty: 0.5, avg: 60000 }] } }) === true, "valid holding");
  assert(validateUserData({ port: { crypto: [{ ticker: "BTC!!", qty: 0.5 }] } }) === false, "invalid ticker chars rejected");
  assert(validateUserData({ port: { crypto: [{ ticker: "B".repeat(21), qty: 1 }] } }) === false, "ticker > 20 chars rejected");
  assert(validateUserData({ port: { crypto: [{ qty: -1 }] } }) === false, "negative qty rejected");
  assert(validateUserData({ port: { crypto: [{ avg: -5 }] } }) === false, "negative avg rejected");
  assert(validateUserData({ port: { crypto: [{ stop: -1 }] } }) === false, "negative stop rejected");
  assert(validateUserData({ port: { crypto: [{ tp: -1 }] } }) === false, "negative tp rejected");

  // watchlist
  assert(validateUserData({ wl: [] }) === true, "empty watchlist valid");
  assert(validateUserData({ wl: [{ ticker: "ETH", targetPrice: 3000, sellTarget: 5000 }] }) === true, "valid watchlist item");
  assert(validateUserData({ wl: [{ ticker: "TICKER!@#" }] }) === false, "invalid watchlist ticker chars rejected");
  assert(validateUserData({ wl: [{ targetPrice: -1 }] }) === false, "negative targetPrice rejected");
  assert(validateUserData({ wl: [{ sellTarget: -1 }] }) === false, "negative sellTarget rejected");
  assert(validateUserData({ port: { crypto: new Array(201).fill({ ticker: "BTC" }) } }) === false, "crypto array > 200 rejected");
  assert(validateUserData({ wl: new Array(101).fill({ ticker: "ETH" }) }) === false, "watchlist > 100 rejected");
}

// ─────────────────────────────────────────────────────────────────────────────
// sync: stripServerFlags
// ─────────────────────────────────────────────────────────────────────────────

const SERVER_ALERT_FLAGS = new Set([
  "serverAlerted", "serverSellAlerted", "serverStopAlerted", "serverTpAlerted",
  "serverLadderHits", "serverAthAlerted", "serverConcentrationAlerted",
]);

function stripServerFlags(data) {
  if (!data || typeof data !== "object") return data;
  const out = Object.assign({}, data);
  if (out.port && Array.isArray(out.port.crypto)) {
    out.port = Object.assign({}, out.port);
    out.port.crypto = out.port.crypto.map(function (h) {
      if (!h || typeof h !== "object") return h;
      const cleaned = Object.assign({}, h);
      for (const flag of SERVER_ALERT_FLAGS) delete cleaned[flag];
      return cleaned;
    });
  }
  if (Array.isArray(out.wl)) {
    out.wl = out.wl.map(function (w) {
      if (!w || typeof w !== "object") return w;
      const cleaned = Object.assign({}, w);
      for (const flag of SERVER_ALERT_FLAGS) delete cleaned[flag];
      return cleaned;
    });
  }
  return out;
}

console.log("\n--- sync: stripServerFlags ---");
{
  const dirty = {
    cash: 1000,
    port: {
      crypto: [
        { ticker: "BTC", qty: 1, serverStopAlerted: true, serverTpAlerted: true, serverLadderHits: 2 },
        { ticker: "ETH", qty: 10, serverConcentrationAlerted: true },
      ],
    },
    wl: [
      { ticker: "SOL", serverAlerted: true, serverSellAlerted: true },
    ],
  };

  const clean = stripServerFlags(dirty);

  assert(clean.cash === 1000, "non-flag fields preserved");
  assert(clean.port.crypto[0].ticker === "BTC", "holding ticker preserved");
  assert(clean.port.crypto[0].serverStopAlerted === undefined, "serverStopAlerted stripped from holding");
  assert(clean.port.crypto[0].serverTpAlerted === undefined, "serverTpAlerted stripped from holding");
  assert(clean.port.crypto[0].serverLadderHits === undefined, "serverLadderHits stripped from holding");
  assert(clean.port.crypto[1].serverConcentrationAlerted === undefined, "serverConcentrationAlerted stripped");
  assert(clean.wl[0].ticker === "SOL", "watchlist ticker preserved");
  assert(clean.wl[0].serverAlerted === undefined, "serverAlerted stripped from watchlist");
  assert(clean.wl[0].serverSellAlerted === undefined, "serverSellAlerted stripped from watchlist");

  // Original object must not be mutated
  assert(dirty.port.crypto[0].serverStopAlerted === true, "original object not mutated");
  assert(dirty.wl[0].serverAlerted === true, "original watchlist not mutated");

  // Edge cases
  assert(stripServerFlags(null) === null, "null passthrough");
  assert(stripServerFlags("str") === "str", "non-object passthrough");
  const noPort = stripServerFlags({ cash: 500 });
  assert(noPort.cash === 500 && !noPort.port, "data without port untouched");
}

// ─────────────────────────────────────────────────────────────────────────────
// news: scoreByTickers + rankByTickers + parseRss
// ─────────────────────────────────────────────────────────────────────────────

function scoreByTickers(title, tickers) {
  const lower = title.toLowerCase();
  return tickers.reduce(function (n, tk) { return n + (lower.includes(tk.toLowerCase()) ? 1 : 0); }, 0);
}

function decodeEntities(s) {
  return String(s)
    .replace(/<\!\[CDATA\[|\]\]>/g, "")
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

console.log("\n--- news: scoreByTickers ---");
{
  assert(scoreByTickers("Bitcoin hits $100k", ["BTC", "bitcoin"]) === 1, "case-insensitive match");
  assert(scoreByTickers("BTC and ETH surge", ["BTC", "ETH"]) === 2, "two ticker matches");
  assert(scoreByTickers("Market update", ["BTC"]) === 0, "no match returns 0");
  // includes() is substring-based: "sol" is in "solana", "eth" is in "ethereum"
  assert(scoreByTickers("solana and ethereum rally", ["SOL", "ETH", "BTC"]) === 2, "substring match: SOL→solana, ETH→ethereum");
  assert(scoreByTickers("solana and ethereum rally", ["SOL", "solana", "ethereum"]) === 3, "3 matches: sol substring + solana + ethereum");
  assert(scoreByTickers("", ["BTC"]) === 0, "empty title returns 0");
  assert(scoreByTickers("BTC", []) === 0, "empty tickers returns 0");
}

console.log("\n--- news: parseRss ---");
{
  const rssXml = `<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <title>Test Feed</title>
    <item>
      <title>Bitcoin Hits New High</title>
      <link>https://example.com/btc-high</link>
      <pubDate>Mon, 13 Oct 2026 10:00:00 +0000</pubDate>
    </item>
    <item>
      <title>Ethereum &amp; DeFi Update</title>
      <link>https://example.com/eth-defi</link>
      <pubDate>Mon, 13 Oct 2026 09:00:00 +0000</pubDate>
    </item>
    <item>
      <title>Item with bad URL</title>
      <link>ftp://bad.url/path</link>
      <pubDate>Mon, 13 Oct 2026 08:00:00 +0000</pubDate>
    </item>
    <item>
      <title>No Link Item</title>
    </item>
  </channel>
</rss>`;

  const items = parseRss(rssXml, "TestFeed");
  assert(items.length === 2, "only valid https items parsed (ftp and no-link excluded)");
  assert(items[0].t === "Bitcoin Hits New High", "title parsed correctly");
  assert(items[0].u === "https://example.com/btc-high", "URL parsed correctly");
  assert(items[0].s === "TestFeed", "source assigned correctly");
  assert(items[1].t === "Ethereum & DeFi Update", "HTML entities decoded in title");
  assert(typeof items[0].at === "number" && items[0].at > 0, "pubDate converted to timestamp");
  assert(items[0].at > items[1].at, "older item has smaller timestamp");

  // Empty/malformed XML
  assert(parseRss("", "X").length === 0, "empty XML returns empty array");
  assert(parseRss("no items here", "X").length === 0, "XML without items returns empty");

  // Title truncation at 160 chars
  const longTitle = "A".repeat(200);
  const longRss = `<rss><channel><item><title>${longTitle}</title><link>https://example.com</link></item></channel></rss>`;
  const longItems = parseRss(longRss, "X");
  assert(longItems.length === 1 && longItems[0].t.length === 160, "title truncated to 160 chars");

  // CDATA section stripping
  const cdataRss = `<rss><channel><item><title><![CDATA[Bitcoin & Crypto Update]]></title><link>https://example.com/cdata</link></item></channel></rss>`;
  const cdataItems = parseRss(cdataRss, "X");
  assert(cdataItems.length === 1, "CDATA item parsed");
  assert(cdataItems[0].t === "Bitcoin &amp; Crypto Update" || cdataItems[0].t === "Bitcoin & Crypto Update", "CDATA markers stripped from title");
}

console.log("\n--- news: rankByTickers ---");
{
  const now = Date.now();
  const items = [
    { t: "Market update", u: "https://a.com/1", s: "A", at: now - 1000 },
    { t: "BTC breaks $100k", u: "https://a.com/2", s: "A", at: now - 2000 },
    { t: "ETH and BTC surge together", u: "https://a.com/3", s: "A", at: now - 3000 },
    { t: "ETH staking update", u: "https://a.com/4", s: "A", at: now - 4000 },
    { t: "General crypto news", u: "https://a.com/5", s: "A", at: now - 5000 },
  ];

  const ranked = rankByTickers(items, ["BTC", "ETH"]);
  assert(ranked.length <= 20, "returns at most 20 items");
  assert(ranked[0].t === "ETH and BTC surge together", "double-match item ranked first");
  assert(ranked[1].t === "BTC breaks $100k" || ranked[1].t === "ETH staking update", "single-match items ranked second/third");
  // Among equal scores, more recent items come first
  const score0 = scoreByTickers(ranked[0].t, ["BTC", "ETH"]);
  const score1 = scoreByTickers(ranked[1].t, ["BTC", "ETH"]);
  assert(score0 >= score1, "higher-scored items always appear before lower-scored");

  // No matching tickers — falls back to recency order
  const noMatch = rankByTickers(items, ["XRP"]);
  assert(noMatch[0].at >= noMatch[noMatch.length - 1].at, "no-match items sorted by recency");
}

// ─────────────────────────────────────────────────────────────────────────────
// platform: checkAlerts re-arm boundary
// ─────────────────────────────────────────────────────────────────────────────

function simulateCheckAlerts(watchlistItem, currentPrice) {
  var w = Object.assign({}, watchlistItem);
  var dist = Math.abs((w.targetPrice - currentPrice) / currentPrice * 100);
  if (dist < 2 && !w.alerted) {
    w.alerted = true;
    w._fired = true;
  } else if (dist >= 2) {
    w.alerted = false;
  }
  return w;
}

console.log("\n--- platform: checkAlerts re-arm ---");
{
  var w1 = simulateCheckAlerts({ targetPrice: 50000, alerted: false }, 49100);
  assert(w1.alerted === true && w1._fired === true, "alert fires when price within 2% of target");

  var w2 = simulateCheckAlerts({ targetPrice: 50000, alerted: true }, 49100);
  assert(w2.alerted === true && !w2._fired, "no re-fire when already alerted");

  var w3 = simulateCheckAlerts({ targetPrice: 50000, alerted: true }, 51550);
  assert(w3.alerted === false, "re-arms when dist is 3% (>= 2% boundary)");

  var w4 = simulateCheckAlerts({ targetPrice: 50000, alerted: false }, 49500);
  assert(w4.alerted === true && w4._fired === true, "fires again after re-arm");

  var w5 = simulateCheckAlerts({ targetPrice: 50000, alerted: true }, 51100);
  var dist5 = Math.abs((50000 - 51100) / 51100 * 100);
  assert(dist5 >= 2, "dist at 51100 is >= 2% (2.15%)");
  assert(w5.alerted === false, "re-arms when dist is 2.15% above target");

  var w6 = simulateCheckAlerts({ targetPrice: 50000, alerted: true }, 52000);
  assert(w6.alerted === false, "re-arms at 4% — fixed dead-zone from old >= 5 threshold");
}

// ─────────────────────────────────────────────────────────────────────────────
// alerts: server-side buy alert re-arm threshold
// ─────────────────────────────────────────────────────────────────────────────

function simulateServerBuyAlert(w, price) {
  var item = Object.assign({}, w);
  var dist = Math.abs((item.targetPrice - price) / price * 100);
  if (dist < 2 && price <= item.targetPrice && !item.serverAlerted) {
    item.serverAlerted = true;
    item._fired = true;
  } else if (dist >= 2 && item.serverAlerted) {
    item.serverAlerted = false;
  }
  return item;
}

console.log("\n--- alerts: server-side buy alert re-arm (dist >= 2) ---");
{
  var s1 = simulateServerBuyAlert({ targetPrice: 50000, serverAlerted: false }, 49100);
  assert(s1.serverAlerted === true && s1._fired === true, "server alert fires within 2% of target");

  var s2 = simulateServerBuyAlert({ targetPrice: 50000, serverAlerted: true }, 49100);
  assert(s2.serverAlerted === true && !s2._fired, "no re-fire when already alerted");

  var s3 = simulateServerBuyAlert({ targetPrice: 50000, serverAlerted: true }, 51550);
  assert(s3.serverAlerted === false, "re-arms at 3% from target");

  var s4 = simulateServerBuyAlert({ targetPrice: 50000, serverAlerted: true }, 52000);
  assert(s4.serverAlerted === false, "re-arms at 4% — old >=5 threshold would have left this stuck");

  var s5 = simulateServerBuyAlert({ targetPrice: 50000, serverAlerted: true }, 50760);
  var dist5 = Math.abs((50000 - 50760) / 50760 * 100);
  assert(dist5 < 2, "dist at 50760 is < 2%");
  assert(s5.serverAlerted === true, "stays alerted when dist < 2%");
}

// ─────────────────────────────────────────────────────────────────────────────
// macro: null indicator guard in checkFalsifiers
// ─────────────────────────────────────────────────────────────────────────────

function checkFalsifiers_test(indicators) {
  var trips = [];
  indicators.forEach(function(i) {
    if (i.v === null || !i.op || i.th === null) return;
    var hit = (i.op === "gt" && i.v > i.th) || (i.op === "lt" && i.v < i.th);
    if (hit) trips.push({ n: i.n, v: i.v });
  });
  return trips;
}

console.log("\n--- macro: checkFalsifiers null-indicator guard ---");
{
  var indicators = [
    { k: "termprem", n: "ACM term premium", v: null, op: null, th: null },
    { k: "real10",   n: "10y TIPS real",    v: null, op: "gt", th: 2.5 },
    { k: "move",     n: "MOVE index",       v: null, op: "gt", th: 120 },
    { k: "ust10",    n: "UST 10y",          v: 5.02, op: "gt", th: 5.25 },
    { k: "dxy",      n: "DXY",              v: 100.3,op: "lt", th: 97  },
  ];
  var trips = checkFalsifiers_test(indicators);
  assert(trips.length === 0, "null-value indicators produce no NaN trips");
  assert(!trips.some(function(t) { return isNaN(t.v); }), "no NaN in trips array");

  var liveIndicators = [{ k: "ust10", n: "UST 10y", v: 5.30, op: "gt", th: 5.25 }];
  var liveTrips = checkFalsifiers_test(liveIndicators);
  assert(liveTrips.length === 1, "live indicator above threshold trips correctly");
  assert(liveTrips[0].n === "UST 10y", "correct indicator identified");
}

// ─────────────────────────────────────────────────────────────────────────────
// macro: MACRO_AI_RULE has no leading whitespace
// ─────────────────────────────────────────────────────────────────────────────

console.log("\n--- macro: MACRO_AI_RULE leading-space check ---");
{
  const macroJs = require("fs").readFileSync(require("path").join(__dirname, "../macro.js"), "utf8");
  const match = macroJs.match(/var MACRO_AI_RULE\s*=\s*'(.*?)';/s);
  assert(match !== null, "MACRO_AI_RULE found in macro.js");
  if (match) {
    assert(match[1][0] !== " ", "MACRO_AI_RULE has no leading space");
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// news: decodeEntities — CDATA stripping
// ─────────────────────────────────────────────────────────────────────────────

console.log("\n--- news: decodeEntities CDATA stripping ---");
{
  assert(decodeEntities("<![CDATA[hello & world]]>") === "hello &amp; world" ||
         decodeEntities("<![CDATA[hello & world]]>") === "hello & world",
    "CDATA markers stripped, inner text preserved");
  assert(!decodeEntities("<![CDATA[test]]>").includes("<![CDATA["), "CDATA open marker removed");
  assert(!decodeEntities("<![CDATA[test]]>").includes("]]>"), "CDATA close marker removed");
  assert(decodeEntities("Bitcoin &amp; Crypto") === "Bitcoin & Crypto", "entity decode still works");
}

// ─────────────────────────────────────────────────────────────────────────────
// macro: macroDataAge() returns a non-negative integer
// ─────────────────────────────────────────────────────────────────────────────

console.log("\n--- macro: macroDataAge ---");
{
  const macro = require("../macro.js");
  const age = macro.macroDataAge();
  assert(typeof age === "number" && Number.isFinite(age), "macroDataAge returns a number");
  assert(age >= 0, "macroDataAge is non-negative");
  assert(Number.isInteger(age), "macroDataAge returns an integer (days)");
}

// ─────────────────────────────────────────────────────────────────────────────
// generate.js: dailyOk receives getBlobStore as a parameter (scope bug fix)
// ─────────────────────────────────────────────────────────────────────────────

async function dailyOkTest(key, cap, getBlobStoreFn) {
  try {
    const store = getBlobStoreFn("ai-usage");
    const today = new Date().toISOString().slice(0, 10);
    const storeKey = key + ":" + today;
    const cur = (await store.get(storeKey, { type: "json" })) || { count: 0 };
    if (cur.count >= cap) return false;
    cur.count++;
    await store.setJSON(storeKey, cur);
    return true;
  } catch (e) {
    return true; // fail open
  }
}

console.log("\n--- generate.js: dailyOk parameter injection ---");
{
  async function runDailyOkTests() {
    const store = {};
    const mockGetStore = function () {
      return {
        get: async function (k) { return store[k] || null; },
        setJSON: async function (k, v) { store[k] = v; },
      };
    };

    const r1 = await dailyOkTest("user:test@example.com", 5, mockGetStore);
    assert(r1 === true, "first call under cap returns true");

    const r2 = await dailyOkTest("user:test@example.com", 5, mockGetStore);
    assert(r2 === true, "second call still under cap returns true");

    await dailyOkTest("user:test@example.com", 5, mockGetStore);
    await dailyOkTest("user:test@example.com", 5, mockGetStore);
    await dailyOkTest("user:test@example.com", 5, mockGetStore);

    const rCapped = await dailyOkTest("user:test@example.com", 5, mockGetStore);
    assert(rCapped === false, "call at cap returns false (limit reached)");

    const brokenStore = function () { return { get: async function () { throw new Error("unavailable"); }, setJSON: async function () {} }; };
    const rBroken = await dailyOkTest("user:broken@example.com", 5, brokenStore);
    assert(rBroken === true, "storage error → fail open (returns true, not false)");

    const r3 = await dailyOkTest("ip:1.2.3.4", 3, mockGetStore);
    assert(r3 === true, "different key has its own counter");
  }
  runDailyOkTests().catch(function (e) { console.error("dailyOk async test failed:", e.message); failed++; });
}

// ─────────────────────────────────────────────────────────────────────────────
// market.js: new_ath kind — coins that broke their all-time high
// ─────────────────────────────────────────────────────────────────────────────

function newAthTransform(data) {
  if (!Array.isArray(data)) return data;
  return data
    .filter(function (c) {
      return typeof c.ath_change_percentage === "number" && c.ath_change_percentage >= 0 &&
        c.market_cap > 100e6;
    })
    .map(function (c) {
      return {
        id: c.id,
        symbol: (c.symbol || "").toUpperCase(),
        name: c.name,
        price: c.current_price,
        ath: c.ath,
        ath_date: c.ath_date,
        market_cap: c.market_cap,
        change_7d: c.price_change_percentage_7d_in_currency,
        change_30d: c.price_change_percentage_30d_in_currency,
      };
    })
    .sort(function (a, b) { return (b.change_7d || 0) - (a.change_7d || 0); });
}

console.log("\n--- market.js: new_ath transform ---");
{
  const coins = [
    { id: "bitcoin", symbol: "btc", name: "Bitcoin", current_price: 101000, ath: 99000, ath_change_percentage: 2.02, market_cap: 2e12, price_change_percentage_7d_in_currency: 8.1, price_change_percentage_30d_in_currency: 15.0, ath_date: "2026-10-15" },
    { id: "solana",  symbol: "sol", name: "Solana",  current_price: 190,    ath: 200,   ath_change_percentage: -5.0, market_cap: 80e9,  price_change_percentage_7d_in_currency: 5.0, price_change_percentage_30d_in_currency: 10.0, ath_date: "2026-08-01" },
    { id: "micro",   symbol: "MCR", name: "MicroCap", current_price: 1,     ath: 1,     ath_change_percentage: 0.0,  market_cap: 50e6,  price_change_percentage_7d_in_currency: 2.0, price_change_percentage_30d_in_currency: 3.0, ath_date: "2026-10-18" },
    { id: "ethereum", symbol: "eth", name: "Ethereum", current_price: 4000, ath: 4200,  ath_change_percentage: -4.8, market_cap: 480e9, price_change_percentage_7d_in_currency: 6.0, price_change_percentage_30d_in_currency: 12.0, ath_date: "2026-09-01" },
  ];

  const result = newAthTransform(coins);
  assert(result.length === 1, "only bitcoin (new ATH, mcap > 100M) included");
  assert(result[0].id === "bitcoin", "bitcoin is the only new-ATH coin");
  assert(result[0].symbol === "BTC", "symbol uppercased");
  assert(typeof result[0].change_7d === "number", "change_7d field present");
  assert(typeof result[0].change_30d === "number", "change_30d field present");
  assert(result[0].ath_date === "2026-10-15", "ath_date preserved");

  const microOnly = newAthTransform([coins[2]]);
  assert(microOnly.length === 0, "micro-cap (<100M mcap) excluded even at ATH");

  const noAth = newAthTransform([coins[1], coins[3]]);
  assert(noAth.length === 0, "coins below ATH excluded");

  const twoAtH = [
    { id: "a", symbol: "a", name: "A", current_price: 10, ath: 9, ath_change_percentage: 5.0, market_cap: 500e6, price_change_percentage_7d_in_currency: 3.0, price_change_percentage_30d_in_currency: 5.0, ath_date: "2026-10-18" },
    { id: "b", symbol: "b", name: "B", current_price: 20, ath: 19, ath_change_percentage: 1.0, market_cap: 200e6, price_change_percentage_7d_in_currency: 12.0, price_change_percentage_30d_in_currency: 20.0, ath_date: "2026-10-17" },
  ];
  const sorted = newAthTransform(twoAtH);
  assert(sorted.length === 2, "both valid ATH coins included");
  assert(sorted[0].id === "b", "coin with higher 7d change ranked first");
}

// ─────────────────────────────────────────────────────────────────────────────
// alerts.js: new-ATH alert flag (serverNewAthAlerted) in SERVER_ALERT_FLAGS
// ─────────────────────────────────────────────────────────────────────────────

console.log("\n--- sync.js: serverNewAthAlerted in SERVER_ALERT_FLAGS ---");
{
  const SERVER_ALERT_FLAGS_NEW = new Set([
    "serverAlerted", "serverSellAlerted", "serverStopAlerted", "serverTpAlerted",
    "serverLadderHits", "serverAthAlerted", "serverNewAthAlerted", "serverConcentrationAlerted",
  ]);

  assert(SERVER_ALERT_FLAGS_NEW.has("serverNewAthAlerted"), "serverNewAthAlerted is in SERVER_ALERT_FLAGS");
  assert(SERVER_ALERT_FLAGS_NEW.has("serverAthAlerted"), "serverAthAlerted still present");
  assert(SERVER_ALERT_FLAGS_NEW.has("serverConcentrationAlerted"), "serverConcentrationAlerted still present");

  function stripServerFlagsNew(data) {
    if (!data || typeof data !== "object") return data;
    const out = Object.assign({}, data);
    if (out.port && Array.isArray(out.port.crypto)) {
      out.port = Object.assign({}, out.port);
      out.port.crypto = out.port.crypto.map(function (h) {
        if (!h || typeof h !== "object") return h;
        const cleaned = Object.assign({}, h);
        for (const flag of SERVER_ALERT_FLAGS_NEW) delete cleaned[flag];
        return cleaned;
      });
    }
    return out;
  }

  const dirty = { port: { crypto: [{ ticker: "BTC", qty: 1, serverNewAthAlerted: true, serverAthAlerted: true }] } };
  const clean = stripServerFlagsNew(dirty);
  assert(clean.port.crypto[0].serverNewAthAlerted === undefined, "serverNewAthAlerted stripped from holding");
  assert(clean.port.crypto[0].serverAthAlerted === undefined, "serverAthAlerted also stripped");
  assert(clean.port.crypto[0].ticker === "BTC", "ticker preserved after strip");
}

// ─────────────────────────────────────────────────────────────────────────────
// Summary
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n══════════════════════════════════════");
console.log(passed + " passed, " + failed + " failed");
if (failed > 0) { console.error("SOME TESTS FAILED"); process.exit(1); }
else { console.log("All tests passed."); }
