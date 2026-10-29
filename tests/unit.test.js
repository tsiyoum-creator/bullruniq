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
  assert(computeLadder(100, 10, 105, "liquidity") === null, "gain < 10% returns null");
  assert(computeLadder(100, 10, 109.9, "liquidity") === null, "gain exactly 9.9% returns null");

  const at10 = computeLadder(100, 10, 110, "liquidity");
  assert(at10 !== null, "gain = 10% returns ladder");
  assert(approx(at10.gainPct, 10), "gainPct correct at 10%");
  assert(at10.hits.length === 0, "no rungs hit at exactly 10% gain");

  const at60 = computeLadder(100, 8, 160, "liquidity");
  assert(at60 !== null, "60% gain returns ladder");
  assert(at60.hits.length === 2, "two rungs hit at 60% gain (liquidity)");
  assert(at60.rungs[0].hit && at60.rungs[1].hit, "rungs 0+1 hit at 60%");
  assert(!at60.rungs[2].hit && !at60.rungs[3].hit, "rungs 2+3 not hit at 60%");
  assert(approx(at60.rungs[0].price, 125), "rung 0 price = avg * 1.25");
  assert(approx(at60.rungs[0].qty, 2), "rung qty = total * 0.25");

  const tight60 = computeLadder(100, 8, 160, "longend");
  assert(tight60.hits.length === 3, "three rungs hit at 60% gain (longend)");

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
      if (h.notes !== undefined && (typeof h.notes !== "string" || h.notes.length > 1000)) return false;
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
      if (w.notes !== undefined && (typeof w.notes !== "string" || w.notes.length > 1000)) return false;
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

  assert(validateUserData({ cash: 0 }) === true, "cash=0 valid");
  assert(validateUserData({ cash: 50000 }) === true, "cash=50000 valid");
  assert(validateUserData({ cash: -1 }) === false, "negative cash rejected");
  assert(validateUserData({ cash: 1e10 }) === false, "cash > 1e9 rejected");
  assert(validateUserData({ cash: NaN }) === false, "NaN cash rejected");
  assert(validateUserData({ cash: Infinity }) === false, "Infinity cash rejected");
  assert(validateUserData({ cash: "1000" }) === false, "string cash rejected");

  assert(validateUserData({ cashApy: 5 }) === true, "cashApy=5 valid");
  assert(validateUserData({ cashApy: 0 }) === true, "cashApy=0 valid");
  assert(validateUserData({ cashApy: 100 }) === true, "cashApy=100 valid");
  assert(validateUserData({ cashApy: -0.1 }) === false, "negative cashApy rejected");
  assert(validateUserData({ cashApy: 101 }) === false, "cashApy > 100 rejected");

  assert(validateUserData({ port: { crypto: [] } }) === true, "empty crypto array valid");
  assert(validateUserData({ port: { crypto: [{ ticker: "BTC", qty: 0.5, avg: 60000 }] } }) === true, "valid holding");
  assert(validateUserData({ port: { crypto: [{ ticker: "BTC!!", qty: 0.5 }] } }) === false, "invalid ticker chars rejected");
  assert(validateUserData({ port: { crypto: [{ ticker: "B".repeat(21), qty: 1 }] } }) === false, "ticker > 20 chars rejected");
  assert(validateUserData({ port: { crypto: [{ qty: -1 }] } }) === false, "negative qty rejected");
  assert(validateUserData({ port: { crypto: [{ avg: -5 }] } }) === false, "negative avg rejected");
  assert(validateUserData({ port: { crypto: [{ stop: -1 }] } }) === false, "negative stop rejected");
  assert(validateUserData({ port: { crypto: [{ tp: -1 }] } }) === false, "negative tp rejected");

  assert(validateUserData({ wl: [] }) === true, "empty watchlist valid");
  assert(validateUserData({ wl: [{ ticker: "ETH", targetPrice: 3000, sellTarget: 5000 }] }) === true, "valid watchlist item");
  assert(validateUserData({ wl: [{ ticker: "TICKER!@#" }] }) === false, "invalid watchlist ticker chars rejected");
  assert(validateUserData({ wl: [{ targetPrice: -1 }] }) === false, "negative targetPrice rejected");
  assert(validateUserData({ wl: [{ sellTarget: -1 }] }) === false, "negative sellTarget rejected");
  assert(validateUserData({ port: { crypto: new Array(201).fill({ ticker: "BTC" }) } }) === false, "crypto array > 200 rejected");
  assert(validateUserData({ wl: new Array(101).fill({ ticker: "ETH" }) }) === false, "watchlist > 100 rejected");

  assert(validateUserData({ port: { crypto: [{ ticker: "BTC", notes: "Bought at support" }] } }) === true, "valid notes string accepted");
  assert(validateUserData({ port: { crypto: [{ ticker: "BTC", notes: "A".repeat(1000) }] } }) === true, "notes at 1000 chars accepted");
  assert(validateUserData({ port: { crypto: [{ ticker: "BTC", notes: "A".repeat(1001) }] } }) === false, "notes > 1000 chars rejected");
  assert(validateUserData({ port: { crypto: [{ ticker: "BTC", notes: 123 }] } }) === false, "non-string notes on holding rejected");

  assert(validateUserData({ wl: [{ ticker: "ETH", notes: "Watching for breakout" }] }) === true, "valid notes on watchlist item accepted");
  assert(validateUserData({ wl: [{ ticker: "ETH", notes: "A".repeat(1001) }] }) === false, "notes > 1000 chars on watchlist rejected");
  assert(validateUserData({ wl: [{ ticker: "ETH", notes: false }] }) === false, "boolean notes on watchlist rejected");
}

// ─────────────────────────────────────────────────────────────────────────────
// sync: stripServerFlags
// ─────────────────────────────────────────────────────────────────────────────

const SERVER_ALERT_FLAGS = new Set([
  "serverAlerted", "serverSellAlerted", "serverStopAlerted", "serverTpAlerted",
  "serverLadderHits", "serverAthAlerted", "serverConcentrationAlerted", "serverDrawdownAlerted",
  "serverDcaRung",
]);

const ROOT_SERVER_FLAGS = ["serverDrawdownAlerted", "portfolioPeak"];

function stripServerFlags(data) {
  if (!data || typeof data !== "object") return data;
  const out = Object.assign({}, data);
  for (const flag of ROOT_SERVER_FLAGS) delete out[flag];
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
        { ticker: "BTC", qty: 1, serverStopAlerted: true, serverTpAlerted: true, serverLadderHits: 2, serverDcaRung: 1 },
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
  assert(clean.port.crypto[0].serverDcaRung === undefined, "serverDcaRung stripped from holding");
  assert(clean.port.crypto[1].serverConcentrationAlerted === undefined, "serverConcentrationAlerted stripped");
  assert(clean.wl[0].ticker === "SOL", "watchlist ticker preserved");
  assert(clean.wl[0].serverAlerted === undefined, "serverAlerted stripped from watchlist");
  assert(clean.wl[0].serverSellAlerted === undefined, "serverSellAlerted stripped from watchlist");

  assert(dirty.port.crypto[0].serverStopAlerted === true, "original object not mutated");
  assert(dirty.wl[0].serverAlerted === true, "original watchlist not mutated");

  assert(stripServerFlags(null) === null, "null passthrough");
  assert(stripServerFlags("str") === "str", "non-object passthrough");
  const noPort = stripServerFlags({ cash: 500 });
  assert(noPort.cash === 500 && !noPort.port, "data without port untouched");

  const withRootFlags = {
    cash: 2000,
    portfolioPeak: 50000,
    serverDrawdownAlerted: true,
    port: { crypto: [{ ticker: "BTC", qty: 1 }] },
  };
  const cleanRoot = stripServerFlags(withRootFlags);
  assert(cleanRoot.cash === 2000, "cash preserved when root flags stripped");
  assert(cleanRoot.portfolioPeak === undefined, "portfolioPeak stripped from root");
  assert(cleanRoot.serverDrawdownAlerted === undefined, "serverDrawdownAlerted stripped from root");
  assert(withRootFlags.portfolioPeak === 50000, "original not mutated (portfolioPeak)");
  assert(withRootFlags.serverDrawdownAlerted === true, "original not mutated (serverDrawdownAlerted)");
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

  assert(parseRss("", "X").length === 0, "empty XML returns empty array");
  assert(parseRss("no items here", "X").length === 0, "XML without items returns empty");

  const longTitle = "A".repeat(200);
  const longRss = `<rss><channel><item><title>${longTitle}</title><link>https://example.com</link></item></channel></rss>`;
  const longItems = parseRss(longRss, "X");
  assert(longItems.length === 1 && longItems[0].t.length === 160, "title truncated to 160 chars");

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
  const score0 = scoreByTickers(ranked[0].t, ["BTC", "ETH"]);
  const score1 = scoreByTickers(ranked[1].t, ["BTC", "ETH"]);
  assert(score0 >= score1, "higher-scored items always appear before lower-scored");

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
// macro: MACRO_DATA freshness check
// ─────────────────────────────────────────────────────────────────────────────

console.log("\n--- macro: MACRO_DATA freshness ---");
{
  const macro = require("../macro.js");
  const age = macro.macroDataAge();
  const MAX_STALE_DAYS = 3;
  assert(age <= MAX_STALE_DAYS, "MACRO_DATA.asOf is at most " + MAX_STALE_DAYS + " days old (actual: " + age + ")");
  assert(macro.MACRO_DATA && typeof macro.MACRO_DATA.asOf === "string", "MACRO_DATA.asOf is a string");
  assert(/^\d{4}-\d{2}-\d{2}$/.test(macro.MACRO_DATA.asOf), "MACRO_DATA.asOf is YYYY-MM-DD format");
}

// ─────────────────────────────────────────────────────────────────────────────
// alerts: late-2026 CGMAP additions present in production file
// ─────────────────────────────────────────────────────────────────────────────

console.log("\n--- alerts: late-2026 CGMAP entries ---");
{
  const fs = require("fs");
  const path = require("path");
  const alertsJs = fs.readFileSync(path.join(__dirname, "../netlify/functions/alerts.js"), "utf8");
  assert(alertsJs.includes("BERA"), "BERA ticker present in alerts.js CGMAP");
  assert(alertsJs.includes("berachain-bgt"), "berachain-bgt ID present in alerts.js CGMAP");
  assert(alertsJs.includes("IO:"), "IO ticker present in alerts.js CGMAP");
  assert(alertsJs.includes("io-net"), "io-net ID present in alerts.js CGMAP");
  assert(alertsJs.includes("GRASS"), "GRASS ticker present in alerts.js CGMAP");
  assert(alertsJs.includes("POL"), "POL ticker present in alerts.js CGMAP");
}

// ─────────────────────────────────────────────────────────────────────────────
// generate: getBlobStore must be imported at module level, not inside handler
// ─────────────────────────────────────────────────────────────────────────────

console.log("\n--- generate: getBlobStore module-level import ---");
{
  const fs = require("fs");
  const path = require("path");
  const src = fs.readFileSync(path.join(__dirname, "../netlify/functions/generate.js"), "utf8");
  const lines = src.split("\n");
  const importLine = lines.findIndex(l => l.includes("getStore") && l.includes("@netlify/blobs"));
  assert(importLine >= 0, "getStore imported from @netlify/blobs");
  const handlerLine = lines.findIndex(l => l.includes("exports.handler"));
  assert(importLine < handlerLine, "getStore import appears before exports.handler (module-level)");
  const importCount = lines.filter(l => l.includes("getStore") && l.includes("@netlify/blobs")).length;
  assert(importCount === 1, "only one getStore import — not duplicated inside handler");
}

// ─────────────────────────────────────────────────────────────────────────────
// macro: buildMacroContext includes dataAgeInDays
// ─────────────────────────────────────────────────────────────────────────────

console.log("\n--- macro: buildMacroContext includes dataAgeInDays ---");
{
  const fs = require("fs");
  const path = require("path");
  const src = fs.readFileSync(path.join(__dirname, "../macro.js"), "utf8");
  assert(src.includes("dataAgeInDays"), "macro.js buildMacroContext exports dataAgeInDays field");
  assert(src.includes("macroDataAge()"), "dataAgeInDays is computed from macroDataAge()");
}

// ─────────────────────────────────────────────────────────────────────────────
// alerts: cgId — ticker-to-CoinGecko-ID resolution
// ─────────────────────────────────────────────────────────────────────────────

const { cgId } = require("../netlify/functions/alerts");

console.log("\n--- alerts: cgId ---");
{
  assert(cgId("BTC") === "bitcoin", "BTC → bitcoin");
  assert(cgId("ETH") === "ethereum", "ETH → ethereum");
  assert(cgId("SOL") === "solana", "SOL → solana");
  assert(cgId("HYPE") === "hyperliquid", "HYPE → hyperliquid");
  assert(cgId("BERA") === "berachain-bgt", "BERA → berachain-bgt");
  assert(cgId("POL") === "matic-network", "POL → matic-network (same as MATIC)");

  assert(cgId("btc") === "bitcoin", "lowercase btc → bitcoin");
  assert(cgId("Eth") === "ethereum", "mixed-case Eth → ethereum");

  assert(cgId("unknown-token") === "unknown-token", "valid CG-safe unknown ticker passes through");
  assert(cgId("my-token-123") === "my-token-123", "hyphenated token ID passes through");

  assert(cgId("TICKER!@#") === null, "ticker with special chars returns null");
  assert(cgId("Bad Token") === null, "ticker with space returns null");
  assert(cgId("TICKER/") === null, "ticker with slash returns null");
}

// ─────────────────────────────────────────────────────────────────────────────
// market: trend_reversal transform logic
// ─────────────────────────────────────────────────────────────────────────────

function trendReversalTransform(data) {
  if (!Array.isArray(data)) return data;
  const recovering = [];
  const fading = [];
  data.forEach(function (c) {
    if (!c.market_cap || c.market_cap < 50e6) return;
    const d1 = c.price_change_percentage_24h;
    const d7 = c.price_change_percentage_7d_in_currency;
    if (typeof d1 !== "number" || typeof d7 !== "number") return;
    const item = {
      id: c.id,
      symbol: (c.symbol || "").toUpperCase(),
      name: c.name,
      price: c.current_price,
      market_cap: c.market_cap,
      change_24h: d1,
      change_7d: d7,
      change_30d: c.price_change_percentage_30d_in_currency,
    };
    if (d1 > 2 && d7 < -5) recovering.push(item);
    else if (d1 < -2 && d7 > 5) fading.push(item);
  });
  return {
    recovering: recovering.sort(function (a, b) { return b.change_24h - a.change_24h; }).slice(0, 15),
    fading: fading.sort(function (a, b) { return a.change_24h - b.change_24h; }).slice(0, 15),
  };
}

console.log("\n--- market: trend_reversal transform ---");
{
  const coins = [
    { id: "token-a", symbol: "TKA", name: "Token A", current_price: 1.0, market_cap: 200e6, price_change_percentage_24h: 5.0, price_change_percentage_7d_in_currency: -10.0, price_change_percentage_30d_in_currency: -15.0 },
    { id: "token-b", symbol: "TKB", name: "Token B", current_price: 2.0, market_cap: 150e6, price_change_percentage_24h: -5.0, price_change_percentage_7d_in_currency: 15.0, price_change_percentage_30d_in_currency: 20.0 },
    { id: "token-c", symbol: "TKC", name: "Token C", current_price: 3.0, market_cap: 500e6, price_change_percentage_24h: 1.0, price_change_percentage_7d_in_currency: -20.0, price_change_percentage_30d_in_currency: -25.0 },
    { id: "token-d", symbol: "TKD", name: "Token D", current_price: 4.0, market_cap: 10e6, price_change_percentage_24h: 10.0, price_change_percentage_7d_in_currency: -20.0, price_change_percentage_30d_in_currency: -30.0 },
    { id: "token-e", symbol: "TKE", name: "Token E", current_price: 5.0, market_cap: 300e6, price_change_percentage_24h: null, price_change_percentage_7d_in_currency: -10.0, price_change_percentage_30d_in_currency: null },
  ];

  const result = trendReversalTransform(coins);

  assert(typeof result === "object" && !Array.isArray(result), "result is an object with two keys");
  assert(Array.isArray(result.recovering), "recovering is an array");
  assert(Array.isArray(result.fading), "fading is an array");
  assert(result.recovering.length === 1, "one recovering coin (token-a meets thresholds)");
  assert(result.recovering[0].symbol === "TKA", "recovering coin is TKA");
  assert(result.fading.length === 1, "one fading coin (token-b meets thresholds)");
  assert(result.fading[0].symbol === "TKB", "fading coin is TKB");
  assert(!result.recovering.find(function (x) { return x.symbol === "TKC"; }), "token-c excluded (24h below +2% threshold)");
  assert(!result.recovering.find(function (x) { return x.symbol === "TKD"; }), "token-d excluded (market cap below 50M)");
  assert(!result.recovering.find(function (x) { return x.symbol === "TKE"; }), "token-e excluded (null 24h)");

  const emptyResult = trendReversalTransform([]);
  assert(emptyResult.recovering.length === 0 && emptyResult.fading.length === 0, "empty input returns empty arrays");
  assert(trendReversalTransform(null) === null, "null passthrough");
}

// ─────────────────────────────────────────────────────────────────────────────
// market: momentum transform logic
// ─────────────────────────────────────────────────────────────────────────────

function momentumTransform(data) {
  if (!Array.isArray(data)) return data;
  return data
    .filter(function (c) {
      return typeof c.price_change_percentage_7d_in_currency === "number" &&
        typeof c.price_change_percentage_30d_in_currency === "number" &&
        c.price_change_percentage_7d_in_currency > 0 &&
        c.price_change_percentage_30d_in_currency > 0 &&
        c.market_cap > 50e6;
    })
    .map(function (c) {
      const change7d = c.price_change_percentage_7d_in_currency;
      const change30d = c.price_change_percentage_30d_in_currency;
      return {
        id: c.id,
        symbol: (c.symbol || "").toUpperCase(),
        name: c.name,
        price: c.current_price,
        market_cap: c.market_cap,
        change_7d: change7d,
        change_30d: change30d,
        momentum_score: (change7d * 0.4) + (change30d * 0.6),
      };
    })
    .sort(function (a, b) { return b.momentum_score - a.momentum_score; })
    .slice(0, 25);
}

console.log("\n--- market: momentum transform ---");
{
  const coins = [
    { id: "coin-a", symbol: "CA", name: "Coin A", current_price: 10, market_cap: 200e6, price_change_percentage_7d_in_currency: 20, price_change_percentage_30d_in_currency: 50 },
    { id: "coin-b", symbol: "CB", name: "Coin B", current_price: 5,  market_cap: 100e6, price_change_percentage_7d_in_currency: 5,  price_change_percentage_30d_in_currency: 15 },
    { id: "coin-c", symbol: "CC", name: "Coin C", current_price: 2,  market_cap: 500e6, price_change_percentage_7d_in_currency: -3, price_change_percentage_30d_in_currency: 10 },
    { id: "coin-d", symbol: "CD", name: "Coin D", current_price: 1,  market_cap: 30e6,  price_change_percentage_7d_in_currency: 30, price_change_percentage_30d_in_currency: 60 },
    { id: "coin-e", symbol: "CE", name: "Coin E", current_price: 3,  market_cap: 150e6, price_change_percentage_7d_in_currency: 10, price_change_percentage_30d_in_currency: -5 },
  ];

  const result = momentumTransform(coins);

  assert(result.length === 2, "only coins with both 7d and 30d positive and mcap > 50M qualify");
  assert(result[0].symbol === "CA", "coin-a ranked first (higher momentum_score)");
  assert(result[1].symbol === "CB", "coin-b ranked second");

  const expectedScoreA = (20 * 0.4) + (50 * 0.6);
  const expectedScoreB = (5 * 0.4) + (15 * 0.6);
  assert(approx(result[0].momentum_score, expectedScoreA), "coin-a momentum_score = (20*0.4)+(50*0.6) = 38");
  assert(approx(result[1].momentum_score, expectedScoreB), "coin-b momentum_score = (5*0.4)+(15*0.6) = 11");
  assert(typeof result[0].change_7d === "number" && typeof result[0].change_30d === "number", "change_7d and change_30d present");
  assert(typeof result[0].market_cap === "number", "market_cap present");
  assert(momentumTransform([]) !== null && momentumTransform([]).length === 0, "empty array returns empty");
  assert(momentumTransform(null) === null, "null passthrough");

  const manyCoins = Array.from({ length: 30 }, function (_, i) {
    return { id: "t" + i, symbol: "T" + i, name: "T" + i, current_price: 1, market_cap: 100e6,
      price_change_percentage_7d_in_currency: i + 1, price_change_percentage_30d_in_currency: i + 1 };
  });
  const capped = momentumTransform(manyCoins);
  assert(capped.length === 25, "result capped at 25 coins");
  assert(capped[0].momentum_score >= capped[capped.length - 1].momentum_score, "sorted descending by momentum_score");
}

// ─────────────────────────────────────────────────────────────────────────────
// market: ath_nearby momentum_score field
// ─────────────────────────────────────────────────────────────────────────────

function athNearbyWithMomentum(data) {
  if (!Array.isArray(data)) return data;
  return data
    .filter(function (c) {
      return typeof c.ath_change_percentage === "number" && c.ath_change_percentage >= -20;
    })
    .map(function (c) {
      const c7d = c.price_change_percentage_7d_in_currency || 0;
      const c30d = c.price_change_percentage_30d_in_currency || 0;
      return {
        id: c.id,
        symbol: (c.symbol || "").toUpperCase(),
        name: c.name,
        price: c.current_price,
        ath: c.ath,
        ath_change_pct: c.ath_change_percentage,
        market_cap: c.market_cap,
        change_7d: c.price_change_percentage_7d_in_currency,
        change_30d: c.price_change_percentage_30d_in_currency,
        momentum_score: parseFloat(((c7d * 0.4) + (c30d * 0.6)).toFixed(2)),
      };
    })
    .sort(function (a, b) { return b.ath_change_pct - a.ath_change_pct; });
}

console.log("\n--- market: ath_nearby momentum_score ---");
{
  const coins = [
    { id: "coin-x", symbol: "cx", name: "X", current_price: 95, ath: 100, ath_change_percentage: -5.0,  market_cap: 1e9, price_change_percentage_7d_in_currency: 10, price_change_percentage_30d_in_currency: 20 },
    { id: "coin-y", symbol: "cy", name: "Y", current_price: 82, ath: 100, ath_change_percentage: -18.0, market_cap: 500e6, price_change_percentage_7d_in_currency: -5, price_change_percentage_30d_in_currency: -10 },
    { id: "coin-z", symbol: "cz", name: "Z", current_price: 60, ath: 100, ath_change_percentage: -40.0, market_cap: 200e6, price_change_percentage_7d_in_currency: 5, price_change_percentage_30d_in_currency: 8 },
  ];

  const result = athNearbyWithMomentum(coins);
  assert(result.length === 2, "coin-z excluded (beyond -20%)");
  assert(result[0].symbol === "CX", "coin-x ranked first (closer to ATH)");

  const expectedX = parseFloat(((10 * 0.4) + (20 * 0.6)).toFixed(2));
  const expectedY = parseFloat(((-5 * 0.4) + (-10 * 0.6)).toFixed(2));
  assert(result[0].momentum_score === expectedX, "coin-x momentum_score: (10*0.4)+(20*0.6)=16");
  assert(result[1].momentum_score === expectedY, "coin-y momentum_score: (-5*0.4)+(-10*0.6)=-8");

  const noChange = [{ id: "nc", symbol: "nc", name: "NC", current_price: 95, ath: 100, ath_change_percentage: -5.0, market_cap: 1e9, price_change_percentage_7d_in_currency: null, price_change_percentage_30d_in_currency: undefined }];
  const ncResult = athNearbyWithMomentum(noChange);
  assert(ncResult.length === 1 && ncResult[0].momentum_score === 0, "null/undefined change fields produce momentum_score of 0");
}

// ─────────────────────────────────────────────────────────────────────────────
// _lib: PLAN_DAILY_CAPS exported and matches both sync and generate values
// ─────────────────────────────────────────────────────────────────────────────

console.log("\n--- _lib: PLAN_DAILY_CAPS export ---");
{
  const lib = require("../netlify/functions/_lib");
  assert(typeof lib.PLAN_DAILY_CAPS === "object", "PLAN_DAILY_CAPS exported from _lib");
  assert(lib.PLAN_DAILY_CAPS.free === 50,   "free cap is 50");
  assert(lib.PLAN_DAILY_CAPS.pro === 500,   "pro cap is 500");
  assert(lib.PLAN_DAILY_CAPS.elite === 1000, "elite cap is 1000");
  assert(lib.PLAN_DAILY_CAPS.advisor === 2000, "advisor cap is 2000");

  const syncJs = require("fs").readFileSync(require("path").join(__dirname, "../netlify/functions/sync.js"), "utf8");
  assert(!syncJs.includes("const PLAN_DAILY_CAPS = {"), "sync.js no longer defines its own PLAN_DAILY_CAPS");
  assert(syncJs.includes("PLAN_DAILY_CAPS"), "sync.js still uses PLAN_DAILY_CAPS (imported from _lib)");

  const generateJs = require("fs").readFileSync(require("path").join(__dirname, "../netlify/functions/generate.js"), "utf8");
  assert(!generateJs.includes("const PLAN_DAILY_CAPS = {"), "generate.js no longer defines its own PLAN_DAILY_CAPS");
  assert(generateJs.includes("PLAN_DAILY_CAPS"), "generate.js still uses PLAN_DAILY_CAPS (imported from _lib)");
}

// ─────────────────────────────────────────────────────────────────────────────
// market: ath_nearby momentum_score present in production market.js
// ─────────────────────────────────────────────────────────────────────────────

console.log("\n--- market: ath_nearby production momentum_score ---");
{
  const marketJs = require("fs").readFileSync(require("path").join(__dirname, "../netlify/functions/market.js"), "utf8");
  assert(marketJs.includes("momentum_score"), "market.js ath_nearby includes momentum_score field");
  assert(marketJs.includes("X-Content-Type-Options"), "market.js CORS includes X-Content-Type-Options: nosniff");
}

// ─────────────────────────────────────────────────────────────────────────────
// track: body size guard present in production track.js
// ─────────────────────────────────────────────────────────────────────────────

console.log("\n--- track: body size guard ---");
{
  const trackJs = require("fs").readFileSync(require("path").join(__dirname, "../netlify/functions/track.js"), "utf8");
  assert(trackJs.includes("MAX_BODY_BYTES"), "track.js defines MAX_BODY_BYTES guard");
  assert(trackJs.includes("2048"), "MAX_BODY_BYTES is set to 2048");
}

// ─────────────────────────────────────────────────────────────────────────────
// alerts: portfolio drawdown calculation
// ─────────────────────────────────────────────────────────────────────────────

function computeDrawdownPct(currentValue, peakValue) {
  if (!peakValue || peakValue <= 0) return 0;
  return (peakValue - currentValue) / peakValue * 100;
}

console.log("\n--- alerts: portfolio drawdown calculation ---");
{
  assert(approx(computeDrawdownPct(70000, 100000), 30), "30% drawdown from 100k to 70k");
  assert(approx(computeDrawdownPct(50000, 100000), 50), "50% drawdown from 100k to 50k");
  assert(approx(computeDrawdownPct(100000, 100000), 0), "0% drawdown when at peak");
  assert(approx(computeDrawdownPct(110000, 100000), -10), "negative drawdown when above peak");
  assert(computeDrawdownPct(50000, 0) === 0, "zero peak returns 0% drawdown");
  assert(computeDrawdownPct(50000, null) === 0, "null peak returns 0% drawdown");

  const peakAbove30 = 100000;
  assert(computeDrawdownPct(69000, peakAbove30) >= 30, "69k triggers 30% drawdown alert");
  assert(computeDrawdownPct(86000, peakAbove30) < 15, "86k clears re-arm threshold (< 15% drawdown)");
  assert(computeDrawdownPct(85000, peakAbove30) >= 15, "85k does not yet clear re-arm threshold");
}

// ─────────────────────────────────────────────────────────────────────────────
// auth: email domain validation
// ─────────────────────────────────────────────────────────────────────────────

function isValidAuthEmail(email) {
  const e = String(email || "").trim().toLowerCase();
  const atIdx = e.indexOf("@");
  const domain = atIdx > 0 ? e.slice(atIdx + 1) : "";
  return !(!e || atIdx < 1 || e.length > 200 || !domain.includes(".") || domain.endsWith("."));
}

console.log("\n--- auth: email domain validation ---");
{
  assert(isValidAuthEmail("user@example.com") === true, "valid email accepted");
  assert(isValidAuthEmail("user@sub.domain.org") === true, "subdomain email accepted");
  assert(isValidAuthEmail("user@") === false, "email with no domain rejected");
  assert(isValidAuthEmail("user@nodot") === false, "domain with no dot rejected");
  assert(isValidAuthEmail("user@domain.") === false, "domain ending in dot rejected");
  assert(isValidAuthEmail("@example.com") === false, "email starting with @ rejected");
  assert(isValidAuthEmail("") === false, "empty string rejected");
  assert(isValidAuthEmail("notanemail") === false, "no @ rejected");
  assert(isValidAuthEmail("a@b.c") === true, "minimal valid email accepted");
  assert(isValidAuthEmail("A@B.C") === true, "uppercase normalised and accepted");
}

// ─────────────────────────────────────────────────────────────────────────────
// alerts: parallel user load (production alerts.js uses Promise.allSettled)
// ─────────────────────────────────────────────────────────────────────────────

console.log("\n--- alerts: parallel user load structure ---");
{
  const fs = require("fs");
  const path = require("path");
  const alertsJs = fs.readFileSync(path.join(__dirname, "../netlify/functions/alerts.js"), "utf8");
  assert(alertsJs.includes("Promise.allSettled"), "alerts.js uses Promise.allSettled for parallel user loading");
  assert(!alertsJs.includes("for (const email of users)"), "sequential for-of-await over users removed");
  assert(alertsJs.includes("LOAD_BATCH"), "LOAD_BATCH constant defined for batch size");
}

// ─────────────────────────────────────────────────────────────────────────────
// sync: stripServerFlags strips root-level server flags (production file check)
// ─────────────────────────────────────────────────────────────────────────────

console.log("\n--- sync: root server flags in production sync.js ---");
{
  const fs = require("fs");
  const path = require("path");
  const syncJs = fs.readFileSync(path.join(__dirname, "../netlify/functions/sync.js"), "utf8");
  assert(syncJs.includes("ROOT_SERVER_FLAGS"), "sync.js defines ROOT_SERVER_FLAGS for root-level stripping");
  assert(syncJs.includes("portfolioPeak"), "portfolioPeak included in root server flags");
  assert(syncJs.includes("serverDrawdownAlerted"), "serverDrawdownAlerted included in server flags");
}

// ─────────────────────────────────────────────────────────────────────────────
// alerts: serverDcaRung flag present in sync.js server flags
// ─────────────────────────────────────────────────────────────────────────────

console.log("\n--- alerts: serverDcaRung in sync.js SERVER_ALERT_FLAGS ---");
{
  const fs = require("fs");
  const path = require("path");
  const syncJs = fs.readFileSync(path.join(__dirname, "../netlify/functions/sync.js"), "utf8");
  assert(syncJs.includes("serverDcaRung"), "sync.js includes serverDcaRung in SERVER_ALERT_FLAGS");
}

// ─────────────────────────────────────────────────────────────────────────────
// alerts: DCA rung logic
// ─────────────────────────────────────────────────────────────────────────────

function computeDcaRung(avg, price) {
  if (!avg || avg <= 0 || !price) return 0;
  const lossFromAvg = (avg - price) / avg * 100;
  return lossFromAvg >= 60 ? 3 : lossFromAvg >= 40 ? 2 : lossFromAvg >= 20 ? 1 : 0;
}

console.log("\n--- alerts: DCA rung computation ---");
{
  assert(computeDcaRung(100, 81) === 0, "19% loss: no DCA rung");
  assert(computeDcaRung(100, 80) === 1, "20% loss: rung 1");
  assert(computeDcaRung(100, 60) === 2, "40% loss: rung 2");
  assert(computeDcaRung(100, 40) === 3, "60% loss: rung 3");
  assert(computeDcaRung(100, 39) === 3, "61% loss: rung 3");
  assert(computeDcaRung(0, 50) === 0, "avg=0: no rung");
  assert(computeDcaRung(100, 120) === 0, "price above avg: no rung");
}

// ─────────────────────────────────────────────────────────────────────────────
// market: btc_alt_divergence endpoint present in production market.js
// ─────────────────────────────────────────────────────────────────────────────

console.log("\n--- market: btc_alt_divergence endpoint ---");
{
  const fs = require("fs");
  const path = require("path");
  const marketJs = fs.readFileSync(path.join(__dirname, "../netlify/functions/market.js"), "utf8");
  assert(marketJs.includes("btc_alt_divergence"), "market.js has btc_alt_divergence kind");
  assert(marketJs.includes("rotation_signal"), "btc_alt_divergence returns rotation_signal");
  assert(marketJs.includes("altseason"), "btc_alt_divergence includes altseason signal");
  assert(marketJs.includes("btc_dominance"), "btc_alt_divergence includes btc_dominance signal");
}

// ─────────────────────────────────────────────────────────────────────────────
// market: btc_alt_divergence transform logic
// ─────────────────────────────────────────────────────────────────────────────

function btcAltDivergenceTransform(data) {
  if (!Array.isArray(data)) return data;
  const btc = data.find(function (c) { return c.id === "bitcoin"; });
  if (!btc) return { error: "bitcoin data unavailable" };
  const alts = data.filter(function (c) {
    return c.id !== "bitcoin" && c.market_cap > 500e6 &&
      typeof c.price_change_percentage_7d_in_currency === "number" &&
      typeof c.price_change_percentage_30d_in_currency === "number";
  });
  const avg7d = alts.length
    ? alts.reduce(function (s, c) { return s + c.price_change_percentage_7d_in_currency; }, 0) / alts.length
    : null;
  const avg30d = alts.length
    ? alts.reduce(function (s, c) { return s + c.price_change_percentage_30d_in_currency; }, 0) / alts.length
    : null;
  const btc7d = btc.price_change_percentage_7d_in_currency;
  const btc30d = btc.price_change_percentage_30d_in_currency;
  const alt_out_7d = avg7d !== null ? avg7d - btc7d : null;
  const alt_out_30d = avg30d !== null ? avg30d - btc30d : null;
  let rotation_signal = "neutral";
  if (alt_out_7d !== null && alt_out_30d !== null) {
    if (alt_out_7d > 5 && alt_out_30d > 5) rotation_signal = "altseason";
    else if (alt_out_7d > 2) rotation_signal = "alts_leading";
    else if (alt_out_7d < -5 && alt_out_30d < -5) rotation_signal = "btc_dominance";
    else if (alt_out_7d < -2) rotation_signal = "btc_leading";
  }
  return {
    btc: { price: btc.current_price, change_7d: btc7d, change_30d: btc30d, market_cap: btc.market_cap },
    alt_basket: { count: alts.length, avg_change_7d: avg7d !== null ? parseFloat(avg7d.toFixed(2)) : null, avg_change_30d: avg30d !== null ? parseFloat(avg30d.toFixed(2)) : null },
    alt_outperformance_7d: alt_out_7d !== null ? parseFloat(alt_out_7d.toFixed(2)) : null,
    alt_outperformance_30d: alt_out_30d !== null ? parseFloat(alt_out_30d.toFixed(2)) : null,
    rotation_signal: rotation_signal,
  };
}

console.log("\n--- market: btc_alt_divergence transform ---");
{
  const coins = [
    { id: "bitcoin", current_price: 82000, market_cap: 1.6e12, price_change_percentage_7d_in_currency: 2.0, price_change_percentage_30d_in_currency: 5.0 },
    { id: "ethereum", current_price: 3200, market_cap: 384e9, price_change_percentage_7d_in_currency: 10.0, price_change_percentage_30d_in_currency: 18.0 },
    { id: "solana", current_price: 180, market_cap: 87e9, price_change_percentage_7d_in_currency: 12.0, price_change_percentage_30d_in_currency: 20.0 },
    { id: "micro-cap", current_price: 0.001, market_cap: 100e6, price_change_percentage_7d_in_currency: 50.0, price_change_percentage_30d_in_currency: 100.0 },
  ];

  const result = btcAltDivergenceTransform(coins);
  assert(result.btc.change_7d === 2.0, "btc 7d change extracted");
  assert(result.alt_basket.count === 2, "micro-cap excluded, 2 qualifying alts");
  // avg alt 7d = (10 + 12) / 2 = 11, btc 7d = 2, outperformance = 9
  assert(result.alt_outperformance_7d === 9, "alt outperformance 7d = (10+12)/2 - 2 = 9");
  assert(result.rotation_signal === "altseason", "alt_out_7d=9 > 5 and alt_out_30d=14 > 5 → altseason");

  const btcDomCoins = [
    { id: "bitcoin", current_price: 90000, market_cap: 1.8e12, price_change_percentage_7d_in_currency: 15.0, price_change_percentage_30d_in_currency: 30.0 },
    { id: "ethereum", current_price: 2800, market_cap: 336e9, price_change_percentage_7d_in_currency: 5.0, price_change_percentage_30d_in_currency: 10.0 },
  ];
  const dom = btcAltDivergenceTransform(btcDomCoins);
  // alt_out_7d = 5 - 15 = -10, alt_out_30d = 10 - 30 = -20 → btc_dominance
  assert(dom.rotation_signal === "btc_dominance", "strongly negative alt outperformance → btc_dominance");

  const neutralCoins = [
    { id: "bitcoin", current_price: 80000, market_cap: 1.5e12, price_change_percentage_7d_in_currency: 3.0, price_change_percentage_30d_in_currency: 8.0 },
    { id: "ethereum", current_price: 3000, market_cap: 360e9, price_change_percentage_7d_in_currency: 4.5, price_change_percentage_30d_in_currency: 10.0 },
  ];
  const neut = btcAltDivergenceTransform(neutralCoins);
  // alt_out_7d = 4.5 - 3 = 1.5 (between -2 and +2) → neutral
  assert(neut.rotation_signal === "neutral", "outperformance between -2 and +2 → neutral");

  assert(btcAltDivergenceTransform([]).error === "bitcoin data unavailable", "no bitcoin data returns error");
  assert(btcAltDivergenceTransform(null) === null, "null passthrough");
}

// ─────────────────────────────────────────────────────────────────────────────
// alerts: DCA html function and dcaRung stripping in sync.js
// ─────────────────────────────────────────────────────────────────────────────

console.log("\n--- alerts: dcaAlertHtml and serverDcaRung strip in production ---");
{
  const fs = require("fs");
  const path = require("path");
  const alertsJs = fs.readFileSync(path.join(__dirname, "../netlify/functions/alerts.js"), "utf8");
  assert(alertsJs.includes("dcaAlertHtml"), "alerts.js defines dcaAlertHtml");
  assert(alertsJs.includes("serverDcaRung"), "alerts.js uses serverDcaRung flag");
  assert(alertsJs.includes("DCA opportunity"), "DCA alert has recognisable subject/heading");
}

// ─────────────────────────────────────────────────────────────────────────────
// _lib: esc() — XSS escaping
// ─────────────────────────────────────────────────────────────────────────────

const { esc } = require("../netlify/functions/_lib");

console.log("\n--- _lib: esc() XSS escaping ---");
{
  assert(esc("<script>alert(1)</script>") === "&lt;script&gt;alert(1)&lt;/script&gt;", "< and > escaped");
  assert(esc('"hello"') === "&quot;hello&quot;", "double quotes escaped");
  assert(esc("it's") === "it&#x27;s", "single quotes escaped");
  assert(esc("a&b") === "a&amp;b", "ampersand escaped");
  assert(esc("safe text") === "safe text", "plain text unchanged");
  assert(esc("") === "", "empty string unchanged");
  assert(esc(123) === "123", "non-string coerced to string");
  assert(esc("<>&\"'") === "&lt;&gt;&amp;&quot;&#x27;", "all special chars escaped in one pass");
}

// ─────────────────────────────────────────────────────────────────────────────
// _lib: signUnsub / verifyUnsub
// ─────────────────────────────────────────────────────────────────────────────

const { signUnsub, verifyUnsub } = require("../netlify/functions/_lib");

console.log("\n--- _lib: signUnsub / verifyUnsub ---");
{
  const origSecret = process.env.AUTH_SECRET;
  process.env.AUTH_SECRET = "test-unsub-secret";

  const tok = signUnsub("user@example.com");
  assert(typeof tok === "string" && tok.length > 0, "signUnsub returns non-empty string");
  assert(verifyUnsub("user@example.com", tok) === true, "verifyUnsub accepts valid token");
  assert(verifyUnsub("other@example.com", tok) === false, "verifyUnsub rejects wrong email");
  assert(verifyUnsub("user@example.com", tok + "x") === false, "verifyUnsub rejects tampered token");
  assert(verifyUnsub("user@example.com", "") === false, "verifyUnsub rejects empty token");
  assert(verifyUnsub("user@example.com", null) === false, "verifyUnsub rejects null token");

  // Token from signUnsub cannot be reused as an auth token (different prefix)
  const tok2 = signUnsub("another@example.com");
  assert(tok !== tok2, "different emails produce different tokens");

  if (origSecret === undefined) delete process.env.AUTH_SECRET;
  else process.env.AUTH_SECRET = origSecret;

  // Without secret, signUnsub returns null
  const savedSecret = process.env.AUTH_SECRET;
  delete process.env.AUTH_SECRET;
  assert(signUnsub("user@example.com") === null, "signUnsub returns null when AUTH_SECRET absent");
  assert(verifyUnsub("user@example.com", "anytoken") === false, "verifyUnsub returns false when AUTH_SECRET absent");
  if (savedSecret !== undefined) process.env.AUTH_SECRET = savedSecret;
}

// ─────────────────────────────────────────────────────────────────────────────
// _lib: signToken / verifyToken round-trip (using _lib directly)
// ─────────────────────────────────────────────────────────────────────────────

const { signToken: libSignToken, verifyToken: libVerifyToken } = require("../netlify/functions/_lib");

console.log("\n--- _lib: signToken / verifyToken via module ---");
{
  const origSecret = process.env.AUTH_SECRET;
  process.env.AUTH_SECRET = "test-lib-token-secret";

  const tok = libSignToken("investor@example.com", 30);
  assert(typeof tok === "string" && tok.includes("."), "signToken produces dot-separated token");
  assert(libVerifyToken(tok) === "investor@example.com", "verifyToken returns correct email");

  // Tampered payload
  const parts = tok.split(".");
  const tampered = parts[0] + "X." + parts[1];
  assert(libVerifyToken(tampered) === null, "tampered payload rejected");

  // Tampered signature
  const tamperedSig = parts[0] + "." + parts[1] + "X";
  assert(libVerifyToken(tamperedSig) === null, "tampered signature rejected");

  // No secret
  process.env.AUTH_SECRET = "";
  assert(libVerifyToken(tok) === null, "empty secret rejects any token");

  if (origSecret === undefined) delete process.env.AUTH_SECRET;
  else process.env.AUTH_SECRET = origSecret;
}

// ─────────────────────────────────────────────────────────────────────────────
// alerts: Q4 2026 CGMAP additions
// ─────────────────────────────────────────────────────────────────────────────

console.log("\n--- alerts: Q4 2026 CGMAP entries ---");
{
  const fs = require("fs");
  const path = require("path");
  const alertsJs = fs.readFileSync(path.join(__dirname, "../netlify/functions/alerts.js"), "utf8");
  assert(alertsJs.includes("PENGU"), "PENGU ticker present in alerts.js CGMAP");
  assert(alertsJs.includes("pudgy-penguins"), "pudgy-penguins ID present in alerts.js CGMAP");
  assert(alertsJs.includes("ZRO"), "ZRO ticker present in alerts.js CGMAP");
  assert(alertsJs.includes("layerzero"), "layerzero ID present in alerts.js CGMAP");
  assert(alertsJs.includes("SPX"), "SPX ticker present in alerts.js CGMAP");
}

// ─────────────────────────────────────────────────────────────────────────────
// macro: FOMC catalyst is now in the past (post-Oct 28 FOMC)
// ─────────────────────────────────────────────────────────────────────────────

console.log("\n--- macro: FOMC catalyst is past ---");
{
  const macro = require("../macro.js");
  const fomcCatalyst = macro.MACRO_DATA.catalysts.find(function (c) {
    return c.n === "FOMC decision";
  });
  assert(fomcCatalyst !== undefined, "FOMC decision catalyst found in MACRO_DATA");
  if (fomcCatalyst) {
    const fomcMs = new Date(fomcCatalyst.d).getTime();
    assert(fomcMs < Date.now(), "FOMC Oct-28 catalyst date is in the past");
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// macro: confidence increased post-FOMC (binary resolved)
// ─────────────────────────────────────────────────────────────────────────────

console.log("\n--- macro: regime confidence post-FOMC ---");
{
  const macro = require("../macro.js");
  const conf = macro.MACRO_DATA.current.confidence;
  assert(typeof conf === "number" && conf >= 0 && conf <= 100, "confidence is a valid 0-100 number");
  assert(conf >= 80, "confidence raised above 80 after FOMC event-risk resolved");
}

// ─────────────────────────────────────────────────────────────────────────────
// alerts: computeLadder regime-aware rung boundary tests
// ─────────────────────────────────────────────────────────────────────────────

function computeLadder2(avg, qty, price, regime) {
  if (!avg || avg <= 0 || !qty || qty <= 0) return null;
  const gainPct = (price - avg) / avg * 100;
  if (gainPct < 10) return null;
  const rungs = (function regimeLadderRungs(r) {
    if (r === "longend" || r === "squeeze") return [15, 30, 60, 100];
    return [25, 50, 100, 200];
  })(regime).map(function (pc) {
    const ladderPrice = avg * (1 + pc / 100);
    return { pct: pc, price: ladderPrice, qty: qty * 0.25, hit: price >= ladderPrice };
  });
  return { gainPct: gainPct, rungs: rungs, hits: rungs.filter(function (r) { return r.hit; }) };
}

console.log("\n--- alerts: computeLadder regime boundaries ---");
{
  // longend regime: tighter rungs [15, 30, 60, 100]
  const longend20 = computeLadder2(100, 4, 120, "longend");
  assert(longend20 !== null, "20% gain in longend returns ladder");
  assert(longend20.rungs[0].pct === 15, "first longend rung at 15%");
  assert(longend20.hits.length === 1, "one rung hit at 20% gain in longend (only 15% rung)");

  // liquidity regime: standard rungs [25, 50, 100, 200]
  const liquidity20 = computeLadder2(100, 4, 120, "liquidity");
  assert(liquidity20 !== null, "20% gain in liquidity returns ladder");
  assert(liquidity20.rungs[0].pct === 25, "first liquidity rung at 25%");
  assert(liquidity20.hits.length === 0, "no rungs hit at 20% gain in liquidity (first rung is 25%)");

  // boundary: exactly at rung threshold
  const atRung = computeLadder2(100, 4, 115, "longend");
  assert(atRung !== null && atRung.hits.length === 1, "exactly at +15% rung in longend: one hit");

  const justBelow = computeLadder2(100, 4, 114.9, "longend");
  assert(justBelow !== null && justBelow.hits.length === 0, "just below +15% rung: no hit");
}

// ─────────────────────────────────────────────────────────────────────────────
// generate: max_tokens plan caps are ordered correctly
// ─────────────────────────────────────────────────────────────────────────────

console.log("\n--- generate: PLAN_TOKEN_CAPS ordering ---");
{
  const fs = require("fs");
  const path = require("path");
  const src = fs.readFileSync(path.join(__dirname, "../netlify/functions/generate.js"), "utf8");
  // Extract PLAN_TOKEN_CAPS values
  const freeMatch = src.match(/free:\s*(\d+)/);
  const proMatch  = src.match(/pro:\s*(\d+)/);
  const eliteMatch = src.match(/elite:\s*(\d+)/);
  const advisorMatch = src.match(/advisor:\s*(\d+)/);
  assert(freeMatch && proMatch && eliteMatch && advisorMatch, "PLAN_TOKEN_CAPS has all four plans in generate.js");
  if (freeMatch && proMatch && eliteMatch && advisorMatch) {
    const free = parseInt(freeMatch[1], 10);
    const pro  = parseInt(proMatch[1], 10);
    const elite = parseInt(eliteMatch[1], 10);
    const adv  = parseInt(advisorMatch[1], 10);
    assert(free < pro, "pro token cap > free cap");
    assert(pro < elite, "elite token cap > pro cap");
    assert(elite < adv, "advisor token cap > elite cap");
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// _lib: verifyToken rejects token for wrong email without AUTH_SECRET leak
// ─────────────────────────────────────────────────────────────────────────────

console.log("\n--- _lib: verifyToken cross-email rejection ---");
{
  const origSecret = process.env.AUTH_SECRET;
  process.env.AUTH_SECRET = "cross-email-test-secret";
  const { signToken, verifyToken } = require("../netlify/functions/_lib");

  const tok = signToken("alice@example.com", 7);
  assert(verifyToken(tok) === "alice@example.com", "own token verifies correctly");
  // Attempt to use the same token structure but for a different email
  const parts = tok.split(".");
  const fakePayload = Buffer.from("bob@example.com|" + (Date.now() + 864e5 * 7)).toString("base64url");
  const fakeTok = fakePayload + "." + parts[1];
  assert(verifyToken(fakeTok) === null, "token with mismatched payload+signature rejected");

  if (origSecret === undefined) delete process.env.AUTH_SECRET;
  else process.env.AUTH_SECRET = origSecret;
}

// ─────────────────────────────────────────────────────────────────────────────
// Summary
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n══════════════════════════════════════");
console.log(passed + " passed, " + failed + " failed");
if (failed > 0) { console.error("SOME TESTS FAILED"); process.exit(1); }
else { console.log("All tests passed."); }
