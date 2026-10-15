// Unit tests for BullrunIQ pure utility functions.
// Run with: node tests/unit.test.js
//
// Functions are imported directly from source files so tests verify the
// actual production implementations — not stale copies.

const crypto = require("crypto");
const path = require("path");

const fnDir = path.join(__dirname, "../netlify/functions");

let passed = 0, failed = 0;
function assert(condition, label) {
  if (condition) { console.log("  ✓ " + label); passed++; }
  else { console.error("  ✗ FAIL: " + label); failed++; }
}
function approx(a, b, eps) { return Math.abs(a - b) <= (eps || 0.001); }

// ─────────────────────────────────────────────────────────────────────────────
// stripe-webhook: verifyStripe
// ─────────────────────────────────────────────────────────────────────────────

const { verifyStripe } = require(path.join(fnDir, "stripe-webhook"));

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
// alerts: regimeLadderRungs, computeLadder, shouldResetLadder, cgId
// ─────────────────────────────────────────────────────────────────────────────

const { regimeLadderRungs, computeLadder, shouldResetLadder, cgId } = require(path.join(fnDir, "alerts"));

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

console.log("\n--- alerts: computeLadder ---");
{
  // Below 10% gain → null
  assert(computeLadder(100, 10, 105, "liquidity") === null, "gain < 10% returns null");
  assert(computeLadder(100, 10, 109.9, "liquidity") === null, "gain exactly 9.9% returns null");

  // Exactly at 10% gain → ladder computed
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

console.log("\n--- alerts: cgId ---");
{
  assert(cgId("BTC") === "bitcoin", "BTC resolves to bitcoin");
  assert(cgId("ETH") === "ethereum", "ETH resolves to ethereum");
  assert(cgId("SOL") === "solana", "SOL resolves to solana");
  assert(cgId("btc") === "bitcoin", "lowercase btc resolves to bitcoin");
  // Unknown ticker falls back to lowercase if safe
  assert(cgId("NEWTOKEN") === "newtoken", "unknown safe ticker returns lowercase");
  // Unsafe ticker (special chars) returns null
  assert(cgId("TICK!ER") === null, "ticker with special chars returns null");
  assert(cgId("ABC SPACE") === null, "ticker with space returns null");
}

// ─────────────────────────────────────────────────────────────────────────────
// sync: validateUserData, stripServerFlags
// ─────────────────────────────────────────────────────────────────────────────

const { validateUserData, stripServerFlags } = require(path.join(fnDir, "sync"));

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

const { scoreByTickers, rankByTickers, parseRss } = require(path.join(fnDir, "news"));

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

  // javascript: URLs rejected
  const jsRss = `<rss><channel><item><title>Test</title><link>javascript:alert(1)</link></item></channel></rss>`;
  assert(parseRss(jsRss, "X").length === 0, "javascript: URL rejected");
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
// generate: validateMessages
// ─────────────────────────────────────────────────────────────────────────────

const { validateMessages } = require(path.join(fnDir, "generate"));

console.log("\n--- generate: validateMessages ---");
{
  // Valid cases
  assert(validateMessages([{ role: "user", content: "hello" }]) === true, "single user message valid");
  assert(validateMessages([
    { role: "user", content: "hi" },
    { role: "assistant", content: "hello" },
  ]) === true, "multi-turn conversation valid");

  // Array content with text blocks
  assert(validateMessages([{
    role: "user",
    content: [{ type: "text", text: "hello" }],
  }]) === true, "array content with text block valid");

  // Invalid structures
  assert(validateMessages(null) === false, "null rejected");
  assert(validateMessages([]) === false, "empty array rejected");
  assert(validateMessages("string") === false, "string rejected");
  assert(validateMessages(new Array(41).fill({ role: "user", content: "x" })) === false, "41 messages rejected");
  assert(validateMessages([{ role: "system", content: "x" }]) === false, "system role rejected");
  assert(validateMessages([{ role: "user", content: 42 }]) === false, "numeric content rejected");
  assert(validateMessages([{ role: "user", content: null }]) === false, "null content rejected");

  // Content length limit
  assert(validateMessages([{ role: "user", content: "x".repeat(20001) }]) === false, "content > 20000 chars rejected");
  assert(validateMessages([{ role: "user", content: "x".repeat(20000) }]) === true, "content at 20000 chars accepted");

  // Message count boundary
  assert(validateMessages(new Array(40).fill({ role: "user", content: "x" })) === true, "exactly 40 messages accepted");

  // Array content block validation
  assert(validateMessages([{
    role: "user",
    content: [{ type: "image", source: {} }],
  }]) === true, "image block type accepted");
  assert(validateMessages([{
    role: "user",
    content: [{ type: "evil_type", text: "x" }],
  }]) === false, "unknown block type rejected");
  assert(validateMessages([{
    role: "user",
    content: [{ type: "text", text: 42 }],
  }]) === false, "text block with non-string text rejected");
  assert(validateMessages([{
    role: "user",
    content: ["not an object"],
  }]) === false, "non-object content block rejected");
  assert(validateMessages([{
    role: "user",
    content: new Array(21).fill({ type: "text", text: "x" }),
  }]) === false, "content array > 20 blocks rejected");
  assert(validateMessages([{
    role: "user",
    content: new Array(20).fill({ type: "text", text: "x" }),
  }]) === true, "content array at 20 blocks accepted");
  assert(validateMessages([{
    role: "user",
    content: [{ type: "text", text: "x".repeat(20001) }],
  }]) === false, "text block > 20000 chars rejected");
}

// ─────────────────────────────────────────────────────────────────────────────
// Summary
// ─────────────────────────────────────────────────────────────────────────────
console.log("\n══════════════════════════════════════");
console.log(passed + " passed, " + failed + " failed");
if (failed > 0) { console.error("SOME TESTS FAILED"); process.exit(1); }
else { console.log("All tests passed."); }
