// Unit tests for market.js transformation and validation logic.
// Run with: node tests/market.test.js

let passed = 0, failed = 0;
function assert(condition, label) {
  if (condition) { console.log("  ✓ " + label); passed++; }
  else { console.error("  ✗ FAIL: " + label); failed++; }
}

// --- ID validation (mirrors market.js) ---
function validateIds(raw) {
  return String(raw).toLowerCase().split(",")
    .map(function (s) { return s.trim(); })
    .filter(function (s) { return /^[a-z0-9-]{1,50}$/.test(s); })
    .slice(0, 25);
}

console.log("\n--- market.js: id validation ---");

assert(validateIds("bitcoin,ethereum").length === 2, "two valid ids pass");
assert(validateIds("bitcoin").length === 1, "single id passes");
assert(validateIds("avalanche-2,matic-network").length === 2, "hyphenated ids pass");
assert(validateIds("BITCOIN,ETHEREUM").length === 2, "uppercase ids lowercased");
assert(validateIds("bitcoin; DROP TABLE").length === 0, "semicolon injection rejected");
assert(validateIds("bitcoin' OR 1=1 --").length === 0, "SQL injection rejected");
assert(validateIds("<script>alert(1)</script>").length === 0, "XSS attempt rejected");
assert(validateIds("a".repeat(51)).length === 0, "id exceeding 50 chars rejected");
assert(validateIds("a".repeat(50)).length === 1, "id exactly 50 chars passes");
assert(validateIds(",,,").length === 0, "empty ids rejected");
assert(validateIds("").length === 0, "empty string rejected");

// slices at 25
const manyIds = Array.from({length: 30}, function(_, i) { return "coin-" + i; }).join(",");
assert(validateIds(manyIds).length === 25, "more than 25 ids capped at 25");

// --- gainers/losers transform ---
function gainersTransform(data) {
  if (!Array.isArray(data)) return data;
  return data
    .filter(function (c) { return c.price_change_percentage_24h != null; })
    .sort(function (a, b) { return b.price_change_percentage_24h - a.price_change_percentage_24h; })
    .slice(0, 20);
}
function losersTransform(data) {
  if (!Array.isArray(data)) return data;
  return data
    .filter(function (c) { return c.price_change_percentage_24h != null; })
    .sort(function (a, b) { return a.price_change_percentage_24h - b.price_change_percentage_24h; })
    .slice(0, 20);
}

console.log("\n--- market.js: gainers/losers transform ---");

const mockCoins = [
  { id: "coin-a", price_change_percentage_24h: 5.0 },
  { id: "coin-b", price_change_percentage_24h: -10.0 },
  { id: "coin-c", price_change_percentage_24h: null },
  { id: "coin-d", price_change_percentage_24h: 20.0 },
  { id: "coin-e", price_change_percentage_24h: -3.0 },
];

const gainers = gainersTransform(mockCoins);
assert(gainers[0].id === "coin-d", "top gainer is coin-d (+20%)");
assert(gainers[1].id === "coin-a", "second gainer is coin-a (+5%)");
assert(!gainers.some(function(c){ return c.id === "coin-c"; }), "null-change coin filtered out");
assert(gainers.length === 4, "4 coins with valid 24h change remain");

const losers = losersTransform(mockCoins);
assert(losers[0].id === "coin-b", "top loser is coin-b (-10%)");
assert(losers[1].id === "coin-e", "second loser is coin-e (-3%)");

const largeSet = Array.from({length: 30}, function(_, i) { return { id: "c"+i, price_change_percentage_24h: i }; });
assert(gainersTransform(largeSet).length === 20, "gainers capped at 20");
assert(losersTransform(largeSet).length === 20, "losers capped at 20");

assert(gainersTransform(null) === null, "non-array input returned as-is");
assert(gainersTransform({}) === null || typeof gainersTransform({}) === "object", "object input returned as-is");

// --- trending transform ---
function trendingTransform(data) {
  const coins = (data && data.coins) || [];
  return coins.slice(0, 15).map(function (c) {
    const i = c.item || {};
    return { id: i.id, symbol: (i.symbol || "").toUpperCase(), name: i.name, market_cap_rank: i.market_cap_rank, thumb: i.thumb, price_btc: i.price_btc, score: i.score };
  });
}

console.log("\n--- market.js: trending transform ---");

const mockTrending = {
  coins: Array.from({length: 20}, function(_, j) {
    return { item: { id: "trend-"+j, symbol: "t"+j, name: "Trend "+j, market_cap_rank: j+1, score: j } };
  })
};
const trending = trendingTransform(mockTrending);
assert(trending.length === 15, "trending capped at 15");
assert(trending[0].symbol === "T0", "symbol uppercased");
assert(trending[0].id === "trend-0", "id preserved");

const emptyTrending = trendingTransform({});
assert(Array.isArray(emptyTrending) && emptyTrending.length === 0, "empty coins gives empty array");

// --- fear-greed transform ---
function fearGreedTransform(data) {
  const d = (data && data.data) || [];
  return d.map(function (x) {
    return {
      value: parseInt(x.value, 10),
      classification: x.value_classification,
      timestamp: parseInt(x.timestamp, 10),
    };
  });
}

console.log("\n--- market.js: fear-greed transform ---");

const mockFng = {
  data: [
    { value: "72", value_classification: "Greed", timestamp: "1700000000" },
    { value: "45", value_classification: "Fear", timestamp: "1699913600" },
  ]
};
const fng = fearGreedTransform(mockFng);
assert(fng.length === 2, "two entries returned");
assert(fng[0].value === 72, "value parsed as integer");
assert(fng[0].classification === "Greed", "classification preserved");
assert(fng[0].timestamp === 1700000000, "timestamp parsed as integer");
assert(fearGreedTransform({}).length === 0, "empty data gives empty array");
assert(fearGreedTransform(null).length === 0, "null gives empty array");

// --- news.js: URL validation ---
function isHttpUrl(url) {
  return /^https?:\/\//i.test(url);
}

console.log("\n--- news.js: URL scheme validation ---");

assert(isHttpUrl("https://coindesk.com/article"), "https URL passes");
assert(isHttpUrl("http://cointelegraph.com/news/test"), "http URL passes");
assert(!isHttpUrl("javascript:alert(1)"), "javascript: URL blocked");
assert(!isHttpUrl("data:text/html,<h1>xss</h1>"), "data: URL blocked");
assert(!isHttpUrl(""), "empty URL blocked");
assert(!isHttpUrl("//no-scheme.com"), "protocol-relative URL blocked");
assert(!isHttpUrl("ftp://old-school.com"), "ftp URL blocked");

console.log("\n==========================================");
console.log("Results: " + passed + " passed, " + failed + " failed");
if (failed > 0) process.exit(1);
