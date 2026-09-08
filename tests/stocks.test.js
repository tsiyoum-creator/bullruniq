// Unit tests for the /api/stocks quote proxy (netlify/functions/stocks.js).
// Run with: node tests/stocks.test.js

let passed = 0, failed = 0;
function assert(condition, label) {
  if (condition) { console.log("  ✓ " + label); passed++; }
  else { console.error("  ✗ FAIL: " + label); failed++; }
}

// Mirrors validateSymbols() in netlify/functions/stocks.js.
const MAX_SYMBOLS = 25;
function validateSymbols(raw) {
  const seen = new Set();
  return String(raw || "").toUpperCase().split(",")
    .map(function (s) { return s.trim(); })
    .filter(function (s) { return /^[A-Z][A-Z0-9.\-]{0,9}$/.test(s); })
    .filter(function (s) { if (seen.has(s)) return false; seen.add(s); return true; })
    .slice(0, MAX_SYMBOLS);
}

// Mirrors normalizeQuote() in netlify/functions/stocks.js.
function normalizeQuote(d, symbol) {
  if (!d || typeof d.c !== "number" || !(d.c > 0)) return null;
  const pct = typeof d.dp === "number" && isFinite(d.dp)
    ? d.dp
    : (d.pc > 0 ? (d.c - d.pc) / d.pc * 100 : 0);
  return {
    symbol: symbol, price: d.c, change24: +pct.toFixed(2),
    open: d.o, high: d.h, low: d.l, prevClose: d.pc,
    at: Date.now(), src: "finnhub",
  };
}

console.log("\n--- stocks.js: symbol validation ---");
assert(validateSymbols("IREN").length === 1, "single symbol passes");
assert(validateSymbols("IREN,AAPL,NVDA").length === 3, "comma list passes");
assert(validateSymbols("iren,aapl")[0] === "IREN", "lowercase is upcased");
assert(validateSymbols(" IREN , AAPL ").length === 2, "surrounding whitespace trimmed");
assert(validateSymbols("BRK.B").length === 1, "dot-class ticker passes");
assert(validateSymbols("RDS-A").length === 1, "hyphenated ticker passes");
assert(validateSymbols("IREN,IREN,IREN").length === 1, "duplicates collapse to one");
assert(validateSymbols("").length === 0, "empty string yields nothing");
assert(validateSymbols(null).length === 0, "null yields nothing");
assert(validateSymbols(undefined).length === 0, "undefined yields nothing");
assert(validateSymbols(",,,").length === 0, "bare commas yield nothing");

console.log("\n--- stocks.js: symbol injection guards ---");
assert(validateSymbols("IREN&token=leaked").length === 0, "query-param injection rejected");
assert(validateSymbols("../../etc/passwd").length === 0, "path traversal rejected");
assert(validateSymbols("IREN;DROP TABLE").length === 0, "sql-ish payload rejected");
assert(validateSymbols("<script>").length === 0, "angle brackets rejected");
assert(validateSymbols("1REN").length === 0, "leading digit rejected");
assert(validateSymbols("TOOLONGSYMBOL").length === 0, "over-10-char symbol rejected");
assert(validateSymbols("IREN,<script>,AAPL").length === 2, "valid survive alongside rejected");
assert(validateSymbols(Array(40).fill("AAPL").join(",")).length === 1, "dedupe applies before cap");
const many = validateSymbols(Array.from({ length: 40 }, function (_, i) { return "AA" + i; }).join(","));
assert(many.length === MAX_SYMBOLS, "caps at " + MAX_SYMBOLS + " symbols");

console.log("\n--- stocks.js: quote normalization ---");
const q = normalizeQuote({ c: 45.16, d: 0.48, dp: 1.07, h: 45.9, l: 44.2, o: 44.6, pc: 44.68 }, "IREN");
assert(q !== null, "well-formed quote normalizes");
assert(q.price === 45.16, "price taken from c");
assert(q.change24 === 1.07, "change taken from dp when present");
assert(q.prevClose === 44.68, "prevClose taken from pc");
assert(q.src === "finnhub", "source tagged finnhub");
assert(typeof q.at === "number" && q.at > 0, "fetch timestamp stamped");

console.log("\n--- stocks.js: quote rejection ---");
assert(normalizeQuote({ c: 0 }, "NOPE") === null, "c=0 (unknown ticker) rejected");
assert(normalizeQuote({ c: -5 }, "NOPE") === null, "negative price rejected");
assert(normalizeQuote({}, "NOPE") === null, "empty object rejected");
assert(normalizeQuote(null, "NOPE") === null, "null rejected");
assert(normalizeQuote(undefined, "NOPE") === null, "undefined rejected");
assert(normalizeQuote({ c: "45.16" }, "NOPE") === null, "string price rejected");

console.log("\n--- stocks.js: change-percent fallback ---");
const noDp = normalizeQuote({ c: 110, pc: 100 }, "X");
assert(noDp.change24 === 10, "derives pct from c/pc when dp absent");
const noPc = normalizeQuote({ c: 110, pc: 0 }, "X");
assert(noPc.change24 === 0, "pc=0 yields 0 rather than Infinity");
const badDp = normalizeQuote({ c: 110, dp: Infinity, pc: 100 }, "X");
assert(badDp.change24 === 10, "non-finite dp falls back to c/pc");
const negDp = normalizeQuote({ c: 90, dp: -10, pc: 100 }, "X");
assert(negDp.change24 === -10, "negative change preserved");

console.log("\n--- quoteState: live vs delayed vs stale vs none ---");
// Mirrors quoteState() in platform.html.
function quoteState(prices, ticker) {
  const p = prices[ticker];
  if (!p || !(p.price > 0)) return "none";
  if (p.delayed) return "delayed";
  if (p.at && Date.now() - p.at > 900000) return "stale";
  return "live";
}
const now = Date.now();
assert(quoteState({ IREN: { price: 45.16, at: now } }, "IREN") === "live", "fresh quote is live");
assert(quoteState({ IREN: { price: 44.68, at: now, delayed: true } }, "IREN") === "delayed", "AV quote is delayed");
assert(quoteState({ IREN: { price: 44.68, at: now - 960000 } }, "IREN") === "stale", "16-min-old quote is stale");
assert(quoteState({ IREN: { price: 45.16, at: now - 840000 } }, "IREN") === "live", "14-min-old quote still live");
assert(quoteState({}, "IREN") === "none", "absent quote is none (cost-basis fallback)");
assert(quoteState({ IREN: { price: 0, at: now } }, "IREN") === "none", "zero price is none");
assert(quoteState({ IREN: { price: 45.16 } }, "IREN") === "live", "quote without timestamp treated as live");

console.log("\n==========================================");
console.log("Results: " + passed + " passed, " + failed + " failed");
if (failed > 0) process.exit(1);
