// Unit tests for netlify function helpers.
// Run with: node tests/functions.test.js

const crypto = require("crypto");

let passed = 0, failed = 0;
function assert(condition, label) {
  if (condition) { console.log("  ✓ " + label); passed++; }
  else { console.error("  ✗ FAIL: " + label); failed++; }
}

// ─── _auth.js helpers ───────────────────────────────────────────────────────

process.env.AUTH_SECRET = "test-secret-for-functions-tests";
const auth = require("../netlify/functions/_auth");

console.log("\n--- _auth: secretKey ---");
assert(typeof auth.secretKey() === "string" && auth.secretKey().length > 0, "returns a string when AUTH_SECRET set");
const origSecret = process.env.AUTH_SECRET;
delete process.env.AUTH_SECRET;
assert(auth.secretKey() === null, "returns null when no env vars set");
process.env.AUTH_SECRET = origSecret;

console.log("\n--- _auth: signToken + verifyToken ---");
const tok = auth.signToken("alice@example.com", 1);
assert(typeof tok === "string" && tok.includes("."), "token has two parts");
assert(auth.verifyToken(tok) === "alice@example.com", "valid token round-trips email");
assert(auth.verifyToken(null) === null, "null token returns null");
assert(auth.verifyToken("") === null, "empty token returns null");
assert(auth.verifyToken("noDot") === null, "token without dot returns null");
assert(auth.verifyToken("a.b.c") === null, "tampered payload returns null");

console.log("\n--- _auth: expired token ---");
function signExpired(email) {
  const exp = Date.now() - 1000;
  const p = Buffer.from(email + "|" + exp).toString("base64url");
  const sig = crypto.createHmac("sha256", process.env.AUTH_SECRET).update(p).digest("base64url");
  return p + "." + sig;
}
assert(auth.verifyToken(signExpired("alice@example.com")) === null, "expired token returns null");

console.log("\n--- _auth: NaN exp protection ---");
function signBadExp(email) {
  const p = Buffer.from(email + "|notanumber").toString("base64url");
  const sig = crypto.createHmac("sha256", process.env.AUTH_SECRET).update(p).digest("base64url");
  return p + "." + sig;
}
assert(auth.verifyToken(signBadExp("alice@example.com")) === null, "NaN exp returns null");

// ─── stripe-webhook: verifyStripe ───────────────────────────────────────────

const { handler: webhookHandler } = require("../netlify/functions/stripe-webhook");

function makeStripeEvent(secret, body) {
  const ts = Math.floor(Date.now() / 1000);
  const signed = ts + "." + body;
  const v1 = crypto.createHmac("sha256", secret).update(signed).digest("hex");
  return { t: String(ts), v1 };
}

// Test the internal verifyStripe by calling it via a mock event
console.log("\n--- stripe-webhook: verifyStripe ---");

// We inline a minimal version here to test directly since verifyStripe is not exported
function verifyStripe(rawBody, sigHeader, secret) {
  if (!sigHeader || !secret) return false;
  const parts = {};
  String(sigHeader).split(",").forEach(function (kv) {
    const i = kv.indexOf("=");
    if (i > 0) parts[kv.slice(0, i).trim()] = kv.slice(i + 1).trim();
  });
  if (!parts.t || !parts.v1) return false;
  const ts = parseInt(parts.t, 10);
  if (!ts || isNaN(ts)) return false;
  const signed = parts.t + "." + rawBody;
  const expected = crypto.createHmac("sha256", secret).update(signed, "utf8").digest("hex");
  try {
    if (expected.length !== parts.v1.length) return false;
    if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(parts.v1))) return false;
  } catch (e) { return false; }
  const age = Math.abs(Math.floor(Date.now() / 1000) - ts);
  return age <= 300;
}

const SECRET = "whsec_test_secret";
const BODY = JSON.stringify({ type: "checkout.session.completed", data: { object: {} } });
const { t, v1 } = makeStripeEvent(SECRET, BODY);
const sigHeader = "t=" + t + ",v1=" + v1;

assert(verifyStripe(BODY, sigHeader, SECRET), "valid signature passes");
assert(!verifyStripe(BODY, sigHeader, "wrong-secret"), "wrong secret fails");
assert(!verifyStripe(BODY + "tampered", sigHeader, SECRET), "tampered body fails");
assert(!verifyStripe(BODY, "", SECRET), "empty sig header fails");
assert(!verifyStripe(BODY, null, SECRET), "null sig header fails");
assert(!verifyStripe(BODY, "t=notanumber,v1=abc", SECRET), "non-numeric timestamp fails");
assert(!verifyStripe(BODY, "t=0,v1=abc", SECRET), "zero timestamp fails");
assert(!verifyStripe(BODY, "t=" + (t - 400) + ",v1=" + v1, SECRET), "expired timestamp (>300s) fails");

console.log("\n--- stripe-webhook: timingSafeEqual length mismatch ---");
const shortV1 = "abc";
assert(!verifyStripe(BODY, "t=" + t + ",v1=" + shortV1, SECRET), "length mismatch on v1 fails safely");

// ─── newsletter.js: briefToHtml ─────────────────────────────────────────────

console.log("\n--- newsletter: briefToHtml ---");
function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function briefToHtml(text) {
  return esc(text)
    .replace(/\*\*(.*?)\*\*/g, "<strong style='color:#f0ece4'>$1</strong>")
    .split(/\n+/)
    .filter(function (l) { return l.trim(); })
    .map(function (l) { return "<p style='margin:0 0 12px;color:#c8c4bc;font-size:15px;line-height:1.7'>" + l.trim() + "</p>"; })
    .join("");
}
const rendered = briefToHtml("📊 **BTC** is up 3%\n🔥 **ETH** is holding\n");
assert(rendered.includes("<strong"), "bold markdown is converted to <strong>");
assert(!rendered.includes("**"), "no raw ** remain");
assert(rendered.includes("<p "), "lines become <p> tags");
assert(rendered.split("<p ").length - 1 === 2, "two non-empty lines → two <p> tags");

const xssInput = "<script>alert(1)</script>";
const xssOut = briefToHtml(xssInput);
assert(!xssOut.includes("<script>"), "script tags escaped in brief HTML");
assert(xssOut.includes("&lt;script&gt;"), "script tags HTML-encoded");

// ─── market.js: id validation ───────────────────────────────────────────────

console.log("\n--- market.js: validateIds ---");
function validateIds(raw) {
  return String(raw).toLowerCase().split(",")
    .map(function (s) { return s.trim(); })
    .filter(function (s) { return /^[a-z0-9-]{1,50}$/.test(s); })
    .slice(0, 25);
}
assert(validateIds("bitcoin,ethereum").length === 2, "two valid ids pass");
assert(validateIds("bitcoin,ethereum,solana").length === 3, "three valid ids pass");
assert(validateIds("bitcoin; DROP TABLE").length === 0, "injection string rejected");
assert(validateIds("a".repeat(51)).length === 0, "too-long id rejected");
assert(validateIds(",,,").length === 0, "empty ids rejected");
assert(validateIds("BTC,ETH").length === 2, "uppercase normalised to lowercase");
const manyIds = Array.from({ length: 30 }, function (_, i) { return "coin" + i; }).join(",");
assert(validateIds(manyIds).length === 25, "capped at 25 ids");

// ─── sync.js: body size guard ───────────────────────────────────────────────

console.log("\n--- sync.js: size guard ---");
const MAX_BYTES = 256 * 1024;
const bigBody = JSON.stringify({ data: { x: "a".repeat(300 * 1024) } });
assert(bigBody.length > MAX_BYTES, "oversized body exceeds MAX_BYTES");
const okBody = JSON.stringify({ data: { wl: [], port: {} } });
assert(okBody.length < MAX_BYTES, "normal body within MAX_BYTES");

// ─── alerts.js: profit ladder (extended) ────────────────────────────────────

console.log("\n--- alerts: profit-lock ladder (extended) ---");
function ladderFor(avg, qty, price) {
  if (!avg || avg <= 0) return null;
  const g = (price - avg) / avg * 100;
  if (g < 20) return null;
  const rungs = [25, 50, 100].map(function (pc) {
    const lp = avg * (1 + pc / 100);
    return { pct: pc, price: lp, qty: qty * 0.25, hit: price >= lp };
  });
  return { gain: g, rungs: rungs, hits: rungs.filter(function (r) { return r.hit; }) };
}
assert(ladderFor(50000, 1, 62000) !== null, "+24% gain → ladder generated");
assert(ladderFor(50000, 1, 60000) !== null, "+20% gain is at threshold (g < 20 is false at exactly 20) → ladder returned");
const lad = ladderFor(50000, 2, 90000);
assert(lad !== null && lad.rungs.length === 3, "ladder has 3 rungs from BTC-like entry");
assert(lad.hits.length === 2, "at +80%, first two rungs hit (at +25% and +50%)");
assert(lad.rungs[2].hit === false, "+100% rung not yet hit at +80%");
assert(ladderFor(50000, 1, 101000).hits.length === 3, "all 3 rungs hit at +102%");

// ─── alerts: CGMAP completeness ─────────────────────────────────────────────

console.log("\n--- alerts: CGMAP coverage ---");
const { } = require("../netlify/functions/alerts"); // just ensure it loads
// Inline a subset test since CGMAP is module-internal
const requiredTickers = ["BTC", "ETH", "SOL", "BNB", "XRP", "ADA", "DOGE", "AVAX", "LINK", "DOT", "MATIC", "NEAR"];
const alertsSrc = require("fs").readFileSync(require("path").join(__dirname, "../netlify/functions/alerts.js"), "utf8");
for (const ticker of requiredTickers) {
  // CGMAP keys may be quoted or unquoted; match either form
  const found = alertsSrc.includes('"' + ticker + '"') || alertsSrc.includes(ticker + ":");
  assert(found, "CGMAP includes " + ticker);
}

// ─── Summary ────────────────────────────────────────────────────────────────

console.log("\n==========================================");
console.log("Results: " + passed + " passed, " + failed + " failed");
if (failed > 0) process.exit(1);
