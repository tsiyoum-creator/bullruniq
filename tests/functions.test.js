// Unit tests for Netlify function logic.
// Run with: node tests/functions.test.js

let passed = 0, failed = 0;

function assert(condition, label) {
  if (condition) {
    console.log("  ✓ " + label);
    passed++;
  } else {
    console.error("  ✗ FAIL: " + label);
    failed++;
  }
}

// ─── generate.js: model validation ───────────────────────────────────────────

console.log("\n--- generate.js: model validation ---");

const ALLOWED_MODELS = new Set([
  "claude-opus-4-8",
  "claude-sonnet-4-6",
  "claude-haiku-4-5-20251001",
]);
const DEFAULT_MODEL = "claude-sonnet-4-6";
const MAX_TOKENS_CAP = 1500;

function resolveModel(model) {
  return ALLOWED_MODELS.has(model) ? model : DEFAULT_MODEL;
}
function resolveMaxTokens(n) {
  return Math.min(Math.max(parseInt(n, 10) || 800, 1), MAX_TOKENS_CAP);
}

assert(resolveModel("claude-sonnet-4-6") === "claude-sonnet-4-6", "allowed model passes through");
assert(resolveModel("claude-haiku-4-5-20251001") === "claude-haiku-4-5-20251001", "haiku allowed");
assert(resolveModel("gpt-4") === DEFAULT_MODEL, "non-allowed model falls back to default");
assert(resolveModel("") === DEFAULT_MODEL, "empty model falls back to default");
assert(resolveModel(undefined) === DEFAULT_MODEL, "undefined model falls back to default");
assert(resolveMaxTokens(500) === 500, "reasonable max_tokens passes through");
assert(resolveMaxTokens(0) === 800, "zero (falsy) defaults to 800 like any non-numeric input");
assert(resolveMaxTokens(99999) === MAX_TOKENS_CAP, "over-cap clamps to cap");
assert(resolveMaxTokens("abc") === 800, "non-numeric defaults to 800");
assert(resolveMaxTokens(-100) === 1, "negative clamps to 1");

// ─── generate.js: in-memory burst rate limit ─────────────────────────────────

console.log("\n--- generate.js: burst rate limit ---");

const BURST_MAX = 30;
const BURST_WINDOW_MS = 60000;
const _burst = new Map();

function burstOk(ip, nowMs) {
  const now = nowMs || Date.now();
  const e = _burst.get(ip);
  if (!e || now - e.t > BURST_WINDOW_MS) {
    _burst.set(ip, { t: now, n: 1 });
    return true;
  }
  e.n++;
  return e.n <= BURST_MAX;
}

const testIp = "1.2.3.4";
const t0 = Date.now();
let burstAllowed = 0;
for (let i = 0; i < 35; i++) {
  if (burstOk(testIp, t0)) burstAllowed++;
}
assert(burstAllowed === BURST_MAX, "burst allows exactly BURST_MAX requests in window");

// New window: reset
const allowed2 = burstOk(testIp, t0 + BURST_WINDOW_MS + 1);
assert(allowed2 === true, "new window resets burst counter");

// ─── sync.js: data size limit ─────────────────────────────────────────────────

console.log("\n--- sync.js: data size limit ---");

const MAX_BYTES = 256 * 1024;

function checkSize(body) {
  return (body || "").length <= MAX_BYTES;
}

assert(checkSize("{}"), "empty body is fine");
assert(checkSize("x".repeat(MAX_BYTES)), "exactly at limit is fine");
assert(!checkSize("x".repeat(MAX_BYTES + 1)), "one byte over limit is rejected");

// ─── checkout.js: tier validation ─────────────────────────────────────────────

console.log("\n--- checkout.js: tier validation ---");

const PRICE_ENV = { pro: "STRIPE_PRICE_PRO", elite: "STRIPE_PRICE_ELITE", advisor: "STRIPE_PRICE_ADVISOR" };

function validTier(t) {
  return !!PRICE_ENV[String(t || "").toLowerCase()];
}
function sanitizeEmail(raw) {
  const e = String(raw || "").trim().toLowerCase().slice(0, 200);
  return e && e.indexOf("@") > 0 ? e : "";
}

assert(validTier("pro"), "pro tier is valid");
assert(validTier("elite"), "elite tier is valid");
assert(validTier("advisor"), "advisor tier is valid");
assert(!validTier("free"), "free tier is rejected");
assert(!validTier(""), "empty tier is rejected");
assert(validTier("PRO"), "uppercase tier is valid — checkout.js lowercases before lookup");

// email sanitization
assert(sanitizeEmail("User@Example.COM") === "user@example.com", "email normalised to lowercase");
assert(sanitizeEmail("") === "", "empty email returns empty");
assert(sanitizeEmail("notanemail") === "", "email without @ returns empty");
assert(sanitizeEmail("a".repeat(201) + "@b.com") === "", "over-length email returns empty");

// ─── newsletter.js: HTML generation ──────────────────────────────────────────

console.log("\n--- newsletter.js: briefToHtml ---");

function escN(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}
function briefToHtml(text) {
  return escN(text)
    .replace(/\*\*(.*?)\*\*/g, "<strong style='color:#f0ece4'>$1</strong>")
    .split(/\n+/)
    .filter(function (l) { return l.trim(); })
    .map(function (l) { return "<p style='margin:0 0 12px;color:#c8c4bc;font-size:15px;line-height:1.7'>" + l.trim() + "</p>"; })
    .join("");
}

const html = briefToHtml("**Bitcoin** — moving up\n<script>xss</script>\nNormal line");
assert(html.includes("<strong style='color:#f0ece4'>Bitcoin</strong>"), "bold label rendered as strong");
assert(!html.includes("<script>"), "script tags escaped");
assert(html.includes("&lt;script&gt;"), "script tags HTML-escaped");
assert(html.includes("<p "), "paragraphs wrapped in p tags");
assert(!html.includes("\n"), "newlines collapsed into p tags");

// ─── newsletter.js: List-Unsubscribe header ───────────────────────────────────

console.log("\n--- newsletter.js: list-unsubscribe header ---");

function buildUnsubHeader(email) {
  var url = "https://bullruniq.com/api/unsubscribe?email=" + encodeURIComponent(email);
  return "<" + url + ">, <mailto:unsubscribe@bullruniq.com?subject=unsubscribe>";
}

const hdr = buildUnsubHeader("user@example.com");
assert(hdr.includes("https://bullruniq.com/api/unsubscribe"), "HTTPS unsubscribe URL present");
assert(hdr.includes("<mailto:"), "mailto: form present for RFC 2369 compat");
assert(hdr.includes("user%40example.com"), "email is URL-encoded in header");

// ─── _lib.js: shared esc, isValidEmail ───────────────────────────────────────

console.log("\n--- _lib.js: esc ---");

function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
}

assert(esc("<script>") === "&lt;script&gt;", "angle brackets escaped");
assert(esc('"quote"') === "&quot;quote&quot;", "double quotes escaped");
assert(esc("it's") === "it&#x27;s", "single quotes escaped");
assert(esc("a&b") === "a&amp;b", "ampersand escaped");
assert(esc("safe") === "safe", "safe text unchanged");

console.log("\n--- _lib.js: isValidEmail ---");

function isValidEmail(s) {
  return typeof s === "string" && s.length > 0 && s.length <= 200 && s.indexOf("@") > 0;
}

assert(isValidEmail("a@b.com"), "valid email");
assert(!isValidEmail(""), "empty string fails");
assert(!isValidEmail("notanemail"), "no @ fails");
assert(!isValidEmail("@domain.com"), "@ at start fails");
assert(!isValidEmail("a".repeat(201) + "@b.com"), "too long fails");
assert(!isValidEmail(null), "null fails");
assert(!isValidEmail(42), "number fails");

// ─── alerts.js: ticker subject escaping ──────────────────────────────────────

console.log("\n--- alerts.js: ticker escaping in email subjects ---");

function subjectSafe(ticker) { return esc(String(ticker)); }

assert(subjectSafe("BTC") === "BTC", "normal ticker unchanged");
assert(subjectSafe("<XSS>") === "&lt;XSS&gt;", "angle brackets escaped in subject");
assert(subjectSafe('"ETH"') === "&quot;ETH&quot;", "quotes escaped in subject");

// ─── Summary ─────────────────────────────────────────────────────────────────

console.log("\n==========================================");
console.log("Results: " + passed + " passed, " + failed + " failed");
if (failed > 0) process.exit(1);
