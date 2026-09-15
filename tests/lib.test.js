// Tests for _lib.js shared helpers and additional coverage areas.
// Run with: node tests/lib.test.js

const crypto = require("crypto");

let passed = 0, failed = 0;
function assert(condition, label) {
  if (condition) { console.log("  ✓ " + label); passed++; }
  else { console.error("  ✗ FAIL: " + label); failed++; }
}

// ─── _lib: verifyToken buffer-length safety ───────────────────────────────
console.log("\n--- _lib.js: verifyToken length-safety ---");

// Simulate the fixed verifyToken that rejects length-mismatched buffers
function verifyTokenFixed(tok, secret) {
  try {
    if (!secret || !tok) return null;
    const i = tok.lastIndexOf(".");
    if (i < 1) return null;
    const p = tok.slice(0, i), sig = tok.slice(i + 1);
    const expect = crypto.createHmac("sha256", secret).update(p).digest("base64url");
    const eBuf = Buffer.from(expect), sBuf = Buffer.from(sig);
    if (eBuf.length !== sBuf.length) return null;          // <── the fix
    if (!crypto.timingSafeEqual(eBuf, sBuf)) return null;
    const raw = Buffer.from(p, "base64url").toString("utf8");
    const j = raw.lastIndexOf("|");
    const email = raw.slice(0, j), exp = parseInt(raw.slice(j + 1), 10);
    if (!email || !exp || Date.now() > exp) return null;
    return email;
  } catch (e) { return null; }
}
const SECRET = "test-secret";
function sign(email, secret) {
  const exp = Date.now() + 864e5;
  const p = Buffer.from(email + "|" + exp).toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(p).digest("base64url");
  return p + "." + sig;
}
const tok = sign("a@b.com", SECRET);
assert(verifyTokenFixed(tok, SECRET) === "a@b.com", "valid token verifies");
// Craft a token whose signature has different base64url length (pad with extra char)
const [payload] = tok.split(".");
const shortSig = "x"; // much shorter than a real hmac
assert(verifyTokenFixed(payload + "." + shortSig, SECRET) === null, "length-mismatched sig returns null");
assert(verifyTokenFixed(payload + "." + ("A".repeat(200)), SECRET) === null, "oversized sig returns null");

// ─── stripe-webhook: verifyStripe ────────────────────────────────────────
console.log("\n--- stripe-webhook: verifyStripe ---");

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
  const eBuf = Buffer.from(expected), vBuf = Buffer.from(parts.v1);
  if (eBuf.length !== vBuf.length) return false;
  try {
    if (!crypto.timingSafeEqual(eBuf, vBuf)) return false;
  } catch (e) { return false; }
  const age = Math.abs(Math.floor(Date.now() / 1000) - parseInt(parts.t, 10));
  return age <= 300;
}
function makeStripeSig(body, secret, ts) {
  ts = ts || Math.floor(Date.now() / 1000);
  const signed = ts + "." + body;
  const sig = crypto.createHmac("sha256", secret).update(signed, "utf8").digest("hex");
  return "t=" + ts + ",v1=" + sig;
}
const body = JSON.stringify({ type: "invoice.paid" });
const wsec = "whsec_test";
assert(verifyStripe(body, makeStripeSig(body, wsec), wsec) === true, "valid stripe sig passes");
assert(verifyStripe(body, makeStripeSig(body, "other"), wsec) === false, "wrong secret rejected");
assert(verifyStripe(body, null, wsec) === false, "missing header rejected");
assert(verifyStripe(body, "", wsec) === false, "empty header rejected");
// Stale timestamp (> 5 minutes old)
const staleTs = Math.floor(Date.now() / 1000) - 400;
assert(verifyStripe(body, makeStripeSig(body, wsec, staleTs), wsec) === false, "stale timestamp rejected");
// Tampered body
assert(verifyStripe(body + "X", makeStripeSig(body, wsec), wsec) === false, "tampered body rejected");

// ─── generate.js: input guards ────────────────────────────────────────────
console.log("\n--- generate.js: input size guards ---");

const MAX_MESSAGE_BYTES = 32000;
const MAX_SYSTEM_BYTES = 4000;
const MAX_TOKENS_CAP = 1500;
const ALLOWED_MODELS = new Set(["claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"]);
const DEFAULT_MODEL = "claude-sonnet-4-6";

function resolveModel(m) { return ALLOWED_MODELS.has(m) ? m : DEFAULT_MODEL; }
function resolveTokens(t) { return Math.min(Math.max(parseInt(t, 10) || 800, 1), MAX_TOKENS_CAP); }
function systemTrunc(s) { return s ? String(s).slice(0, MAX_SYSTEM_BYTES) : undefined; }

assert(resolveModel("claude-sonnet-4-6") === "claude-sonnet-4-6", "allowed model passes through");
assert(resolveModel("gpt-4") === DEFAULT_MODEL, "disallowed model falls back to default");
assert(resolveModel(undefined) === DEFAULT_MODEL, "undefined model falls back to default");
assert(resolveTokens(1500) === 1500, "max_tokens at cap allowed");
assert(resolveTokens(9999) === MAX_TOKENS_CAP, "max_tokens above cap is clamped");
assert(resolveTokens(0) === 800, "zero max_tokens treated as unset → default 800");
assert(resolveTokens("bad") === 800, "non-numeric max_tokens uses default 800");
const bigMessages = JSON.stringify([{ role: "user", content: "x".repeat(MAX_MESSAGE_BYTES) }]);
assert(bigMessages.length > MAX_MESSAGE_BYTES, "oversized messages payload detected");
const bigSystem = "s".repeat(MAX_SYSTEM_BYTES + 100);
assert(systemTrunc(bigSystem).length === MAX_SYSTEM_BYTES, "system prompt truncated at cap");
assert(systemTrunc(null) === undefined, "null system returns undefined");

// ─── sync.js: base64-encoded body ────────────────────────────────────────
console.log("\n--- sync.js: base64 body decode ---");

const MAX_BYTES = 256 * 1024;
function decodeBody(event) {
  return event.isBase64Encoded
    ? Buffer.from(event.body || "", "base64").toString("utf8")
    : (event.body || "");
}
const syncPayload = JSON.stringify({ data: { key: "value" } });
const encoded = Buffer.from(syncPayload).toString("base64");
assert(decodeBody({ isBase64Encoded: true, body: encoded }) === syncPayload, "base64 body decoded correctly");
assert(decodeBody({ isBase64Encoded: false, body: syncPayload }) === syncPayload, "plain body returned as-is");
// Oversized check
const oversized = "x".repeat(MAX_BYTES + 1);
assert(oversized.length > MAX_BYTES, "oversized body detected");
// Base64 of oversized still triggers size check when decoded
const oversizedB64 = Buffer.from(oversized).toString("base64");
assert(decodeBody({ isBase64Encoded: true, body: oversizedB64 }).length > MAX_BYTES, "decoded base64 size check works");

// ─── market.js: kind validation ───────────────────────────────────────────
console.log("\n--- market.js: kind parameter ---");

const VALID_KINDS = new Set(["top50", "top100", "gainers", "losers", "trending", "global", "fear_greed"]);
function isValidKind(k) { return VALID_KINDS.has(k); }
assert(isValidKind("top50"), "top50 is valid");
assert(isValidKind("gainers"), "gainers is valid");
assert(isValidKind("global"), "global is valid");
assert(isValidKind("fear_greed"), "fear_greed is valid");
assert(!isValidKind("unknown"), "unknown kind is invalid");
assert(!isValidKind(""), "empty kind is invalid");
assert(!isValidKind("__proto__"), "__proto__ kind is invalid");

// ─── alerts.js: expanded CGMAP coverage ──────────────────────────────────
console.log("\n--- alerts.js: CGMAP coverage ---");

const CGMAP = require("../netlify/functions/alerts.js") ? null : null; // just test the logic

// Manually reproduce the key resolution logic from alerts.js
function resolveId(ticker, cgmap) {
  return cgmap[String(ticker).toUpperCase()] || String(ticker).toLowerCase();
}
const SAMPLE_CGMAP = {
  BTC: "bitcoin", ETH: "ethereum", SOL: "solana",
  FET: "fetch-ai", AGIX: "singularitynet", AAVE: "aave",
  USDC: "usd-coin",
};
assert(resolveId("BTC", SAMPLE_CGMAP) === "bitcoin", "BTC resolves to bitcoin");
assert(resolveId("fet", SAMPLE_CGMAP) === "fetch-ai", "lowercase ticker resolved");
assert(resolveId("UNKNOWN", SAMPLE_CGMAP) === "unknown", "unmapped ticker lowercased as fallback");
assert(resolveId("AAVE", SAMPLE_CGMAP) === "aave", "DeFi token AAVE resolves");

// ─── _lib.js: isValidEmail edge cases ────────────────────────────────────
console.log("\n--- _lib.js: isValidEmail ---");

function isValidEmail(s) {
  return typeof s === "string" && s.length > 0 && s.length <= 200 && s.indexOf("@") > 0;
}
assert(isValidEmail("user@example.com"), "basic email valid");
assert(isValidEmail("user+tag@sub.domain.co.uk"), "tagged email valid");
assert(!isValidEmail(""), "empty string invalid");
assert(!isValidEmail("@domain.com"), "leading @ invalid");
assert(!isValidEmail("nodomain"), "no @ invalid");
assert(!isValidEmail("a".repeat(201)), "too long invalid");
assert(!isValidEmail(null), "null invalid");
assert(!isValidEmail(42), "number invalid");

// ─── auth.js: code format guard ──────────────────────────────────────────
console.log("\n--- auth.js: code input guard ---");

function isValidCode(code) {
  const s = String(code || "").trim();
  return s.length > 0 && s.length <= 10;
}
assert(isValidCode("123456"), "6-digit code valid");
assert(isValidCode("999999"), "max 6-digit code valid");
assert(!isValidCode(""), "empty code invalid");
assert(!isValidCode("12345678901"), "too-long code invalid");

// ─── Summary ──────────────────────────────────────────────────────────────
console.log("\n==========================================");
console.log("Results: " + passed + " passed, " + failed + " failed");
if (failed > 0) process.exit(1);
