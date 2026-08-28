// Unit tests for sync.js logic: token verification, payload validation, size guard.
// Run with: node tests/sync.test.js

const crypto = require("crypto");

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

// --- Token helpers (from shared.js logic) ---

const TEST_SECRET = "test-secret-sync";

function signToken(email, days, secret) {
  const exp = Date.now() + (days || 30) * 864e5;
  const p = Buffer.from(email + "|" + exp).toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(p).digest("base64url");
  return p + "." + sig;
}

function verifyToken(tok, secret) {
  try {
    if (!secret || !tok) return null;
    const i = tok.lastIndexOf(".");
    if (i < 1) return null;
    const p = tok.slice(0, i), sig = tok.slice(i + 1);
    const expect = crypto.createHmac("sha256", secret).update(p).digest("base64url");
    const eBuf = Buffer.from(expect);
    const sBuf = Buffer.from(sig);
    if (eBuf.length !== sBuf.length) return null;
    if (!crypto.timingSafeEqual(eBuf, sBuf)) return null;
    const raw = Buffer.from(p, "base64url").toString("utf8");
    const j = raw.lastIndexOf("|");
    const email = raw.slice(0, j), exp = parseInt(raw.slice(j + 1), 10);
    if (!email || !exp || Date.now() > exp) return null;
    return email;
  } catch (e) { return null; }
}

console.log("\n--- sync: token verification ---");

const tok = signToken("user@example.com", 30, TEST_SECRET);
assert(verifyToken(tok, TEST_SECRET) === "user@example.com", "valid token passes");
assert(verifyToken(tok, "bad-secret") === null, "wrong secret fails");
assert(verifyToken("", TEST_SECRET) === null, "empty token fails");
assert(verifyToken(null, TEST_SECRET) === null, "null token fails");
assert(verifyToken("no-dot", TEST_SECRET) === null, "token without dot fails");

// Truncated sig (length mismatch → timingSafeEqual guard)
const parts = tok.split(".");
const truncatedSig = tok.slice(0, tok.length - 4); // remove last 4 chars of sig
assert(verifyToken(truncatedSig, TEST_SECRET) === null, "length-mismatched sig returns null");

// Expired token
const expiredExp = Date.now() - 1000;
const expiredP = Buffer.from("user@example.com|" + expiredExp).toString("base64url");
const expiredSig = crypto.createHmac("sha256", TEST_SECRET).update(expiredP).digest("base64url");
const expiredTok = expiredP + "." + expiredSig;
assert(verifyToken(expiredTok, TEST_SECRET) === null, "expired token fails");

console.log("\n--- sync: payload validation ---");

const MAX_BYTES = 256 * 1024;

function validatePayload(bodyStr) {
  if ((bodyStr || "").length > MAX_BYTES) return { error: "State too large." };
  let p = {};
  try { p = JSON.parse(bodyStr || "{}"); } catch (e) { return { error: "Bad JSON" }; }
  if (!p.data || typeof p.data !== "object") return { error: "Missing data" };
  return { ok: true, data: p.data };
}

assert(validatePayload(JSON.stringify({ data: { holdings: [] } })).ok, "valid payload passes");
assert(validatePayload(JSON.stringify({ data: {} })).ok, "empty data object passes");
assert(validatePayload(JSON.stringify({})).error === "Missing data", "missing data field fails");
assert(validatePayload(JSON.stringify({ data: "string" })).error === "Missing data", "string data fails");
assert(validatePayload(JSON.stringify({ data: null })).error === "Missing data", "null data fails");
assert(validatePayload("{bad json}").error === "Bad JSON", "malformed JSON fails");
assert(validatePayload("a".repeat(MAX_BYTES + 1)).error === "State too large.", "oversized payload fails");
assert(validatePayload("a".repeat(MAX_BYTES)).error === "Bad JSON", "exactly max bytes is checked (bad json here)");

console.log("\n--- sync: authorization header parsing ---");

function extractBearer(header) {
  return (header || "").replace(/^Bearer\s+/i, "").trim();
}

assert(extractBearer("Bearer tok123") === "tok123", "Bearer prefix stripped");
assert(extractBearer("bearer tok123") === "tok123", "lowercase bearer stripped");
assert(extractBearer("BEARER tok123") === "tok123", "uppercase BEARER stripped");
assert(extractBearer("tok123") === "tok123", "no prefix left unchanged");
assert(extractBearer("") === "", "empty header returns empty string");
assert(extractBearer(null) === "", "null header returns empty string");

console.log("\n--- sync: plan downgrade on subscription end ---");

// planFor returns "free" when status is not active/trialing
function planFor(rec) {
  if (rec && (rec.status === "active" || rec.status === "trialing")) return rec.tier || "pro";
  return "free";
}

assert(planFor({ status: "active", tier: "elite" }) === "elite", "active elite → elite");
assert(planFor({ status: "trialing", tier: "pro" }) === "pro", "trialing pro → pro");
assert(planFor({ status: "active" }) === "pro", "active with no tier → pro default");
assert(planFor({ status: "canceled", tier: "elite" }) === "free", "canceled → free");
assert(planFor({ status: "past_due", tier: "elite" }) === "free", "past_due → free");
assert(planFor(null) === "free", "no customer record → free");
assert(planFor({}) === "free", "empty record → free");

// --- Summary ---
console.log("\n==========================================");
console.log("Results: " + passed + " passed, " + failed + " failed");
if (failed > 0) process.exit(1);
