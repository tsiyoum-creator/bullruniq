// Unit tests for Stripe webhook signature verification logic.
// Run with: node tests/stripe.test.js

const crypto = require("crypto");

// Inline verifyStripe from stripe-webhook.js (same logic)
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
    const expBuf = Buffer.from(expected);
    const gotBuf = Buffer.from(parts.v1);
    if (expBuf.length !== gotBuf.length) return false;
    if (!crypto.timingSafeEqual(expBuf, gotBuf)) return false;
  } catch (e) { return false; }
  const age = Math.abs(Math.floor(Date.now() / 1000) - parseInt(parts.t, 10));
  return age <= 300;
}

function makeStripeHeader(body, secret, t) {
  const ts = t || Math.floor(Date.now() / 1000);
  const sig = crypto.createHmac("sha256", secret).update(ts + "." + body, "utf8").digest("hex");
  return "t=" + ts + ",v1=" + sig;
}

let passed = 0, failed = 0;
function assert(condition, label) {
  if (condition) { console.log("  ✓ " + label); passed++; }
  else { console.error("  ✗ FAIL: " + label); failed++; }
}

const SECRET = "whsec_test_secret";
const BODY = JSON.stringify({ type: "checkout.session.completed", data: { object: {} } });

console.log("\n--- verifyStripe: valid signature ---");

const validHeader = makeStripeHeader(BODY, SECRET);
assert(verifyStripe(BODY, validHeader, SECRET) === true, "valid signature passes");

console.log("\n--- verifyStripe: wrong secret ---");

assert(verifyStripe(BODY, validHeader, "wrong-secret") === false, "wrong secret fails");

console.log("\n--- verifyStripe: tampered body ---");

assert(verifyStripe(BODY + " ", validHeader, SECRET) === false, "tampered body fails");

console.log("\n--- verifyStripe: tampered signature ---");

const tamperedHeader = validHeader.replace(/v1=[a-f0-9]+/, "v1=aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");
assert(verifyStripe(BODY, tamperedHeader, SECRET) === false, "tampered v1 fails");

console.log("\n--- verifyStripe: missing fields ---");

assert(verifyStripe(BODY, "", SECRET) === false, "empty header fails");
assert(verifyStripe(BODY, null, SECRET) === false, "null header fails");
assert(verifyStripe(BODY, validHeader, null) === false, "null secret fails");
assert(verifyStripe(BODY, "t=12345", SECRET) === false, "missing v1 fails");
assert(verifyStripe(BODY, "v1=abc", SECRET) === false, "missing t fails");

console.log("\n--- verifyStripe: replay protection (> 5 min old) ---");

const oldTs = Math.floor(Date.now() / 1000) - 301;
const oldHeader = makeStripeHeader(BODY, SECRET, oldTs);
assert(verifyStripe(BODY, oldHeader, SECRET) === false, "replay attack (301s old) blocked");

const freshTs = Math.floor(Date.now() / 1000) - 299;
const freshHeader = makeStripeHeader(BODY, SECRET, freshTs);
assert(verifyStripe(BODY, freshHeader, SECRET) === true, "fresh signature (299s old) passes");

console.log("\n--- verifyStripe: mismatched buffer lengths ---");

const shortSigHeader = "t=" + Math.floor(Date.now() / 1000) + ",v1=abc";
assert(verifyStripe(BODY, shortSigHeader, SECRET) === false, "short v1 (length mismatch) fails safely");

console.log("\n==========================================");
console.log("Results: " + passed + " passed, " + failed + " failed");
if (failed > 0) process.exit(1);
