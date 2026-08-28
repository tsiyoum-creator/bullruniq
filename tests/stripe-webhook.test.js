// Unit tests for stripe-webhook.js logic.
// Run with: node tests/stripe-webhook.test.js

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

// --- Stripe signature verification (inlined from stripe-webhook.js) ---

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

function makeStripeHeader(rawBody, secret, tsOverride) {
  const t = tsOverride !== undefined ? tsOverride : Math.floor(Date.now() / 1000);
  const signed = t + "." + rawBody;
  const v1 = crypto.createHmac("sha256", secret).update(signed, "utf8").digest("hex");
  return "t=" + t + ",v1=" + v1;
}

const BODY = JSON.stringify({ type: "checkout.session.completed", data: { object: {} } });
const SECRET = "whsec_test_secret";

console.log("\n--- Stripe signature verification ---");

const validSig = makeStripeHeader(BODY, SECRET);
assert(verifyStripe(BODY, validSig, SECRET), "valid signature passes");
assert(!verifyStripe(BODY, validSig, "wrong_secret"), "wrong secret fails");
assert(!verifyStripe(BODY, "", SECRET), "empty header fails");
assert(!verifyStripe(BODY, null, SECRET), "null header fails");
assert(!verifyStripe(BODY, "t=123,v1=badhex", SECRET), "invalid v1 fails");
assert(!verifyStripe("", null, null), "no secret fails");

// Timestamp tolerance: 301 seconds old → outside 300s window
const oldSig = makeStripeHeader(BODY, SECRET, Math.floor(Date.now() / 1000) - 301);
assert(!verifyStripe(BODY, oldSig, SECRET), "expired signature (301s) fails");

const freshSig = makeStripeHeader(BODY, SECRET, Math.floor(Date.now() / 1000) - 299);
assert(verifyStripe(BODY, freshSig, SECRET), "fresh signature (299s) passes");

// Tampered body
const tamperedSig = makeStripeHeader(BODY, SECRET);
assert(!verifyStripe(BODY + "tamper", tamperedSig, SECRET), "tampered body fails");

console.log("\n--- Tier mapping logic ---");

function tierForPriceId(priceId, env) {
  if (!priceId) return undefined;
  if (priceId === env.STRIPE_PRICE_ADVISOR) return "advisor";
  if (priceId === env.STRIPE_PRICE_ELITE) return "elite";
  if (priceId === env.STRIPE_PRICE_PRO) return "pro";
  return undefined;
}

const env = {
  STRIPE_PRICE_ADVISOR: "price_advisor_123",
  STRIPE_PRICE_ELITE: "price_elite_456",
  STRIPE_PRICE_PRO: "price_pro_789",
};

assert(tierForPriceId("price_advisor_123", env) === "advisor", "advisor price ID maps to advisor tier");
assert(tierForPriceId("price_elite_456", env) === "elite", "elite price ID maps to elite tier");
assert(tierForPriceId("price_pro_789", env) === "pro", "pro price ID maps to pro tier");
assert(tierForPriceId("price_unknown", env) === undefined, "unknown price ID returns undefined");
assert(tierForPriceId(null, env) === undefined, "null price ID returns undefined");
assert(tierForPriceId(undefined, env) === undefined, "undefined price ID returns undefined");

console.log("\n--- setStatus tier guard ---");

// When tier is undefined, the record's existing tier should be preserved
function applyTier(rec, tier) {
  if (tier) rec.tier = tier;
  return rec;
}

const recWithTier = { email: "a@b.com", tier: "elite", status: "active" };
applyTier(recWithTier, undefined);
assert(recWithTier.tier === "elite", "undefined tier preserves existing tier");
applyTier(recWithTier, "pro");
assert(recWithTier.tier === "pro", "explicit tier overwrites existing tier");

const newRec = { email: "a@b.com" };
applyTier(newRec, undefined);
assert(newRec.tier === undefined, "undefined tier on new record leaves tier absent");

console.log("\n--- checkout.session.completed email extraction ---");

function emailFromSession(obj) {
  return ((obj.customer_details && obj.customer_details.email) || obj.customer_email || "").toLowerCase();
}

assert(emailFromSession({ customer_details: { email: "Test@Example.com" } }) === "test@example.com", "customer_details.email extracted and lowercased");
assert(emailFromSession({ customer_email: "fallback@example.com" }) === "fallback@example.com", "customer_email fallback works");
assert(emailFromSession({}) === "", "empty object returns empty string");
assert(emailFromSession({ customer_details: {} }) === "", "missing email in customer_details returns empty");

console.log("\n--- Subscription lifecycle status transitions ---");

// subscription.deleted → canceled; payment_failed → past_due; invoice.paid → active
const transitions = [
  ["customer.subscription.deleted", "canceled"],
  ["invoice.payment_failed", "past_due"],
  ["invoice.paid", "active"],
];

function statusForEvent(evtType, objStatus) {
  if (evtType === "customer.subscription.deleted") return "canceled";
  if (evtType === "invoice.payment_failed") return "past_due";
  if (evtType === "invoice.paid") return "active";
  if (evtType === "customer.subscription.updated") return objStatus || "active";
  return null;
}

for (const [evtType, expected] of transitions) {
  assert(statusForEvent(evtType, null) === expected, evtType + " → " + expected);
}
assert(statusForEvent("customer.subscription.updated", "trialing") === "trialing", "subscription.updated uses obj.status");
assert(statusForEvent("customer.subscription.updated", null) === "active", "subscription.updated defaults to active");
assert(statusForEvent("unknown.event", null) === null, "unknown event returns null");

// --- Summary ---
console.log("\n==========================================");
console.log("Results: " + passed + " passed, " + failed + " failed");
if (failed > 0) process.exit(1);
