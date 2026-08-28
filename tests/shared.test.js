// Unit tests for netlify/functions/shared.js.
// Run with: node tests/shared.test.js

// Minimal env for testing (secretKey falls back to AUTH_SECRET)
process.env.AUTH_SECRET = "test-auth-secret-shared";

const { secretKey, signToken, verifyToken, signUnsubToken, verifyUnsubToken, planFor, CGMAP } = require("../netlify/functions/shared");

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

console.log("\n--- shared: secretKey ---");

assert(typeof secretKey() === "string" && secretKey().length > 0, "secretKey returns non-empty string");

console.log("\n--- shared: signToken / verifyToken ---");

const tok = signToken("alice@example.com", 30);
assert(typeof tok === "string" && tok.includes("."), "token is a dotted string");
assert(verifyToken(tok) === "alice@example.com", "valid token verifies to email");
assert(verifyToken(tok + "x") === null, "tampered token fails");
assert(verifyToken("") === null, "empty token fails");
assert(verifyToken(null) === null, "null token fails");
assert(verifyToken("no-dot-at-all") === null, "token without dot fails");

// Length mismatch guard (truncated sig)
const shortened = tok.slice(0, tok.length - 3);
assert(verifyToken(shortened) === null, "length-mismatched sig returns null");

// Expired
const expiredExp = Date.now() - 1000;
const crypto = require("crypto");
const ep = Buffer.from("alice@example.com|" + expiredExp).toString("base64url");
const esig = crypto.createHmac("sha256", secretKey()).update(ep).digest("base64url");
assert(verifyToken(ep + "." + esig) === null, "expired token returns null");

console.log("\n--- shared: signUnsubToken / verifyUnsubToken ---");

const email = "bob@example.com";
const unsub = signUnsubToken(email);
assert(typeof unsub === "string" && unsub.length > 0, "unsub token is non-empty string");
assert(verifyUnsubToken(email, unsub), "correct token verifies");
assert(!verifyUnsubToken(email, "badtoken"), "wrong token fails");
assert(!verifyUnsubToken("other@example.com", unsub), "different email fails");
assert(!verifyUnsubToken(email, ""), "empty token fails");
assert(!verifyUnsubToken(email, null), "null token fails");

console.log("\n--- shared: CGMAP completeness ---");

const requiredTickers = ["BTC", "ETH", "SOL", "BNB", "XRP", "ADA", "DOGE", "AVAX"];
for (const tk of requiredTickers) {
  assert(typeof CGMAP[tk] === "string" && CGMAP[tk].length > 0, "CGMAP has entry for " + tk);
}

// Extended tickers (added from platform.html that were missing from old alerts.js)
const extendedTickers = ["WEN", "ZETA", "W", "BEAM", "FDUSD", "PEOPLE"];
for (const tk of extendedTickers) {
  assert(typeof CGMAP[tk] === "string" && CGMAP[tk].length > 0, "CGMAP has extended entry for " + tk);
}

assert(Object.keys(CGMAP).length >= 60, "CGMAP has at least 60 entries");

console.log("\n--- shared: planFor logic ---");

// Simulate getStore returning different customer records
async function makeGetStore(record) {
  return function (storeName) {
    return {
      get: async function () { return record; }
    };
  };
}

(async function () {
  const gs1 = await makeGetStore({ status: "active", tier: "elite" });
  assert(await planFor("a@b.com", gs1) === "elite", "active elite customer → elite");

  const gs2 = await makeGetStore({ status: "trialing", tier: "advisor" });
  assert(await planFor("a@b.com", gs2) === "advisor", "trialing advisor → advisor");

  const gs3 = await makeGetStore({ status: "canceled", tier: "pro" });
  assert(await planFor("a@b.com", gs3) === "free", "canceled → free");

  const gs4 = await makeGetStore(null);
  assert(await planFor("a@b.com", gs4) === "free", "no customer record → free");

  const gs5 = await makeGetStore({ status: "active" });
  assert(await planFor("a@b.com", gs5) === "pro", "active with no tier → pro default");

  // Error case: store throws
  const gsBad = function () { return { get: async function () { throw new Error("storage down"); } }; };
  assert(await planFor("a@b.com", gsBad) === "free", "storage error returns free gracefully");

  // --- Summary ---
  console.log("\n==========================================");
  console.log("Results: " + passed + " passed, " + failed + " failed");
  if (failed > 0) process.exit(1);
})();
