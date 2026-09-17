// Unit tests for BullrunIQ Netlify function logic.
// Run with: node tests/auth.test.js

const crypto = require("crypto");

// --- Inline the token helpers (copied from _shared.js) ---

const TEST_SECRET = "test-secret-key-for-unit-tests";

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
    const eBuf = Buffer.from(expect), sBuf = Buffer.from(sig);
    if (eBuf.length !== sBuf.length) return null;
    if (!crypto.timingSafeEqual(eBuf, sBuf)) return null;
    const raw = Buffer.from(p, "base64url").toString("utf8");
    const j = raw.lastIndexOf("|");
    const email = raw.slice(0, j), exp = parseInt(raw.slice(j + 1), 10);
    if (!email || !exp || Date.now() > exp) return null;
    return email;
  } catch (e) { return null; }
}

// Single shared esc() matching _shared.js (includes single-quote escaping)
function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

// --- Tests ---

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

console.log("\n--- auth token: sign + verify ---");

const token = signToken("user@example.com", 30, TEST_SECRET);
assert(typeof token === "string" && token.includes("."), "token has two parts");
assert(verifyToken(token, TEST_SECRET) === "user@example.com", "valid token verifies to email");
assert(verifyToken(token, "wrong-secret") === null, "wrong secret returns null");
assert(verifyToken("", TEST_SECRET) === null, "empty token returns null");
assert(verifyToken("invalid.token", TEST_SECRET) === null, "tampered token returns null");
assert(verifyToken(null, TEST_SECRET) === null, "null token returns null");

console.log("\n--- auth token: length-mismatched signature ---");

// A token with a short signature must be rejected without throwing
const [payload] = token.split(".");
assert(verifyToken(payload + ".short", TEST_SECRET) === null, "short signature returns null");
assert(verifyToken(payload + "." + "a".repeat(200), TEST_SECRET) === null, "long signature returns null");
assert(verifyToken(payload + ".", TEST_SECRET) === null, "empty signature returns null");

console.log("\n--- auth token: expiry ---");

function signExpired(email, secret) {
  const exp = Date.now() - 1000; // already expired
  const p = Buffer.from(email + "|" + exp).toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(p).digest("base64url");
  return p + "." + sig;
}
const expiredToken = signExpired("user@example.com", TEST_SECRET);
assert(verifyToken(expiredToken, TEST_SECRET) === null, "expired token returns null");

console.log("\n--- auth token: email embedding ---");

const emails = ["test@example.com", "user+tag@sub.domain.io", "A@B.CO"];
for (const em of emails) {
  const t = signToken(em.toLowerCase(), 1, TEST_SECRET);
  assert(verifyToken(t, TEST_SECRET) === em.toLowerCase(), "round-trips: " + em);
}

console.log("\n--- unsubscribe: email validation ---");

function isValidEmail(s) {
  return typeof s === "string" && s.length > 0 && s.length <= 200 && s.indexOf("@") > 0;
}
assert(isValidEmail("a@b.com"), "valid email passes");
assert(!isValidEmail(""), "empty string fails");
assert(!isValidEmail("notanemail"), "missing @ fails");
assert(!isValidEmail("@nodomain"), "@ at start fails");
assert(!isValidEmail("a".repeat(201) + "@b.com"), "too long fails");

console.log("\n--- HTML escaping (XSS guard) ---");

assert(esc("<script>alert(1)</script>") === "&lt;script&gt;alert(1)&lt;/script&gt;", "script tags escaped");
assert(esc('"><img src=x onerror=alert(1)>') === "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;", "attribute injection escaped");
assert(esc("safe text") === "safe text", "safe text unchanged");
assert(esc("a&b") === "a&amp;b", "ampersand escaped");
assert(esc("it's here") === "it&#x27;s here", "single quote escaped");
assert(esc('<BTC>') === "&lt;BTC&gt;", "angle brackets escaped in ticker");
assert(esc("ETH & BNB") === "ETH &amp; BNB", "ampersand escaped in name");
assert(esc('BTC"injection"') === "BTC&quot;injection&quot;", "double quotes escaped");

console.log("\n--- market.js: id validation ---");

function validateIds(raw) {
  return String(raw).toLowerCase().split(",")
    .map(function (s) { return s.trim(); })
    .filter(function (s) { return /^[a-z0-9-]{1,50}$/.test(s); })
    .slice(0, 25);
}
assert(validateIds("bitcoin,ethereum").length === 2, "two valid ids pass");
assert(validateIds("bitcoin; DROP TABLE").length === 0, "injection string rejected");
assert(validateIds("a".repeat(51)).length === 0, "too-long id rejected");
assert(validateIds(",,,").length === 0, "empty ids rejected");
assert(validateIds("bitcoin,<script>").length === 1, "one valid, one script-tag rejected");

console.log("\n--- alerts: sell alert logic ---");

function shouldSendSellAlert(w, price) {
  return w.sellTarget && price >= w.sellTarget && !w.serverSellAlerted;
}
function shouldRearmSellAlert(w, price) {
  return w.sellTarget && price < w.sellTarget * 0.95 && w.serverSellAlerted;
}

const watchlistEntry = { ticker: "BTC", targetPrice: 50000, sellTarget: 70000 };
assert(!shouldSendSellAlert({ ...watchlistEntry }, 65000), "no sell alert below target");
assert(shouldSendSellAlert({ ...watchlistEntry }, 70000), "sell alert at target");
assert(shouldSendSellAlert({ ...watchlistEntry }, 75000), "sell alert above target");
assert(!shouldSendSellAlert({ ...watchlistEntry, serverSellAlerted: true }, 75000), "no duplicate sell alert");
assert(shouldRearmSellAlert({ ...watchlistEntry, serverSellAlerted: true }, 60000), "re-arm when price drops 5%+ below sell");
assert(!shouldRearmSellAlert({ ...watchlistEntry, serverSellAlerted: true }, 67000), "no re-arm within 5% of sell");

console.log("\n--- alerts: buy alert logic (directional — approaches from above) ---");

function shouldSendBuyAlert(w, price) {
  const dist = (w.targetPrice - price) / price * 100;
  // Only fires when price is still above target (dist > 0) and within 2%
  return dist > 0 && dist < 2 && !w.serverAlerted;
}

const buyEntry = { ticker: "ETH", targetPrice: 2000 };
assert(shouldSendBuyAlert({ ...buyEntry }, 1990), "buy alert within 1% from above");
assert(!shouldSendBuyAlert({ ...buyEntry }, 2000), "no buy alert when price exactly at target (dist=0, not above)");
assert(!shouldSendBuyAlert({ ...buyEntry }, 2200), "no buy alert 10% above target (out of range)");
assert(!shouldSendBuyAlert({ ...buyEntry }, 1900), "no buy alert when price already below target");
assert(!shouldSendBuyAlert({ ...buyEntry, serverAlerted: true }, 1990), "no duplicate buy alert");

console.log("\n--- submission-created: contact form filter ---");

function shouldSubscribe(formName) {
  if (formName === "contact" || formName === "contact-form") return false;
  return true;
}
assert(shouldSubscribe("waitlist"), "waitlist form gets subscribed");
assert(shouldSubscribe("tier-signup"), "tier-signup form gets subscribed");
assert(!shouldSubscribe("contact"), "contact form is skipped");
assert(!shouldSubscribe("contact-form"), "contact-form variant is skipped");

console.log("\n--- news.js: URL scheme validation ---");

function isHttpUrl(url) {
  return /^https?:\/\//i.test(url);
}
assert(isHttpUrl("https://coindesk.com/article"), "https URL passes");
assert(isHttpUrl("http://cointelegraph.com/news/test"), "http URL passes");
assert(!isHttpUrl("javascript:alert(1)"), "javascript: URL blocked");
assert(!isHttpUrl("data:text/html,<h1>xss</h1>"), "data: URL blocked");
assert(!isHttpUrl(""), "empty URL blocked");
assert(!isHttpUrl("ftp://example.com/feed"), "ftp: URL blocked");

console.log("\n--- portfolio guard: stop-loss / take-profit ---");

function shouldStopAlert(h, price) { return !!(h.stop && price <= h.stop && !h.serverStopAlerted); }
function shouldRearmStop(h, price) { return !!(h.stop && price >= h.stop * 1.05 && h.serverStopAlerted); }
function shouldTpAlert(h, price) { return !!(h.tp && price >= h.tp && !h.serverTpAlerted); }
function shouldRearmTp(h, price) { return !!(h.tp && price < h.tp * 0.95 && h.serverTpAlerted); }

const holding = { ticker: "BTC", avg: 60000, qty: 0.5, stop: 55000, tp: 80000 };
assert(shouldStopAlert({ ...holding }, 54000), "stop alert below stop");
assert(shouldStopAlert({ ...holding }, 55000), "stop alert at exact stop");
assert(!shouldStopAlert({ ...holding }, 56000), "no stop alert above stop");
assert(!shouldStopAlert({ ...holding, serverStopAlerted: true }, 54000), "no duplicate stop alert");
assert(shouldRearmStop({ ...holding, serverStopAlerted: true }, 58000), "stop re-arms 5% above");
assert(!shouldRearmStop({ ...holding, serverStopAlerted: true }, 56000), "no stop re-arm within 5%");
assert(shouldTpAlert({ ...holding }, 80000), "tp alert at target");
assert(shouldTpAlert({ ...holding }, 90000), "tp alert above target");
assert(!shouldTpAlert({ ...holding }, 79000), "no tp alert below target");
assert(!shouldTpAlert({ ...holding, serverTpAlerted: true }, 90000), "no duplicate tp alert");
assert(shouldRearmTp({ ...holding, serverTpAlerted: true }, 75000), "tp re-arms 5% below");
assert(!shouldStopAlert({ ticker: "ETH", avg: 2000, qty: 1 }, 100), "no levels set → no alert");

console.log("\n--- profit-lock ladder ---");

function ladderFor(avg, qty, price) {
  if (!avg || avg <= 0) return null;
  const g = (price - avg) / avg * 100;
  if (g < 20) return null;
  const rungs = [25, 50, 100].map(pc => {
    const lp = avg * (1 + pc / 100);
    return { pct: pc, price: lp, qty: qty * 0.25, hit: price >= lp };
  });
  return { gain: g, rungs, hits: rungs.filter(r => r.hit) };
}
assert(ladderFor(100, 10, 110) === null, "no ladder under +20% gain");
assert(ladderFor(0, 10, 500) === null, "no ladder without cost basis");
const lad = ladderFor(100, 10, 160);
assert(lad !== null && lad.rungs.length === 3, "ladder has 3 rungs");
assert(lad.rungs[0].price === 125 && lad.rungs[1].price === 150 && lad.rungs[2].price === 200, "rung prices at +25/+50/+100%");
assert(lad.hits.length === 2, "at +60%, first two rungs are hit");
assert(lad.rungs[0].qty === 2.5, "each rung sells 25% of the position");
assert(ladderFor(100, 10, 250).hits.length === 3, "at +150%, all rungs hit");

console.log("\n--- cash deployment engine ---");

function deployPlan(cash, near) {
  if (cash < 100) return null;
  const reserve = Math.round(cash * 0.2), deploy = cash - reserve;
  const per = near.length ? Math.max(0, Math.floor(deploy / near.length)) : 0;
  return { cash, reserve, deploy, per };
}
assert(deployPlan(50, []) === null, "under $100 cash → no plan");
const dp = deployPlan(1000, ["BTC", "ETH"]);
assert(dp.reserve === 200, "keeps 20% reserve");
assert(dp.deploy === 800, "deploys 80%");
assert(dp.per === 400, "splits evenly across near-zone buys");
assert(deployPlan(1000, []).per === 0, "no near-zone assets → nothing deployed");
assert(deployPlan(99, ["BTC"]) === null, "just under $100 threshold → no plan");
assert(deployPlan(100, ["BTC"]).deploy === 80, "$100 cash deploys $80");

console.log("\n--- stripe-webhook: signature verification ---");

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
    const eBuf = Buffer.from(expected, "hex");
    const vBuf = Buffer.from(parts.v1, "hex");
    if (eBuf.length !== vBuf.length) return false;
    if (!crypto.timingSafeEqual(eBuf, vBuf)) return false;
  } catch (e) { return false; }
  const age = Math.abs(Math.floor(Date.now() / 1000) - parseInt(parts.t, 10));
  return age <= 300;
}

function makeStripeHeader(body, secret, tOffset) {
  const t = Math.floor(Date.now() / 1000) + (tOffset || 0);
  const sig = crypto.createHmac("sha256", secret).update(t + "." + body).digest("hex");
  return "t=" + t + ",v1=" + sig;
}

const STRIPE_SECRET = "whsec_test123";
const BODY = '{"type":"invoice.paid"}';
const validSig = makeStripeHeader(BODY, STRIPE_SECRET);
assert(verifyStripe(BODY, validSig, STRIPE_SECRET), "valid stripe signature passes");
assert(!verifyStripe(BODY, validSig, "wrong-secret"), "wrong secret fails");
assert(!verifyStripe(BODY + "tampered", validSig, STRIPE_SECRET), "tampered body fails");
assert(!verifyStripe(BODY, null, STRIPE_SECRET), "missing header fails");
assert(!verifyStripe(BODY, validSig, null), "missing secret fails");
assert(!verifyStripe(BODY, "t=123,v1=abc", STRIPE_SECRET), "malformed hex v1 fails gracefully");

const staleSig = makeStripeHeader(BODY, STRIPE_SECRET, -400);
assert(!verifyStripe(BODY, staleSig, STRIPE_SECRET), "replay > 5 minutes old fails");

const freshSig = makeStripeHeader(BODY, STRIPE_SECRET, -100);
assert(verifyStripe(BODY, freshSig, STRIPE_SECRET), "recent signature within 5 minutes passes");

console.log("\n--- portal.js: URL validation ---");

function safePortalUrl(url) {
  return url && /^https:\/\/billing\.stripe\.com\//.test(url) ? url : "/contact";
}
assert(safePortalUrl("https://billing.stripe.com/session/abc") === "https://billing.stripe.com/session/abc", "valid stripe portal URL allowed");
assert(safePortalUrl("https://evil.com/redirect") === "/contact", "non-stripe URL rejected");
assert(safePortalUrl("http://billing.stripe.com/session") === "/contact", "http not allowed");
assert(safePortalUrl(null) === "/contact", "null falls back to /contact");
assert(safePortalUrl("") === "/contact", "empty falls back to /contact");
assert(safePortalUrl("https://billing.stripe.com.evil.com/") === "/contact", "subdomain spoofing rejected");

console.log("\n--- generate.js: system prompt truncation ---");

const MAX_SYSTEM_LENGTH = 2000;
function truncateSystem(s) { return String(s).slice(0, MAX_SYSTEM_LENGTH); }
assert(truncateSystem("hello").length === 5, "short system prompt unchanged");
assert(truncateSystem("a".repeat(3000)).length === MAX_SYSTEM_LENGTH, "long system prompt truncated to cap");
assert(truncateSystem("a".repeat(2000)).length === MAX_SYSTEM_LENGTH, "system prompt at exact cap unchanged");

// --- Summary ---
console.log("\n==========================================");
console.log("Results: " + passed + " passed, " + failed + " failed");
if (failed > 0) process.exit(1);
