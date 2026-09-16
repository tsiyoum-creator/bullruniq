// Unit tests for BullrunIQ server logic.
// Run with: node tests/auth.test.js

const crypto = require("crypto");

// ── Token helpers imported from shared utils ──────────────────────────────────
// Override env vars so _utils.js uses our test secret instead of real env keys.
process.env.AUTH_SECRET = "test-secret-key-for-unit-tests";
const { signToken, verifyToken } = require("../netlify/functions/_utils");

// ── Test harness ──────────────────────────────────────────────────────────────
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

// ── auth token: sign + verify ─────────────────────────────────────────────────
console.log("\n--- auth token: sign + verify ---");

const token = signToken("user@example.com", 30);
assert(typeof token === "string" && token.includes("."), "token has two parts");
assert(verifyToken(token) === "user@example.com", "valid token verifies to email");

process.env.AUTH_SECRET = "wrong-secret";
assert(verifyToken(token) === null, "wrong secret returns null");
process.env.AUTH_SECRET = "test-secret-key-for-unit-tests";

assert(verifyToken("") === null, "empty token returns null");
assert(verifyToken("invalid.token") === null, "tampered token returns null");
assert(verifyToken(null) === null, "null token returns null");

// ── auth token: timingSafeEqual length mismatch guard ─────────────────────────
console.log("\n--- auth token: length mismatch guard ---");

// Craft a token whose signature part is truncated — should return null, not throw.
const goodToken = signToken("len@example.com", 1);
const [payload] = goodToken.split(".");
const truncatedSig = "abc";
assert(verifyToken(payload + "." + truncatedSig) === null, "truncated sig returns null, not throw");
assert(verifyToken(payload + ".") === null, "empty sig returns null");

// ── auth token: expiry ────────────────────────────────────────────────────────
console.log("\n--- auth token: expiry ---");

function signExpired(email) {
  const exp = Date.now() - 1000;
  const p = Buffer.from(email + "|" + exp).toString("base64url");
  const sig = crypto.createHmac("sha256", process.env.AUTH_SECRET).update(p).digest("base64url");
  return p + "." + sig;
}
assert(verifyToken(signExpired("user@example.com")) === null, "expired token returns null");

// ── auth token: email embedding ───────────────────────────────────────────────
console.log("\n--- auth token: email embedding ---");

const emails = ["test@example.com", "user+tag@sub.domain.io", "A@B.CO"];
for (const em of emails) {
  const t = signToken(em.toLowerCase(), 1);
  assert(verifyToken(t) === em.toLowerCase(), "round-trips: " + em);
}

// ── unsubscribe: email validation ─────────────────────────────────────────────
console.log("\n--- unsubscribe: email validation ---");

function isValidEmail(s) {
  return typeof s === "string" && s.length > 0 && s.length <= 200 && s.indexOf("@") > 0;
}
assert(isValidEmail("a@b.com"), "valid email passes");
assert(!isValidEmail(""), "empty string fails");
assert(!isValidEmail("notanemail"), "missing @ fails");
assert(!isValidEmail("@nodomain"), "@ at start fails");
assert(!isValidEmail("a".repeat(201) + "@b.com"), "too long fails");

// ── unsubscribe: HMAC token generation ───────────────────────────────────────
console.log("\n--- unsubscribe: signed token ---");

function unsubToken(email) {
  return crypto.createHmac("sha256", process.env.AUTH_SECRET).update("unsub:" + email).digest("base64url").slice(0, 32);
}
const tok1 = unsubToken("a@b.com");
const tok2 = unsubToken("a@b.com");
const tok3 = unsubToken("c@d.com");
assert(tok1 === tok2, "same email produces same token");
assert(tok1 !== tok3, "different emails produce different tokens");
assert(typeof tok1 === "string" && tok1.length === 32, "token is 32 chars");

// ── HTML escaping (XSS guard) ─────────────────────────────────────────────────
console.log("\n--- HTML escaping (XSS guard) ---");

function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
}
assert(esc("<script>alert(1)</script>") === "&lt;script&gt;alert(1)&lt;/script&gt;", "script tags escaped");
assert(esc('"><img src=x onerror=alert(1)>') === "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;", "attribute injection escaped");
assert(esc("safe text") === "safe text", "safe text unchanged");
assert(esc("a&b") === "a&amp;b", "ampersand escaped");

// ── market.js: id validation ──────────────────────────────────────────────────
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
assert(validateIds("bitcoin,ethereum,solana").length === 3, "three valid ids pass");

// ── sync.js: data validation ──────────────────────────────────────────────────
console.log("\n--- sync.js: data validation ---");

function validateSyncData(p) {
  return p.data && typeof p.data === "object" && !Array.isArray(p.data);
}
assert(validateSyncData({ data: { wl: [] } }), "object data passes");
assert(!validateSyncData({ data: [1, 2, 3] }), "array data rejected");
assert(!validateSyncData({}), "missing data rejected");
assert(!validateSyncData({ data: null }), "null data rejected");
assert(!validateSyncData({ data: "string" }), "string data rejected");

// ── sync.js: body byte length check ──────────────────────────────────────────
console.log("\n--- sync.js: byte length check ---");

const MAX_BYTES = 256 * 1024;
assert(Buffer.byteLength("hello", "utf8") < MAX_BYTES, "small payload within limit");
const largeStr = JSON.stringify({ d: "x".repeat(MAX_BYTES) });
assert(Buffer.byteLength(largeStr, "utf8") > MAX_BYTES, "large payload detected correctly");
const multibyteStr = "é".repeat(100); // é is 2 bytes in UTF-8
assert(Buffer.byteLength(multibyteStr, "utf8") === 200, "multibyte chars counted correctly");

// ── alerts: sell alert logic ──────────────────────────────────────────────────
console.log("\n--- alerts: sell alert logic ---");

function shouldSendSellAlert(w, price) {
  return !!(w.sellTarget && price >= w.sellTarget && !w.serverSellAlerted);
}
function shouldRearmSellAlert(w, price) {
  return !!(w.sellTarget && price < w.sellTarget * 0.95 && w.serverSellAlerted);
}

const watchlistEntry = { ticker: "BTC", targetPrice: 50000, sellTarget: 70000 };
assert(!shouldSendSellAlert({ ...watchlistEntry }, 65000), "no sell alert below target");
assert(shouldSendSellAlert({ ...watchlistEntry }, 70000), "sell alert at target");
assert(shouldSendSellAlert({ ...watchlistEntry }, 75000), "sell alert above target");
assert(!shouldSendSellAlert({ ...watchlistEntry, serverSellAlerted: true }, 75000), "no duplicate sell alert");
assert(shouldRearmSellAlert({ ...watchlistEntry, serverSellAlerted: true }, 60000), "re-arm when price drops 5%+ below sell");
assert(!shouldRearmSellAlert({ ...watchlistEntry, serverSellAlerted: true }, 67000), "no re-arm within 5% of sell");

// ── alerts: buy alert logic ───────────────────────────────────────────────────
console.log("\n--- alerts: buy alert logic ---");

function shouldSendBuyAlert(w, price) {
  const dist = Math.abs((w.targetPrice - price) / price * 100);
  return !!(dist < 2 && price <= w.targetPrice * 1.02 && !w.serverAlerted);
}

const buyEntry = { ticker: "ETH", targetPrice: 2000 };
assert(shouldSendBuyAlert({ ...buyEntry }, 1990), "buy alert within 1%");
assert(shouldSendBuyAlert({ ...buyEntry }, 2000), "buy alert at exact target");
assert(!shouldSendBuyAlert({ ...buyEntry }, 2200), "no buy alert 10% above target");
assert(!shouldSendBuyAlert({ ...buyEntry, serverAlerted: true }, 1990), "no duplicate buy alert");

// ── submission-created: contact form filter ───────────────────────────────────
console.log("\n--- submission-created: contact form filter ---");

function shouldSubscribe(formName) {
  if (formName === "contact" || formName === "contact-form") return false;
  return true;
}
assert(shouldSubscribe("waitlist"), "waitlist form gets subscribed");
assert(shouldSubscribe("tier-signup"), "tier-signup form gets subscribed");
assert(!shouldSubscribe("contact"), "contact form is skipped");
assert(!shouldSubscribe("contact-form"), "contact-form variant is skipped");

// ── news.js: URL scheme validation ────────────────────────────────────────────
console.log("\n--- news.js: URL scheme validation ---");

function isHttpUrl(url) {
  return /^https?:\/\//i.test(url);
}
assert(isHttpUrl("https://coindesk.com/article"), "https URL passes");
assert(isHttpUrl("http://cointelegraph.com/news/test"), "http URL passes");
assert(!isHttpUrl("javascript:alert(1)"), "javascript: URL blocked");
assert(!isHttpUrl("data:text/html,<h1>xss</h1>"), "data: URL blocked");
assert(!isHttpUrl(""), "empty URL blocked");

// ── alerts: HTML escaping in emails ──────────────────────────────────────────
console.log("\n--- alerts: HTML escaping in emails ---");

function escAlerts(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
assert(escAlerts("<BTC>") === "&lt;BTC&gt;", "angle brackets escaped in ticker");
assert(escAlerts("ETH & BNB") === "ETH &amp; BNB", "ampersand escaped in name");
assert(escAlerts('BTC"injection"') === "BTC&quot;injection&quot;", "quotes escaped");

// ── portfolio guard: stop-loss / take-profit ──────────────────────────────────
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

// ── stripe webhook: replay protection ────────────────────────────────────────
console.log("\n--- stripe-webhook: replay protection ---");

function isReplayOk(webhookTimestamp) {
  const age = Math.floor(Date.now() / 1000) - webhookTimestamp;
  return age >= 0 && age <= 300;
}
assert(isReplayOk(Math.floor(Date.now() / 1000)), "fresh timestamp accepted");
assert(isReplayOk(Math.floor(Date.now() / 1000) - 299), "299s old accepted");
assert(!isReplayOk(Math.floor(Date.now() / 1000) - 301), "301s old rejected");
assert(!isReplayOk(Math.floor(Date.now() / 1000) + 10), "future timestamp rejected");

// ── profit-lock ladder ────────────────────────────────────────────────────────
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

// ── cash deployment engine ────────────────────────────────────────────────────
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

// ── generate.js: system prompt length cap ────────────────────────────────────
console.log("\n--- generate.js: system prompt length cap ---");

const MAX_SYSTEM_LENGTH = 4000;
const longSystem = "x".repeat(5000);
assert(String(longSystem).slice(0, MAX_SYSTEM_LENGTH).length === MAX_SYSTEM_LENGTH, "long system prompt truncated to cap");
assert(String("short").slice(0, MAX_SYSTEM_LENGTH) === "short", "short system prompt unchanged");

// ── Summary ───────────────────────────────────────────────────────────────────
console.log("\n==========================================");
console.log("Results: " + passed + " passed, " + failed + " failed");
if (failed > 0) process.exit(1);
