// Unit tests for BullrunIQ server-side logic.
// Run with: node tests/auth.test.js

const crypto = require("crypto");

// ─── Token helpers (mirrors _auth.js) ───────────────────────────────────────

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
    const p = tok.slice(0, i);
    const sig = tok.slice(i + 1);
    const expect = crypto.createHmac("sha256", secret).update(p).digest("base64url");
    const expectBuf = Buffer.from(expect);
    const sigBuf = Buffer.from(sig);
    if (expectBuf.length !== sigBuf.length) return null;
    if (!crypto.timingSafeEqual(expectBuf, sigBuf)) return null;
    const raw = Buffer.from(p, "base64url").toString("utf8");
    const j = raw.lastIndexOf("|");
    const email = raw.slice(0, j);
    const exp = parseInt(raw.slice(j + 1), 10);
    if (!email || !exp || Date.now() > exp) return null;
    return email;
  } catch (e) { return null; }
}

// ─── Test harness ────────────────────────────────────────────────────────────

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

// ─── Auth token: sign + verify ───────────────────────────────────────────────

console.log("\n--- auth token: sign + verify ---");

const token = signToken("user@example.com", 30, TEST_SECRET);
assert(typeof token === "string" && token.includes("."), "token has two parts");
assert(verifyToken(token, TEST_SECRET) === "user@example.com", "valid token verifies to email");
assert(verifyToken(token, "wrong-secret") === null, "wrong secret returns null");
assert(verifyToken("", TEST_SECRET) === null, "empty token returns null");
assert(verifyToken("invalid.token", TEST_SECRET) === null, "tampered token returns null");
assert(verifyToken(null, TEST_SECRET) === null, "null token returns null");
assert(verifyToken(undefined, TEST_SECRET) === null, "undefined token returns null");
assert(verifyToken("nodot", TEST_SECRET) === null, "token with no dot returns null");

// ─── Auth token: expiry ──────────────────────────────────────────────────────

console.log("\n--- auth token: expiry ---");

function signExpired(email, secret) {
  const exp = Date.now() - 1000;
  const p = Buffer.from(email + "|" + exp).toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(p).digest("base64url");
  return p + "." + sig;
}
const expiredToken = signExpired("user@example.com", TEST_SECRET);
assert(verifyToken(expiredToken, TEST_SECRET) === null, "expired token returns null");

// Token expiring far in the future should remain valid
const longToken = signToken("user@example.com", 365, TEST_SECRET);
assert(verifyToken(longToken, TEST_SECRET) === "user@example.com", "1-year token is valid");

// ─── Auth token: email embedding ─────────────────────────────────────────────

console.log("\n--- auth token: email embedding ---");

const emails = ["test@example.com", "user+tag@sub.domain.io", "A@B.CO"];
for (const em of emails) {
  const t = signToken(em.toLowerCase(), 1, TEST_SECRET);
  assert(verifyToken(t, TEST_SECRET) === em.toLowerCase(), "round-trips: " + em);
}

// Pipe character in email — token parsing uses lastIndexOf("|") so it handles this
const pipeEmail = "user|test@example.com";
const pipeToken = signToken(pipeEmail, 1, TEST_SECRET);
assert(verifyToken(pipeToken, TEST_SECRET) === pipeEmail, "email with pipe char round-trips");

// ─── Auth token: timing-safe comparison ──────────────────────────────────────

console.log("\n--- auth token: timing-safe comparison ---");

// Tokens with mismatched HMAC length should not throw, just return null
// (this guards the timingSafeEqual length mismatch path in _auth.js)
const validPayload = Buffer.from("test@example.com|" + (Date.now() + 864e5)).toString("base64url");
const shortSig = "x"; // far shorter than a real base64url HMAC-SHA256
assert(verifyToken(validPayload + "." + shortSig, TEST_SECRET) === null, "length-mismatch sig returns null");

// ─── Unsubscribe: email validation ───────────────────────────────────────────

console.log("\n--- unsubscribe: email validation ---");

function isValidEmail(s) {
  return typeof s === "string" && s.length > 0 && s.length <= 200 && s.indexOf("@") > 0;
}
assert(isValidEmail("a@b.com"), "valid email passes");
assert(!isValidEmail(""), "empty string fails");
assert(!isValidEmail("notanemail"), "missing @ fails");
assert(!isValidEmail("@nodomain"), "@ at start fails");
assert(!isValidEmail("a".repeat(201) + "@b.com"), "too long fails");

// ─── HTML escaping (XSS guard) ────────────────────────────────────────────────

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
assert(esc("it's") === "it&#x27;s", "apostrophe escaped");

// ─── market.js: id validation ─────────────────────────────────────────────────

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
assert(validateIds("bitcoin,".repeat(30)).length === 25, "capped at 25 ids");
assert(validateIds("BITCOIN").length === 1 && validateIds("BITCOIN")[0] === "bitcoin", "uppercase ids normalised to lowercase");
assert(validateIds("coin-gecko-id").length === 1, "hyphenated id passes");

// ─── market.js: kind validation ──────────────────────────────────────────────

console.log("\n--- market.js: kind validation ---");

const VALID_KINDS = new Set(["top50", "top100", "gainers", "losers", "trending", "fear-greed", "dominance"]);

function isValidKind(kind) {
  return VALID_KINDS.has(kind);
}
assert(isValidKind("top50"), "top50 is valid");
assert(isValidKind("fear-greed"), "fear-greed is valid");
assert(isValidKind("dominance"), "dominance is valid");
assert(!isValidKind(""), "empty kind rejected");
assert(!isValidKind("BITCOIN"), "random string rejected");
assert(!isValidKind("top500"), "top500 rejected");

// ─── alerts.js: sell alert logic ─────────────────────────────────────────────

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
assert(!shouldSendSellAlert({ ticker: "BTC" }, 999999), "no sell alert without sellTarget set");

// ─── alerts.js: buy alert logic ──────────────────────────────────────────────

console.log("\n--- alerts: buy alert logic ---");

function shouldSendBuyAlert(w, price) {
  const dist = Math.abs((w.targetPrice - price) / price * 100);
  return dist < 2 && price <= w.targetPrice * 1.02 && !w.serverAlerted;
}

const buyEntry = { ticker: "ETH", targetPrice: 2000 };
assert(shouldSendBuyAlert({ ...buyEntry }, 1990), "buy alert within 1%");
assert(shouldSendBuyAlert({ ...buyEntry }, 2000), "buy alert at exact target");
assert(!shouldSendBuyAlert({ ...buyEntry }, 2200), "no buy alert 10% above target");
assert(!shouldSendBuyAlert({ ...buyEntry, serverAlerted: true }, 1990), "no duplicate buy alert");
assert(!shouldSendBuyAlert({ ...buyEntry }, 1500), "no buy alert 25% below target (past it by too much)");

// ─── submission-created: contact form filter ──────────────────────────────────

console.log("\n--- submission-created: contact form filter ---");

function shouldSubscribe(formName) {
  if (formName === "contact" || formName === "contact-form") return false;
  return true;
}
assert(shouldSubscribe("waitlist"), "waitlist form gets subscribed");
assert(shouldSubscribe("tier-signup"), "tier-signup form gets subscribed");
assert(!shouldSubscribe("contact"), "contact form is skipped");
assert(!shouldSubscribe("contact-form"), "contact-form variant is skipped");

// ─── news.js: URL scheme validation ──────────────────────────────────────────

console.log("\n--- news.js: URL scheme validation ---");

function isHttpUrl(url) {
  return /^https?:\/\//i.test(url);
}
assert(isHttpUrl("https://coindesk.com/article"), "https URL passes");
assert(isHttpUrl("http://cointelegraph.com/news/test"), "http URL passes");
assert(!isHttpUrl("javascript:alert(1)"), "javascript: URL blocked");
assert(!isHttpUrl("data:text/html,<h1>xss</h1>"), "data: URL blocked");
assert(!isHttpUrl(""), "empty URL blocked");
assert(!isHttpUrl("ftp://example.com"), "ftp: URL blocked");

// ─── alerts.js: HTML escaping in emails ──────────────────────────────────────

console.log("\n--- alerts: HTML escaping in emails ---");

function escAlerts(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
assert(escAlerts("<BTC>") === "&lt;BTC&gt;", "angle brackets escaped in ticker");
assert(escAlerts("ETH & BNB") === "ETH &amp; BNB", "ampersand escaped in name");
assert(escAlerts('BTC"injection"') === "BTC&quot;injection&quot;", "quotes escaped");

// ─── portfolio guard: stop-loss / take-profit ─────────────────────────────────

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

// ─── profit-lock ladder ───────────────────────────────────────────────────────

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
assert(ladderFor(100, 10, 120).hits.length === 0, "at +20%, no rungs hit yet");

// ─── cash deployment engine ───────────────────────────────────────────────────

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
assert(deployPlan(99, ["BTC"]) === null, "$99 is below minimum");
assert(deployPlan(100, ["BTC"]).reserve === 20, "$100 keeps $20 reserve");

// ─── stripe-webhook: signature verification ───────────────────────────────────

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
    if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(parts.v1))) return false;
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

const STRIPE_SECRET = "whsec_test_secret";
const body = JSON.stringify({ type: "invoice.paid" });
const goodSig = makeStripeSig(body, STRIPE_SECRET);
assert(verifyStripe(body, goodSig, STRIPE_SECRET), "valid stripe signature passes");
assert(!verifyStripe(body, goodSig, "wrong_secret"), "wrong secret fails");
assert(!verifyStripe(body, null, STRIPE_SECRET), "null sig-header fails");
assert(!verifyStripe(body, "", STRIPE_SECRET), "empty sig-header fails");
assert(!verifyStripe(body, goodSig, null), "null secret fails");
assert(!verifyStripe(body, "t=123,v1=bad", STRIPE_SECRET), "bad v1 value fails");
assert(!verifyStripe(body, "t=123", STRIPE_SECRET), "missing v1 field fails");

// Stale timestamp (> 5 min old) should fail
const staleTs = Math.floor(Date.now() / 1000) - 400;
const staleSig = makeStripeSig(body, STRIPE_SECRET, staleTs);
assert(!verifyStripe(body, staleSig, STRIPE_SECRET), "stale timestamp (>300s) fails");

// Fresh timestamp right on the 300-second boundary
const borderTs = Math.floor(Date.now() / 1000) - 299;
const borderSig = makeStripeSig(body, STRIPE_SECRET, borderTs);
assert(verifyStripe(body, borderSig, STRIPE_SECRET), "299-second-old timestamp passes");

// ─── checkout.js: tier validation ────────────────────────────────────────────

console.log("\n--- checkout: tier validation ---");

const PRICE_ENV = { pro: "STRIPE_PRICE_PRO", elite: "STRIPE_PRICE_ELITE", advisor: "STRIPE_PRICE_ADVISOR" };

function resolveTier(tier) {
  const t = String(tier || "").toLowerCase();
  return PRICE_ENV[t] || null;
}

assert(resolveTier("pro") === "STRIPE_PRICE_PRO", "pro tier resolves");
assert(resolveTier("elite") === "STRIPE_PRICE_ELITE", "elite tier resolves");
assert(resolveTier("advisor") === "STRIPE_PRICE_ADVISOR", "advisor tier resolves");
assert(resolveTier("FREE") === null, "free tier not a checkout tier");
assert(resolveTier("") === null, "empty string returns null");
assert(resolveTier("PRO") === "STRIPE_PRICE_PRO", "case-insensitive tier match");
assert(resolveTier(null) === null, "null tier returns null");
assert(resolveTier("admin") === null, "unknown tier returns null");

// ─── newsletter.js: briefToHtml ───────────────────────────────────────────────

console.log("\n--- newsletter: briefToHtml ---");

function escHtml(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
function briefToHtml(text) {
  return escHtml(text)
    .replace(/\*\*(.*?)\*\*/g, "<strong style='color:#f0ece4'>$1</strong>")
    .split(/\n+/)
    .filter(function (l) { return l.trim(); })
    .map(function (l) { return "<p style='margin:0 0 12px;color:#c8c4bc;font-size:15px;line-height:1.7'>" + l.trim() + "</p>"; })
    .join("");
}

const briefOut = briefToHtml("📊 **Market** — BTC at $50k.\n\n⚠️ Risk: <volatility>");
assert(briefOut.includes("<strong"), "bold markdown converted to <strong>");
assert(briefOut.includes("&lt;volatility&gt;"), "HTML in brief is escaped");
assert(!briefOut.includes("**"), "markdown asterisks not present in output");
assert(briefOut.split("<p ").length > 1, "paragraphs split on newlines");
const emptyBrief = briefToHtml("   \n  ");
assert(emptyBrief === "", "whitespace-only brief produces empty output");

// ─── sync.js: data validation ─────────────────────────────────────────────────

console.log("\n--- sync: data validation ---");

function validateSyncData(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) return false;
  return true;
}
assert(validateSyncData({ wl: [], port: {} }), "object data passes");
assert(!validateSyncData(null), "null data fails");
assert(!validateSyncData([1, 2, 3]), "array data fails");
assert(!validateSyncData("string"), "string data fails");
assert(!validateSyncData(42), "number data fails");
assert(validateSyncData({}), "empty object data passes");

// ─── Summary ─────────────────────────────────────────────────────────────────
console.log("\n==========================================");
console.log("Results: " + passed + " passed, " + failed + " failed");
if (failed > 0) process.exit(1);
