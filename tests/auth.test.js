// Unit tests for BullrunIQ logic.
// Run with: node tests/auth.test.js

const crypto = require("crypto");

// --- Inline the token helpers (mirrors _shared.js) ---

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
    const expected = crypto.createHmac("sha256", secret).update(p).digest("base64url");
    if (expected.length !== sig.length) return null;
    if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig))) return null;
    const raw = Buffer.from(p, "base64url").toString("utf8");
    const j = raw.lastIndexOf("|");
    const email = raw.slice(0, j), exp = parseInt(raw.slice(j + 1), 10);
    if (!email || !exp || Date.now() > exp) return null;
    return email;
  } catch (e) { return null; }
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

console.log("\n--- auth token: expiry ---");

function signExpired(email, secret) {
  const exp = Date.now() - 1000;
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

console.log("\n--- auth token: length mismatch guard ---");

// A token whose sig is a different length should not be timingSafeEqual'd
const shortToken = signToken("a@b.com", 1, TEST_SECRET);
const parts = shortToken.split(".");
const truncatedSig = parts[1].slice(0, 10);
assert(verifyToken(parts[0] + "." + truncatedSig, TEST_SECRET) === null, "truncated sig returns null");

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

function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
}
assert(esc("<script>alert(1)</script>") === "&lt;script&gt;alert(1)&lt;/script&gt;", "script tags escaped");
assert(esc('"><img src=x onerror=alert(1)>') === "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;", "attribute injection escaped");
assert(esc("safe text") === "safe text", "safe text unchanged");
assert(esc("a&b") === "a&amp;b", "ampersand escaped");

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
assert(validateIds("BITCOIN").length === 1, "uppercase input is lowercased and accepted");

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

console.log("\n--- alerts: HTML escaping in emails ---");

assert(esc("<BTC>") === "&lt;BTC&gt;", "angle brackets escaped in ticker");
assert(esc("ETH & BNB") === "ETH &amp; BNB", "ampersand escaped in name");
assert(esc('BTC"injection"') === "BTC&quot;injection&quot;", "quotes escaped");
assert(esc("'; DROP TABLE--") === "&#x27;; DROP TABLE--", "single quote escaped");

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
assert(ladderFor(100, 10, 120) !== null, "ladder created at +20%");
assert(ladderFor(100, 10, 119) === null, "no ladder just under +20%");

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
assert(deployPlan(100, ["BTC"]) !== null, "exactly $100 triggers plan");
assert(deployPlan(99, ["BTC"]) === null, "under $100 no plan");

console.log("\n--- newsletter: null-safe BTC formatting ---");

function formatBtcLine(d) {
  if (!d || d.usd == null) return "n/a";
  const change = d.usd_24h_change;
  const changeStr = (change != null && isFinite(change))
    ? " (" + (change >= 0 ? "+" : "") + change.toFixed(1) + "%)"
    : "";
  return "$" + Math.round(d.usd).toLocaleString() + changeStr;
}
assert(formatBtcLine(null) === "n/a", "null data returns n/a");
assert(formatBtcLine({}) === "n/a", "missing usd returns n/a");
assert(formatBtcLine({ usd: 100000, usd_24h_change: 3.5 }) === "$100,000 (+3.5%)", "positive change formatted");
assert(formatBtcLine({ usd: 95000, usd_24h_change: -2.1 }) === "$95,000 (-2.1%)", "negative change formatted");
assert(formatBtcLine({ usd: 80000, usd_24h_change: null }) === "$80,000", "null change omitted");
assert(formatBtcLine({ usd: 80000, usd_24h_change: NaN }) === "$80,000", "NaN change omitted");
assert(formatBtcLine({ usd: 80000, usd_24h_change: Infinity }) === "$80,000", "Infinity change omitted");

console.log("\n--- generate.js: message sanitization ---");

function sanitizeMessages(messages, maxLen) {
  return messages.map(function (m) {
    const role = m.role === "assistant" ? "assistant" : "user";
    let content = m.content;
    if (typeof content === "string") {
      content = content.slice(0, maxLen);
    } else if (Array.isArray(content)) {
      content = content.slice(0, 20).map(function (block) {
        if (block && typeof block.text === "string") {
          return { ...block, text: block.text.slice(0, maxLen) };
        }
        return block;
      });
    }
    return { role, content };
  });
}
const longMsg = "x".repeat(10000);
const sanitized = sanitizeMessages([{ role: "user", content: longMsg }], 8000);
assert(sanitized[0].content.length === 8000, "string content truncated to maxLen");
assert(sanitized[0].role === "user", "user role preserved");

const badRole = sanitizeMessages([{ role: "admin", content: "hi" }], 8000);
assert(badRole[0].role === "user", "unknown role coerced to user");

const assistantMsg = sanitizeMessages([{ role: "assistant", content: "hello" }], 8000);
assert(assistantMsg[0].role === "assistant", "assistant role preserved");

const arrayContent = sanitizeMessages([{ role: "user", content: [{ type: "text", text: "x".repeat(10000) }] }], 8000);
assert(arrayContent[0].content[0].text.length === 8000, "array block text truncated");

console.log("\n--- generate.js: system prompt cap ---");

const MAX_SYSTEM_LEN = 2000;
const longSystem = "s".repeat(5000);
const cappedSystem = String(longSystem).slice(0, MAX_SYSTEM_LEN);
assert(cappedSystem.length === MAX_SYSTEM_LEN, "system prompt capped at MAX_SYSTEM_LEN");

console.log("\n--- sync.js: authorization ---");

// A request without a valid token should be rejected
function syncAuthCheck(authHeader, secret) {
  const tok = (authHeader || "").replace(/^Bearer\s+/i, "").trim();
  return verifyToken(tok, secret);
}
assert(syncAuthCheck("", TEST_SECRET) === null, "empty auth header rejected");
assert(syncAuthCheck("Bearer invalid", TEST_SECRET) === null, "invalid token rejected");
const goodToken = signToken("user@example.com", 1, TEST_SECRET);
assert(syncAuthCheck("Bearer " + goodToken, TEST_SECRET) === "user@example.com", "valid bearer token accepted");
assert(syncAuthCheck("bearer " + goodToken, TEST_SECRET) === "user@example.com", "case-insensitive Bearer prefix");

console.log("\n--- market.js: kind validation ---");

const VALID_KINDS = new Set(["top50", "top100", "gainers", "losers", "trending", "fear-greed", "global"]);
assert(VALID_KINDS.has("fear-greed"), "fear-greed is a valid kind");
assert(VALID_KINDS.has("global"), "global is a valid kind");
assert(!VALID_KINDS.has("invalid"), "invalid kind is rejected");
assert(!VALID_KINDS.has(""), "empty kind is rejected");

// --- Summary ---
console.log("\n==========================================");
console.log("Results: " + passed + " passed, " + failed + " failed");
if (failed > 0) process.exit(1);
