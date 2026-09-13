// Unit tests for auth.js logic (token signing, verification, validation).
// Run with: node tests/auth.test.js

const crypto = require("crypto");

// --- Inline the token helpers (copied from auth.js / sync.js) ---

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
    const expectBuf = Buffer.from(crypto.createHmac("sha256", secret).update(p).digest("base64url"));
    const sigBuf = Buffer.from(sig);
    if (expectBuf.length !== sigBuf.length) return null;
    if (!crypto.timingSafeEqual(expectBuf, sigBuf)) return null;
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
  const exp = Date.now() - 1000; // already expired
  const p = Buffer.from(email + "|" + exp).toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(p).digest("base64url");
  return p + "." + sig;
}
const expiredToken = signExpired("user@example.com", TEST_SECRET);
assert(verifyToken(expiredToken, TEST_SECRET) === null, "expired token returns null");

console.log("\n--- auth token: length-mismatch tamper guard ---");

// A token with a padded/truncated signature should be rejected without throwing
const parts = token.split(".");
const shortSig = parts[1].slice(0, 10);
const paddedSig = parts[1] + "AAAA";
assert(verifyToken(parts[0] + "." + shortSig, TEST_SECRET) === null, "truncated sig rejected");
assert(verifyToken(parts[0] + "." + paddedSig, TEST_SECRET) === null, "padded sig rejected");

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
assert(validateIds("bitcoin,ethereum,solana,cardano,ripple,doge").length === 6, "six ids all pass");

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

function escAlerts(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
assert(escAlerts("<BTC>") === "&lt;BTC&gt;", "angle brackets escaped in ticker");
assert(escAlerts("ETH & BNB") === "ETH &amp; BNB", "ampersand escaped in name");
assert(escAlerts('BTC"injection"') === "BTC&quot;injection&quot;", "quotes escaped");

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

console.log("\n--- generate.js: message validation ---");

function isValidMessage(m) {
  if (!m || typeof m !== "object" || Array.isArray(m)) return false;
  if (m.role !== "user" && m.role !== "assistant") return false;
  if (typeof m.content !== "string" || !m.content.trim()) return false;
  return true;
}
assert(isValidMessage({ role: "user", content: "hello" }), "user message passes");
assert(isValidMessage({ role: "assistant", content: "reply" }), "assistant message passes");
assert(!isValidMessage({ role: "system", content: "inject" }), "system role rejected");
assert(!isValidMessage({ role: "user", content: "" }), "empty content rejected");
assert(!isValidMessage({ role: "user", content: "   " }), "whitespace-only content rejected");
assert(!isValidMessage(null), "null message rejected");
assert(!isValidMessage([]), "array rejected");
assert(!isValidMessage({ content: "no role" }), "missing role rejected");
assert(!isValidMessage({ role: "user" }), "missing content rejected");

console.log("\n--- generate.js: message count and size limits ---");

const MAX_MESSAGES = 20;
const MAX_CONTENT_CHARS = 40000;

function validateMessages(messages) {
  if (!Array.isArray(messages) || !messages.length) return { ok: false, error: "missing messages" };
  if (!messages.every(isValidMessage)) return { ok: false, error: "invalid message" };
  if (messages.length > MAX_MESSAGES) return { ok: false, error: "too many messages" };
  const total = messages.reduce(function (s, m) { return s + m.content.length; }, 0);
  if (total > MAX_CONTENT_CHARS) return { ok: false, error: "content too large" };
  return { ok: true };
}

assert(validateMessages([{ role: "user", content: "hi" }]).ok, "single valid message passes");
assert(!validateMessages([]).ok, "empty array rejected");
assert(!validateMessages(null).ok, "null rejected");
const tooMany = Array.from({ length: 21 }, function (_, i) { return { role: i % 2 === 0 ? "user" : "assistant", content: "msg" }; });
assert(!validateMessages(tooMany).ok, "21 messages rejected");
const exactly20 = tooMany.slice(0, 20);
assert(validateMessages(exactly20).ok, "20 messages accepted");
const bigMsg = [{ role: "user", content: "a".repeat(40001) }];
assert(!validateMessages(bigMsg).ok, "40001 chars rejected");
const maxMsg = [{ role: "user", content: "a".repeat(40000) }];
assert(validateMessages(maxMsg).ok, "40000 chars accepted");

console.log("\n--- newsletter: briefToHtml ---");

function briefToHtml(text) {
  function escHtml(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
  return escHtml(text)
    .replace(/\*\*(.*?)\*\*/g, "<strong style='color:#f0ece4'>$1</strong>")
    .split(/\n+/)
    .filter(function (l) { return l.trim(); })
    .map(function (l) { return "<p style='margin:0 0 12px;color:#c8c4bc;font-size:15px;line-height:1.7'>" + l.trim() + "</p>"; })
    .join("");
}

const briefOut = briefToHtml("**Bold label** — plain text");
assert(briefOut.includes("<strong"), "bold converted to strong tag");
assert(briefOut.includes("Bold label"), "bold text preserved");
assert(briefOut.includes("<p "), "paragraphs wrapped");

const xssBrief = briefToHtml("<script>alert(1)</script>");
assert(!xssBrief.includes("<script>"), "script tags escaped in brief");
assert(xssBrief.includes("&lt;script&gt;"), "script tags HTML-encoded");

const multiline = briefToHtml("Line one\n\nLine two");
assert(multiline.split("<p ").length === 3, "two paragraphs from two lines");

const emptyLines = briefToHtml("Text\n\n\n\nMore text");
assert(emptyLines.split("<p ").length === 3, "extra blank lines collapsed");

console.log("\n--- sync.js: data validation ---");

function validateSyncData(p) {
  if (!p.data || typeof p.data !== "object" || Array.isArray(p.data)) return false;
  return true;
}
assert(validateSyncData({ data: {} }), "empty object passes");
assert(validateSyncData({ data: { wl: [], port: {} } }), "valid data object passes");
assert(!validateSyncData({ data: null }), "null data rejected");
assert(!validateSyncData({ data: [] }), "array data rejected");
assert(!validateSyncData({}), "missing data field rejected");
assert(!validateSyncData({ data: "string" }), "string data rejected");

console.log("\n--- market.js: Fear & Greed transform ---");

function transformFg(d) {
  return { data: (d.data || []).map(function (e) { return { value: +e.value, label: e.value_classification, timestamp: +e.timestamp }; }) };
}
const fgRaw = { data: [{ value: "45", value_classification: "Fear", timestamp: "1700000000" }] };
const fgOut = transformFg(fgRaw);
assert(Array.isArray(fgOut.data), "fg data is array");
assert(fgOut.data[0].value === 45, "fg value parsed as number");
assert(fgOut.data[0].label === "Fear", "fg label preserved");
assert(fgOut.data[0].timestamp === 1700000000, "fg timestamp parsed as number");
assert(transformFg({}).data.length === 0, "empty fg response → empty array");

// --- Summary ---
console.log("\n==========================================");
console.log("Results: " + passed + " passed, " + failed + " failed");
if (failed > 0) process.exit(1);
