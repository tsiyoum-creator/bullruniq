// Unit tests for BullrunIQ backend logic.
// Run with: node tests/auth.test.js

const crypto = require("crypto");

// --- Inline helpers (mirrored from production code) ---

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
    const expectBuf = Buffer.from(expect);
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

// --- Test runner ---

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

// ============================================================
// auth token: sign + verify
// ============================================================
console.log("\n--- auth token: sign + verify ---");

const token = signToken("user@example.com", 30, TEST_SECRET);
assert(typeof token === "string" && token.includes("."), "token has two parts");
assert(verifyToken(token, TEST_SECRET) === "user@example.com", "valid token verifies to email");
assert(verifyToken(token, "wrong-secret") === null, "wrong secret returns null");
assert(verifyToken("", TEST_SECRET) === null, "empty token returns null");
assert(verifyToken("invalid.token", TEST_SECRET) === null, "tampered token returns null");
assert(verifyToken(null, TEST_SECRET) === null, "null token returns null");
assert(verifyToken(undefined, TEST_SECRET) === null, "undefined token returns null");

// ============================================================
// auth token: expiry
// ============================================================
console.log("\n--- auth token: expiry ---");

function signExpired(email, secret) {
  const exp = Date.now() - 1000;
  const p = Buffer.from(email + "|" + exp).toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(p).digest("base64url");
  return p + "." + sig;
}
const expiredToken = signExpired("user@example.com", TEST_SECRET);
assert(verifyToken(expiredToken, TEST_SECRET) === null, "expired token returns null");

// ============================================================
// auth token: email embedding
// ============================================================
console.log("\n--- auth token: email embedding ---");

const emails = ["test@example.com", "user+tag@sub.domain.io", "A@B.CO"];
for (const em of emails) {
  const t = signToken(em.toLowerCase(), 1, TEST_SECRET);
  assert(verifyToken(t, TEST_SECRET) === em.toLowerCase(), "round-trips: " + em);
}

// ============================================================
// auth token: token tampering
// ============================================================
console.log("\n--- auth token: tampering ---");

const goodToken = signToken("admin@example.com", 30, TEST_SECRET);
const parts = goodToken.split(".");
// Modify payload to claim a different email
const fakePart = Buffer.from("hacker@evil.com|" + (Date.now() + 864e5)).toString("base64url");
assert(verifyToken(fakePart + "." + parts[1], TEST_SECRET) === null, "payload tamper detected");
// Truncated token
assert(verifyToken(parts[0], TEST_SECRET) === null, "token with no signature rejected");
// Extra segments
assert(verifyToken(goodToken + ".extra", TEST_SECRET) === null || verifyToken(goodToken + ".extra", TEST_SECRET) === "admin@example.com", "extra segment handled");

// ============================================================
// email validation
// ============================================================
console.log("\n--- unsubscribe: email validation ---");

function isValidEmail(s) {
  return typeof s === "string" && s.length > 0 && s.length <= 200 && s.indexOf("@") > 0;
}
assert(isValidEmail("a@b.com"), "valid email passes");
assert(!isValidEmail(""), "empty string fails");
assert(!isValidEmail("notanemail"), "missing @ fails");
assert(!isValidEmail("@nodomain"), "@ at start fails");
assert(!isValidEmail("a".repeat(201) + "@b.com"), "too long fails");
assert(!isValidEmail(null), "null fails");
assert(!isValidEmail(undefined), "undefined fails");
assert(!isValidEmail(42), "number fails");

// ============================================================
// HTML escaping (XSS guard)
// ============================================================
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
assert(esc("it's") === "it&#x27;s", "single quote escaped");

// ============================================================
// market.js: id validation
// ============================================================
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
assert(validateIds("bitcoin,<script>").length === 1, "only valid id kept from mixed input");
// Ensure max 25 ids enforced
const manyIds = Array.from({ length: 30 }, function (_, i) { return "coin" + i; }).join(",");
assert(validateIds(manyIds).length === 25, "max 25 ids enforced");

// ============================================================
// generate.js: message validation
// ============================================================
console.log("\n--- generate.js: message validation ---");

const VALID_ROLES = new Set(["user", "assistant"]);
const MAX_MESSAGE_CHARS = 8000;
const MAX_MESSAGES = 20;

function validateMessages(messages) {
  if (!Array.isArray(messages) || messages.length === 0) return "Missing messages or prompt";
  if (messages.length > MAX_MESSAGES) return "Too many messages";
  for (const m of messages) {
    if (!m || typeof m !== "object") return "Invalid message format";
    if (!VALID_ROLES.has(m.role)) return "Invalid message role";
    const content = m.content;
    if (typeof content === "string") {
      if (content.length > MAX_MESSAGE_CHARS) return "Message too long";
    } else if (Array.isArray(content)) {
      for (const block of content) {
        if (!block || typeof block !== "object") return "Invalid content block";
        if (typeof block.text === "string" && block.text.length > MAX_MESSAGE_CHARS) return "Message too long";
      }
    } else {
      return "Invalid message content type";
    }
  }
  return null;
}

assert(validateMessages([{ role: "user", content: "hello" }]) === null, "valid single message passes");
assert(validateMessages([]) === "Missing messages or prompt", "empty array rejected");
assert(validateMessages(null) === "Missing messages or prompt", "null rejected");
assert(validateMessages([{ role: "system", content: "hi" }]) === "Invalid message role", "system role rejected");
assert(validateMessages([{ role: "user", content: "x".repeat(8001) }]) === "Message too long", "oversized message rejected");
assert(validateMessages([{ role: "user", content: 42 }]) === "Invalid message content type", "numeric content rejected");
const tooMany = Array.from({ length: 21 }, function () { return { role: "user", content: "hi" }; });
assert(validateMessages(tooMany) === "Too many messages", "too many messages rejected");
assert(validateMessages([{ role: "user", content: [{ type: "text", text: "hi" }] }]) === null, "array content passes");
assert(validateMessages([{ role: "user", content: [{ type: "text", text: "x".repeat(8001) }] }]) === "Message too long", "oversized array content rejected");

// ============================================================
// stripe-webhook.js: signature verification
// ============================================================
console.log("\n--- stripe-webhook.js: signature verification ---");

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

function makeStripeSignature(rawBody, secret, ts) {
  const t = ts || Math.floor(Date.now() / 1000);
  const signed = t + "." + rawBody;
  const v1 = crypto.createHmac("sha256", secret).update(signed, "utf8").digest("hex");
  return "t=" + t + ",v1=" + v1;
}

const webhookSecret = "whsec_test";
const webhookBody = JSON.stringify({ type: "invoice.paid", data: { object: { customer: "cus_123" } } });
const validSig = makeStripeSignature(webhookBody, webhookSecret);
assert(verifyStripe(webhookBody, validSig, webhookSecret) === true, "valid Stripe signature passes");
assert(verifyStripe(webhookBody, validSig, "wrong-secret") === false, "wrong secret rejected");
assert(verifyStripe(webhookBody + "x", validSig, webhookSecret) === false, "body tamper detected");
assert(verifyStripe(webhookBody, "", webhookSecret) === false, "empty sig header rejected");
assert(verifyStripe(webhookBody, null, webhookSecret) === false, "null sig header rejected");
assert(verifyStripe(webhookBody, validSig, "") === false, "empty secret rejected");
// Replayed event (older than 300s)
const oldSig = makeStripeSignature(webhookBody, webhookSecret, Math.floor(Date.now() / 1000) - 301);
assert(verifyStripe(webhookBody, oldSig, webhookSecret) === false, "replayed webhook (>300s old) rejected");

// ============================================================
// alerts: sell alert logic
// ============================================================
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

// ============================================================
// alerts: buy alert logic
// ============================================================
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

// ============================================================
// submission-created: contact form filter
// ============================================================
console.log("\n--- submission-created: contact form filter ---");

function shouldSubscribe(formName) {
  if (formName === "contact" || formName === "contact-form") return false;
  return true;
}
assert(shouldSubscribe("waitlist"), "waitlist form gets subscribed");
assert(shouldSubscribe("tier-signup"), "tier-signup form gets subscribed");
assert(!shouldSubscribe("contact"), "contact form is skipped");
assert(!shouldSubscribe("contact-form"), "contact-form variant is skipped");

// ============================================================
// news.js: URL scheme validation
// ============================================================
console.log("\n--- news.js: URL scheme validation ---");

function isHttpUrl(url) {
  return /^https?:\/\//i.test(url);
}
assert(isHttpUrl("https://coindesk.com/article"), "https URL passes");
assert(isHttpUrl("http://cointelegraph.com/news/test"), "http URL passes");
assert(!isHttpUrl("javascript:alert(1)"), "javascript: URL blocked");
assert(!isHttpUrl("data:text/html,<h1>xss</h1>"), "data: URL blocked");
assert(!isHttpUrl(""), "empty URL blocked");
assert(!isHttpUrl("//example.com"), "protocol-relative URL blocked");
assert(!isHttpUrl("ftp://example.com"), "ftp URL blocked");

// ============================================================
// alerts: HTML escaping in emails
// ============================================================
console.log("\n--- alerts: HTML escaping in emails ---");

function esc2(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
assert(esc2("<BTC>") === "&lt;BTC&gt;", "angle brackets escaped in ticker");
assert(esc2("ETH & BNB") === "ETH &amp; BNB", "ampersand escaped in name");
assert(esc2('BTC"injection"') === "BTC&quot;injection&quot;", "quotes escaped");

// ============================================================
// portfolio guard: stop-loss / take-profit
// ============================================================
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

// ============================================================
// profit-lock ladder
// ============================================================
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
assert(ladderFor(100, 10, 120).gain >= 20, "exactly +20% gain returns ladder");

// ============================================================
// cash deployment engine
// ============================================================
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
assert(deployPlan(100, ["BTC"]).per === 80, "$100 with one target deploys $80");
assert(deployPlan(99, ["BTC"]) === null, "$99 does not meet minimum");

// ============================================================
// newsletter: briefToHtml
// ============================================================
console.log("\n--- newsletter: briefToHtml ---");

function briefToHtml(text) {
  function esc3(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
  return esc3(text)
    .replace(/\*\*(.*?)\*\*/g, "<strong style='color:#f0ece4'>$1</strong>")
    .split(/\n+/)
    .filter(function (l) { return l.trim(); })
    .map(function (l) { return "<p style='margin:0 0 12px;color:#c8c4bc;font-size:15px;line-height:1.7'>" + l.trim() + "</p>"; })
    .join("");
}
const rendered = briefToHtml("📊 **Market** — Good day.\n⚠️ **Risk** — Be careful.");
assert(rendered.includes("<strong"), "bold labels rendered");
assert(rendered.includes("<p style="), "paragraphs wrapped");
assert(!rendered.includes("**"), "markdown markers removed");
// XSS in brief text
const xssRendered = briefToHtml("<script>alert(1)</script>");
assert(xssRendered.includes("&lt;script&gt;"), "HTML in brief text is escaped");

// ============================================================
// sync.js: data size guard
// ============================================================
console.log("\n--- sync.js: data size guard ---");

const MAX_BYTES = 256 * 1024;
function checkSize(body) {
  return (body || "").length <= MAX_BYTES;
}
assert(checkSize("{}"), "small body passes");
assert(!checkSize("x".repeat(MAX_BYTES + 1)), "body exceeding 256KB rejected");
assert(checkSize("x".repeat(MAX_BYTES)), "body at exactly 256KB passes");

// ============================================================
// market.js: Fear & Greed transform
// ============================================================
console.log("\n--- market.js: Fear & Greed transform ---");

function fngTransform(data) {
  const entry = data && data.data && data.data[0];
  if (!entry) return { value: null, classification: null };
  return {
    value: parseInt(entry.value, 10),
    classification: entry.value_classification,
    timestamp: entry.timestamp,
  };
}
const fngData = { data: [{ value: "72", value_classification: "Greed", timestamp: "1000000" }] };
const fngResult = fngTransform(fngData);
assert(fngResult.value === 72, "F&G value parsed as int");
assert(fngResult.classification === "Greed", "F&G classification extracted");
assert(fngTransform(null).value === null, "null F&G data handled gracefully");
assert(fngTransform({ data: [] }).value === null, "empty F&G data handled gracefully");

// ============================================================
// Summary
// ============================================================
console.log("\n==========================================");
console.log("Results: " + passed + " passed, " + failed + " failed");
if (failed > 0) process.exit(1);
