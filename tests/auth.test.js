// Unit tests for BullrunIQ server logic.
// Run with: node tests/auth.test.js

const crypto = require("crypto");

// --- Inline helpers (copied from their respective source files) ---

const TEST_SECRET = "test-secret-key-for-unit-tests";

function signToken(email, days, secret) {
  const exp = Date.now() + (days || 30) * 864e5;
  const p = Buffer.from(email + "|" + exp).toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(p).digest("base64url");
  return p + "." + sig;
}

// Mirrors _shared.js: decodes both sides as base64url before timingSafeEqual
// so a mismatched-length sig returns null instead of throwing.
function verifyToken(tok, secret) {
  try {
    if (!secret || !tok) return null;
    const i = tok.lastIndexOf(".");
    if (i < 1) return null;
    const p = tok.slice(0, i), sig = tok.slice(i + 1);
    const expect = crypto.createHmac("sha256", secret).update(p).digest("base64url");
    const eBuf = Buffer.from(expect, "base64url");
    const sBuf = Buffer.from(sig, "base64url");
    if (eBuf.length !== sBuf.length) return null;
    if (!crypto.timingSafeEqual(eBuf, sBuf)) return null;
    const raw = Buffer.from(p, "base64url").toString("utf8");
    const j = raw.lastIndexOf("|");
    const email = raw.slice(0, j), exp = parseInt(raw.slice(j + 1), 10);
    if (!email || !exp || Date.now() > exp) return null;
    return email;
  } catch (e) { return null; }
}

// HTML escaper used in alert emails and unsubscribe page
function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
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

// ─────────────────────────────────────────────────────────
console.log("\n--- auth token: sign + verify ---");

const token = signToken("user@example.com", 30, TEST_SECRET);
assert(typeof token === "string" && token.includes("."), "token has two parts");
assert(verifyToken(token, TEST_SECRET) === "user@example.com", "valid token verifies to email");
assert(verifyToken(token, "wrong-secret") === null, "wrong secret returns null");
assert(verifyToken("", TEST_SECRET) === null, "empty token returns null");
assert(verifyToken("invalid.token", TEST_SECRET) === null, "tampered token returns null");
assert(verifyToken(null, TEST_SECRET) === null, "null token returns null");

// ─────────────────────────────────────────────────────────
console.log("\n--- auth token: expiry ---");

function signExpired(email, secret) {
  const exp = Date.now() - 1000; // already expired
  const p = Buffer.from(email + "|" + exp).toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(p).digest("base64url");
  return p + "." + sig;
}
const expiredToken = signExpired("user@example.com", TEST_SECRET);
assert(verifyToken(expiredToken, TEST_SECRET) === null, "expired token returns null");

// ─────────────────────────────────────────────────────────
console.log("\n--- auth token: email embedding ---");

const emails = ["test@example.com", "user+tag@sub.domain.io", "A@B.CO"];
for (const em of emails) {
  const t = signToken(em.toLowerCase(), 1, TEST_SECRET);
  assert(verifyToken(t, TEST_SECRET) === em.toLowerCase(), "round-trips: " + em);
}

// ─────────────────────────────────────────────────────────
console.log("\n--- auth token: buffer-length mismatch (timingSafeEqual safety) ---");

// A sig that's shorter or longer than the expected 43-char base64url output should
// return null cleanly rather than throwing from timingSafeEqual.
const goodToken = signToken("a@b.com", 1, TEST_SECRET);
const [payload] = goodToken.split(".");
assert(verifyToken(payload + ".short", TEST_SECRET) === null, "short sig returns null (no throw)");
assert(verifyToken(payload + "." + "A".repeat(100), TEST_SECRET) === null, "long sig returns null (no throw)");

// ─────────────────────────────────────────────────────────
console.log("\n--- unsubscribe: email validation ---");

function isValidEmail(s) {
  return typeof s === "string" && s.length > 0 && s.length <= 200 && s.indexOf("@") > 0;
}
assert(isValidEmail("a@b.com"), "valid email passes");
assert(!isValidEmail(""), "empty string fails");
assert(!isValidEmail("notanemail"), "missing @ fails");
assert(!isValidEmail("@nodomain"), "@ at start fails");
assert(!isValidEmail("a".repeat(201) + "@b.com"), "too long fails");

// ─────────────────────────────────────────────────────────
console.log("\n--- HTML escaping (XSS guard) ---");

assert(esc("<script>alert(1)</script>") === "&lt;script&gt;alert(1)&lt;/script&gt;", "script tags escaped");
assert(esc('"><img src=x onerror=alert(1)>') === "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;", "attribute injection escaped");
assert(esc("safe text") === "safe text", "safe text unchanged");
assert(esc("a&b") === "a&amp;b", "ampersand escaped");
assert(esc("it's") === "it&#x27;s", "single quote escaped");

// ─────────────────────────────────────────────────────────
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

// ─────────────────────────────────────────────────────────
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

// ─────────────────────────────────────────────────────────
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

// ─────────────────────────────────────────────────────────
console.log("\n--- submission-created: contact form filter ---");

function shouldSubscribe(formName) {
  if (formName === "contact" || formName === "contact-form") return false;
  return true;
}
assert(shouldSubscribe("waitlist"), "waitlist form gets subscribed");
assert(shouldSubscribe("tier-signup"), "tier-signup form gets subscribed");
assert(!shouldSubscribe("contact"), "contact form is skipped");
assert(!shouldSubscribe("contact-form"), "contact-form variant is skipped");

// ─────────────────────────────────────────────────────────
console.log("\n--- news.js: URL scheme validation ---");

function isHttpUrl(url) {
  return /^https?:\/\//i.test(url);
}
assert(isHttpUrl("https://coindesk.com/article"), "https URL passes");
assert(isHttpUrl("http://cointelegraph.com/news/test"), "http URL passes");
assert(!isHttpUrl("javascript:alert(1)"), "javascript: URL blocked");
assert(!isHttpUrl("data:text/html,<h1>xss</h1>"), "data: URL blocked");
assert(!isHttpUrl(""), "empty URL blocked");

// ─────────────────────────────────────────────────────────
console.log("\n--- news.js: decodeEntities ---");

function decodeEntities(s) {
  return String(s)
    .replace(/<!\[CDATA\[|\]\]>/g, "")
    .replace(/&#(\d+);/g, function (_, n) { return String.fromCharCode(+n); })
    .replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#039;|&apos;/g, "'")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&nbsp;/g, " ").trim();
}
assert(decodeEntities("<![CDATA[headline]]>") === "headline", "CDATA wrapper stripped");
assert(decodeEntities("Bitcoin &amp; Crypto") === "Bitcoin & Crypto", "amp entity decoded");
assert(decodeEntities("&#36;100") === "$100", "numeric entity decoded");
assert(decodeEntities("&quot;quoted&quot;") === '"quoted"', "quote entity decoded");
assert(decodeEntities("  padded  ") === "padded", "whitespace trimmed");

// ─────────────────────────────────────────────────────────
console.log("\n--- alerts: HTML escaping in emails ---");

assert(esc("<BTC>") === "&lt;BTC&gt;", "angle brackets escaped in ticker");
assert(esc("ETH & BNB") === "ETH &amp; BNB", "ampersand escaped in name");
assert(esc('BTC"injection"') === "BTC&quot;injection&quot;", "quotes escaped");

// ─────────────────────────────────────────────────────────
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

// ─────────────────────────────────────────────────────────
console.log("\n--- portfolio guard: trailing stop ---");

function shouldTrailingAlert(h, price) {
  if (!h.trailingPct || !h.serverHwm || h.serverHwm <= 0) return false;
  const drawdown = (h.serverHwm - price) / h.serverHwm * 100;
  return drawdown >= h.trailingPct && !h.serverTrailingAlerted;
}
function shouldRearmTrailing(h, price) {
  if (!h.trailingPct || !h.serverHwm) return false;
  const drawdown = (h.serverHwm - price) / h.serverHwm * 100;
  return drawdown < h.trailingPct * 0.5 && !!h.serverTrailingAlerted;
}

const trailingH = { ticker: "SOL", avg: 100, qty: 10, trailingPct: 20, serverHwm: 200 };
assert(shouldTrailingAlert({ ...trailingH }, 155), "trailing alert at 22.5% drawdown from HWM");
assert(shouldTrailingAlert({ ...trailingH }, 160), "trailing alert at exactly 20% drawdown");
assert(!shouldTrailingAlert({ ...trailingH }, 170), "no alert at 15% drawdown (below threshold)");
assert(!shouldTrailingAlert({ ...trailingH, serverTrailingAlerted: true }, 155), "no duplicate trailing alert");
assert(shouldRearmTrailing({ ...trailingH, serverTrailingAlerted: true }, 196), "trailing re-arms near HWM");
assert(!shouldRearmTrailing({ ...trailingH, serverTrailingAlerted: true }, 170), "no re-arm mid-drawdown");
assert(!shouldTrailingAlert({ ticker: "BTC", avg: 50000, qty: 1 }, 45000), "no trailingPct set → no alert");

// ─────────────────────────────────────────────────────────
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

// ─────────────────────────────────────────────────────────
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

// ─────────────────────────────────────────────────────────
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

const nowTs = Math.floor(Date.now() / 1000);
const whPayload = '{"type":"checkout.session.completed","id":"cs_test_123"}';
const whSecret = "whsec_testkey123";
const signedStr = nowTs + "." + whPayload;
const v1Hex = crypto.createHmac("sha256", whSecret).update(signedStr, "utf8").digest("hex");
const validSig = `t=${nowTs},v1=${v1Hex}`;

assert(verifyStripe(whPayload, validSig, whSecret), "valid stripe signature passes");
assert(!verifyStripe(whPayload, validSig, "wrong-secret"), "wrong secret fails");
assert(!verifyStripe(whPayload, `t=${nowTs},v1=deadbeef0000`, whSecret), "tampered v1 fails");
assert(!verifyStripe(whPayload, "", whSecret), "empty sig header fails");
assert(!verifyStripe(whPayload, null, whSecret), "null sig header fails");
assert(!verifyStripe(whPayload, `t=${nowTs},v1=${v1Hex}`, null), "null secret fails");

// Old timestamp (> 5 min) — must use correct sig for that old timestamp to test age check
const oldTs = nowTs - 400;
const oldSignedStr = oldTs + "." + whPayload;
const oldV1 = crypto.createHmac("sha256", whSecret).update(oldSignedStr, "utf8").digest("hex");
assert(!verifyStripe(whPayload, `t=${oldTs},v1=${oldV1}`, whSecret), "expired stripe signature (>5min) fails");

// ─────────────────────────────────────────────────────────
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
assert(briefToHtml("**Bold** text").includes("<strong"), "bold markdown rendered");
assert(briefToHtml("**Bold** text").includes("Bold"), "bold content preserved");
assert(!briefToHtml("**Bold** text").includes("**"), "markdown markers removed");
assert(briefToHtml("<script>xss</script>").includes("&lt;script&gt;"), "HTML in brief is escaped");
assert(briefToHtml("Line 1\n\nLine 2").split("<p").length - 1 === 2, "double-newline splits into two paragraphs");
assert(briefToHtml("Line 1\nLine 2").split("<p").length - 1 === 2, "single-newline also splits paragraphs");
assert(briefToHtml("").trim() === "", "empty brief returns empty string");
assert(briefToHtml("   ").trim() === "", "whitespace-only brief returns empty string");

// ─────────────────────────────────────────────────────────
// --- Summary ---
console.log("\n==========================================");
console.log("Results: " + passed + " passed, " + failed + " failed");
if (failed > 0) process.exit(1);
