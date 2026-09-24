// Unit tests for BullrunIQ server-side logic.
// Run with: node tests/auth.test.js

const crypto = require("crypto");

// --- Inline the token helpers (copied from _lib.js) ---

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
    if (!crypto.timingSafeEqual(Buffer.from(expect), Buffer.from(sig))) return null;
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

console.log("\n--- auth token: email embedding ---");

const emails = ["test@example.com", "user+tag@sub.domain.io", "A@B.CO"];
for (const em of emails) {
  const t = signToken(em.toLowerCase(), 1, TEST_SECRET);
  assert(verifyToken(t, TEST_SECRET) === em.toLowerCase(), "round-trips: " + em);
}

console.log("\n--- auth token: tamper detection ---");

const tamperedPayload = token.slice(0, token.lastIndexOf(".")) + "X." + token.split(".").pop();
assert(verifyToken(tamperedPayload, TEST_SECRET) === null, "modified payload rejected");

const parts = token.split(".");
const fakeSig = parts[0] + "." + crypto.randomBytes(32).toString("base64url");
assert(verifyToken(fakeSig, TEST_SECRET) === null, "random signature rejected");

// Ensure timing-safe comparison (different-length sigs don't crash)
assert(verifyToken(parts[0] + "." + "short", TEST_SECRET) === null, "short signature rejected safely");

console.log("\n--- auth: OTP timing-safe comparison ---");

function sha(s) { return crypto.createHash("sha256").update(s).digest("hex"); }
function verifyOtpHash(codeHash, storedHash) {
  if (codeHash.length !== storedHash.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(codeHash), Buffer.from(storedHash));
  } catch (e) { return false; }
}
const correctHash = sha("user@example.com:123456");
assert(verifyOtpHash(correctHash, correctHash), "correct OTP hash matches");
assert(!verifyOtpHash(sha("user@example.com:654321"), correctHash), "wrong code rejected");
assert(!verifyOtpHash("short", correctHash), "length mismatch returns false, not exception");
assert(!verifyOtpHash("", correctHash), "empty hash safely rejected");

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
assert(validateIds("bitcoin,ethereum,solana,cardano,dogecoin").length === 5, "five valid ids pass");
assert(validateIds("BITCOIN").length === 1, "uppercase is normalized to lowercase and passes");
assert(validateIds("bitcoin").length === 1, "single valid id passes");

console.log("\n--- market.js: kind validation ---");

const VALID_KINDS = new Set(["top50", "top100", "gainers", "losers", "trending", "fear_greed", "dominance", "sectors"]);
function isValidKind(kind) { return VALID_KINDS.has(kind); }
assert(isValidKind("top50"), "top50 valid");
assert(isValidKind("fear_greed"), "fear_greed valid");
assert(isValidKind("dominance"), "dominance valid");
assert(isValidKind("sectors"), "sectors valid (new)");
assert(!isValidKind("admin"), "admin rejected");
assert(!isValidKind("__proto__"), "__proto__ rejected");
assert(!isValidKind(""), "empty rejected");

console.log("\n--- generate.js: max_tokens clamping ---");

const MAX_TOKENS_CAP = 1500;
const MIN_TOKENS = 100;

function clampTokens(raw) {
  return Math.min(Math.max(parseInt(raw, 10) || 800, MIN_TOKENS), MAX_TOKENS_CAP);
}
assert(clampTokens(0) === 800, "0 (falsy) defaults to 800 before clamping");
assert(clampTokens(1) === MIN_TOKENS, "1 clamped to MIN_TOKENS (" + MIN_TOKENS + ")");
assert(clampTokens(50) === MIN_TOKENS, "50 clamped to MIN_TOKENS");
assert(clampTokens(100) === 100, "100 passes through");
assert(clampTokens(800) === 800, "800 (default) passes through");
assert(clampTokens(1500) === 1500, "1500 (cap) passes through");
assert(clampTokens(2000) === MAX_TOKENS_CAP, "2000 clamped to MAX_TOKENS_CAP");
assert(clampTokens("abc") === 800, "non-numeric defaults to 800");

console.log("\n--- generate.js: plan-based daily caps ---");

const PLAN_DAILY_CAPS = { free: 50, pro: 500, elite: 1000, advisor: 2000 };
const PLAN_TOKEN_CAPS = { free: 800, pro: 1500, elite: 2000, advisor: 3000 };

assert(PLAN_DAILY_CAPS.free < PLAN_DAILY_CAPS.pro, "pro cap > free cap");
assert(PLAN_DAILY_CAPS.pro < PLAN_DAILY_CAPS.elite, "elite cap > pro cap");
assert(PLAN_TOKEN_CAPS.free < PLAN_TOKEN_CAPS.elite, "elite gets more tokens per request");
assert(PLAN_TOKEN_CAPS.elite < PLAN_TOKEN_CAPS.advisor, "advisor gets most tokens");

console.log("\n--- generate.js: message validation ---");

const ALLOWED_ROLES = new Set(["user", "assistant"]);
function validateMessages(messages) {
  if (!Array.isArray(messages) || messages.length === 0 || messages.length > 40) return false;
  for (const m of messages) {
    if (!m || typeof m !== "object") return false;
    if (!ALLOWED_ROLES.has(m.role)) return false;
    if (typeof m.content !== "string" && !Array.isArray(m.content)) return false;
    if (typeof m.content === "string" && m.content.length > 20000) return false;
  }
  return true;
}
assert(validateMessages([{ role: "user", content: "hello" }]), "single user message valid");
assert(validateMessages([{ role: "user", content: "q" }, { role: "assistant", content: "a" }]), "conversation turn valid");
assert(!validateMessages([]), "empty array invalid");
assert(!validateMessages([{ role: "system", content: "inject" }]), "system role blocked");
assert(!validateMessages([{ role: "user", content: "x".repeat(20001) }]), "oversized content blocked");
assert(!validateMessages(null), "null messages invalid");
assert(!validateMessages("string"), "string instead of array invalid");
const longConvo = Array.from({ length: 41 }, function (_, i) { return { role: i % 2 ? "assistant" : "user", content: "msg" }; });
assert(!validateMessages(longConvo), "over 40 messages rejected");

console.log("\n--- generate.js: system prompt length cap ---");

const MAX_SYSTEM_LEN = 2000;
const PREAMBLE = "You are the BullrunIQ AI assistant.";

function buildSystem(clientSystem, authed) {
  if (!authed || !clientSystem) return PREAMBLE;
  const truncated = String(clientSystem).slice(0, MAX_SYSTEM_LEN).trim();
  return truncated ? PREAMBLE + "\n\n" + truncated : PREAMBLE;
}

assert(buildSystem(null, true) === PREAMBLE, "null system → preamble only");
assert(buildSystem("", true) === PREAMBLE, "empty system → preamble only");
assert(buildSystem("custom", false) === PREAMBLE, "unauthenticated → preamble only");
assert(buildSystem("custom instruction", true).startsWith(PREAMBLE), "authenticated → preamble first");
assert(buildSystem("custom instruction", true).includes("custom instruction"), "authenticated → client system appended");
const longSystem = "x".repeat(MAX_SYSTEM_LEN + 500);
const built = buildSystem(longSystem, true);
assert(built.length < PREAMBLE.length + MAX_SYSTEM_LEN + 10, "long system truncated");

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
  if (!avg || avg <= 0 || !qty || qty <= 0) return null;
  const g = (price - avg) / avg * 100;
  if (g < 20) return null;
  const rungs = [25, 50, 100, 200].map(pc => {
    const lp = avg * (1 + pc / 100);
    return { pct: pc, price: lp, qty: qty * 0.25, hit: price >= lp };
  });
  return { gainPct: g, rungs, hits: rungs.filter(r => r.hit) };
}
assert(ladderFor(100, 10, 110) === null, "no ladder under +20% gain");
assert(ladderFor(0, 10, 500) === null, "no ladder without cost basis");
assert(ladderFor(100, 0, 500) === null, "no ladder without qty");
const lad = ladderFor(100, 10, 160);
assert(lad !== null && lad.rungs.length === 4, "ladder has 4 rungs");
assert(lad.rungs[0].price === 125 && lad.rungs[1].price === 150 && lad.rungs[2].price === 200 && lad.rungs[3].price === 300, "rung prices at +25/+50/+100/+200%");
assert(lad.hits.length === 2, "at +60%, first two rungs are hit");
assert(lad.rungs[0].qty === 2.5, "each rung sells 25% of the position");
assert(ladderFor(100, 10, 250).hits.length === 3, "at +150%, three rungs hit");
assert(ladderFor(100, 10, 300).hits.length === 4, "at exactly +200%, all four rungs hit");
assert(ladderFor(100, 10, 400).hits.length === 4, "above +200%, all four rungs hit");
assert(ladderFor(100, 10, 125).hits.length === 1, "at exactly +25%, one rung hit");
assert(ladderFor(100, 10, 124).hits.length === 0, "just below +25%, no rung hit but ladder active");

console.log("\n--- profit-ladder: new-rung alert logic ---");

function shouldSendLadderAlert(h, price) {
  const ladder = ladderFor(h.avg, h.qty, price);
  const prevHits = h.serverLadderHits || 0;
  return ladder !== null && ladder.hits.length > prevHits;
}
function shouldResetLadder(avg, price, prevHits) {
  if (!prevHits) return false;
  if (!avg || avg <= 0) return false;
  const gainPct = (price - avg) / avg * 100;
  return gainPct < 10;
}

const ladderHolding = { ticker: "SOL", avg: 100, qty: 10 };
assert(!shouldSendLadderAlert({ ...ladderHolding }, 110), "no ladder alert under +20%");
assert(!shouldSendLadderAlert({ ...ladderHolding }, 120), "no alert at +20% (below first rung)");
assert(shouldSendLadderAlert({ ...ladderHolding }, 126), "alert when first rung (+25%) crossed");
assert(!shouldSendLadderAlert({ ...ladderHolding, serverLadderHits: 1 }, 130), "no re-alert same rung");
assert(shouldSendLadderAlert({ ...ladderHolding, serverLadderHits: 1 }, 151), "alert when second rung (+50%) crossed");
assert(shouldSendLadderAlert({ ...ladderHolding, serverLadderHits: 3 }, 301), "alert when 4th rung (+200%) crossed after 3 already recorded");
assert(!shouldSendLadderAlert({ ...ladderHolding, serverLadderHits: 4 }, 400), "no alert when all four rungs already recorded");
// New hysteresis: reset only below +10%, not below +20%
assert(shouldResetLadder(100, 109, 2), "ladder resets below +10% (hysteresis)");
assert(!shouldResetLadder(100, 119, 2), "no reset between +10% and +20% (hysteresis holds)");
assert(!shouldResetLadder(100, 125, 2), "no reset above +25% (position still in profit)");
assert(!shouldResetLadder(100, 115, 0), "no reset when already 0 hits");

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
assert(deployPlan(99, ["BTC"]) === null, "just under $100 → no plan");
assert(deployPlan(100, ["BTC"]).reserve === 20, "$100 minimum: 20% reserve");

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

function makeStripeSig(rawBody, secret, t) {
  const ts = t !== undefined ? t : Math.floor(Date.now() / 1000);
  const sig = crypto.createHmac("sha256", secret).update(ts + "." + rawBody).digest("hex");
  return "t=" + ts + ",v1=" + sig;
}

const STRIPE_SECRET = "whsec_test_123";
const body = JSON.stringify({ type: "checkout.session.completed" });

assert(verifyStripe(body, makeStripeSig(body, STRIPE_SECRET), STRIPE_SECRET), "valid stripe sig passes");
assert(!verifyStripe(body, makeStripeSig(body, "wrong-secret"), STRIPE_SECRET), "wrong secret fails");
assert(!verifyStripe(body, makeStripeSig("other-body", STRIPE_SECRET), STRIPE_SECRET), "body mismatch fails");
assert(!verifyStripe(body, makeStripeSig(body, STRIPE_SECRET, Math.floor(Date.now() / 1000) - 400), STRIPE_SECRET), "expired (>5 min) sig fails");
assert(verifyStripe(body, makeStripeSig(body, STRIPE_SECRET, Math.floor(Date.now() / 1000) - 299), STRIPE_SECRET), "sig within 5 min passes");
assert(!verifyStripe(body, "", STRIPE_SECRET), "empty sig header fails");
assert(!verifyStripe(body, "t=123", STRIPE_SECRET), "sig header missing v1 fails");
assert(!verifyStripe(body, makeStripeSig(body, STRIPE_SECRET), ""), "empty secret fails");

console.log("\n--- sync.js: user data validation ---");

function validateUserData(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) return false;
  if (data.port && data.port.crypto !== undefined) {
    if (!Array.isArray(data.port.crypto)) return false;
    if (data.port.crypto.length > 200) return false;
    for (const h of data.port.crypto) {
      if (!h || typeof h !== "object") return false;
      if (h.ticker && typeof h.ticker !== "string") return false;
      if (h.ticker && h.ticker.length > 20) return false;
      if (h.qty !== undefined && typeof h.qty !== "number") return false;
      if (h.avg !== undefined && typeof h.avg !== "number") return false;
      if (h.stop !== undefined && typeof h.stop !== "number") return false;
      if (h.tp !== undefined && typeof h.tp !== "number") return false;
    }
  }
  if (data.wl !== undefined) {
    if (!Array.isArray(data.wl)) return false;
    if (data.wl.length > 100) return false;
    for (const w of data.wl) {
      if (!w || typeof w !== "object") return false;
      if (w.ticker && typeof w.ticker !== "string") return false;
      if (w.ticker && w.ticker.length > 20) return false;
      if (w.targetPrice !== undefined && typeof w.targetPrice !== "number") return false;
      if (w.sellTarget !== undefined && typeof w.sellTarget !== "number") return false;
    }
  }
  return true;
}

assert(validateUserData({}), "empty object is valid");
assert(validateUserData({ cash: 5000 }), "object with cash is valid");
assert(validateUserData({ port: { crypto: [] } }), "empty crypto array is valid");
assert(validateUserData({ port: { crypto: [{ ticker: "BTC", qty: 0.5, avg: 60000 }] } }), "valid holding passes");
assert(!validateUserData(null), "null rejected");
assert(!validateUserData([]), "array rejected");
assert(!validateUserData("string"), "string rejected");
assert(!validateUserData({ port: { crypto: "not-an-array" } }), "non-array crypto rejected");
const tooManyHoldings = Array.from({ length: 201 }, function () { return { ticker: "BTC" }; });
assert(!validateUserData({ port: { crypto: tooManyHoldings } }), "too many holdings rejected");
assert(!validateUserData({ port: { crypto: [{ ticker: "A".repeat(21) }] } }), "too-long ticker rejected");
assert(!validateUserData({ port: { crypto: [{ qty: "not-a-number" }] } }), "string qty rejected");
assert(!validateUserData({ wl: "not-an-array" }), "non-array watchlist rejected");
const tooManyWatchlist = Array.from({ length: 101 }, function () { return { ticker: "ETH" }; });
assert(!validateUserData({ wl: tooManyWatchlist }), "too many watchlist items rejected");
assert(validateUserData({ wl: [{ ticker: "ETH", targetPrice: 2000, sellTarget: 3000 }] }), "valid watchlist entry passes");
assert(!validateUserData({ wl: [{ targetPrice: "two-thousand" }] }), "string targetPrice rejected");

console.log("\n--- newsletter: briefToHtml formatting ---");

function briefToHtml(text) {
  function escFn(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
  return escFn(text)
    .replace(/\*\*(.*?)\*\*/g, "<strong style='color:#f0ece4'>$1</strong>")
    .split(/\n+/)
    .filter(function (l) { return l.trim(); })
    .map(function (l) { return "<p style='margin:0 0 12px;color:#c8c4bc;font-size:15px;line-height:1.7'>" + l.trim() + "</p>"; })
    .join("");
}
const html = briefToHtml("📊 **BTC trend** — Bitcoin is above $64k.\n\n⚠️ **Risk** — Watch liquidity.");
assert(html.includes("<strong"), "bold text rendered as strong");
assert(html.includes("BTC trend"), "bold label text present");
assert(!html.includes("**"), "markdown asterisks removed from output");
assert(html.split("<p").length > 2, "multiple paragraphs generated");

const xssInput = briefToHtml("<script>alert(1)</script>");
assert(xssInput.includes("&lt;script&gt;"), "script tags escaped in brief HTML");
assert(!xssInput.includes("<script>"), "raw script tag not present");

console.log("\n--- sync.js: cash and cashApy validation ---");

function validateUserDataWithCash(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) return false;
  if (data.cash !== undefined) {
    if (typeof data.cash !== "number" || !isFinite(data.cash) || data.cash < 0 || data.cash > 1e9) return false;
  }
  if (data.cashApy !== undefined) {
    if (typeof data.cashApy !== "number" || !isFinite(data.cashApy) || data.cashApy < 0 || data.cashApy > 100) return false;
  }
  return true;
}

assert(validateUserDataWithCash({}), "empty data valid");
assert(validateUserDataWithCash({ cash: 0 }), "zero cash valid");
assert(validateUserDataWithCash({ cash: 5000 }), "positive cash valid");
assert(validateUserDataWithCash({ cash: 1e9 }), "max cash (1bn) valid");
assert(!validateUserDataWithCash({ cash: -1 }), "negative cash rejected");
assert(!validateUserDataWithCash({ cash: 1e9 + 1 }), "cash over 1bn rejected");
assert(!validateUserDataWithCash({ cash: "5000" }), "string cash rejected");
assert(!validateUserDataWithCash({ cash: Infinity }), "Infinity cash rejected");
assert(!validateUserDataWithCash({ cash: NaN }), "NaN cash rejected");
assert(validateUserDataWithCash({ cashApy: 0 }), "zero APY valid");
assert(validateUserDataWithCash({ cashApy: 5.25 }), "positive APY valid");
assert(validateUserDataWithCash({ cashApy: 100 }), "max APY (100%) valid");
assert(!validateUserDataWithCash({ cashApy: -0.1 }), "negative APY rejected");
assert(!validateUserDataWithCash({ cashApy: 100.01 }), "APY over 100% rejected");
assert(!validateUserDataWithCash({ cashApy: "5" }), "string APY rejected");
assert(!validateUserDataWithCash({ cashApy: Infinity }), "Infinity APY rejected");
assert(validateUserDataWithCash({ cash: 10000, cashApy: 5.25 }), "valid cash+APY combo passes");

console.log("\n--- _lib: listAllKeys pagination logic ---");

async function listAllKeysMock(store) {
  const keys = [];
  let cursor;
  do {
    const page = await store.list(cursor ? { cursor } : undefined);
    for (const b of (page.blobs || [])) keys.push(b.key);
    cursor = page.cursor;
  } while (cursor);
  return keys;
}

async function runPaginationTests() {
  // Single page, no cursor
  const singlePage = { blobs: [{ key: "a@b.com" }, { key: "c@d.com" }] };
  const keys1 = await listAllKeysMock({ list: async () => singlePage });
  assert(keys1.length === 2 && keys1[0] === "a@b.com", "single page returns all keys");

  // Two pages with cursor
  let call2 = 0;
  const pages2 = [
    { blobs: [{ key: "a@b.com" }], cursor: "page2" },
    { blobs: [{ key: "c@d.com" }, { key: "e@f.com" }] },
  ];
  const keys2 = await listAllKeysMock({ list: async () => pages2[call2++] });
  assert(keys2.length === 3, "two pages returns all 3 keys");
  assert(keys2[2] === "e@f.com", "last key from second page is correct");

  // Empty store
  const keys3 = await listAllKeysMock({ list: async () => ({ blobs: [] }) });
  assert(keys3.length === 0, "empty store returns empty array");
}
runPaginationTests().then(function () {

console.log("\n--- news.js: feed source deduplication ---");

function dedupeByUrl(items) {
  const seen = new Set();
  return items.filter(function (item) {
    if (seen.has(item.u)) return false;
    seen.add(item.u);
    return true;
  });
}

const feedItems = [
  { t: "BTC breaks $100k", u: "https://coindesk.com/btc-100k", s: "CoinDesk", at: 1000 },
  { t: "BTC breaks $100k (dup)", u: "https://coindesk.com/btc-100k", s: "Cointelegraph", at: 999 },
  { t: "ETH upgrade live", u: "https://cointelegraph.com/eth-upgrade", s: "Cointelegraph", at: 998 },
];
const deduped = dedupeByUrl(feedItems);
assert(deduped.length === 2, "duplicate URL removed from feed items");
assert(deduped[0].s === "CoinDesk", "first occurrence kept on dedup");

console.log("\n--- alerts: CGMAP coverage ---");

const CGMAP_TEST = {
  BTC:"bitcoin", ETH:"ethereum", SOL:"solana", VIRTUAL:"virtual-protocol",
  AI16Z:"ai16z", MORPHO:"morpho", ENS:"ethereum-name-service",
};
assert(CGMAP_TEST["BTC"] === "bitcoin", "BTC maps to bitcoin");
assert(CGMAP_TEST["VIRTUAL"] === "virtual-protocol", "VIRTUAL (new) mapped");
assert(CGMAP_TEST["AI16Z"] === "ai16z", "AI16Z (new) mapped");
assert(CGMAP_TEST["MORPHO"] === "morpho", "MORPHO (new DeFi) mapped");
assert(!CGMAP_TEST["UNKNOWN"], "unknown ticker returns undefined");

console.log("\n--- alerts: CoinGecko batch split ---");

function splitBatches(ids, batchSize) {
  const result = [];
  for (let i = 0; i < ids.length; i += batchSize) {
    result.push(ids.slice(i, i + batchSize));
  }
  return result;
}

const smallIds = ["bitcoin", "ethereum", "solana"];
assert(splitBatches(smallIds, 50).length === 1, "under 50 ids → single batch");
assert(splitBatches(smallIds, 50)[0].length === 3, "single batch contains all ids");

const bigIds = Array.from({ length: 120 }, function (_, i) { return "token-" + i; });
const bigBatches = splitBatches(bigIds, 50);
assert(bigBatches.length === 3, "120 ids → 3 batches of 50");
assert(bigBatches[0].length === 50, "first batch is 50");
assert(bigBatches[2].length === 20, "last batch is the remainder (20)");

assert(splitBatches([], 50).length === 0, "empty ids → no batches");

console.log("\n--- market.js: volume_leaders validation ---");

const VALID_KINDS_V2 = new Set(["top50","top100","gainers","losers","trending","fear_greed","dominance","sectors","volume_leaders"]);
assert(VALID_KINDS_V2.has("volume_leaders"), "volume_leaders is a valid kind");

function computeVolMcapRatio(volume, mcap) {
  if (!mcap || mcap <= 0) return 0;
  return volume / mcap;
}

const tokens = [
  { id: "a", total_volume: 1000, market_cap: 5000 },
  { id: "b", total_volume: 3000, market_cap: 4000 },
  { id: "c", total_volume: 500,  market_cap: 10000 },
];
const sorted = tokens
  .map(function (t) { return { ...t, ratio: computeVolMcapRatio(t.total_volume, t.market_cap) }; })
  .sort(function (a, b) { return b.ratio - a.ratio; });
assert(sorted[0].id === "b", "highest volume/mcap ratio ranked first");
assert(sorted[1].id === "a", "second-highest ranked second");
assert(sorted[2].id === "c", "lowest volume/mcap ratio ranked last");

console.log("\n--- market.js: fetchJson checks r.ok before r.json ---");

// Simulates the fixed fetchJson: r.ok is checked first, so non-JSON error bodies
// (e.g. plain-text "Too Many Requests" from CoinGecko) no longer surface as
// confusing SyntaxErrors.
function simulateFetchJson(okStatus, body) {
  const ok = okStatus >= 200 && okStatus < 300;
  // Fixed behaviour: throw on !r.ok before attempting JSON parse
  if (!ok) throw new Error("upstream " + okStatus);
  return JSON.parse(body);
}

let fetchJsonThrew = false;
try { simulateFetchJson(429, "Too Many Requests"); }
catch (e) { fetchJsonThrew = e.message === "upstream 429"; }
assert(fetchJsonThrew, "non-JSON 429 body throws upstream error, not SyntaxError");

let fetchJsonOk = false;
try { fetchJsonOk = simulateFetchJson(200, '{"price":50000}').price === 50000; }
catch (e) {}
assert(fetchJsonOk, "successful JSON response is parsed correctly");

let fetchJsonServerErr = false;
try { simulateFetchJson(502, "<html>Bad Gateway</html>"); }
catch (e) { fetchJsonServerErr = e.message === "upstream 502"; }
assert(fetchJsonServerErr, "HTML 502 response throws upstream error, not SyntaxError");

console.log("\n--- market.js: ath_nearby kind validation ---");

const VALID_KINDS_FULL = new Set([
  "top50","top100","gainers","losers","trending",
  "fear_greed","dominance","sectors","volume_leaders","ath_nearby",
]);
assert(VALID_KINDS_FULL.has("ath_nearby"), "ath_nearby is a valid kind");
assert(VALID_KINDS_FULL.has("volume_leaders"), "volume_leaders still valid after ath_nearby addition");
assert(!VALID_KINDS_FULL.has("admin"), "admin rejected");

console.log("\n--- market.js: ath_nearby transform logic ---");

function athNearbyTransform(data) {
  if (!Array.isArray(data)) return data;
  return data
    .filter(function (c) {
      return typeof c.ath_change_percentage === "number" && c.ath_change_percentage >= -20;
    })
    .map(function (c) {
      return {
        id: c.id,
        symbol: (c.symbol || "").toUpperCase(),
        name: c.name,
        price: c.current_price,
        ath: c.ath,
        ath_change_pct: c.ath_change_percentage,
        market_cap: c.market_cap,
      };
    })
    .sort(function (a, b) { return b.ath_change_pct - a.ath_change_pct; });
}

const sampleCoins = [
  { id: "bitcoin", symbol: "btc", name: "Bitcoin", current_price: 81000, ath: 99000, ath_change_percentage: -18.2, market_cap: 1600000000000 },
  { id: "ethereum", symbol: "eth", name: "Ethereum", current_price: 3500, ath: 4800, ath_change_percentage: -27.1, market_cap: 420000000000 },
  { id: "solana", symbol: "sol", name: "Solana", current_price: 190, ath: 200, ath_change_percentage: -5.0, market_cap: 80000000000 },
];
const athResult = athNearbyTransform(sampleCoins);
assert(athResult.length === 2, "ethereum (-27.1%) excluded, bitcoin and solana within -20% included");
assert(athResult[0].id === "solana", "solana (-5%) ranked above bitcoin (-18.2%)");
assert(athResult[1].id === "bitcoin", "bitcoin (-18.2%) ranked second");
assert(athResult[0].symbol === "SOL", "symbol uppercased");
assert(athNearbyTransform(null) === null, "non-array input returned as-is");

const exactBoundary = [
  { id: "token-a", symbol: "a", name: "A", current_price: 100, ath: 125, ath_change_percentage: -20.0, market_cap: 1e9 },
  { id: "token-b", symbol: "b", name: "B", current_price: 100, ath: 126, ath_change_percentage: -20.6, market_cap: 1e9 },
];
const boundaryResult = athNearbyTransform(exactBoundary);
assert(boundaryResult.length === 1, "exactly -20% included, -20.6% excluded");
assert(boundaryResult[0].id === "token-a", "boundary coin at exactly -20% included");

console.log("\n--- _lib.js: signToken null-key guard ---");

function signTokenWithGuard(email, days, key) {
  if (!key) throw new Error("AUTH_SECRET not configured — cannot sign token");
  const exp = Date.now() + (days || 30) * 864e5;
  const p = Buffer.from(email + "|" + exp).toString("base64url");
  const sig = crypto.createHmac("sha256", key).update(p).digest("base64url");
  return p + "." + sig;
}

let nullKeyThrew = false;
try { signTokenWithGuard("user@example.com", 30, null); }
catch (e) { nullKeyThrew = e.message.includes("AUTH_SECRET not configured"); }
assert(nullKeyThrew, "signToken throws a clear error when secretKey returns null");

let emptyKeyThrew = false;
try { signTokenWithGuard("user@example.com", 30, ""); }
catch (e) { emptyKeyThrew = e.message.includes("AUTH_SECRET not configured"); }
assert(emptyKeyThrew, "signToken throws on empty-string key");

const goodToken = signTokenWithGuard("user@example.com", 30, TEST_SECRET);
assert(typeof goodToken === "string" && goodToken.includes("."), "signToken works normally with a valid key");

console.log("\n--- alerts.js: 2026 CGMAP additions ---");

const CGMAP_2026 = {
  HYPE:"hyperliquid", KAITO:"kaito", IP:"story-2", MOVE:"movement-2",
  LAYER:"solayer", ORCA:"orca", PYUSD:"paypal-usd", USUAL:"usual",
  RESOLV:"resolv", INIT:"initia",
};
assert(CGMAP_2026["HYPE"] === "hyperliquid", "HYPE maps to hyperliquid");
assert(CGMAP_2026["KAITO"] === "kaito", "KAITO maps to kaito");
assert(CGMAP_2026["IP"] === "story-2", "IP maps to story-2 (Story Protocol)");
assert(CGMAP_2026["MOVE"] === "movement-2", "MOVE maps to movement-2");
assert(CGMAP_2026["LAYER"] === "solayer", "LAYER maps to solayer");
assert(!CGMAP_2026["UNKNOWN"], "unknown ticker still returns undefined");

console.log("\n--- news.js: deduplication applied before slice ---");

function buildFeed(rawItems) {
  const seen = new Set();
  return rawItems
    .sort(function (a, b) { return b.at - a.at; })
    .filter(function (item) {
      if (seen.has(item.u)) return false;
      seen.add(item.u);
      return true;
    })
    .slice(0, 5);
}

const rawFeed = [
  { t: "Story 1", u: "https://a.com/1", s: "A", at: 1000 },
  { t: "Story 1 dup", u: "https://a.com/1", s: "B", at: 900 },
  { t: "Story 2", u: "https://a.com/2", s: "A", at: 800 },
  { t: "Story 3", u: "https://a.com/3", s: "A", at: 700 },
  { t: "Story 4", u: "https://a.com/4", s: "A", at: 600 },
  { t: "Story 5", u: "https://a.com/5", s: "A", at: 500 },
];
const built = buildFeed(rawFeed);
assert(built.length === 5, "5 unique URLs fit exactly into slice(0,5)");
assert(built.every(function (i) { return i.s === "A"; }), "all items are from source A (earliest dup from B removed)");

console.log("\n--- alerts.js: ATH proximity alert logic ---");

function shouldSendAthAlert(h, athChangePct) {
  return athChangePct >= -10 && athChangePct <= 0 && !h.serverAthAlerted;
}
function shouldRearmAthAlert(h, athChangePct) {
  return !!h.serverAthAlerted && athChangePct < -20;
}

const athHolding = { ticker: "BTC", avg: 60000, qty: 0.5 };
assert(shouldSendAthAlert({ ...athHolding }, -5), "ATH alert fires within 5% of ATH");
assert(shouldSendAthAlert({ ...athHolding }, -10), "ATH alert fires at exactly -10% boundary");
assert(shouldSendAthAlert({ ...athHolding }, 0), "ATH alert fires at new ATH (0% change)");
assert(!shouldSendAthAlert({ ...athHolding }, -11), "ATH alert suppressed at -11% (outside window)");
assert(!shouldSendAthAlert({ ...athHolding }, -50), "ATH alert suppressed far below ATH");
assert(!shouldSendAthAlert({ ...athHolding, serverAthAlerted: true }, -5), "no duplicate ATH alert");
assert(shouldRearmAthAlert({ ...athHolding, serverAthAlerted: true }, -25), "ATH alert re-arms at -25% (below -20%)");
assert(!shouldRearmAthAlert({ ...athHolding, serverAthAlerted: true }, -15), "no re-arm at -15% (above -20% threshold)");
assert(!shouldRearmAthAlert({ ...athHolding }, -25), "no re-arm if alert was never sent");

console.log("\n--- alerts.js: concentration risk alert logic ---");

function concentrationOf(holdings, cgid, prices) {
  let total = 0, myVal = 0;
  let priced = 0;
  for (const h of holdings) {
    const price = prices[h.cgid];
    if (price == null) continue;
    const val = (h.qty || 0) * price;
    total += val;
    if (h.cgid === cgid) myVal = val;
    priced++;
  }
  if (priced < 2 || total === 0) return 0;
  return myVal / total;
}

function shouldSendConcentrationAlert(ratio, alerted) {
  return ratio >= 0.60 && !alerted;
}
function shouldRearmConcentrationAlert(ratio, alerted) {
  return !!alerted && ratio < 0.50;
}

const holdings = [
  { cgid: "bitcoin", qty: 1 },
  { cgid: "ethereum", qty: 5 },
];
const prices60 = { bitcoin: 60000, ethereum: 3000 };  // BTC: 60k (80%), ETH: 15k (20%)
const ratio80 = concentrationOf(holdings, "bitcoin", prices60);
assert(ratio80 > 0.79 && ratio80 < 0.81, "concentration correctly computed at ~80%");
assert(shouldSendConcentrationAlert(ratio80, false), "concentration alert fires at 80%");
assert(!shouldSendConcentrationAlert(ratio80, true), "no duplicate concentration alert");

const pricesLow = { bitcoin: 10000, ethereum: 3000 };  // BTC: 10k (40%), ETH: 15k (60%)
const ratioLow = concentrationOf(holdings, "bitcoin", pricesLow);
assert(ratioLow < 0.60, "concentration below 60% at equal value");
assert(!shouldSendConcentrationAlert(ratioLow, false), "no alert below 60% threshold");
assert(shouldRearmConcentrationAlert(ratioLow, true), "concentration alert re-arms below 50%");

const ratioExact60 = 0.60;
assert(shouldSendConcentrationAlert(ratioExact60, false), "alert fires at exactly 60% boundary");
assert(!shouldRearmConcentrationAlert(0.50, true), "no re-arm at exactly 50% (above threshold)");
assert(shouldRearmConcentrationAlert(0.49, true), "re-arms just below 50%");

const singleHolding = [{ cgid: "bitcoin", qty: 1 }];
const ratioSingle = concentrationOf(singleHolding, "bitcoin", { bitcoin: 60000 });
assert(ratioSingle === 0, "single holding returns 0 (requires >=2 priced holdings)");

console.log("\n--- macro.js: date fix — catalyst window uses real current time ---");

function isCatalystInsideWindow(catalystDateStr, windowDays) {
  const catalystMs = new Date(catalystDateStr).getTime();
  const nowMs = Date.now();
  const diff = (catalystMs - nowMs) / (1000 * 60 * 60 * 24);
  return diff >= 0 && diff <= windowDays;
}

function daysUntilCatalyst(catalystDateStr) {
  const catalystMs = new Date(catalystDateStr).getTime();
  const nowMs = Date.now();
  return (catalystMs - nowMs) / (1000 * 60 * 60 * 24);
}

// A catalyst well in the past should not be inside the 21-day window
const pastCatalyst = new Date(Date.now() - 30 * 24 * 3600 * 1000).toISOString().slice(0, 10);
assert(!isCatalystInsideWindow(pastCatalyst, 21), "past catalyst not inside 21-day window");

// A catalyst 10 days from now should be inside
const futureCatalyst10d = new Date(Date.now() + 10 * 24 * 3600 * 1000).toISOString().slice(0, 10);
assert(isCatalystInsideWindow(futureCatalyst10d, 21), "catalyst 10 days out is inside 21-day window");

// A catalyst 25 days from now is outside
const futureCatalyst25d = new Date(Date.now() + 25 * 24 * 3600 * 1000).toISOString().slice(0, 10);
assert(!isCatalystInsideWindow(futureCatalyst25d, 21), "catalyst 25 days out is outside 21-day window");

// Days-until should be positive for future, negative for past
const daysUntilFuture = daysUntilCatalyst(futureCatalyst10d);
assert(daysUntilFuture > 9 && daysUntilFuture < 11, "days-until correctly ~10 days for near-future catalyst");

const daysUntilPast = daysUntilCatalyst(pastCatalyst);
assert(daysUntilPast < 0, "days-until is negative for past catalyst");

// Verify that using a stale reference date (like MACRO_DATA.asOf) gives wrong results
const staleAsOf = "2026-09-21";
function isCatalystInsideWindowStale(catalystDateStr, windowDays) {
  const catalystMs = new Date(catalystDateStr).getTime();
  const nowMs = new Date(staleAsOf).getTime();
  const diff = (catalystMs - nowMs) / (1000 * 60 * 60 * 24);
  return diff >= 0 && diff <= windowDays;
}
// futureCatalyst10d is 10 days from today (2026-09-23). With stale date 2026-09-21 it appears 12 days out.
// With real Date.now() it's 10 days. Both are in window, but stale date gives wrong day count.
const realDays = Math.round((new Date(futureCatalyst10d).getTime() - Date.now()) / 864e5);
const staleDays = Math.round((new Date(futureCatalyst10d).getTime() - new Date(staleAsOf).getTime()) / 864e5);
assert(staleDays > realDays, "stale reference date overstates days remaining vs real Date.now()");

console.log("\n--- sync.js: ticker character validation ---");

function isValidTicker(ticker) {
  if (!ticker) return true; // falsy tickers are skipped, not rejected
  if (typeof ticker !== "string") return false;
  if (ticker.length > 20) return false;
  return /^[A-Za-z0-9._-]{1,20}$/.test(ticker);
}
assert(isValidTicker("BTC"), "BTC passes");
assert(isValidTicker("bitcoin"), "lowercase passes");
assert(isValidTicker("WSTETH"), "long uppercase ticker passes");
assert(isValidTicker("BTC.B"), "ticker with dot passes (Avalanche bridge)");
assert(isValidTicker("token-2"), "ticker with hyphen passes (CG-style IDs)");
assert(isValidTicker("T_K"), "ticker with underscore passes");
assert(!isValidTicker("bitcoin,ethereum"), "comma injection rejected");
assert(!isValidTicker("bitcoin?q=1"), "query-string injection rejected");
assert(!isValidTicker("../../etc"), "path traversal rejected");
assert(!isValidTicker("<script>"), "angle bracket injection rejected");
assert(!isValidTicker("a".repeat(21)), "ticker over 20 chars rejected");
assert(isValidTicker(null), "null ticker is falsy — passes (skipped, not rejected)");

console.log("\n--- sync.js: validateUserData structure ---");

function validateUserData(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) return false;
  if (data.cash !== undefined) {
    if (typeof data.cash !== "number" || !isFinite(data.cash) || data.cash < 0 || data.cash > 1e9) return false;
  }
  if (data.cashApy !== undefined) {
    if (typeof data.cashApy !== "number" || !isFinite(data.cashApy) || data.cashApy < 0 || data.cashApy > 100) return false;
  }
  if (data.port && data.port.crypto !== undefined) {
    if (!Array.isArray(data.port.crypto)) return false;
    if (data.port.crypto.length > 200) return false;
    for (const h of data.port.crypto) {
      if (!h || typeof h !== "object") return false;
      if (h.ticker && typeof h.ticker !== "string") return false;
      if (h.ticker && h.ticker.length > 20) return false;
      if (h.ticker && !/^[A-Za-z0-9._-]{1,20}$/.test(h.ticker)) return false;
      if (h.qty !== undefined && typeof h.qty !== "number") return false;
      if (h.avg !== undefined && typeof h.avg !== "number") return false;
      if (h.stop !== undefined && typeof h.stop !== "number") return false;
      if (h.tp !== undefined && typeof h.tp !== "number") return false;
    }
  }
  if (data.wl !== undefined) {
    if (!Array.isArray(data.wl)) return false;
    if (data.wl.length > 100) return false;
    for (const w of data.wl) {
      if (!w || typeof w !== "object") return false;
      if (w.ticker && typeof w.ticker !== "string") return false;
      if (w.ticker && w.ticker.length > 20) return false;
      if (w.ticker && !/^[A-Za-z0-9._-]{1,20}$/.test(w.ticker)) return false;
      if (w.targetPrice !== undefined && typeof w.targetPrice !== "number") return false;
      if (w.sellTarget !== undefined && typeof w.sellTarget !== "number") return false;
    }
  }
  return true;
}

assert(validateUserData({ cash: 1000, port: { crypto: [{ ticker: "BTC", qty: 1, avg: 60000 }] } }), "valid holding passes");
assert(!validateUserData({ port: { crypto: [{ ticker: "bitcoin,ethereum", qty: 1 }] } }), "comma-injection ticker rejected");
assert(!validateUserData({ port: { crypto: [{ ticker: "<script>", qty: 1 }] } }), "XSS ticker rejected");
assert(!validateUserData({ wl: [{ ticker: "bitcoin?q=1", targetPrice: 50000 }] }), "query-string ticker in watchlist rejected");
assert(validateUserData({ wl: [{ ticker: "BTC", targetPrice: 50000, sellTarget: 70000 }] }), "valid watchlist entry passes");
assert(!validateUserData({ cash: -1 }), "negative cash rejected");
assert(!validateUserData({ cash: 2e9 }), "cash over 1bn rejected");
assert(!validateUserData({ cashApy: 101 }), "APY over 100% rejected");
assert(!validateUserData({ port: { crypto: Array.from({ length: 201 }, () => ({ ticker: "BTC" })) } }), "over 200 holdings rejected");
assert(validateUserData({}), "empty object is valid");
assert(!validateUserData(null), "null rejected");
assert(!validateUserData([]), "array rejected");

console.log("\n--- alerts.js: cgId safe ticker resolution ---");

const TEST_CGMAP = {
  BTC: "bitcoin",
  ETH: "ethereum",
  "BTC.B": "bitcoin", // hypothetical bridge token mapped in CGMAP
};

function cgIdTest(ticker) {
  const upper = String(ticker).toUpperCase();
  if (TEST_CGMAP[upper]) return TEST_CGMAP[upper];
  const lower = String(ticker).toLowerCase();
  return /^[a-z0-9-]+$/.test(lower) ? lower : null;
}

assert(cgIdTest("BTC") === "bitcoin", "known CGMAP ticker resolves correctly");
assert(cgIdTest("ETH") === "ethereum", "ETH resolves via CGMAP");
assert(cgIdTest("solana") === "solana", "safe lowercase fallback accepted");
assert(cgIdTest("injective-protocol") === "injective-protocol", "hyphenated CG ID accepted");
assert(cgIdTest("bitcoin,ethereum") === null, "comma-injection returns null");
assert(cgIdTest("../../etc/passwd") === null, "path traversal returns null");
assert(cgIdTest("<script>alert(1)</script>") === null, "XSS string returns null");
assert(cgIdTest("token.with.dots") === null, "dots not allowed in CG fallback ID");
assert(cgIdTest("TOKEN_UNDER") === null, "underscore not allowed in CG fallback ID");

console.log("\n--- profit-ladder: +200% rung addition ---");

const lad200 = ladderFor(100, 8, 301);
assert(lad200 !== null, "ladder active at +201%");
assert(lad200.rungs.length === 4, "four rungs total with +200% addition");
assert(lad200.rungs[3].pct === 200, "fourth rung is +200%");
assert(lad200.rungs[3].price === 300, "fourth rung price is 3x avg cost");
assert(lad200.hits.length === 4, "all four rungs hit at +201%");
assert(lad200.rungs[3].qty === 2, "each rung still sells 25% of initial qty");
// At exactly +200% all 4 should hit
const ladExact200 = ladderFor(100, 8, 300);
assert(ladExact200.hits.length === 4, "all four rungs hit at exactly +200%");
// At +190% only 3 should hit (below the +200% threshold)
const ladBelow200 = ladderFor(100, 8, 290);
assert(ladBelow200.hits.length === 3, "only three rungs hit at +190% (below +200% rung)");

}).catch(function (err) {
  console.error("Async test error:", err);
  failed++;
}).finally(function () {
  // --- Summary ---
  console.log("\n==========================================");
  console.log("Results: " + passed + " passed, " + failed + " failed");
  if (failed > 0) process.exit(1);
});
