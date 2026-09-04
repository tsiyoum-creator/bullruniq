// Unit tests for BullrunIQ backend logic.
// Run with: node tests/auth.test.js

const crypto = require("crypto");

// --- Shared helpers (inline copies from production functions) ---

const TEST_SECRET = "test-secret-key-for-unit-tests";
const RESEND_SECRET = "test-resend-key";

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

// =============================================================================
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

// =============================================================================
console.log("\n--- unsubscribe: email validation ---");

function isValidEmail(s) {
  return typeof s === "string" && s.length > 0 && s.length <= 200 && s.indexOf("@") > 0;
}
assert(isValidEmail("a@b.com"), "valid email passes");
assert(!isValidEmail(""), "empty string fails");
assert(!isValidEmail("notanemail"), "missing @ fails");
assert(!isValidEmail("@nodomain"), "@ at start fails");
assert(!isValidEmail("a".repeat(201) + "@b.com"), "too long fails");

// =============================================================================
console.log("\n--- unsubscribe: HMAC token verification ---");

function unsubHmac(email, secret) {
  return crypto.createHmac("sha256", secret).update("unsub:" + email).digest("hex");
}
function verifyUnsubToken(token, email, secret) {
  const expected = unsubHmac(email, secret);
  if (!expected || !token) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(String(token), "hex"));
  } catch (e) { return false; }
}

const ubEmail = "unsub@example.com";
const ubToken = unsubHmac(ubEmail, RESEND_SECRET);
assert(verifyUnsubToken(ubToken, ubEmail, RESEND_SECRET), "correct token verifies");
assert(!verifyUnsubToken("wrongtoken", ubEmail, RESEND_SECRET), "wrong token rejected");
assert(!verifyUnsubToken(ubToken, "other@example.com", RESEND_SECRET), "token bound to email");
assert(!verifyUnsubToken("", ubEmail, RESEND_SECRET), "empty token rejected");
assert(!verifyUnsubToken(null, ubEmail, RESEND_SECRET), "null token rejected");

// =============================================================================
console.log("\n--- HTML escaping (XSS guard) ---");

assert(esc("<script>alert(1)</script>") === "&lt;script&gt;alert(1)&lt;/script&gt;", "script tags escaped");
assert(esc('"><img src=x onerror=alert(1)>') === "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;", "attribute injection escaped");
assert(esc("safe text") === "safe text", "safe text unchanged");
assert(esc("a&b") === "a&amp;b", "ampersand escaped");
assert(esc("it's a test") === "it&#x27;s a test", "single quote escaped");

// =============================================================================
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

// =============================================================================
console.log("\n--- alerts: ticker validation (S-4 fix) ---");

const CGMAP = { BTC: "bitcoin", ETH: "ethereum", SOL: "solana" };
const VALID_COIN_ID = /^[a-z0-9-]{1,50}$/;

function coinId(ticker) {
  const mapped = CGMAP[String(ticker).toUpperCase()];
  if (mapped) return mapped;
  const fallback = String(ticker).toLowerCase().trim();
  return VALID_COIN_ID.test(fallback) ? fallback : null;
}

assert(coinId("BTC") === "bitcoin", "CGMAP-mapped ticker returns CoinGecko ID");
assert(coinId("ETH") === "ethereum", "CGMAP-mapped ETH correct");
assert(coinId("unknown-coin") === "unknown-coin", "valid unmapped ticker passes through");
assert(coinId("bitcoin&page=99") === null, "URL injection rejected");
assert(coinId("bitcoin,ethereum") === null, "comma-separated injection rejected");
assert(coinId("") === null, "empty ticker rejected");
assert(coinId("a".repeat(51)) === null, "too-long ticker rejected");
assert(coinId("BITCOIN EXPLOIT") === null, "space in ticker rejected");

// =============================================================================
console.log("\n--- alerts: buy alert direction fix (B-4) ---");

// Fixed logic: use signed distance (not absolute), require price <= targetPrice.
function shouldSendBuyAlert(w, price) {
  const dist = (w.targetPrice - price) / price * 100; // positive = price below target
  return dist >= 0 && dist < 2 && !w.serverAlerted;
}
function shouldRearmBuyAlert(w, price) {
  return Math.abs((w.targetPrice - price) / price * 100) >= 5 && w.serverAlerted;
}

const buyEntry = { ticker: "ETH", targetPrice: 2000 };
assert(shouldSendBuyAlert({ ...buyEntry }, 1990), "buy alert 0.5% below target");
assert(shouldSendBuyAlert({ ...buyEntry }, 2000), "buy alert at exact target");
assert(!shouldSendBuyAlert({ ...buyEntry }, 2030), "NO buy alert 1.5% ABOVE target (B-4 fix)");
assert(!shouldSendBuyAlert({ ...buyEntry }, 2200), "no buy alert 10% above target");
assert(!shouldSendBuyAlert({ ...buyEntry, serverAlerted: true }, 1990), "no duplicate buy alert");
assert(shouldRearmBuyAlert({ ...buyEntry, serverAlerted: true }, 1900), "re-arm when price drops 5%+ away");
assert(!shouldRearmBuyAlert({ ...buyEntry, serverAlerted: true }, 1960), "no re-arm within 5%");

// =============================================================================
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

// =============================================================================
console.log("\n--- alerts: HTML escaping in emails ---");

assert(esc("<BTC>") === "&lt;BTC&gt;", "angle brackets escaped in ticker");
assert(esc("ETH & BNB") === "ETH &amp; BNB", "ampersand escaped in name");
assert(esc('BTC"injection"') === "BTC&quot;injection&quot;", "quotes escaped");

// =============================================================================
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

// =============================================================================
console.log("\n--- stripe webhook: signature verification ---");

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

function makeStripeSig(body, secret, timestampOverride) {
  const t = timestampOverride || Math.floor(Date.now() / 1000);
  const signed = t + "." + body;
  const v1 = crypto.createHmac("sha256", secret).update(signed, "utf8").digest("hex");
  return "t=" + t + ",v1=" + v1;
}

const stripeSecret = "whsec_test";
const stripeBody = JSON.stringify({ type: "invoice.paid", data: { object: { customer: "cus_test" } } });
const validSig = makeStripeSig(stripeBody, stripeSecret);

assert(verifyStripe(stripeBody, validSig, stripeSecret), "valid stripe signature passes");
assert(!verifyStripe(stripeBody, validSig, "wrong-secret"), "wrong secret rejected");
assert(!verifyStripe(stripeBody + "x", validSig, stripeSecret), "tampered body rejected");
assert(!verifyStripe(stripeBody, "t=12345,v1=badhex", stripeSecret), "tampered signature rejected");
assert(!verifyStripe(stripeBody, "", stripeSecret), "empty sig header rejected");
assert(!verifyStripe(stripeBody, validSig, ""), "empty secret rejected");
assert(!verifyStripe("", "", ""), "all empty rejected");

// Stale timestamp (>5 min old) should be rejected.
const staleSig = makeStripeSig(stripeBody, stripeSecret, Math.floor(Date.now() / 1000) - 400);
assert(!verifyStripe(stripeBody, staleSig, stripeSecret), "stale timestamp rejected");

// Timestamp in the near future is fine (clock skew tolerance).
const futureSig = makeStripeSig(stripeBody, stripeSecret, Math.floor(Date.now() / 1000) + 60);
assert(verifyStripe(stripeBody, futureSig, stripeSecret), "near-future timestamp accepted");

// =============================================================================
console.log("\n--- sync.js: data schema validation (S-8 fix) ---");

function isFinitePositive(v) { return typeof v === "number" && isFinite(v) && v > 0; }

function validateData(data) {
  if (!data || typeof data !== "object") return "data must be an object";
  if (data.wl !== undefined) {
    if (!Array.isArray(data.wl)) return "data.wl must be an array";
    for (const w of data.wl) {
      if (!w || typeof w !== "object") continue;
      if (w.ticker !== undefined) {
        const t = String(w.ticker).toUpperCase().trim();
        if (t.length > 20) return "ticker too long: " + t.slice(0, 20);
      }
      for (const field of ["targetPrice", "sellTarget"]) {
        if (w[field] !== undefined && !isFinitePositive(w[field])) {
          return field + " must be a positive number";
        }
      }
    }
  }
  if (data.port !== undefined) {
    if (typeof data.port !== "object") return "data.port must be an object";
    if (data.port.crypto !== undefined) {
      if (!Array.isArray(data.port.crypto)) return "data.port.crypto must be an array";
      for (const h of data.port.crypto) {
        if (!h || typeof h !== "object") continue;
        for (const field of ["avg", "qty", "stop", "tp"]) {
          if (h[field] !== undefined && !isFinitePositive(h[field])) {
            return field + " must be a positive number";
          }
        }
      }
    }
  }
  return null;
}

assert(validateData({}) === null, "empty object valid");
assert(validateData({ wl: [] }) === null, "empty watchlist valid");
assert(validateData({ wl: [{ ticker: "BTC", targetPrice: 50000 }] }) === null, "valid watchlist entry");
assert(validateData({ wl: [{ targetPrice: -100 }] }) !== null, "negative price rejected");
assert(validateData({ wl: [{ targetPrice: 0 }] }) !== null, "zero price rejected");
assert(validateData({ wl: [{ targetPrice: Infinity }] }) !== null, "Infinity price rejected");
assert(validateData({ wl: [{ targetPrice: NaN }] }) !== null, "NaN price rejected");
assert(validateData({ wl: [{ ticker: "A".repeat(21) }] }) !== null, "ticker too long rejected");
assert(validateData({ port: { crypto: [{ avg: 50000, stop: 40000 }] } }) === null, "valid holdings entry");
assert(validateData({ port: { crypto: [{ stop: -1 }] } }) !== null, "negative stop rejected");
assert(validateData(null) !== null, "null rejected");
assert(validateData("string") !== null, "string rejected");

// =============================================================================
console.log("\n--- submission-created: contact form filter ---");

function shouldSubscribe(formName) {
  if (formName === "contact" || formName === "contact-form") return false;
  return true;
}
assert(shouldSubscribe("waitlist"), "waitlist form gets subscribed");
assert(shouldSubscribe("tier-signup"), "tier-signup form gets subscribed");
assert(!shouldSubscribe("contact"), "contact form is skipped");
assert(!shouldSubscribe("contact-form"), "contact-form variant is skipped");

// =============================================================================
console.log("\n--- news.js: URL scheme validation ---");

function isHttpUrl(url) {
  return /^https?:\/\//i.test(url);
}
assert(isHttpUrl("https://coindesk.com/article"), "https URL passes");
assert(isHttpUrl("http://cointelegraph.com/news/test"), "http URL passes");
assert(!isHttpUrl("javascript:alert(1)"), "javascript: URL blocked");
assert(!isHttpUrl("data:text/html,<h1>xss</h1>"), "data: URL blocked");
assert(!isHttpUrl(""), "empty URL blocked");

// =============================================================================
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

// =============================================================================
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

// =============================================================================
console.log("\n--- generate.js: model allowlist ---");

const ALLOWED_MODELS = new Set([
  "claude-opus-5",
  "claude-sonnet-5",
  "claude-sonnet-4-6",
  "claude-haiku-4-5-20251001",
]);
const DEFAULT_MODEL = "claude-sonnet-4-6";

function resolveModel(m) {
  return ALLOWED_MODELS.has(m) ? m : DEFAULT_MODEL;
}

assert(resolveModel("claude-sonnet-4-6") === "claude-sonnet-4-6", "sonnet-4-6 allowed");
assert(resolveModel("claude-opus-5") === "claude-opus-5", "opus-5 allowed");
assert(resolveModel("claude-haiku-4-5-20251001") === "claude-haiku-4-5-20251001", "haiku allowed");
assert(resolveModel("gpt-4o") === DEFAULT_MODEL, "non-Anthropic model falls back to default");
assert(resolveModel("") === DEFAULT_MODEL, "empty string falls back to default");
assert(resolveModel(null) === DEFAULT_MODEL, "null falls back to default");
assert(resolveModel("claude-opus-4-8") === DEFAULT_MODEL, "unknown claude ID falls back to default");

// =============================================================================
// Summary
console.log("\n==========================================");
console.log("Results: " + passed + " passed, " + failed + " failed");
if (failed > 0) process.exit(1);
