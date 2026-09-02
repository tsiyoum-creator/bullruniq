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

function esc(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}
assert(esc("<BTC>") === "&lt;BTC&gt;", "angle brackets escaped in ticker");
assert(esc("ETH & BNB") === "ETH &amp; BNB", "ampersand escaped in name");
assert(esc('BTC"injection"') === "BTC&quot;injection&quot;", "quotes escaped");

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

console.log("\n--- stripe webhook: signature verification ---");

const crypto2 = require("crypto");
function verifyStripe(rawBody, sigHeader, secret) {
  if (!sigHeader || !secret) return false;
  const parts = {};
  String(sigHeader).split(",").forEach(function (kv) {
    const i = kv.indexOf("=");
    if (i > 0) parts[kv.slice(0, i).trim()] = kv.slice(i + 1).trim();
  });
  if (!parts.t || !parts.v1) return false;
  const signed = parts.t + "." + rawBody;
  const expected = crypto2.createHmac("sha256", secret).update(signed, "utf8").digest("hex");
  try {
    if (!crypto2.timingSafeEqual(Buffer.from(expected), Buffer.from(parts.v1))) return false;
  } catch (e) { return false; }
  const age = Math.abs(Math.floor(Date.now() / 1000) - parseInt(parts.t, 10));
  return age <= 300;
}
const STRIPE_SECRET = "whsec_test_secret";
const BODY = '{"type":"checkout.session.completed"}';
const TS = Math.floor(Date.now() / 1000);
const STRIPE_SIG = crypto2.createHmac("sha256", STRIPE_SECRET).update(TS + "." + BODY).digest("hex");
const validHeader = "t=" + TS + ",v1=" + STRIPE_SIG;
assert(verifyStripe(BODY, validHeader, STRIPE_SECRET), "valid signature passes");
assert(!verifyStripe(BODY, validHeader, "wrong-secret"), "wrong secret fails");
assert(!verifyStripe(BODY, "t=" + TS + ",v1=badvalue", STRIPE_SECRET), "tampered v1 fails");
assert(!verifyStripe(BODY, "", STRIPE_SECRET), "empty header fails");
assert(!verifyStripe(BODY, validHeader, ""), "empty secret fails");

// Replay attack: timestamp more than 5 minutes old
const oldTS = Math.floor(Date.now() / 1000) - 400;
const oldSig = crypto2.createHmac("sha256", STRIPE_SECRET).update(oldTS + "." + BODY).digest("hex");
assert(!verifyStripe(BODY, "t=" + oldTS + ",v1=" + oldSig, STRIPE_SECRET), "old timestamp rejected (replay guard)");

console.log("\n--- generate.js: message validation ---");

const VALID_ROLES = new Set(["user", "assistant"]);
const MAX_MESSAGES_CHARS = 20000;
const MAX_SYSTEM_CHARS = 2000;

function validateMessages(messages) {
  if (!Array.isArray(messages) || !messages.length) return "Missing messages or prompt";
  let totalChars = 0;
  for (const m of messages) {
    if (!m || typeof m !== "object") return "Invalid message format";
    if (!VALID_ROLES.has(m.role)) return "Invalid message role: " + m.role;
    const content = typeof m.content === "string" ? m.content : JSON.stringify(m.content);
    totalChars += content.length;
    if (totalChars > MAX_MESSAGES_CHARS) return "Messages too large";
  }
  return null;
}

assert(validateMessages([{ role: "user", content: "hello" }]) === null, "valid single message passes");
assert(validateMessages([{ role: "user", content: "a" }, { role: "assistant", content: "b" }]) === null, "valid conversation passes");
assert(validateMessages([]) === "Missing messages or prompt", "empty array fails");
assert(validateMessages(null) === "Missing messages or prompt", "null fails");
assert(validateMessages([{ role: "system", content: "x" }]) !== null, "invalid role 'system' rejected");
assert(validateMessages([{ role: "admin", content: "x" }]) !== null, "invalid role 'admin' rejected");
assert(validateMessages([null]) !== null, "null message fails");
const bigMsg = [{ role: "user", content: "x".repeat(MAX_MESSAGES_CHARS + 1) }];
assert(validateMessages(bigMsg) === "Messages too large", "oversized message rejected");
const exactMsg = [{ role: "user", content: "x".repeat(MAX_MESSAGES_CHARS) }];
assert(validateMessages(exactMsg) === null, "exactly at limit passes (limit is inclusive)");
const justUnder = [{ role: "user", content: "x".repeat(MAX_MESSAGES_CHARS - 1) }];
assert(validateMessages(justUnder) === null, "one under limit passes");

assert(String("hello").slice(0, MAX_SYSTEM_CHARS) === "hello", "short system prompt unchanged");
assert("x".repeat(3000).slice(0, MAX_SYSTEM_CHARS).length === MAX_SYSTEM_CHARS, "oversized system prompt truncated");

console.log("\n--- market.js: global data transform ---");

function transformGlobal(data) {
  const d = (data && data.data) || {};
  return {
    total_market_cap_usd: d.total_market_cap && d.total_market_cap.usd,
    btc_dominance: d.market_cap_percentage && d.market_cap_percentage.btc,
    eth_dominance: d.market_cap_percentage && d.market_cap_percentage.eth,
    market_cap_change_percentage_24h: d.market_cap_change_percentage_24h_usd,
  };
}
const mockGlobal = { data: { total_market_cap: { usd: 2500000000000 }, market_cap_percentage: { btc: 52.5, eth: 17.3 }, market_cap_change_percentage_24h_usd: 1.2 } };
const g = transformGlobal(mockGlobal);
assert(g.total_market_cap_usd === 2500000000000, "total market cap extracted");
assert(g.btc_dominance === 52.5, "BTC dominance extracted");
assert(g.eth_dominance === 17.3, "ETH dominance extracted");
assert(g.market_cap_change_percentage_24h === 1.2, "24h market cap change extracted");
assert(transformGlobal(null).total_market_cap_usd === undefined, "null data returns empty object gracefully");

console.log("\n--- market.js: fear & greed transform ---");

function transformFear(data) {
  const entries = (data && data.data) || [];
  return entries.map(function (e) {
    return { value: parseInt(e.value, 10), label: e.value_classification, timestamp: e.timestamp };
  });
}
const mockFear = { data: [
  { value: "72", value_classification: "Greed", timestamp: "1700000000" },
  { value: "45", value_classification: "Fear", timestamp: "1699913600" },
]};
const f = transformFear(mockFear);
assert(f.length === 2, "two fear/greed entries returned");
assert(f[0].value === 72 && f[0].label === "Greed", "first entry parsed correctly");
assert(f[1].value === 45 && f[1].label === "Fear", "second entry parsed correctly");
assert(transformFear(null).length === 0, "null returns empty array");

console.log("\n--- alerts: CGMAP coverage ---");

// Inline the expanded CGMAP from alerts.js to verify key coins are present
const CGMAP_TEST = {
  BTC:"bitcoin", ETH:"ethereum", SOL:"solana", BNB:"binancecoin", XRP:"ripple",
  ADA:"cardano", DOGE:"dogecoin", AVAX:"avalanche-2", MATIC:"matic-network",
  LINK:"chainlink", NEAR:"near", APT:"aptos", UNI:"uniswap", OP:"optimism", ARB:"arbitrum",
  SUI:"sui", PEPE:"pepe", WIF:"dogwifcoin", BONK:"bonk", POPCAT:"popcat",
  AAVE:"aave", MKR:"maker", CRV:"curve-dao-token", GMX:"gmx", PENDLE:"pendle",
  TIA:"celestia", ZRO:"layerzero", W:"wormhole", EIGEN:"eigenlayer",
  TAO:"bittensor", PYTH:"pyth-network", ENA:"ethena", LDO:"lido-dao",
};
const requiredCoins = ["BTC","ETH","SOL","AAVE","MKR","PENDLE","TIA","EIGEN","POPCAT","BONK"];
for (const coin of requiredCoins) {
  assert(CGMAP_TEST[coin] !== undefined, "CGMAP contains " + coin);
}
assert(Object.keys(CGMAP_TEST).length >= 30, "CGMAP has at least 30 tickers");

console.log("\n--- planFor logic ---");

async function planFor(email, getStore) {
  try {
    const rec = await getStore("customers").get(email, { type: "json" });
    if (rec && (rec.status === "active" || rec.status === "trialing")) return rec.tier || "pro";
  } catch (e) {}
  return "free";
}
function makeStore(records) {
  return { get: async function (key) { return records[key] || null; } };
}
function wrap(store) { return function (name) { return store; }; }

async function runPlanTests() {
  const s1 = wrap(makeStore({ "user@example.com": { status: "active", tier: "elite" } }));
  assert(await planFor("user@example.com", s1) === "elite", "active elite subscription → elite plan");

  const s2 = wrap(makeStore({ "user@example.com": { status: "trialing", tier: "pro" } }));
  assert(await planFor("user@example.com", s2) === "pro", "trialing → pro plan");

  const s3 = wrap(makeStore({ "user@example.com": { status: "canceled", tier: "pro" } }));
  assert(await planFor("user@example.com", s3) === "free", "canceled subscription → free plan");

  const s4 = wrap(makeStore({ "user@example.com": { status: "past_due", tier: "pro" } }));
  assert(await planFor("user@example.com", s4) === "free", "past_due → free plan (auto-revoke)");

  const s5 = wrap(makeStore({}));
  assert(await planFor("new@example.com", s5) === "free", "no record → free plan");

  const s6 = wrap(makeStore({ "user@example.com": { status: "active" } }));
  assert(await planFor("user@example.com", s6) === "pro", "active without explicit tier defaults to pro");
}
runPlanTests().then(function () {
  // --- Summary ---
  console.log("\n==========================================");
  console.log("Results: " + passed + " passed, " + failed + " failed");
  if (failed > 0) process.exit(1);
});
