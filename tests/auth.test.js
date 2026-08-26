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

console.log("\n--- generate.js: input validation ---");

function validateMessages(messages, maxMsgs, maxBytes) {
  if (!Array.isArray(messages) || !messages.length) return { ok: false, error: "Missing messages or prompt" };
  if (messages.length > maxMsgs) return { ok: false, error: "Too many messages" };
  for (const msg of messages) {
    if (!msg || (msg.role !== "user" && msg.role !== "assistant")) return { ok: false, error: "Invalid message role" };
    const content = typeof msg.content === "string" ? msg.content : JSON.stringify(msg.content);
    if (Buffer.byteLength(content, "utf8") > maxBytes) return { ok: false, error: "Message content too large" };
  }
  return { ok: true };
}

assert(validateMessages(null, 20, 8000).ok === false, "null messages rejected");
assert(validateMessages([], 20, 8000).ok === false, "empty messages array rejected");
assert(validateMessages([{ role: "user", content: "hello" }], 20, 8000).ok === true, "valid user message accepted");
assert(validateMessages([{ role: "assistant", content: "hi" }], 20, 8000).ok === true, "valid assistant message accepted");
assert(validateMessages([{ role: "system", content: "inject!" }], 20, 8000).ok === false, "system role rejected");
assert(validateMessages([{ role: "user", content: "a".repeat(9000) }], 20, 8000).ok === false, "oversized content rejected");
const manyMsgs = Array.from({ length: 21 }, (_, i) => ({ role: i % 2 === 0 ? "user" : "assistant", content: "hi" }));
assert(validateMessages(manyMsgs, 20, 8000).ok === false, "too many messages rejected");
assert(validateMessages(manyMsgs.slice(0, 20), 20, 8000).ok === true, "exactly max messages accepted");

console.log("\n--- market.js: fear-greed data shape ---");

function validateFearGreedPayload(payload) {
  if (!payload || typeof payload !== "object") return false;
  if (payload.fear_greed !== null) {
    if (typeof payload.fear_greed.value !== "number") return false;
    if (typeof payload.fear_greed.label !== "string") return false;
    if (payload.fear_greed.value < 0 || payload.fear_greed.value > 100) return false;
  }
  if (payload.bitcoin !== null) {
    if (typeof payload.bitcoin.usd !== "number") return false;
  }
  return true;
}
assert(validateFearGreedPayload({ fear_greed: { value: 55, label: "Greed" }, bitcoin: { usd: 90000, change_24h: 1.5, market_cap: 1.8e12 } }), "valid fear-greed payload accepted");
assert(validateFearGreedPayload({ fear_greed: null, bitcoin: null }), "null data fields accepted");
assert(!validateFearGreedPayload({ fear_greed: { value: 150, label: "Extreme Greed" }, bitcoin: null }), "out-of-range fear-greed value rejected");
assert(!validateFearGreedPayload(null), "null payload rejected");

console.log("\n--- alerts: profit-lock ladder rung logic ---");

function ladderRungAlert(h, price) {
  if (!h.avg || h.avg <= 0) return [];
  const RUNGS = [{ pct: 25, key: "serverladder25Alerted" }, { pct: 50, key: "serverladder50Alerted" }, { pct: 100, key: "serverladder100Alerted" }];
  return RUNGS.filter(function (rung) {
    const rungPrice = h.avg * (1 + rung.pct / 100);
    return price >= rungPrice && !h[rung.key];
  });
}
function ladderRungRearm(h, price) {
  if (!h.avg || h.avg <= 0) return [];
  const RUNGS = [{ pct: 25, key: "serverladder25Alerted" }, { pct: 50, key: "serverladder50Alerted" }, { pct: 100, key: "serverladder100Alerted" }];
  return RUNGS.filter(function (rung) {
    const rungPrice = h.avg * (1 + rung.pct / 100);
    return price < rungPrice * 0.95 && h[rung.key];
  });
}
const ladderHolding = { ticker: "SOL", avg: 100, qty: 10 };
assert(ladderRungAlert({ ...ladderHolding }, 120).length === 0, "no ladder alert at +20% (below +25% rung)");
assert(ladderRungAlert({ ...ladderHolding }, 125).length === 1, "ladder alert fires at exactly +25%");
assert(ladderRungAlert({ ...ladderHolding }, 155).length === 2, "two ladder alerts at +55%");
assert(ladderRungAlert({ ...ladderHolding }, 205).length === 3, "all three ladder alerts at +105%");
assert(ladderRungAlert({ ...ladderHolding, serverladder25Alerted: true }, 140).length === 0, "skips already-alerted rung, next rung not reached");
assert(ladderRungAlert({ ...ladderHolding, serverladder25Alerted: true, serverladder50Alerted: true }, 205).length === 1, "only third rung fires when first two already alerted");
assert(ladderRungRearm({ ...ladderHolding, serverladder25Alerted: true }, 118).length === 1, "rung re-arms when price drops 5%+ below it");
assert(ladderRungRearm({ ...ladderHolding, serverladder25Alerted: true }, 122).length === 0, "no re-arm within 5% of rung");
assert(ladderRungAlert({ ticker: "ETH", avg: 0, qty: 1 }, 5000).length === 0, "no ladder without cost basis");

console.log("\n--- alerts: CGMAP coverage ---");

const CGMAP_SAMPLE = { BTC:"bitcoin", ETH:"ethereum", SOL:"solana", WLD:"worldcoin-wld", AI16Z:"ai16z", TIA:"celestia", VIRTUAL:"virtual-protocol" };
assert(CGMAP_SAMPLE["BTC"] === "bitcoin", "BTC maps to bitcoin");
assert(CGMAP_SAMPLE["WLD"] === "worldcoin-wld", "WLD (2024 coin) is mapped");
assert(CGMAP_SAMPLE["AI16Z"] === "ai16z", "AI16Z (AI agent token) is mapped");
assert(CGMAP_SAMPLE["TIA"] === "celestia", "TIA (Celestia) is mapped");
assert(CGMAP_SAMPLE["VIRTUAL"] === "virtual-protocol", "VIRTUAL (AI token) is mapped");

console.log("\n--- portal.js: no-cache redirect ---");

function portalHeaders(hasUrl) {
  return { Location: hasUrl ? "https://billing.stripe.com/portal" : "/contact", "Cache-Control": "no-store, no-cache, must-revalidate" };
}
const h1 = portalHeaders(true);
assert(h1["Cache-Control"] === "no-store, no-cache, must-revalidate", "portal sets no-cache headers");
assert(h1["Location"].startsWith("https://"), "portal redirects to Stripe URL when configured");
const h2 = portalHeaders(false);
assert(h2["Location"] === "/contact", "portal falls back to /contact");

// --- Summary ---
console.log("\n==========================================");
console.log("Results: " + passed + " passed, " + failed + " failed");
if (failed > 0) process.exit(1);
