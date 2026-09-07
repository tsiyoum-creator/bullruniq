// Unit tests for BullrunIQ serverless function logic.
// Run with: node tests/auth.test.js

const crypto = require("crypto");
const path = require("path");

// --- Inline the token helpers (mirrors auth.js / sync.js) ---
// These are kept inline so the tests run without Netlify env vars.

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

console.log("\n--- auth token: structure edge cases ---");
assert(verifyToken("nodot", TEST_SECRET) === null, "token with no dot returns null");
assert(verifyToken("a.b.c", TEST_SECRET) === null, "token with wrong signature returns null");
const shortToken = "." + TEST_SECRET; // dot at position 0
assert(verifyToken(shortToken, TEST_SECRET) === null, "dot at position 0 returns null");

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
assert(!isValidEmail(123), "non-string fails");

console.log("\n--- HTML escaping (XSS guard) ---");

// Single canonical esc() used throughout; matches the lib/utils.js definition.
function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
}
assert(esc("<script>alert(1)</script>") === "&lt;script&gt;alert(1)&lt;/script&gt;", "script tags escaped");
assert(esc('"><img src=x onerror=alert(1)>') === "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;", "attribute injection escaped");
assert(esc("safe text") === "safe text", "safe text unchanged");
assert(esc("a&b") === "a&amp;b", "ampersand escaped");
assert(esc("<BTC>") === "&lt;BTC&gt;", "angle brackets escaped in ticker");
assert(esc("ETH & BNB") === "ETH &amp; BNB", "ampersand escaped in name");
assert(esc('BTC"injection"') === "BTC&quot;injection&quot;", "quotes escaped");
assert(esc("it's") === "it&#x27;s", "single quote escaped");

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
assert(validateIds("bitcoin").length === 1, "single id passes");
assert(validateIds("the-open-network").length === 1, "hyphenated id passes");
assert(validateIds("bitcoin," + "a".repeat(51)).length === 1, "one valid + one too-long = 1 result");

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
assert(!shouldSendSellAlert({ ticker: "ETH" }, 1000), "missing sellTarget → no alert");

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
assert(!shouldSendBuyAlert({ ...buyEntry }, 1900), "5% below target — too low for alert");

console.log("\n--- submission-created: contact form filter ---");

function shouldSubscribe(formName) {
  if (formName === "contact" || formName === "contact-form") return false;
  return true;
}
assert(shouldSubscribe("waitlist"), "waitlist form gets subscribed");
assert(shouldSubscribe("tier-signup"), "tier-signup form gets subscribed");
assert(!shouldSubscribe("contact"), "contact form is skipped");
assert(!shouldSubscribe("contact-form"), "contact-form variant is skipped");
assert(shouldSubscribe(""), "empty form name is subscribed (non-contact)");

console.log("\n--- news.js: URL scheme validation ---");

function isHttpUrl(url) {
  return /^https?:\/\//i.test(url);
}
assert(isHttpUrl("https://coindesk.com/article"), "https URL passes");
assert(isHttpUrl("http://cointelegraph.com/news/test"), "http URL passes");
assert(!isHttpUrl("javascript:alert(1)"), "javascript: URL blocked");
assert(!isHttpUrl("data:text/html,<h1>xss</h1>"), "data: URL blocked");
assert(!isHttpUrl(""), "empty URL blocked");
assert(!isHttpUrl("//relative.com/path"), "protocol-relative URL blocked");
assert(!isHttpUrl("ftp://ftp.example.com"), "ftp: URL blocked");

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
assert(ladderFor(100, 10, 119) === null, "no ladder at exactly +19% gain");
assert(ladderFor(100, 10, 120) !== null, "ladder activates at exactly +20% gain");

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
assert(deployPlan(99, ["BTC"]) === null, "exactly $99 → no plan");
assert(deployPlan(100, ["BTC"]) !== null, "exactly $100 → plan created");

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

function makeStripeHeader(body, secret, tsOffset) {
  const t = String(Math.floor(Date.now() / 1000) + (tsOffset || 0));
  const sig = crypto.createHmac("sha256", secret).update(t + "." + body, "utf8").digest("hex");
  return "t=" + t + ",v1=" + sig;
}

const STRIPE_SECRET = "whsec_test_secret";
const stripeBody = JSON.stringify({ type: "checkout.session.completed" });
assert(verifyStripe(stripeBody, makeStripeHeader(stripeBody, STRIPE_SECRET), STRIPE_SECRET), "valid stripe signature passes");
assert(!verifyStripe(stripeBody, makeStripeHeader(stripeBody, "wrong-secret"), STRIPE_SECRET), "wrong secret fails");
assert(!verifyStripe(stripeBody, "", STRIPE_SECRET), "empty header fails");
assert(!verifyStripe(stripeBody, null, STRIPE_SECRET), "null header fails");
assert(!verifyStripe(stripeBody, makeStripeHeader(stripeBody, STRIPE_SECRET), null), "null secret fails");
assert(!verifyStripe("tampered-body", makeStripeHeader(stripeBody, STRIPE_SECRET), STRIPE_SECRET), "body mismatch fails");
assert(!verifyStripe(stripeBody, makeStripeHeader(stripeBody, STRIPE_SECRET, -400), STRIPE_SECRET), "signature >5 min old fails");
assert(verifyStripe(stripeBody, makeStripeHeader(stripeBody, STRIPE_SECRET, -299), STRIPE_SECRET), "signature <5 min old passes");

console.log("\n--- news.js: RSS parseRss logic ---");

function decodeEntities(s) {
  return String(s)
    .replace(/<!\[CDATA\[|\]\]>/g, "")
    .replace(/&#(\d+);/g, function (_, n) { return String.fromCharCode(+n); })
    .replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#039;|&apos;/g, "'")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&nbsp;/g, " ").trim();
}
function parseRss(xml, source) {
  const items = [];
  const chunks = String(xml).split(/<item[\s>]/).slice(1, 12);
  for (const c of chunks) {
    const t = (c.match(/<title>([\s\S]*?)<\/title>/) || [])[1];
    const l = (c.match(/<link>([\s\S]*?)<\/link>/) || [])[1];
    const d = (c.match(/<pubDate>([\s\S]*?)<\/pubDate>/) || [])[1];
    if (t && l) {
      const at = d ? new Date(d).getTime() : Date.now();
      const url = decodeEntities(l);
      if (!/^https?:\/\//i.test(url)) continue;
      items.push({ t: decodeEntities(t).slice(0, 160), u: url, s: source, at: isNaN(at) ? Date.now() : at });
    }
  }
  return items;
}

const rssXml = `<?xml version="1.0"?>
<rss><channel>
<item><title>Bitcoin hits $100k</title><link>https://coindesk.com/article1</link><pubDate>Mon, 07 Sep 2026 10:00:00 +0000</pubDate></item>
<item><title>ETH upgrade live</title><link>https://coindesk.com/article2</link><pubDate>Mon, 07 Sep 2026 09:00:00 +0000</pubDate></item>
<item><title>Bad item</title><link>javascript:alert(1)</link></item>
<item><title>No link item</title></item>
</channel></rss>`;

const rssItems = parseRss(rssXml, "CoinDesk");
assert(rssItems.length === 2, "only 2 valid items parsed (js: URL and no-link skipped)");
assert(rssItems[0].s === "CoinDesk", "source set correctly");
assert(rssItems[0].t === "Bitcoin hits $100k", "title parsed");
assert(rssItems[0].u === "https://coindesk.com/article1", "URL parsed");
assert(parseRss("", "X").length === 0, "empty XML returns no items");
assert(parseRss("<rss><channel></channel></rss>", "X").length === 0, "no items in valid XML returns empty");

console.log("\n--- decodeEntities ---");
assert(decodeEntities("&amp;amp;") === "&amp;", "nested amp decodes one level");
assert(decodeEntities("<![CDATA[hello]]>") === "hello", "CDATA unwrapped");
assert(decodeEntities("&#65;") === "A", "decimal entity decoded");
assert(decodeEntities("&lt;tag&gt;") === "<tag>", "lt/gt decoded");
assert(decodeEntities("&quot;quoted&quot;") === '"quoted"', "quot decoded");

console.log("\n--- lib/utils: shared module exports ---");
try {
  const utils = require(path.join(__dirname, "../netlify/functions/lib/utils"));
  assert(typeof utils.esc === "function", "lib/utils exports esc");
  assert(typeof utils.fp === "function", "lib/utils exports fp");
  assert(typeof utils.pct === "function", "lib/utils exports pct");
  assert(typeof utils.signToken === "function", "lib/utils exports signToken");
  assert(typeof utils.verifyToken === "function", "lib/utils exports verifyToken");
  assert(typeof utils.secretKey === "function", "lib/utils exports secretKey");
  assert(typeof utils.planFor === "function", "lib/utils exports planFor");
  assert(typeof utils.emailLayout === "function", "lib/utils exports emailLayout");
  assert(typeof utils.json === "function", "lib/utils exports json");

  // Smoke-test esc from the shared module
  assert(utils.esc("<test>") === "&lt;test&gt;", "lib/utils esc works");

  // Smoke-test fp formatting
  assert(utils.fp(0.00001234) === "$0.000012", "fp formats micro price");
  assert(utils.fp(1.5) === "$1.50", "fp formats dollars");
  assert(utils.fp(100000) === "$100,000", "fp formats thousands with commas");

  // Smoke-test pct formatting
  assert(utils.pct(5.123) === "+5.1%", "pct formats positive gain");
  assert(utils.pct(-3.456) === "-3.5%", "pct formats negative loss");

  // Smoke-test emailLayout HTML output
  const html = utils.emailLayout({
    badge: "🎯 Test", badgeColor: "#4ade80",
    safeTitle: "Test title",
    safeBody: "<p>body</p>",
    ctaLabel: "Click →",
    reason: "you are testing",
    email: "test@example.com",
  });
  assert(typeof html === "string" && html.includes("Test title"), "emailLayout produces HTML with title");
  assert(html.includes("bullruniq.com/api/unsubscribe"), "emailLayout includes unsubscribe link");
  assert(html.includes(encodeURIComponent("test@example.com")), "emailLayout encodes email in unsub URL");
  assert(html.includes("you are testing"), "emailLayout includes reason");

  // json helper
  const resp = utils.json(200, { ok: true }, { "X-Test": "1" });
  assert(resp.statusCode === 200, "json helper sets status code");
  assert(JSON.parse(resp.body).ok === true, "json helper serialises body");
  assert(resp.headers["X-Test"] === "1", "json helper merges extra headers");

} catch (e) {
  console.error("  ✗ FAIL: lib/utils could not be loaded:", e.message);
  failed++;
}

// --- Summary ---
console.log("\n==========================================");
console.log("Results: " + passed + " passed, " + failed + " failed");
if (failed > 0) process.exit(1);
