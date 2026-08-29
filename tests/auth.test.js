// Unit tests for BullrunIQ serverless function logic.
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
    const expect = crypto.createHmac("sha256", secret).update(p).digest("base64url");
    if (!crypto.timingSafeEqual(Buffer.from(expect), Buffer.from(sig))) return null;
    const raw = Buffer.from(p, "base64url").toString("utf8");
    const j = raw.lastIndexOf("|");
    const email = raw.slice(0, j), exp = parseInt(raw.slice(j + 1), 10);
    if (!email || !exp || Date.now() > exp) return null;
    return email;
  } catch (e) { return null; }
}

// Mirrors _shared.esc — escapes &, <, >, ", '
function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
}

// Mirrors _shared.signUnsub / verifyUnsub
function signUnsub(email, secret) {
  return crypto.createHmac("sha256", secret).update("unsub:" + String(email)).digest("base64url").slice(0, 20);
}
function verifyUnsub(email, token, secret) {
  if (!secret || !email || !token) return false;
  const expected = crypto.createHmac("sha256", secret).update("unsub:" + String(email)).digest("base64url").slice(0, 20);
  if (expected.length !== token.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(token)); } catch (e) { return false; }
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

// ── auth token: sign + verify ─────────────────────────────────────────────────
console.log("\n--- auth token: sign + verify ---");

const token = signToken("user@example.com", 30, TEST_SECRET);
assert(typeof token === "string" && token.includes("."), "token has two parts");
assert(verifyToken(token, TEST_SECRET) === "user@example.com", "valid token verifies to email");
assert(verifyToken(token, "wrong-secret") === null, "wrong secret returns null");
assert(verifyToken("", TEST_SECRET) === null, "empty token returns null");
assert(verifyToken("invalid.token", TEST_SECRET) === null, "tampered token returns null");
assert(verifyToken(null, TEST_SECRET) === null, "null token returns null");

// ── auth token: expiry ────────────────────────────────────────────────────────
console.log("\n--- auth token: expiry ---");

function signExpired(email, secret) {
  const exp = Date.now() - 1000;
  const p = Buffer.from(email + "|" + exp).toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(p).digest("base64url");
  return p + "." + sig;
}
const expiredToken = signExpired("user@example.com", TEST_SECRET);
assert(verifyToken(expiredToken, TEST_SECRET) === null, "expired token returns null");

// ── auth token: email embedding ───────────────────────────────────────────────
console.log("\n--- auth token: email embedding ---");

const emails = ["test@example.com", "user+tag@sub.domain.io", "A@B.CO"];
for (const em of emails) {
  const t = signToken(em.toLowerCase(), 1, TEST_SECRET);
  assert(verifyToken(t, TEST_SECRET) === em.toLowerCase(), "round-trips: " + em);
}

// ── unsubscribe token: sign + verify ─────────────────────────────────────────
console.log("\n--- unsubscribe token: sign + verify ---");

const utok = signUnsub("alice@example.com", TEST_SECRET);
assert(typeof utok === "string" && utok.length === 20, "unsub token is 20 chars");
assert(verifyUnsub("alice@example.com", utok, TEST_SECRET), "valid unsub token verifies");
assert(!verifyUnsub("alice@example.com", utok, "wrong-secret"), "wrong secret fails");
assert(!verifyUnsub("bob@example.com", utok, TEST_SECRET), "different email fails");
assert(!verifyUnsub("alice@example.com", utok.slice(0, 19) + "X", TEST_SECRET), "tampered token fails");
assert(!verifyUnsub("", utok, TEST_SECRET), "empty email fails");
assert(!verifyUnsub("alice@example.com", "", TEST_SECRET), "empty token fails");
// Tokens are email-specific
assert(signUnsub("a@b.com", TEST_SECRET) !== signUnsub("c@d.com", TEST_SECRET), "different emails produce different tokens");

// ── unsubscribe: email validation ─────────────────────────────────────────────
console.log("\n--- unsubscribe: email validation ---");

function isValidEmail(s) {
  return typeof s === "string" && s.length > 0 && s.length <= 200 && s.indexOf("@") > 0;
}
assert(isValidEmail("a@b.com"), "valid email passes");
assert(!isValidEmail(""), "empty string fails");
assert(!isValidEmail("notanemail"), "missing @ fails");
assert(!isValidEmail("@nodomain"), "@ at start fails");
assert(!isValidEmail("a".repeat(201) + "@b.com"), "too long fails");

// ── HTML escaping (XSS guard) ─────────────────────────────────────────────────
console.log("\n--- HTML escaping (XSS guard) ---");

assert(esc("<script>alert(1)</script>") === "&lt;script&gt;alert(1)&lt;/script&gt;", "script tags escaped");
assert(esc('"><img src=x onerror=alert(1)>') === "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;", "attribute injection escaped");
assert(esc("safe text") === "safe text", "safe text unchanged");
assert(esc("a&b") === "a&amp;b", "ampersand escaped");
assert(esc("it's") === "it&#x27;s", "single quote escaped");
assert(esc("'<script>'") === "&#x27;&lt;script&gt;&#x27;", "single quotes and tags escaped together");

// ── market.js: id validation ──────────────────────────────────────────────────
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
assert(validateIds("bitcoin,ethereum,solana,binancecoin,ripple").length === 5, "five ids pass");
assert(validateIds(Array(30).fill("bitcoin").join(",")).length === 25, "capped at 25 ids");

// ── news.js: URL scheme validation ───────────────────────────────────────────
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

// ── news.js: decodeEntities ───────────────────────────────────────────────────
console.log("\n--- news.js: decodeEntities ---");

function decodeEntities(s) {
  return String(s)
    .replace(/<!\[CDATA\[|\]\]>/g, "")
    .replace(/&#(\d+);/g, function (_, n) { return String.fromCharCode(+n); })
    .replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#039;|&apos;/g, "'")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&nbsp;/g, " ").trim();
}
assert(decodeEntities("&amp;") === "&", "&amp; decoded");
assert(decodeEntities("&lt;div&gt;") === "<div>", "HTML tags decoded");
assert(decodeEntities("&quot;hello&quot;") === '"hello"', "quotes decoded");
assert(decodeEntities("&#60;") === "<", "numeric entity decoded");
assert(decodeEntities("<![CDATA[text]]>") === "text", "CDATA stripped");
assert(decodeEntities("a&nbsp;b") === "a b", "nbsp decoded to space");
assert(decodeEntities("  trimmed  ") === "trimmed", "whitespace trimmed");
assert(decodeEntities("no entities") === "no entities", "plain text unchanged");

// ── news.js: parseRss ─────────────────────────────────────────────────────────
console.log("\n--- news.js: parseRss ---");

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
const rssFixture = `<?xml version="1.0"?>
<rss><channel>
<item>
  <title>BTC hits all-time high</title>
  <link>https://coindesk.com/btc-ath</link>
  <pubDate>Fri, 01 Jan 2027 12:00:00 GMT</pubDate>
</item>
<item>
  <title>ETH upgrade complete &amp; analysis</title>
  <link>https://coindesk.com/eth-upgrade</link>
  <pubDate>Thu, 31 Dec 2026 18:00:00 GMT</pubDate>
</item>
<item>
  <title>Bad item — no link</title>
</item>
<item>
  <title>JS injection item</title>
  <link>javascript:alert(1)</link>
</item>
</channel></rss>`;
const parsed = parseRss(rssFixture, "CoinDesk");
assert(parsed.length === 2, "parseRss returns 2 valid items (no-link and js: items excluded)");
assert(parsed[0].t === "BTC hits all-time high", "first item title correct");
assert(parsed[0].u === "https://coindesk.com/btc-ath", "first item URL correct");
assert(parsed[0].s === "CoinDesk", "source tag set");
assert(parsed[1].t === "ETH upgrade complete & analysis", "HTML entities decoded in title");
assert(parseRss("", "X").length === 0, "empty XML returns no items");

// ── alerts: price formatting ──────────────────────────────────────────────────
console.log("\n--- alerts: price formatting ---");

function fp(v) { return v >= 1000 ? "$" + v.toLocaleString("en-US", { maximumFractionDigits: 2 }) : v >= 1 ? "$" + v.toFixed(2) : "$" + v.toFixed(6); }
function pct(v) { return (v >= 0 ? "+" : "") + v.toFixed(1) + "%"; }

assert(fp(95000) === "$95,000", "large price formatted with comma");
assert(fp(2.5) === "$2.50", "small price formatted to 2 dp");
assert(fp(0.000123) === "$0.000123", "micro price formatted to 6 dp");
assert(fp(1000) === "$1,000", "exactly $1000 uses comma format");
assert(pct(25.7) === "+25.7%", "positive pct has + prefix");
assert(pct(-10.3) === "-10.3%", "negative pct has no extra prefix");
assert(pct(0) === "+0.0%", "zero pct has + prefix");

// ── alerts: sell alert logic ──────────────────────────────────────────────────
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

// ── alerts: buy alert logic ───────────────────────────────────────────────────
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

// ── submission-created: contact form filter ───────────────────────────────────
console.log("\n--- submission-created: contact form filter ---");

function shouldSubscribe(formName) {
  if (formName === "contact" || formName === "contact-form") return false;
  return true;
}
assert(shouldSubscribe("waitlist"), "waitlist form gets subscribed");
assert(shouldSubscribe("tier-signup"), "tier-signup form gets subscribed");
assert(!shouldSubscribe("contact"), "contact form is skipped");
assert(!shouldSubscribe("contact-form"), "contact-form variant is skipped");

// ── alerts: HTML escaping in emails ──────────────────────────────────────────
console.log("\n--- alerts: HTML escaping in emails ---");

assert(esc("<BTC>") === "&lt;BTC&gt;", "angle brackets escaped in ticker");
assert(esc("ETH & BNB") === "ETH &amp; BNB", "ampersand escaped in name");
assert(esc('BTC"injection"') === "BTC&quot;injection&quot;", "quotes escaped");
assert(esc("Coin's name") === "Coin&#x27;s name", "apostrophe in name escaped");

// ── portfolio guard: stop-loss / take-profit ──────────────────────────────────
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

// ── profit-lock ladder ────────────────────────────────────────────────────────
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

// ── cash deployment engine ────────────────────────────────────────────────────
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

// ── newsletter: briefToHtml ───────────────────────────────────────────────────
console.log("\n--- newsletter: briefToHtml ---");

function briefToHtml(text) {
  return esc(text)
    .replace(/\*\*(.*?)\*\*/g, "<strong style='color:#f0ece4'>$1</strong>")
    .split(/\n+/)
    .filter(function (l) { return l.trim(); })
    .map(function (l) { return "<p style='margin:0 0 12px;color:#c8c4bc;font-size:15px;line-height:1.7'>" + l.trim() + "</p>"; })
    .join("");
}
const briefOut = briefToHtml("📊 **Market check** — BTC up 5%.\n\n💡 **Tip** — Review positions.");
assert(briefOut.includes("<strong style='color:#f0ece4'>Market check</strong>"), "bold label rendered");
assert(briefOut.includes("<strong style='color:#f0ece4'>Tip</strong>"), "second bold label rendered");
assert(briefOut.includes("<p style="), "wrapped in paragraph tags");
assert(!briefOut.includes("\n"), "newlines collapsed");
assert(briefToHtml("<script>xss</script>") === "<p style='margin:0 0 12px;color:#c8c4bc;font-size:15px;line-height:1.7'>&lt;script&gt;xss&lt;/script&gt;</p>", "XSS content escaped in brief");
assert(briefToHtml("") === "", "empty brief returns empty string");
assert(briefToHtml("   \n\n  ") === "", "whitespace-only brief returns empty string");

// ── generate.js: message validation ──────────────────────────────────────────
console.log("\n--- generate.js: message validation ---");

function validateMessages(messages, maxCount, maxChars) {
  if (!Array.isArray(messages) || !messages.length) return null;
  if (messages.length > maxCount) return null;
  return messages.map(function (m) {
    return { role: String(m.role || "user"), content: String(m.content || "").slice(0, maxChars) };
  });
}
assert(validateMessages([], 10, 10000) === null, "empty messages rejected");
assert(validateMessages(null, 10, 10000) === null, "null messages rejected");
assert(validateMessages([{ role: "user", content: "hello" }], 10, 10000) !== null, "single message accepted");
assert(validateMessages(Array(11).fill({ role: "user", content: "x" }), 10, 10000) === null, "11 messages rejected with cap 10");
const truncated = validateMessages([{ role: "user", content: "a".repeat(20) }], 10, 10);
assert(truncated !== null && truncated[0].content.length === 10, "message content truncated to cap");

// ── stripe-webhook: signature verification ────────────────────────────────────
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
const STRIPE_SECRET = "whsec_test";
const body = '{"type":"checkout.session.completed"}';
const ts = Math.floor(Date.now() / 1000);
const validSig = crypto.createHmac("sha256", STRIPE_SECRET).update(ts + "." + body, "utf8").digest("hex");
const sigHeader = "t=" + ts + ",v1=" + validSig;
assert(verifyStripe(body, sigHeader, STRIPE_SECRET), "valid stripe signature passes");
assert(!verifyStripe(body, sigHeader, "wrong-secret"), "wrong secret fails");
assert(!verifyStripe(body, "t=" + ts + ",v1=badhex", STRIPE_SECRET), "tampered v1 fails");
assert(!verifyStripe(body, "", STRIPE_SECRET), "empty sig header fails");
assert(!verifyStripe(body, sigHeader, ""), "empty secret fails");
// Expired timestamp (>5 min)
const oldTs = Math.floor(Date.now() / 1000) - 400;
const oldSig = crypto.createHmac("sha256", STRIPE_SECRET).update(oldTs + "." + body, "utf8").digest("hex");
assert(!verifyStripe(body, "t=" + oldTs + ",v1=" + oldSig, STRIPE_SECRET), "expired stripe timestamp fails");

// ── market.js: sentiment transform ───────────────────────────────────────────
console.log("\n--- market.js: sentiment transform ---");

const fngResponse = { name: "Fear and Greed Index", data: [{ value: "72", value_classification: "Greed", timestamp: "1234567890" }, { value: "55", value_classification: "Neutral", timestamp: "1234481490" }] };
function sentimentTransform(data) { return (data && data.data) || []; }
const sentiment = sentimentTransform(fngResponse);
assert(Array.isArray(sentiment) && sentiment.length === 2, "sentiment transform returns data array");
assert(sentiment[0].value === "72", "first sentiment value correct");
assert(sentimentTransform(null).length === 0, "null input returns empty array");
assert(sentimentTransform({}).length === 0, "missing data key returns empty array");

// ── Summary ───────────────────────────────────────────────────────────────────
console.log("\n==========================================");
console.log("Results: " + passed + " passed, " + failed + " failed");
if (failed > 0) process.exit(1);
