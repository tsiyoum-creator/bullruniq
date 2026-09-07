// Shared utilities for BullrunIQ serverless functions.
// Centralises token auth, plan lookup, HTML helpers, and email layout so each
// function file doesn't need its own copy.

const crypto = require("crypto");

// ── Auth ─────────────────────────────────────────────────────────────────────

function secretKey() {
  if (process.env.AUTH_SECRET) return process.env.AUTH_SECRET;
  // Fallback: derive from the Anthropic key so the app works with zero extra
  // config. Rotating ANTHROPIC_API_KEY logs everyone out — safe but disruptive.
  // Set AUTH_SECRET to decouple the two.
  if (process.env.ANTHROPIC_API_KEY) {
    return crypto.createHash("sha256").update("briq-auth:" + process.env.ANTHROPIC_API_KEY).digest("hex");
  }
  return null;
}

function signToken(email, days) {
  const exp = Date.now() + (days || 30) * 864e5;
  const p = Buffer.from(email + "|" + exp).toString("base64url");
  const sig = crypto.createHmac("sha256", secretKey()).update(p).digest("base64url");
  return p + "." + sig;
}

function verifyToken(tok) {
  try {
    const key = secretKey();
    if (!key || !tok) return null;
    const i = tok.lastIndexOf(".");
    if (i < 1) return null;
    const p = tok.slice(0, i), sig = tok.slice(i + 1);
    const expect = crypto.createHmac("sha256", key).update(p).digest("base64url");
    if (!crypto.timingSafeEqual(Buffer.from(expect), Buffer.from(sig))) return null;
    const raw = Buffer.from(p, "base64url").toString("utf8");
    const j = raw.lastIndexOf("|");
    const email = raw.slice(0, j), exp = parseInt(raw.slice(j + 1), 10);
    if (!email || !exp || Date.now() > exp) return null;
    return email;
  } catch (e) { return null; }
}

// ── Plan lookup ───────────────────────────────────────────────────────────────

async function planFor(email, getStore) {
  try {
    const rec = await getStore("customers").get(email, { type: "json" });
    if (rec && (rec.status === "active" || rec.status === "trialing")) return rec.tier || "pro";
  } catch (e) {}
  return "free";
}

// ── Formatting ────────────────────────────────────────────────────────────────

function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
}

function fp(v) {
  return v >= 1000
    ? "$" + v.toLocaleString("en-US", { maximumFractionDigits: 2 })
    : v >= 1
      ? "$" + v.toFixed(2)
      : "$" + v.toFixed(6);
}

function pct(v) {
  return (v >= 0 ? "+" : "") + v.toFixed(1) + "%";
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

function json(code, obj, cors) {
  return { statusCode: code, headers: { "Content-Type": "application/json", ...(cors || {}) }, body: JSON.stringify(obj) };
}

// ── Email layout ──────────────────────────────────────────────────────────────
// All parameters are treated as already-safe HTML strings except `email`
// (used only in the unsubscribe URL, which is encodeURIComponent-encoded).
//
// opts: { badge, badgeColor, safeTitle, safeBody, ctaLabel, ctaBg, ctaFg, reason, email }
//   badge       – pill text including emoji (HTML, trusted)
//   badgeColor  – CSS colour for the badge
//   safeTitle   – h1 text (caller must esc() any user data)
//   safeBody    – middle block HTML (caller must esc() any user data)
//   ctaLabel    – button label text (plain, no escaping needed)
//   ctaBg       – button background colour (default #c9a84c)
//   ctaFg       – button foreground colour (default #000)
//   reason      – short clause after "You get these because" (plain text, no HTML)
//   email       – recipient email for the unsubscribe link

function emailLayout(opts) {
  const ctaBg = opts.ctaBg || "#c9a84c";
  const ctaFg = opts.ctaFg || "#000";
  const reasonStr = opts.reason ? "You get these because " + opts.reason + ".<br>" : "";
  return "<!doctype html><html><head><meta charset='utf-8'></head>"
    + "<body style='margin:0;background:#050505;padding:40px 24px;font-family:-apple-system,Segoe UI,sans-serif;text-align:center'>"
    + "<div style='font-family:Georgia,serif;font-size:20px;letter-spacing:2px;color:#f0ece4;margin-bottom:24px'>Bullrun<span style='color:#c9a84c'>IQ</span></div>"
    + "<div style='font-size:12px;letter-spacing:2px;text-transform:uppercase;color:" + opts.badgeColor + ";margin-bottom:10px'>" + opts.badge + "</div>"
    + "<div style='font-family:Georgia,serif;font-size:30px;color:#f0ece4;margin-bottom:8px'>" + opts.safeTitle + "</div>"
    + opts.safeBody
    + "<a href='https://bullruniq.com/platform' style='display:inline-block;background:" + ctaBg + ";color:" + ctaFg + ";text-decoration:none;border-radius:4px;padding:14px 32px;font-size:13px;font-weight:600;letter-spacing:1px;text-transform:uppercase'>" + opts.ctaLabel + "</a>"
    + "<div style='border-top:1px solid #1a1a1a;margin-top:32px;padding-top:16px;font-size:11px;color:#5c574e;line-height:1.6;max-width:420px;margin-left:auto;margin-right:auto'>"
    + "Educational alert, not financial advice. " + reasonStr
    + "<a href='https://bullruniq.com/api/unsubscribe?email=" + encodeURIComponent(opts.email) + "' style='color:#8a8278'>Unsubscribe from all emails</a>"
    + "</div>"
    + "</body></html>";
}

module.exports = { secretKey, signToken, verifyToken, planFor, esc, fp, pct, json, emailLayout };
