// BullrunIQ — Daily Brief newsletter (scheduled).

const MAX_SEND = 1000;

function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function briefToHtml(text) {
  return esc(text)
    .replace(/\*\*(.*?)\*\*/g, "<strong style='color:#f0ece4'>$1</strong>")
    .split(/\n+/)
    .filter(function (l) { return l.trim(); })
    .map(function (l) { return "<p style='margin:0 0 12px;color:#c8c4bc;font-size:15px;line-height:1.7'>" + l.trim() + "</p>"; })
    .join("");
}
function emailHtml(briefHtml, btc, fg, email, dateStr) {
  var unsub = "https://bullruniq.com/api/unsubscribe?email=" + encodeURIComponent(email);
  return "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'></head><body style='margin:0;background:#050505;padding:0'>"
    + "<div style='max-width:560px;margin:0 auto;padding:32px 24px;font-family:-apple-system,Segoe UI,Helvetica,sans-serif'>"
    + "<div style='font-family:Georgia,serif;font-size:20px;letter-spacing:2px;color:#f0ece4;margin-bottom:4px'>Bullrun<span style='color:#c9a84c'>IQ</span></div>"
    + "<div style='font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:#5c574e;margin-bottom:24px'>Daily Brief · " + esc(dateStr) + "</div>"
    + "<div style='display:flex;gap:10px;margin-bottom:24px'>"
    + "<div style='flex:1;background:#111;border:1px solid #1a1a1a;border-radius:8px;padding:12px 14px'><div style='font-size:10px;color:#5c574e;text-transform:uppercase;letter-spacing:1px'>Bitcoin</div><div style='font-size:15px;color:#c9a84c;margin-top:3px'>" + esc(btc) + "</div></div>"
    + "<div style='flex:1;background:#111;border:1px solid #1a1a1a;border-radius:8px;padding:12px 14px'><div style='font-size:10px;color:#5c574e;text-transform:uppercase;letter-spacing:1px'>Fear &amp; Greed</div><div style='font-size:15px;color:#c9a84c;margin-top:3px'>" + esc(fg) + "</div></div>"
    + "</div>"
    + briefHtml
    + "<a href='https://bullruniq.com/platform' style='display:inline-block;background:#c9a84c;color:#000;text-decoration:none;border-radius:4px;padding:14px 32px;font-size:13px;font-weight:600;letter-spacing:1px;text-transform:uppercase;margin:18px 0 8px'>Open your command center →</a>"
    + "<div style='border-top:1px solid #1a1a1a;margin-top:28px;padding-top:18px;font-size:11px;color:#5c574e;line-height:1.6'>"
    + "BullrunIQ provides AI-generated market analysis for educational purposes only. Not financial advice.<br>"
    + "<a href='" + unsub + "' style='color:#8a8278'>Unsubscribe</a> · <a href='https://bullruniq.com' style='color:#8a8278'>bullruniq.com</a>"
    + "</div></div></body></html>";
}

exports.handler = async function (event) {
  try { require("@netlify/blobs").connectLambda(event); } catch (e) {}
  const RESEND = process.env.RESEND_API_KEY;
  const ANTH = process.env.ANTHROPIC_API_KEY;
  const FROM = process.env.NEWSLETTER_FROM || "BullrunIQ <brief@bullruniq.com>";
  if (!RESEND || !ANTH) {
    console.log("[newsletter] skipped — set RESEND_API_KEY and ANTHROPIC_API_KEY to enable.");
    return { statusCode: 200, body: "not configured" };
  }

  const MODEL = process.env.NEWSLETTER_MODEL || "claude-sonnet-4-6";
  var btc = "n/a", fg = "n/a";
  try {
    const r = await fetch("https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd&include_24hr_change=true");
    const d = await r.json();
    if (d.bitcoin) btc = "$" + Math.round(d.bitcoin.usd).toLocaleString() + " (" + (d.bitcoin.usd_24h_change >= 0 ? "+" : "") + d.bitcoin.usd_24h_change.toFixed(1) + "%)";
  } catch (e) {}
  try {
    const r = await fetch("https://api.alternative.me/fng/?limit=1");
    const d = await r.json();
    if (d.data && d.data[0]) fg = d.data[0].value + " (" + d.data[0].value_classification + ")";
  } catch (e) {}

  var brief = "";
  try {
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": ANTH, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: 500,
        messages: [{ role: "user", content: "Write the BullrunIQ daily market brief as 4-5 short bullet points. Each bullet: an emoji + a **bold label** + one concrete sentence. Cover: the crypto market backdrop, the BTC trend, one altcoin/sector theme, the biggest risk to watch, and end with one action to consider today. Under 160 words. Educational, not financial advice. Live data: BTC " + btc + ", Fear & Greed " + fg + ". Date " + new Date().toUTCString() }],
      }),
    });
    const d = await r.json();
    brief = (d.content && d.content[0] && d.content[0].text) || "";
  } catch (e) { console.log("[newsletter] brief generation failed:", e.message); }
  if (!brief) {
    brief = "📊 **Market check** — AI brief generation failed today; check your portfolio in the command center.\n💡 **Tip** — Review your watchlist targets and ensure your stop-losses are current.\n⚠️ **Reminder** — This is an educational newsletter, not financial advice.";
    console.log("[newsletter] using fallback brief");
  }

  var subs = [];
  try {
    const { getStore } = require("@netlify/blobs");
    const list = await getStore("subscribers").list();
    subs = (list.blobs || []).map(function (b) { return b.key; });
  } catch (e) { console.log("[newsletter] subscriber list failed:", e.message); }
  if (!subs.length) { console.log("[newsletter] no subscribers yet"); return { statusCode: 200, body: "no subscribers" }; }

  var dateStr = new Date().toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" });
  var subject = "BullrunIQ Daily Brief — " + new Date().toLocaleDateString("en-US", { month: "short", day: "numeric" });
  var briefHtml = briefToHtml(brief);
  var BATCH = 10;
  var sent = 0, failed = 0;
  var batch = subs.slice(0, MAX_SEND);
  for (var i = 0; i < batch.length; i += BATCH) {
    var chunk = batch.slice(i, i + BATCH);
    var results = await Promise.allSettled(chunk.map(function (email) {
      return fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { Authorization: "Bearer " + RESEND, "Content-Type": "application/json" },
        body: JSON.stringify({
          from: FROM,
          to: email,
          subject: subject,
          html: emailHtml(briefHtml, btc, fg, email, dateStr),
          headers: { "List-Unsubscribe": "<https://bullruniq.com/api/unsubscribe?email=" + encodeURIComponent(email) + ">" },
        }),
      }).then(function (r) { return r.ok ? "ok" : "err"; });
    }));
    results.forEach(function (r) {
      if (r.status === "fulfilled" && r.value === "ok") sent++; else failed++;
    });
  }
  console.log("[newsletter] sent " + sent + ", failed " + failed + ", of " + subs.length + " subscribers");
  return { statusCode: 200, body: "sent " + sent + "/" + subs.length };
};
