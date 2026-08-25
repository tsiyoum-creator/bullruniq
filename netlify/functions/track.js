// BullrunIQ — minimal first-party analytics beacon.

const GIF = Buffer.from("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7", "base64");

exports.handler = async function (event) {
  try {
    let e = {};
    if (event.httpMethod === "POST") {
      try { e = JSON.parse(event.body || "{}"); } catch (x) {}
    } else {
      e = event.queryStringParameters || {};
    }
    const h = event.headers || {};
    const rec = {
      t: new Date().toISOString(),
      ev: String(e.ev || "pageview").slice(0, 40),
      path: String(e.path || h.referer || "").slice(0, 200),
      ref: String(e.ref || "").slice(0, 200),
      meta: e.meta ? String(JSON.stringify(e.meta)).slice(0, 300) : undefined,
      ua: String(h["user-agent"] || "").slice(0, 160),
      country: h["x-country"] || h["x-nf-geo"] || undefined,
    };
    console.log("[analytics]", JSON.stringify(rec));
  } catch (err) {
    console.log("[analytics] error", err.message);
  }
  return {
    statusCode: 200,
    headers: {
      "Content-Type": "image/gif",
      "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
      "Access-Control-Allow-Origin": "*",
    },
    body: GIF.toString("base64"),
    isBase64Encoded: true,
  };
};
