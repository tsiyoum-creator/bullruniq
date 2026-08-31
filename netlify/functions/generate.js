// BullrunIQ — Secure Anthropic proxy

const { CORS_POST, verifyToken } = require("./_shared");

const ALLOWED_MODELS = new Set([
  "claude-opus-4-8",
  "claude-sonnet-4-6",
  "claude-haiku-4-5-20251001",
]);
const DEFAULT_MODEL = "claude-sonnet-4-6";
const MAX_TOKENS_CAP = 1500;
const DAILY_IP_CAP = 200;
const BURST_MAX = 30;
const BURST_WINDOW_MS = 60000;
const DAILY_USER_CAP = 1000;
const MAX_SYSTEM_LEN = 2000;
const MAX_MSG_CONTENT_LEN = 8000;

const CORS = CORS_POST;

const _burst = new Map();

function clientIp(event) {
  const h = event.headers || {};
  return h["x-nf-client-connection-ip"] || (h["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";
}

function burstOk(ip) {
  const now = Date.now();
  const e = _burst.get(ip);
  if (!e || now - e.t > BURST_WINDOW_MS) {
    _burst.set(ip, { t: now, n: 1 });
    if (_burst.size > 5000) {
      for (const [k, v] of _burst) if (now - v.t > BURST_WINDOW_MS) _burst.delete(k);
    }
    return true;
  }
  e.n++;
  return e.n <= BURST_MAX;
}

async function dailyOk(key, cap) {
  try {
    const { getStore } = require("@netlify/blobs");
    const store = getStore("ai-usage");
    const today = new Date().toISOString().slice(0, 10);
    const storeKey = key + ":" + today;
    const cur = (await store.get(storeKey, { type: "json" })) || { count: 0 };
    if (cur.count >= cap) return false;
    cur.count++;
    await store.setJSON(storeKey, cur);
    return true;
  } catch (e) { return true; }
}

function sanitizeMessages(messages) {
  return messages.map(function (m) {
    const role = m.role === "assistant" ? "assistant" : "user";
    let content = m.content;
    if (typeof content === "string") {
      content = content.slice(0, MAX_MSG_CONTENT_LEN);
    } else if (Array.isArray(content)) {
      content = content.slice(0, 20).map(function (block) {
        if (block && typeof block.text === "string") {
          return { ...block, text: block.text.slice(0, MAX_MSG_CONTENT_LEN) };
        }
        return block;
      });
    }
    return { role, content };
  });
}

exports.handler = async function (event) {
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, headers: CORS, body: "" };
  if (event.httpMethod !== "POST") return { statusCode: 405, headers: CORS, body: "Method Not Allowed" };

  const API_KEY = process.env.ANTHROPIC_API_KEY;
  if (!API_KEY) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: { message: "Server AI is not configured." } }) };
  }

  try { require("@netlify/blobs").connectLambda(event); } catch (e) {}
  const ip = clientIp(event);
  const h = event.headers || {};
  const authz = (h.authorization || h.Authorization || "").replace(/^Bearer\s+/i, "").trim();
  const authedEmail = verifyToken(authz);

  if (authedEmail) {
    if (!(await dailyOk("user:" + authedEmail, DAILY_USER_CAP))) {
      return { statusCode: 429, headers: CORS, body: JSON.stringify({ error: { message: "Daily AI limit reached. Try again tomorrow or add your own API key in Settings." } }) };
    }
  } else {
    if (!burstOk(ip)) {
      return { statusCode: 429, headers: CORS, body: JSON.stringify({ error: { message: "Too many requests — slow down a moment and try again." } }) };
    }
    if (!(await dailyOk("ip:" + ip, DAILY_IP_CAP))) {
      return { statusCode: 429, headers: CORS, body: JSON.stringify({ error: { message: "Daily AI limit reached for this network. Log in or add your own API key in Settings for more." } }) };
    }
  }

  let payload;
  try { payload = JSON.parse(event.body || "{}"); } catch (e) {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: { message: "Invalid JSON body" } }) };
  }

  let { system, messages, prompt, model, max_tokens } = payload;
  if (!messages && prompt) messages = [{ role: "user", content: String(prompt) }];
  if (!Array.isArray(messages) || !messages.length) {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: { message: "Missing messages or prompt" } }) };
  }

  model = ALLOWED_MODELS.has(model) ? model : DEFAULT_MODEL;
  max_tokens = Math.min(Math.max(parseInt(max_tokens, 10) || 800, 1), MAX_TOKENS_CAP);

  const body = { model, max_tokens, messages: sanitizeMessages(messages) };
  if (system) body.system = String(system).slice(0, MAX_SYSTEM_LEN);

  try {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": API_KEY, "anthropic-version": "2023-06-01" },
      body: JSON.stringify(body),
    });
    const text = await response.text();
    return { statusCode: response.status, headers: { "Content-Type": "application/json", ...CORS }, body: text };
  } catch (err) {
    return { statusCode: 502, headers: CORS, body: JSON.stringify({ error: { message: "Upstream error: " + err.message } }) };
  }
};
