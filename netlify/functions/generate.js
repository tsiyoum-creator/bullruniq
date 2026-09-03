// BullrunIQ — Secure Anthropic proxy

const { verifyToken } = require("./_shared");

const ALLOWED_MODELS = new Set([
  "claude-opus-5",
  "claude-sonnet-5",
  "claude-opus-4-8",
  "claude-sonnet-4-6",
  "claude-haiku-4-5-20251001",
]);
const DEFAULT_MODEL = "claude-sonnet-4-6";
const MAX_TOKENS_CAP = 1500;
const MAX_BODY_BYTES = 32 * 1024; // 32 KB guard against oversized requests
const MAX_SYSTEM_LEN = 4000;
const MAX_MSG_CONTENT_LEN = 8000;
const DAILY_IP_CAP = 200;
const BURST_MAX = 30;
const BURST_WINDOW_MS = 60000;
const DAILY_USER_CAP = 1000;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const VALID_ROLES = new Set(["user", "assistant"]);

function sanitizeMessages(msgs) {
  if (!Array.isArray(msgs)) return null;
  const out = [];
  for (const m of msgs) {
    if (!m || typeof m !== "object") return null;
    const role = String(m.role || "");
    if (!VALID_ROLES.has(role)) return null;
    const content = String(m.content || "").slice(0, MAX_MSG_CONTENT_LEN);
    if (!content.trim()) return null;
    out.push({ role, content });
  }
  return out.length ? out : null;
}

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

exports.handler = async function (event) {
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, headers: CORS, body: "" };
  if (event.httpMethod !== "POST") return { statusCode: 405, headers: CORS, body: "Method Not Allowed" };

  const API_KEY = process.env.ANTHROPIC_API_KEY;
  if (!API_KEY) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: { message: "Server AI is not configured." } }) };
  }

  const rawBody = event.body || "";
  if (rawBody.length > MAX_BODY_BYTES) {
    return { statusCode: 413, headers: CORS, body: JSON.stringify({ error: { message: "Request body too large." } }) };
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
  try { payload = JSON.parse(rawBody || "{}"); } catch (e) {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: { message: "Invalid JSON body" } }) };
  }

  let { system, messages, prompt, model, max_tokens } = payload;
  if (!messages && prompt) messages = [{ role: "user", content: String(prompt) }];

  const cleanMessages = sanitizeMessages(messages);
  if (!cleanMessages) {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: { message: "Missing or invalid messages" } }) };
  }

  model = ALLOWED_MODELS.has(model) ? model : DEFAULT_MODEL;
  max_tokens = Math.min(Math.max(parseInt(max_tokens, 10) || 800, 1), MAX_TOKENS_CAP);

  const body = { model, max_tokens, messages: cleanMessages };
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
