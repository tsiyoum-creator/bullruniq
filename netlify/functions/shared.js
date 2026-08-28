// BullrunIQ — shared utilities for Netlify Functions.
// Single source of truth for token signing/verification, plan lookup, and CORS.

const crypto = require("crypto");

const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "https://bullruniq.com";

function cors(methods) {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": methods || "POST, OPTIONS",
  };
}

function secretKey() {
  if (process.env.AUTH_SECRET) return process.env.AUTH_SECRET;
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
    // Guard against timingSafeEqual throwing on length mismatch
    const eBuf = Buffer.from(expect);
    const sBuf = Buffer.from(sig);
    if (eBuf.length !== sBuf.length) return null;
    if (!crypto.timingSafeEqual(eBuf, sBuf)) return null;
    const raw = Buffer.from(p, "base64url").toString("utf8");
    const j = raw.lastIndexOf("|");
    const email = raw.slice(0, j), exp = parseInt(raw.slice(j + 1), 10);
    if (!email || !exp || Date.now() > exp) return null;
    return email;
  } catch (e) { return null; }
}

function signUnsubToken(email) {
  const mac = crypto.createHmac("sha256", secretKey() || "briq-unsub").update(email).digest("base64url");
  return mac;
}

function verifyUnsubToken(email, token) {
  const expected = signUnsubToken(email);
  const eBuf = Buffer.from(expected);
  const tBuf = Buffer.from(token || "");
  if (eBuf.length !== tBuf.length) return false;
  try { return crypto.timingSafeEqual(eBuf, tBuf); } catch (e) { return false; }
}

async function planFor(email, getStore) {
  try {
    const rec = await getStore("customers").get(email, { type: "json" });
    if (rec && (rec.status === "active" || rec.status === "trialing")) return rec.tier || "pro";
  } catch (e) {}
  return "free";
}

function json(code, obj, methods) {
  return { statusCode: code, headers: { "Content-Type": "application/json", ...cors(methods) }, body: JSON.stringify(obj) };
}

// Canonical CoinGecko ID map — single source of truth for both server and client alerts.
const CGMAP = {
  BTC:"bitcoin", ETH:"ethereum", SOL:"solana", BNB:"binancecoin", XRP:"ripple",
  ADA:"cardano", DOGE:"dogecoin", AVAX:"avalanche-2", DOT:"polkadot", MATIC:"matic-network",
  LINK:"chainlink", LTC:"litecoin", NEAR:"near", APT:"aptos", SHIB:"shiba-inu",
  UNI:"uniswap", ATOM:"cosmos", TRX:"tron", OP:"optimism", ARB:"arbitrum",
  SUI:"sui", INJ:"injective-protocol", PEPE:"pepe", WIF:"dogwifcoin", TON:"the-open-network",
  XLM:"stellar", HBAR:"hedera-hashgraph", QNT:"quant-network", AERO:"aerodrome-finance",
  ALGO:"algorand", VET:"vechain", FIL:"filecoin", ICP:"internet-computer",
  RENDER:"render-token", FTM:"fantom", CRO:"crypto-com-chain", LDO:"lido-dao",
  RUNE:"thorchain", SAND:"the-sandbox", MANA:"decentraland", AXS:"axie-infinity",
  GALA:"gala", IMX:"immutable-x", BLUR:"blur", SEI:"sei-network", ONDO:"ondo-finance",
  JUP:"jupiter-exchange-solana", PYTH:"pyth-network", JTO:"jito-governance-token",
  BONK:"bonk", STRK:"starknet", TAO:"bittensor", ETHFI:"ether-fi", ENA:"ethena",
  FLOKI:"floki", WEN:"wen-4", ZETA:"zetachain", W:"wormhole", BEAM:"beam-2",
  FDUSD:"first-digital-usd", PEOPLE:"constitutiondao",
};

module.exports = { cors, secretKey, signToken, verifyToken, signUnsubToken, verifyUnsubToken, planFor, json, CGMAP };
