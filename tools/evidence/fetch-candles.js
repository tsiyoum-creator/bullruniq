// Widen the sample. Coinbase public candles: free, no key, paginates.
// Daily granularity, several years, multiple assets -> enough trades to say
// something, and enough history to cover more than one regime.
const fs = require('fs');
const path = require('path');
const OUT = process.env.CANDLE_DIR || path.join(__dirname,'candles');
fs.mkdirSync(OUT,{recursive:true});

const PRODUCTS = ['BTC-USD','ETH-USD','SOL-USD','LTC-USD','LINK-USD','AVAX-USD',
                  'DOT-USD','ADA-USD','XRP-USD','DOGE-USD','ATOM-USD','UNI-USD'];
const GRAN = 86400;          // 1 day
const YEARS = 5;
const PAGE = 290 * GRAN;     // stay under the 300-candle cap

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function fetchProduct(p) {
  const now = Math.floor(Date.now() / 1000);
  const start0 = now - YEARS * 365 * GRAN;
  const rows = new Map();
  for (let s = start0; s < now; s += PAGE) {
    const e = Math.min(s + PAGE, now);
    const url = `https://api.exchange.coinbase.com/products/${p}/candles`
              + `?granularity=${GRAN}&start=${new Date(s*1000).toISOString()}&end=${new Date(e*1000).toISOString()}`;
    let ok = false;
    for (let attempt = 0; attempt < 3 && !ok; attempt++) {
      try {
        const r = await fetch(url, { headers: { 'User-Agent': 'bt/1.0' } });
        if (r.status === 429) { await sleep(1500 * (attempt + 1)); continue; }
        const d = await r.json();
        if (Array.isArray(d)) { d.forEach(row => rows.set(row[0], row)); ok = true; }
        else { await sleep(900); }
      } catch (err) { await sleep(900); }
    }
    await sleep(260);   // be polite
  }
  // Coinbase rows: [time, low, high, open, close, volume] -> our shape
  const out = [...rows.values()].sort((a, b) => a[0] - b[0])
    .map(r => ({ time: r[0] * 1000, open: r[3], high: r[2], low: r[1], close: r[4] }))
    .filter(k => k.open && k.high && k.low && k.close);
  return out;
}

(async () => {
  const summary = [];
  for (const p of PRODUCTS) {
    const sym = p.split('-')[0];
    try {
      const c = await fetchProduct(p);
      if (c.length < 120) { console.log(`${sym}: only ${c.length} candles — skipped`); continue; }
      fs.writeFileSync(`${OUT}/d_${sym}.json`, JSON.stringify(c));
      const f = t => new Date(t).toISOString().slice(0, 10);
      summary.push(`${sym}: ${c.length} candles  ${f(c[0].time)} -> ${f(c[c.length-1].time)}`);
      console.log(summary[summary.length - 1]);
    } catch (e) { console.log(`${sym}: ${e.message}`); }
  }
  console.log(`\n${summary.length} assets saved`);
})();
