// Phase 0, widened. Real engine, 12 assets, 5 years of DAILY candles.
// Reports per-regime so we can see whether any edge generalises or is a
// single-period artifact. Includes the random-entry control at full sample.
const { loadEngine } = require('./extract-engine.js');
const E = loadEngine();   // pulled from platform.html at runtime — never a stale copy
const fs = require('fs');
const path = require('path');
const DATA_DIR = process.env.CANDLE_DIR || path.join(__dirname,'candles');

const COST = (10 + 5) / 10000;           // 0.10% fee + 0.05% slippage, per side
const SYMS = ['BTC','ETH','SOL','LTC','LINK','AVAX','DOT','ADA','XRP','DOGE','ATOM','UNI'];
const HORIZON = +(process.env.HORIZON || 10);   // bars allowed to resolve

// Regimes chosen from BTC's own price history, not fitted to results.
const REGIMES = [
  ['2022 bear',      '2021-11-10', '2022-12-31'],
  ['2023 recovery',  '2023-01-01', '2023-12-31'],
  ['2024 bull',      '2024-01-01', '2024-12-31'],
  ['2025-26 decline','2025-01-01', '2026-12-31'],
];
const ms = d => new Date(d + 'T00:00:00Z').getTime();

function load(sym){ try { return JSON.parse(fs.readFileSync(`${DATA_DIR}/d_${sym}.json`,'utf8')); } catch(e){ return null; } }

function signalAt(c){
  if (c.length < 25) return null;
  const price = c[c.length-1].close;
  const bb = E.calcBB(c,20,2), atr = E.calcATR(c,14), rsiArr = E.calcRSI(c,14);
  const lb = bb[bb.length-1];
  if (!lb || !atr) return null;
  const rsi = rsiArr.length ? rsiArr[rsiArr.length-1].value : 50;
  let pctB = lb.upper>lb.lower ? (price-lb.lower)/(lb.upper-lb.lower) : 0.5;
  pctB = Math.max(-0.2, Math.min(1.2, pctB));
  const n=c.length, mom = n>5 ? (price-c[n-6].close)/c[n-6].close : 0;
  let score = E._oppScore(rsi,pctB,mom);
  const tr = E.tradeRead(c);
  if (tr) score += Math.round((tr.score-50)/10);
  return {
    price, score, action: E._oppAction(score),
    target: Math.max(lb.upper, price + 2*atr, (tr&&tr.levels)?tr.levels.target:0),
    stop:   Math.min(lb.lower, price - 1.5*atr),
  };
}
function gradeExit(call, future, maxBars){
  for (const k of future.slice(0,maxBars)){
    const hitT = call.side==='buy' ? k.high>=call.target : k.low<=call.target;
    const hitS = call.side==='buy' ? k.low<=call.stop    : k.high>=call.stop;
    if (hitT && hitS) return {exit:call.stop, resolved:true};
    if (hitT) return {exit:call.target, resolved:true};
    if (hitS) return {exit:call.stop,   resolved:true};
  }
  const h = future.slice(0,maxBars);
  return h.length ? {exit:h[h.length-1].close, resolved:false} : null;
}
function rOf(call, exit){
  const risk = Math.abs(call.entry-call.stop) || 1;
  const gross = call.side==='buy' ? exit-call.entry : call.entry-exit;
  return (gross - (call.entry+exit)*COST) / risk;
}

// Collect every trade once; tag with time so regimes are just filters.
const trades = [];
const universe = [];
for (const sym of SYMS){
  const c = load(sym); if (!c) continue;
  for (let i=24;i<c.length-1;i++){
    const s = signalAt(c.slice(0,i+1));
    if (!s || !s.action || !s.target || !s.stop) continue;
    if (s.target>s.price && s.stop<s.price) universe.push({sym,i,s,c});
    let side=null;
    if (s.action.type==='buy'  && s.score>=3)  side='buy';
    else if (s.action.type==='sell' && s.score<=-3) side='sell';
    if (!side) continue;
    if (side==='buy'  && !(s.target>s.price && s.stop<s.price)) continue;
    if (side==='sell' && !(s.target<s.price && s.stop>s.price)) continue;
    const call={sym,side,entry:s.price,target:s.target,stop:s.stop,t:c[i].time,score:s.score};
    const g=gradeExit(call,c.slice(i+1),HORIZON); if(!g) continue;
    call.r=rOf(call,g.exit); call.resolved=g.resolved;
    trades.push(call);
  }
}

function stats(ts){
  if(!ts.length) return null;
  const rs=ts.map(x=>x.r);
  const n=rs.length, mean=rs.reduce((a,b)=>a+b,0)/n;
  const sd=Math.sqrt(rs.reduce((a,b)=>a+(b-mean)**2,0)/Math.max(1,n-1));
  const se=sd/Math.sqrt(n);
  let peak=0,eq=0,dd=0;
  for(const r of rs){eq+=r; if(eq>peak)peak=eq; if(peak-eq>dd)dd=peak-eq;}
  return {n, wins:+(ts.filter(x=>x.r>0).length/n*100).toFixed(1),
    mean:+mean.toFixed(3), lo:+(mean-1.96*se).toFixed(3), hi:+(mean+1.96*se).toFixed(3),
    t:+(mean/(se||1e-9)).toFixed(2), totalR:+rs.reduce((a,b)=>a+b,0).toFixed(1),
    maxDD:+dd.toFixed(1), resolved:+(ts.filter(x=>x.resolved).length/n*100).toFixed(1)};
}
function line(label,s){
  if(!s) return console.log(`  ${label.padEnd(18)} no trades`);
  const sig = (s.lo>0) ? ' SIGNIFICANT>0' : (s.hi<0 ? ' SIGNIFICANT<0' : ' (CI crosses 0)');
  console.log(`  ${label.padEnd(18)} n=${String(s.n).padStart(4)} win=${String(s.wins).padStart(5)}% ` +
    `E=${String(s.mean).padStart(7)}R CI[${s.lo},${s.hi}] t=${String(s.t).padStart(6)} ` +
    `totalR=${String(s.totalR).padStart(7)} maxDD=${String(s.maxDD).padStart(6)}R res=${s.resolved}%${sig}`);
}

console.log(`HORIZON=${HORIZON} bars | daily candles | costs ${(COST*2*100).toFixed(2)}% round trip`);
console.log(`buys=${trades.filter(t=>t.side==='buy').length}  sells=${trades.filter(t=>t.side==='sell').length}`);

console.log('\n=== BY REGIME ===');
for(const [name,a,b] of REGIMES){
  line(name, stats(trades.filter(t=>t.t>=ms(a)&&t.t<=ms(b))));
}
console.log('\n=== OVERALL ===');
line('all trades', stats(trades));
line('buys only',  stats(trades.filter(t=>t.side==='buy')));

console.log('\n=== BY ASSET ===');
for(const sym of SYMS){ const s=stats(trades.filter(t=>t.sym===sym)); if(s) line(sym,s); }

// ---- random-entry control at full sample ----
const buys = trades.filter(t=>t.side==='buy');
if (buys.length && universe.length){
  const target = stats(buys).mean;
  const ITER=1000, means=[];
  for(let it=0;it<ITER;it++){
    let sum=0,k=0;
    for(let j=0;j<buys.length;j++){
      const u=universe[(Math.random()*universe.length)|0];
      const call={side:'buy',entry:u.s.price,target:u.s.target,stop:u.s.stop};
      const g=gradeExit(call,u.c.slice(u.i+1),HORIZON); if(!g) continue;
      sum+=rOf(call,g.exit); k++;
    }
    if(k) means.push(sum/k);
  }
  means.sort((a,b)=>a-b);
  const pct=q=>means[Math.floor(means.length*q)];
  const beat=means.filter(m=>m>=target).length/means.length;
  console.log('\n=== RANDOM-ENTRY CONTROL (identical exit geometry, n matched) ===');
  console.log(`  random: median=${pct(.5).toFixed(3)}R  5th=${pct(.05).toFixed(3)}R  95th=${pct(.95).toFixed(3)}R`);
  console.log(`  signal: ${target.toFixed(3)}R`);
  console.log(`  P(random >= signal) = ${(beat*100).toFixed(1)}%  =>  ` +
    (beat<0.05 ? 'signal BEATS random entry' : 'signal does NOT separate from random entry'));
}
