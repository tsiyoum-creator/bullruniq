/* ================================================================
   BullrunIQ — macro.js
   Regime & capital-flow awareness layer.

   Loaded BEFORE the inline script in platform.html. Everything here
   reads globals defined there (port, prices, pof, f$, totals, render)
   at CALL time, never at load time.

   Three views: regime · flows · expo   (registered in NAV_GROUPS)
   Plus buildMacroContext() for the AI and checkFalsifiers() for the brief.
   ================================================================ */

/* ================================================================
   ░░ REFRESHABLE DATA BLOCK — everything verifiable lives here ░░
   To refresh: ask Claude to re-verify MACRO_DATA and republish.
   Merging is automated: see .github/workflows/auto-merge-improvements.yml
   Every figure carries asOf + src. null means NO DATA — never guess.
   ================================================================ */
var MACRO_DATA = {
  asOf: "2026-09-20",

  current: {
    regime: "longend",
    confidence: 78,
    summary: "The 30-year sits at 5.36% and the 10-year touched 5.00%, the highest since July 2007. There is a buyers' strike in the 10–30y sector and Treasury has doubled buyback operations to $4bn+. The Fed hiked to 3.75–4.00%, its first increase since July 2023, and the dollar has reclaimed 100.",
    forBook: "Rising real yields plus a firming dollar is historically the worst combination for long-duration risk assets, crypto included. This is not the regime a debasement or liquidity thesis needs."
  },

  regimes: [
    { id:"longend", name:"Long-end disorder",
      d:"Term premium rising, the 30y repricing, a buyers' strike, Treasury intervening. A financing problem, not a growth problem.",
      enter:"30y above 5.25% with bear steepening while Treasury expands buybacks",
      exit:"30y sustainably below 5% without intervention, or a Fed pivot that re-anchors the curve",
      favours:"Cash and T-bills, very short duration, gold on a lag",
      punishes:"Long duration, levered risk, high-multiple equity, crypto" },
    { id:"liquidity", name:"Liquidity expansion",
      d:"Fed easing or expanding the balance sheet, net liquidity rising, dollar falling, real yields falling.",
      enter:"Fed cutting, net liquidity rising 8+ weeks, DXY below 97",
      exit:"Any resumption of tightening, or a TGA rebuild that drains reserves",
      favours:"Long-duration risk, crypto, growth equity, gold",
      punishes:"Cash, the dollar, defensives" },
    { id:"fiscdom", name:"Fiscal dominance",
      d:"Deficits force monetary accommodation. Real rates suppressed deliberately, curve steepens, hard assets bid.",
      enter:"Explicit curve control or sustained Fed buying with inflation above target",
      exit:"Credible fiscal consolidation, or a Fed reasserting the inflation mandate over funding costs",
      favours:"Gold, bitcoin, real assets, TIPS, equity over bonds",
      punishes:"Nominal long bonds, cash, the currency itself" },
    { id:"squeeze", name:"Dollar squeeze",
      d:"DXY spikes, offshore dollar funding tightens, cross-asset correlations converge to one.",
      enter:"DXY above 105 with widening cross-currency basis and rising SOFR",
      exit:"Swap lines deployed, or the Fed easing into the stress",
      favours:"The dollar, T-bills, volatility",
      punishes:"Emerging markets, commodities, crypto, anything levered" },
    { id:"deflation", name:"Deflationary shock",
      d:"Growth breaks, yields collapse, the Fed cuts hard into it. Painful first, then the setup for liquidity expansion.",
      enter:"ISM below 48 with negative payrolls and credit spreads widening sharply",
      exit:"The policy response lands, which transitions directly into liquidity expansion",
      favours:"Long Treasuries, quality duration, cash",
      punishes:"Crypto and cyclicals initially; they lead on the way out, not in" }
  ],

  /* thresholds[] drive checkFalsifiers(). op: 'gt' | 'lt' */
  indicators: [
    { k:"dxy",      n:"DXY",                 v:100.30, u:"",      asOf:"2026-09-20", src:"FXStreet",        op:"lt", th:97,   trips:"liquidity" },
    { k:"ust30",    n:"UST 30y",             v:5.36,   u:"%",     asOf:"2026-09-16", src:"US Treasury",     op:"gt", th:5.75, trips:"longend"   },
    { k:"ust10",    n:"UST 10y",             v:5.00,   u:"%",     asOf:"2026-09-16", src:"US Treasury",     op:"gt", th:5.25, trips:"longend"   },
    { k:"ust2",     n:"UST 2y",              v:4.67,   u:"%",     asOf:"2026-09-16", src:"US Treasury",     op:null, th:null, trips:null        },
    { k:"ffr",      n:"Fed funds target",    v:3.875,  u:"%",     asOf:"2026-09-17", src:"FOMC",            op:"gt", th:4.5,  trips:"longend"   },
    { k:"netliq",   n:"Net liquidity",       v:5857,   u:"bn",    asOf:"2026-09-09", src:"Fed H.4.1",       op:null, th:null, trips:null        },
    { k:"tga",      n:"Treasury General Acct", v:883,  u:"bn",    asOf:"2026-09-09", src:"Fed H.4.1",       op:null, th:null, trips:null        },
    { k:"rrp",      n:"Overnight RRP",       v:1,      u:"bn",    asOf:"2026-09-09", src:"Fed H.4.1",       op:null, th:null, trips:null        },
    { k:"gold",     n:"Gold",                v:4384.78,u:"/oz",   asOf:"2026-09-18", src:"Trading Economics", op:null, th:null, trips:null      },
    { k:"stables",  n:"Stablecoin supply",   v:310.95, u:"bn",    asOf:"2026-09-10", src:"DefiLlama",       op:"lt", th:280,  trips:"deflation" },
    { k:"cofer",    n:"COFER USD share",     v:57.13,  u:"%",     asOf:"2026-Q1",    src:"IMF COFER",       op:null, th:null, trips:null        },
    { k:"ism",      n:"ISM Manufacturing",   v:54.6,   u:"",      asOf:"2026-08",    src:"ISM",             op:"lt", th:48,   trips:"deflation" },
    { k:"btc",      n:"Bitcoin",             v:81000,  u:"",      asOf:"2026-09-20", src:"CoinDesk",        op:"lt", th:63000,trips:null        },
    { k:"termprem", n:"ACM term premium",    v:null,   u:"",      asOf:null,         src:"NY Fed",          op:null, th:null, trips:null        },
    { k:"real10",   n:"10y TIPS real",       v:null,   u:"%",     asOf:null,         src:"US Treasury",     op:null, th:null, trips:null        },
    { k:"move",     n:"MOVE index",          v:null,   u:"",      asOf:null,         src:"ICE",             op:null, th:null, trips:null        }
  ],

  /* Committed but not yet deployed. unalloc null = no data. */
  flows: [
    { id:"jp", n:"Japan Strategic Investment Fund", committed:550, unalloc:514, tier:4, tierL:"T-24m+",
      cert:"Contracted", dir:"in", asOf:"2026-09-05", src:"Japan Times / Nikkei",
      note:"First batch ≈$36bn into US oil, gas and minerals including an Ohio gas facility. Next phase is explicitly AI and semiconductors — a ¥2–3tn fab is under discussion. Projects are directed by the US president, so the pattern of picks is the signal." },
    { id:"kr", n:"Korea–US Strategic Investment Co.", committed:350, unalloc:350, tier:4, tierL:"T-24m+",
      cert:"Announced", dir:"in", asOf:"2026-09-18", src:"Korea Herald / Bloomberg",
      note:"$150bn earmarked for shipbuilding; $200bn unassigned. Delayed and being renegotiated over a 'commercial reasonableness' clause on loss allocation. Zero named projects means zero priced in." },
    { id:"hs", n:"Hyperscaler capex 2027", committed:934, unalloc:934, tier:3, tierL:"T-6/12m",
      cert:"Guided", dir:"in", asOf:"2026-09", src:"Company guidance / consensus",
      note:"Consensus $934.5bn: Google $284.8bn, Amazon $256.5bn, Microsoft $207.6bn, Meta $185.6bn. 2026 is $725bn, up 77% from $410bn. The largest private flow tracked, and it sets every bottleneck." },
    { id:"pe", n:"Private capital dry powder", committed:3900, unalloc:2500, tier:3, tierL:"T-6/12m",
      cert:"Contracted", dir:"in", asOf:"2026-01", src:"Bain / industry",
      note:"$3.7tn PE alone entering 2026, ~$3.9tn across all private capital. Over $2.5tn still uncalled, ~$1.0tn US. LP commitments are contractual but deployment timing is discretionary." },
    { id:"iija", n:"IIJA remaining authority", committed:496, unalloc:282, tier:1, tierL:"T-0",
      cert:"Legislated", dir:"out", asOf:"2026-01-31", src:"US DOT / GAO",
      note:"$496.1bn enacted, $360.3bn obligated (72.6%), only $213.7bn outlaid (43.1%). Authority EXPIRES 2026-09-30. A flow switching off — most trackers only look for inflows." }
  ],

  bottlenecks: [
    { id:"xfmr", n:"Large power transformers", bind:5, crowd:2, crowdL:"Building",
      d:"128-week average lead times, 144 for generator step-ups, up to 60 months for extra-high-voltage. US makes only ~20% of its own need. The binding constraint is a ~15,000-person hand coil-winding workforce — labour, not capital. A capex-relievable shortage clears in 24–36 months; a skilled-labour one does not.",
      asOf:"2026", src:"Wood Mackenzie, PwC" },
    { id:"turb", n:"Gas turbines", bind:4, crowd:4, crowdL:"Crowded",
      d:"Lead times stretched from 2–3 to 5–7 years; GE Vernova sold into 2029–30 with ~100GW backlog. But all three makers are expanding output 25–35% annually from 2026. A constraint with three owners and an announced capacity response has a decay date.",
      asOf:"2026", src:"GE Vernova 8-K, Utility Dive" },
    { id:"intc", n:"Load-side interconnection", bind:5, crowd:2, crowdL:"Building",
      d:"ERCOT took 198GW of large-load applications in Q1 2026 alone, 86GW under review — roughly its entire peak load. PJM cleared its generation queue but faces a 15GW capacity shortfall by 2030. The constraint moved from connecting generators to connecting consumers.",
      asOf:"2026", src:"PJM, Ascend Analytics, LBNL" }
  ],

  catalysts: [
    { d:"2026-09-30", n:"IIJA authority expires",        tests:"IIJA cliff" },
    { d:"2026-10-28", n:"FOMC decision",                 tests:"Regime — one hike or a cycle" },
    { d:"2026-11-02", n:"Quarterly refunding statement", tests:"Long-end financing; watch the duration mix" },
    { d:"2026-11-04", n:"Buyback authority lapses",      tests:"Whether the buyers' strike cleared" },
    { d:"2026-12-09", n:"FOMC + dot plot",               tests:"Terminal rate. Above 4.5% forecloses the liquidity case" },
    { d:"2027-02-01", n:"Section 301 litigation window", tests:"Tariff authority durability" }
  ]
};

/* ================================================================
   ░░ END REFRESHABLE DATA BLOCK ░░
   ================================================================ */

/* Ticker → what it is actually a bet on. Unknown tickers are NOT guessed;
   they render as "untagged" and the user tags them. Overrides persist. */
var MACRO_TAGS = {
  BTC:{r:"liquidity", f:null,  b:null,   w:"Long-duration liquidity proxy. Needs falling real yields and a falling dollar."},
  ETH:{r:"liquidity", f:null,  b:null,   w:"Same driver as BTC with higher beta and weaker relative flows this cycle."},
  SOL:{r:"liquidity", f:null,  b:null,   w:"High-beta liquidity bet. Amplifies both directions of the regime."},
  ONDO:{r:"fiscdom", f:null,   b:null,   w:"Tokenised Treasuries. Structurally bid by the same stablecoin channel in the flow ledger."},
  GEV:{r:"fiscdom",  f:"hs",   b:"turb", w:"Direct hyperscaler capex exposure via turbines. Binding now, but crowded and easing from 2028–29."},
  ETN:{r:"fiscdom",  f:"hs",   b:"xfmr", w:"Electrical equipment. Upstream of the grid-equipment constraint."},
  PWR:{r:"fiscdom",  f:"hs",   b:"intc", w:"Grid construction labour — downstream of interconnection, upstream of nothing that can substitute."},
  VRT:{r:"fiscdom",  f:"hs",   b:"intc", w:"Datacentre cooling and power. Rides capex directly."},
  NVDA:{r:"liquidity",f:"hs",  b:null,   w:"The demand source for the capex, not a beneficiary of the bottleneck."},
  MSFT:{r:"liquidity",f:"hs",  b:null,   w:"Spender, not receiver. Capex is a cost line here."},
  GOOGL:{r:"liquidity",f:"hs", b:null,   w:"Spender, not receiver."},
  AMZN:{r:"liquidity",f:"hs",  b:null,   w:"Spender, not receiver."},
  META:{r:"liquidity",f:"hs",  b:null,   w:"Spender, not receiver."},
  AAPL:{r:"liquidity",f:null,  b:null,   w:"Broad duration / consumer. Not a flow or bottleneck play."},
  GLD:{r:"fiscdom",  f:null,   b:null,   w:"Debasement hedge. Central banks bought 863t in 2025."},
  TLT:{r:"deflation",f:null,   b:null,   w:"Long duration. Directly punished by the regime currently in force."}
};
var MTAGK='briq-macrotags';
var macroTags={};
function loadMacroTags(){try{var x=localStorage.getItem(MTAGK);if(x)macroTags=JSON.parse(x);}catch(e){}}
function saveMacroTags(){try{localStorage.setItem(MTAGK,JSON.stringify(macroTags));}catch(e){}}
function tagFor(tk){
  tk=(tk||'').toUpperCase();
  return macroTags[tk]||MACRO_TAGS[tk]||null;
}
function setTag(tk,rid){
  tk=(tk||'').toUpperCase();
  if(!rid){delete macroTags[tk];}
  else{var base=MACRO_TAGS[tk]||{f:null,b:null,w:'Tagged manually.'};macroTags[tk]={r:rid,f:base.f,b:base.b,w:base.w};}
  saveMacroTags();if(typeof render==='function')render();
}
function regimeName(id){var r=MACRO_DATA.regimes.find(function(x){return x.id===id;});return r?r.name:'—';}
function regimeById(id){return MACRO_DATA.regimes.find(function(x){return x.id===id;})||null;}

/* ── Cash helpers ───────────────────────────────────────────────
   port.cash is a SCALAR dollar amount (set via setCash() in
   platform.html and used by Autopilot, cashCard and rAlloc). This
   layer reads it, it does not reshape it.
   port.cashApy is an optional scalar added alongside it so the
   exposure map can say what cash actually earns. Absent → 0, and
   the yield claim is suppressed rather than guessed at.           */
function cashTotal(){return (typeof port!=='undefined'&&parseFloat(port.cash))||0;}
function cashYield(){return (typeof port!=='undefined'&&parseFloat(port.cashApy))||0;}
function hasCashApy(){return cashYield()>0;}

/* ================================================================
   EXPOSURE MAP — the point of the whole layer
   ================================================================ */
function buildExposure(){
  var rows=[],untagged=[];
  all().forEach(function(h){
    var val=pof(h)*h.qty; if(!val)return;
    var t=tagFor(h.ticker);
    if(t)rows.push({ticker:h.ticker,name:h.name,val:val,r:t.r,f:t.f,b:t.b,w:t.w,kind:'pos'});
    else {rows.push({ticker:h.ticker,name:h.name,val:val,r:null,f:null,b:null,w:null,kind:'pos'});untagged.push(h.ticker);}
  });
  var ct=cashTotal();
  if(ct>0){
    rows.push({ticker:'CASH',name:'Cash & equivalents',val:ct,r:'longend',f:null,b:null,kind:'cash',
      w:'Cash is a position, not a residual. '+(hasCashApy()
          ? 'At '+cashYield().toFixed(2)+'% it is paid to wait, and it is what the regime currently in force favours.'
          : 'It is what the regime currently in force favours. Set an APY on the Holdings tab to see what it earns — no rate is assumed.')});
  }
  var tv=rows.reduce(function(s,r){return s+r.val;},0);
  var byRegime={};
  rows.forEach(function(r){if(!r.r)return;byRegime[r.r]=(byRegime[r.r]||0)+r.val;});
  var untaggedVal=rows.filter(function(r){return !r.r;}).reduce(function(s,r){return s+r.val;},0);
  var buckets=Object.keys(byRegime).map(function(k){
    return {id:k,name:regimeName(k),val:byRegime[k],pct:tv?byRegime[k]/tv*100:0};
  }).sort(function(a,b){return b.val-a.val;});
  var cur=MACRO_DATA.current.regime;
  var aligned=byRegime[cur]||0;
  var against=rows.filter(function(r){return r.r&&r.r!==cur;});
  return {rows:rows,tv:tv,buckets:buckets,untagged:untagged,untaggedVal:untaggedVal,
          cur:cur,alignedVal:aligned,alignedPct:tv?aligned/tv*100:0,against:against,cashVal:ct};
}

/* ================================================================
   FALSIFIER WATCH — normal output is "nothing changed"
   ================================================================ */
function checkFalsifiers(){
  var trips=[];
  MACRO_DATA.indicators.forEach(function(i){
    if(i.v===null||!i.op||i.th===null)return;
    var hit=(i.op==='gt'&&i.v>i.th)||(i.op==='lt'&&i.v<i.th);
    if(hit)trips.push({n:i.n,v:i.v,u:i.u,op:i.op,th:i.th,trips:i.trips,asOf:i.asOf});
  });
  var soon=[],now=new Date(MACRO_DATA.asOf).getTime();
  MACRO_DATA.catalysts.forEach(function(c){
    var d=new Date(c.d).getTime(),days=Math.round((d-now)/86400000);
    if(days>=0&&days<=21)soon.push({n:c.n,d:c.d,days:days,tests:c.tests});
  });
  return {trips:trips,soon:soon,clean:trips.length===0};
}

/* ================================================================
   VIEWS — reuse platform.html classes: card / sc / g2-g4 / sh gold
   ================================================================ */
function _mBar(fill,max,hot){
  var h='<span style="display:inline-flex;gap:2px;vertical-align:-1px">';
  for(var i=0;i<max;i++){
    h+='<i style="width:8px;height:10px;display:block;background:'+(i<fill?(hot?'var(--red)':'var(--gold)'):'var(--b3)')+'"></i>';
  }
  return h+'</span>';
}
function _stale(asOf){return '<span style="color:var(--t3);font-size:10px">'+(asOf||'no date')+'</span>';}

function rRegime(){
  var c=MACRO_DATA.current,cr=regimeById(c.regime);
  var h='<div class="card" style="border:1px solid var(--o2);margin-bottom:12px">';
  h+='<div style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:1.5px;margin-bottom:6px">Regime in force · as of '+MACRO_DATA.asOf+'</div>';
  h+='<div style="font-size:20px;font-weight:700;color:var(--ora);margin-bottom:8px">'+(cr?cr.name:'—')+'</div>';
  h+='<div style="font-size:12px;color:var(--t2);line-height:1.65;margin-bottom:10px">'+c.summary+'</div>';
  h+='<div style="font-size:12px;color:var(--t);line-height:1.65;padding-left:10px;border-left:2px solid var(--ora)">'+c.forBook+'</div>';
  h+='<div style="display:flex;align-items:center;gap:10px;margin-top:12px"><span style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:1px">Confidence</span>';
  h+='<span style="flex:1;max-width:150px;height:5px;background:var(--s2);border-radius:3px;overflow:hidden;display:inline-block"><span style="display:block;height:100%;width:'+c.confidence+'%;background:var(--ora)"></span></span>';
  h+='<span class="mono" style="font-size:11px;color:var(--t2)">'+c.confidence+'%</span></div></div>';

  h+='<div class="sh gold">Indicators</div><div class="card">';
  h+='<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;min-width:460px">';
  h+='<tr style="font-size:9px;color:var(--t3);text-transform:uppercase;letter-spacing:1px"><td style="padding:4px 6px">Indicator</td><td style="padding:4px 6px;text-align:right">Value</td><td style="padding:4px 6px">Threshold</td><td style="padding:4px 6px">As of</td><td style="padding:4px 6px">Source</td></tr>';
  MACRO_DATA.indicators.forEach(function(i){
    var val = i.v===null ? '<span style="color:var(--t3);font-style:italic">no data</span>'
            : '<span class="mono" style="color:var(--t)">'+i.v.toLocaleString('en-US')+i.u+'</span>';
    var th = i.th===null ? '<span style="color:var(--t3)">—</span>'
           : '<span style="color:var(--t2);font-size:10px">'+(i.op==='gt'?'>':'<')+' '+i.th+i.u+'</span>';
    h+='<tr style="border-top:1px solid var(--b1)"><td style="padding:6px">'+i.n+'</td><td style="padding:6px;text-align:right">'+val+'</td><td style="padding:6px">'+th+'</td><td style="padding:6px">'+_stale(i.asOf)+'</td><td style="padding:6px"><span style="font-size:10px;color:var(--t3)">'+i.src+'</span></td></tr>';
  });
  h+='</table></div></div>';

  h+='<div class="sh gold">All regimes &amp; transition triggers</div>';
  MACRO_DATA.regimes.forEach(function(r){
    var on=r.id===c.regime;
    h+='<div class="card" style="'+(on?'border:1px solid var(--o2);background:var(--o8)':'')+'">';
    h+='<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px"><span style="font-size:13px;font-weight:600">'+r.name+'</span>';
    if(on)h+='<span style="font-size:9px;background:var(--ora);color:#000;padding:2px 6px;border-radius:3px;letter-spacing:1px;font-weight:700">NOW</span>';
    h+='</div><div style="font-size:11px;color:var(--t2);line-height:1.6;margin-bottom:8px">'+r.d+'</div>';
    h+='<div style="font-size:10px;line-height:1.7"><div><span style="color:var(--t3);text-transform:uppercase;letter-spacing:1px">Enters</span> <span style="color:var(--t2)">'+r.enter+'</span></div>';
    h+='<div><span style="color:var(--t3);text-transform:uppercase;letter-spacing:1px">Exits</span> <span style="color:var(--t2)">'+r.exit+'</span></div>';
    h+='<div><span style="color:var(--t3);text-transform:uppercase;letter-spacing:1px">Favours</span> <span style="color:var(--grn)">'+r.favours+'</span></div>';
    h+='<div><span style="color:var(--t3);text-transform:uppercase;letter-spacing:1px">Punishes</span> <span style="color:var(--red)">'+r.punishes+'</span></div></div></div>';
  });
  return h;
}

function rFlows(){
  var h='<div class="sh gold">Committed, not yet deployed</div>';
  h+='<div class="card"><div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;min-width:620px">';
  h+='<tr style="font-size:9px;color:var(--t3);text-transform:uppercase;letter-spacing:1px"><td style="padding:4px 6px">Pool</td><td style="padding:4px 6px;text-align:right">Committed</td><td style="padding:4px 6px;text-align:right">Unallocated</td><td style="padding:4px 6px">Lead tier</td><td style="padding:4px 6px">Certainty</td></tr>';
  MACRO_DATA.flows.forEach(function(f){
    var col=f.dir==='out'?'var(--red)':'var(--gold)';
    var un=f.unalloc===null?'<span style="color:var(--t3);font-style:italic">no data</span>'
      :'<span class="mono" style="color:'+col+';font-weight:600">$'+(f.unalloc>=1000?(f.unalloc/1000).toFixed(1)+'tn':f.unalloc+'bn')+'</span>';
    h+='<tr style="border-top:1px solid var(--b1)"><td style="padding:7px 6px"><div style="font-weight:600;font-size:12px">'+f.n+'</div><div style="font-size:10px;color:var(--t3)">'+f.src+' · '+f.asOf+'</div></td>';
    h+='<td style="padding:7px 6px;text-align:right"><span class="mono">$'+(f.committed>=1000?(f.committed/1000).toFixed(1)+'tn':f.committed+'bn')+'</span></td>';
    h+='<td style="padding:7px 6px;text-align:right">'+un+'</td>';
    h+='<td style="padding:7px 6px">'+_mBar(f.tier,4,f.tier===1)+' <span style="font-size:10px;color:var(--t2)">'+f.tierL+'</span></td>';
    h+='<td style="padding:7px 6px"><span style="font-size:10px;color:var(--t2)">'+f.cert+'</span></td></tr>';
    h+='<tr><td colspan="5" style="padding:0 6px 9px;font-size:11px;color:var(--t2);line-height:1.6">'+f.note+'</td></tr>';
  });
  h+='</table></div></div>';

  h+='<div class="sh gold">Bottlenecks — where the money actually lands</div>';
  MACRO_DATA.bottlenecks.forEach(function(b){
    h+='<div class="card"><div style="font-size:13px;font-weight:600;margin-bottom:6px">'+b.n+'</div>';
    h+='<div style="font-size:11px;color:var(--t2);line-height:1.65;margin-bottom:10px">'+b.d+'</div>';
    h+='<div style="display:flex;gap:20px;flex-wrap:wrap;font-size:10px">';
    h+='<span><span style="color:var(--t3);text-transform:uppercase;letter-spacing:1px">Binding</span> '+_mBar(b.bind,5,false)+'</span>';
    h+='<span><span style="color:var(--t3);text-transform:uppercase;letter-spacing:1px">Crowding</span> '+_mBar(b.crowd,4,b.crowd>=3)+' <span style="color:var(--t2)">'+b.crowdL+'</span></span>';
    h+='<span style="color:var(--t3)">'+b.src+' · '+b.asOf+'</span></div></div>';
  });

  h+='<div class="sh gold">Dated catalysts</div><div class="card">';
  var now=new Date(MACRO_DATA.asOf).getTime();
  MACRO_DATA.catalysts.forEach(function(c){
    var days=Math.round((new Date(c.d).getTime()-now)/86400000);
    var urgent=days>=0&&days<=14;
    h+='<div style="display:flex;gap:12px;align-items:baseline;padding:7px 0;border-bottom:1px solid var(--b1)">';
    h+='<span class="mono" style="font-size:11px;color:'+(urgent?'var(--red)':'var(--gold)')+';min-width:82px">'+c.d+'</span>';
    h+='<span style="font-size:12px;flex:1">'+c.n+(urgent?' <span style="color:var(--red);font-size:10px">· '+days+'d</span>':'')+'<div style="font-size:10px;color:var(--t3);margin-top:2px">'+c.tests+'</div></span></div>';
  });
  return h+'</div>';
}

function rExpo(){
  var e=buildExposure();
  if(!e.tv)return '<div class="empty">Add holdings or cash to see what your book is actually betting on.</div>';
  var curName=regimeName(e.cur);
  var top=e.buckets[0];

  var h='';
  /* headline */
  var mismatch = top && top.id!==e.cur;
  h+='<div class="card" style="border:1px solid '+(mismatch?'var(--r2)':'var(--gn2)')+';margin-bottom:12px">';
  h+='<div style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:1.5px;margin-bottom:8px">What your book is actually betting on</div>';
  if(top){
    h+='<div style="font-size:15px;line-height:1.6;color:var(--t);margin-bottom:8px"><b style="color:'+(mismatch?'var(--red)':'var(--grn)')+'">'+top.pct.toFixed(0)+'% of your book is a bet on '+top.name+'.</b> The regime in force is <b>'+curName+'</b>.</div>';
  }
  if(mismatch){
    h+='<div style="font-size:12px;color:var(--t2);line-height:1.65">Your largest exposure is positioned for a regime that is not currently running. That is not automatically wrong — being early is what this whole framework is for — but it should be deliberate rather than inherited. '+MACRO_DATA.current.forBook+'</div>';
  } else {
    h+='<div style="font-size:12px;color:var(--t2);line-height:1.65">Your largest exposure matches the regime in force. The risk in this configuration is the transition, not the present: check the exit trigger on the Regime tab.</div>';
  }
  h+='</div>';

  /* aligned / against / cash */
  h+='<div class="g3" style="margin-bottom:12px">';
  h+='<div class="sc"><div class="sc-n" style="color:var(--grn)">'+e.alignedPct.toFixed(0)+'%</div><div class="sc-l">With the regime</div></div>';
  var againstVal=e.against.reduce(function(s,r){return s+r.val;},0);
  h+='<div class="sc"><div class="sc-n" style="color:var(--red)">'+(e.tv?(againstVal/e.tv*100).toFixed(0):0)+'%</div><div class="sc-l">Against it</div></div>';
  h+='<div class="sc"><div class="sc-n" style="color:var(--gold)">'+(e.tv?(e.cashVal/e.tv*100).toFixed(0):0)+'%</div><div class="sc-l">Cash'+(hasCashApy()?' @ '+cashYield().toFixed(2)+'%':'')+'</div></div>';
  h+='</div>';

  /* regime buckets */
  h+='<div class="sh gold">Exposure by regime bet</div><div class="card">';
  e.buckets.forEach(function(b){
    var on=b.id===e.cur;
    h+='<div style="margin-bottom:9px"><div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:3px">';
    h+='<span style="color:var(--t)">'+b.name+(on?' <span style="color:var(--ora);font-size:9px;letter-spacing:1px">· IN FORCE</span>':'')+'</span>';
    h+='<span style="color:var(--t2)">'+b.pct.toFixed(1)+'% · '+f$(b.val)+'</span></div>';
    h+='<div style="height:6px;background:var(--s2);border-radius:3px;overflow:hidden"><div style="height:100%;width:'+b.pct+'%;background:'+(on?'var(--ora)':'var(--blue)')+';border-radius:3px"></div></div></div>';
  });
  if(e.untaggedVal>0){
    h+='<div style="margin-top:10px;padding-top:9px;border-top:1px solid var(--b1);font-size:11px;color:var(--t3)">'+f$(e.untaggedVal)+' ('+(e.untaggedVal/e.tv*100).toFixed(0)+'%) untagged — tag it below so it counts. Untagged value is excluded from the percentages above rather than guessed at.</div>';
  }
  h+='</div>';

  /* per position */
  var opts=MACRO_DATA.regimes.map(function(r){return r;});
  h+='<div class="sh gold">Position by position</div><div class="card"><div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;min-width:640px">';
  h+='<tr style="font-size:9px;color:var(--t3);text-transform:uppercase;letter-spacing:1px"><td style="padding:4px 6px">Position</td><td style="padding:4px 6px;text-align:right">Value</td><td style="padding:4px 6px">Regime bet</td><td style="padding:4px 6px">Flow / bottleneck</td><td style="padding:4px 6px">Read</td></tr>';
  e.rows.sort(function(a,b){return b.val-a.val;}).forEach(function(r){
    var flow=r.f?(MACRO_DATA.flows.find(function(f){return f.id===r.f;})||{}).n:null;
    var bn=r.b?(MACRO_DATA.bottlenecks.find(function(b){return b.id===r.b;})||{}).n:null;
    h+='<tr style="border-top:1px solid var(--b1)">';
    h+='<td style="padding:7px 6px"><b style="font-size:12px">'+r.ticker+'</b><div style="font-size:10px;color:var(--t3)">'+(r.name||'')+'</div></td>';
    h+='<td style="padding:7px 6px;text-align:right" class="mono">'+f$(r.val)+'</td>';
    h+='<td style="padding:7px 6px">';
    if(r.kind==='cash'){h+='<span style="font-size:11px;color:var(--gold)">'+regimeName(r.r)+'</span>';}
    else{
      h+='<select onchange="setTag(\''+r.ticker+'\',this.value)" style="background:var(--s2);border:1px solid var(--b2);color:var(--t);font-size:10px;padding:3px 5px;border-radius:3px;font-family:inherit">';
      h+='<option value=""'+(r.r?'':' selected')+'>— untagged</option>';
      opts.forEach(function(o){h+='<option value="'+o.id+'"'+(r.r===o.id?' selected':'')+'>'+o.name+'</option>';});
      h+='</select>';
    }
    h+='</td>';
    h+='<td style="padding:7px 6px;font-size:10px;color:var(--t2)">'+(flow?flow:'<span style="color:var(--t3)">—</span>')+(bn?'<div style="color:var(--t3);margin-top:2px">'+bn+'</div>':'')+'</td>';
    h+='<td style="padding:7px 6px;font-size:11px;color:var(--t2);line-height:1.55;max-width:300px">'+(r.w||'<span style="color:var(--t3);font-style:italic">Untagged — no read. Pick a regime to classify it.</span>')+'</td></tr>';
  });
  h+='</table></div></div>';

  /* falsifier watch */
  var fw=checkFalsifiers();
  h+='<div class="sh gold">Falsifier watch</div><div class="card">';
  if(fw.clean){
    h+='<div style="font-size:13px;color:var(--grn);margin-bottom:6px">✓ Nothing material changed</div>';
    h+='<div style="font-size:11px;color:var(--t2);line-height:1.6">No regime trigger fired and no threshold crossed. This is the normal and correct output most days — a tool that finds something actionable every morning is manufacturing activity, not finding it.</div>';
  } else {
    h+='<div style="font-size:13px;color:var(--red);margin-bottom:8px">'+fw.trips.length+' threshold'+(fw.trips.length>1?'s':'')+' crossed</div>';
    fw.trips.forEach(function(t){
      h+='<div style="font-size:11px;color:var(--t2);line-height:1.6;margin-bottom:5px">• <b style="color:var(--t)">'+t.n+'</b> at '+t.v+t.u+' is '+(t.op==='gt'?'above':'below')+' your '+t.th+t.u+' threshold'+(t.trips?' — points toward <b>'+regimeName(t.trips)+'</b>':'')+'. <span style="color:var(--t3)">('+t.asOf+')</span></div>';
    });
  }
  if(fw.soon.length){
    h+='<div style="margin-top:10px;padding-top:9px;border-top:1px solid var(--b1)">';
    h+='<div style="font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Inside 21 days</div>';
    fw.soon.forEach(function(s){
      h+='<div style="font-size:11px;color:var(--t2);margin-bottom:4px"><span class="mono" style="color:var(--red)">'+s.days+'d</span> · '+s.n+' <span style="color:var(--t3)">— '+s.tests+'</span></div>';
    });
    h+='</div>';
  }
  h+='</div>';

  h+='<div class="card" style="border:1px solid var(--b2);font-size:10px;color:var(--t3);line-height:1.65">Research aid, not advice. This maps your holdings onto a macro framework so you can see what you are implicitly betting on. It issues no buy or sell instruction and does not know your horizon or risk tolerance. Figures come from the refreshable block in macro.js — ask Claude to re-verify them.</div>';
  return h;
}

/* ================================================================
   AI CONTEXT — real values only, explicit no-data instruction
   ================================================================ */
function buildMacroContext(){
  var e=buildExposure(),fw=checkFalsifiers();
  var ind={};MACRO_DATA.indicators.forEach(function(i){if(i.v!==null)ind[i.k]={v:i.v,u:i.u,asOf:i.asOf};});
  var missing=MACRO_DATA.indicators.filter(function(i){return i.v===null;}).map(function(i){return i.k;});
  return {
    asOf:MACRO_DATA.asOf,
    regimeInForce:regimeName(MACRO_DATA.current.regime),
    regimeConfidence:MACRO_DATA.current.confidence,
    regimeEvidence:MACRO_DATA.current.summary,
    indicators:ind,
    noDataFor:missing,
    flowsUnallocatedBn:MACRO_DATA.flows.map(function(f){return {name:f.n,unalloc:f.unalloc,tier:f.tierL,dir:f.dir};}),
    bottlenecks:MACRO_DATA.bottlenecks.map(function(b){return {name:b.n,binding:b.bind,crowding:b.crowdL};}),
    exposureByRegime:e.buckets.map(function(b){return {regime:b.name,pct:+b.pct.toFixed(1)};}),
    pctAlignedWithRegime:+e.alignedPct.toFixed(1),
    cashPct:e.tv?+((e.cashVal/e.tv)*100).toFixed(1):0,
    cashApy: hasCashApy() ? +cashYield().toFixed(2) : null,
    untaggedPct:e.tv?+((e.untaggedVal/e.tv)*100).toFixed(1):0,
    thresholdsCrossed:fw.trips.map(function(t){return t.n;}),
    catalystsWithin21d:fw.soon.map(function(s){return s.n+' ('+s.d+')';})
  };
}
var MACRO_AI_RULE=' You are given a macro regime read and an exposure map computed from the user\'s real holdings. Use these figures directly. If a value you need appears in noDataFor or is absent, say "insufficient data" for that point — never estimate or invent a number. Do not issue buy or sell instructions.';

loadMacroTags();

/* ── Node interop ──────────────────────────────────────────────
   Netlify functions require() this same file so the regime data has
   exactly ONE source of truth. Everything above is browser-safe:
   the only top-level call is loadMacroTags(), whose localStorage
   access is inside try/catch, so it no-ops under Node.
   Exposure/render functions are NOT exported — they need browser
   globals (port, pof, f$) that do not exist server-side.          */
if (typeof module !== "undefined" && module.exports) {
  module.exports = { MACRO_DATA: MACRO_DATA, checkFalsifiers: checkFalsifiers, regimeName: regimeName };
}
