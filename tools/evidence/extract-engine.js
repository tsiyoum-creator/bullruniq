// Extracts the signal engine from platform.html at runtime.
//
// Deliberately NOT a copy. A frozen duplicate drifts from what ships, and then
// the backtest measures something the users never run. This parses the live
// file, walks the dependency closure from the entry points, and returns the
// real functions. If platform.html changes, the harness changes with it.
//
// Requires the functions to be top-level `function name(...)` declarations in
// the single inline <script>. If that stops being true this throws loudly
// rather than silently measuring the wrong thing.

const fs = require('fs');
const path = require('path');

const ENTRY_POINTS = ['tradeRead', 'calcBB', 'calcRSI', 'calcATR', '_oppScore', '_oppAction'];

function extractSource(htmlPath) {
  const html = fs.readFileSync(htmlPath, 'utf8');
  const blocks = html.match(/<script>([\s\S]*?)<\/script>/g) || [];
  if (!blocks.length) throw new Error('no inline <script> found in ' + htmlPath);
  // the app lives in the last (largest) inline block
  const src = blocks[blocks.length - 1].replace(/^<script>/, '').replace(/<\/script>$/, '');
  const lines = src.split('\n');

  const topLevel = {};
  lines.forEach((l, i) => {
    const m = /^function ([A-Za-z_][A-Za-z0-9_]*)\(/.exec(l);
    if (m) topLevel[m[1]] = i;
  });

  function grab(name) {
    const start = topLevel[name];
    if (start === undefined) throw new Error('function not found at top level: ' + name);
    let depth = 0;
    for (let i = start; i < lines.length; i++) {
      depth += (lines[i].match(/\{/g) || []).length;
      depth -= (lines[i].match(/\}/g) || []).length;
      if (depth === 0 && i >= start) return lines.slice(start, i + 1).join('\n');
    }
    throw new Error('unbalanced braces extracting ' + name);
  }

  // transitive closure
  const need = new Set(ENTRY_POINTS);
  const stack = [...ENTRY_POINTS];
  while (stack.length) {
    const n = stack.pop();
    if (!(n in topLevel)) continue;
    const body = grab(n);
    const called = new Set((body.match(/\b([A-Za-z_][A-Za-z0-9_]*)\s*\(/g) || [])
      .map(s => s.replace(/\s*\($/, '')));
    for (const c of called) {
      if (c in topLevel && !need.has(c)) { need.add(c); stack.push(c); }
    }
  }

  const ordered = [...need].sort((a, b) => topLevel[a] - topLevel[b]);
  const missing = ENTRY_POINTS.filter(e => !need.has(e));
  if (missing.length) throw new Error('entry points missing: ' + missing.join(', '));

  return { code: ordered.map(grab).join('\n\n'), names: ordered };
}

function loadEngine(htmlPath) {
  const p = htmlPath || path.join(__dirname, '..', '..', 'platform.html');
  const { code, names } = extractSource(p);
  const factory = new Function(code + '\nreturn {' + names.join(',') + '};');
  return factory();
}

module.exports = { loadEngine, extractSource, ENTRY_POINTS };

if (require.main === module) {
  const e = loadEngine();
  console.log('extracted ' + Object.keys(e).length + ' functions from platform.html:');
  console.log('  ' + Object.keys(e).join(', '));
}
