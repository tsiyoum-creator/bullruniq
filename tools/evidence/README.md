# Evidence harness

Measures whether a signal source has an edge, before it is allowed to tell
anyone what to do.

```bash
npm run evidence            # run the backtest on committed candles
npm run evidence:fetch      # refresh candles from Coinbase (free, no key)
node tools/evidence/extract-engine.js   # show what it extracted
```

## How it works

`extract-engine.js` pulls the signal functions **out of `platform.html` at
runtime** and walks their dependency closure. It is deliberately not a copy — a
frozen duplicate drifts from what ships, and then the backtest measures code
nobody runs. Change `platform.html` and the harness changes with it, or it
throws.

`backtest.js` replays the engine walk-forward: at each bar it sees only bars up
to that point. Entries, targets and stops are constructed exactly as
`runOpps()` does. Grading mirrors `gradeCalls()`, including its conservative
rule that a bar touching both target and stop counts as a **loss**. Fees
(0.10%) and slippage (0.05%) are applied to both sides.

Results are reported per regime, per asset, and overall, each with a 95%
confidence interval. A point estimate without an interval is not a result.

## The random-entry control

The most important number the harness produces.

The same target/stop geometry is fired on **random bars** instead of signal
bars, resampled 1000×. A 2:1 target/stop produces a hit rate on its own, in any
market. If the signal cannot beat random entry with identical exits, the
apparent edge belongs to the exit geometry and the signal is decoration.

## Phase 0 result — 2026-09-19

Engine as shipped, 12 assets, daily candles, 2021-09 → 2026-09.

```
n=606 trades   expectancy = +0.001R   95% CI [-0.075, +0.077]   t = 0.03
```

**No edge.** Not a weak edge — zero, with an interval now tight enough
(±0.076R at n=606) that this is no longer an underpowered result.

| Regime | n | expectancy | significant? |
|---|---|---|---|
| 2022 bear | 142 | +0.078R | no, CI crosses 0 |
| 2023 recovery | 136 | −0.044R | no |
| 2024 bull | 112 | +0.009R | no |
| 2025–26 decline | 216 | −0.025R | no |

Random-entry control: `P(random >= signal) = 6.1%` → does not separate.

### Three structural findings

1. **The 72h expiry is shorter than one candle.** The app fetches 180-day OHLC,
   which CoinGecko serves as 4-day candles, so technicals run on ~45 bars and a
   call is graded on roughly one. A 2×ATR target cannot resolve in that window.
   At 4-day resolution only ~13% of calls ever hit target or stop; the rest
   expire.

2. **The sell side has never fired.** Zero sell signals across 606 signals, 12
   assets, five years — including a 2022 bear market and the 2025–26 decline.
   The sell half exists in code, not in practice.

3. **Small samples lie.** The first cut of this measurement used 31 trades on
   two assets and showed +0.205R, which looked like an edge worth building on.
   At n=606 it is +0.001R. Nothing below ~200 trades should be believed.

### Consequence

The scoring engine (`_oppScore` + `tradeRead` blend) must not be carried into a
rewrite as if it were validated. It is not.

## The rule this exists to enforce

No signal source ships to the UI without a measurement here, reported as:

    hit rate · expectancy in R · sample size · max drawdown · period tested
    · 95% CI · result of the random-entry control

A source whose CI crosses zero renders as **UNPROVEN** and is excluded from any
recommendation. That includes the one currently shipping.
