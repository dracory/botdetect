# Spike: `github.com/x-way/crawlerdetect` — regex UA bot lists

Date: 2026-10-24
Status: findings — decision pending

## What it is

A Go port of the PHP [`JayBizzle/Crawler-Detect`](https://github.com/JayBizzle/Crawler-Detect)
class — the most widely-used bot-detection list in the PHP world. Single
function surface:

```go
crawlerdetect.IsCrawler(uaString) bool
```

MIT licensed, 72 stars, 92 commits, stdlib-only (regexp). Claims
"1,000's of bots/spiders/crawlers".

## Architecture worth noting

- **`crawlers.go`** — a giant list of regex patterns, synced from the PHP
  upstream via `update_data.sh`. The community maintains the list upstream;
  the Go port is a thin consumer.
- **`exclusions.go`** — a second regex list applied *first*: matching
  portions are stripped from the UA before the crawler patterns run. This
  is the key FP-defense mechanism — e.g. strip known-good browser chrome
  phrases so a generic pattern like `bot` can't match inside them.
- **Header-based detection** (inherited from the PHP design): the original
  also inspects headers beyond User-Agent (`From`, `X-Requested-With`-era
  markers and similar bot-typical headers).
- Test corpus synced from upstream as well, so Go/PHP behavior stays
  aligned.

## How it compares

| | botdetect | crawlerdetect | uasurfer `IsBot` |
|---|---|---|---|
| UA coverage | ~100 hand-picked patterns | 1000s of regexes | heuristic + named fleet |
| FP defense | word-boundary rules | **exclusion-strip pass** | conventions-based |
| Maintenance | we own the list | upstream community | upstream heuristics |
| Beyond UA (paths, IP, referrer) | yes | no | no |
| Dependencies | uasurfer | none | none |

The pattern-count gap is real: our ~100 specific patterns vs their
maintained list of thousands. The exclusion-strip mechanism is the part
most worth copying — it's how a 1000-pattern list avoids FP chaos.

## Options

1. **Adopt `IsCrawler` as a third signal** in `IsBot` — i.e.
   `ua.IsBot() || crawlerdetect.IsCrawler(ua) || ourPatterns(ua)`. Cheapest
   way to close the coverage gap; +1 dep, MIT, zero transitive deps.
   Risk: regex-per-request cost (their list is large; the PHP original
   compiles into one alternation — worth a benchmark before adopting).
2. **Copy the mechanism, not the dep:** implement an exclusion-strip pass
   in `IsBot` (preprocess UA through an exclusion list before applying our
   patterns), letting us safely add broad patterns.
3. **Vendor just the pattern data** via their `update_data.sh` approach —
   sync `crawlers.go`'s regex list into our own table. License-fine (MIT)
   but we'd own update mechanics and the FP tuning.

Recommendation: option 1 behind a benchmark — if the regex list is
compiled once at init, the per-request cost is one alternation scan and
it's a strict recall win. Option 2's exclusion pass is worth adding
regardless.

## References

- https://github.com/x-way/crawlerdetect
- https://github.com/JayBizzle/Crawler-Detect (upstream pattern source)
