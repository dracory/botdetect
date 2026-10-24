# Spike: `github.com/JayBizzle/Crawler-Detect` (PHP upstream)

Date: 2026-10-24
Status: findings — decision pending

## What it is

The upstream source that `x-way/crawlerdetect` ports to Go. The most
battle-tested bot pattern list available: **2.4k stars, 281 forks, 1,001
commits**, MIT licensed, actively community-maintained.

## The key discovery: the data is standalone

`raw/` in the repo ships the pattern lists as **plain data, not code**:

- `Crawlers.txt` / `Crawlers.json` — the bot/crawler regex patterns
- `Exclusions.txt` / `Exclusions.json` — FP-defense patterns stripped from
  the UA before matching
- `Headers.txt` / `Headers.json` — bot-indicating HTTP **header names**
  (detection beyond User-Agent, e.g. `From:` which crawlers use for their
  contact address)

`export.php` regenerates the compiled PHP arrays from these raw files —
the `.txt`/`.json` are the source of truth.

## Why this matters for botdetect

We don't need the PHP port *or* the Go port — we can **consume the raw
data directly**:

1. `go:embed` a vendored copy of `Crawlers.json` + `Exclusions.json` +
   `Headers.json`, compile to a combined regex alternation at init.
2. An `update_data.sh`-style script (like the Go port's) fetches fresh
   copies from upstream on demand — pattern maintenance becomes a pull
   script instead of a dependency.
3. MIT license on data files — vendoring with attribution is clean.

This gives us the 1000s-of-patterns recall of the whole Crawler-Detect
ecosystem **with zero new dependencies** and no coupling to either port's
release cadence.

## The three-list model

| List | Role |
|---|---|
| Crawlers | regex → bot |
| Exclusions | strip-from-UA first (the FP defense) |
| Headers | non-UA header names that signal bots |

The Exclusions mechanism is the same one flagged in the `crawlerdetect`
spike — seeing it as raw data confirms it's the core design, not an
implementation detail. The Headers list is new information: `IsBot` could
gain a header-aware variant `IsBotRequest(r *http.Request)` that checks
UA + bot-typical headers.

## Caveats

- **Regex cost**: ~1000 patterns. The ports compile them into one big
  alternation — Go's `regexp` handles that fine, but a benchmark vs our
  current substring scan is warranted.
- **Patterns are tuned for recall**, matching against the whole UA. Some
  FP risk remains even with exclusions; our word-boundary logic is
  stricter per-pattern. Combined: run their list *after* exclusions, keep
  our specific list as a separate high-precision pass.
- Update drift: vendored data goes stale like our hand-maintained list —
  same problem, but the pull script makes refreshing trivial.

## Options

1. **Vendor the raw lists** (`data/` dir + embed + update script). Best
   recall-per-dependency ratio of anything surveyed so far.
2. **Depend on the Go port** — same data, less control, dep risk (72
   stars, slower sync than upstream).
3. **Stay hand-maintained** — highest precision, worst recall; our list
   already drifted behind the AI-crawler explosion once.

Recommendation: option 1 — vendor `Crawlers/Exclusions/Headers` JSON with
attribution and a pull script; layer it as a third signal in `IsBot`
alongside `ua.IsBot()` and our patterns.

## References

- https://github.com/JayBizzle/Crawler-Detect
- `raw/Crawlers.json`, `raw/Exclusions.json`, `raw/Headers.json`
- `export.php` (raw → compiled arrays)
