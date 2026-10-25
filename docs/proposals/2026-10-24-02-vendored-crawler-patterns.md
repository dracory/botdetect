# Proposal: vendor Crawler-Detect raw pattern data

Status: implemented
Date: 2026-10-24
Spikes: `docs/spikes/crawler-detect-php/README.md`,
`docs/spikes/crawlerdetect/README.md`

## Problem

Our hand-maintained UA lists (~100 patterns) can't keep pace with the
crawler ecosystem — they already drifted behind the AI-crawler explosion
once. Crawler-Detect upstream (2.4k stars, 1,001 commits, MIT) maintains
1000s of patterns as plain data files, and ports exist only to compile
them into a language runtime.

## Proposal

Vendor the data, not the code:

- `data/crawlers.json`, `data/exclusions.json`, `data/headers.json`
  embedded via `go:embed`
- `scripts/update-data.sh` pulls fresh copies from
  `JayBizzle/Crawler-Detect/raw/` (modeled on x-way's `update_data.sh`),
  paired with a `data_vendored_test.go` test that validates JSON parsing and
  regex compilation in `go test ./...`
- Compile the exclusion and crawler patterns into case-insensitive `(?i)`
  regex alternations at init
- **Exclusions pass first**: strip `exclusions.json` matches from the UA
  before crawler-pattern matching — the upstream FP-defense mechanism,
  required for correctness at this pattern count. If the stripped string is
  empty/whitespace (common for standard human browser UAs once browser/OS
  tokens are stripped), return `false` immediately without running the
  crawler regex
- Use `FindString` (not just `MatchString`) on the compiled crawler regex so
  the matched token can be surfaced as `Detection.Name` in Proposal 04
- Normalize `headers.json` entries at init: upstream stores PHP `$_SERVER`
  keys (`HTTP_USER_AGENT`, `HTTP_FROM`, `HTTP_X_ORIGINAL_USER_AGENT`,
  `HTTP_X_SCANNER`, etc.) whose *values* are scanned against crawler patterns
  (see Proposal 03). Strip the `HTTP_` prefix, convert `_` to `-`, and
  exclude `User-Agent` (already checked directly)
- MIT attribution in `data/` (`LICENSE` or `NOTICE`)

Detection order in `IsBot`: uasurfer `IsBot()` → our hand lists →
vendored patterns. Ours remain a separate high-precision pass — substring
matching catches things regexes express poorly, and the list encodes
dracory-specific knowledge (CVE probes, security scanners, AI crawlers).

## Impact

- Broad recall without new runtime dependencies.
- Pattern maintenance becomes a script run, not hand-editing.

## Performance & caching note

Short-circuit evaluation (`uasurfer` → hand lists → vendored regex) only
short-circuits when the verdict is `true` (bots). Every **human** browser
request (>90% of real traffic) evaluates to `false` in the first two passes
and therefore reaches the vendored regex pass.

To keep the middleware hot path fast:
1. Benchmark `IsBot` with a mix of real browser and bot UAs before merging.
2. Add a small, bounded, concurrency-safe cache (e.g. sharded ring/LRU of
   512–1024 entries keyed by UA string) in front of UA detection so repeated
   browser UAs resolve in ~30–50ns without re-running regexes.

## Open questions

- Vendored data goes stale like any list — decide whether a scheduled CI
  workflow opens a PR on upstream drift or refreshes stay manual.
