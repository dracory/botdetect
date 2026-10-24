# Proposal: vendor Crawler-Detect raw pattern data

Status: proposed
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
  `JayBizzle/Crawler-Detect/raw/` (modeled on x-way's `update_data.sh`)
- Compile the crawler patterns into a single regex alternation at init
- **Exclusions pass first**: strip exclusion matches from the UA before
  crawler-pattern matching — the upstream FP-defense mechanism, required
  for correctness at this pattern count
- MIT attribution in `data/` (LICENSE or NOTICE)

Detection order in `IsBot`: uasurfer `IsBot()` → our hand lists →
vendored patterns. Ours remain a separate high-precision pass — substring
matching catches things regexes express poorly, and the list encodes
dracory-specific knowledge (CVE probes, agent config files).

## Impact

- Broad recall without new runtime dependencies.
- Pattern maintenance becomes a script run, not hand-editing.

## Open questions

- **Regex cost on the hot path** — benchmark `IsBot` before merging; a
  small LRU cache is the mitigation (~32ns hits are achievable per the
  go-ua-parser spike).
- Vendored data goes stale like any list — decide whether CI flags drift
  or it stays manual.
