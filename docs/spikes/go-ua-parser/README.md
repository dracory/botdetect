# Spike: `github.com/motiv8-team/go-ua-parser`

Date: 2026-10-24
Status: findings — decision pending

## What it is

A high-performance, zero-dependency (stdlib-only, MIT) UA parser with
first-class bot detection. Claims **1,666 detection rules** — 385 browsers,
**821 bots**, 76 devices, 368 in-app browsers, 16 engines — plus 14
heuristic bot-keyword patterns for unnamed bots.

Repo health: new and small (10 commits, 6 stars) — similar maturity risk
to aibouncer, but substantially more feature-complete.

## Feature surface vs botdetect

| Feature | botdetect | go-ua-parser |
|---|---|---|
| UA parse (browser/OS/device) | uasurfer-backed | own rules engine |
| Bot detection | ~100 patterns + uasurfer `IsBot` | 821 named + 14 heuristics |
| Bot **classification** | none | `search`/`social`/`ai`/`seo-tool`/`monitor`/`scraper`/`other` |
| Bot metadata (vendor, version, confidence) | none | `Name`, `Vendor`, `Version`, `IsVerified`, `Confidence` |
| Client Hints | none | full `Sec-CH-UA-*` incl. Windows 11 fix |
| `ParseRequest(*http.Request)` | none | built-in (UA + hints auto-extract) |
| Parse caching | none | sharded LRU, ~32–82ns hits, zero-alloc |
| In-app browser detection | none (uasurfer has it, we don't surface) | 368 rules, `App.Kind` |
| Custom rules override | none | `WithCustomBotRules` etc., checked before builtins |
| Malicious paths / referrer spam / datacenter IPs | yes | no |
| Device classes | desktop/mobile/tablet/tv | + smarttv, console, car, wearable |
| Engine + CPU arch | none | Blink/Gecko/..., x86_64/arm |
| Pre/post-parse hooks | none | yes |

The bot **class** taxonomy is the aibouncer "purpose" idea, at the
pattern level: `ai` vs `search` vs `seo-tool` vs `monitor` — exactly the
distinction needed for "block scrapers, allow Googlebot, observe AI
crawlers" policy.

`IsVerified`/`Confidence` fields exist but there's no cryptographic or
IP verification like aibouncer — they're rule-confidence metadata.

## Performance angle

- ~500K parses/sec/core; cached hits at ~32ns zero-alloc.
- Our `IsBot` does ~100 substring scans + a uasurfer parse per request —
  fine, but their `parser.DetectBot(ua)` fast path + LRU cache is
  engineered for the hot middleware path we're planning.

## What it lacks that we have

- `IsMaliciousPath` / `IsBotPath` — path-based detection is ours alone.
- `IsReferrerSpam`, `IsDataCenterIP`.
- Verification proper (aibouncer's IP lists / rDNS / RFC 9421) — it has
  `IsVerified` metadata but no live verification.

## Options

1. **Replace the uasurfer + pattern-list core with go-ua-parser** and keep
   botdetect as the layer that adds paths/referrer/IP checks + middleware
   policy. `ParseUserAgent` becomes a thin adapter over their `Result`.
   Pros: better coverage, classes, hints, caching, zero deps (drops
   uasurfer). Cons: bets the module's core on a 6-star repo.
2. **Add it as an optional engine** — `IsBot` stays ours; expose
   `botdetect.WithEngine(uaparser)` for consumers who want the deeper
   rules. More API surface, less commitment.
3. **Steal the design:** bot classes + confidence on our own pattern
   table; `ParseRequest(r)` helper; optional LRU cache. No new dep.

Recommendation: watch, don't adopt yet — same maturity concern as
aibouncer, but this one is a plausible *replacement* for our whole UA
core, which makes the risk bigger, not smaller. If it matures (releases,
adoption), option 1 becomes attractive. In the meantime option 3 gives
us the two features that matter most — bot classes and `ParseRequest` —
for little code.

## References

- https://github.com/motiv8-team/go-ua-parser (README, `bot.go`, `rules/`)
