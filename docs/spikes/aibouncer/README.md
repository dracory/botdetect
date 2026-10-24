# Spike: `github.com/emorilebo/aibouncer` — verified AI-crawler detection

Date: 2026-10-24
Status: findings — decision pending

## What it is

A dependency-free (stdlib-only) Go middleware + CLI, MIT licensed, that
identifies **34 AI crawlers from 14 operators** and — the key differentiator
— **verifies they are who they claim to be** rather than trusting the
User-Agent string.

Repo health caveat: brand new (single commit, 0 stars, single author).
Conceptually strong, but unproven as a dependency.

## Capabilities relevant to botdetect

### 1. Verification — the thing we don't do at all

Our `IsBot` trusts the UA string. aibouncer checks the claim three ways:

- **Official IP-range lists** (20 published lists — OpenAI, Anthropic,
  Google, Meta, etc.), embedded snapshot + periodic live refresh.
- **Forward-confirmed reverse DNS** for operators without IP lists.
- **Web Bot Auth (RFC 9421)** HTTP-message signatures — the *only* way to
  identify OpenAI's ChatGPT agent, which has no documented UA token or IP
  list. Key directories fetched only from catalog URLs (never from the
  request — blocks SSRF-via-keyid).

Verdicts: `verified` / `spoofed` / `unverifiable` / `not-ai`, each with the
method used and a reason. `spoofed` = claimed a name and failed its
operator's own verification → blocked by default. `unverifiable` is
explicitly *not* evidence of spoofing.

### 2. Purpose classification

Every catalog agent is tagged `training` / `search` / `user` / `agent` /
`other`, so policy can be "block training crawlers, allow search crawlers
and user-initiated fetches" — the distinction our flat `IsBot` can't make.
E.g. `ChatGPT-User` is a human clicking a link; blocking it loses referral
traffic.

### 3. Policy engine

Allow/block per purpose or per agent ID, ordered: impostor rule → agent
rule → purpose rule → default allow. `AllowSpoofed` gives observe-only
mode. Two sharp details:

- **`/robots.txt` is never blocked** — RFC 9309: a 4xx robots.txt means
  "no rules", so blocking it tells crawlers everything is allowed.
- The same policy object **renders to robots.txt** (`policy.RobotsTxt()`),
  including control tokens (`Google-Extended`, `Applebot-Extended`) that
  never appear in a UA string.

### 4. AI referral measurement

Detects *human* visits arriving from ChatGPT, Perplexity, Gemini, Copilot,
Claude, DeepSeek, Grok (referrer hosts + documented `utm_source` tags) —
the flip side of bot detection that statsadmin would care about.

### 5. Trusted-proxy client IP

`TrustedProxies(cidrs)` — only honor `X-Forwarded-For` from your own
proxies; never `0.0.0.0/0`. Same problem our middleware will face.

### 6. Sub-packages

- `robotstxt` — RFC 9309 parser/matcher (fuzzed, 99% coverage).
- `webbotauth` — RFC 9421 verify *and* sign, tested against RFC/draft
  vectors.
- CLI: `aibouncer logs` (analyze access logs for AI crawls + spoofers +
  referrals), `robots`, `verify`, `agents`, `robots-gen`.

## Gap analysis vs botdetect today

| Concern | botdetect | aibouncer |
|---|---|---|
| UA pattern matching | yes | yes (catalog) |
| Bot **verification** (IP lists, rDNS, signatures) | no | yes |
| Purpose-aware policy | no | yes |
| Malicious-path detection (.env, .git/) | yes | no |
| Referrer spam domains | yes | no |
| Datacenter CIDRs | yes (static) | yes (live operator lists) |
| AI referral measurement | no | yes |
| robots.txt parse/generate | no | yes |
| General (non-AI) bots: curl, scrapy, scanners | yes | partial |
| Dependencies | uasurfer | **zero** |

They're complementary, not redundant: aibouncer verifies *claimed* AI
agents; we detect *unclaimed* automation, scanner probes, and hostile paths.

## Risks

- 1 commit / 0 stars / single author — adoption risk as a hard dependency.
- Live refresh + rDNS + signature fetch = network calls in the request path
  (mitigated by its Verifier goroutine + caching, but it's a new failure
  mode our pure functions don't have).
- Overlaps uasurfer's `IsBot` for AI crawlers specifically — three sources
  of bot truth (our patterns, uasurfer, aibouncer catalog) could disagree.

## Options

1. **Adopt concepts, not the dependency.** Port the valuable ideas into
   botdetect: verdict enum (`verified`/`spoofed`/`unverifiable`/`not-ai`),
   purpose classification on our pattern table, "never block robots.txt"
   rule, trusted-proxy client IP helper. License-compatible (MIT), no
   supply-chain risk. Cost: we re-implement.
2. **Depend on it** for the verification layer only. Gets Web Bot Auth +
   IP-list freshness for free. Cost: a zero-track-record dep with network
   behavior.
3. **Bridge:** keep botdetect pure; let the *app* compose both —
   `aibouncer.Middleware` for AI-crawler verification/policy, our checks
   for everything else. Documents the composition as the intended pattern.

Recommendation: option 3 short-term (no code needed), option 1 for the
cheap wins — a `Purpose` field on detected bots and a `Verdict` type are
small additions that make the middleware far more useful. Verification
proper (option 2) is worth revisiting if the repo matures.

## References

- https://github.com/emorilebo/aibouncer (README)
- Catalog: `catalog.json` (34 agents, 14 operators, purposes, doc links)
