# Proposal: request-level detection APIs

Status: implemented
Date: 2026-10-24
Spikes: `docs/spikes/crawler-detect-php/README.md`,
`docs/spikes/uasurfer/README.md`, `docs/spikes/go-ua-parser/README.md`

## Problem

All current functions take strings (`IsBot(ua)`, `IsBotPath(path)`).
Middleware consumers re-extract fields from `*http.Request` themselves,
and two available signal sources are unused: bot-typical HTTP headers and
client hints.

## Proposal

Add request-level entry points:

```go
// IsBotRequest checks r.UserAgent() plus alternate UA-carrier headers
// (From, X-Original-User-Agent, X-Scanner, etc. from the normalized
// vendored Headers list). Returns false if r is nil.
func IsBotRequest(r *http.Request) bool

// ParseRequest parses r.UserAgent() plus Sec-CH-UA-* client hints via
// uasurfer's ParseWithHints — better device-type and OS-version accuracy
// on Chromium where the consumer emits Accept-CH. Returns a zero
// UserAgentInfo if r is nil.
func ParseRequest(r *http.Request) UserAgentInfo
```

### Header matching rules in `IsBotRequest`

Upstream `Headers.json` in Crawler-Detect is not a list of headers whose mere
presence means "bot" — it is a list of PHP `$_SERVER` keys (`HTTP_USER_AGENT`,
`HTTP_FROM`, `HTTP_X_ORIGINAL_USER_AGENT`, `HTTP_X_DEVICE_USER_AGENT`,
`HTTP_X_SCANNER`, etc.) whose **values** may carry the user-agent or crawler
contact string (e.g. `From: googlebot(at)googlebot.com`). Checking presence
alone would false-positive on legitimate traffic behind reverse proxies or
mobile transcoders that set `X-Original-User-Agent` or `X-Device-User-Agent`.

`IsBotRequest(r)` should therefore:

1. Return `false` if `r == nil`.
2. Return `true` if `IsBot(r.UserAgent())` is `true`.
3. Iterate over the normalized non-UA header names from `data/headers.json`:
   for each non-empty header value, run `IsBot(val)` (and treat a non-empty
   `X-Scanner` header as an immediate match).

### Scope boundary: why `IsBotRequest` does not check request paths

`IsBotRequest(r)` intentionally checks **agent identity only** (UA + headers),
not `IsBotPath(r.URL.Path)` or `IsMaliciousPath(r.URL.Path)`:

- **`IsBotPath` (`/robots.txt`, `/sitemap.xml`, `/ads.txt`)**: RFC 9309
  specifies that a `4xx` response on `/robots.txt` means "no crawl
  restrictions". If a blocking middleware calls `IsBotRequest(r)` and blocks
  matches with `403`, folding `IsBotPath` into `IsBotRequest` would block
  `/robots.txt` and `/sitemap.xml`.
- **`IsMaliciousPath` (`/.env`, `/.git/`, `/shell.php`)**: consumers like
  `statsstore` and blocking middleware treat malicious path probes as
  *threats* (always block/flag as threat), distinct from *bots* (where SEO
  crawlers may be allowed).

Both stay pure (no I/O, no network calls).

## Impact

- Single call in middleware: `botdetect.IsBotRequest(r)` covers UA +
  alternate UA/crawler headers.
- Client-hints path in `ParseRequest(r)` is opt-in — no behavior change for
  string-only callers, and recovers accurate Android tablet vs phone and
  macOS/Android versions when `Accept-CH` is sent.

## Open questions

- Alongside `IsBotRequest(r) bool`, add `DetectRequest(r *http.Request) Detection`
  (see Proposal 04) so middleware can inspect `BotClass` and `Name` from an
  `*http.Request` in one call.
