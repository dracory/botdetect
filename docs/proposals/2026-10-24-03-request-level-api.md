# Proposal: request-level detection APIs

Status: proposed
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
// IsBotRequest checks UA plus bot-typical headers (e.g. crawler From:
// contact addresses) from the vendored Headers list.
func IsBotRequest(r *http.Request) bool

// ParseRequest parses UA plus Sec-CH-UA-* client hints via uasurfer's
// ParseWithHints — better device-type and OS-version accuracy on
// Chromium where the consumer emits Accept-CH.
func ParseRequest(r *http.Request) UserAgentInfo
```

Both stay pure (no I/O, no global state).

## Impact

- Single call in middleware: `botdetect.IsBotRequest(r)` covers UA +
  header signals.
- Client-hints path is opt-in — no behavior change for string-only callers.

## Open questions

- Should `IsBotRequest` also run `IsMaliciousPath(r.URL.Path)` and return
  a richer verdict than `bool`? Interacts with the bot-classes proposal —
  a `Verdict`/`Detection` result type may replace bare bools.
