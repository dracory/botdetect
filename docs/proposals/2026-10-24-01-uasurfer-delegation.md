# Proposal: delegate primary bot verdict to uasurfer's `IsBot()`

Status: proposed
Date: 2026-10-24
Spike: `docs/spikes/uasurfer/README.md`

## Problem

`botdetect.IsBot` currently derives its bot verdict from `ParseUserAgent`
output fields (`DeviceType`/`Browser`/`Device == "bot"`) plus our own
pattern lists. uasurfer v0.3.1 — already a dependency — ships a tested
`ua.IsBot()` method with richer heuristics we don't replicate: contact-URL
convention, "like X" impostor handling, headless-browser detection, and
named crawler constants.

## Proposal

Change `IsBot` to:

1. Call `uasurfer.Parse` once.
2. Primary verdict: `ua.IsBot()`.
3. Supplementary pass: our existing pattern lists (broad + specific) —
   they cover scanners and AI crawlers uasurfer deliberately skips
   (~17% of real crawler agents).
4. Surface the named bot constant in `UserAgentInfo.Browser`
   (`"googlebot"`, `"gptbot"`, ...) via `StringTrimPrefix` + lowercase, so
   statsadmin can break down crawler types later.

## Impact

- Higher recall at zero added dependency cost.
- `UserAgentInfo` may gain bot-name values in `Browser` — consumers
  displaying it get a meaningful label instead of empty.
- Small, low-risk refactor; all existing tests still apply.

## Open questions

- Naming: with named bots landing in `Browser`, document that the field
  means "browser-or-bot identity", or add a separate `BotName` field.
