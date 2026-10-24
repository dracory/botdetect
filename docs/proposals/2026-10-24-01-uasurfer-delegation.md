# Proposal: delegate primary bot verdict to uasurfer's `IsBot()`

Status: implemented
Date: 2026-10-24
Spike: `docs/spikes/uasurfer/README.md`

## Problem

`botdetect.IsBot` currently derives its primary bot verdict by calling
`ParseUserAgent` and checking `DeviceType`/`Browser`/`Device == "bot"`, then
falling back to our own pattern lists.

With `uasurfer` v0.3.1 — already in `go.mod` — this check is partially broken
and misses capabilities upstream already ships:

1. **Named bots bypass the `uaInfo` check in `IsBot`**: `ParseUserAgent`
   already converts `parsed.Browser.Name` via `StringTrimPrefix` + lowercase
   (`user_agent.go:78`). For generic bots (`BrowserBot`) that yields `"bot"`,
   but for all 22 named bots (`BrowserGoogleBot` → `"googlebot"`,
   `BrowserOpenAIBot` → `"openaibot"`, `BrowserAnthropicBot` →
   `"anthropicbot"`, etc.) `uaInfo.Browser` is the bot's name, not `"bot"`.
   Meanwhile `uasurfer` sets `DeviceType = DeviceComputer` (`"desktop"`) and
   `OS.Platform = PlatformBot` (which `ParseUserAgent` does not map to
   `Device`). As a result, `DeviceType|Browser|Device == "bot"` evaluates to
   `false` for every named bot in `uasurfer`, and they are only caught if
   they happen to match our fallback substring lists (missing fleet members
   like `OAI-SearchBot`, `GoogleOther`, or `Mediapartners-Google`).
2. **`ParseUserAgent` reports `DeviceType: "desktop"` for bots**: because
   `uasurfer` sets `DeviceType = DeviceComputer` in `applyBotDefaults`,
   `ParseUserAgent` returns `DeviceType: "desktop"` for bots instead of
   `Bot` (`"bot"`), contradicting the doc comment on `const Bot`,
   `README.md`, and downstream checks in `statsstore`/`statsadmin`.
3. **Unused upstream heuristics**: `ua.IsBot()` includes contact-URL
   convention (`+http...`), "like X" impostor handling, and headless-browser
   detection that we don't replicate.

## Proposal

1. **In `IsBot(ua)`**:
   - Call `uasurfer.Parse(ua).IsBot()` directly as the primary verdict
     (avoiding the extra allocations of building `UserAgentInfo` and
     formatting version strings on every `IsBot` call).
   - Keep our existing pattern lists (broad word-boundary + specific
     substring) as the supplementary pass — they cover security scanners,
     HTTP client libraries, and AI crawlers `uasurfer` skips (~17% of real
     crawler agents).
2. **In `ParseUserAgent(ua)`**:
   - Keep surfacing the lowercase bot identity in `UserAgentInfo.Browser`
     (`"googlebot"`, `"openaibot"`, `"anthropicbot"`, or generic `"bot"`).
   - When `parsed.IsBot()` is true (or `IsBot(ua)` matches), set
     `UserAgentInfo.DeviceType = Bot` (`"bot"`) instead of `"desktop"`,
     bringing implementation in line with `const Bot`, `README.md`, and
     `statsstore`/`statsadmin`.

## Impact

- Fixes named-bot detection in `IsBot` and gains `uasurfer`'s contact-URL,
  impostor, and headless heuristics at zero added dependency cost.
- Fixes `UserAgentInfo.DeviceType` for bots (`"bot"` instead of `"desktop"`),
  preventing bot traffic from inflating desktop device counts in downstream
  analytics while preserving the bot identity in `UserAgentInfo.Browser`.
- Avoids unnecessary string formatting in `IsBot`.

## Open questions

- **Fleet-level vs specific bot names in `Browser`**: `uasurfer` groups
  several agents under one `BrowserName` (e.g. `GPTBot`, `OAI-SearchBot`, and
  `ChatGPT-User` all become `"openaibot"`). If a caller needs the exact agent
  token, Proposal 04's `Detect(ua).Name` should report the specific matched
  agent while `UserAgentInfo.Browser` keeps the normalized family name.
