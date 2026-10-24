# Spike: what `uasurfer` (v0.3.1) already gives us for bot detection

Date: 2026-10-24
Status: findings — decision pending

## Context

`botdetect` carries its own UA pattern lists (`botUserAgentBroadPatterns`,
`botUserAgentSpecificPatterns`) on top of `ParseUserAgent`. Since statsstore
originally wrote them, upstream `github.com/LumenResearch/uasurfer` was
revived — v0.3.1 (our pinned version) now ships a dedicated `bot.go` and a
`ua.IsBot()` method. This spike compares coverage.

## What upstream provides (v0.3.1, already in go.mod)

- `ua := uasurfer.Parse(ua); ua.IsBot()` — canonical bot verdict.
- When `IsBot()` is true, `applyBotDefaults` sets:
  - `OS.Name = OSBot`, `OS.Platform = PlatformBot`
  - `DeviceType = DeviceComputer` (NOT a `DeviceBot` — see pitfalls below)
  - `Browser.Name` = a named constant or generic `BrowserBot`.
- Named constants for high-volume crawlers: `BrowserGoogleBot`,
  `BrowserBingBot`, `BrowserOpenAIBot`, `BrowserAnthropicBot`,
  `BrowserPerplexityBot`, `BrowserAmazonBot`, `BrowserBytedanceBot`,
  `BrowserAhrefsBot`, `BrowserSemrushBot`, plus others in `BrowserName`.
  A named constant covers the whole fleet (e.g. `BrowserGoogleBot` covers
  AdsBot, Mediapartners, GoogleOther, Google-InspectionTool).
- Detection heuristics beyond name lists:
  - conventional suffixes (`…bot`, `…spider`, `…crawler`),
  - contact-URL convention (`+http…` in the UA) — an agent with no browser
    token but a contact URL is classified `BrowserBot`,
  - HTTP client libraries (curl, python-requests, Go-http-client, Scrapy),
  - headless/automation browsers, link-preview fetchers,
  - impostor handling: "like Googlebot" claims report as `BrowserBot`.
- Documented accuracy: ~83% of 1,975 real crawler agents, zero false
  positives across 2,906 real device agents. The ~17% missed are crawlers
  wearing a full browser UA with an unguessable name (Datanyze, Rigor,
  Scope3, binlar).
- Edge is now detected upstream too: `edg/`, `edgios/`, `edga/`, `edge/`
  all classify as `BrowserIE` — so our manual `Edg/` family check still
  adds value by naming it `edge` instead of `ie`.

## What we have that upstream does not

- `IsBotPath` / `botPathPatterns` — robots.txt, ads.txt, sitemap.xml, etc.
- `IsMaliciousPath` / `maliciousPathPatterns` — .env, .git/, shell.php, etc.
- `IsReferrerSpam` / `referrerSpamDomains`.
- `IsDataCenterIP` / `dataCenterCIDRs`.
- Our extra specific-substring list partly overlaps upstream's named
  constants but also covers things upstream misses or deliberately skipped
  (e.g. `cve-`, `nikto`, `nmap`, `sqlmap`, `masscan`, `zgrab`, `site24x7`,
  `thewebreport`, `omgili`, AI-crawler tokens like `google-extended`).

## Other docs reviewed (doc/hints.md, doc/inapp.md, doc/tv.md)

- **`ParseWithHints(ua, &Hints{...})`** exists: consumes Chromium client-hint
  headers (`Sec-CH-UA-Mobile`, `Sec-CH-UA-Platform`,
  `Sec-CH-UA-Platform-Version`, `Sec-CH-UA-Form-Factors`) plus a
  `ScreenSize`/`AppBundle` hint. Fixes things the UA string alone gets
  wrong (Android phone vs tablet, frozen OS versions, iPad-in-desktop-mode).
  Relevant for us: `ParseUserAgent` could grow a hints-aware variant that
  takes `*http.Request` or raw headers — better `DeviceType` accuracy for
  stats, at the cost of needing `Accept-CH` response headers upstream of us.
- **In-app browsers report as the app, not the engine**: `BrowserFacebook`,
  `BrowserInstagram`, `BrowserWeChat`, `BrowserTikTok`, `BrowserSnapchat`,
  `BrowserLine` — plus Chromium-reskins `BrowserVivaldi`, `BrowserWhale`,
  `BrowserMIUI`, `BrowserHuawei`, `BrowserDuckDuckGo`. These are humans, not
  bots — important if a blocking middleware pattern-list ever includes app
  name tokens (`"tiktok"` etc. would flag real users).
- **`DeviceTV`** exists for TVs/sticks/set-top boxes (Samsung/LG/Roku/
  AppleTV/FireTV/Android TV). These are real users streaming — not bots.
  Our `deviceTypeToString` default branch maps it to `"tv"`, but there is
  no exported `DeviceTypeTV` const yet — add one.
- Edge/`Edg` reports as `BrowserIE` upstream (confirmed by inapp.md) — our
  token-based override to `"edge"` remains the right call.

## Pitfalls found

- **`DeviceType` is `DeviceComputer` for bots**, not `DeviceBot` — upstream
  encodes "bot" in `OS.Name`/`OS.Platform`/`Browser.Name` instead. Our
  `IsBot` checking `DeviceType|Browser|Device == "bot"` still works via
  `Browser` (BrowserBot → `"bot"`) and via `Os` (`OSBot` → `osNameToString`
  → `"bot"`), but `Os` is not currently in the check.
- uasurfer is flagged "effectively unmaintained" in
  `statsstore/docs/security-review.md` — the v0.3.x revival contradicts
  that; the note should be updated if we keep the dependency.

## Options

1. **Delegate to `ua.IsBot()` inside `botdetect.IsBot`**, keep our lists as
   a supplementary pass for scanner/AI-crawler tokens upstream misses.
   Less pattern-list to maintain; inherits upstream's tested heuristics
   (contact-URL, impostors, headless).
2. **Keep both lists independent** (status quo). More code to own, but no
   behavior coupling to upstream release cadence.
3. **Expose upstream named bot constants** in `UserAgentInfo.Browser`
   (e.g. `Browser: "googlebot"`) — useful signal for statsadmin if we want
   crawler breakdowns rather than a flat is_bot flag.

Recommendation: option 1 + 3 — call `uasurfer.Parse` once, use `IsBot()`
as the primary verdict, keep the specific-pattern list as a catch for the
~17% upstream misses (scanner tools, niche AI crawlers), and surface the
named bot constant in `UserAgentInfo.Browser`.

## References

- https://github.com/LumenResearch/uasurfer/blob/master/doc/bots.md
- `doc/hints.md`, `doc/inapp.md`, `doc/tv.md`, `bot.go`, `browser.go`,
  `uasurfer.go` in the v0.3.1 module cache
