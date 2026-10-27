# botdetect

Bot, crawler, and malicious-traffic detection for Go HTTP services.

Pure, request-agnostic functions you can call from middleware, ingestion
pipelines, or batch jobs — no store, no DB, no goroutines.

```bash
go get github.com/dracory/botdetect
```

## Detection functions

```go
import "github.com/dracory/botdetect"

// User-agent based bot/crawler detection (browsers, scrapers, AI crawlers,
// CLI HTTP clients, scanners)
botdetect.IsBot(r.UserAgent())

// Richer verdict: identity + class for purpose-aware policy
d := botdetect.Detect(r.UserAgent())
// d.Bot   → true/false
// d.Name  → "googlebot", "gptbot", "chatgpt-user", "sqlmap", ...
// d.Class → ClassSearch | ClassSocial | ClassAI | ClassAIUser |
//           ClassSEOTool | ClassMonitor | ClassScraper | ClassScanner | ClassOther

// Same, from an *http.Request (nil-safe)
botdetect.DetectRequest(r)

// Structured bot detection with normalized identity and BotClass
// (ClassSearch, ClassSocial, ClassAI, ClassAIUser, ClassSEOTool,
// ClassMonitor, ClassScraper, ClassScanner, ClassOther)
det := botdetect.Detect(r.UserAgent())
// det.Bot   true
// det.Name  "googlebot" | "gptbot" | "chatgpt-user" | "sqlmap" | ...
// det.Class botdetect.ClassSearch | botdetect.ClassAI | ...
det = botdetect.DetectRequest(r)

// Bot-only file probes: robots.txt, ads.txt, sitemap.xml, llms.txt, ...
botdetect.IsBotPath(r.URL.Path)

// Universally malicious endpoints: .env, .git/, .ssh/, shell.php, ...
// A single hit is strong evidence of a vulnerability scanner.
botdetect.IsMaliciousPath(r.URL.Path)

// Known referrer-spam domains (exact and subdomain matching)
botdetect.IsReferrerSpam(r.Referer())

// Cloud/data-center CIDR ranges (AWS, GCP, Azure, Hetzner, OVH, ...)
botdetect.IsDataCenterIP(clientIP)
```

All functions return plain `bool` and are safe to call with empty strings.

## User-agent parsing

```go
info := botdetect.ParseUserAgent(r.UserAgent())
// info.Browser        "edge" | "chrome" | "firefox" | ...
// info.BrowserVersion "120.0"
// info.Os             "macos" | "windows" | "ios" | ...
// info.OsVersion      "17.2"
// info.Device         "iphone" | "ipad" | "ipod" | ""
// info.DeviceType     "desktop" | "mobile" | "tablet" | "bot"
```

All name fields are normalized to lowercase — compare against the exported
constants (`botdetect.DeviceTypeMobile`, `botdetect.OsIOS`,
`botdetect.BrowserEdge`, `botdetect.Bot`, ...).

## Blocking middleware

```go
mux := http.NewServeMux()
// ... routes

handler := botdetect.Middleware(mux, botdetect.Options{
    // Let search engines and human-initiated AI fetches through;
    // block scanners, scrapers, and everything else detected.
    AllowedClasses: map[botdetect.BotClass]bool{
        botdetect.ClassSearch: true,
        botdetect.ClassAIUser: true,
    },
    // Jail repeat offenders for 5 minutes — after any block decision
    // the IP is rejected on a cheap map lookup.
    JailDuration: 5 * time.Minute,
    // Bearer-authed machine endpoints and assets bypass everything.
    ExcludePaths: []string{"/api/", "/assets*"},
    OnDetection: func(r *http.Request, d botdetect.Detection) {
        log.Printf("bot: %s class=%s path=%s", d.Name, d.Class, r.URL.Path)
    },
    OnJail: func(ip string, r *http.Request, d botdetect.Detection) {
        log.Printf("jailed %s (%s) for %s", ip, d.Name, r.URL.Path)
    },
})
http.ListenAndServe(":8080", handler)
```

Mount it early in the chain, before routing — bots then never reach your
handlers or analytics. Details:

- Malicious paths (`.env`, `.git/`, `shell.php`, ...) are blocked regardless
  of UA — disable via `DisableMaliciousPathBlock`. Stack-specific probes
  (`wp`, `.php`, `cgi-bin`, `backup`, ...) come from `PathBlocklist`,
  which defaults to `DefaultPathBlocklist()` — edit a copy of the
  returned slice to exclude tokens (e.g. `/new`) or add your own.
- `JailDuration` jails the client IP after any block decision;
  `GetIP` customizes the jail key (default: `RemoteAddr` — supply an
  X-Forwarded-For-aware func behind a trusted proxy). Jails are
  in-process: they don't survive restarts or span replicas.
- `ExcludePaths` bypasses every check including jails — keep assets
  reachable for visitors on a jailed shared IP.
- `/robots.txt` is never blocked (RFC 9309: a 4xx robots.txt means "no
  rules").
- `ObserveOnly: true` detects + reports via `OnDetection` but never blocks
  or jails — good for a rollout phase.
- `BlockResponse` customizes the rejection (default: 403 `Forbidden`).

## Pattern lists

The raw pattern tables are exported for consumers that want to drive their
own matching (e.g. SQL `LIKE` scans over stored logs):

```go
botdetect.BotPathPatterns()       // bot-only filenames
botdetect.MaliciousPathPatterns() // malicious path patterns
```

## Design notes

- `IsBot("")` returns `false` — a missing UA is not, by itself, evidence of
  a bot.
- Malicious-path patterns are stack-agnostic by design (`*.php`, `wp-admin`
  are excluded — they're malicious on some stacks, legitimate on others).
  Add your own stack-specific checks on top.
- Data-center CIDR matching uses coarse published ranges; some ranges may
  produce false positives on non-datacenter traffic. See
  [docs/maintaining-data.md](docs/maintaining-data.md) for how to update the
  detection lists and refresh the CIDR ranges.

## License

AGPL-3.0 — see [LICENSE](LICENSE).
