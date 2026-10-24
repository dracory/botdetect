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

## Blocking middleware example

```go
func botBlock(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if botdetect.IsMaliciousPath(r.URL.Path) {
            http.Error(w, "forbidden", http.StatusForbidden)
            return
        }
        if botdetect.IsBot(r.UserAgent()) {
            http.Error(w, "forbidden", http.StatusForbidden)
            return
        }
        next.ServeHTTP(w, r)
    })
}
```

Mount it early in the chain, before routing — bots then never reach your
handlers or analytics.

> **Note:** blocking on `IsBot` also rejects legitimate crawlers
> (Googlebot, Bingbot). If SEO matters, flag rather than block, or allowlist
> known crawlers first.

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
  produce false positives on non-datacenter traffic.

## License

AGPL-3.0 — see [LICENSE](LICENSE).
