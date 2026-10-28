package botdetect

import (
	"net/http"
	"strings"

	"github.com/LumenResearch/uasurfer"
)

// BotClass categorizes a detected bot so consumers can apply purpose-aware
// policy (allow search engines, block scanners, observe AI crawlers)
// instead of a flat allow/block.
type BotClass string

const (
	ClassSearch  BotClass = "search"   // Googlebot, Bingbot, DuckDuckBot, ...
	ClassSocial  BotClass = "social"   // Twitterbot, FacebookExternalHit, LinkedInBot, ...
	ClassAI      BotClass = "ai"       // GPTBot, ClaudeBot, Google-Extended, Bytespider, ...
	ClassAIUser  BotClass = "ai-user"  // ChatGPT-User, Perplexity-User, Claude-Web (human-initiated fetch)
	ClassSEOTool BotClass = "seo-tool" // AhrefsBot, SemrushBot, PetalBot, ...
	ClassMonitor BotClass = "monitor"  // Pingdom, Datadog, Site24x7, UptimeRobot, ...
	ClassScraper BotClass = "scraper"  // curl, python-requests, scrapy, headless, ...
	ClassScanner BotClass = "scanner"  // sqlmap, nikto, nmap, masscan, zgrab, cve-, ...
	ClassOther   BotClass = "other"    // generic/unclassified bots
)

// Detection is the result of analyzing a user-agent or request: whether it
// is a bot, its normalized identity, and its class.
type Detection struct {
	Bot   bool     // true if identified as a bot
	Name  string   // normalized bot identifier (e.g. "googlebot", "gptbot", "sqlmap")
	Class BotClass // empty when Bot is false
}

// Detect analyzes a user-agent string and returns a Detection with the
// bot's identity and class. An empty user-agent returns a zero Detection.
//
// Order of evaluation: the specific-name classification table runs first
// (preserving per-agent identity that uasurfer collapses into fleet
// constants — e.g. "chatgpt-user" vs "gptbot" both parse as
// BrowserOpenAIBot), then uasurfer's IsBot() for named fleets and generic
// heuristics, then our broad word-boundary pattern list for anything
// unclassified.
var uaCache = newDetectionCache()

func Detect(userAgent string) Detection {
	if userAgent == "" {
		return Detection{}
	}
	key := cacheKey(userAgent)
	if d, ok := uaCache.get(key); ok {
		return d
	}
	d := detectImpl(userAgent, strings.ToLower(userAgent), nil)
	uaCache.set(key, d)
	return d
}

// DetectRequest analyzes an *http.Request: the User-Agent plus alternate
// UA-carrier headers from the vendored list (X-Operamini-Phone-Ua,
// X-Device-User-Agent, X-Original-User-Agent, From, X-Scanner, ...).
// Returns a zero Detection if r is nil. A non-empty X-Scanner header is
// an immediate match — scanners announce themselves there and the value
// is not checked against patterns.
func DetectRequest(r *http.Request) Detection {
	if r == nil {
		return Detection{}
	}

	if d := Detect(r.UserAgent()); d.Bot {
		return d
	}

	for _, h := range uaCarrierHeaders {
		v := r.Header.Get(h)
		if v == "" {
			continue
		}
		// X-Scanner is an announcement header — its mere presence flags
		// the request as a scanner, per upstream Crawler-Detect semantics.
		if strings.EqualFold(h, "X-Scanner") {
			return Detection{Bot: true, Name: "x-scanner", Class: ClassScanner}
		}
		if d := Detect(v); d.Bot {
			return d
		}
	}

	return Detection{}
}

// IsBotRequest is the boolean shorthand for DetectRequest — reports
// whether the request's User-Agent or any alternate UA-carrier header
// identifies as a bot. Agent identity only: paths are not checked
// (IsBotPath/IsMaliciousPath stay separate concerns).
func IsBotRequest(r *http.Request) bool {
	return DetectRequest(r).Bot
}

// detectImpl classifies a user-agent given its lowercase form and optional
// pre-parsed uasurfer result (so callers that already parsed don't parse
// twice, while Detect avoids parsing when botClassifications matches).
func detectImpl(userAgent, uaLower string, parsed *uasurfer.UserAgent) Detection {
	// Specific-name table first: uasurfer collapses agents from the same
	// vendor into one fleet constant (GPTBot/OAI-SearchBot/ChatGPT-User all
	// become BrowserOpenAIBot), so per-agent identity must be matched before.
	for _, c := range botClassifications {
		if strings.Contains(uaLower, c.token) {
			return Detection{Bot: true, Name: c.name, Class: c.class}
		}
	}

	if parsed == nil {
		parsed = uasurfer.Parse(userAgent)
	}
	if parsed.IsBot() {
		name := strings.ToLower(parsed.Browser.Name.StringTrimPrefix())
		return Detection{Bot: true, Name: name, Class: classForUasurferBot(parsed.Browser.Name)}
	}

	if pattern, ok := matchUserAgentPattern(uaLower); ok {
		return Detection{Bot: true, Name: pattern, Class: ClassOther}
	}

	// Vendored Crawler-Detect list last: exclusion pass strips browser/OS
	// chrome tokens first, then the combined regex runs once on the
	// remainder. An empty remainder means the UA was only browser
	// boilerplate — not a bot.
	if crawlersRegex != nil {
		stripped := strings.TrimSpace(exclusionsRegex.ReplaceAllString(userAgent, ""))
		if stripped != "" {
			if m := crawlersRegex.FindString(stripped); m != "" {
				return Detection{Bot: true, Name: strings.ToLower(m), Class: ClassOther}
			}
		}
	}

	return Detection{}
}

// classForUasurferBot maps uasurfer's named bot constants to bot classes.
// BrowserBot (generic) and anything unlisted map to ClassOther.
func classForUasurferBot(name uasurfer.BrowserName) BotClass {
	switch name {
	case uasurfer.BrowserAppleBot, uasurfer.BrowserBaiduBot, uasurfer.BrowserBingBot,
		uasurfer.BrowserCocCocBot, uasurfer.BrowserDuckDuckGoBot, uasurfer.BrowserGoogleBot,
		uasurfer.BrowserMsnBot, uasurfer.BrowserYahooBot, uasurfer.BrowserYandexBot:
		return ClassSearch
	case uasurfer.BrowserFacebookBot, uasurfer.BrowserLinkedInBot, uasurfer.BrowserTwitterBot:
		return ClassSocial
	case uasurfer.BrowserAmazonBot, uasurfer.BrowserAnthropicBot, uasurfer.BrowserBytedanceBot,
		uasurfer.BrowserCommonCrawlBot, uasurfer.BrowserOpenAIBot, uasurfer.BrowserPerplexityBot:
		return ClassAI
	case uasurfer.BrowserAhrefsBot, uasurfer.BrowserPetalBot, uasurfer.BrowserSemrushBot:
		return ClassSEOTool
	case uasurfer.BrowserPingdomBot:
		return ClassMonitor
	default:
		return ClassOther
	}
}
