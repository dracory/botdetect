package botdetect

import (
	"log/slog"
	"net/netip"
	"net/url"
	"strings"
)

// == BOT USER-AGENT PATTERNS ==================================================

// botUserAgentBroadPatterns contains lowercase substrings that indicate a bot,
// crawler, spider, or automated tool but are short enough to cause false
// positives if matched as plain substrings (e.g. "bot" inside "RoboBotonic").
// These are matched with a word-boundary check: the pattern must be followed
// by a non-alphanumeric character (or end of string).
var botUserAgentBroadPatterns = []string{
	"bot",
	"crawler",
	"spider",
	"scraper",
	"slurp",
}

// botUserAgentSpecificPatterns contains lowercase substrings that are specific
// enough to be safely matched as plain case-insensitive substrings.
var botUserAgentSpecificPatterns = []string{
	"ahrefs",
	"aiohttp",      // async HTTP client library: "Python/3.14 aiohttp/3.14.1"
	"anthropic-ai", // Anthropic crawler
	"applebot",
	"archive.org_bot",
	"awario",
	"axios",
	"baidu",
	"bytespider",
	"chatgpt-user", // OpenAI user-facing fetcher
	"chrome-lighthouse",
	"claude-web", // Anthropic Claude web fetcher
	"cohere-ai",  // Cohere AI crawler
	"colly",
	"commons-httpclient", // Apache Commons HttpClient default UA
	"curl",
	"cve-", // vulnerability scanners / exploit probes
	"cypress",
	"dart:io", // Dart/Flutter HTTP client
	"datadog",
	"duckduckbot",
	"facebookexternalhit",
	"faraday", // Ruby HTTP client
	"feedly",
	"go-http-client",
	"google-extended", // Google AI training fetcher
	"google-page-speed-insights",
	"google-structured-data-testing-tool",
	"guzzlehttp", // PHP Guzzle client
	"headless",
	"heritrix",
	"httpx",
	"ia_archiver",
	"insomnia",
	"jakarta commons-httpclient", // Apache Commons HttpClient variant
	"java/",                      // Apache HttpClient default: "Java/1.8.0_301"
	"keenablebot",
	"libcurl-agent", // libcurl default UA variant
	"libwww-perl",   // Perl LWP user agent
	"lighthouse",
	"linkedinbot",
	"masscan", // port scanner / web probe
	"mechanize",
	"mechanize-go",
	"meta-externalagent", // Meta AI/LLM crawler
	"meta-externalfetcher",
	"netcraft",
	"newrelic",
	"nikto", // web vulnerability scanner
	"nmap",  // network/vulnerability scanner
	"node-fetch",
	"nutch",
	"okhttp",
	"omgili", // AI news aggregator crawler
	"petalbot",
	"phantom",
	"pingdom",
	"postman",
	"puppeteer",
	"python-requests",
	"python-urllib", // stdlib urllib format: "Python-urllib/3.10"
	"python/",       // stdlib urllib format: "Python/3.14" — no real browser UA contains "python/"
	"restsharp",     // .NET HTTP client
	"scrapy",
	"selenium",
	"semrush",
	"site24x7",
	"sqlmap", // SQL injection scanning tool
	"telegrambot",
	"thewebreport", // theweb.report monitoring service — "TheWebReport/1.0; +https://theweb.report"
	"twitterbot",
	"uptime",
	"w3c_validator",
	"wayback",
	"wget",
	"winhttp", // Windows WinHTTP library
	"yandex",
	"zgrab", // banner grabber / scanner
}

// == REFERRER SPAM DOMAINS ====================================================

// referrerSpamDomains contains lowercase domain names known to engage in
// referrer spam. Matching is case-insensitive against the referrer host.
var referrerSpamDomains = map[string]bool{
	"7makemoneyonline.com":             true,
	"adsterra.com":                     true,
	"adviceforum.info":                 true,
	"bestwebsitesawards.com":           true,
	"best-seo-offer.com":               true,
	"blackhatworth.com":                true,
	"buttons-for-website.com":          true,
	"buttons-for-your-site.com":        true,
	"buy-cheap-online.com":             true,
	"cyber-monday.ga":                  true,
	"cyber-monday.biz":                 true,
	"darodar.com":                      true,
	"econom.co":                        true,
	"erot.co":                          true,
	"floating-share-buttons.com":       true,
	"free-share-buttons.com":           true,
	"free-traffic.xyz":                 true,
	"get-free-traffic-now.com":         true,
	"get-clicky.com":                   true,
	"gowildpass.com":                   true,
	"hongfanji.com":                    true,
	"howtostopreferralspam.eu":         true,
	"humanorightswatch.org":            true,
	"hulfingtonpost.com":               true,
	"ilovevitaly.com":                  true,
	"ilovevitaly.ru":                   true,
	"ilovevitaly.org":                  true,
	"ilovevitaly.co":                   true,
	"o-o-6-o-o.com":                    true,
	"o-o-8-o-o.com":                    true,
	"offers.bycontext.com":             true,
	"palvira.com":                      true,
	"priceg.com":                       true,
	"quality-traffic.com":              true,
	"ranksonic.info":                   true,
	"ranksonic.org":                    true,
	"ranksonic.com":                    true,
	"rank-checker.online":              true,
	"referrerdisabler.com":             true,
	"semalt.com":                       true,
	"semalt.semalt.com":                true,
	"site1.floating-share-buttons.com": true,
	"snip.to":                          true,
	"snip.it":                          true,
	"www1.social-buttons.com":          true,
	"social-buttons.com":               true,
	"success-seo.com":                  true,
	"torture.ml":                       true,
	"trafficmonetize.com":              true,
	"traffic2cash.com":                 true,
	"traffic2money.com":                true,
	"webmonetizer.net":                 true,
	"xn--80adgbcm5aj1b5bfh.xn--p1ai":   true,
	"videos-for-your-business.com":     true,
}

// == DATA CENTER CIDR RANGES ==================================================

// dataCenterCIDRs contains CIDR ranges commonly associated with cloud
// providers and data centers. Traffic from these ranges is more likely
// to be automated.
//
// NOTE: Some entries use coarse ranges that are not wholly owned by the
// named provider and may produce false positives on residential/business
// traffic:
//   - IPv4: AWS/Azure /8s (13.0.0.0/8, 20.0.0.0/8, 40.0.0.0/8)
//   - IPv6: Azure 2603::/16 covers all Microsoft IPv6 space, not just Azure
//     compute; AWS 2600:1f00::/24 etc. are similarly broad.
//
// For higher accuracy, ingest the published JSON range files (AWS:
// https://ip-ranges.amazonaws.com/ip-ranges.json, GCP:
// https://www.gstatic.com/ipranges/cloud.json, Azure:
// https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-
// DA25A22F7F7C/ServiceTags_Public.json) instead of hand-maintaining these.
var dataCenterCIDRs = []string{
	// AWS
	"3.0.0.0/8",
	"13.0.0.0/8",
	"15.0.0.0/8",
	"16.0.0.0/8",
	"18.128.0.0/9",
	"34.0.0.0/8",
	"52.0.0.0/8",
	"54.0.0.0/8",
	"99.77.0.0/16",
	// GCP
	"35.184.0.0/13",
	"35.192.0.0/14",
	"35.196.0.0/15",
	"35.198.0.0/16",
	"35.199.0.0/17",
	"35.200.0.0/13",
	"35.208.0.0/12",
	"35.224.0.0/12",
	// Azure
	"4.128.0.0/12",
	"4.144.0.0/12",
	"4.160.0.0/12",
	"20.0.0.0/8",
	"40.0.0.0/8",
	// DigitalOcean
	"146.190.0.0/16",
	"159.65.0.0/16",
	"159.203.0.0/16",
	"165.22.0.0/16",
	"167.99.0.0/16",
	"206.189.0.0/16",
	// Oracle Cloud
	"129.146.0.0/16",
	"129.148.0.0/16",
	"129.150.0.0/15",
	"129.152.0.0/14",
	"129.156.0.0/14",
	"129.213.0.0/16",
	"130.61.0.0/16",
	"132.145.0.0/16",
	"140.238.0.0/16",
	"147.154.0.0/16",
	"150.136.0.0/16",
	"152.70.0.0/16",
	"192.29.0.0/16",
	"193.122.0.0/15",
	// Hetzner
	"5.9.0.0/16",
	"23.88.0.0/16",
	"37.120.128.0/19",
	"46.4.0.0/16",
	"49.12.0.0/15",
	"78.46.0.0/15",
	"88.99.0.0/16",
	"116.202.0.0/15",
	"135.181.0.0/16",
	"136.243.0.0/16",
	"138.201.0.0/16",
	"142.132.0.0/15",
	"144.76.0.0/16",
	"148.251.0.0/16",
	"159.69.0.0/16",
	"162.55.0.0/16",
	"167.235.0.0/16",
	"168.119.0.0/16",
	"176.9.0.0/16",
	"178.63.0.0/16",
	"188.40.0.0/16",
	"195.201.0.0/16",
	"213.239.0.0/18",
	"65.108.0.0/16",
	"65.109.0.0/16",
	"95.216.0.0/16",
	"95.217.0.0/16",
	// OVH
	"37.187.0.0/16",
	"51.68.0.0/16",
	"51.77.0.0/16",
	"51.83.0.0/16",
	"51.89.0.0/16",
	"51.91.0.0/16",
	"51.92.0.0/16",
	"51.254.0.0/16",
	"54.36.0.0/16",
	"54.37.0.0/16",
	"57.128.0.0/16",
	"91.134.0.0/16",
	"92.222.0.0/16",
	"94.23.0.0/16",
	"135.125.0.0/16",
	"137.74.0.0/16",
	"145.239.0.0/16",
	"146.59.0.0/16",
	"149.56.0.0/16",
	"149.202.0.0/16",
	"151.80.0.0/16",
	"158.69.0.0/16",
	"164.132.0.0/16",
	"167.114.0.0/16",
	"176.31.0.0/16",
	"178.32.0.0/16",
	"193.70.0.0/16",
	"198.50.0.0/16",
	"213.186.32.0/19",
	"217.182.0.0/16",
	// Linode / Akamai
	"45.33.0.0/17",
	"45.56.0.0/17",
	"45.79.0.0/16",
	"45.232.0.0/16",
	"50.116.0.0/16",
	"69.164.0.0/16",
	"72.14.0.0/16",
	"96.126.0.0/16",
	"139.144.0.0/16",
	"172.104.0.0/16",
	"173.230.0.0/16",
	"178.79.128.0/17",
	"194.195.0.0/16",
	"23.139.0.0/16",
	// Vultr
	"45.32.0.0/16",
	"45.63.0.0/16",
	"45.76.0.0/16",
	"45.77.0.0/16",
	"45.119.0.0/16",
	"64.227.0.0/16",
	"65.20.0.0/16",
	"78.141.192.0/18",
	"104.238.128.0/18",
	"108.61.0.0/16",
	"139.180.128.0/18",
	"140.82.0.0/16",
	"149.28.0.0/16",
	"155.94.0.0/16",
	"161.129.0.0/16",
	"167.179.0.0/16",
	"169.197.0.0/16",
	"174.138.0.0/16",
	"199.247.0.0/16",
	"207.246.96.0/19",
	"208.167.192.0/18",
	// Alibaba Cloud
	"47.52.0.0/16",
	"47.56.0.0/16",
	"47.74.0.0/15",
	"47.90.0.0/15",
	"47.92.0.0/14",
	"47.96.0.0/15",
	"47.116.0.0/15",
	"47.128.0.0/14",
	"52.80.0.0/16",
	"59.110.0.0/16",
	"60.205.0.0/16",
	"101.37.0.0/16",
	"101.132.0.0/15",
	"106.14.0.0/15",
	"110.75.0.0/16",
	"112.124.0.0/16",
	"114.55.0.0/16",
	"115.28.0.0/16",
	"116.62.0.0/16",
	"118.31.0.0/16",
	"119.23.0.0/16",
	"120.24.0.0/16",
	"120.26.0.0/16",
	"120.55.0.0/16",
	"120.76.0.0/16",
	"121.40.0.0/16",
	"121.42.0.0/16",
	"123.56.0.0/16",
	"139.129.0.0/16",
	"139.196.0.0/16",
	"140.205.0.0/16",
	"161.117.0.0/16",
	"182.92.0.0/16",
	"183.60.0.0/16",
	"203.107.0.0/17",
	"218.244.0.0/16",
	"220.181.0.0/16",
	// Tencent Cloud
	"49.51.0.0/16",
	"49.234.0.0/16",
	"49.235.0.0/16",
	"81.68.0.0/16",
	"81.69.0.0/16",
	"82.156.0.0/16",
	"94.191.0.0/16",
	"101.33.0.0/16",
	"101.34.0.0/15",
	"101.42.0.0/16",
	"110.40.0.0/16",
	"110.41.0.0/16",
	"111.229.0.0/16",
	"111.230.0.0/16",
	"119.29.0.0/16",
	"119.91.0.0/16",
	"120.53.0.0/16",
	"121.4.0.0/16",
	"121.5.0.0/16",
	"129.226.0.0/16",
	"134.175.0.0/16",
	"139.155.0.0/16",
	"139.186.0.0/16",
	"150.109.0.0/16",
	"150.158.0.0/16",
	"152.136.0.0/16",
	"159.75.0.0/16",
	"162.14.0.0/16",
	"175.27.0.0/16",
	"175.178.0.0/16",
	"182.254.0.0/16",
	"193.112.0.0/16",
	"203.195.0.0/16",
	"203.205.0.0/16",
	// Contabo
	"5.189.128.0/17",
	"62.171.128.0/17",
	"80.241.208.0/20",
	"84.252.64.0/18",
	"161.97.0.0/17",
	"173.212.192.0/18",
	"178.162.128.0/17",
	"194.163.128.0/17",
	"209.126.0.0/18",
	// Scaleway / Online.net
	"51.15.0.0/16",
	"51.158.0.0/20",
	"51.158.128.0/17",
	"62.210.0.0/16",
	"163.172.0.0/16",
	"195.154.0.0/16",
	"212.47.224.0/19",
	"212.83.128.0/19",
	// IBM Cloud
	"129.40.0.0/16",
	"129.41.0.0/16",
	"129.42.0.0/16",
	"150.239.0.0/16",
	"150.240.0.0/16",
	"150.241.0.0/16",
	"158.85.0.0/16",
	"159.122.0.0/16",
	"168.1.0.0/16",
	// UpCloud
	"94.237.0.0/17",
	"94.237.128.0/17",
	"109.230.192.0/18",
	"183.177.128.0/17",
	"191.101.0.0/18",
	"191.101.64.0/18",

	// == IPv6 ranges ==
	// AWS
	"2600:1f00::/24",
	"2600:1f01::/24",
	"2600:1f02::/24",
	"2600:1f03::/24",
	// GCP
	"2600:1900::/28",
	// Azure
	"2603::/16",
	"2604::/22",
	// Hetzner
	"2a01:4f8::/29",
	// OVH
	"2001:41d0::/32",
	// Linode / Akamai
	"2600:3c00::/24",
	// Vultr
	"2001:19f0::/29",
	// Alibaba Cloud
	"2400:3200::/32",
	// Tencent Cloud
	"2402:4e00::/32",
	// Scaleway / Online.net
	"2001:bc8::/32",
}

// parsedDataCenterCIDRs is initialized from dataCenterCIDRs at package load.
var parsedDataCenterCIDRs []netip.Prefix

func init() {
	for _, cidr := range dataCenterCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			slog.Error("botdetect: invalid datacenter CIDR in dataCenterCIDRs, skipping", "cidr", cidr, "error", err)
			continue
		}
		parsedDataCenterCIDRs = append(parsedDataCenterCIDRs, prefix)
	}
}

// == BOT PATH PATTERNS ========================================================

// botPathPatterns contains lowercase path substrings for files that
// legitimate crawlers request but no human browser ever does. These are
// universal across all websites regardless of tech stack.
//
// favicon.ico is excluded because browsers automatically request it.
// /.well-known/ is excluded because browsers use it for legitimate
// purposes (e.g. /.well-known/change-password for credential discovery).
//
// Matching is suffix-on-last-segment (see IsBotPath), so filename variants
// each need an explicit entry — e.g. "sitemap.xml" does not catch
// "sitemap_index.xml". Prefix-matched names (e.g. google*.html site
// verification files) cannot be expressed with this list.
var botPathPatterns = []string{
	"ads.txt",
	"ai.txt", // spawning.ai proposal for AI-crawler permissions;
	// rare false positive on files like "samurai.txt" (suffix match)
	"bingsiteauth.xml",
	"browserconfig.xml",      // IE/Edge tile config probed by some crawlers
	"clientaccesspolicy.xml", // legacy Silverlight policy file, only scanners fetch it
	"crossdomain.xml",        // legacy Flash policy file, only scanners fetch it
	"dnt-policy.txt",
	"humans.txt",
	"llms.txt",      // llmstxt.org manifest for LLM crawlers
	"llms-full.txt", // llmstxt.org full-content variant
	"robots.txt",
	"sitemap.xml",
	"security.txt",
	"sellers.json",
	"sitemap_index.xml", // Yoast/RankMath sitemap variant
	"sitemap-index.xml", // hyphenated sitemap variant
	"sitemap.xml.gz",    // compressed sitemap
}

// maliciousPathPatterns contains lowercase path substrings for endpoints
// that are never legitimate on any properly-configured website, regardless
// of tech stack. A single request to any of these is strong evidence of a
// vulnerability scanner or malicious bot.
//
// Stack-dependent patterns (e.g. .php, .asp, wp-admin) are intentionally
// excluded — they are malicious on some stacks but legitimate on others.
// Consumers should add their own stack-specific patterns on top.
//
// Matching (see IsMaliciousPath): file patterns match as a suffix of the
// last path segment; directory patterns (trailing "/") match a whole path
// segment. All entries must be lowercase — the path is lowercased before
// matching but the pattern is compared as-is.
var maliciousPathPatterns = []string{
	".aws/",    // AWS credentials directory
	".claude/", // Claude Code config directory
	".clinerules",
	".continue/",   // Continue.dev config — may contain API keys
	".cursor/",     // Cursor config dir — mcp.json may contain secrets
	".cursorrules", // Cursor rules file
	".devin/",      // Devin config dir — mcp.json may contain secrets
	".ds_store",    // macOS metadata leak (path is lowercased before matching)
	".env",
	".git/",
	".htpasswd",
	".npmrc", // npm config, can leak auth tokens
	".ssh/",  // SSH keys directory
	".svn/",
	".windsurf/",                 // Windsurf config directory
	".windsurfrules",             // Windsurf rules file
	"agents.md",                  // AGENTS.md — probed for agent-instruction leaks
	"claude.md",                  // CLAUDE.md agent instructions
	"claude_desktop_config.json", // Claude Desktop MCP config — contains secrets
	"copilot-instructions.md",    // GitHub Copilot instructions (.github/)
	"gemini.md",                  // GEMINI.md agent instructions
	"id_rsa",                     // SSH private key
	"mcp.json",                   // MCP server config — often contains API keys/tokens
	"shell.php",
}

// == PUBLIC FUNCTIONS =========================================================

// IsBot checks whether a user-agent string matches known bot/crawler patterns
// or is identified as a bot device by uasurfer parsing.
// An empty user-agent returns false — a missing UA is not, by itself,
// evidence of a bot.
// Broad patterns (bot, crawler, spider, scraper, slurp) are matched with a
// word-boundary check to avoid false positives (e.g. "bot" inside a non-bot
// word). Specific patterns (semrush, curl, googlebot, etc.) are matched as
// plain case-insensitive substrings.
func IsBot(userAgent string) bool {
	if userAgent == "" {
		return false
	}

	uaInfo := ParseUserAgent(userAgent)
	// Check all name fields — uasurfer sets DeviceType=bot and often
	// Browser=bot for known bots; Device can only be a platform name
	// today, but the check is kept defensively against parser changes.
	if strings.EqualFold(uaInfo.DeviceType, Bot) ||
		strings.EqualFold(uaInfo.Browser, Bot) ||
		strings.EqualFold(uaInfo.Device, Bot) {
		return true
	}

	uaLower := strings.ToLower(userAgent)

	// Check broad patterns with word-boundary matching.
	for _, pattern := range botUserAgentBroadPatterns {
		if matchWordBoundary(uaLower, pattern) {
			return true
		}
	}

	// Check specific patterns with plain substring matching.
	for _, pattern := range botUserAgentSpecificPatterns {
		if strings.Contains(uaLower, pattern) {
			return true
		}
	}

	return false
}

// BotPathPatterns returns the list of path substrings for bot-only files
// (robots.txt, ads.txt, sitemap.xml, etc.) that legitimate crawlers request
// but no human browser does. Consumers can use this list to drive SQL LIKE
// scans or similar bulk queries.
func BotPathPatterns() []string {
	return append([]string(nil), botPathPatterns...)
}

// MaliciousPathPatterns returns the list of path substrings for endpoints
// that are never legitimate on any properly-configured website (e.g. .env,
// .git/, shell.php). Stack-dependent patterns like .php or wp-admin are
// excluded — consumers should add their own based on their tech stack.
func MaliciousPathPatterns() []string {
	return append([]string(nil), maliciousPathPatterns...)
}

// IsBotPath reports whether a request path targets a bot-only file
// (robots.txt, ads.txt, sitemap.xml, etc.) that no human browser requests.
// Matching is case-insensitive. The pattern is matched as a suffix of the
// last path segment (filename), so "/app-ads.txt" matches "ads.txt" but
// "/ads.txt.backup" does not.
func IsBotPath(path string) bool {
	if path == "" {
		return false
	}
	pathLower := strings.ToLower(path)
	lastSegment := pathLastSegment(pathLower)
	for _, pattern := range botPathPatterns {
		if strings.HasSuffix(lastSegment, pattern) {
			return true
		}
	}
	return false
}

// IsMaliciousPath reports whether a request path targets a universally
// malicious endpoint (.env, .git/, .svn/, .htpasswd, shell.php) that is
// never legitimate on any properly-configured site. A single hit is strong
// evidence of a vulnerability scanner. Stack-dependent patterns are not
// included — consumers should add their own.
//
// File patterns (e.g. shell.php) are matched as a suffix of the last path
// segment. Dotfile patterns starting with '.' (e.g. .env, .htpasswd) match
// the segment exactly, as a suffix (e.g. "backup.env"), or as a prefix
// followed by a separator — capturing variants like .env.bak, .env_old,
// and .env.local while avoiding false positives on .envrc or .envelope.yml.
// Directory patterns (e.g. .git/, .svn/) are matched against individual path
// segments, so "/.git/config" matches but "/.github/workflows" does not.
func IsMaliciousPath(path string) bool {
	if path == "" {
		return false
	}
	pathLower := strings.ToLower(path)
	lastSeg := pathLastSegment(pathLower)
	for _, pattern := range maliciousPathPatterns {
		if strings.HasSuffix(pattern, "/") {
			dirName := strings.TrimSuffix(pattern, "/")
			for _, segment := range strings.Split(pathLower, "/") {
				if segment == dirName {
					return true
				}
			}
		} else if strings.HasPrefix(pattern, ".") {
			if lastSeg == pattern ||
				strings.HasPrefix(lastSeg, pattern+".") ||
				strings.HasPrefix(lastSeg, pattern+"_") ||
				strings.HasSuffix(lastSeg, pattern) {
				return true
			}
		} else {
			if strings.HasSuffix(lastSeg, pattern) {
				return true
			}
		}
	}
	return false
}

// pathLastSegment extracts the last path segment (filename) from a path.
// Query strings and fragments are stripped first, so "/robots.txt?v=1"
// returns "robots.txt". For example, "/courses/go" returns "go",
// "[GET] /robots.txt" returns "robots.txt".
func pathLastSegment(path string) string {
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	idx := strings.LastIndex(path, "/")
	if idx < 0 {
		return path
	}
	return path[idx+1:]
}

// matchWordBoundary reports whether s contains pattern followed by a
// non-alphanumeric character (or end of string). This prevents false
// positives like "bot" matching inside "RoboBotonic" or "ibotonic".
//
// Only the after-boundary is checked — this is a deliberate design
// decision, not an oversight. Adding a before-boundary check would break
// detection of "Googlebot", "SemrushBot", "AppleBot", "Bingbot" etc.,
// where "bot" is a suffix of a longer word with an alphanumeric char
// before it. None of these are in botUserAgentSpecificPatterns, so the
// broad "bot" pattern is the only thing that catches them. The accepted
// tradeoff is that hypothetical UAs like "turbot" or "abbot" would also
// match — but no real browser UA contains "bot" as a substring, so this
// false-positive risk is negligible in practice.
func matchWordBoundary(s, pattern string) bool {
	idx := 0
	for {
		pos := strings.Index(s[idx:], pattern)
		if pos < 0 {
			return false
		}
		pos += idx
		// Check the character after the match.
		end := pos + len(pattern)
		if end >= len(s) {
			return true // end of string is a valid boundary
		}
		next := s[end]
		if !isAlnum(next) {
			return true
		}
		// Not a boundary — keep searching after this position.
		idx = pos + 1
	}
}

// isAlnum reports whether b is an ASCII letter or digit.
func isAlnum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// IsReferrerSpam checks whether a referrer URL host matches a known spam domain.
// The referrer can be a full URL or just a domain. Matching is case-insensitive.
func IsReferrerSpam(referrer string) bool {
	if referrer == "" {
		return false
	}

	host := referrer

	// Try to parse as URL to extract host. Bare inputs like
	// "semalt.com/foo" parse with an empty Host, so strip any path
	// portion before falling back to the raw string.
	if u, err := url.Parse(referrer); err == nil && u.Host != "" {
		host = u.Host
	} else if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}

	host = strings.ToLower(strings.TrimSpace(host))
	// Strip port if present (handle IPv6 brackets)
	if i := strings.LastIndex(host, "]"); i >= 0 {
		host = host[:i+1]
	} else if idx := strings.LastIndex(host, ":"); idx > 0 {
		host = host[:idx]
	}
	// Strip leading "www." for matching
	host = strings.TrimPrefix(host, "www.")

	if host == "" {
		return false
	}

	// Check exact match
	if referrerSpamDomains[host] {
		return true
	}

	// Check if any spam domain is a suffix (handles subdomains)
	for domain := range referrerSpamDomains {
		if strings.HasSuffix(host, "."+domain) {
			return true
		}
	}

	return false
}

// IsDataCenterIP checks whether an IP address falls within known data center
// CIDR ranges (AWS, GCP, Azure, DigitalOcean, Oracle Cloud, Hetzner, OVH,
// Linode/Akamai, Vultr, Alibaba, Tencent, Contabo, Scaleway/Online.net,
// IBM Cloud, UpCloud).
func IsDataCenterIP(ip string) bool {
	if ip == "" {
		return false
	}

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()

	for _, prefix := range parsedDataCenterCIDRs {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}
