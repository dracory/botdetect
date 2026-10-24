package botdetect

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
