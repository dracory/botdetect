package botdetect

// botClassifications maps lowercase user-agent substrings to a specific bot
// identity (name + class). Entries are checked in order against the
// lowercased UA, so more specific tokens must precede overlapping ones
// (e.g. "oai-searchbot" before "openai").
//
// This table exists because uasurfer collapses agents from the same vendor
// into a single fleet constant (GPTBot, OAI-SearchBot and ChatGPT-User all
// parse as BrowserOpenAIBot) — matching tokens here preserves per-agent
// identity and the ClassAI vs ClassAIUser distinction.
var botClassifications = []struct {
	token string
	name  string
	class BotClass
}{
	// — AI: user-initiated fetchers (a human clicked a link in the app) —
	{"chatgpt-user", "chatgpt-user", ClassAIUser},
	{"perplexity-user", "perplexity-user", ClassAIUser},
	{"claude-user", "claude-user", ClassAIUser},
	{"claude-web", "claude-web", ClassAIUser},
	{"meta-externalfetcher", "meta-externalfetcher", ClassAIUser},

	// — AI: training/data crawlers —
	{"gptbot", "gptbot", ClassAI},
	{"claudebot", "claudebot", ClassAI},
	{"google-extended", "google-extended", ClassAI},
	{"bytespider", "bytespider", ClassAI},
	{"ccbot", "ccbot", ClassAI},
	{"amazonbot", "amazonbot", ClassAI},
	{"meta-externalagent", "meta-externalagent", ClassAI},
	{"anthropic-ai", "anthropic-ai", ClassAI},
	{"cohere-ai", "cohere-ai", ClassAI},
	{"keenablebot", "keenablebot", ClassAI},
	{"omgili", "omgili", ClassAI},

	// — Search engines (operator-documented index crawlers) —
	// NOTE: "slurp" is intentionally not here — it stays in
	// botUserAgentBroadPatterns where word-boundary matching applies.
	{"oai-searchbot", "oai-searchbot", ClassSearch},
	{"claude-searchbot", "claude-searchbot", ClassSearch},
	{"googlebot", "googlebot", ClassSearch},
	{"bingbot", "bingbot", ClassSearch},
	{"msnbot", "msnbot", ClassSearch},
	{"duckduckbot", "duckduckbot", ClassSearch},
	{"applebot", "applebot", ClassSearch},
	{"baidu", "baiduspider", ClassSearch},
	{"yandex", "yandexbot", ClassSearch},
	{"archive.org_bot", "archivebot", ClassSearch},
	{"ia_archiver", "ia-archiver", ClassSearch},
	{"wayback", "wayback", ClassSearch},
	{"heritrix", "heritrix", ClassSearch},

	// — Social / link-preview fetchers —
	// Note: "telegrambot" precedes "twitterbot" because Telegram's crawler UA
	// is "TelegramBot (like TwitterBot)".
	{"facebookexternalhit", "facebookexternalhit", ClassSocial},
	{"telegrambot", "telegrambot", ClassSocial},
	{"twitterbot", "twitterbot", ClassSocial},
	{"linkedinbot", "linkedinbot", ClassSocial},
	{"slackbot", "slackbot", ClassSocial},
	{"discordbot", "discordbot", ClassSocial},
	{"whatsapp", "whatsapp", ClassSocial},
	{"pinterestbot", "pinterestbot", ClassSocial},

	// — SEO / marketing crawlers —
	{"ahrefs", "ahrefsbot", ClassSEOTool},
	{"semrush", "semrushbot", ClassSEOTool},
	{"petalbot", "petalbot", ClassSEOTool},
	{"mj12bot", "mj12bot", ClassSEOTool},
	{"dotbot", "dotbot", ClassSEOTool},
	{"screaming frog", "screaming-frog", ClassSEOTool},
	{"sistrix", "sistrix", ClassSEOTool},
	{"seobility", "seobility", ClassSEOTool},
	{"awario", "awario", ClassSEOTool},

	// — Monitoring / uptime services —
	{"uptimerobot", "uptimerobot", ClassMonitor},
	{"uptime", "uptime-monitor", ClassMonitor},
	{"pingdom", "pingdom", ClassMonitor},
	{"datadog", "datadog", ClassMonitor},
	{"newrelic", "newrelic", ClassMonitor},
	{"site24x7", "site24x7", ClassMonitor},
	{"thewebreport", "thewebreport", ClassMonitor},
	{"netcraft", "netcraft", ClassMonitor},
	{"gtmetrix", "gtmetrix", ClassMonitor},

	// — Security scanners / exploit probes —
	{"sqlmap", "sqlmap", ClassScanner},
	{"nikto", "nikto", ClassScanner},
	{"nmap", "nmap", ClassScanner},
	{"masscan", "masscan", ClassScanner},
	{"zgrab", "zgrab", ClassScanner},
	{"cve-", "cve-probe", ClassScanner},
	{"acunetix", "acunetix", ClassScanner},
	{"nuclei", "nuclei", ClassScanner},
	{"openvas", "openvas", ClassScanner},
	{"nessus", "nessus", ClassScanner},

	// — Scrapers / HTTP clients / headless automation —
	// Note: specific tools that embed HeadlessChrome, Python/, or curl tokens
	// precede those generic tokens so per-tool identity is preserved.
	{"chrome-lighthouse", "chrome-lighthouse", ClassScraper},
	{"lighthouse", "lighthouse", ClassScraper},
	{"google-page-speed-insights", "pagespeed", ClassScraper},
	{"google-structured-data-testing-tool", "google-sdtt", ClassScraper},
	{"w3c_validator", "w3c-validator", ClassScraper},
	{"headless", "headless-browser", ClassScraper},
	{"puppeteer", "puppeteer", ClassScraper},
	{"playwright", "playwright", ClassScraper},
	{"selenium", "selenium", ClassScraper},
	{"phantom", "phantomjs", ClassScraper},
	{"cypress", "cypress", ClassScraper},
	{"scrapy", "scrapy", ClassScraper},
	{"colly", "colly", ClassScraper},
	{"libcurl-agent", "libcurl-agent", ClassScraper},
	{"curl", "curl", ClassScraper},
	{"wget", "wget", ClassScraper},
	{"aiohttp", "aiohttp", ClassScraper},
	{"python-requests", "python-requests", ClassScraper},
	{"python-urllib", "python-urllib", ClassScraper},
	{"python/", "python", ClassScraper},
	{"httpx", "httpx", ClassScraper},
	{"go-http-client", "go-http-client", ClassScraper},
	{"java/", "java-http", ClassScraper},
	{"okhttp", "okhttp", ClassScraper},
	{"dart:io", "dart", ClassScraper},
	{"node-fetch", "node-fetch", ClassScraper},
	{"axios", "axios", ClassScraper},
	{"guzzlehttp", "guzzle", ClassScraper},
	{"restsharp", "restsharp", ClassScraper},
	{"winhttp", "winhttp", ClassScraper},
	{"faraday", "faraday", ClassScraper},
	{"libwww-perl", "libwww-perl", ClassScraper},
	{"jakarta commons-httpclient", "jakarta-commons-httpclient", ClassScraper},
	{"commons-httpclient", "commons-httpclient", ClassScraper},
	{"mechanize-go", "mechanize-go", ClassScraper},
	{"mechanize", "mechanize", ClassScraper},
	{"postman", "postman", ClassScraper},
	{"insomnia", "insomnia", ClassScraper},
	{"feedly", "feedly", ClassScraper},
	{"nutch", "nutch", ClassScraper},
}
