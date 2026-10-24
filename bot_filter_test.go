package botdetect

import (
	"testing"
)

// == IsBot TESTS =============================================================

func TestIsBot_UasurferNamedBots(t *testing.T) {
	// Named crawler fleets only detected via uasurfer's IsBot() — these
	// contain no "bot"-ish token our own patterns would match.
	uas := []string{
		"Mozilla/5.0 (compatible; GoogleOther/1.0; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; Mediapartners-Google/2.1)",
		"Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)",
		"Mozilla/5.0 (compatible; Google-InspectionTool/1.0)",
	}
	for _, ua := range uas {
		if !IsBot(ua) {
			t.Errorf("expected IsBot(%q) = true (uasurfer named bot), got false", ua)
		}
	}
}

func TestIsBot_DeviceBotUserAgents(t *testing.T) {
	deviceBotUAs := []string{
		"YandexBot",
		"ClaudeBot",
		"Googlebot",
		"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
		"Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
	}
	for _, ua := range deviceBotUAs {
		if !IsBot(ua) {
			t.Errorf("IsBot(%q) = false, expected true", ua)
		}
	}
}

func TestIsBot_KnownBots(t *testing.T) {
	botUAs := []string{
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
		"Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
		"Mozilla/5.0 (compatible; DuckDuckBot/1.1; +http://duckduckgo.com/duckduckbot.html)",
		"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
		"Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
		"Mozilla/5.0 (compatible; PetalBot;+https://webmaster.petalsearch.com/site/petalbot)",
		"Mozilla/5.0 (compatible; Bytespider; spider'bot, +https://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; AwarioBot/1.0; +https://awario.com/bots.html)",
		"cve-2026-63030/1.0",
		"curl/7.88.1",
		"Wget/1.21.4",
		"python-requests/2.31.0",
		"Go-http-client/1.1",
		"okhttp/4.12.0",
		"HeadlessChrome/120.0.6099.109",
		"phantomjs",
		"selenium/4.15.0",
		"Puppeteer/1.20.0",
		"Cypress/13.6.0",
		"Chrome-Lighthouse",
		"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
		"Twitterbot/1.0",
		"LinkedInBot/1.0 (compatible; LinkedInApp/1.0)",
		"TelegramBot (like TwitterBot)",
		"AppleBot/0.1; +http://www.apple.com/go/applebot.html)",
		"feedly/1.0",
		"Pingdom.com_bot_version_1.4_(http://www.pingdom.com)",
		"Datadog/Synthetic HTTP/1.0",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; KeenableBot/1.0; +https://keenable.ai/bot)",
		"TheWebReport/1.0; +https://theweb.report",
		"archive.org_bot",
		"IA_Archiver",
		// Python HTTP clients — stdlib urllib and aiohttp.
		"Python/3.14 aiohttp/3.14.1", // real scraper UA seen in production
		"Python/3.12 urllib/3.12",    // stdlib urllib format
		"Python-urllib/3.10",         // stdlib urllib format
		"Python/3.10",                // bare stdlib format
		"aiohttp/3.14.1",             // aiohttp without Python prefix
		// AI/LLM crawlers without "bot"/"crawler"/"spider" keywords.
		"ChatGPT-User/1.0",
		"anthropic-ai/1.0",
		"Claude-Web/1.0",
		"Google-Extended/1.0",
		"cohere-ai/1.0",
		"Meta-ExternalAgent/1.1",
		"Meta-ExternalFetcher/1.1",
		"omgili/0.5",
		// Additional HTTP client libraries.
		"libwww-perl/6.43",
		"Java/1.8.0_301",
		"Jakarta Commons-HttpClient/3.1",
		"Commons-HttpClient/3.1",
		"GuzzleHttp/7.0",
		"Faraday/2.7",
		"RestSharp/106.12",
		"dart:io (2.19)",
		"winhttp",
		"libcurl-agent/1.0",
		"Mozilla/4.0 (compatible; Netcraft Web Server Survey)",
		// Security scanners
		"sqlmap/1.5.11#stable",
		"Nikto/2.1.6",
		"masscan/1.3.2",
		"zgrab/0.x",
		"Nmap Scripting Engine",
	}

	for _, ua := range botUAs {
		if !IsBot(ua) {
			t.Errorf("IsBot(%q) = false, expected true", ua)
		}
	}
}

func TestIsBot_RealBrowsers(t *testing.T) {
	realUAs := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	}

	for _, ua := range realUAs {
		if IsBot(ua) {
			t.Errorf("IsBot(%q) = true, expected false", ua)
		}
	}
}

func TestIsBot_EmptyAndEdgeCases(t *testing.T) {
	if IsBot("") {
		t.Error("IsBot(\"\") = true, expected false")
	}
	if IsBot("Mozilla/5.0") {
		t.Error("IsBot(\"Mozilla/5.0\") = true, expected false")
	}
}

func TestIsBot_CaseInsensitive(t *testing.T) {
	if !IsBot("GOOGLEBOT/2.1") {
		t.Error("IsBot(\"GOOGLEBOT/2.1\") = false, expected true (case-insensitive)")
	}
	if !IsBot("CURL/7.88") {
		t.Error("IsBot(\"CURL/7.88\") = false, expected true (case-insensitive)")
	}
}

func TestIsBot_WordBoundary(t *testing.T) {
	// "bot" followed by / ; ) . space or end-of-string should match.
	matchingUAs := []string{
		"Mozilla/5.0 (compatible; Googlebot/2.1)",
		"Mozilla/5.0 (compatible; SemrushBot/7~bl)",
		"Mozilla/5.0 (compatible; AppleBot)",
		"Mozilla/5.0 (compatible; SomeBot; +http://example.com)",
		"SomeBot",
		"Mozilla/5.0 (compatible; MyBot. Version 1.0)",
	}
	for _, ua := range matchingUAs {
		if !IsBot(ua) {
			t.Errorf("IsBot(%q) = false, expected true (word-boundary match)", ua)
		}
	}

	// UAs where "bot" appears inside a word but NOT as a standalone token
	// should NOT match on the broad "bot" pattern. These may still match if
	// they contain a specific pattern, but the "bot" broad pattern should
	// not be the reason they match.
	//
	// "iBotonic" contains "bot" but it's inside a word — no boundary.
	// "RoboBotonic" same thing.
	// We can't test these directly with IsBot since other patterns might
	// match, but we can test matchWordBoundary directly.
	if matchWordBoundary("mozilla/5.0 (ibotonic/1.0)", "bot") {
		t.Error("matchWordBoundary should not match 'bot' inside 'ibotonic'")
	}
	if matchWordBoundary("mozilla/5.0 (robobotonic/1.0)", "bot") {
		t.Error("matchWordBoundary should not match 'bot' inside 'robobotonic'")
	}
	// "bot" at end of string is a valid boundary.
	if !matchWordBoundary("somebot", "bot") {
		t.Error("matchWordBoundary should match 'bot' at end of string")
	}
	// "bot/" has a boundary (slash).
	if !matchWordBoundary("googlebot/2.1", "bot") {
		t.Error("matchWordBoundary should match 'bot/' ")
	}
	// "bot;" has a boundary (semicolon).
	if !matchWordBoundary("googlebot; +http://x.com", "bot") {
		t.Error("matchWordBoundary should match 'bot;'")
	}
	// "bot)" has a boundary (closing paren).
	if !matchWordBoundary("(googlebot)", "bot") {
		t.Error("matchWordBoundary should match 'bot)'")
	}
	// "bot " has a boundary (space).
	if !matchWordBoundary("googlebot 2.1", "bot") {
		t.Error("matchWordBoundary should match 'bot '")
	}
	// "bot." has a boundary (dot).
	if !matchWordBoundary("googlebot. v2", "bot") {
		t.Error("matchWordBoundary should match 'bot.'")
	}
	// "bot123" — digit after, NOT a boundary.
	if matchWordBoundary("googlebot123", "bot") {
		t.Error("matchWordBoundary should not match 'bot123' (digit is not a boundary)")
	}
	// "botbot" — first "bot" is followed by "b" (alpha), not a boundary.
	// Second "bot" is at end of string, IS a boundary.
	if !matchWordBoundary("botbot", "bot") {
		t.Error("matchWordBoundary should match second 'bot' in 'botbot' (end of string)")
	}
}

// == IsReferrerSpam TESTS ====================================================

func TestIsReferrerSpam_KnownSpam(t *testing.T) {
	spamReferrers := []string{
		"https://semalt.com/",
		"http://darodar.com/",
		"https://www.priceg.com/",
		"https://best-seo-offer.com/seo.php",
		"http://ilovevitaly.com/",
		"https://social-buttons.com/",
		"http://hulfingtonpost.com/",
		"https://adsterra.com/",
	}

	for _, ref := range spamReferrers {
		if !IsReferrerSpam(ref) {
			t.Errorf("IsReferrerSpam(%q) = false, expected true", ref)
		}
	}
}

func TestIsReferrerSpam_LegitimateReferrers(t *testing.T) {
	legitReferrers := []string{
		"https://www.google.com/search?q=test",
		"https://www.bing.com/search?q=test",
		"https://duckduckgo.com/",
		"https://github.com/user/repo",
		"https://twitter.com/user/status/123",
		"https://www.facebook.com/page",
		"https://www.linkedin.com/in/user",
		"https://stackoverflow.com/questions/123",
		"https://news.ycombinator.com/item?id=123",
		"",
	}

	for _, ref := range legitReferrers {
		if IsReferrerSpam(ref) {
			t.Errorf("IsReferrerSpam(%q) = true, expected false", ref)
		}
	}
}

func TestIsReferrerSpam_SubdomainMatch(t *testing.T) {
	if !IsReferrerSpam("https://sub.semalt.com/") {
		t.Error("IsReferrerSpam(\"https://sub.semalt.com/\") = false, expected true (subdomain match)")
	}
	if !IsReferrerSpam("https://www1.social-buttons.com/") {
		t.Error("IsReferrerSpam(\"https://www1.social-buttons.com/\") = false, expected true (subdomain match)")
	}
}

func TestIsReferrerSpam_BareDomain(t *testing.T) {
	if !IsReferrerSpam("semalt.com") {
		t.Error("IsReferrerSpam(\"semalt.com\") = false, expected true")
	}
	if !IsReferrerSpam("darodar.com") {
		t.Error("IsReferrerSpam(\"darodar.com\") = false, expected true")
	}
}

func TestIsReferrerSpam_BareDomainWithPath(t *testing.T) {
	// A bare domain carrying a path has no scheme, so url.Parse yields no
	// Host — the path must be stripped before matching.
	if !IsReferrerSpam("semalt.com/foo") {
		t.Error("IsReferrerSpam(\"semalt.com/foo\") = false, expected true")
	}
}

// == IsDataCenterIP TESTS ====================================================

func TestIsDataCenterIP_KnownRanges(t *testing.T) {
	ips := []string{
		"3.1.2.3",       // AWS lower 3.x
		"3.128.1.2",     // AWS upper 3.x
		"13.107.21.200", // AWS/Microsoft
		"16.1.2.3",      // AWS
		"18.128.1.2",    // AWS 18.x leased
		"52.1.2.3",      // AWS
		"35.192.1.2",    // GCP
		"35.200.1.2",    // GCP
		"20.1.2.3",      // Azure
		"40.1.2.3",      // Azure
		"159.65.1.2",    // DigitalOcean
		"167.99.1.2",    // DigitalOcean
		"129.146.1.2",   // Oracle Cloud
		"129.150.1.2",   // Oracle Cloud
		// Hetzner
		"23.88.1.2",
		"78.46.1.2",
		"135.181.1.2",
		"159.69.1.2",
		"95.216.1.2",
		// OVH
		"37.187.1.2",
		"51.77.1.2",
		"51.254.1.2",
		"94.23.1.2",
		"176.31.1.2",
		// Linode / Akamai
		"45.79.1.2",
		"172.104.1.2",
		// Vultr
		"45.32.1.2",
		"45.76.1.2",
		"108.61.1.2",
		// Alibaba Cloud
		"47.52.1.2",
		"120.24.1.2",
		"139.196.1.2",
		// Tencent Cloud
		"49.51.1.2",
		"119.29.1.2",
		"129.226.1.2",
		// Contabo
		"5.189.128.1",
		"161.97.1.2",
		// Scaleway / Online.net — includes the incident IP
		"51.15.217.215",
		"62.210.1.2",
		"163.172.1.2",
		// IBM Cloud
		"129.40.1.2",
		"158.85.1.2",
		// UpCloud
		"94.237.1.2",
		// DigitalOcean (146.190.x — moved from UpCloud after verification)
		"146.190.1.2",
	}

	for _, ip := range ips {
		if !IsDataCenterIP(ip) {
			t.Errorf("IsDataCenterIP(%q) = false, expected true", ip)
		}
	}
}

func TestIsDataCenterIP_IPv6Ranges(t *testing.T) {
	ips := []string{
		"2600:1f00:1::1",   // AWS
		"::ffff:52.1.2.3",  // IPv4-mapped IPv6 (AWS)
		"::ffff:3.128.1.2", // IPv4-mapped IPv6 (AWS upper 3.x)
		"2600:1900:1::1",   // GCP
		"2603:1::1",        // Azure
		"2a01:4f8:1::1",    // Hetzner
		"2001:41d0:1::1",   // OVH
		"2600:3c00:1::1",   // Linode
		"2001:19f0:1::1",   // Vultr
		"2400:3200:1::1",   // Alibaba
		"2402:4e00:1::1",   // Tencent
		"2001:bc8:1::1",    // Scaleway
	}

	for _, ip := range ips {
		if !IsDataCenterIP(ip) {
			t.Errorf("IsDataCenterIP(%q) = false, expected true (IPv6 datacenter)", ip)
		}
	}
}

func TestIsDataCenterIP_ResidentialIPs(t *testing.T) {
	ips := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"8.8.8.8",
		"1.1.1.1",
		"203.0.113.1",
		"198.51.100.1",
		"192.0.2.1",
	}

	for _, ip := range ips {
		if IsDataCenterIP(ip) {
			t.Errorf("IsDataCenterIP(%q) = true, expected false", ip)
		}
	}
}

func TestIsDataCenterIP_EmptyAndInvalid(t *testing.T) {
	if IsDataCenterIP("") {
		t.Error("IsDataCenterIP(\"\") = true, expected false")
	}
	if IsDataCenterIP("not-an-ip") {
		t.Error("IsDataCenterIP(\"not-an-ip\") = true, expected false")
	}
}

// == IsBotPath / IsMaliciousPath TESTS ========================================

func TestIsBotPath_KnownBotFiles(t *testing.T) {
	paths := []string{
		"/robots.txt",
		"[GET] /robots.txt",
		"/ads.txt",
		"/app-ads.txt",
		"/sitemap.xml",
		"/humans.txt",
		"/security.txt",
		"/.well-known/security.txt",
		"/BingSiteAuth.xml",
		"/dnt-policy.txt",
		"/sellers.json",
		"/browserconfig.xml",
		"/llms.txt",
		"/llms-full.txt",
		"/ai.txt",
		"/sitemap_index.xml",
		"/sitemap-index.xml",
		"/sitemap.xml.gz",
		"/crossdomain.xml",
		"/clientaccesspolicy.xml",
	}

	for _, p := range paths {
		if !IsBotPath(p) {
			t.Errorf("expected IsBotPath(%q) = true, got false", p)
		}
	}
}

func TestIsBotPath_WithQueryString(t *testing.T) {
	paths := []string{
		"/robots.txt?v=1",
		"/ads.txt?nocache=123",
		"/sitemap.xml?ts=456",
		"[GET] /robots.txt?cb=789",
	}

	for _, p := range paths {
		if !IsBotPath(p) {
			t.Errorf("expected IsBotPath(%q) = true, got false", p)
		}
	}
}

func TestIsBotPath_NormalPages(t *testing.T) {
	paths := []string{
		"/courses/go",
		"/home",
		"/shop/product/123",
		"/blog/post",
		"/favicon.ico",
		"/.well-known/change-password",
		"",
	}

	for _, p := range paths {
		if IsBotPath(p) {
			t.Errorf("expected IsBotPath(%q) = false, got true", p)
		}
	}
}

func TestIsMaliciousPath_UniversalMalicious(t *testing.T) {
	paths := []string{
		"/.env",
		"[GET] /.env",
		"/config/.env",
		"/.env.bak",
		"/.env.old",
		"/.env.local",
		"/.env.production",
		"/.git/config",
		"/.svn/entries",
		"/.htpasswd",
		"/.htpasswd.bak",
		"/.htpasswd.old",
		"/shell.php",
		"/uploads/shell.php",
		// Credential / metadata leak patterns.
		"/.aws/credentials",
		"[GET] /.aws/credentials",
		"/.ssh/id_rsa",
		"/.ssh/config",
		"/id_rsa",
		"/.DS_Store",
		"/.npmrc",
		// AI-agent config / instruction file probes.
		"/AGENTS.md",
		"/.claude/settings.json",
		"/.cursor/mcp.json",
		"/.cursorrules",
		"/.windsurfrules",
		"/.continue/config.json",
		"/claude.md",
		"/gemini.md",
		"/.github/copilot-instructions.md",
		"/mcp.json",
		"/claude_desktop_config.json",
	}

	for _, p := range paths {
		if !IsMaliciousPath(p) {
			t.Errorf("expected IsMaliciousPath(%q) = true, got false", p)
		}
	}
}

func TestIsMaliciousPath_StackDependentNotIncluded(t *testing.T) {
	// These patterns are stack-dependent and should NOT be flagged by the
	// library — consumers add them based on their tech stack.
	paths := []string{
		"/index.php",    // legitimate on a PHP site
		"/wp-admin/",    // legitimate on a WordPress site
		"/wp-login.php", // legitimate on a WordPress site
		"/xmlrpc.php",   // legitimate on a WordPress site
		"/adminer.php",  // legitimate if adminer is installed
		"/config.php",   // legitimate on a PHP site
		"/index.asp",    // legitimate on a classic ASP site
		"/index.aspx",   // legitimate on an ASP.NET site
		"/index.jsp",    // legitimate on a Java site
		"/script.py",    // legitimate on a Python site
		"/script.rb",    // legitimate on a Ruby site
		"/script.cgi",   // legitimate on a CGI site
		"/script.pl",    // legitimate on a Perl site
	}

	for _, p := range paths {
		if IsMaliciousPath(p) {
			t.Errorf("expected IsMaliciousPath(%q) = false (stack-dependent), got true", p)
		}
	}
}

func TestIsMaliciousPath_WithQueryString(t *testing.T) {
	paths := []string{
		"/.env?nocache=123",
		"/.git/config?ref=heads",
		"/shell.php?cmd=ls",
	}

	for _, p := range paths {
		if !IsMaliciousPath(p) {
			t.Errorf("expected IsMaliciousPath(%q) = true, got false", p)
		}
	}
}

func TestIsMaliciousPath_NormalPages(t *testing.T) {
	paths := []string{
		"/courses/go",
		"/home",
		"/robots.txt",          // bot file, not malicious
		"/ads.txt",             // bot file, not malicious
		"/my.envfile.js",       // contains .env but not a suffix of the filename
		"/how-shell.php-works", // contains shell.php but not a suffix of the filename
		"/.github/workflows",   // .github != .git
		"/.envrc",              // shares the .env prefix but is a different file
		"/.envelope.yml",       // shares the .env prefix but is a different file
		"/.clinerulesx",        // shares the .clinerules prefix but is a different file
		"",
	}

	for _, p := range paths {
		if IsMaliciousPath(p) {
			t.Errorf("expected IsMaliciousPath(%q) = false, got true", p)
		}
	}
}

func TestBotPathPatterns_ReturnsCopy(t *testing.T) {
	patterns := BotPathPatterns()
	if len(patterns) == 0 {
		t.Fatal("expected non-empty pattern list")
	}
	// Mutating the returned slice should not affect the package-level var.
	original := patterns[0]
	patterns[0] = "mutated"
	again := BotPathPatterns()
	if again[0] != original {
		t.Fatal("BotPathPatterns() should return a copy, not the internal slice")
	}
}

func TestMaliciousPathPatterns_ReturnsCopy(t *testing.T) {
	patterns := MaliciousPathPatterns()
	if len(patterns) == 0 {
		t.Fatal("expected non-empty pattern list")
	}
	original := patterns[0]
	patterns[0] = "mutated"
	again := MaliciousPathPatterns()
	if again[0] != original {
		t.Fatal("MaliciousPathPatterns() should return a copy, not the internal slice")
	}
}
