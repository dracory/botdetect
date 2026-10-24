package botdetect

import (
	"net/http/httptest"
	"testing"
)

func TestDetect_Classification(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want Detection
	}{
		{
			name: "GPTBot is AI training",
			ua:   "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)",
			want: Detection{Bot: true, Name: "gptbot", Class: ClassAI},
		},
		{
			name: "ChatGPT-User is AI user fetcher",
			ua:   "Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)",
			want: Detection{Bot: true, Name: "chatgpt-user", Class: ClassAIUser},
		},
		{
			name: "OAI-SearchBot is search, not collapsed into openaibot",
			ua:   "Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)",
			want: Detection{Bot: true, Name: "oai-searchbot", Class: ClassSearch},
		},
		{
			name: "Googlebot is search",
			ua:   "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			want: Detection{Bot: true, Name: "googlebot", Class: ClassSearch},
		},
		{
			name: "Bytespider is AI",
			ua:   "Mozilla/5.0 (compatible; Bytespider; +https://zhanzhang.toutiao.com/)",
			want: Detection{Bot: true, Name: "bytespider", Class: ClassAI},
		},
		{
			name: "sqlmap is scanner",
			ua:   "sqlmap/1.7",
			want: Detection{Bot: true, Name: "sqlmap", Class: ClassScanner},
		},
		{
			name: "curl is scraper",
			ua:   "curl/8.6.0",
			want: Detection{Bot: true, Name: "curl", Class: ClassScraper},
		},
		{
			name: "AhrefsBot is seo-tool via specific table",
			ua:   "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
			want: Detection{Bot: true, Name: "ahrefsbot", Class: ClassSEOTool},
		},
		{
			name: "Pingdom is monitor",
			ua:   "Pingdom.com_bot_version_1.4_(http://www.pingdom.com/)",
			want: Detection{Bot: true, Name: "pingdom", Class: ClassMonitor},
		},
		{
			name: "Slackbot is social",
			ua:   "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
			want: Detection{Bot: true, Name: "slackbot", Class: ClassSocial},
		},
		{
			name: "TelegramBot (like TwitterBot) matches telegrambot, not twitterbot",
			ua:   "TelegramBot (like TwitterBot)",
			want: Detection{Bot: true, Name: "telegrambot", Class: ClassSocial},
		},
		{
			name: "libcurl-agent matches libcurl-agent, not curl",
			ua:   "libcurl-agent/1.0",
			want: Detection{Bot: true, Name: "libcurl-agent", Class: ClassScraper},
		},
		{
			name: "aiohttp with Python prefix matches aiohttp, not python",
			ua:   "Python/3.14 aiohttp/3.14.1",
			want: Detection{Bot: true, Name: "aiohttp", Class: ClassScraper},
		},
		{
			name: "Chrome-Lighthouse with HeadlessChrome matches chrome-lighthouse",
			ua:   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36 Chrome-Lighthouse",
			want: Detection{Bot: true, Name: "chrome-lighthouse", Class: ClassScraper},
		},
		{
			name: "KeenableBot is AI",
			ua:   "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; KeenableBot/1.0; +https://keenable.ai/bot)",
			want: Detection{Bot: true, Name: "keenablebot", Class: ClassAI},
		},
		{
			name: "Yahoo Slurp is search",
			ua:   "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
			want: Detection{Bot: true, Name: "yahoobot", Class: ClassSearch},
		},
		{
			name: "uasurfer fleet fallback keeps fleet name",
			ua:   "Mozilla/5.0 (compatible; Mediapartners-Google/2.1)",
			want: Detection{Bot: true, Name: "googlebot", Class: ClassSearch},
		},
		{
			name: "generic uasurfer bot is ClassOther",
			ua:   "Mozilla/5.0 (compatible; SomeNewBot/1.0)",
			want: Detection{Bot: true, Name: "bot", Class: ClassOther},
		},
		{
			name: "uasurfer-caught generic scraper name is ClassOther",
			ua:   "SomeScraper/2.0",
			want: Detection{Bot: true, Name: "bot", Class: ClassOther},
		},
		{
			name: "real browser is not a bot",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			want: Detection{Bot: false},
		},
		{
			name: "empty UA",
			ua:   "",
			want: Detection{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Detect(tt.ua)
			if got != tt.want {
				t.Errorf("Detect(%q)\n  got:  %+v\n  want: %+v", tt.ua, got, tt.want)
			}
			// IsBot must agree with Detect.
			if IsBot(tt.ua) != got.Bot {
				t.Errorf("IsBot(%q) = %v, but Detect().Bot = %v", tt.ua, IsBot(tt.ua), got.Bot)
			}
		})
	}
}

func TestDetectRequest(t *testing.T) {
	if got := DetectRequest(nil); got != (Detection{}) {
		t.Errorf("DetectRequest(nil) = %+v, expected zero Detection", got)
	}

	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("User-Agent", "curl/8.6.0")
	got := DetectRequest(r)
	if !got.Bot || got.Name != "curl" {
		t.Errorf("DetectRequest(curl) = %+v, expected curl bot", got)
	}
}
