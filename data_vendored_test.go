package botdetect

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// Vendored data must compile and be non-empty — a corrupt refresh of the
// JSON files should fail here, not silently degrade detection.
func TestVendoredData_Loads(t *testing.T) {
	if crawlersRegex == nil {
		t.Fatal("crawlersRegex is nil — data/crawlers.json failed to load or compile")
	}
	if exclusionsRegex == nil {
		t.Fatal("exclusionsRegex is nil — data/exclusions.json failed to load or compile")
	}
	if len(uaCarrierHeaders) == 0 {
		t.Fatal("uaCarrierHeaders is empty — data/headers.json failed to load or normalize")
	}
	// User-Agent itself must not be a carrier header.
	for _, h := range uaCarrierHeaders {
		if strings.EqualFold(h, "User-Agent") {
			t.Fatalf("uaCarrierHeaders contains %q — User-Agent is checked directly", h)
		}
	}
}

// The vendored list should catch crawlers our own patterns don't know.
func TestDetect_VendoredCrawlers(t *testing.T) {
	uas := []string{
		"Mozilla/5.0 (compatible; SeznamBot/4.0; +http://napoveda.seznam.cz/seznambot-intro/)",
		"Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)",
		"Mozilla/5.0 (compatible; Yeti/1.1; +http://naver.me/bot)",
	}
	for _, ua := range uas {
		if !IsBot(ua) {
			t.Errorf("expected IsBot(%q) = true via vendored list, got false", ua)
		}
	}
}

// Real browser UAs must still pass the exclusions strip + crawler regex
// without matching.
func TestDetect_VendoredNoFalsePositives(t *testing.T) {
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Gecko/20100101 Firefox/130.0",
	}
	for _, ua := range uas {
		if IsBot(ua) {
			t.Errorf("expected IsBot(%q) = false (real browser), got true", ua)
		}
	}
}

// PHP-flavored patterns that RE2 can't express directly (trailing literal
// negative lookaheads) must be rewritten, not skipped — skipping loses real
// detections like YandexBot.
func TestCompileAlternation_NegativeLookahead(t *testing.T) {
	re := compileAlternation([]string{`Yandex(?!Search)`})
	if re == nil {
		t.Fatal("compileAlternation returned nil for Yandex(?!Search)")
	}
	if !re.MatchString("Mozilla/5.0 (compatible; YandexBot/3.0)") {
		t.Error("expected YandexBot UA to match")
	}
	if re.MatchString("YandexSearch/5.0") {
		t.Error("expected YandexSearch UA NOT to match — (?!Search) exclusion lost")
	}
}

// Every vendored pattern must compile — a skip means silently lost coverage.
func TestVendoredData_NoSkippedPatterns(t *testing.T) {
	var crawlers, exclusions []string
	if err := json.Unmarshal(crawlersJSON, &crawlers); err != nil {
		t.Fatalf("unmarshal crawlers.json: %v", err)
	}
	if err := json.Unmarshal(exclusionsJSON, &exclusions); err != nil {
		t.Fatalf("unmarshal exclusions.json: %v", err)
	}
	for _, p := range append(crawlers, exclusions...) {
		p = strings.ReplaceAll(p, `\/`, "/")
		if _, err := regexp.Compile("(?i)" + sanitizePattern(p)); err != nil {
			t.Errorf("pattern %q failed to compile after sanitize: %v", p, err)
		}
	}
}
