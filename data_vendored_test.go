package botdetect

import (
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
