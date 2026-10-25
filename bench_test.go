package botdetect

import (
	"strings"
	"testing"
)

var benchUAs = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	"curl/8.6.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (compatible; SeznamBot/4.0; +http://napoveda.seznam.cz/seznambot-intro/)",
}

func BenchmarkIsBot(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		IsBot(benchUAs[i%len(benchUAs)])
	}
}

// BenchmarkDetectCold bypasses the UA cache (detectImpl directly) so the
// real cost of the uasurfer parse + vendored regex pass is measured —
// the IsBot benchmark above resolves to cache hits after warmup.
func BenchmarkDetectCold(b *testing.B) {
	lower := make([]string, len(benchUAs))
	for i, ua := range benchUAs {
		lower[i] = strings.ToLower(ua)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		i2 := i % len(benchUAs)
		detectImpl(benchUAs[i2], lower[i2], nil)
	}
}
