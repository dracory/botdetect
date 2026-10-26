package botdetect

import (
	_ "embed"
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
)

// Vendored pattern data from JayBizzle/Crawler-Detect (MIT), refreshed via
// scripts/update-data.sh. Three lists:
//   - crawlers.json:   regex patterns matching bot/crawler user-agents
//   - exclusions.json: regexes stripped from the UA before matching — the
//     upstream false-positive defense (browser/OS chrome tokens)
//   - headers.json:    PHP $_SERVER keys naming headers that may carry a UA
//     or crawler contact string (e.g. From: googlebot(at)googlebot.com)

//go:embed data/crawlers.json
var crawlersJSON []byte

//go:embed data/exclusions.json
var exclusionsJSON []byte

//go:embed data/headers.json
var headersJSON []byte

var (
	crawlersRegex    *regexp.Regexp // single case-insensitive alternation
	exclusionsRegex  *regexp.Regexp
	uaCarrierHeaders []string // normalized from headers.json
)

func init() {
	var crawlers, exclusions, headers []string
	if err := json.Unmarshal(crawlersJSON, &crawlers); err != nil {
		slog.Error("botdetect: invalid crawlers.json", "error", err)
	}
	if err := json.Unmarshal(exclusionsJSON, &exclusions); err != nil {
		slog.Error("botdetect: invalid exclusions.json", "error", err)
	}
	if err := json.Unmarshal(headersJSON, &headers); err != nil {
		slog.Error("botdetect: invalid headers.json", "error", err)
	}

	crawlersRegex = compileAlternation(crawlers)
	exclusionsRegex = compileAlternation(exclusions)
	uaCarrierHeaders = normalizeCarrierHeaders(headers)
}

// compileAlternation joins patterns into one case-insensitive regex.
// Upstream patterns are PHP-flavored: "\/" is unescaped to "/", trailing
// literal negative lookaheads are rewritten to RE2-safe alternations, and
// patterns that still fail to compile are skipped rather than fatal.
func compileAlternation(patterns []string) *regexp.Regexp {
	valid := make([]string, 0, len(patterns))
	for _, p := range patterns {
		p = sanitizePattern(strings.ReplaceAll(p, `\/`, "/"))
		if _, err := regexp.Compile("(?i)" + p); err != nil {
			slog.Error("botdetect: skipping invalid vendored pattern", "pattern", p, "error", err)
			continue
		}
		valid = append(valid, p)
	}
	if len(valid) == 0 {
		return nil
	}
	return regexp.MustCompile(`(?i)(` + strings.Join(valid, ")|(") + `)`)
}

var trailingNegLookahead = regexp.MustCompile(`\(\?!([^()\\]*(?:\\.[^()\\]*)*)\)$`)

// sanitizePattern rewrites PHP/PCRE constructs RE2 rejects. Currently only
// a trailing literal negative lookahead, e.g. "Yandex(?!Search)", which is
// expanded into an equivalent alternation. Non-literal or mid-pattern
// lookarounds are left for compileAlternation to skip.
func sanitizePattern(p string) string {
	for {
		m := trailingNegLookahead.FindStringSubmatchIndex(p)
		if m == nil {
			return p
		}
		lit, ok := unescapeLiteral(p[m[2]:m[3]])
		if !ok {
			return p
		}
		p = p[:m[0]] + notFollowedBy(lit)
	}
}

// unescapeLiteral returns the literal string s denotes ("\." → "."), or
// ok=false if s contains unescaped regex metacharacters.
func unescapeLiteral(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			if i >= len(s) {
				return "", false
			}
		} else if strings.IndexByte(`.^$*+?[]{}|()`, s[i]) >= 0 {
			return "", false
		}
		b.WriteByte(s[i])
	}
	return b.String(), true
}

// notFollowedBy returns a RE2-safe subpattern matching only when s does not
// follow: "Search" → (?:$|[^S]|S(?:$|[^e]|e(?:$|[^a]|a(?:$|[^r]|r(?:$|[^c]|c(?:$|[^h])))))).
func notFollowedBy(s string) string {
	runes := []rune(s)
	if len(runes) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("(?:$|[^")
	b.WriteString(charClassEscape(runes[0]))
	b.WriteByte(']')
	for i := 1; i < len(runes); i++ {
		b.WriteByte('|')
		b.WriteString(regexp.QuoteMeta(string(runes[i-1])))
		b.WriteString("(?:$|[^")
		b.WriteString(charClassEscape(runes[i]))
		b.WriteByte(']')
	}
	b.WriteString(strings.Repeat(")", len(runes)))
	return b.String()
}

// charClassEscape escapes a rune for use inside [^...].
func charClassEscape(r rune) string {
	switch r {
	case ']', '\\', '^', '-':
		return `\` + string(r)
	}
	return string(r)
}

// normalizeCarrierHeaders converts PHP $_SERVER keys to canonical HTTP
// header names ("HTTP_X_OPERAMINI_PHONE_UA" → "X-Operamini-Phone-Ua") and
// drops User-Agent itself (checked directly by callers).
func normalizeCarrierHeaders(keys []string) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		name := strings.TrimPrefix(k, "HTTP_")
		name = http.CanonicalHeaderKey(strings.ReplaceAll(name, "_", "-"))
		if strings.EqualFold(name, "User-Agent") {
			continue
		}
		out = append(out, name)
	}
	return out
}
