package botdetect

import (
	"log/slog"
	"net/netip"
	"net/url"
	"strings"
)

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

// == PUBLIC FUNCTIONS =========================================================

// IsBot checks whether a user-agent string belongs to a bot, crawler, or
// automated tool. The primary verdict comes from uasurfer's IsBot()
// (conventional bot tokens, contact-URL convention, headless browsers,
// named crawler fleets). Our own pattern lists then act as a supplementary
// pass for scanners and crawlers uasurfer deliberately skips.
// An empty user-agent returns false — a missing UA is not, by itself,
// evidence of a bot.
func IsBot(userAgent string) bool {
	return Detect(userAgent).Bot
}

// matchUserAgentPattern reports whether a lowercased user-agent matches our
// broad word-boundary pattern list (bot, crawler, spider, scraper, slurp),
// returning the matched pattern. Specific substring patterns are checked
// earlier via botClassifications in detectImpl.
func matchUserAgentPattern(uaLower string) (string, bool) {
	for _, pattern := range botUserAgentBroadPatterns {
		if matchWordBoundary(uaLower, pattern) {
			return pattern, true
		}
	}

	return "", false
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
