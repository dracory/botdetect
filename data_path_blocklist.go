package botdetect

import "strings"

// == PATH BLOCKLIST ===========================================================

// stackPathBlocklist is the default middleware path blocklist:
// stack-specific probe targets that are malicious on the vast majority
// of real sites (WordPress/PHP/adminer/Exchange scanner traffic) but,
// unlike maliciousPathPatterns, are not universal — a consumer that
// legitimately serves one of these must exclude the token via
// Options.PathBlocklist.
//
// Matching semantics (see MatchesPathBlocklist) are shape-based:
//   - leading "/"  → prefix match on a non-alphanumeric boundary
//     ("/wp" matches "/wp", "/wp-admin", "/wp/x"; not "/wpxyz")
//   - bare alphanumeric → whole-path-segment match
//     ("wp" jails "/wp/login" but never "/newspaper")
//   - anything else → substring
//
// All entries are lowercase; the request path is lowercased before
// matching. Known false-positive-prone tokens — "/new", "/main", "/old",
// "/bk" — probe site-migration leftovers but also collide with real
// routes like /news; exclude them per-app when needed.
var stackPathBlocklist = []string{
	// — prefix probes (backup copies, CMS roots) —
	"/backup",
	"/bc",
	"/bk",
	"/content/sitetree",
	"/main",
	"/new",
	"/old",
	"/tmp/",
	"/wordpress",
	"/wp",
	"/www",

	// — whole-segment probes —
	"alfacgiapi",
	"backup",
	"bc",
	"bin",
	"bk",
	"cgialfa",
	"credentials",
	"db",
	"phpinfo",
	"simpla",
	"wordpress",
	"wp",

	// — substring signatures —
	"${print",
	".aws",
	".ds_store",
	".env",
	".env.example",
	".git",
	".php",
	".vscode",
	".well-known/alfa_data",
	".well-known/alfacgiapi",
	".well-known/cgialfa",
	"_ignition/health-check",
	"alfa_data",
	"aws/credentials",
	"backup/license.txt",
	"blog/license.txt",
	"cgi-bin",
	"cloud-config.yml",
	"components/com_",
	"config.json",
	"content/sitetree",
	"ecp/current/exporttool/microsoft.exchange.ediscovery.exporttool.application",
	"js/mage/cookies.js",
	"meta-inf",
	"print(",
	"search?folderids=0",
	"server-status",
	"shop/license.txt",
	"sites/all/libraries/plupload/examples/upload.php",
	"telerik.web.ui.webresource.axd",
	"telescope/requests",
	"tmp/license.txt",
	"v2/_catalog",
	"www/license.txt",
}

// DefaultPathBlocklist returns a fresh copy of the default
// stack-specific path blocklist used by Middleware. Edit the returned
// slice — e.g. slices.DeleteFunc(list, func(p string) bool { return
// p == "/new" }) — and assign it to Options.PathBlocklist to exclude
// or add tokens.
func DefaultPathBlocklist() []string {
	out := make([]string, len(stackPathBlocklist))
	copy(out, stackPathBlocklist)
	return out
}

// MatchesPathBlocklist reports whether path matches any blocklist
// pattern, using the shape-based semantics documented on
// stackPathBlocklist. A nil or empty pattern list matches nothing;
// an empty path matches nothing.
func MatchesPathBlocklist(path string, patterns []string) bool {
	if path == "" {
		return false
	}
	pathLower := strings.ToLower(path)
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		if matchPathBlocklistPattern(pathLower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func matchPathBlocklistPattern(pathLower, pattern string) bool {
	if strings.HasPrefix(pattern, "/") {
		return hasPathPrefix(pathLower, pattern)
	}
	if isBareSegmentToken(pattern) {
		want := strings.TrimPrefix(pattern, "/")
		for _, seg := range strings.Split(pathLower, "/") {
			if seg == want {
				return true
			}
		}
		return false
	}
	return strings.Contains(pathLower, pattern)
}

// hasPathPrefix reports whether path starts with prefix on a
// non-alphanumeric boundary, so "/wp" matches "/wp", "/wp/foo", and
// "/wp-admin", while "/bc" does not false-positive on root-level GUIDs
// like "/bc840000-e29b-...".
func hasPathPrefix(path, prefix string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	if len(path) == len(prefix) || !isAlphaNum(prefix[len(prefix)-1]) {
		return true
	}
	return !isAlphaNum(path[len(prefix)])
}

// isBareSegmentToken reports whether a blocklist token is a plain
// alphanumeric segment name (letters/digits only). Anything containing
// other characters is a self-anchored signature matched as a substring.
func isBareSegmentToken(token string) bool {
	if token == "" {
		return false
	}
	for i := 0; i < len(token); i++ {
		if !isAlphaNum(token[i]) {
			return false
		}
	}
	return true
}

func isAlphaNum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// matchesPathScope reports whether path matches any pattern in the
// IncludePaths/ExcludePaths syntax: a trailing '*' in a pattern means
// prefix match ("/assets*" matches "/assets/style.css"); without '*'
// the pattern is segment-aware: it matches the path exactly or any
// subpath starting with pattern + "/" ("/api" matches "/api/users",
// not "/apix").
func matchesPathScope(path string, patterns []string) bool {
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		if strings.HasSuffix(pattern, "*") {
			if strings.HasPrefix(path, strings.TrimSuffix(pattern, "*")) {
				return true
			}
			continue
		}
		if path == pattern || strings.HasPrefix(path, pattern+"/") {
			return true
		}
	}
	return false
}
