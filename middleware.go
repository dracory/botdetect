package botdetect

import (
	"net"
	"net/http"
	"strings"
	"time"
)

// Options configures Middleware.
type Options struct {
	// AllowedClasses lets detected bots of these classes through (e.g.
	// ClassSearch for SEO). Empty means every detected bot is blocked.
	// Humans (Bot == false) are always allowed.
	AllowedClasses map[BotClass]bool

	// DisableMaliciousPathBlock rejects requests to universally malicious
	// paths (.env, .git/, shell.php, ...) regardless of user-agent.
	// Enabled unless explicitly set to true.
	DisableMaliciousPathBlock bool

	// PathBlocklist adds stack-specific probe patterns (wp, .php,
	// cgi-bin, backup, ...) checked by MatchesPathBlocklist on top of
	// the universal IsMaliciousPath set. nil means
	// DefaultPathBlocklist(); pass an empty slice to disable, or an
	// edited copy of DefaultPathBlocklist() to exclude/add tokens —
	// e.g. "/new" false-positives on routes like /news.
	// Ignored when DisableMaliciousPathBlock is true.
	PathBlocklist []string

	// ExcludePaths bypasses every check — detection, blocking, and
	// jails — for matching request paths. A trailing '*' means prefix
	// match; otherwise the pattern is segment-aware (exact path or
	// subpath). Matching is case-sensitive and exact by design —
	// exclusions are explicit opt-outs, not fingerprints (unlike
	// PathBlocklist, which is matched case-insensitively).
	// Use it for bearer-authed machine endpoints and assets that must
	// keep working for visitors on a jailed shared IP.
	ExcludePaths []string

	// JailDuration > 0 enables IP jailing: after any block decision the
	// client IP is rejected for this duration on a cheap map lookup,
	// before any detection work. 0 (default) keeps per-request
	// blocking only. Jails live in process memory — they do not
	// survive restarts and are not shared across replicas.
	JailDuration time.Duration

	// GetIP resolves the client IP used as the jail key. The default
	// reads RemoteAddr only — matching the challenge package, which
	// does not trust proxy headers by default. Consumers behind a
	// trusted proxy should supply an X-Forwarded-For-aware
	// implementation; note that trusting client-set headers lets an
	// attacker jail arbitrary IPs, so only honor them from a known
	// proxy chain.
	//
	// The inverse failure exists too: if every request arrives from a
	// public-IP edge (e.g. a CDN's egress) and GetIP keys on RemoteAddr
	// or a private-peer heuristic, one scanner jails the shared egress
	// IP and every user behind it eats 403s for the jail term — a
	// self-inflicted outage. Behind such an edge, GetIP must honor XFF
	// from a configured trusted-proxy CIDR list (CDNs publish theirs),
	// not just private ranges.
	GetIP func(r *http.Request) string

	// ObserveOnly detects and reports via OnDetection but never blocks
	// and never jails.
	ObserveOnly bool

	// OnDetection is called for every request that Detect flags as a
	// bot, that hits a malicious path, or that arrives from a jailed IP
	// — before the block decision. Useful for logging or metrics.
	OnDetection func(r *http.Request, d Detection)

	// OnJail is called once when an IP is jailed — not on every jailed
	// hit. Only fires when JailDuration > 0.
	OnJail func(ip string, r *http.Request, d Detection)

	// BlockResponse writes the rejection for blocked and jailed
	// requests. Defaults to a 403 "Forbidden".
	BlockResponse http.HandlerFunc
}

// Middleware returns HTTP middleware that blocks bots (by class policy)
// and malicious-path probes before they reach the wrapped handler, with
// optional IP jailing for repeat offenders.
//
// /robots.txt is never blocked: RFC 9309 defines a 4xx robots.txt as "no
// crawl restrictions", so blocking it would tell crawlers everything is
// allowed.
//
// Evaluation order: ExcludePaths → robots.txt → jailed-IP check →
// malicious paths (IsMaliciousPath + PathBlocklist) → UA detection.
// Any block decision jails the client IP when JailDuration > 0;
// ObserveOnly never blocks or jails.
func Middleware(next http.Handler, opts Options) http.Handler {
	block := opts.BlockResponse
	if block == nil {
		block = func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Forbidden", http.StatusForbidden)
		}
	}

	pathBlocklist := opts.PathBlocklist
	if pathBlocklist == nil && !opts.DisableMaliciousPathBlock {
		pathBlocklist = DefaultPathBlocklist()
	}

	var jail *jailStore
	if opts.JailDuration > 0 {
		jail = newJailStore(opts.JailDuration)
	}

	getIP := opts.GetIP
	if getIP == nil {
		getIP = clientIP
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r == nil {
			next.ServeHTTP(w, r)
			return
		}

		if matchesExcludedPath(r.URL.Path, opts.ExcludePaths) {
			next.ServeHTTP(w, r)
			return
		}

		// Never block robots.txt — see doc comment.
		if isRobotsPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		var ip string
		if jail != nil {
			ip = getIP(r)
			if jail.jailed(ip) {
				d := Detection{Bot: true, Name: "jailed", Class: ClassScanner}
				if opts.OnDetection != nil {
					opts.OnDetection(r, d)
				}
				block(w, r)
				return
			}
		}

		if !opts.DisableMaliciousPathBlock &&
			(IsMaliciousPath(r.URL.Path) || MatchesPathBlocklist(r.URL.Path, pathBlocklist)) {
			d := Detection{Bot: true, Name: "malicious-path", Class: ClassScanner}
			if opts.OnDetection != nil {
				opts.OnDetection(r, d)
			}
			if !opts.ObserveOnly {
				if jail != nil && jail.jail(ip) && opts.OnJail != nil {
					opts.OnJail(ip, r, d)
				}
				block(w, r)
				return
			}
		}

		d := DetectRequest(r)
		if d.Bot {
			if opts.OnDetection != nil {
				opts.OnDetection(r, d)
			}
			allowed := opts.AllowedClasses[d.Class]
			if !allowed && !opts.ObserveOnly {
				if jail != nil && jail.jail(ip) && opts.OnJail != nil {
					opts.OnJail(ip, r, d)
				}
				block(w, r)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// isRobotsPath reports whether path is exactly /robots.txt.
func isRobotsPath(path string) bool {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	return path == "/robots.txt"
}

// clientIP returns the remote IP without port — the default GetIP.
// Consumers behind a trusted proxy should supply Options.GetIP and
// read X-Forwarded-For there.
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
