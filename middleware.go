package botdetect

import (
	"net/http"
	"strings"
)

// Options configures Middleware.
type Options struct {
	// AllowedClasses lets detected bots of these classes through (e.g.
	// ClassSearch for SEO). Empty means every detected bot is blocked.
	// Humans (Bot == false) are always allowed.
	AllowedClasses map[BotClass]bool

	// BlockMaliciousPath rejects requests to universally malicious paths
	// (.env, .git/, shell.php, ...) regardless of user-agent. Enabled
	// unless explicitly set to false via DisableMaliciousPathBlock.
	DisableMaliciousPathBlock bool

	// ObserveOnly detects and reports via OnDetection but never blocks.
	ObserveOnly bool

	// OnDetection is called for every request that Detect flags as a bot
	// or that hits a malicious path — before the block decision. Useful
	// for logging or metrics.
	OnDetection func(r *http.Request, d Detection)

	// BlockResponse writes the rejection for blocked requests.
	// Defaults to a 403 "Forbidden".
	BlockResponse http.HandlerFunc
}

// Middleware returns HTTP middleware that blocks bots (by class policy)
// and malicious-path probes before they reach the wrapped handler.
//
// /robots.txt is never blocked: RFC 9309 defines a 4xx robots.txt as "no
// crawl restrictions", so blocking it would tell crawlers everything is
// allowed.
func Middleware(next http.Handler, opts Options) http.Handler {
	block := opts.BlockResponse
	if block == nil {
		block = func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Forbidden", http.StatusForbidden)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r == nil {
			next.ServeHTTP(w, r)
			return
		}

		// Never block robots.txt — see doc comment.
		if isRobotsPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		if !opts.DisableMaliciousPathBlock && IsMaliciousPath(r.URL.Path) {
			d := Detection{Bot: true, Name: "malicious-path", Class: ClassScanner}
			if opts.OnDetection != nil {
				opts.OnDetection(r, d)
			}
			if !opts.ObserveOnly {
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
