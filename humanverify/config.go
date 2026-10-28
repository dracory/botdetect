package humanverify

import (
	"net/http"
	"time"
)

// ReplayStore optionally makes solved tokens single-use. CheckAndMark
// must return false if the token was already redeemed, otherwise record
// it (until expiresAt at the latest) and return true.
type ReplayStore interface {
	CheckAndMark(token string, expiresAt time.Time) bool
}

// Config controls the press-and-hold human verification gate.
//
// Middleware serves an interstitial page on GET requests for clients
// without a valid pass cookie. The page requires the visitor to press
// and hold a button while it records coarse behavioral signals (hold
// duration, pointer movement count, pointer jitter, pointer type).
// The client POSTs those signals to VerifyPath; the server applies
// heuristic checks and, on success, issues an HMAC-signed pass cookie.
//
// This is a speed bump against unsophisticated automation — it is not
// a substitute for a fingerprinting service. Compose it with declared-
// bot detection (e.g. dracory/botdetect) for layered defense.
type Config struct {
	// Secret signs tokens and pass cookies. Required; Middleware
	// panics if empty on first use.
	Secret []byte

	// VerifyPath is the path the challenge page POSTs solutions to.
	// The middleware intercepts POSTs to this path before next runs.
	// Default: "/human-verify".
	VerifyPath string

	// CookieName is the pass cookie name. Default: "hv_pass".
	CookieName string

	// MinHold is the minimum continuous press duration accepted.
	// Default: 800ms.
	MinHold time.Duration

	// MaxHold is the maximum press duration accepted — a hold far
	// beyond human patience suggests a scripted timer. Default: 30s.
	MaxHold time.Duration

	// TokenTTL is how long an issued challenge token stays valid.
	// Default: 5 minutes.
	TokenTTL time.Duration

	// CookieTTL is how long a pass cookie stays valid.
	// Default: 24 hours.
	CookieTTL time.Duration

	// SecureCookie marks the pass cookie Secure (HTTPS only). Enable it
	// in production — including behind a TLS-terminating proxy, where
	// r.TLS is always nil and cannot be used to detect HTTPS.
	SecureCookie bool

	// BindFunc overrides the default client binding (User-Agent +
	// remote IP) embedded in tokens and pass cookies, so a solved
	// pass cannot be replayed from a different client. Return a short
	// stable fingerprint of the request — useful for /24 binding or
	// trusted-proxy IP resolution. The returned value is embedded in
	// dot-separated tokens and must not contain ".".
	BindFunc func(r *http.Request) string

	// Replay optionally enforces single-use tokens. Without it an
	// issued token can mint pass cookies until its TokenTTL expires.
	Replay ReplayStore
}

func (c *Config) defaults() {
	if c.VerifyPath == "" {
		c.VerifyPath = "/human-verify"
	}
	if c.CookieName == "" {
		c.CookieName = "hv_pass"
	}
	if c.MinHold <= 0 {
		c.MinHold = 800 * time.Millisecond
	}
	if c.MaxHold <= 0 {
		c.MaxHold = 30 * time.Second
	}
	if c.TokenTTL <= 0 {
		c.TokenTTL = 5 * time.Minute
	}
	if c.CookieTTL <= 0 {
		c.CookieTTL = 24 * time.Hour
	}
}
