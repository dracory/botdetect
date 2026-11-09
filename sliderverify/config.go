package sliderverify

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

// Config controls the slide-to-verify human verification gate.
//
// Middleware serves an interactive slider challenge page on GET requests
// for clients without a valid pass cookie. The user drags a handle
// across a track to a randomized target position. During the drag, the
// client records pointer kinematics: timestamps (dt), 2D coordinates (x, y),
// velocities, and jitter.
//
// Upon release, the client POSTs the trajectory and final landing position.
// The server verifies the cryptographic token, validates target precision,
// and evaluates human motor control characteristics (bell-shaped velocity profile,
// micro-tremor / non-zero orthogonal jitter, non-linear acceleration, realistic durations).
// On success, an HMAC-signed pass cookie is issued.
type Config struct {
	// Secret signs challenge tokens and pass cookies (HMAC-SHA-256).
	// Required; Middleware panics if empty.
	Secret []byte

	// VerifyPath is the path the slider page POSTs solutions to.
	// Default: "/slider-verify".
	VerifyPath string

	// CookieName is the pass cookie name. Default: "sv_pass".
	CookieName string

	// MinDuration is the minimum duration a human drag takes.
	// Humans need at least ~300ms to visually acquire, initiate, and complete
	// a targeted drag. Default: 350ms.
	MinDuration time.Duration

	// MaxDuration is the maximum drag duration accepted. Default: 30s.
	MaxDuration time.Duration

	// TargetTolerance is the allowable distance (in percentage points 0-100)
	// from the designated target zone. Default: 5.0 (±5%).
	TargetTolerance float64

	// TokenTTL is how long an issued challenge token stays valid.
	// Default: 5 minutes.
	TokenTTL time.Duration

	// CookieTTL is how long a pass cookie stays valid.
	// Default: 24 hours.
	CookieTTL time.Duration

	// SecureCookie marks the pass cookie Secure (HTTPS only).
	SecureCookie bool

	// BindFunc overrides the default client binding (User-Agent +
	// remote IP). Return a short stable fingerprint of the request.
	// Must not contain ".".
	BindFunc func(r *http.Request) string

	// Replay optionally enforces single-use tokens.
	Replay ReplayStore
}

func (c *Config) defaults() {
	if c.VerifyPath == "" {
		c.VerifyPath = "/slider-verify"
	}
	if c.CookieName == "" {
		c.CookieName = "sv_pass"
	}
	if c.MinDuration <= 0 {
		c.MinDuration = 350 * time.Millisecond
	}
	if c.MaxDuration <= 0 {
		c.MaxDuration = 30 * time.Second
	}
	if c.TargetTolerance <= 0 {
		c.TargetTolerance = 5.0
	}
	if c.TokenTTL <= 0 {
		c.TokenTTL = 5 * time.Minute
	}
	if c.CookieTTL <= 0 {
		c.CookieTTL = 24 * time.Hour
	}
}
