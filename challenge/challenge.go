// Package challenge implements a stateless, HMAC-signed proof-of-work
// challenge ("poor man's Turnstile") for protecting expensive anonymous
// endpoints. It fits the botdetect philosophy: no store, no DB, no
// goroutines, stdlib only.
//
// Flow: the gate serves a small challenge page containing a signed
// token. Embedded JavaScript finds a counter such that
// SHA-256(token + ":" + counter) has N leading zero bits and POSTs the
// solution. On success the server sets a signed pass cookie; subsequent
// requests only check the cookie.
//
// Stateless means a solved token is reusable until expiry; short TTLs
// and IP/UA binding limit the blast radius. For true single-use tokens
// plug a ReplayStore. PoW raises the cost of bulk scraping; it does not
// prove humanity — a headless browser will pass.
package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/bits"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ReplayStore optionally makes solved tokens single-use. CheckAndMark
// must return false if the token was already redeemed, otherwise record
// it (until expiresAt at the latest) and return true.
type ReplayStore interface {
	CheckAndMark(token string, expiresAt time.Time) bool
}

// Config configures the challenge. Secret is required; everything else
// has sane defaults applied by withDefaults.
type Config struct {
	// Secret signs challenge tokens and pass cookies (HMAC-SHA-256).
	Secret []byte

	// Difficulty is the number of leading zero bits required in the
	// solution hash. 18-20 ≈ 0.2-1s in a browser. Default 18.
	Difficulty int

	// TTL is how long an issued challenge token stays valid.
	// Default 5 minutes.
	TTL time.Duration

	// PassTTL is how long the pass cookie stays valid after a
	// successful solve. Default 1 hour.
	PassTTL time.Duration

	// MinSolve rejects solutions submitted suspiciously fast after
	// token issuance. Weak signal; filters lazy scripts. Default 0
	// (disabled).
	MinSolve time.Duration

	// CookieName is the pass cookie name. Default "bd_pass".
	CookieName string

	// VerifyPath is the endpoint the challenge page POSTs solutions
	// to. Default "/_challenge/verify".
	VerifyPath string

	// SecureCookie marks the pass cookie Secure (HTTPS only).
	SecureCookie bool

	// BindFunc overrides the default client binding (User-Agent +
	// remote IP). Return a short stable fingerprint of the request.
	// Useful for /24 binding or trusted-proxy IP resolution. The
	// returned value is embedded in dot-separated tokens and must
	// not contain ".".
	BindFunc func(r *http.Request) string

	// Replay optionally enforces single-use tokens.
	Replay ReplayStore
}

func (c Config) withDefaults() Config {
	if len(c.Secret) == 0 {
		panic("challenge: Config.Secret is required")
	}
	if c.Difficulty <= 0 {
		c.Difficulty = 18
	}
	if c.TTL <= 0 {
		c.TTL = 5 * time.Minute
	}
	if c.PassTTL <= 0 {
		c.PassTTL = time.Hour
	}
	if c.CookieName == "" {
		c.CookieName = "bd_pass"
	}
	if c.VerifyPath == "" {
		c.VerifyPath = "/_challenge/verify"
	}
	return c
}

// clientIP returns the remote IP without port. Consumers behind a
// trusted proxy should supply BindFunc and read X-Forwarded-For there.
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func (c Config) bind(r *http.Request) string {
	if c.BindFunc != nil {
		return c.BindFunc(r)
	}
	h := sha256.Sum256([]byte(r.UserAgent() + "|" + clientIP(r)))
	return hex.EncodeToString(h[:8])
}

func (c Config) sign(s string) string {
	m := hmac.New(sha256.New, c.Secret)
	m.Write([]byte(s))
	return hex.EncodeToString(m.Sum(nil))
}

// Issue returns a signed challenge token for the request:
// "nonce.expiry.difficulty.bind.hmac". Nothing is stored server-side.
func (c Config) Issue(r *http.Request) string {
	c = c.withDefaults()
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)
	payload := fmt.Sprintf("%x.%d.%d.%s", nonce,
		time.Now().Add(c.TTL).Unix(), c.Difficulty, c.bind(r))
	return payload + "." + c.sign(payload)
}

// Verify checks a token/counter solution: signature, expiry, client
// binding, minimum solve time, and that SHA-256(token + ":" + counter)
// has the required leading zero bits. If a ReplayStore is configured
// the token is also marked as spent.
//
// The required difficulty is read from the (signed) token, not the
// current Config — tokens issued before a difficulty raise stay
// solvable at the old difficulty until they expire; TTL is the only
// bound.
func (c Config) Verify(r *http.Request, token, counter string) bool {
	c = c.withDefaults()
	i := strings.LastIndex(token, ".")
	if i < 0 {
		return false
	}
	payload, sig := token[:i], token[i+1:]
	if !hmac.Equal([]byte(sig), []byte(c.sign(payload))) {
		return false
	}
	p := strings.Split(payload, ".") // nonce, exp, difficulty, bind
	if len(p) != 4 || p[3] != c.bind(r) {
		return false
	}
	exp, err := strconv.ParseInt(p[1], 10, 64)
	if err != nil {
		return false
	}
	diff, err := strconv.Atoi(p[2])
	if err != nil || diff < 0 {
		return false
	}
	now := time.Now()
	if now.Unix() > exp {
		return false
	}
	if c.MinSolve > 0 && now.Sub(time.Unix(exp, 0).Add(-c.TTL)) < c.MinSolve {
		return false
	}
	sum := sha256.Sum256([]byte(token + ":" + counter))
	if leadingZeroBits(sum[:]) < diff {
		return false
	}
	if c.Replay != nil && !c.Replay.CheckAndMark(token, time.Unix(exp, 0)) {
		return false
	}
	return true
}

// IssuePass signs a pass-cookie value "expiry.bind.hmac" for the
// request, valid for PassTTL.
func (c Config) issuePass(r *http.Request) string {
	payload := fmt.Sprintf("%d.%s", time.Now().Add(c.PassTTL).Unix(), c.bind(r))
	return payload + "." + c.sign(payload)
}

// VerifyPass reports whether the request carries a valid pass cookie.
func (c Config) VerifyPass(r *http.Request) bool {
	c = c.withDefaults()
	cookie, err := r.Cookie(c.CookieName)
	if err != nil {
		return false
	}
	v := cookie.Value
	i := strings.LastIndex(v, ".")
	if i < 0 {
		return false
	}
	payload, sig := v[:i], v[i+1:]
	if !hmac.Equal([]byte(sig), []byte(c.sign(payload))) {
		return false
	}
	p := strings.Split(payload, ".") // exp, bind
	if len(p) != 2 || p[1] != c.bind(r) {
		return false
	}
	exp, err := strconv.ParseInt(p[0], 10, 64)
	if err != nil {
		return false
	}
	return time.Now().Unix() <= exp
}

// setPassCookie writes the pass cookie on a successful solve.
func (c Config) setPassCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.CookieName,
		Value:    c.issuePass(r),
		Path:     "/",
		Expires:  time.Now().Add(c.PassTTL),
		MaxAge:   int(c.PassTTL.Seconds()),
		HttpOnly: true,
		Secure:   c.SecureCookie,
		SameSite: http.SameSiteLaxMode,
	})
}

// leadingZeroBits counts the number of zero bits at the front of b.
func leadingZeroBits(b []byte) int {
	n := 0
	for _, v := range b {
		if v == 0 {
			n += 8
			continue
		}
		return n + bits.LeadingZeros8(v)
	}
	return n
}
