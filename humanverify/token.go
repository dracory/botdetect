package humanverify

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Token format: "<nonce>.<unix>.<bind>.<sig>" where sig is
// hex(HMAC-SHA256(secret, "tok|" + nonce + "." + unix + "." + bind)).
//
// Pass cookie format: "<unix-expiry>.<bind>.<sig>" where sig is
// hex(HMAC-SHA256(secret, "pass|" + unix-expiry + "." + bind)).
//
// <bind> is a client fingerprint (default SHA-256(UA|IP), first 8
// bytes) so a token or pass solved by one client cannot be replayed
// from another.

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

func (c Config) sign(payload string) string {
	m := hmac.New(sha256.New, c.Secret)
	m.Write([]byte(payload))
	return hex.EncodeToString(m.Sum(nil))
}

func (c Config) issueToken(r *http.Request) (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(nonce) + "." +
		strconv.FormatInt(time.Now().Unix(), 10) + "." + c.bind(r)
	return payload + "." + c.sign("tok|"+payload), nil
}

// verifyToken validates a challenge token's signature, expiry, and
// client binding. If a ReplayStore is configured the token is also
// marked as spent, making it single-use.
func (c Config) verifyToken(token string, now time.Time, r *http.Request) error {
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		return errors.New("malformed token")
	}
	payload := parts[0] + "." + parts[1] + "." + parts[2]
	expected := c.sign("tok|" + payload)
	if !hmac.Equal([]byte(expected), []byte(parts[3])) {
		return errors.New("bad signature")
	}
	issued, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return errors.New("bad timestamp")
	}
	if now.Unix()-issued > int64(c.TokenTTL.Seconds()) || issued > now.Unix()+30 {
		return errors.New("token expired")
	}
	if !hmac.Equal([]byte(parts[2]), []byte(c.bind(r))) {
		return errors.New("client mismatch")
	}
	if c.Replay != nil &&
		!c.Replay.CheckAndMark(token, time.Unix(issued, 0).Add(c.TokenTTL)) {
		return errors.New("token already used")
	}
	return nil
}

func (c Config) issuePass(now time.Time, r *http.Request) string {
	exp := strconv.FormatInt(now.Add(c.CookieTTL).Unix(), 10)
	payload := exp + "." + c.bind(r)
	return payload + "." + c.sign("pass|"+payload)
}

// VerifyPass reports whether the request carries a valid pass cookie.
// Use it inside downstream handlers that also need the gate (e.g. a
// POST endpoint covered by a cookie earned on the GET page).
func (c Config) VerifyPass(r *http.Request) bool {
	ck, err := r.Cookie(c.CookieName)
	if err != nil {
		return false
	}
	return c.verifyPassValue(ck.Value, time.Now(), r)
}

func (c Config) verifyPassValue(value string, now time.Time, r *http.Request) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	payload := parts[0] + "." + parts[1]
	expected := c.sign("pass|" + payload)
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}
	if now.Unix() >= exp {
		return false
	}
	return hmac.Equal([]byte(parts[1]), []byte(c.bind(r)))
}

func secEncode(d time.Duration) string {
	return fmt.Sprintf("%d", int64(d/time.Millisecond))
}
