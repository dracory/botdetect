package sliderverify

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Token format:
// "<nonce>.<unix>.<targetPct>.<bind>.<sig>"
//
// where:
// - nonce: 16 random bytes (base64url)
// - unix: issue timestamp
// - targetPct: randomized target slider position in percentage (e.g. "72")
// - bind: SHA-256 client fingerprint (first 8 bytes hex)
// - sig: hex(HMAC-SHA256(secret, "svtok|<payload>"))

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

// issueToken creates a signed challenge token with a random target position (between 50% and 90%).
func (c Config) issueToken(r *http.Request) (string, int, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", 0, err
	}

	// Random target between 50% and 90%
	n, err := rand.Int(rand.Reader, big.NewInt(41))
	if err != nil {
		return "", 0, err
	}
	targetPct := int(n.Int64()) + 50

	payload := fmt.Sprintf("%s.%d.%d.%s",
		base64.RawURLEncoding.EncodeToString(nonce),
		time.Now().Unix(),
		targetPct,
		c.bind(r),
	)
	token := payload + "." + c.sign("svtok|"+payload)
	return token, targetPct, nil
}

// verifyToken validates signature, timestamp/expiry, binding, and extracts the target percentage.
func (c Config) verifyToken(token string, now time.Time, r *http.Request) (int, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 5 {
		return 0, errors.New("malformed token")
	}
	payload := parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3]
	expectedSig := c.sign("svtok|" + payload)
	if !hmac.Equal([]byte(expectedSig), []byte(parts[4])) {
		return 0, errors.New("bad signature")
	}

	issued, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, errors.New("bad timestamp")
	}
	if now.Unix()-issued > int64(c.TokenTTL.Seconds()) || issued > now.Unix()+30 {
		return 0, errors.New("token expired")
	}

	if !hmac.Equal([]byte(parts[3]), []byte(c.bind(r))) {
		return 0, errors.New("client mismatch")
	}

	targetPct, err := strconv.Atoi(parts[2])
	if err != nil || targetPct < 0 || targetPct > 100 {
		return 0, errors.New("invalid target")
	}

	if c.Replay != nil &&
		!c.Replay.CheckAndMark(token, time.Unix(issued, 0).Add(c.TokenTTL)) {
		return 0, errors.New("token already used")
	}

	return targetPct, nil
}

// issuePass signs a pass cookie: "<unix-expiry>.<bind>.<sig>"
func (c Config) issuePass(now time.Time, r *http.Request) string {
	exp := strconv.FormatInt(now.Add(c.CookieTTL).Unix(), 10)
	payload := exp + "." + c.bind(r)
	return payload + "." + c.sign("svpass|"+payload)
}

// VerifyPass reports whether the request carries a valid pass cookie.
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
	expected := c.sign("svpass|" + payload)
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
