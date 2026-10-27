package humanverify

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Token format: "<nonce>.<unix>.<sig>" where sig is
// hex(HMAC-SHA256(secret, nonce + "." + unix)).
//
// Pass cookie format: "<unix-expiry>.<sig>" where sig is
// hex(HMAC-SHA256(secret, "pass|" + unix-expiry)).

func (c Config) sign(payload string) string {
	m := hmac.New(sha256.New, c.Secret)
	m.Write([]byte(payload))
	return hex.EncodeToString(m.Sum(nil))
}

func (c Config) issueToken() (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(nonce) + "." +
		strconv.FormatInt(time.Now().Unix(), 10)
	return payload + "." + c.sign("tok|"+payload), nil
}

func (c Config) verifyToken(token string, now time.Time) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("malformed token")
	}
	payload := parts[0] + "." + parts[1]
	expected := c.sign("tok|" + payload)
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return errors.New("bad signature")
	}
	issued, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return errors.New("bad timestamp")
	}
	if now.Unix()-issued > int64(c.TokenTTL.Seconds()) || issued > now.Unix()+30 {
		return errors.New("token expired")
	}
	return nil
}

func (c Config) issuePass(now time.Time) string {
	exp := strconv.FormatInt(now.Add(c.CookieTTL).Unix(), 10)
	return exp + "." + c.sign("pass|"+exp)
}

// VerifyPass reports whether the request carries a valid pass cookie.
// Use it inside downstream handlers that also need the gate (e.g. a
// POST endpoint covered by a cookie earned on the GET page).
func (c Config) VerifyPass(r *http.Request) bool {
	ck, err := r.Cookie(c.CookieName)
	if err != nil {
		return false
	}
	return c.verifyPassValue(ck.Value, time.Now())
}

func (c Config) verifyPassValue(value string, now time.Time) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return false
	}
	expected := c.sign("pass|" + parts[0])
	if !hmac.Equal([]byte(expected), []byte(parts[1])) {
		return false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}
	return now.Unix() < exp
}

func secEncode(d time.Duration) string {
	return fmt.Sprintf("%d", int64(d/time.Millisecond))
}
