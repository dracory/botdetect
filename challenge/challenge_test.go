package challenge

import (
	"crypto/sha256"
	"fmt"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

var testConfig = Config{
	Secret:     []byte("test-secret"),
	Difficulty: 4,
	TTL:        time.Minute,
}

// solve brute-forces a counter for token at its declared difficulty.
func solve(t *testing.T, token string) string {
	t.Helper()
	p := strings.Split(token, ".")
	diff, err := strconv.Atoi(p[2])
	if err != nil {
		t.Fatalf("bad difficulty in token %q", token)
	}
	for c := 0; c < 1<<24; c++ {
		sum := sha256.Sum256([]byte(token + ":" + strconv.Itoa(c)))
		if leadingZeroBits(sum[:]) >= diff {
			return strconv.Itoa(c)
		}
	}
	t.Fatalf("no solution found for token %q", token)
	return ""
}

func TestLeadingZeroBits(t *testing.T) {
	cases := []struct {
		b    []byte
		want int
	}{
		{[]byte{0x00, 0x01}, 15},
		{[]byte{0x00, 0x00, 0xff}, 16},
		{[]byte{0x80}, 0},
		{[]byte{0x01}, 7},
		{[]byte{0x00}, 8},
		{nil, 0},
	}
	for _, tc := range cases {
		if got := leadingZeroBits(tc.b); got != tc.want {
			t.Errorf("leadingZeroBits(%x) = %d, want %d", tc.b, got, tc.want)
		}
	}
}

func TestIssueVerifyRoundTrip(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.7:12345"
	r.Header.Set("User-Agent", "test-agent")
	token := testConfig.Issue(r)
	counter := solve(t, token)
	if !testConfig.Verify(r, token, counter) {
		t.Error("valid solution rejected")
	}
}

func TestVerifyRejectsTamperedToken(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.7:12345"
	r.Header.Set("User-Agent", "test-agent")
	token := testConfig.Issue(r)
	counter := solve(t, token)

	parts := strings.Split(token, ".")
	parts[2] = "1" // lower difficulty claim — signature must fail
	if testConfig.Verify(r, strings.Join(parts, "."), counter) {
		t.Error("tampered difficulty accepted")
	}
	// Flip the last signature char to a different value — a fixed "0"
	// flakes whenever the signature already ends in it (~1/16 of runs).
	tampered := token[:len(token)-1]
	if token[len(token)-1] == '0' {
		tampered += "1"
	} else {
		tampered += "0"
	}
	if testConfig.Verify(r, tampered, counter) {
		t.Error("tampered signature accepted")
	}
	if testConfig.Verify(r, "not-a-token", "0") {
		t.Error("garbage token accepted")
	}
}

func TestVerifyRejectsBadCounter(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.7:12345"
	r.Header.Set("User-Agent", "test-agent")
	token := testConfig.Issue(r)
	// Counter "0" is overwhelmingly unlikely to satisfy difficulty 4.
	sum := sha256.Sum256([]byte(token + ":0"))
	if leadingZeroBits(sum[:]) >= testConfig.Difficulty {
		t.Skip("counter 0 happens to be a valid solution")
	}
	if testConfig.Verify(r, token, "0") {
		t.Error("invalid counter accepted")
	}
}

func TestVerifyRejectsDifferentClient(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.7:12345"
	r.Header.Set("User-Agent", "test-agent")
	token := testConfig.Issue(r)
	counter := solve(t, token)

	other := httptest.NewRequest("GET", "/", nil)
	other.RemoteAddr = "198.51.100.9:9999"
	other.Header.Set("User-Agent", "test-agent")
	if testConfig.Verify(other, token, counter) {
		t.Error("solution from different IP accepted")
	}
	other.RemoteAddr = "203.0.113.7:12345"
	other.Header.Set("User-Agent", "other-agent")
	if testConfig.Verify(other, token, counter) {
		t.Error("solution with different UA accepted")
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	c := testConfig
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.7:12345"
	r.Header.Set("User-Agent", "test-agent")
	// Forge a correctly-signed token with a past expiry.
	payload := fmt.Sprintf("%x.%d.%d.%s", []byte("nonce"),
		time.Now().Add(-time.Minute).Unix(), c.Difficulty, c.bind(r))
	token := payload + "." + c.sign(payload)
	if c.Verify(r, token, solve(t, token)) {
		t.Error("expired token accepted")
	}
}

func TestVerifyRejectsFastSolve(t *testing.T) {
	c := testConfig
	c.MinSolve = time.Hour
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.7:12345"
	r.Header.Set("User-Agent", "test-agent")
	token := c.Issue(r)
	if c.Verify(r, token, solve(t, token)) {
		t.Error("solution submitted faster than MinSolve accepted")
	}
}

func TestReplayStoreSingleUse(t *testing.T) {
	seen := map[string]bool{}
	c := testConfig
	c.Replay = replayFunc(func(token string, _ time.Time) bool {
		if seen[token] {
			return false
		}
		seen[token] = true
		return true
	})
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.7:12345"
	r.Header.Set("User-Agent", "test-agent")
	token := c.Issue(r)
	counter := solve(t, token)
	if !c.Verify(r, token, counter) {
		t.Fatal("first use rejected")
	}
	if c.Verify(r, token, counter) {
		t.Error("replayed token accepted")
	}
}

type replayFunc func(string, time.Time) bool

func (f replayFunc) CheckAndMark(token string, exp time.Time) bool { return f(token, exp) }

func TestPassCookieRoundTrip(t *testing.T) {
	c := testConfig.withDefaults()
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.7:12345"
	r.Header.Set("User-Agent", "test-agent")

	w := httptest.NewRecorder()
	c.setPassCookie(w, r)
	resp := w.Result()
	if len(resp.Cookies()) != 1 || resp.Cookies()[0].Name != c.CookieName {
		t.Fatalf("expected one %q cookie, got %v", c.CookieName, resp.Cookies())
	}
	if !resp.Cookies()[0].HttpOnly {
		t.Error("pass cookie missing HttpOnly")
	}

	r2 := httptest.NewRequest("GET", "/", nil)
	r2.RemoteAddr = r.RemoteAddr
	r2.Header.Set("User-Agent", "test-agent")
	r2.AddCookie(resp.Cookies()[0])
	if !c.VerifyPass(r2) {
		t.Error("valid pass cookie rejected")
	}

	r3 := httptest.NewRequest("GET", "/", nil)
	r3.RemoteAddr = "198.51.100.9:1"
	r3.Header.Set("User-Agent", "test-agent")
	r3.AddCookie(resp.Cookies()[0])
	if c.VerifyPass(r3) {
		t.Error("pass cookie accepted from different client")
	}
}

func TestTokenFormat(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.7:12345"
	r.Header.Set("User-Agent", "test-agent")
	parts := strings.Split(testConfig.Issue(r), ".")
	if len(parts) != 5 {
		t.Fatalf("token has %d fields, want 5", len(parts))
	}
	if d, _ := strconv.Atoi(parts[2]); d != testConfig.Difficulty {
		t.Errorf("token difficulty %d, want %d", d, testConfig.Difficulty)
	}
	if _, err := strconv.ParseInt(parts[1], 10, 64); err != nil {
		t.Errorf("token expiry %q not a unix timestamp", parts[1])
	}
}
