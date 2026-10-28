package humanverify

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func testConfig() Config {
	cfg := Config{Secret: []byte("test-secret"), VerifyPath: "/hv"}
	cfg.defaults()
	return cfg
}

func hit(t *testing.T, cfg Config, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	ok := false
	h := cfg.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok = true
		w.WriteHeader(http.StatusTeapot)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	_ = ok
	return rec
}

func extractToken(t *testing.T, body string) string {
	t.Helper()
	const marker = `data-token="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatal("no token in page")
	}
	rest := body[i+len(marker):]
	return rest[:strings.Index(rest, `"`)]
}

func TestGetWithoutPassServesPage(t *testing.T) {
	cfg := testConfig()
	rec := hit(t, cfg, httptest.NewRequest("GET", "/mirror", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("content-type = %q", ct)
	}
	extractToken(t, rec.Body.String())
}

func TestPostGatedIsForbidden(t *testing.T) {
	cfg := testConfig()
	rec := hit(t, cfg, httptest.NewRequest("POST", "/mirror/reflect", nil))
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Header().Get("Content-Type"), "html") {
		t.Fatalf("expected plain 403, got %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func validForm(t *testing.T, cfg Config, overrides map[string]string) url.Values {
	t.Helper()
	rec := hit(t, cfg, httptest.NewRequest("GET", "/mirror", nil))
	token := extractToken(t, rec.Body.String())
	v := url.Values{
		"token":   {token},
		"hold_ms": {"1500"},
		"moves":   {"12"},
		"jitter":  {"3.5"},
		"ptr":     {"mouse"},
		"hv_hp":   {""},
		"hv_next": {"/mirror"},
	}
	for k, vv := range overrides {
		v[k] = []string{vv}
	}
	return v
}

func verifyRequest(v url.Values) *http.Request {
	r := httptest.NewRequest("POST", "/hv", strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestVerifySuccessIssuesCookie(t *testing.T) {
	cfg := testConfig()
	rec := hit(t, cfg, verifyRequest(validForm(t, cfg, nil)))
	if rec.Code != http.StatusOK {
		b, _ := io.ReadAll(rec.Result().Body)
		t.Fatalf("status = %d body = %s", rec.Code, b)
	}
	var pass *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == cfg.CookieName {
			pass = c
		}
	}
	if pass == nil {
		t.Fatal("no pass cookie issued")
	}
	if !pass.HttpOnly {
		t.Fatal("pass cookie not HttpOnly")
	}

	// Cookie must unlock the gate.
	r := httptest.NewRequest("GET", "/mirror", nil)
	r.AddCookie(pass)
	rec2 := hit(t, cfg, r)
	if rec2.Code != http.StatusTeapot {
		t.Fatalf("gated request with pass = %d", rec2.Code)
	}
}

func TestVerifyRejects(t *testing.T) {
	cfg := testConfig()
	cases := map[string]map[string]string{
		"short hold":        {"hold_ms": "100"},
		"long hold":         {"hold_ms": "999999"},
		"honeypot filled":   {"hv_hp": "spam"},
		"zero-move mouse":   {"moves": "0"},
		"bad token":         {"token": "bogus.sig.here"},
		"jitter flood":      {"jitter": "99999999"},
		"open redirect":     {"hv_next": "https://evil.example"},
		"protocol-relative": {"hv_next": "//evil.example"},
		"backslash":         {"hv_next": "/\\evil.example"},
	}
	for name, over := range cases {
		rec := hit(t, cfg, verifyRequest(validForm(t, cfg, over)))
		if name == "open redirect" || name == "protocol-relative" || name == "backslash" {
			// these should still verify but redirect to "/"
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: status = %d", name, rec.Code)
			}
			if !strings.Contains(rec.Body.String(), `"next":"/"`) {
				t.Fatalf("%s: next not sanitized: %s", name, rec.Body.String())
			}
			continue
		}
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: status = %d", name, rec.Code)
		}
	}
}

func TestTouchHoldWithZeroMovesPasses(t *testing.T) {
	cfg := testConfig()
	rec := hit(t, cfg, verifyRequest(validForm(t, cfg, map[string]string{
		"moves": "0", "ptr": "touch",
	})))
	if rec.Code != http.StatusOK {
		t.Fatalf("touch hold rejected: %d", rec.Code)
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	cfg := testConfig()
	cfg.Secret = []byte("test-secret")
	r := verifyRequest(nil)
	payload := "AAAAAAAAAAAAAAAAAAAAAA." + "1000000000." + cfg.bind(r) // 2001
	token := payload + "." + cfg.sign("tok|"+payload)
	v := validForm(t, cfg, map[string]string{"token": token})
	rec := hit(t, cfg, verifyRequest(v))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expired token accepted: %d", rec.Code)
	}
}

func TestPassCookieExpiry(t *testing.T) {
	cfg := testConfig()
	cfg.CookieTTL = time.Hour
	r := httptest.NewRequest("GET", "/mirror", nil)
	val := cfg.issuePass(time.Now().Add(-2*time.Hour), r) // already expired
	if cfg.verifyPassValue(val, time.Now(), r) {
		t.Fatal("expired pass accepted")
	}
}

func TestPassCookieBoundToClient(t *testing.T) {
	cfg := testConfig()

	// Solve from one client.
	rec := hit(t, cfg, verifyRequest(validForm(t, cfg, nil)))
	if rec.Code != http.StatusOK {
		t.Fatalf("verify status = %d", rec.Code)
	}
	var pass *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == cfg.CookieName {
			pass = c
		}
	}
	if pass == nil {
		t.Fatal("no pass cookie issued")
	}

	// Same cookie from a different client (other IP) must not pass.
	r := httptest.NewRequest("GET", "/mirror", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	r.AddCookie(pass)
	if rec2 := hit(t, cfg, r); rec2.Code == http.StatusTeapot {
		t.Fatal("pass cookie replayed from a different client")
	}

	// Same client still passes.
	r2 := httptest.NewRequest("GET", "/mirror", nil)
	r2.AddCookie(pass)
	if rec3 := hit(t, cfg, r2); rec3.Code != http.StatusTeapot {
		t.Fatalf("pass cookie rejected for original client: %d", rec3.Code)
	}
}

func TestTokenSingleUseWithReplayStore(t *testing.T) {
	cfg := testConfig()
	used := map[string]bool{}
	cfg.Replay = replayFunc(func(token string, _ time.Time) bool {
		if used[token] {
			return false
		}
		used[token] = true
		return true
	})

	v := validForm(t, cfg, nil)
	if rec := hit(t, cfg, verifyRequest(v)); rec.Code != http.StatusOK {
		t.Fatalf("first solve status = %d", rec.Code)
	}
	// Reusing the same token must fail.
	if rec := hit(t, cfg, verifyRequest(v)); rec.Code != http.StatusForbidden {
		t.Fatalf("replayed token accepted: %d", rec.Code)
	}
}

type replayFunc func(token string, expiresAt time.Time) bool

func (f replayFunc) CheckAndMark(token string, expiresAt time.Time) bool {
	return f(token, expiresAt)
}
