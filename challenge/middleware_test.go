package challenge

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestMiddleware_ChallengesWithoutPass(t *testing.T) {
	reached := false
	h := testConfig.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	r := httptest.NewRequest("GET", "/expensive", nil)
	r.RemoteAddr = "203.0.113.7:12345"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if reached {
		t.Error("request without pass reached next handler")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("challenge page returned %d, want 403", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `data-token="`) {
		t.Error("challenge page missing token")
	}
	if !strings.Contains(body, "crypto.subtle.digest") {
		t.Error("challenge page missing embedded solver script")
	}
}

func TestMiddleware_FullSolveFlow(t *testing.T) {
	c := testConfig.withDefaults()
	reached := false
	h := c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	// Step 1: gated request gets a challenge page with a token.
	r := httptest.NewRequest("GET", "/expensive", nil)
	r.RemoteAddr = "203.0.113.7:12345"
	r.Header.Set("User-Agent", "test-agent")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	body := w.Body.String()
	i := strings.Index(body, `data-token="`)
	if i < 0 {
		t.Fatal("no token in challenge page")
	}
	token := strings.SplitN(body[i+len(`data-token="`):], `"`, 2)[0]

	// Step 2: POST a valid solution to the verify endpoint.
	form := url.Values{
		"token":   {token},
		"counter": {solve(t, token)},
		"bd_hp":   {""},
		"bd_next": {"/expensive"},
	}
	vr := httptest.NewRequest("POST", c.VerifyPath, strings.NewReader(form.Encode()))
	vr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	vr.RemoteAddr = r.RemoteAddr
	vr.Header.Set("User-Agent", "test-agent")
	vw := httptest.NewRecorder()
	h.ServeHTTP(vw, vr)
	if vw.Code != http.StatusOK {
		t.Fatalf("verify returned %d, want 200", vw.Code)
	}
	cookies := vw.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != c.CookieName {
		t.Fatalf("expected pass cookie %q, got %v", c.CookieName, cookies)
	}

	// Step 3: the pass cookie lets the original request through.
	r2 := httptest.NewRequest("GET", "/expensive", nil)
	r2.RemoteAddr = r.RemoteAddr
	r2.Header.Set("User-Agent", "test-agent")
	r2.AddCookie(cookies[0])
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)
	if !reached || w2.Code != http.StatusOK {
		t.Error("request with pass cookie did not reach next handler")
	}
}

func TestMiddleware_VerifyRejectsBadSolution(t *testing.T) {
	c := testConfig.withDefaults()
	h := c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.7:12345"
	r.Header.Set("User-Agent", "test-agent")
	token := c.Issue(r)

	form := url.Values{"token": {token}, "counter": {"0"}, "bd_hp": {""}}
	digest := sha256.Sum256([]byte(token + ":0"))
	sum := leadingZeroBits(digest[:])
	if sum >= testConfig.Difficulty {
		t.Skip("counter 0 is a valid solution")
	}
	vr := httptest.NewRequest("POST", c.VerifyPath, strings.NewReader(form.Encode()))
	vr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	vr.RemoteAddr = r.RemoteAddr
	vr.Header.Set("User-Agent", "test-agent")
	vw := httptest.NewRecorder()
	h.ServeHTTP(vw, vr)
	if vw.Code != http.StatusForbidden {
		t.Errorf("bad solution got %d, want 403", vw.Code)
	}
}

func TestMiddleware_VerifyRejectsHoneypot(t *testing.T) {
	c := testConfig.withDefaults()
	h := c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.7:12345"
	r.Header.Set("User-Agent", "test-agent")
	token := c.Issue(r)

	form := url.Values{
		"token":   {token},
		"counter": {solve(t, token)},
		"bd_hp":   {"spammy"},
	}
	vr := httptest.NewRequest("POST", c.VerifyPath, strings.NewReader(form.Encode()))
	vr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	vr.RemoteAddr = r.RemoteAddr
	vr.Header.Set("User-Agent", "test-agent")
	vw := httptest.NewRecorder()
	h.ServeHTTP(vw, vr)
	if vw.Code != http.StatusForbidden {
		t.Errorf("honeypot submission got %d, want 403", vw.Code)
	}
}

func TestSafeRedirect(t *testing.T) {
	for in, want := range map[string]string{
		"/path":            "/path",
		"/p?q=1":           "/p?q=1",
		"":                 "/",
		"//evil.com":       "/",
		"https://evil.com": "/",
		"javascript:alert": "/",
		"relative/path":    "/",
		"/\nSet-Cookie: x": "/",
		"/\\evil":          "/",
	} {
		if got := safeRedirect(in); got != want {
			t.Errorf("safeRedirect(%q) = %q, want %q", in, got, want)
		}
	}
}
