package turnstile

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// fakeSiteverify returns an httptest server mimicking siteverify,
// recording the last form it received.
func fakeSiteverify(t *testing.T, res Result, lastForm *url.Values) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("siteverify got unparseable form: %v", err)
		}
		if lastForm != nil {
			*lastForm = r.PostForm
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(res)
	}))
}

func TestVerifySuccess(t *testing.T) {
	var form url.Values
	srv := fakeSiteverify(t, Result{
		Success: true, Hostname: "example.com", Action: "login",
		ChallengeTS: time.Now(),
	}, &form)
	defer srv.Close()

	v := New("secret-1")
	v.Endpoint = srv.URL
	res, err := v.Verify(context.Background(), "tok-abc", "203.0.113.7")
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if !res.Success || res.Hostname != "example.com" || res.Action != "login" {
		t.Errorf("unexpected result %+v", res)
	}
	if form.Get("secret") != "secret-1" || form.Get("response") != "tok-abc" ||
		form.Get("remoteip") != "203.0.113.7" {
		t.Errorf("siteverify got wrong form: %v", form)
	}
}

func TestVerifyRejectionIsNotError(t *testing.T) {
	srv := fakeSiteverify(t, Result{Success: false, ErrorCodes: []string{"invalid-input-response"}}, nil)
	defer srv.Close()

	v := New("s")
	v.Endpoint = srv.URL
	res, err := v.Verify(context.Background(), "bad-tok", "")
	if err != nil {
		t.Fatalf("rejected token returned error: %v", err)
	}
	if res.Success {
		t.Error("expected Success=false")
	}
}

func TestVerifyMissingToken(t *testing.T) {
	v := New("s")
	if _, err := v.Verify(context.Background(), "", ""); !errors.Is(err, ErrMissingToken) {
		t.Errorf("got %v, want ErrMissingToken", err)
	}
}

// deadEndpoint returns a URL whose server is already shut down, giving
// a fast connection-refused for outage tests.
func deadEndpoint(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	u := srv.URL
	srv.Close()
	return u
}

func TestVerifyTransportError(t *testing.T) {
	v := New("s")
	v.Endpoint = deadEndpoint(t)
	if _, err := v.Verify(context.Background(), "tok", ""); err == nil {
		t.Error("expected transport error")
	}
}

func TestVerifyBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()
	v := New("s")
	v.Endpoint = srv.URL
	if _, err := v.Verify(context.Background(), "tok", ""); err == nil {
		t.Error("expected decode error")
	}
}

func okHandler(reached *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusOK)
	})
}

func postForm(token string) *http.Request {
	r := httptest.NewRequest("POST", "/submit",
		strings.NewReader(url.Values{"cf-turnstile-response": {token}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "203.0.113.7:12345"
	return r
}

func TestMiddleware_PassesNonPOST(t *testing.T) {
	reached := false
	h := Middleware(New("s"), Options{})(okHandler(&reached))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/submit", nil))
	if !reached || w.Code != http.StatusOK {
		t.Error("GET request was gated")
	}
}

func TestMiddleware_RejectsMissingToken(t *testing.T) {
	reached := false
	h := Middleware(New("s"), Options{})(okHandler(&reached))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, postForm(""))
	if reached {
		t.Error("request without token reached handler")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("got %d, want 403", w.Code)
	}
}

func TestMiddleware_AcceptsValidToken(t *testing.T) {
	srv := fakeSiteverify(t, Result{Success: true, Hostname: "example.com"}, nil)
	defer srv.Close()
	v := New("s")
	v.Endpoint = srv.URL

	reached := false
	h := Middleware(v, Options{Hostname: "example.com"})(okHandler(&reached))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, postForm("tok"))
	if !reached {
		t.Error("valid token did not reach handler")
	}
}

func TestMiddleware_EnforcesHostnameAndAction(t *testing.T) {
	srv := fakeSiteverify(t, Result{Success: true, Hostname: "other.com", Action: "other"}, nil)
	defer srv.Close()
	v := New("s")
	v.Endpoint = srv.URL

	reached := false
	h := Middleware(v, Options{Hostname: "example.com", Action: "login"})(okHandler(&reached))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, postForm("tok"))
	if reached {
		t.Error("token for another site/action reached handler")
	}
}

func TestMiddleware_FailClosedOnOutage(t *testing.T) {
	v := New("s")
	v.Endpoint = deadEndpoint(t)
	reached := false
	h := Middleware(v, Options{})(okHandler(&reached))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, postForm("tok"))
	if reached {
		t.Error("request passed during outage with fail-closed default")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("got %d, want 503", w.Code)
	}
}

func TestMiddleware_FailOpen(t *testing.T) {
	v := New("s")
	v.Endpoint = deadEndpoint(t)
	reached := false
	h := Middleware(v, Options{FailOpen: true})(okHandler(&reached))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, postForm("tok"))
	if !reached {
		t.Error("FailOpen did not let request through during outage")
	}
}

func TestMiddleware_CustomOnFailure(t *testing.T) {
	srv := fakeSiteverify(t, Result{Success: false}, nil)
	defer srv.Close()
	v := New("s")
	v.Endpoint = srv.URL

	reached := false
	h := Middleware(v, Options{
		OnFailure: func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/try-again", http.StatusSeeOther)
		},
	})(okHandler(&reached))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, postForm("tok"))
	if reached || w.Code != http.StatusSeeOther {
		t.Errorf("custom OnFailure not used: code %d reached=%v", w.Code, reached)
	}
}

func TestMiddleware_OnlyIfSuspicious(t *testing.T) {
	srv := fakeSiteverify(t, Result{Success: true}, nil)
	defer srv.Close()
	v := New("s")
	v.Endpoint = srv.URL

	reached := false
	h := Middleware(v, Options{OnlyIfSuspicious: true})(okHandler(&reached))

	// Human UA, residential-looking IP, no token: passes unchecked.
	r := httptest.NewRequest("GET", "/submit", nil)
	r.Method = "POST"
	r.RemoteAddr = "203.0.113.7:12345"
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !reached {
		t.Error("normal user was challenged")
	}

	// Bot UA, no token: gated (curl is a declared bot).
	reached = false
	r2 := postForm("")
	r2.Header.Set("User-Agent", "curl/8.6.0")
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)
	if reached {
		t.Error("detected bot passed without token")
	}
}

func TestWidget(t *testing.T) {
	html := string(Widget(`my"key`, "login"))
	if !strings.Contains(html, "cf-turnstile") || !strings.Contains(html, "api.js") {
		t.Error("widget missing script or div")
	}
	if !strings.Contains(html, `data-action="login"`) {
		t.Error("widget missing action attribute")
	}
	if strings.Contains(html, `my"key`) {
		t.Error("sitekey not escaped")
	}
	if string(Widget("k", "")) == "" || strings.Contains(string(Widget("k", "")), "data-action") {
		t.Error("empty action should omit the attribute")
	}
}
