package botdetect

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestJailStore_JailAndExpiry(t *testing.T) {
	s := newJailStore(30 * time.Millisecond)
	ip := "203.0.113.10"
	if s.jailed(ip) {
		t.Fatal("ip jailed before any jail call")
	}
	s.jail(ip)
	if !s.jailed(ip) {
		t.Fatal("ip not jailed after jail call")
	}
	time.Sleep(50 * time.Millisecond)
	if s.jailed(ip) {
		t.Fatal("ip still jailed after ttl")
	}
}

func TestJailStore_RejailExtends(t *testing.T) {
	s := newJailStore(60 * time.Millisecond)
	s.jail("10.0.0.1")
	time.Sleep(40 * time.Millisecond)
	s.jail("10.0.0.1") // extend
	time.Sleep(40 * time.Millisecond)
	if !s.jailed("10.0.0.1") {
		t.Fatal("re-jail did not extend the term")
	}
}

func TestJailStore_JailReportsFreshTerm(t *testing.T) {
	s := newJailStore(30 * time.Millisecond)
	ip := "10.0.0.2"
	if !s.jail(ip) {
		t.Fatal("first jail should report a fresh term")
	}
	if s.jail(ip) {
		t.Fatal("re-jail during an active term must report false")
	}
	time.Sleep(50 * time.Millisecond)
	if !s.jail(ip) {
		t.Fatal("jail after expiry should report a fresh term")
	}
}

func TestMiddleware_JailsBlockedIP(t *testing.T) {
	code := 0
	var detections []Detection
	h := Middleware(serve(&code), Options{
		JailDuration: time.Minute,
		OnDetection:  func(r *http.Request, d Detection) { detections = append(detections, d) },
	})

	// First hit: malicious path → 403 and jail.
	r := httptest.NewRequest("GET", "/.env", nil)
	r.RemoteAddr = "203.0.113.50:9000"
	h.ServeHTTP(httptest.NewRecorder(), r)

	// Second hit: clean path, human UA — still 403 (jailed).
	r2 := httptest.NewRequest("GET", "/page", nil)
	r2.RemoteAddr = "203.0.113.50:1234" // different port, same IP
	r2.Header.Set("User-Agent", testUA["browser"])
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r2)
	if w.Code != http.StatusForbidden {
		t.Errorf("jailed ip got %d, expected 403", w.Code)
	}
	if len(detections) != 2 || detections[1].Name != "jailed" {
		t.Fatalf("expected OnDetection(Name=jailed), got %+v", detections)
	}
}

func TestMiddleware_JailsOnBotBlock(t *testing.T) {
	code := 0
	h := Middleware(serve(&code), Options{JailDuration: time.Minute})

	r := httptest.NewRequest("GET", "/page", nil)
	r.RemoteAddr = "198.51.100.7:80"
	r.Header.Set("User-Agent", testUA["scanner"])
	h.ServeHTTP(httptest.NewRecorder(), r)

	// UA block jailed the IP — a follow-up with a human UA is rejected.
	r2 := httptest.NewRequest("GET", "/page", nil)
	r2.RemoteAddr = "198.51.100.7:81"
	r2.Header.Set("User-Agent", testUA["browser"])
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r2)
	if w.Code != http.StatusForbidden {
		t.Errorf("ip jailed by bot block got %d, expected 403", w.Code)
	}
}

func TestMiddleware_AllowedClassNeverJailed(t *testing.T) {
	code := 0
	h := Middleware(serve(&code), Options{
		AllowedClasses: map[BotClass]bool{ClassSearch: true},
		JailDuration:   time.Minute,
	})
	r := httptest.NewRequest("GET", "/page", nil)
	r.RemoteAddr = "203.0.113.60:80"
	r.Header.Set("User-Agent", testUA["search"])
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("allowed search bot got %d", w.Code)
	}
	// Same IP with human UA still passes — never jailed.
	r2 := httptest.NewRequest("GET", "/page", nil)
	r2.RemoteAddr = "203.0.113.60:81"
	r2.Header.Set("User-Agent", testUA["browser"])
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)
	if w2.Code != http.StatusOK {
		t.Errorf("ip after allowed-class pass got %d, expected 200", w2.Code)
	}
}

func TestMiddleware_ObserveOnlyNeverJails(t *testing.T) {
	code := 0
	h := Middleware(serve(&code), Options{
		JailDuration: time.Minute,
		ObserveOnly:  true,
	})
	for i := 0; i < 3; i++ {
		r := httptest.NewRequest("GET", "/.env", nil)
		r.RemoteAddr = "203.0.113.70:80"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("observe-only request %d got %d, expected 200", i, w.Code)
		}
	}
}

func TestMiddleware_ExcludePathsBypassesJail(t *testing.T) {
	code := 0
	h := Middleware(serve(&code), Options{
		JailDuration: time.Minute,
		ExcludePaths: []string{"/assets*"},
	})
	// Jail the IP via a malicious path.
	r := httptest.NewRequest("GET", "/.env", nil)
	r.RemoteAddr = "203.0.113.80:80"
	h.ServeHTTP(httptest.NewRecorder(), r)

	// Excluded path still serves the jailed IP.
	r2 := httptest.NewRequest("GET", "/assets/app.css", nil)
	r2.RemoteAddr = "203.0.113.80:81"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r2)
	if w.Code != http.StatusOK {
		t.Errorf("excluded path for jailed ip got %d, expected 200", w.Code)
	}
}

func TestMiddleware_GetIPOverride(t *testing.T) {
	code := 0
	var jailedIP string
	h := Middleware(serve(&code), Options{
		JailDuration: time.Minute,
		GetIP:        func(r *http.Request) string { return r.Header.Get("X-Forwarded-For") },
		OnJail:       func(ip string, r *http.Request, d Detection) { jailedIP = ip },
	})
	r := httptest.NewRequest("GET", "/.env", nil)
	r.Header.Set("X-Forwarded-For", "198.51.100.99")
	r.RemoteAddr = "10.0.0.1:80" // proxy
	h.ServeHTTP(httptest.NewRecorder(), r)
	if jailedIP != "198.51.100.99" {
		t.Fatalf("OnJail got ip %q, expected XFF value", jailedIP)
	}
}

func TestMiddleware_OnJailFiresOncePerJail(t *testing.T) {
	code := 0
	jails := 0
	h := Middleware(serve(&code), Options{
		JailDuration: time.Minute,
		OnJail:       func(ip string, r *http.Request, d Detection) { jails++ },
	})
	for i := 0; i < 3; i++ {
		r := httptest.NewRequest("GET", "/.env", nil)
		r.RemoteAddr = "203.0.113.90:80"
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	if jails != 1 {
		t.Fatalf("OnJail fired %d times for one jail term, expected 1", jails)
	}
}

func TestMiddleware_NoJailByDefault(t *testing.T) {
	code := 0
	h := Middleware(serve(&code), Options{})
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest("GET", "/.env", nil)
		r.RemoteAddr = "203.0.113.100:80"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("malicious path got %d, expected 403", w.Code)
		}
	}
	// Same IP, clean path, human UA: passes — nothing was jailed.
	r := httptest.NewRequest("GET", "/page", nil)
	r.RemoteAddr = "203.0.113.100:81"
	r.Header.Set("User-Agent", testUA["browser"])
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("clean request after blocks got %d, expected 200 (no jail)", w.Code)
	}
}
