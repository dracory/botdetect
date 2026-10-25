package botdetect

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

var testUA = map[string]string{
	"browser": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"search":  "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	"scraper": "curl/8.6.0",
	"scanner": "sqlmap/1.7",
	"aiuser":  "Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)",
}

func serve(code *int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*code = http.StatusOK
		w.WriteHeader(http.StatusOK)
	})
}

func TestMiddleware_BlocksByDefault(t *testing.T) {
	code := 0
	h := Middleware(serve(&code), Options{})
	r := httptest.NewRequest("GET", "/page", nil)
	r.Header.Set("User-Agent", testUA["scraper"])
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("scraper request got %d, expected 403", w.Code)
	}
	if code != 0 {
		t.Error("blocked request reached next handler")
	}
}

func TestMiddleware_AllowsHumans(t *testing.T) {
	code := 0
	h := Middleware(serve(&code), Options{})
	r := httptest.NewRequest("GET", "/page", nil)
	r.Header.Set("User-Agent", testUA["browser"])
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || code != http.StatusOK {
		t.Errorf("browser request got %d, expected 200 pass-through", w.Code)
	}
}

func TestMiddleware_AllowedClasses(t *testing.T) {
	code := 0
	h := Middleware(serve(&code), Options{
		AllowedClasses: map[BotClass]bool{ClassSearch: true, ClassAIUser: true},
	})

	// Googlebot allowed through.
	r := httptest.NewRequest("GET", "/page", nil)
	r.Header.Set("User-Agent", testUA["search"])
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("search crawler got %d, expected 200 (allowed class)", w.Code)
	}

	// AI user fetcher allowed through.
	r = httptest.NewRequest("GET", "/page", nil)
	r.Header.Set("User-Agent", testUA["aiuser"])
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("ai-user fetcher got %d, expected 200 (allowed class)", w.Code)
	}

	// sqlmap still blocked.
	r = httptest.NewRequest("GET", "/page", nil)
	r.Header.Set("User-Agent", testUA["scanner"])
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("scanner got %d, expected 403", w.Code)
	}
}

func TestMiddleware_MaliciousPathBlocked(t *testing.T) {
	code := 0
	h := Middleware(serve(&code), Options{})
	r := httptest.NewRequest("GET", "/.env", nil)
	r.Header.Set("User-Agent", testUA["browser"]) // even a "human" UA
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("/.env request got %d, expected 403", w.Code)
	}
}

func TestMiddleware_RobotsTxtNeverBlocked(t *testing.T) {
	code := 0
	h := Middleware(serve(&code), Options{})
	r := httptest.NewRequest("GET", "/robots.txt", nil)
	r.Header.Set("User-Agent", testUA["scraper"])
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("/robots.txt got %d, expected 200 (RFC 9309)", w.Code)
	}
}

func TestMiddleware_ObserveOnly(t *testing.T) {
	code := 0
	var seen []Detection
	h := Middleware(serve(&code), Options{
		ObserveOnly: true,
		OnDetection: func(r *http.Request, d Detection) { seen = append(seen, d) },
	})
	r := httptest.NewRequest("GET", "/.env", nil)
	r.Header.Set("User-Agent", testUA["scraper"])
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("observe-only request got %d, expected 200", w.Code)
	}
	if len(seen) == 0 {
		t.Error("OnDetection was not called")
	}
}
