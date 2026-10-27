package humanverify

import (
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Middleware returns an http.Handler wrapper that gates requests:
//
//   - POST to VerifyPath: treated as a solve attempt, verified, and a
//     pass cookie issued on success. next is not invoked.
//   - Request with a valid pass cookie: passed to next.
//   - Any other request: the press-and-hold page is served for GET/HEAD;
//     other methods get 403 (a fetch/XHR can't answer an HTML page).
func (c Config) Middleware(next http.Handler) http.Handler {
	c.defaults()
	if len(c.Secret) == 0 {
		panic("humanverify: Config.Secret is required")
	}
	cfg := c
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == cfg.VerifyPath {
			cfg.handleVerify(w, r)
			return
		}
		if cfg.VerifyPass(r) {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		token, err := cfg.issueToken()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		nextURL := r.URL.RequestURI()
		if q := r.URL.Query().Get("hv_next"); q != "" {
			nextURL = q
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusForbidden)
		_ = pageTpl.Execute(w, pageData{
			Token:      token,
			VerifyPath: cfg.VerifyPath,
			Next:       nextURL,
			MinHoldMS:  secEncode(cfg.MinHold),
			JS:         template.JS(pageJS),
		})
	})
}

// handleVerify grades a solve attempt. Expected form fields:
//
//	token     — the HMAC token embedded in the page
//	hold_ms   — milliseconds the button was held
//	moves     — count of pointermove events during the hold
//	jitter    — total pointer travel in px during the hold (float)
//	ptr       — pointerType reported by the browser (mouse|touch|pen|"")
//	hv_hp     — honeypot field, must be empty
//	hv_next   — where to redirect on success (must be a local path)
func (c Config) handleVerify(w http.ResponseWriter, r *http.Request) {
	fail := func(msg string) {
		http.Error(w, msg, http.StatusForbidden)
	}

	if err := r.ParseForm(); err != nil {
		fail("Bad request")
		return
	}
	if r.PostForm.Get("hv_hp") != "" {
		fail("Verification failed")
		return
	}
	if err := c.verifyToken(r.PostForm.Get("token"), time.Now()); err != nil {
		fail("Verification failed")
		return
	}

	holdMS, err := strconv.ParseInt(r.PostForm.Get("hold_ms"), 10, 64)
	if err != nil {
		fail("Verification failed")
		return
	}
	hold := time.Duration(holdMS) * time.Millisecond
	if hold < c.MinHold || hold > c.MaxHold {
		fail("Verification failed")
		return
	}

	moves, _ := strconv.ParseInt(r.PostForm.Get("moves"), 10, 64)
	jitter, _ := strconv.ParseFloat(r.PostForm.Get("jitter"), 64)
	ptr := r.PostForm.Get("ptr")

	// Heuristics — each is a signal a real hand produces and a bare
	// HTTP client or naive synthetic-event script does not:
	//
	//  - Mouse held 800ms+ with zero pointermove events: real hands
	//    tremble; a stationary cursor for the whole hold is rare.
	//  - Any pointer type with enormous jitter: random-coordinate
	//    flooding.
	//  - Unknown pointer types pass: touch holds legitimately produce
	//    zero moves.
	if ptr == "mouse" && moves == 0 {
		fail("Verification failed")
		return
	}
	if jitter > 50000 {
		fail("Verification failed")
		return
	}

	nextURL := safeNextURL(r.PostForm.Get("hv_next"))

	http.SetCookie(w, &http.Cookie{
		Name:     c.CookieName,
		Value:    c.issuePass(time.Now()),
		Path:     "/",
		Expires:  time.Now().Add(c.CookieTTL),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   c.SecureCookie,
	})
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true,"next":` + strconv.Quote(nextURL) + `}`))
}

// safeNextURL keeps the post-verify redirect same-site: absolute paths
// only — no scheme-relative "//host", no backslashes (browsers treat
// '/\evil.com' as '//evil.com'), no control characters.
func safeNextURL(u string) string {
	if u == "" || !strings.HasPrefix(u, "/") || strings.HasPrefix(u, "//") ||
		strings.ContainsAny(u, "\r\n\t") || strings.ContainsRune(u, '\\') {
		return "/"
	}
	return u
}
