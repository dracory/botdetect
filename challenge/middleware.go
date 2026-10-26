package challenge

import (
	"html/template"
	"net/http"
	"strings"
)

// Middleware returns HTTP middleware that gates every request behind
// the proof-of-work challenge: requests without a valid pass cookie
// receive the challenge page (HTTP 403), and POSTs to VerifyPath are
// answered by the solution verifier. Mount it behind botdetect's
// verdict so only suspicious traffic is challenged.
func (c Config) Middleware(next http.Handler) http.Handler {
	c = c.withDefaults()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == c.VerifyPath {
			c.serveVerify(w, r)
			return
		}
		if c.VerifyPass(r) {
			next.ServeHTTP(w, r)
			return
		}
		c.servePage(w, r)
	})
}

// serveVerify handles a solution POST: form fields token, counter, the
// bd_hp honeypot (must stay empty), and bd_next (redirect target).
func (c Config) serveVerify(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if r.PostForm.Get("bd_hp") != "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if !c.Verify(r, r.PostForm.Get("token"), r.PostForm.Get("counter")) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	c.setPassCookie(w, r)
	next := safeRedirect(r.PostForm.Get("bd_next"))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Location", next)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(next))
}

// servePage renders the challenge page with a fresh token.
func (c Config) servePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	_ = pageTpl.Execute(w, pageData{
		Token:      c.Issue(r),
		VerifyPath: c.VerifyPath,
		Next:       safeRedirect(r.URL.RequestURI()),
		JS:         template.JS(challengeJS),
	})
}

// safeRedirect keeps redirects same-site: absolute paths only, no
// scheme-relative "//host" tricks, no control characters.
func safeRedirect(u string) string {
	if u == "" || !strings.HasPrefix(u, "/") || strings.HasPrefix(u, "//") ||
		strings.ContainsAny(u, "\r\n\t") || strings.ContainsRune(u, '\\') {
		return "/"
	}
	return u
}
