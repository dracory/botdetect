package sliderverify

import (
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Middleware returns an http.Handler wrapper that gates requests:
//   - POST to VerifyPath: receives kinematics trajectory and token, evaluates humanity,
//     and issues a pass cookie on success.
//   - Request with a valid pass cookie: passed directly to next.
//   - Other requests: GET/HEAD requests are served the interactive slider challenge page;
//     non-GET/HEAD methods receive 403 Forbidden.
func (c Config) Middleware(next http.Handler) http.Handler {
	c.defaults()
	if len(c.Secret) == 0 {
		panic("sliderverify: Config.Secret is required")
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
		token, targetPct, err := cfg.issueToken(r)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		nextURL := r.URL.RequestURI()
		if q := r.URL.Query().Get("sv_next"); q != "" {
			nextURL = q
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusForbidden)
		_ = pageTpl.Execute(w, pageData{
			Token:      token,
			VerifyPath: cfg.VerifyPath,
			Next:       nextURL,
			TargetPct:  targetPct,
			TargetLeft: formatPercent(targetPct),
			JS:         template.JS(pageJS),
		})
	})
}

// handleVerify inspects POST submission with kinematics data.
func (c Config) handleVerify(w http.ResponseWriter, r *http.Request) {
	fail := func(msg string) {
		http.Error(w, msg, http.StatusForbidden)
	}

	if err := r.ParseForm(); err != nil {
		fail("Bad request")
		return
	}

	// Honeypot check
	if r.PostForm.Get("sv_hp") != "" {
		fail("Verification failed")
		return
	}

	// Validate signed challenge token and retrieve target percentage
	targetPct, err := c.verifyToken(r.PostForm.Get("token"), time.Now(), r)
	if err != nil {
		fail("Verification failed")
		return
	}

	// Parse JSON kinematics data
	kinematicsRaw := r.PostForm.Get("kinematics")
	if kinematicsRaw == "" {
		fail("Verification failed")
		return
	}

	rep, err := ParseKinematics([]byte(kinematicsRaw))
	if err != nil {
		fail("Verification failed")
		return
	}

	// Run kinematics evaluation
	if err := ValidateKinematics(rep, targetPct, c); err != nil {
		fail("Verification failed")
		return
	}

	nextURL := safeNextURL(r.PostForm.Get("sv_next"))

	http.SetCookie(w, &http.Cookie{
		Name:     c.CookieName,
		Value:    c.issuePass(time.Now(), r),
		Path:     "/",
		Expires:  time.Now().Add(c.CookieTTL),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   c.SecureCookie,
	})
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true,"next":` + strconv.Quote(nextURL) + `}`))
}

func safeNextURL(u string) string {
	if u == "" || !strings.HasPrefix(u, "/") || strings.HasPrefix(u, "//") ||
		strings.ContainsAny(u, "\r\n\t") || strings.ContainsRune(u, '\\') {
		return "/"
	}
	return u
}
